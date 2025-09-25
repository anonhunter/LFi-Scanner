"""
LFI / Path Traversal Scanner - Professional template

IMPORTANT:
- This tool is provided as a professional, *authorized* pentesting template.
- Do NOT use this against systems you do NOT have explicit permission to test.
- By design this template *does not* ship with evasive bypass payloads or aggressive exploitation features.
  You (the tester) must supply the payload lists you are authorized to use.

Features:
- Async, high-performance scanning with configurable concurrency
- Proxy support (HTTP/HTTPS) so you can route traffic through Burp/mitmproxy
- Multiple injection points (path, query params, headers, file param skeleton)
- Baseline comparison to reduce false positives (checks status, length, similarity)
- Rate limiting, retries, random jitter to reduce accidental blocking
- JSON and plain-text reporting
- Pluggable payload list: specify a file of payload templates

Usage example:
    python3 lfi_path_traversal_scanner.py --url "https://example.com/download?file=report.pdf" \
        --payloads payloads.txt --proxy http://127.0.0.1:8080 --concurrency 8 --output results.json

Payload file format (one template per line):
- Use `{INJECT}` as placeholder where payload should go, e.g.
    ../../..{INJECT}
    ../../../../etc/passwd{INJECT}
  (This tool will replace `{INJECT}` with traversal sequences you provide.)

Note: payloads are intentionally left to you. This file is a framework to perform
accurate, low-false-positive detection and to integrate with proxies for analysis.
"""

import argparse
import asyncio
import aiohttp
import json
import time
import random
import sys
from typing import List, Dict, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, ParseResult
import hashlib
import difflib
import logging

# === Configuration Defaults ===
DEFAULT_TIMEOUT = 15
DEFAULT_CONCURRENCY = 6
DEFAULT_RETRIES = 2
DEFAULT_DELAY = 0.25  # base delay between requests
SIMILARITY_THRESHOLD = 0.80  # for baseline comparison (0-1, lower -> stricter)

# === Logging setup ===
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("lfi_scanner")

# === Utilities ===
def sha1hex(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()

# === HTTP helper ===
class HTTPClient:
    def __init__(self, proxy: str = None, timeout: int = DEFAULT_TIMEOUT, verify_ssl: bool = True, headers: Dict[str,str] = None):
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        self._connector = aiohttp.TCPConnector(ssl=verify_ssl)
        self._session = aiohttp.ClientSession(timeout=timeout_cfg, connector=self._connector, headers=headers)
        self._proxy = proxy

    async def close(self):
        await self._session.close()

    async def fetch(self, method: str, url: str, **kwargs) -> Tuple[int, bytes, Dict[str,str]]:
        proxy = self._proxy
        try:
            async with self._session.request(method, url, proxy=proxy, **kwargs) as resp:
                data = await resp.read()
                headers = {k: v for k, v in resp.headers.items()}
                return resp.status, data, headers
        except Exception as e:
            raise

# === Scanner core ===
class Scanner:
    def __init__(self, target_url: str, payloads: List[str], proxy: str = None, concurrency: int = DEFAULT_CONCURRENCY,
                 verify_ssl: bool = True, max_retries: int = DEFAULT_RETRIES, delay: float = DEFAULT_DELAY, headers: Dict[str,str]=None):
        self.target_url = target_url
        self.payloads = payloads
        self.proxy = proxy
        self.concurrency = concurrency
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.base_delay = delay
        self.headers = headers or {}

        self.http = HTTPClient(proxy=proxy, verify_ssl=verify_ssl, headers=self.headers)
        self.semaphore = asyncio.Semaphore(concurrency)

        self.results = []

    async def _get_baseline(self) -> Dict:
        """
        Fetch baseline response for the target URL (no injection) to compare.
        """
        for attempt in range(self.max_retries + 1):
            try:
                status, data, headers = await self.http.fetch('GET', self.target_url, allow_redirects=True)
                text = data.decode('utf-8', errors='ignore')
                return {
                    'status': status,
                    'length': len(data),
                    'sha1': sha1hex(data),
                    'text': text,
                    'headers': headers
                }
            except Exception as e:
                logger.debug(f"Baseline fetch attempt {attempt} failed: {e}")
                await asyncio.sleep(0.5 + attempt)
        raise RuntimeError('Failed to fetch baseline response')

    async def _request_with_retries(self, method: str, url: str, **kwargs) -> Tuple[int, bytes, Dict[str,str]]:
        last_err = None
        for attempt in range(self.max_retries + 1):
            try:
                status, data, headers = await self.http.fetch(method, url, **kwargs)
                return status, data, headers
            except Exception as e:
                last_err = e
                jitter = random.random() * 0.3
                await asyncio.sleep(0.5 + jitter + attempt * 0.2)
        raise last_err

    async def _run_payload(self, payload_template: str, inject_location: str) -> Dict:
        """
        payload_template: string containing `{INJECT}` where injection should go
        inject_location: 'path' or 'param' or 'header' etc.
        """
        parsed = urlparse(self.target_url)
        q = dict(parse_qsl(parsed.query, keep_blank_values=True))

        if inject_location == 'param':
            if not q:
                return {}
            for param in q.keys():
                new_q = q.copy()
                new_q[param] = payload_template.replace('{INJECT}', '')
                new_parsed = ParseResult(parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(new_q), parsed.fragment)
                target = urlunparse(new_parsed)
                status, data, headers = await self._request_with_retries('GET', target, allow_redirects=True)
                text = data.decode('utf-8', errors='ignore')
                entry = {
                    'location': f'param:{param}',
                    'payload': payload_template,
                    'status': status,
                    'length': len(data),
                    'sha1': sha1hex(data),
                    'text_snippet': text[:200]
                }
                return entry
        elif inject_location == 'path':
            path = parsed.path
            injected_path = (path.rstrip('/') + '/') + payload_template.replace('{INJECT}', '')
            new_parsed = ParseResult(parsed.scheme, parsed.netloc, injected_path, parsed.params, parsed.query, parsed.fragment)
            target = urlunparse(new_parsed)
            status, data, headers = await self._request_with_retries('GET', target, allow_redirects=True)
            text = data.decode('utf-8', errors='ignore')
            return {
                'location': 'path',
                'payload': payload_template,
                'status': status,
                'length': len(data),
                'sha1': sha1hex(data),
                'text_snippet': text[:200]
            }
        elif inject_location == 'header':
            hdrs = self.headers.copy()
            hdrs['X-File-Name'] = payload_template.replace('{INJECT}', '')
            status, data, headers = await self._request_with_retries('GET', self.target_url, headers=hdrs, allow_redirects=True)
            text = data.decode('utf-8', errors='ignore')
            return {
                'location': 'header:X-File-Name',
                'payload': payload_template,
                'status': status,
                'length': len(data),
                'sha1': sha1hex(data),
                'text_snippet': text[:200]
            }
        else:
            return {}

    def _assess_result(self, baseline: Dict, candidate: Dict) -> Tuple[bool, Dict]:
        """
        Compare candidate result to baseline to decide if it's interesting (possible LFI)
        Returns (is_interesting, details)
        """
        if not candidate:
            return False, {}

        if candidate['status'] != baseline['status']:
            return True, {'reason': f"status_changed {baseline['status']} -> {candidate['status']}"}

        if baseline['length'] != 0:
            ratio = abs(candidate['length'] - baseline['length']) / baseline['length']
            if ratio > 0.15:  # 15% length difference
                return True, {'reason': f"length_diff {baseline['length']} -> {candidate['length']}", 'ratio': ratio}

        sim = similarity(baseline['text'], candidate.get('text_snippet', ''))
        if sim < SIMILARITY_THRESHOLD:
            return True, {'reason': f'low_similarity {sim:.2f}'}

        return False, {}

    async def _worker(self, baseline: Dict, payload: str, inject_location: str):
        async with self.semaphore:
            try:
                await asyncio.sleep(self.base_delay + random.random() * 0.2)
                candidate = await self._run_payload(payload, inject_location)
                interesting, details = self._assess_result(baseline, candidate)
                if interesting:
                    record = {
                        'target': self.target_url,
                        'location': candidate.get('location'),
                        'payload': candidate.get('payload'),
                        'status': candidate.get('status'),
                        'length': candidate.get('length'),
                        'sha1': candidate.get('sha1'),
                        'snippet': candidate.get('text_snippet'),
                        'details': details,
                        'timestamp': time.time()
                    }
                    self.results.append(record)
                    logger.info(f"Potential issue discovered: {record['location']} | status {record['status']} | payload {record['payload']}")
            except Exception as e:
                logger.debug(f"Worker error for payload {payload}: {e}")

    async def run(self, locations: List[str] = None) -> List[Dict]:
        if locations is None:
            locations = ['param', 'path', 'header']

        baseline = await self._get_baseline()
        logger.info(f"Baseline: status={baseline['status']} length={baseline['length']} sha1={baseline['sha1']}")

        tasks = []
        for payload in self.payloads:
            for loc in locations:
                tasks.append(self._worker(baseline, payload, loc))

        await asyncio.gather(*tasks)
        await self.http.close()
        return self.results

# === CLI ===
def load_payloads(path: str) -> List[str]:
    p = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '{INJECT}' not in line:
                p.append(line)
            else:
                p.append(line)
    return p

def parse_headers_list(hlist: List[str]) -> Dict[str,str]:
    hdrs = {}
    for h in hlist:
        if ':' in h:
            k, v = h.split(':', 1)
            hdrs[k.strip()] = v.strip()
    return hdrs

def main():
    parser = argparse.ArgumentParser(description='LFI / Path Traversal Scanner (template)')
    parser.add_argument('--url', required=True, help='Target URL (pointing to a file endpoint)')
    parser.add_argument('--payloads', required=True, help='Path to payload templates file (one per line)')
    parser.add_argument('--proxy', required=False, help='Proxy URL (eg http://127.0.0.1:8080)')
    parser.add_argument('--concurrency', type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument('--retries', type=int, default=DEFAULT_RETRIES)
    parser.add_argument('--delay', type=float, default=DEFAULT_DELAY)
    parser.add_argument('--output', required=False, help='Output JSON file for results')
    parser.add_argument('--header', action='append', default=[], help='Additional header in \"Key: Value\" form (can be repeated)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL verification (useful for intercepting proxies with self-signed certs)')

    args = parser.parse_args()

    headers = parse_headers_list(args.header)

    payloads = load_payloads(args.payloads)
    if not payloads:
        logger.error('No payloads loaded. Provide a payload file with at least one template.')
        sys.exit(2)

    scanner = Scanner(
        target_url=args.url,
        payloads=payloads,
        proxy=args.proxy,
        concurrency=args.concurrency,
        verify_ssl=not args.no_ssl_verify,
        max_retries=args.retries,
        delay=args.delay,
        headers=headers
    )

    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(scanner.run())

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as out:
            json.dump(results, out, indent=2)
        logger.info(f"Saved results to {args.output}")
    else:
        print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()
