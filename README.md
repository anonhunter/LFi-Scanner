# LFI / Path Traversal Scanner

Professional, low-false-positive LFI & Path Traversal scanning framework — an async, proxyable, configurable Python template for authorized security testing of file endpoints.

> **Important:** Only use this tool against systems you have explicit, written authorization to test. This repository intentionally does not ship evasive bypass payloads or exploitation modules.

## Features
- Async scanning with configurable concurrency
- Proxy support (`--proxy`) for Burp/mitmproxy inspection
- Multiple injection points: path, query parameters, headers
- Baseline comparison (status, length, content similarity) to reduce false positives
- Polite scanning: rate limiting, retries, and jitter
- Extensible payload list (you supply authorized payloads)
- JSON output for easy integration

## Quickstart
1. Install dependencies (Python 3.8+):
```bash
pip install -r requirements.txt
```
2. Create a payload file (see `payloads-example.txt`).
3. Run the scanner:
```bash
python3 lfitest.py \
  --url "https://example.com/download?file=report.pdf" \
  --payloads payloads-example.txt \
  --proxy http://127.0.0.1:8080 \
  --concurrency 6 \
  --output results.json
```

## Payload format
- One template per line.
- Optional placeholder `{INJECT}` for dynamic injection placement.

## Contributing
Contributions welcome. Please open issues or pull requests and include tests/documentation for changes.

## License
MIT (see `LICENSE`)
