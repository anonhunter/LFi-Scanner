# LFI / Path Traversal Scanner 


**Professional, low-false-positive LFI & Path Traversal scanning framework** — an async, proxyable, configurable Python template for authorized security testing of file endpoints.
Designed for accuracy and observability (works with Burp/mitmproxy), it uses baseline comparison and multiple injection vectors to minimize false positives while staying non-opinionated about exploit payloads.

---

### Key features

* Async, high-performance scanning with configurable concurrency.
* Proxy support (`--proxy`) so traffic can be routed through Burp/mitmproxy for inspection.
* Multiple injection points: path, query parameters, request headers (pluggable).
* Baseline comparison (status, length, content similarity) to reduce false positives.
* Polite scanning: rate limiting, retries, and random jitter to lower chance of blocking.
* Extensible payload list (you supply authorized payloads); tool intentionally does **not** include evasive bypass payloads.
* JSON (and console) output for easy integration with other tools and reporting.
* Clear logging & timestamps for auditability.

---

### Important notice (Ethics & Safety)

This tool is a **professional pentesting template**. Only run it against systems you have **explicit, written authorization** to test. The repository does **not** ship bypass payloads or exploitation modules — you must supply and be authorized to use any payloads you run. Misuse may be illegal.

---

### Quickstart / Usage

1. Clone the repository and install dependencies (requires Python 3.8+ and `aiohttp`):

   ```bash
   git clone <repo>
   pip install -r requirements.txt
   ```

2. Prepare a payload file (one template per line). See **Payload format** below.

3. Run the scanner:

   ```bash
   python3 lfi_path_traversal_scanner.py \
     --url "https://example.com/download?file=report.pdf" \
     --payloads payloads.txt \
     --proxy http://127.0.0.1:8080 \
     --concurrency 8 \
     --output results.json
   ```

Flags (high level):

* `--url` : Target URL (file endpoint).
* `--payloads` : Path to payload templates file.
* `--proxy` : Optional HTTP/HTTPS proxy (useful for Burp).
* `--concurrency`, `--timeout`, `--retries`, `--delay` : Tuning parameters.
* `--header` : Add custom headers (repeatable).
* `--no-ssl-verify` : Disable SSL verification (useful with intercepting proxies).

---

### Payload file format

* One template per line.
* Use `{INJECT}` as a placeholder where dynamic injection might be needed (tool will accept templates without the placeholder as plain payloads).
* Example lines:

  ```
  ../../..{INJECT}
  ../../../../etc/passwd
  ../%2e%2e/%2e%2e/{INJECT}
  ```

> Note: Only include payloads you are authorized to use. This project intentionally *does not* ship bypass suites.

---

### Detection & False-Positive Reduction

The scanner performs a baseline fetch (unmodified request) and compares subsequent responses by:

* HTTP status code changes
* Response length differences (configurable)
* Content similarity (difflib based similarity check)

These combined checks aim to reduce noisy / irrelevant findings and surface only actionable leads.

---

### Proxy / Burp Integration

To inspect requests and responses in Burp or mitmproxy, run the scanner with `--proxy http://127.0.0.1:8080` and configure Burp to listen on that port. Optionally use `--no-ssl-verify` if intercepting HTTPS traffic with a self-signed Burp certificate (only when authorized).

---

### Extensibility

* Add new injection vectors (POST multipart form, file upload skeletons).
* Swap similarity function or adjust thresholds.
* Hook result output into an issue tracker or SIEM by post-processing the JSON results.

If you want, I can:

* Add a safe example payload set (benign) for demo/testing.
* Add multipart/form-data / file param injection support.
* Add HTML/CSV export or a simple web UI to review results.

---

### Contributing

Contributions are welcome for bug fixes, new injection vectors, improved heuristics, and integrations. Please open issues or pull requests and ensure tests/documentation accompany changes.

---

### License

Pick an appropriate license for your project (e.g., MIT, Apache-2.0). This template contains no exploit payloads; licensing clarifies permitted use.

---

### Example README blurb (short)

> Professional LFI & Path Traversal scanner — async, proxyable, and engineered for low false positives. Use with explicit authorization. Provides path/param/header injection, baseline comparison, and JSON output for easy triage. No bypass payloads included.

---


