# 🔍 Web Vulnerability Scanner

A Python-based CLI tool that automatically scans websites for common security vulnerabilities and generates structured security reports.

> ⚠️ **For authorized testing only.** Always obtain explicit permission before scanning any target.

---

## Features

- **Web Crawling** — BFS crawler that discovers internal links and form inputs
- **SQL Injection Detection** — Injects payloads and detects DB error signatures
- **XSS Detection** — Tests for reflected Cross-Site Scripting via form inputs
- **Port Scanning** — Multi-threaded raw TCP socket scanner for common ports
- **HTTP Header Analysis** — Checks for missing/misconfigured security headers
- **OWASP Top 10 Checks** — CSRF detection, directory traversal, sensitive file exposure
- **Rich Reports** — Generates both JSON and a dark-themed HTML dashboard report

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic scan
python scanner.py --url https://example.com

# Custom depth, port list, and report name
python scanner.py --url https://example.com --depth 3 --ports 80 443 22 3306 --output my_report
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `--url` | Target URL *(required)* | — |
| `--depth` | Crawl depth | `2` |
| `--ports` | Ports to scan (space-separated integers) | 18 common ports |
| `--output` | Output filename without extension | `report` |

Reports are saved as `<output>.json` and `<output>.html`.

---

## Local Testing

Test the scanner against the included intentionally vulnerable Flask app:

```bash
# Terminal 1 — start vulnerable test server
python test_server.py

# Terminal 2 — run scanner against it
python scanner.py --url http://127.0.0.1:5000 --depth 2 --output scan_report
```

Then open `scan_report.html` in your browser to view the full dashboard.

---

## Project Structure

```
web_vuln_scanner/
├── scanner.py              # CLI entry point
├── requirements.txt
├── test_server.py          # Vulnerable Flask test server
├── modules/
│   ├── crawler.py          # Web crawler
│   ├── sql_injection.py    # SQL injection tester
│   ├── xss_scanner.py      # XSS tester
│   ├── port_scanner.py     # TCP port scanner
│   ├── header_checker.py   # HTTP header analyzer
│   └── owasp_checks.py     # OWASP supplementary checks
└── reports/
    ├── report_generator.py # JSON + HTML report generator
    └── template.html       # Jinja2 HTML report template
```

---

## Tech Stack

- **Python 3.8+**
- `requests` — HTTP client
- `beautifulsoup4` — HTML parsing
- `jinja2` — HTML report templating
- `colorama` — Colorized terminal output

---

## Disclaimer

This tool is intended for **educational purposes** and **authorized penetration testing** only. The author is not responsible for any misuse. Always get written permission before testing any system you do not own.

---

## License

MIT License
