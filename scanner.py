#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scanner.py -- Web Vulnerability Scanner
Main CLI entry point that orchestrates all scanning modules.

Usage:
    python scanner.py --url https://example.com
    python scanner.py --url http://127.0.0.1:5000 --depth 2 --output report
    python scanner.py --url https://example.com --ports 80 443 22 3306
"""
import sys, io
# Force UTF-8 stdout on Windows so Unicode prints cleanly
if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import argparse
import time
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class _FakeFore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = BLUE = ""
    class _FakeStyle:
        BRIGHT = RESET_ALL = ""
    Fore = _FakeFore()
    Style = _FakeStyle()

# --- Module imports ---
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.crawler      import crawl
from modules.sql_injection import test_sql_injection
from modules.xss_scanner   import test_xss
from modules.port_scanner  import scan_ports
from modules.header_checker import check_headers
from modules.owasp_checks   import check_sensitive_files, check_directory_traversal, check_csrf_indicators
from reports.report_generator import generate_json_report, generate_html_report


# ─────────────────────────────────────────────────────────
#  Pretty print helpers
# ─────────────────────────────────────────────────────────

def _banner():
    print(Fore.CYAN + Style.BRIGHT + """
  +============================================================+
  |   WEB VULN SCANNER v1.0 - Authorized Security Testing     |
  |  SQLi | XSS | Open Ports | Headers | OWASP Top 10 Checks  |
  +============================================================+
""" + Style.RESET_ALL)


def _header(text: str):
    line = "-" * 60
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{line}")
    print(f"  {text}")
    print(f"{line}{Style.RESET_ALL}")


def _ok(msg: str):
    print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL}  {msg}")


def _warn(msg: str):
    print(f"  {Fore.YELLOW}[!!]{Style.RESET_ALL}  {msg}")


def _err(msg: str):
    print(f"  {Fore.RED}[ERR]{Style.RESET_ALL} {msg}")


def _info(msg: str):
    print(f"  {Fore.BLUE}[>>]{Style.RESET_ALL}  {msg}")


def _risk_color(risk: str) -> str:
    colors = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.CYAN, "Info": Fore.BLUE}
    return colors.get(risk, Fore.WHITE)


def _print_findings(findings: list):
    if not findings:
        _ok("No issues found in this category.")
        return
    for f in findings:
        risk = f.get("risk", "Info")
        rc = _risk_color(risk)
        ftype = f.get("type", "Finding")
        url = f.get("url", f.get("host", ""))
        port = f.get("port")
        reason = f.get("reason", "")
        header = f.get("header", "")

        endpoint = f"{url}:{port}" if port else url
        print(f"\n  {rc}[{risk}]{Style.RESET_ALL} {Style.BRIGHT}{ftype}{Style.RESET_ALL}")
        if endpoint:
            print(f"       {Fore.WHITE}URL   :{Style.RESET_ALL} {endpoint}")
        if header:
            print(f"       {Fore.WHITE}Header:{Style.RESET_ALL} {header}")
        if reason:
            print(f"       {Fore.WHITE}Detail:{Style.RESET_ALL} {reason}")
        if f.get("payload"):
            print(f"       {Fore.MAGENTA}Payload:{Style.RESET_ALL} {f['payload']}")


# ─────────────────────────────────────────────────────────
#  Main scan logic
# ─────────────────────────────────────────────────────────

def run_scan(args) -> dict:
    target = args.url.rstrip("/")
    depth  = args.depth
    output = args.output
    ports  = args.ports  # list of ints or None

    _banner()
    print(f"  {Fore.WHITE}Target :{Style.RESET_ALL} {target}")
    print(f"  {Fore.WHITE}Depth  :{Style.RESET_ALL} {depth}")
    print(f"  {Fore.WHITE}Output :{Style.RESET_ALL} {output}.[json|html]")
    print(f"  {Fore.WHITE}Time   :{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    start_time = time.time()
    all_findings = []
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── 1. Crawl ──────────────────────────────────────────
    _header("PHASE 1 — Web Crawling")
    _info(f"Crawling {target} (depth={depth}) …")
    crawl_result = crawl(target, depth=depth)
    discovered_urls = list(crawl_result["urls"])
    forms = crawl_result["forms"]
    _ok(f"Discovered {len(discovered_urls)} URL(s)")
    _ok(f"Found {len(forms)} form(s)")
    for u in sorted(discovered_urls):
        print(f"       {Fore.WHITE}{u}{Style.RESET_ALL}")

    # ── 2. SQL Injection ──────────────────────────────────
    _header("PHASE 2 — SQL Injection Testing")
    _info(f"Testing {len(forms)} form(s) for SQL injection …")
    sqli_findings = test_sql_injection(forms)
    all_findings.extend(sqli_findings)
    _print_findings(sqli_findings)

    # ── 3. XSS ────────────────────────────────────────────
    _header("PHASE 3 — Cross-Site Scripting (XSS) Testing")
    _info(f"Testing {len(forms)} form(s) for reflected XSS …")
    xss_findings = test_xss(forms)
    all_findings.extend(xss_findings)
    _print_findings(xss_findings)

    # ── 4. HTTP Headers ────────────────────────────────────
    _header("PHASE 4 — HTTP Security Header Analysis")
    _info(f"Checking security headers on {target} …")
    header_findings = check_headers(target)
    all_findings.extend(header_findings)
    _print_findings(header_findings)

    # ── 5. Port Scan ───────────────────────────────────────
    _header("PHASE 5 — Open Port Scanning")
    _info(f"Scanning ports on {target} …")
    port_findings = scan_ports(target, custom_ports=ports)
    all_findings.extend(port_findings)
    _print_findings(port_findings)

    # ── 6. OWASP Checks ────────────────────────────────────
    _header("PHASE 6 — OWASP Top 10 Checks")
    _info("Probing for sensitive files …")
    sensitive = check_sensitive_files(target)
    all_findings.extend(sensitive)
    _print_findings(sensitive)

    _info("Testing for directory traversal …")
    traversal = check_directory_traversal(forms)
    all_findings.extend(traversal)
    _print_findings(traversal)

    _info("Checking CSRF protection on POST forms …")
    csrf = check_csrf_indicators(forms)
    all_findings.extend(csrf)
    _print_findings(csrf)

    # ── Summary ────────────────────────────────────────────
    duration = round(time.time() - start_time, 2)
    high_count   = sum(1 for f in all_findings if f.get("risk") == "High")
    medium_count = sum(1 for f in all_findings if f.get("risk") == "Medium")
    low_count    = sum(1 for f in all_findings if f.get("risk") == "Low")

    _header("SCAN COMPLETE — Summary")
    print(f"  {Fore.WHITE}Total Findings : {Style.RESET_ALL}{Style.BRIGHT}{len(all_findings)}{Style.RESET_ALL}")
    print(f"  {Fore.RED}High Risk      : {high_count}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Medium Risk    : {medium_count}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Low Risk       : {low_count}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Duration       : {Style.RESET_ALL}{duration}s")

    # Build result dict
    result = {
        "target": target,
        "scan_time": scan_time,
        "duration_seconds": duration,
        "crawled_urls": sorted(discovered_urls),
        "forms_found": forms,
        "findings": all_findings,
        "summary": {
            "total": len(all_findings),
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        },
    }

    # ── 7. Reports ─────────────────────────────────────────
    _header("PHASE 7 — Generating Reports")
    json_path = generate_json_report(result, output)
    html_path = generate_html_report(result, output)
    _ok(f"JSON report : {json_path}")
    _ok(f"HTML report : {html_path}")
    print(f"\n  {Fore.GREEN}Open {os.path.basename(html_path)} in your browser to view the full dashboard.{Style.RESET_ALL}\n")

    return result


# ─────────────────────────────────────────────────────────
#  CLI argument parsing
# ─────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Web Vulnerability Scanner — SQL Injection, XSS, Open Ports, Header Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --url https://example.com
  python scanner.py --url http://127.0.0.1:5000 --depth 3
  python scanner.py --url https://example.com --ports 80 443 22 3306 --output my_report
        """,
    )
    parser.add_argument("--url",    required=True,  help="Target URL to scan (e.g. https://example.com)")
    parser.add_argument("--depth",  type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--ports",  type=int, nargs="+", default=None, help="Ports to scan (default: common ports)")
    parser.add_argument("--output", default="report", help="Output file path without extension (default: report)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_scan(args)
