"""
report_generator.py — Vulnerability Report Generator
Produces JSON and styled HTML security reports from scan results.
"""

import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def generate_json_report(scan_results: dict, output_path: str) -> str:
    """
    Write scan results to a JSON file.

    Args:
        scan_results: The full results dict from the scanner.
        output_path: File path (without extension) to write to.

    Returns:
        Absolute path to the written file.
    """
    json_path = output_path + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(scan_results, f, indent=2, default=str)
    return json_path


def generate_html_report(scan_results: dict, output_path: str) -> str:
    """
    Render a rich, dashboard-style HTML report from scan results using Jinja2.

    Args:
        scan_results: The full results dict from the scanner.
        output_path: File path (without extension) to write to.

    Returns:
        Absolute path to the written file.
    """
    html_path = output_path + ".html"
    template_dir = os.path.dirname(os.path.abspath(__file__))
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    template = env.get_template("template.html")

    all_findings = scan_results.get("findings", [])
    high = [f for f in all_findings if f.get("risk") == "High"]
    medium = [f for f in all_findings if f.get("risk") == "Medium"]
    low = [f for f in all_findings if f.get("risk") == "Low"]

    html_content = template.render(
        target=scan_results.get("target", "Unknown"),
        scan_time=scan_results.get("scan_time", ""),
        duration=scan_results.get("duration_seconds", 0),
        crawled_urls=scan_results.get("crawled_urls", []),
        forms_found=scan_results.get("forms_found", []),
        findings=all_findings,
        high=high,
        medium=medium,
        low=low,
        total=len(all_findings),
    )

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return html_path
