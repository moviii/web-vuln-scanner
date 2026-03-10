"""
xss_scanner.py — Cross-Site Scripting (XSS) Detection Module
Tests discovered forms for reflected XSS vulnerabilities.
"""

import requests
import copy
import html

# XSS payloads to inject
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'><script>alert(document.cookie)</script>",
    "<iframe src=\"javascript:alert('XSS')\">",
    "<input autofocus onfocus=alert(1)>",
]


def _is_reflected(payload: str, response_text: str) -> bool:
    """
    Check if the payload (or its HTML-entity equivalent) appears in the response.
    """
    if payload in response_text:
        return True
    # Some frameworks HTML-encode injections — check for the encoded version too
    if html.escape(payload) in response_text and html.escape(payload) != payload:
        # Encoded means it WAS reflected but safely escaped — not vulnerable
        return False
    return False


def test_xss(forms: list, timeout: int = 10) -> list:
    """
    Test forms for reflected XSS vulnerabilities.

    Args:
        forms: List of form dicts from the crawler.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of vulnerability finding dicts.
    """
    findings = []
    tested = set()

    for form in forms:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        page_url = form["page_url"]

        if action in tested:
            continue
        tested.add(action)

        # Build form data skeleton
        base_data = {}
        for inp in inputs:
            inp_type = inp.get("type", "text")
            if inp_type in ("submit", "button", "image", "reset", "file", "hidden"):
                continue
            base_data[inp["name"]] = "harmless"

        if not base_data:
            continue

        for payload in XSS_PAYLOADS:
            injected_data = copy.copy(base_data)
            for field_name in list(injected_data.keys()):
                injected_data[field_name] = payload

            try:
                if method == "post":
                    resp = requests.post(action, data=injected_data, timeout=timeout, allow_redirects=True)
                else:
                    resp = requests.get(action, params=injected_data, timeout=timeout, allow_redirects=True)
            except Exception:
                continue

            if _is_reflected(payload, resp.text):
                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "url": action,
                    "source_page": page_url,
                    "payload": payload,
                    "reason": "Injected payload was reflected verbatim in the response body",
                    "risk": "High",
                    "recommendation": (
                        "Encode all user-supplied input before rendering it in HTML. "
                        "Use a Content-Security-Policy header. "
                        "Prefer a templating engine with auto-escaping enabled."
                    ),
                })
                break  # One finding per endpoint is enough

    return findings
