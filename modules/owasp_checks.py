"""
owasp_checks.py — OWASP Top 10 Supplementary Checks
Covers: sensitive file exposure, directory traversal, CSRF indicators.
"""

import requests

# Sensitive files/paths to probe for
SENSITIVE_PATHS = [
    ".env",
    ".git/config",
    ".htaccess",
    "config.php",
    "wp-config.php",
    "web.config",
    "phpinfo.php",
    "info.php",
    "test.php",
    "admin/",
    "admin/index.php",
    "administrator/",
    "phpmyadmin/",
    "backup/",
    "backup.zip",
    "backup.sql",
    "db.sql",
    "database.sql",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "debug.log",
    "error.log",
    "server-status",
    "server-info",
]

# Directory traversal payloads
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

TRAVERSAL_SIGNATURES = [
    "root:x:0:0",
    "[boot loader]",
    "for 16-bit app support",
    "[fonts]",
    "windows",
]


def check_sensitive_files(base_url: str, timeout: int = 8) -> list:
    """
    Probe the target for commonly exposed sensitive files.

    Args:
        base_url: Base URL of the target (e.g. https://example.com).
        timeout: HTTP request timeout.

    Returns:
        List of finding dicts.
    """
    findings = []
    base = base_url.rstrip("/")

    for path in SENSITIVE_PATHS:
        url = f"{base}/{path}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
        except Exception:
            continue

        # 200 or 403 (accessible but forbidden) are interesting
        if resp.status_code in (200, 301, 302, 403):
            risk = "High" if resp.status_code == 200 else "Medium"
            findings.append({
                "type": "Sensitive File Exposure",
                "url": url,
                "http_status": resp.status_code,
                "reason": (
                    f"Sensitive path '{path}' returned HTTP {resp.status_code}. "
                    "File may be publicly accessible."
                ),
                "risk": risk,
                "recommendation": (
                    f"Restrict access to '{path}' via server configuration or .htaccess rules. "
                    "Remove or relocate sensitive files from the web root."
                ),
            })

    return findings


def check_directory_traversal(forms: list, timeout: int = 10) -> list:
    """
    Test form inputs for directory traversal vulnerabilities.

    Args:
        forms: List of form dicts from the crawler.
        timeout: HTTP request timeout.

    Returns:
        List of finding dicts.
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

        base_data = {}
        for inp in inputs:
            if inp.get("type") in ("submit", "button", "image", "reset", "file"):
                continue
            base_data[inp["name"]] = "test"

        if not base_data:
            continue

        for payload in TRAVERSAL_PAYLOADS:
            injected = {k: payload for k in base_data}
            try:
                if method == "post":
                    resp = requests.post(action, data=injected, timeout=timeout, allow_redirects=True)
                else:
                    resp = requests.get(action, params=injected, timeout=timeout, allow_redirects=True)
            except Exception:
                continue

            resp_lower = resp.text.lower()
            if any(sig.lower() in resp_lower for sig in TRAVERSAL_SIGNATURES):
                findings.append({
                    "type": "Directory Traversal",
                    "url": action,
                    "source_page": page_url,
                    "payload": payload,
                    "reason": "System file content detected in response (possible /etc/passwd or win.ini leak)",
                    "risk": "High",
                    "recommendation": (
                        "Validate and sanitize file path inputs. "
                        "Use a whitelist of allowed files. "
                        "Resolve canonical paths and ensure they stay within the web root."
                    ),
                })
                break

    return findings


def check_csrf_indicators(forms: list) -> list:
    """
    Check forms for absence of CSRF protection tokens.

    Args:
        forms: List of form dicts from the crawler.

    Returns:
        List of finding dicts for forms lacking CSRF tokens.
    """
    findings = []
    csrf_token_names = {
        "csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
        "authenticity_token", "__requestverificationtoken", "xsrf-token"
    }

    for form in forms:
        method = form["method"]
        if method != "post":
            continue  # CSRF mainly matters for state-changing (POST) forms

        input_names = {inp["name"].lower() for inp in form["inputs"]}
        has_csrf = bool(csrf_token_names & input_names)

        if not has_csrf:
            findings.append({
                "type": "Missing CSRF Protection",
                "url": form["action"],
                "source_page": form["page_url"],
                "reason": "POST form has no detectable CSRF token field.",
                "risk": "Medium",
                "recommendation": (
                    "Implement CSRF tokens for all state-changing forms. "
                    "Use the SameSite cookie attribute (Strict or Lax). "
                    "Consider using the Double Submit Cookie pattern."
                ),
            })

    return findings
