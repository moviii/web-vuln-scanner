"""
header_checker.py — HTTP Security Header Analysis Module
Checks if the target website sends important security headers.
"""

import requests

# Security headers we expect, with risk if missing and a fix recommendation
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "risk": "High",
        "recommendation": (
            "Add a Content-Security-Policy header to restrict sources of scripts, "
            "styles, and other resources. Example: "
            "Content-Security-Policy: default-src 'self'"
        ),
    },
    "X-Frame-Options": {
        "risk": "Medium",
        "recommendation": (
            "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks."
        ),
    },
    "X-XSS-Protection": {
        "risk": "Medium",
        "recommendation": (
            "Add X-XSS-Protection: 1; mode=block to enable the browser's built-in "
            "XSS filter (for legacy browsers)."
        ),
    },
    "Strict-Transport-Security": {
        "risk": "High",
        "recommendation": (
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains "
            "to enforce HTTPS connections."
        ),
    },
    "X-Content-Type-Options": {
        "risk": "Medium",
        "recommendation": (
            "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing."
        ),
    },
    "Referrer-Policy": {
        "risk": "Low",
        "recommendation": (
            "Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin "
            "to control referrer information."
        ),
    },
    "Permissions-Policy": {
        "risk": "Low",
        "recommendation": (
            "Add a Permissions-Policy header to restrict access to browser features "
            "like camera, microphone, and geolocation."
        ),
    },
}

# Insecure header values to flag even when header IS present
INSECURE_HEADER_VALUES = {
    "X-XSS-Protection": ("0",),                        # Disabled
    "Strict-Transport-Security": (),                   # Any value is ok
    "X-Frame-Options": ("ALLOWALL",),                  # Insecure value
}


def check_headers(url: str, timeout: int = 10) -> list:
    """
    Analyze security headers of the target URL.

    Args:
        url: Target URL to check.
        timeout: HTTP request timeout.

    Returns:
        List of finding dicts for missing or misconfigured headers.
    """
    findings = []

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
    except Exception as e:
        findings.append({
            "type": "HTTP Header Check Error",
            "url": url,
            "reason": f"Could not connect to URL: {e}",
            "risk": "Info",
            "recommendation": "Ensure the target URL is reachable.",
        })
        return findings

    response_headers = {k.lower(): v for k, v in resp.headers.items()}

    for header_name, meta in SECURITY_HEADERS.items():
        h_lower = header_name.lower()
        if h_lower not in response_headers:
            findings.append({
                "type": "Missing Security Header",
                "url": url,
                "header": header_name,
                "current_value": None,
                "reason": f"The '{header_name}' header is absent from the response.",
                "risk": meta["risk"],
                "recommendation": meta["recommendation"],
            })
        else:
            # Check for insecure values
            insecure_vals = INSECURE_HEADER_VALUES.get(header_name, ())
            val = response_headers[h_lower]
            if any(bad in val.upper() for bad in (v.upper() for v in insecure_vals)):
                findings.append({
                    "type": "Misconfigured Security Header",
                    "url": url,
                    "header": header_name,
                    "current_value": val,
                    "reason": f"'{header_name}' is set to an insecure value: '{val}'",
                    "risk": meta["risk"],
                    "recommendation": meta["recommendation"],
                })

    # Check for server information leakage
    server_val = response_headers.get("server", "")
    if server_val and any(v in server_val.lower() for v in ["apache", "nginx", "iis", "php", "express"]):
        findings.append({
            "type": "Server Information Disclosure",
            "url": url,
            "header": "Server",
            "current_value": server_val,
            "reason": f"The 'Server' header reveals software version info: '{server_val}'",
            "risk": "Low",
            "recommendation": "Configure your web server to suppress or mask the Server header.",
        })

    # Check for X-Powered-By leakage
    powered_by = response_headers.get("x-powered-by", "")
    if powered_by:
        findings.append({
            "type": "Technology Information Disclosure",
            "url": url,
            "header": "X-Powered-By",
            "current_value": powered_by,
            "reason": f"'X-Powered-By' reveals backend technology: '{powered_by}'",
            "risk": "Low",
            "recommendation": "Remove the X-Powered-By header from server configuration.",
        })

    return findings
