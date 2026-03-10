"""
port_scanner.py — Open Port Scanning Module
Scans common TCP ports on the target host using raw Python sockets.
Multi-threaded using ThreadPoolExecutor for speed.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Default ports to scan with service names
DEFAULT_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Risk mapping: sensitive services = High, common web services = Low/Medium
PORT_RISK = {
    21:    "High",   # FTP often unencrypted
    22:    "Medium", # SSH — legitimate but exposure is noteworthy
    23:    "High",   # Telnet — unencrypted
    25:    "Medium", # SMTP
    53:    "Low",    # DNS
    80:    "Low",    # HTTP — expected
    110:   "Medium", # POP3
    143:   "Medium", # IMAP
    443:   "Low",    # HTTPS — expected
    445:   "High",   # SMB — frequently exploited
    3306:  "High",   # MySQL exposed
    3389:  "High",   # RDP exposed
    5432:  "High",   # PostgreSQL exposed
    5900:  "High",   # VNC exposed
    6379:  "High",   # Redis (often no auth)
    8080:  "Low",
    8443:  "Low",
    27017: "High",   # MongoDB (often no auth)
}

PORT_RECOMMENDATIONS = {
    21:    "Disable FTP or replace with SFTP/SCP. Ensure strong credentials.",
    22:    "Restrict SSH access to known IPs using firewall rules. Use key-based auth.",
    23:    "Disable Telnet immediately; use SSH instead.",
    25:    "Restrict SMTP relay. Use authentication and TLS.",
    53:    "Ensure DNS resolver is not open to the internet.",
    80:    "Redirect all HTTP traffic to HTTPS.",
    443:   "Ensure TLS certificate is valid and up to date.",
    445:   "Block SMB from public internet. Apply Windows patches for EternalBlue.",
    3306:  "Block MySQL port from public internet. Restrict to localhost or VPN.",
    3389:  "Restrict RDP access behind a VPN. Enable NLA authentication.",
    5432:  "Block PostgreSQL port from public internet.",
    5900:  "Disable VNC or restrict to VPN. Use strong passwords.",
    6379:  "Add Redis authentication. Bind to localhost only.",
    8080:  "Ensure no sensitive admin panels are exposed on HTTP-Alt.",
    8443:  "Ensure TLS is configured correctly on alternate HTTPS port.",
    27017: "Add MongoDB authentication. Bind to localhost or VPN.",
}


def _check_port(host: str, port: int, timeout: float = 1.5) -> bool:
    """Try to open a TCP socket to host:port. Returns True if open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_ports(
    target_url: str,
    custom_ports: list = None,
    timeout: float = 1.5,
    max_workers: int = 50,
) -> list:
    """
    Scan ports on the host extracted from target_url.

    Args:
        target_url: Full URL of the target (to extract hostname).
        custom_ports: Optional list of ints to scan instead of defaults.
        timeout: Per-port socket timeout in seconds.
        max_workers: Thread pool size.

    Returns:
        List of finding dicts for each open port.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname

    if not host:
        return []

    ports = custom_ports if custom_ports else list(DEFAULT_PORTS.keys())
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_check_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
            except Exception:
                is_open = False

            if is_open:
                service = DEFAULT_PORTS.get(port, "Unknown")
                open_ports.append({
                    "type": "Open Port",
                    "host": host,
                    "port": port,
                    "service": service,
                    "risk": PORT_RISK.get(port, "Medium"),
                    "recommendation": PORT_RECOMMENDATIONS.get(
                        port,
                        f"Verify that port {port} must be publicly accessible. Close if unnecessary.",
                    ),
                })

    # Sort results by port number for readability
    open_ports.sort(key=lambda x: x["port"])
    return open_ports
