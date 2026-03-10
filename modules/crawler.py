"""
crawler.py — Web Crawling Module
Crawls the target website, collects internal links, and discovers forms/input fields.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import threading


def crawl(base_url: str, depth: int = 2, timeout: int = 10) -> dict:
    """
    BFS crawl of the target site.

    Args:
        base_url: The starting URL to crawl.
        depth: Maximum crawl depth (default 2).
        timeout: HTTP request timeout in seconds.

    Returns:
        dict with keys 'urls' (set) and 'forms' (list of form dicts).
    """
    visited = set()
    forms_found = []
    queue = deque([(base_url, 0)])
    lock = threading.Lock()

    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; WebVulnScanner/1.0)"
        )
    }

    def is_internal(url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == "" or parsed.netloc == base_domain

    while queue:
        current_url, current_depth = queue.popleft()

        if current_url in visited or current_depth > depth:
            continue

        with lock:
            visited.add(current_url)

        try:
            response = requests.get(current_url, headers=headers, timeout=timeout, allow_redirects=True)
        except Exception:
            continue

        # Only parse HTML content
        content_type = response.headers.get("Content-Type", "")
        if "html" not in content_type.lower():
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        # --- Collect forms ---
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            action_url = urljoin(current_url, action) if action else current_url

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inp_name = inp.get("name")
                inp_type = inp.get("type", "text")
                if inp_name:
                    inputs.append({"name": inp_name, "type": inp_type})

            if inputs:
                forms_found.append({
                    "page_url": current_url,
                    "action": action_url,
                    "method": method,
                    "inputs": inputs,
                })

        # --- Collect links for next depth ---
        if current_depth < depth:
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                full_url = urljoin(current_url, href)
                parsed_full = urlparse(full_url)
                # Strip fragments
                clean_url = parsed_full._replace(fragment="").geturl()
                if is_internal(clean_url) and clean_url not in visited:
                    queue.append((clean_url, current_depth + 1))

    return {
        "urls": visited,
        "forms": forms_found,
    }
