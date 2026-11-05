"""Fetch a public web page on behalf of a transform, without letting it reach internal systems (SSRF guard).

* only http/https on ports 80/443
* every address the host name resolves to must be globally routable (no loopback, private, link-local, metadata)
* redirects are followed manually, and each hop is re-checked
* response size and time are capped, and only HTML/XHTML is returned
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

MAX_BYTES = 1_000_000
MAX_REDIRECTS = 3


class UnsafeURL(ValueError):
    pass


def check_public_url(url: str) -> Tuple[str, str, int]:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise UnsafeURL("only http(s) URLs can be fetched")
    host = (p.hostname or "").rstrip(".").lower()
    if not host or "@" in (p.netloc or "").split(":")[0]:
        raise UnsafeURL("URL has no usable host")
    port = p.port or (443 if p.scheme == "https" else 80)
    if port not in (80, 443):
        raise UnsafeURL("only ports 80 and 443 are allowed")
    try:
        literal = ipaddress.ip_address(host)
        addrs = [str(literal)]
    except ValueError:
        try:
            addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)})
        except OSError:
            raise UnsafeURL("host name does not resolve") from None
    if not addrs:
        raise UnsafeURL("host name does not resolve")
    for a in addrs:
        if not ipaddress.ip_address(a.split("%")[0]).is_global:
            raise UnsafeURL("refusing to fetch a non-public address")
    return host, p.scheme, port


def fetch_public_html(url: str, user_agent: str, timeout: float = 8.0) -> Tuple[Optional[str], str, Optional[str]]:
    """Return (html_text or None, final_url, error)."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            check_public_url(current)
        except UnsafeURL as exc:
            return None, current, str(exc)
        try:
            with requests.get(current, headers={"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml"},
                              stream=True, timeout=timeout, allow_redirects=False) as r:
                if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                    current = urljoin(current, r.headers["Location"])
                    continue
                if not 200 <= r.status_code < 300:
                    return None, current, f"HTTP {r.status_code}"
                ctype = r.headers.get("Content-Type", "").lower()
                if "html" not in ctype:
                    return None, current, "not an HTML page"
                total, chunks = 0, []
                for chunk in r.iter_content(65536):
                    total += len(chunk)
                    if total > MAX_BYTES:
                        break                       # a truncated page is fine for link extraction
                    chunks.append(chunk)
                return b"".join(chunks).decode(r.encoding or "utf-8", errors="replace"), current, None
        except requests.RequestException as exc:
            return None, current, f"{exc.__class__.__name__}"
    return None, current, "too many redirects"
