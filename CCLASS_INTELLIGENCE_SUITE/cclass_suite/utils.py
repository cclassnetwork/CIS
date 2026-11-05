"""Validation, normalisation, hashing, logging and a fail-soft HTTP client."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from .config import Settings
from .models import utcnow_iso  # noqa: F401  (re-exported for convenience)

log = logging.getLogger("cclass")

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})$"
)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,38}[A-Za-z0-9]$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
COORD_RE = re.compile(r"^\s*(-?\d{1,2}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*$")
MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def valid_email(value: str) -> bool:
    return bool(value) and len(value) <= 254 and bool(EMAIL_RE.match(value))


def valid_domain(value: str) -> bool:
    return bool(value) and bool(DOMAIN_RE.match(value.lower().rstrip(".")))


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def valid_username(value: str) -> bool:
    return bool(value) and bool(USERNAME_RE.match(value))


def parse_coordinates(value: str) -> Optional[tuple[float, float]]:
    m = COORD_RE.match(value or "")
    if not m:
        return None
    lat, lon = float(m.group(1)), float(m.group(2))
    if -90 <= lat <= 90 and -180 <= lon <= 180:
        return lat, lon
    return None


def detect_type(query: str) -> str:
    """Classify a free-text query into an entity type."""
    q = (query or "").strip()
    if not q:
        return "text"
    low = q.lower()
    if low.startswith(("http://", "https://")):
        return "url"
    if valid_email(q):
        return "email"
    if valid_ip(q):
        return "ip"
    try:
        ipaddress.ip_network(q, strict=False)
        if "/" in q:
            return "network"
    except ValueError:
        pass
    if CVE_RE.match(q):
        return "cve"
    if parse_coordinates(q):
        return "coordinates"
    if HASH_RE.match(q):
        return "hash"
    if MAC_RE.match(q):
        return "mac"
    if valid_domain(low):
        return "domain"
    if q.startswith("@") and valid_username(q[1:]):
        return "username"
    # A bare alphabetic word ("Lagos") is ambiguous, so it is treated as text (place / keyword search).
    # Handles with digits or ._- separators, or an explicit "@" prefix, are treated as usernames.
    if valid_username(q) and " " not in q and re.search(r"[\d._-]", q):
        return "username"
    return "text"


def normalise_value(entity_type: str, value: str) -> str:
    v = (value or "").strip()
    if entity_type in ("email", "domain", "hostname", "username", "cve", "hash", "mac"):
        v = v.lower()
        if entity_type in ("domain", "hostname"):
            v = v.rstrip(".")
        if entity_type == "mac":
            v = v.replace("-", ":")
        if entity_type == "cve":
            v = v.upper()
        return v
    if entity_type == "ip":
        try:
            return ipaddress.ip_address(v).compressed
        except ValueError:
            return v.lower()
    if entity_type == "asn":
        v = v.upper()
        return v if v.startswith("AS") else f"AS{v}"
    if entity_type in ("url",):
        return v
    return re.sub(r"\s+", " ", v).lower()


def clean_text(value: Any, limit: int = 2000) -> str:
    """Strip control characters and truncate text coming from external sources."""
    s = "" if value is None else str(value)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    return s[:limit]


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------
def hash_file(path: Path | str, chunk: int = 1 << 20) -> Dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()  # noqa: S324 (identification only)
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
def setup_logging(settings: Settings, console: bool = True) -> None:
    root = logging.getLogger("cclass")
    root.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    if getattr(root, "_cclass_configured", False):
        return
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    try:
        settings.logs_dir.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(settings.logs_dir / "cclass.log", maxBytes=2_000_000, backupCount=3)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        pass
    if console:
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        root.addHandler(ch)
    root._cclass_configured = True  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
@dataclass
class HttpResult:
    ok: bool
    status: Optional[int]
    data: Any
    text: str
    error: Optional[str]
    url: str

    @property
    def not_found(self) -> bool:
        return self.status == 404


class HttpClient:
    """Thin wrapper around ``requests`` that never raises and honours offline mode."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        as_json: bool = True,
        timeout: Optional[float] = None,
        max_bytes: int = 8 * 1024 * 1024,
    ) -> HttpResult:
        if self.settings.offline_mode:
            return HttpResult(False, None, None, "", "offline mode is enabled", url)
        if not url.lower().startswith(("http://", "https://")):
            return HttpResult(False, None, None, "", "only http(s) URLs are allowed", url)
        hdrs = {"User-Agent": self.settings.user_agent, "Accept": "application/json, text/*;q=0.8, */*;q=0.5"}
        if headers:
            hdrs.update(headers)
        try:
            with requests.get(
                url, params=params, headers=hdrs, stream=True,
                timeout=timeout or self.settings.http_timeout,
            ) as resp:
                total, chunks = 0, []
                for chunk in resp.iter_content(65536):
                    total += len(chunk)
                    if total > max_bytes:
                        return HttpResult(False, resp.status_code, None, "", "response exceeded size limit", url)
                    chunks.append(chunk)
                raw = b"".join(chunks)
                text = raw.decode(resp.encoding or "utf-8", errors="replace")
                status = resp.status_code
        except requests.RequestException as exc:
            log.warning("HTTP request failed for %s: %s", url, exc.__class__.__name__)
            return HttpResult(False, None, None, "", f"{exc.__class__.__name__}: {str(exc)[:160]}", url)
        except Exception as exc:  # noqa: BLE001 - never let an integration crash the platform
            log.exception("Unexpected HTTP error for %s", url)
            return HttpResult(False, None, None, "", f"unexpected error: {exc.__class__.__name__}", url)

        ok = 200 <= status < 300
        data = None
        err = None if ok else f"HTTP {status}"
        if ok and as_json:
            try:
                import json as _json

                data = _json.loads(text)
            except ValueError:
                ok, err = False, "response was not valid JSON"
        return HttpResult(ok, status, data, text, err, url)


def safe_xml_fromstring(data: bytes | str):
    """Parse XML from an untrusted source; refuses DTD/entity tricks even without defusedxml."""
    try:
        import defusedxml.ElementTree as ET  # type: ignore

        return ET.fromstring(data)
    except ImportError:
        raw = data if isinstance(data, str) else data.decode("utf-8", "replace")
        if re.search(r"<!DOCTYPE|<!ENTITY", raw, re.IGNORECASE):
            return None
        import xml.etree.ElementTree as ET2  # noqa: S405

        try:
            return ET2.fromstring(data)
        except ET2.ParseError:
            return None
    except Exception:  # noqa: BLE001 - malformed or hostile XML
        return None
