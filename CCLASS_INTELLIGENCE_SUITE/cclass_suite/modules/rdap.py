"""RDAP helpers shared by DOMAININTEL and IPINTEL (public registration data only)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..utils import clean_text
from .base import ModuleContext


def vcard_fn(entity: Dict[str, Any]) -> Optional[str]:
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item and item[0] == "fn" and item[3]:
                return clean_text(item[3], 200)
    except (IndexError, TypeError, AttributeError):
        pass
    return None


def names_by_role(rdap: Dict[str, Any], *roles: str) -> List[str]:
    out: List[str] = []
    for ent in rdap.get("entities", []) or []:
        if not isinstance(ent, dict):
            continue
        if any(r in (ent.get("roles") or []) for r in roles):
            name = vcard_fn(ent)
            if name and name not in out:
                out.append(name)
    return out


def event_date(rdap: Dict[str, Any], action: str) -> Optional[str]:
    for ev in rdap.get("events", []) or []:
        if isinstance(ev, dict) and ev.get("eventAction", "").lower() == action:
            return clean_text(ev.get("eventDate"), 40) or None
    return None


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def rdap_lookup(ctx: ModuleContext, kind: str, key: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return (rdap_json, error).  ``kind`` is 'domain' or 'ip'."""
    if ctx.settings.offline_mode:
        if kind == "domain":
            data = (ctx.sample("sample_rdap.json") or {}).get(key.lower())
        else:
            data = ((ctx.sample("sample_ip_geo.json") or {}).get(key) or {}).get("rdap")
        return (data, None) if data else (None, "no offline sample data for this object")
    res = ctx.http.get(f"https://rdap.org/{kind}/{key}",
                       headers={"Accept": "application/rdap+json, application/json"})
    if res.ok and isinstance(res.data, dict):
        return res.data, None
    if res.not_found:
        return None, "not found in RDAP"
    return None, res.error or "RDAP unavailable"
