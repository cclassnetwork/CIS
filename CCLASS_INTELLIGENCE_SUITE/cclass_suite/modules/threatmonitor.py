"""THREATMONITOR - public cybersecurity feeds (CISA KEV, NVD, CISA advisories RSS), CVE lookup and watchlists."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..db import Database
from ..models import ModuleResult
from ..utils import clean_text
from .base import Module, ModuleContext

log = logging.getLogger("cclass.threat")

CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
FEED_SOURCES = {"kev": "CISA KEV catalog", "nvd": "NVD CVE API", "rss": "CISA advisories RSS"}


# --------------------------------------------------------------------------- parsers
def parse_kev(data: Any) -> List[Dict[str, Any]]:
    out = []
    for v in (data or {}).get("vulnerabilities", []) if isinstance(data, dict) else []:
        if not isinstance(v, dict) or not v.get("cveID"):
            continue
        ransomware = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        out.append({
            "external_id": v["cveID"], "cve_id": v["cveID"].upper(),
            "title": clean_text(f"{v['cveID']}: {v.get('vulnerabilityName', '')}", 300),
            "description": clean_text(f"{v.get('shortDescription', '')} Required action: {v.get('requiredAction', '')}", 2000),
            "severity": "critical" if ransomware else "high",
            "vendor": clean_text(v.get("vendorProject"), 100), "product": clean_text(v.get("product"), 100),
            "published_at": clean_text(v.get("dateAdded"), 30) or None,
            "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            "data": {"due_date": v.get("dueDate"), "known_ransomware_use": v.get("knownRansomwareCampaignUse"),
                     "actively_exploited": True},
        })
    return out


def parse_nvd(data: Any) -> List[Dict[str, Any]]:
    out = []
    for item in (data or {}).get("vulnerabilities", []) if isinstance(data, dict) else []:
        cve = (item or {}).get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        score, sev = None, "medium"
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore")
                rating = (cvss.get("baseSeverity") or m.get("baseSeverity") or "").lower()
                sev = rating if rating in ("low", "medium", "high", "critical") else sev
                break
        out.append({
            "external_id": cid, "cve_id": cid.upper(), "title": clean_text(f"{cid}: {desc[:140]}", 300),
            "description": clean_text(desc, 2000), "severity": sev, "vendor": None, "product": None,
            "published_at": clean_text(cve.get("published"), 30) or None,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            "data": {"cvss": score, "status": cve.get("vulnStatus")},
        })
    return out


def parse_rss(text: str) -> List[Dict[str, Any]]:
    try:
        import defusedxml.ElementTree as ET  # type: ignore
    except ImportError:
        if re.search(r"<!DOCTYPE|<!ENTITY", text, re.IGNORECASE):
            return []  # refuse DTD/entity constructs we cannot safely parse
        import xml.etree.ElementTree as ET  # noqa: S405
    try:
        root = ET.fromstring(text)
    except Exception:  # noqa: BLE001 - malformed feed
        return []
    out = []
    for item in root.iter("item"):
        title = clean_text((item.findtext("title") or "").strip(), 300)
        link = clean_text((item.findtext("link") or "").strip(), 500)
        if not title:
            continue
        desc = re.sub(r"<[^>]+>", " ", item.findtext("description") or "")
        pub = None
        raw = (item.findtext("pubDate") or "").strip()
        for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"):
            try:
                pub = datetime.strptime(raw, fmt).astimezone(timezone.utc).isoformat(timespec="seconds")
                break
            except ValueError:
                continue
        cves = CVE_IN_TEXT.findall(f"{title} {desc}")
        out.append({
            "external_id": link or title, "cve_id": cves[0].upper() if cves else None, "title": title,
            "description": clean_text(re.sub(r"\s+", " ", desc).strip(), 2000), "severity": "medium",
            "vendor": None, "product": None, "published_at": pub,
            "url": link if link.startswith("https://") else None, "data": {"cves": [c.upper() for c in cves[:10]]},
        })
    return out


# --------------------------------------------------------------------------- feed manager
class ThreatFeedManager:
    def __init__(self, db: Database, ctx: ModuleContext):
        self.db, self.ctx = db, ctx

    def refresh(self, only: Optional[List[str]] = None, offline_sample: bool = False) -> Dict[str, Any]:
        """Fetch all enabled feeds.  Failures are reported per feed and never raise."""
        settings = self.ctx.settings
        summary: Dict[str, Any] = {"feeds": {}, "new_alerts": 0, "matched": 0}
        use_sample = offline_sample or settings.offline_mode
        if use_sample:
            data = self.ctx.sample("sample_threat_feed.json")
            if data is None:
                summary["feeds"]["offline_sample"] = {"ok": False, "error": "sample feed missing", "new": 0}
            else:
                n = self._store("kev-sample", "Offline sample dataset", parse_kev(data))
                summary["feeds"]["offline_sample"] = {"ok": True, "error": None, "new": n}
                summary["new_alerts"] += n
        else:
            for name, cfg in settings.feeds.items():
                if only and name not in only:
                    continue
                if not cfg.get("enabled", True):
                    continue
                try:
                    items, err = self._fetch(cfg)
                except Exception as exc:  # noqa: BLE001
                    log.exception("feed %s crashed", name)
                    items, err = [], f"internal error: {exc.__class__.__name__}"
                n = self._store(name, FEED_SOURCES.get(cfg.get("type"), "NVD CVE API"), items) if not err else 0
                summary["feeds"][name] = {"ok": err is None, "error": err, "new": n}
                summary["new_alerts"] += n
        summary["matched"] = self.match_watchlists()
        self.db.log("feed_refresh", f"{summary['new_alerts']} new alert(s), {summary['matched']} watchlist match(es)")
        return summary

    def _fetch(self, cfg: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        http, ftype = self.ctx.http, cfg.get("type")
        if ftype == "kev":
            r = http.get(cfg["url"], timeout=30)
            return (parse_kev(r.data), None) if r.ok else ([], r.error)
        if ftype == "nvd":
            now = datetime.now(timezone.utc)
            start = now - timedelta(days=int(cfg.get("days", 3)))
            params = {"pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                      "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"), "resultsPerPage": 200}
            headers = {"apiKey": self.ctx.settings.nvd_api_key} if self.ctx.settings.nvd_api_key else None
            r = http.get(cfg["url"], params=params, headers=headers, timeout=30)
            return (parse_nvd(r.data), None) if r.ok else ([], r.error)
        if ftype == "rss":
            r = http.get(cfg["url"], as_json=False, timeout=30)
            if not r.ok:
                return [], r.error
            items = parse_rss(r.text)
            return (items, None) if items else ([], "feed contained no parsable items")
        return [], f"unknown feed type {ftype!r}"

    def _store(self, feed: str, source_name: str, items: List[Dict[str, Any]]) -> int:
        from ..scoring import source_defaults
        kind, url, rel = source_defaults(source_name)
        sid = self.db.ensure_source(source_name, kind=kind, url=url or None, reliability=rel)
        new = 0
        for it in items:
            _, created = self.db.upsert_alert(
                feed, it["external_id"], it["title"], it["description"], it["severity"], it.get("cve_id"),
                it.get("vendor"), it.get("product"), it.get("published_at"), it.get("url"), it.get("data"), sid)
            new += 1 if created else 0
        return new

    def match_watchlists(self) -> int:
        """Flag alerts matching active watchlists; returns the number of alerts whose match set changed."""
        lists = self.db.list_watchlists(active_only=True)
        if not lists:
            return 0
        changed = 0
        for alert in self.db.list_alerts(limit=5000):
            hay = " ".join(str(alert.get(k) or "") for k in ("title", "description", "vendor", "product", "cve_id")).lower()
            hits = sorted({f"{w['kind']}:{w['value']}" for w in lists
                           if w["kind"] in ("keyword", "product", "vendor", "cve", "domain") and w["value"].lower() in hay})
            if hits != sorted(alert["matched_watchlists"]):
                self.db.set_alert_matches(alert["id"], hits)
                changed += 1 if hits else 0
        return changed


# --------------------------------------------------------------------------- module (CVE / keyword lookup)
class ThreatMonitor(Module):
    name = "THREATMONITOR"
    description = "Look up a CVE or keyword in stored threat alerts (and NVD when online); manage public threat feeds."
    accepts = ("cve", "text")

    def run(self, query: str, ctx: ModuleContext, **options: Any) -> ModuleResult:
        q = clean_text(query, 200).strip()
        res = ModuleResult(self.name, q, offline=ctx.settings.offline_mode)
        if not q:
            return res.fail("empty query")
        if ctx.db is None:
            return res.fail("database unavailable")
        is_cve = bool(CVE_IN_TEXT.fullmatch(q))
        matches: List[Dict[str, Any]] = []
        if is_cve:
            row = ctx.db.get_alert_by_cve(q)
            matches = [row] if row else []
            if not matches and not ctx.settings.offline_mode:
                headers = {"apiKey": ctx.settings.nvd_api_key} if ctx.settings.nvd_api_key else None
                r = ctx.http.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                 params={"cveId": q.upper()}, headers=headers, timeout=30)
                if r.ok:
                    for it in parse_nvd(r.data):
                        matches.append({**it, "severity": it["severity"], "feed": "nvd-lookup"})
                else:
                    res.warnings.append(f"NVD lookup unavailable: {r.error}")
        else:
            matches = ctx.db.list_alerts(q=q, limit=25)
        if not matches:
            note = (f"'{q}' matched nothing in stored alerts" + ("" if ctx.settings.offline_mode else " or NVD")
                    + ". Try refreshing feeds.")
            if is_cve:  # a CVE that is unknown is itself worth recording; a keyword with no hits is just noise
                res.add_finding("No matching threat intelligence", note, source="User supplied", quality=0.4)
            else:
                res.warnings.append(note)
            return res
        for m in matches[:25]:
            cve = m.get("cve_id")
            ent = ("cve", cve) if cve else None
            if ent:
                res.add_entity("cve", cve, label=m["title"][:90],
                               attributes={"vendor": m.get("vendor"), "product": m.get("product")})
            src = "Offline sample dataset" if m.get("feed") == "kev-sample" else FEED_SOURCES.get(
                "kev" if str(m.get("feed", "")).startswith("cisa_kev") else "nvd" if "nvd" in str(m.get("feed", "")) else "rss",
                "NVD CVE API")
            res.add_finding(m["title"], m.get("description", ""), m.get("severity", "medium"), source=src,
                            entity=ent, observed_at=m.get("published_at"),
                            data={"url": m.get("url"), "vendor": m.get("vendor"), "product": m.get("product")})
            if m.get("vendor"):
                res.add_entity("organization", m["vendor"])
                if ent:
                    res.relate(ent, ("organization", m["vendor"]), "affects_vendor", src, 0.9)
        return res
