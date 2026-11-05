"""GLOBALWATCH - international OSINT news watch (security, military readiness, cyber, conflict).

Ported and extended from the standalone ``global_watch.py`` script.  It reads public, keyless Google News
RSS search results, classifies each headline by severity, country and region, and stores the events as
findings/entities so they appear in the graph, timeline, map-free reports and correlation like any other module.

Headline keyword classification is a *triage aid*, not an assessment: confidence is deliberately low and every
event links back to the original article for verification.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..models import ModuleResult
from ..utils import clean_text, safe_xml_fromstring
from .base import OFFLINE_SOURCE, Module, ModuleContext

SOURCE = "Google News RSS"

CATEGORIES: Dict[str, str] = {
    "AFRICAN SECURITY": "Africa attack OR militants OR insurgents OR terrorism",
    "MILITARY READINESS": "military readiness OR emergency preparedness OR mobilisation",
    "CYBERSECURITY": "cyberattack OR ransomware OR critical infrastructure hack",
    "CONFLICT & CRISIS": "conflict OR airstrike OR ceasefire OR coup",
}

HIGH_WORDS = [
    "attack", "killed", "dead", "death", "bomb", "explosion", "airstrike", "massacre", "kidnap", "abduct",
    "hostage", "coup", "invasion", "missile", "ransomware", "breach", "shutdown", "casualt", "assault", "ambush",
]
MEDIUM_WORDS = [
    "warn", "threat", "tension", "campaign", "preparedness", "readiness", "exercise", "deploy", "mobilis",
    "mobiliz", "sanction", "alert", "investigat", "protest", "ceasefire", "talks",
]

COUNTRIES = [
    "Nigeria", "Niger", "Mali", "Burkina Faso", "Chad", "Cameroon", "Sudan", "South Sudan", "Somalia", "Ethiopia",
    "Kenya", "Uganda", "Mozambique", "Democratic Republic of Congo", "DR Congo", "DRC", "Libya", "Egypt", "Algeria",
    "Tunisia", "Morocco", "Ghana", "Senegal", "Ivory Coast", "South Africa", "Zimbabwe", "Ukraine", "Russia",
    "Israel", "Gaza", "Palestine", "Lebanon", "Syria", "Iran", "Iraq", "Yemen", "Turkey", "China", "Taiwan",
    "North Korea", "South Korea", "Japan", "India", "Pakistan", "Afghanistan", "United Kingdom", "UK", "Britain",
    "United States", "US", "USA", "Canada", "France", "Germany", "Poland", "Italy", "Spain", "Netherlands", "Sweden",
    "Finland", "Norway", "Australia", "Brazil", "Mexico", "Venezuela", "Philippines", "Myanmar",
]
COUNTRY_ALIASES = {
    "UK": "United Kingdom", "Britain": "United Kingdom", "US": "United States", "USA": "United States",
    "DRC": "Democratic Republic of Congo", "DR Congo": "Democratic Republic of Congo", "Gaza": "Palestine",
}
REGIONS = [
    "Borno", "Yobe", "Adamawa", "Kaduna", "Zamfara", "Katsina", "Sokoto", "Kebbi", "Niger State", "Plateau", "Benue",
    "Kogi", "Lagos", "Abuja", "Niger Delta", "Kano", "Bauchi", "Taraba",
    "Sahel", "Darfur", "Tigray", "Kivu", "Cabo Delgado", "Donbas", "Crimea", "Kharkiv", "Kherson", "West Bank",
    "Red Sea", "Idlib",
]
_NIGERIA = ["Borno", "Yobe", "Adamawa", "Kaduna", "Zamfara", "Katsina", "Sokoto", "Kebbi", "Niger State", "Plateau",
            "Benue", "Kogi", "Lagos", "Abuja", "Niger Delta", "Kano", "Bauchi", "Taraba"]
REGION_TO_COUNTRY: Dict[str, str] = {r: "Nigeria" for r in _NIGERIA}
REGION_TO_COUNTRY.update({
    "Darfur": "Sudan", "Tigray": "Ethiopia", "Kivu": "Democratic Republic of Congo", "Cabo Delgado": "Mozambique",
    "Donbas": "Ukraine", "Crimea": "Ukraine", "Kharkiv": "Ukraine", "Kherson": "Ukraine", "West Bank": "Palestine",
    "Idlib": "Syria",
})

# Short all-caps abbreviations must match case-sensitively, otherwise the pronoun "us" becomes "United States".
CASE_SENSITIVE = {"US", "UK", "USA", "DRC"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
PLACE_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{1,59}$")
WIDTH = 52
LINE = "=" * WIDTH


# --------------------------------------------------------------------------- analysis (pure functions)
def split_title_source(raw_title: str) -> Tuple[str, Optional[str]]:
    """Google News titles look like 'Headline - Source'."""
    if " - " in raw_title:
        headline, source = raw_title.rsplit(" - ", 1)
        return headline.strip(), source.strip()
    return raw_title.strip(), None


def find_term(text: str, terms: Sequence[str]) -> Optional[str]:
    """First term found as a whole word/phrase, longest first."""
    for term in sorted(terms, key=len, reverse=True):
        flags = 0 if term in CASE_SENSITIVE else re.IGNORECASE
        if re.search(rf"\b{re.escape(term)}\b", text, flags=flags):
            return term
    return None


def classify_severity(text: str) -> str:
    low = text.lower()
    if any(w in low for w in HIGH_WORDS):
        return "HIGH"
    if any(w in low for w in MEDIUM_WORDS):
        return "MEDIUM"
    return "LOW"


def build_event(category: str, raw_title: str, link: str, published: datetime, countries: Sequence[str] = COUNTRIES,
                regions: Sequence[str] = REGIONS, region_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    region_map = REGION_TO_COUNTRY if region_map is None else region_map
    headline, source = split_title_source(raw_title)
    region = find_term(headline, regions)
    # Remove the region phrase first so that e.g. "Niger Delta" is not read as the country "Niger".
    scrubbed = re.sub(rf"\b{re.escape(region)}\b", " ", headline, flags=re.IGNORECASE) if region else headline
    country = find_term(scrubbed, countries)
    if country:
        country = COUNTRY_ALIASES.get(country, country)
    elif region in region_map:
        country = region_map[region]
    return {"severity": classify_severity(headline), "category": category, "country": country or "Unknown",
            "region": region, "event": headline, "source": source, "link": link, "published": published}


def matches_filters(ev: Dict[str, Any], country: Optional[str], state: Optional[str]) -> bool:
    text = ev["event"].lower()
    if state and state.lower() not in text:
        return False
    if country:
        c = country.lower()
        if c not in text and ev["country"].lower() != c:
            return False
    return True


def dedupe(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for ev in events:
        key = re.sub(r"\W+", "", ev["event"].lower())[:60]
        if key not in seen:
            seen.add(key)
            out.append(ev)
    return out


def select_events(raw: List[Tuple[str, str, str, datetime]], country: Optional[str], state: Optional[str],
                  min_severity: str, per_category: int) -> List[Dict[str, Any]]:
    """Classify, filter, sort (severity then recency) and cap per category."""
    countries, regions, region_map = list(COUNTRIES), list(REGIONS), dict(REGION_TO_COUNTRY)
    if country and country not in countries:
        countries.append(country)
    if state and state not in regions:
        regions.append(state)
        if country:
            region_map.setdefault(state, country)
    events = dedupe([build_event(c, t, l, p, countries, regions, region_map) for c, t, l, p in raw])
    events = [e for e in events if matches_filters(e, country, state)]
    floor = SEVERITY_ORDER[min_severity]
    events = [e for e in events if SEVERITY_ORDER[e["severity"]] <= floor]
    events.sort(key=lambda e: (SEVERITY_ORDER[e["severity"]], -e["published"].timestamp()))
    counts: Dict[str, int] = {}
    final = []
    for ev in events:
        counts[ev["category"]] = counts.get(ev["category"], 0) + 1
        if counts[ev["category"]] <= per_category:
            final.append(ev)
    return final


def parse_rss_items(xml_bytes: bytes, category: str, days: int, limit: int) -> List[Tuple[str, str, str, datetime]]:
    root = safe_xml_fromstring(xml_bytes)
    if root is None:
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    items: List[Tuple[str, str, str, datetime]] = []
    for item in root.iter("item"):
        title = clean_text((item.findtext("title") or "").strip(), 400)
        link = (item.findtext("link") or "").strip()
        if not title:
            continue
        pub = item.findtext("pubDate")
        try:
            published = parsedate_to_datetime(pub) if pub else datetime.now(timezone.utc)
        except (TypeError, ValueError):
            published = datetime.now(timezone.utc)
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        if published < cutoff:
            continue
        items.append((category, title, link if link.startswith(("https://", "http://")) else "", published))
        if len(items) >= limit:
            break
    return items


def format_report(events: List[Dict[str, Any]], country: Optional[str] = None, state: Optional[str] = None,
                  show_links: bool = False) -> str:
    """Plain-text report in the same layout as the original global_watch.py."""
    out = [LINE, "GLOBAL WATCH 2026".center(WIDTH).rstrip(), "INTERNATIONAL OSINT".center(WIDTH).rstrip(),
           f"Generated: {datetime.now().strftime('%d %b %Y %H:%M')}".center(WIDTH).rstrip(), LINE, ""]
    if country or state:
        out += [f"Filter: {', '.join(p for p in (state, country) if p)}", ""]
    if not events:
        out += ["No events found. Check your internet connection, widen --days, or lower --min-severity.", ""]
    for ev in events:
        out += [f"[{ev['severity']}] {ev['category']}", f"Country: {ev['country']}"]
        if ev["region"]:
            out.append(f"Region: {ev['region']}")
        out.append(f"Event: {ev['event']}")
        if ev["source"]:
            out.append(f"Source: {ev['source']}")
        if show_links and ev["link"]:
            out.append(f"Link: {ev['link']}")
        out.append("")
    counts: Dict[str, int] = {}
    for ev in events:
        counts[ev["severity"]] = counts.get(ev["severity"], 0) + 1
    out += [LINE, f"TOTAL EVENTS: {len(events)}"]
    out += [f"{lvl}: {counts[lvl]}" for lvl in ("HIGH", "MEDIUM", "LOW") if lvl in counts]
    out.append(LINE)
    return "\n".join(out)


# --------------------------------------------------------------------------- module
class GlobalWatch(Module):
    name = "GLOBALWATCH"
    description = ("International OSINT news watch: security, military readiness, cyber and conflict headlines "
                   "classified by severity, country and region. Query: a country, 'Country | State', or 'global'.")
    accepts = ("place", "text")
    api_options = ("state", "days", "max_per_category", "min_severity")

    def run(self, query: str, ctx: ModuleContext, state: Optional[str] = None, days: Any = 3,
            max_per_category: Any = 3, min_severity: str = "MEDIUM", **options: Any) -> ModuleResult:
        q = clean_text(query, 200).strip()
        res = ModuleResult(self.name, q or "global", offline=ctx.settings.offline_mode)
        country: Optional[str] = None
        if "|" in q:
            left, _, right = q.partition("|")
            country, state = left.strip() or None, (right.strip() or state)
        elif q.lower() not in ("", "global", "world", "*"):
            country = q
        try:
            days, per_cat = int(days), int(max_per_category)
        except (TypeError, ValueError):
            return res.fail("days and max_per_category must be whole numbers")
        min_severity = str(min_severity).upper()
        if not 1 <= days <= 30 or not 1 <= per_cat <= 10:
            return res.fail("days must be 1-30 and max_per_category 1-10")
        if min_severity not in SEVERITY_ORDER:
            return res.fail("min_severity must be LOW, MEDIUM or HIGH")
        for label, val in (("country", country), ("state", state)):
            if val and not PLACE_RE.match(val):
                return res.fail(f"{label} may contain only letters, spaces, '.', apostrophes and hyphens (2-60 chars)")

        raw, errors = self._collect(ctx, days, per_cat, country, state)
        if errors and not raw and len(errors) >= (1 if ctx.settings.offline_mode else len(CATEGORIES)):
            return res.fail("news feed unavailable: " + "; ".join(sorted(set(errors.values())))[:200])
        res.warnings += [f"could not fetch '{c}': {e}" for c, e in errors_items(errors)]
        events = select_events(raw, country, state, min_severity, per_cat)
        src = OFFLINE_SOURCE if ctx.settings.offline_mode else SOURCE
        res.raw = {"events": [{**e, "published": e["published"].isoformat(timespec="seconds")} for e in events],
                   "country": country, "state": state}
        if not events:
            res.warnings.append("no matching events; widen days or lower min_severity")
            return res
        for ev in events:
            key = clean_text(ev["event"], 200)
            ref = ("event", key)
            res.add_entity("event", key, label=clean_text(ev["event"], 90),
                           attributes={"category": ev["category"], "severity": ev["severity"], "source": ev["source"],
                                       "url": ev["link"]})
            if ev["country"] != "Unknown":
                res.add_entity("country", ev["country"])
                res.relate(ref, ("country", ev["country"]), "occurred_in", src, 0.5)
            if ev["region"]:
                res.add_entity("place", ev["region"], attributes={"kind": "region"})
                res.relate(ref, ("place", ev["region"]), "occurred_in", src, 0.5)
                if ev["country"] != "Unknown":
                    res.relate(("place", ev["region"]), ("country", ev["country"]), "located_in", src, 0.7)
            where = ", ".join(p for p in (ev["region"], ev["country"] if ev["country"] != "Unknown" else None) if p)
            res.add_finding(
                ev["event"], f"{ev['category'].title()} | {where or 'location not stated'} | via {ev['source'] or 'unknown'}",
                SEVERITY_MAP[ev["severity"]], source=src, entity=ref, observed_at=ev["published"].isoformat(timespec="seconds"),
                quality=0.5, data={"url": ev["link"], "category": ev["category"], "country": ev["country"],
                                   "region": ev["region"], "publisher": ev["source"]})
        res.add_finding(f"Global Watch: {len(events)} event(s)", "Severity from headline keywords only - verify at the source.",
                        "info", source=src, quality=0.5)
        return res

    # ------------------------------------------------------------------
    def _collect(self, ctx: ModuleContext, days: int, per_cat: int, country: Optional[str], state: Optional[str]
                 ) -> Tuple[List[Tuple[str, str, str, datetime]], Dict[str, str]]:
        errors: Dict[str, str] = {}
        if ctx.settings.offline_mode:
            data = ctx.sample("sample_news.json")
            if not data:
                return [], {"sample": "bundled sample_news.json is missing"}
            now = datetime.now(timezone.utc)
            return [(d["category"], d["title"], d.get("link", ""), now) for d in data], errors
        raw: List[Tuple[str, str, str, datetime]] = []
        for category, query in CATEGORIES.items():
            place = " ".join(f'"{p}"' for p in (state, country) if p)
            full = f"{place} ({query})" if place else query
            r = ctx.http.get("https://news.google.com/rss/search",
                             params={"q": f"{full} when:{days}d", "hl": "en", "gl": "US", "ceid": "US:en"},
                             as_json=False, timeout=15)
            if not r.ok:
                errors[category] = r.error or "unavailable"
                continue
            items = parse_rss_items(r.text.encode("utf-8", "replace"), category, days, per_cat * 3)
            if not items and r.text.strip():
                errors[category] = "no parsable items"
            raw += items
        return raw, errors


def errors_items(errors: Dict[str, str]) -> List[Tuple[str, str]]:
    return sorted(errors.items())
