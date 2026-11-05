"""Source reliability ratings and confidence scoring.

Reliability follows the familiar A-F admiralty-style scale.  Confidence is an
explainable number in [0, 0.99]:

* a single observation scores ``reliability_weight * quality``
* independent corroborating observations combine as ``1 - prod(1 - c_i)``
* older observations decay with a configurable half-life, floored at 60 %.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Iterable, Optional, Tuple

RELIABILITY_WEIGHT: Dict[str, float] = {
    "A": 1.00,  # completely reliable (authoritative registry / official feed)
    "B": 0.85,  # usually reliable
    "C": 0.65,  # fairly reliable
    "D": 0.45,  # not usually reliable
    "E": 0.25,  # unreliable
    "F": 0.40,  # reliability cannot be judged (sample data, unknown origin)
}

RELIABILITY_LABEL: Dict[str, str] = {
    "A": "Completely reliable", "B": "Usually reliable", "C": "Fairly reliable",
    "D": "Not usually reliable", "E": "Unreliable", "F": "Cannot be judged",
}

# name -> (kind, url, reliability)
DEFAULT_SOURCES: Dict[str, Tuple[str, str, str]] = {
    "DNS resolver": ("dns", "", "B"),
    "Team Cymru IP-to-ASN DNS": ("dns", "https://team-cymru.com/community-services/ip-asn-mapping/", "B"),
    "RDAP registry": ("registry", "https://rdap.org", "A"),
    "Certificate Transparency (crt.sh)": ("ct-log", "https://crt.sh", "B"),
    "ipwho.is geolocation": ("geoip", "https://ipwho.is", "C"),
    "Gravatar public profile": ("profile", "https://gravatar.com", "B"),
    "Email syntax and policy checks": ("analysis", "", "A"),
    "Public profile probe": ("profile", "", "D"),
    "GitHub public API": ("api", "https://api.github.com", "B"),
    "CISA KEV catalog": ("threat-feed", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "A"),
    "NVD CVE API": ("threat-feed", "https://nvd.nist.gov/developers/vulnerabilities", "A"),
    "CISA advisories RSS": ("threat-feed", "https://www.cisa.gov/news-events/cybersecurity-advisories", "B"),
    "Bundled gazetteer": ("dataset", "", "B"),
    "OpenStreetMap Nominatim": ("geocoder", "https://nominatim.openstreetmap.org", "C"),
    "Google News RSS": ("news", "https://news.google.com", "C"),
    "Local file metadata": ("file", "", "C"),
    "Local file hashing": ("file", "", "A"),
    "Local network observation": ("network", "", "B"),
    "Offline sample dataset": ("sample", "", "F"),
    "Correlation engine": ("analysis", "", "C"),
    "User supplied": ("user", "", "C"),
}


def reliability_weight(rating: str) -> float:
    return RELIABILITY_WEIGHT.get((rating or "F").upper(), RELIABILITY_WEIGHT["F"])


def source_defaults(name: str) -> Tuple[str, str, str]:
    return DEFAULT_SOURCES.get(name, ("public", "", "C"))


def age_factor(observed_at: Optional[str], half_life_days: float = 365.0) -> float:
    if not observed_at:
        return 1.0
    try:
        ts = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        return 1.0
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age_days = max(0.0, (datetime.now(timezone.utc) - ts).total_seconds() / 86400)
    return max(0.6, 0.5 ** (age_days / half_life_days))


def finding_confidence(reliability: str, quality: float = 0.85, observed_at: Optional[str] = None) -> float:
    quality = min(1.0, max(0.0, quality))
    score = reliability_weight(reliability) * quality * age_factor(observed_at)
    return round(min(0.99, max(0.01, score)), 3)


def combine(confidences: Iterable[float]) -> float:
    """Combine independent confidences: 1 - prod(1 - c)."""
    remaining = 1.0
    for c in confidences:
        remaining *= 1.0 - min(0.99, max(0.0, c))
    return round(min(0.99, 1.0 - remaining), 3)


def confidence_label(score: float) -> str:
    if score >= 0.8:
        return "High"
    if score >= 0.5:
        return "Medium"
    return "Low"
