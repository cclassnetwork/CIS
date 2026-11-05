"""Transforms: one-click expansions of a graph entity (the Maltego idea).

Two kinds:
  * module transforms wrap the suite's lawful public-source modules (DNS/RDAP/CT, IP geolocation,
    news watch, CVE data, ...). They use the same offline sample data in offline mode.
  * local transforms are pure functions of the entity text (e.g. email -> domain) and never touch the network.

NETWORKINTEL (active scanning) is deliberately NOT available as a transform.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import social
from ..utils import clean_text, normalise_value, valid_domain, valid_email, valid_ip
from .store import TYPES, GraphError, norm_of, validate_value

MAX_ENTITIES_PER_RUN = 150
Ref = Tuple[str, str]

_SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng", "com.au", "net.au",
    "org.au", "co.za", "org.za", "gov.za", "co.ke", "or.ke", "co.in", "com.br", "com.cn", "co.jp", "com.gh", "com.eg",
}


@dataclass
class Output:
    entities: List[Dict[str, Any]] = field(default_factory=list)   # {type, value, label, attrs, lat, lon}
    edges: List[Dict[str, Any]] = field(default_factory=list)      # {src:(t,v), dst:(t,v), label, confidence}
    warnings: List[str] = field(default_factory=list)
    summary_notes: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def ent(self, t: str, v: str, **kw: Any) -> Ref:
        self.entities.append({"type": t, "value": v, **kw})
        return (t, v)

    def link(self, src: Ref, dst: Ref, label: str, confidence: float = 0.8) -> None:
        self.edges.append({"src": src, "dst": dst, "label": label, "confidence": confidence})


@dataclass(frozen=True)
class Transform:
    id: str
    name: str
    description: str
    accepts: Tuple[str, ...]
    kind: str                       # "module" | "local"
    module: str = ""
    group: str = ""
    runner: Optional[Callable[[Dict[str, Any], Any], Output]] = field(default=None, compare=False, repr=False)

    def public(self) -> Dict[str, Any]:
        return {"id": self.id, "name": self.name, "description": self.description, "accepts": list(self.accepts),
                "kind": self.kind, "module": self.module, "group": self.group}


# ---------------------------------------------------------------------------- module wrapper
def _module_runner(module: str, alias: Dict[str, str]) -> Callable[[Dict[str, Any], Any], Output]:
    """alias maps the node's type to the type the module reports for its own input (hostname -> domain)."""

    def run(node: Dict[str, Any], ctx: Any) -> Output:
        from ..modules import REGISTRY
        out = Output()
        mod = REGISTRY.get(module)
        if mod is None or mod.requires_authorization or mod.cli_only:
            out.error = f"{module} is not available as a transform"
            return out
        res = mod.safe_run(node["value"], ctx.mctx)
        if not res.ok:
            out.error = res.error or f"{module} failed"
            return out
        out.warnings.extend(res.warnings[:5])
        me: Ref = (alias.get(node["type"], node["type"]), normalise_value(alias.get(node["type"], node["type"]), node["value"]))
        origin: Ref = (node["type"], node["norm"])

        def conv(ref: Any) -> Optional[Ref]:
            t, v = ref[0], str(ref[1])
            if t not in TYPES:
                t = "text"
            r = (t, norm_of(t, v)) if t != "text" else (t, v)
            return origin if r == me else r

        meta: Dict[Ref, Dict[str, Any]] = {}
        for e in res.entities:
            t = e.type if e.type in TYPES else "text"
            r = conv((e.type, e.value))
            if r == origin:
                continue
            attrs = dict(e.attributes or {})
            if e.lat is not None and e.lon is not None:
                attrs.update(lat=e.lat, lon=e.lon)
            out.entities.append({"type": t, "value": clean_text(e.value, 500), "label": clean_text(e.label or "", 200), "attrs": attrs})
            meta[r] = {}
        touched = set()
        for rel in res.relations:
            a, b = conv(rel.src), conv(rel.dst)
            if a and b and a != b:
                out.link(a, b, clean_text(rel.kind, 80), rel.confidence)
                touched.update((a, b))
        for r in meta:   # anything the module found but did not relate stays attached to the entity you expanded
            if r not in touched:
                out.link(origin, r, "related_to", 0.5)
        for f in res.findings[:5]:
            out.summary_notes.append(f"[{f.severity}] {clean_text(f.title, 160)}")
        return out

    return run


# ---------------------------------------------------------------------------- local transforms
def _email_domain(node: Dict[str, Any], ctx: Any) -> Output:
    out = Output()
    host = node["value"].rsplit("@", 1)[-1].lower()
    out.link((node["type"], node["norm"]), out.ent("domain", host), "at_domain", 1.0)
    return out


def _url_host(node: Dict[str, Any], ctx: Any) -> Output:
    out = Output()
    host = (urlparse(node["value"]).hostname or "").rstrip(".")
    if not host:
        out.error = "No host found in this URL"
        return out
    t = "ip" if valid_ip(host) else "domain"
    out.link((node["type"], node["norm"]), out.ent(t, host), "hosted_on", 1.0)
    return out


def _parent_domain(node: Dict[str, Any], ctx: Any) -> Output:
    out = Output()
    labels = node["value"].lower().rstrip(".").split(".")
    keep = 3 if ".".join(labels[-2:]) in _SECOND_LEVEL else 2
    if len(labels) <= keep:
        out.error = "Already a registrable domain"
        return out
    out.link((node["type"], node["norm"]), out.ent("domain", ".".join(labels[-keep:])), "subdomain_of", 1.0)
    return out


def _ip_network(node: Dict[str, Any], ctx: Any) -> Output:
    out = Output()
    ip = ipaddress.ip_address(node["value"])
    net = ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 48}", strict=False)
    out.link((node["type"], node["norm"]), out.ent("network", str(net)), "in_network", 1.0)
    return out


_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}"),
    "url": re.compile(r"https?://[^\s<>\"')\]]{3,300}", re.I),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "domain": re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.){1,6}[A-Za-z]{2,24}\b"),
    "hash": re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b"),
}


def _extract(node: Dict[str, Any], ctx: Any) -> Output:
    out = Output()
    text = node["value"][:20000] + "\n" + (node.get("notes") or "")[:5000]
    origin: Ref = (node["type"], node["norm"])
    seen: set = set()
    skip_domains: set = set()
    for t in ("email", "url", "ip", "cve", "hash", "domain"):
        for m in _PATTERNS[t].findall(text):
            v = m.rstrip(".,;:")
            try:
                v = validate_value(t, v)
            except GraphError:
                continue
            key = (t, norm_of(t, v))
            if t == "email":
                skip_domains.add(v.rsplit("@", 1)[-1].lower())
            elif t == "url":
                skip_domains.add((urlparse(v).hostname or "").lower())
            elif t == "domain" and key[1] in skip_domains:
                continue
            if key in seen:
                continue
            seen.add(key)
            out.link(origin, out.ent(t, v), "mentions", 0.6)
            if len(seen) >= MAX_ENTITIES_PER_RUN:
                out.warnings.append("Stopped after the per-run limit")
                return out
    if not seen:
        out.error = "No emails, URLs, IPs, domains, CVEs or hashes found in the text"
    return out


# ---------------------------------------------------------------------------- registry
_DOM = ("domain", "hostname")
TRANSFORMS: Dict[str, Transform] = {t.id: t for t in [
    Transform("domain.dns", "To DNS, name servers & registration", "A/AAAA/MX/NS records, registrar and certificate-transparency names (DOMAININTEL)",
              _DOM, "module", "DOMAININTEL", "Infrastructure", _module_runner("DOMAININTEL", {"hostname": "domain"})),
    Transform("ip.intel", "To ASN, network, owner & location", "Reverse DNS, ASN, network, organisation and geolocation (IPINTEL)",
              ("ip",), "module", "IPINTEL", "Infrastructure", _module_runner("IPINTEL", {})),
    Transform("email.intel", "To domain & mail servers", "Domain, MX servers and address checks (EMAILINTEL)",
              ("email",), "module", "EMAILINTEL", "Identity", _module_runner("EMAILINTEL", {})),
    Transform("username.profiles", "To public profiles", "Checks a short list of open public APIs for the username (SOCIALINTEL)",
              ("username",), "module", "SOCIALINTEL", "Social", _module_runner("SOCIALINTEL", {})),
    Transform("url.profile", "Profile URL to handle", "Recognises 20+ public profile URL formats and extracts the handle (no network)",
              ("url", "profile"), "local", "", "Social", social.url_profile),
    Transform("domain.social", "To social profiles the site links to", "Reads the home page the site itself publishes and collects its social links (public page only)",
              _DOM, "module", "", "Social", social.domain_social_links),
    Transform("email.gravatar", "To public Gravatar profile", "Name, linked accounts and websites the address owner chose to publish on Gravatar",
              ("email",), "module", "", "Social", social.email_gravatar),
    Transform("username.variants", "To possible handle variants", "Separator variants of a handle, marked unverified (no network)",
              ("username",), "local", "", "Social", social.username_variant_nodes),
    Transform("phone.region", "Phone to numbering-plan country", "Country of the calling-code prefix only; no owner lookup (no network)",
              ("phone",), "local", "", "Social", social.phone_region),
    Transform("place.geo", "To coordinates & country", "Geocodes a place name or reads coordinates (GEOINT)",
              ("place", "country"), "module", "GEOINT", "Location", _module_runner("GEOINT", {})),
    Transform("place.news", "To news & security events", "International OSINT news watch for the place (GLOBALWATCH)",
              ("place", "country"), "module", "GLOBALWATCH", "Location", _module_runner("GLOBALWATCH", {})),
    Transform("cve.details", "To CVE details & exploitation status", "Public CVE data and known-exploited status (THREATMONITOR)",
              ("cve",), "module", "THREATMONITOR", "Threat", _module_runner("THREATMONITOR", {})),
    Transform("email.to_domain", "Email to domain", "Splits the address (no network)", ("email",), "local", "", "Local", _email_domain),
    Transform("url.to_host", "URL to host", "Extracts the host name or IP (no network)", ("url",), "local", "", "Local", _url_host),
    Transform("domain.parent", "Subdomain to parent domain", "Naive registrable-domain guess using a short built-in list of second-level suffixes (no network)",
              _DOM, "local", "", "Local", _parent_domain),
    Transform("ip.network", "IP to enclosing network", "/24 for IPv4, /48 for IPv6 (no network)", ("ip",), "local", "", "Local", _ip_network),
    Transform("text.extract", "Extract entities from text", "Finds emails, URLs, IPs, domains, CVEs and hashes in a note (no network)",
              ("text", "event"), "local", "", "Local", _extract),
]}


def applicable(node_type: str) -> List[Transform]:
    return [t for t in TRANSFORMS.values() if node_type in t.accepts]


def run(transform_id: str, node: Dict[str, Any], ctx: Any) -> Output:
    t = TRANSFORMS.get(transform_id)
    if t is None:
        raise GraphError("Unknown transform")
    if node["type"] not in t.accepts:
        raise GraphError(f"'{t.name}' cannot run on a {TYPES[node['type']][0]}")
    out = t.runner(node, ctx)  # type: ignore[misc]
    if len(out.entities) > MAX_ENTITIES_PER_RUN:
        out.warnings.append(f"Showing the first {MAX_ENTITIES_PER_RUN} of {len(out.entities)} results")
        out.entities = out.entities[:MAX_ENTITIES_PER_RUN]
    return out
