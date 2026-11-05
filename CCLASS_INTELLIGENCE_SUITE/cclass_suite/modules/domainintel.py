"""DOMAININTEL - DNS, RDAP registration data, certificate transparency and public sub-domain discovery.

All sources are public.  Sub-domain discovery is passive: names are taken from
certificate-transparency logs and only resolved through ordinary DNS queries.
No brute forcing, zone transfers or port scanning is performed.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import ModuleResult
from ..utils import clean_text, valid_domain
from .base import Module, ModuleContext, pick_source
from .rdap import event_date, names_by_role, parse_dt, rdap_lookup

SENSITIVE_HINTS = ("admin", "vpn", "dev", "staging", "stage", "test", "internal", "intranet", "backup",
                   "jenkins", "git", "db", "sql", "vault", "remote", "rdp", "ssh", "corp", "uat", "beta")


def parse_ct_rows(rows: Any, domain: str) -> Tuple[Set[str], Counter, int, bool]:
    """Extract (sub-domains, issuer counter, certificate count, wildcard_seen) from crt.sh style rows."""
    names: Set[str] = set()
    issuers: Counter = Counter()
    wildcard = False
    count = 0
    if not isinstance(rows, list):
        return names, issuers, 0, False
    for row in rows:
        if not isinstance(row, dict):
            continue
        count += 1
        issuer = clean_text(row.get("issuer_name"), 200)
        if issuer:
            org = next((p.split("=", 1)[1] for p in issuer.split(", ") if p.startswith("O=")), issuer)
            issuers[org] += 1
        for raw in str(row.get("name_value", "")).splitlines():
            n = raw.strip().lower()
            if n.startswith("*."):
                wildcard = True
                n = n[2:]
            if (n == domain or n.endswith("." + domain)) and valid_domain(n):
                names.add(n)
    return names, issuers, count, wildcard


class DomainIntel(Module):
    name = "DOMAININTEL"
    description = "DNS records, RDAP registration data, certificate transparency and passive sub-domain discovery."
    accepts = ("domain",)

    def run(self, query: str, ctx: ModuleContext, **options: Any) -> ModuleResult:
        domain = query.strip().lower().rstrip(".")
        res = ModuleResult(self.name, domain, offline=ctx.settings.offline_mode)
        if not valid_domain(domain):
            return res.fail("not a valid domain name")
        ref = ("domain", domain)
        res.add_entity("domain", domain)
        dns_src = pick_source(ctx, "DNS resolver")

        # ---------------- DNS
        records: Dict[str, List[str]] = {}
        errors: Dict[str, str] = {}
        for rtype in ("A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA"):
            recs, err = ctx.dns.query(domain, rtype)
            records[rtype] = recs
            if err:
                errors[rtype] = err
        nxdomain = any(e == "NXDOMAIN" for e in errors.values())
        if nxdomain:
            res.add_finding("Domain does not resolve (NXDOMAIN)", f"{domain} does not exist in DNS.", "medium",
                            source=dns_src, entity=ref)
        else:
            for ip in records["A"] + records["AAAA"]:
                try:
                    norm = ipaddress.ip_address(ip).compressed
                except ValueError:
                    continue
                res.add_entity("ip", norm)
                res.relate(ref, ("ip", norm), "resolves_to", dns_src, 0.95)
            if records["A"] or records["AAAA"]:
                res.add_finding("Address records", ", ".join(records["A"] + records["AAAA"]), source=dns_src,
                                entity=ref, data={"A": records["A"], "AAAA": records["AAAA"]})
            if records["NS"]:
                for ns in records["NS"]:
                    host = ns.rstrip(".").lower()
                    res.add_entity("hostname", host)
                    res.relate(ref, ("hostname", host), "name_server", dns_src, 0.95)
                res.add_finding(f"{len(records['NS'])} name server(s)", ", ".join(records["NS"]), source=dns_src, entity=ref)
            if records["MX"]:
                res.add_finding("Mail exchangers", "; ".join(records["MX"]), source=dns_src, entity=ref)
            if records["TXT"]:
                res.add_finding(f"{len(records['TXT'])} TXT record(s)",
                                " | ".join(clean_text(t, 120) for t in records["TXT"][:6]), source=dns_src, entity=ref)
            if not records["CAA"] and (records["A"] or records["AAAA"]):
                res.add_finding("No CAA record", "Any certificate authority may issue certificates for this name.",
                                "low", source=dns_src, entity=ref)
        for rtype, err in errors.items():
            if err not in ("NXDOMAIN",):
                res.warnings.append(f"DNS {rtype}: {err}")
                break

        # ---------------- RDAP
        rdap, rdap_err = rdap_lookup(ctx, "domain", domain)
        rdap_src = pick_source(ctx, "RDAP registry")
        if rdap:
            registrars = names_by_role(rdap, "registrar")
            reg = parse_dt(event_date(rdap, "registration"))
            exp = parse_dt(event_date(rdap, "expiration"))
            now = datetime.now(timezone.utc)
            for r in registrars[:1]:
                res.add_entity("organization", r, attributes={"role": "registrar"})
                res.relate(ref, ("organization", r), "registered_via", rdap_src, 0.9)
            statuses = [clean_text(s, 60) for s in (rdap.get("status") or [])][:6]
            res.add_finding("Registration data (RDAP)",
                            f"Registrar: {', '.join(registrars) or 'n/a'}; registered: {event_date(rdap, 'registration') or 'n/a'}; "
                            f"expires: {event_date(rdap, 'expiration') or 'n/a'}; status: {', '.join(statuses) or 'n/a'}.",
                            source=rdap_src, entity=ref, observed_at=event_date(rdap, "last changed"))
            if reg:
                age = (now - reg).days
                res.entities[0].attributes["age_days"] = age
                if age < 30:
                    res.add_finding("Newly registered domain", f"Registered {age} day(s) ago - recently created domains "
                                    "are over-represented in phishing and fraud infrastructure.", "medium",
                                    source=rdap_src, entity=ref, quality=0.9)
            if exp:
                left = (exp - now).days
                if left < 0:
                    res.add_finding("Registration has expired", f"Expired {-left} day(s) ago.", "high",
                                    source=rdap_src, entity=ref)
                elif left <= 30:
                    res.add_finding("Registration expires soon", f"Expires in {left} day(s).", "medium",
                                    source=rdap_src, entity=ref)
        else:
            res.warnings.append(f"RDAP: {rdap_err}")

        # ---------------- Certificate transparency
        ct_src = pick_source(ctx, "Certificate Transparency (crt.sh)")
        rows: Any = None
        if ctx.settings.offline_mode:
            rows = (ctx.sample("sample_ct.json") or {}).get(domain)
        else:
            r = ctx.http.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=25)
            if r.ok:
                rows = r.data
            else:
                res.warnings.append(f"certificate transparency unavailable: {r.error}")
        subs: Set[str] = set()
        if rows is not None:
            subs, issuers, certs, wildcard = parse_ct_rows(rows, domain)
            subs.discard(domain)
            if certs:
                top = ", ".join(f"{k} ({v})" for k, v in issuers.most_common(3))
                res.add_finding(f"{len(subs)} sub-domain name(s) in CT logs",
                                f"From {certs} certificate record(s). Issuers: {top or 'n/a'}."
                                + (" A wildcard certificate exists." if wildcard else ""),
                                source=ct_src, entity=ref, data={"subdomains": sorted(subs)[:200]})
            interesting = sorted(s for s in subs if any(h in s.split(".")[0] for h in SENSITIVE_HINTS))
            if interesting:
                res.add_finding("Sub-domains with sensitive-sounding names are publicly logged",
                                ", ".join(interesting[:15]), "low", source=ct_src, entity=ref, quality=0.7)
            limit = ctx.settings.subdomain_resolve_limit
            for i, sub in enumerate(sorted(subs)):
                res.add_entity("domain", sub, attributes={"discovered_via": "certificate transparency"})
                res.relate((("domain", sub)), ref, "subdomain_of", ct_src, 0.95)
                if i < limit:
                    a, _ = ctx.dns.query(sub, "A")
                    for ip in a:
                        try:
                            norm = ipaddress.ip_address(ip).compressed
                        except ValueError:
                            continue
                        res.add_entity("ip", norm)
                        res.relate(("domain", sub), ("ip", norm), "resolves_to", dns_src, 0.9)
            if len(subs) > limit:
                res.warnings.append(f"only the first {limit} of {len(subs)} sub-domains were resolved")
        res.raw = {"records": records}
        return res
