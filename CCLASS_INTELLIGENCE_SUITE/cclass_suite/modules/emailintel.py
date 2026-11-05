"""EMAILINTEL - e-mail syntax, DNS (MX / SPF / DMARC / DKIM) and public-source checks.

Only public DNS records and the e-mail owner's *public* Gravatar profile are
consulted.  The module never sends e-mail, never probes mail servers (no SMTP
VRFY / RCPT TO) and never queries breach corpora.
"""

from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from typing import Any, Dict, List, Optional

from ..models import ModuleResult
from ..utils import clean_text, valid_email
from .base import Module, ModuleContext, pick_source

ROLE_ACCOUNTS = {
    "admin", "administrator", "info", "support", "sales", "contact", "help", "billing", "abuse",
    "postmaster", "hostmaster", "webmaster", "security", "noreply", "no-reply", "root", "office",
    "hr", "jobs", "marketing", "press", "legal", "privacy", "team", "hello",
}
FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com",
    "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "zoho.com", "yandex.com",
}
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]


@lru_cache(maxsize=1)
def _disposable(path: str) -> frozenset:
    try:
        with open(path, encoding="utf-8") as fh:
            return frozenset(l.strip().lower() for l in fh if l.strip() and not l.startswith("#"))
    except OSError:
        return frozenset()


def analyze_spf(txt_records: List[str]) -> Dict[str, Any]:
    recs = [t.strip() for t in txt_records if t.strip().lower().startswith("v=spf1")]
    out: Dict[str, Any] = {"present": bool(recs), "count": len(recs), "all": None, "lookups": 0, "record": None}
    if not recs:
        return out
    rec = recs[0]
    out["record"] = rec
    for tok in rec.split()[1:]:
        t = tok.lower()
        m = re.fullmatch(r"([+\-~?]?)all", t)
        if m:
            out["all"] = m.group(1) or "+"
        elif t.startswith(("include:", "redirect=", "exists:")) or t in ("a", "mx", "ptr") \
                or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:")):
            out["lookups"] += 1
    return out


def analyze_dmarc(txt_records: List[str]) -> Dict[str, Any]:
    recs = [t.strip() for t in txt_records if t.strip().lower().startswith("v=dmarc1")]
    out: Dict[str, Any] = {"present": bool(recs), "policy": None, "subdomain_policy": None, "pct": 100,
                           "rua": None, "record": None}
    if not recs:
        return out
    out["record"] = recs[0]
    for part in recs[0].split(";"):
        if "=" not in part:
            continue
        k, v = (x.strip() for x in part.split("=", 1))
        k = k.lower()
        if k == "p":
            out["policy"] = v.lower()
        elif k == "sp":
            out["subdomain_policy"] = v.lower()
        elif k == "pct" and v.isdigit():
            out["pct"] = int(v)
        elif k == "rua":
            out["rua"] = v
    return out


class EmailIntel(Module):
    name = "EMAILINTEL"
    description = "E-mail syntax, DNS, MX, SPF, DKIM, DMARC and public Gravatar profile checks."
    accepts = ("email",)

    def run(self, query: str, ctx: ModuleContext, **options: Any) -> ModuleResult:
        email = query.strip().lower()
        res = ModuleResult(self.name, email, offline=ctx.settings.offline_mode)
        if not valid_email(email):
            return res.fail("invalid e-mail address syntax")
        local, domain = email.rsplit("@", 1)
        ref = ("email", email)
        policy_src = "Email syntax and policy checks"
        dns_src = pick_source(ctx, "DNS resolver")

        base = local.split("+", 1)[0]
        attrs: Dict[str, Any] = {
            "local_part": local, "domain": domain,
            "role_account": base in ROLE_ACCOUNTS,
            "free_provider": domain in FREE_PROVIDERS,
            "disposable": domain in _disposable(str(ctx.settings.sample_dir / "disposable_domains.txt")),
        }
        res.add_entity("email", email, attributes=attrs)
        res.add_entity("domain", domain)
        res.relate(ref, ("domain", domain), "at_domain", policy_src, 0.99)
        res.add_finding("E-mail address syntax is valid", f"{email} conforms to RFC 5322 address rules.",
                        source=policy_src, entity=ref, quality=0.99)
        if "+" in local:
            res.add_finding("Plus-addressing used", f"Mailbox is probably '{base}@{domain}'; the tag is a sub-address.",
                            source=policy_src, entity=ref, quality=0.7)
        if attrs["role_account"]:
            res.add_finding("Role-based account", f"'{base}' is a shared/functional mailbox, not an individual.",
                            "low", source=policy_src, entity=ref, quality=0.9)
        if attrs["free_provider"]:
            res.add_finding("Free mailbox provider", f"{domain} is a consumer webmail service.",
                            source=policy_src, entity=ref, quality=0.95)
        if attrs["disposable"]:
            res.add_finding("Disposable e-mail provider", f"{domain} is a known throw-away mail service.",
                            "medium", source=policy_src, entity=ref, quality=0.9)

        # ---- MX / address records
        mx, mx_err = ctx.dns.query(domain, "MX")
        mx_hosts: List[str] = []
        for rec in mx:
            parts = rec.split(None, 1)
            host = parts[1].strip().rstrip(".").lower() if len(parts) == 2 else ""
            if host:
                mx_hosts.append(host)
                res.add_entity("hostname", host)
                res.relate(("domain", domain), ("hostname", host), "mail_handled_by", dns_src, 0.95)
        a_recs, _ = ctx.dns.query(domain, "A")
        if mx_hosts:
            res.add_finding(f"{len(mx_hosts)} MX record(s) found", "Mail exchangers: " + ", ".join(mx_hosts),
                            source=dns_src, entity=("domain", domain), data={"mx": mx})
        elif mx and not mx_hosts:
            res.add_finding("Null MX published", f"{domain} declares that it does not accept e-mail.", "low",
                            source=dns_src, entity=("domain", domain))
        elif a_recs:
            res.add_finding("No MX record; address record fallback", "Mail would be delivered to the A record (RFC 5321).",
                            "low", source=dns_src, entity=("domain", domain))
        elif mx_err == "NXDOMAIN":
            res.add_finding("Domain does not exist", f"{domain} returned NXDOMAIN - the address cannot receive mail.",
                            "high", source=dns_src, entity=("domain", domain))
        else:
            reason = f" ({mx_err})" if mx_err else ""
            res.add_finding("No mail routing records found", f"No MX or address records for {domain}{reason}.",
                            "medium", source=dns_src, entity=("domain", domain), quality=0.6 if mx_err else 0.85)
            if mx_err:
                res.warnings.append(f"DNS: {mx_err}")

        # ---- SPF
        txt, _ = ctx.dns.query(domain, "TXT")
        spf = analyze_spf(txt)
        dom_ref = ("domain", domain)
        if not spf["present"]:
            res.add_finding("No SPF record", f"{domain} does not publish SPF; spoofing is easier.", "medium",
                            source=dns_src, entity=dom_ref)
        else:
            if spf["count"] > 1:
                res.add_finding("Multiple SPF records", "More than one v=spf1 record is a permanent error (RFC 7208).",
                                "medium", source=dns_src, entity=dom_ref)
            q = spf["all"]
            verdict = {"-": ("Strict SPF policy (-all)", "info"), "~": ("SPF soft-fail policy (~all)", "info"),
                       "?": ("SPF neutral policy (?all)", "low"),
                       "+": ("SPF permits any sender (+all)", "high"), None: ("SPF has no 'all' mechanism", "low")}[q]
            res.add_finding(verdict[0], f"Record: {clean_text(spf['record'], 300)}", verdict[1],
                            source=dns_src, entity=dom_ref, data=spf)
            if spf["lookups"] > 10:
                res.add_finding("SPF exceeds 10 DNS lookups", f"{spf['lookups']} lookup-causing terms; receivers may "
                                "return permerror.", "medium", source=dns_src, entity=dom_ref)

        # ---- DMARC
        dtxt, _ = ctx.dns.query(f"_dmarc.{domain}", "TXT")
        dmarc = analyze_dmarc(dtxt)
        if not dmarc["present"]:
            res.add_finding("No DMARC record", f"_dmarc.{domain} is not published.", "medium",
                            source=dns_src, entity=dom_ref)
        else:
            sev = {"none": "low", "quarantine": "info", "reject": "info"}.get(dmarc["policy"] or "", "low")
            res.add_finding(f"DMARC policy: {dmarc['policy'] or 'unspecified'}",
                            f"Record: {clean_text(dmarc['record'], 300)}", sev, source=dns_src, entity=dom_ref, data=dmarc)
            if dmarc["pct"] < 100:
                res.add_finding("DMARC applied to a subset of mail", f"pct={dmarc['pct']}.", "low",
                                source=dns_src, entity=dom_ref)
            if not dmarc["rua"]:
                res.add_finding("DMARC has no aggregate-report address", "No rua= tag.", "info",
                                source=dns_src, entity=dom_ref)
        res.entities[0].attributes.update({"spf": (spf["all"] or "none") if spf["present"] else "missing",
                                           "dmarc": dmarc["policy"] or ("missing" if not dmarc["present"] else "none")})

        # ---- DKIM (common selectors only; selectors are arbitrary so absence is not proof)
        def probe(sel: str) -> Optional[str]:
            recs, _ = ctx.dns.query(f"{sel}._domainkey.{domain}", "TXT")
            return sel if any("p=" in r.lower() or "v=dkim1" in r.lower() for r in recs) else None

        with ThreadPoolExecutor(max_workers=5) as pool:
            found = [s for s in pool.map(probe, DKIM_SELECTORS) if s]
        if found:
            res.add_finding("DKIM key(s) published", "Selectors found: " + ", ".join(found), source=dns_src, entity=dom_ref)
        else:
            res.add_finding("No DKIM key at common selectors",
                            "Selectors are arbitrary; this does not prove DKIM is absent.", "info",
                            source=dns_src, entity=dom_ref, quality=0.4)

        # ---- Gravatar (public profile the owner chose to publish)
        if ctx.settings.offline_mode:
            res.warnings.append("Gravatar lookup skipped in offline mode")
        else:
            digest = hashlib.md5(email.encode()).hexdigest()  # noqa: S324 - Gravatar's public identifier
            g = ctx.http.get(f"https://www.gravatar.com/{digest}.json")
            if g.ok and isinstance(g.data, dict) and g.data.get("entry"):
                entry = g.data["entry"][0]
                name = clean_text(entry.get("displayName") or entry.get("preferredUsername") or "", 120)
                url = clean_text(entry.get("profileUrl"), 300)
                prof = res.add_entity("profile", url or f"gravatar:{digest}", label=f"Gravatar {name}".strip())
                res.relate(ref, ("profile", prof.value), "has_profile", "Gravatar public profile", 0.9)
                res.add_finding("Public Gravatar profile exists", f"Display name: {name or 'n/a'}.",
                                source="Gravatar public profile", entity=ref, data={"profile_url": url})
                uname = clean_text(entry.get("preferredUsername"), 60)
                if uname:
                    res.add_entity("username", uname)
                    res.relate(ref, ("username", uname), "same_username", "Gravatar public profile", 0.7)
            elif g.not_found:
                res.add_finding("No public Gravatar profile", "", "info", source="Gravatar public profile",
                                entity=ref, quality=0.5)
            else:
                res.warnings.append(f"Gravatar unavailable: {g.error}")
        return res
