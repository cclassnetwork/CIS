"""IPINTEL - IP classification, reverse DNS, ASN (Team Cymru DNS), RDAP allocation and public geolocation."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional, Tuple

from ..models import ModuleResult
from ..utils import clean_text
from .base import Module, ModuleContext, pick_source
from .rdap import event_date, names_by_role, rdap_lookup


def classify_ip(ip: ipaddress._BaseAddress) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return "reserved"
    return "global" if ip.is_global else "non-global"


def lookup_allowed(ctx: ModuleContext, ip: ipaddress._BaseAddress) -> bool:
    """Public addresses are looked up online; in offline mode only addresses present in the bundled sample set
    (which uses RFC 5737 documentation ranges) are looked up, and no network request is made."""
    if classify_ip(ip) == "global":
        return True
    return ctx.settings.offline_mode and ip.compressed in (ctx.sample("sample_ip_geo.json") or {})


def cymru_name(ip: ipaddress._BaseAddress) -> str:
    if ip.version == 4:
        return ".".join(reversed(ip.exploded.split("."))) + ".origin.asn.cymru.com"
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _asn_lookup(ctx: ModuleContext, ip: ipaddress._BaseAddress) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    if ctx.settings.offline_mode:
        row = (ctx.sample("sample_ip_geo.json") or {}).get(ip.compressed)
        if row and row.get("asn"):
            return {"asn": row["asn"], "prefix": row.get("prefix", ""), "as_name": row.get("as_name", ""),
                    "country": row.get("country_code", "")}, None
        return None, "no offline sample data"
    txt, err = ctx.dns.query(cymru_name(ip), "TXT")
    if not txt:
        return None, err or "no ASN mapping returned"
    fields = [f.strip() for f in txt[0].split("|")]
    if len(fields) < 3 or not fields[0].split():
        return None, "unparseable ASN response"
    asn = "AS" + fields[0].split()[0]
    info = {"asn": asn, "prefix": fields[1], "country": fields[2], "as_name": ""}
    name_txt, _ = ctx.dns.query(f"{asn}.asn.cymru.com", "TXT")
    if name_txt:
        parts = [f.strip() for f in name_txt[0].split("|")]
        if parts:
            info["as_name"] = clean_text(parts[-1], 150)
    return info, None


def _geo_lookup(ctx: ModuleContext, ip: ipaddress._BaseAddress) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if ctx.settings.offline_mode:
        row = (ctx.sample("sample_ip_geo.json") or {}).get(ip.compressed)
        return (row, None) if row else (None, "no offline sample data")
    res = ctx.http.get(f"https://ipwho.is/{ip.compressed}")
    if not res.ok or not isinstance(res.data, dict) or res.data.get("success") is False:
        return None, res.error or clean_text((res.data or {}).get("message"), 100) or "geolocation unavailable"
    d = res.data
    try:
        lat, lon = float(d.get("latitude")), float(d.get("longitude"))
    except (TypeError, ValueError):
        return None, "geolocation response lacked coordinates"
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None, "geolocation coordinates out of range"
    return {"country": clean_text(d.get("country"), 80), "country_code": clean_text(d.get("country_code"), 3),
            "region": clean_text(d.get("region"), 80), "city": clean_text(d.get("city"), 80),
            "lat": lat, "lon": lon}, None


class IpIntel(Module):
    name = "IPINTEL"
    description = "IP classification, reverse DNS, ASN, RDAP allocation and approximate public geolocation."
    accepts = ("ip",)

    def run(self, query: str, ctx: ModuleContext, **options: Any) -> ModuleResult:
        raw = query.strip()
        res = ModuleResult(self.name, raw, offline=ctx.settings.offline_mode)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return res.fail("not a valid IPv4/IPv6 address")
        ref = ("ip", ip.compressed)
        kind = classify_ip(ip)
        res.add_entity("ip", ip.compressed, attributes={"classification": kind, "version": ip.version})
        dns_src = pick_source(ctx, "DNS resolver")

        if not lookup_allowed(ctx, ip):
            res.add_finding(f"Non-public address ({kind})",
                            "This address is not routable on the public Internet, so no external lookups were made.",
                            source="User supplied", entity=ref, quality=0.99)
            return res

        # reverse DNS
        ptr, ptr_err = ctx.dns.reverse(ip.compressed)
        for host in ptr:
            host = host.rstrip(".").lower()
            res.add_entity("hostname", host)
            res.relate(ref, ("hostname", host), "reverse_dns", dns_src, 0.9)
        if ptr:
            res.add_finding("Reverse DNS", "PTR: " + ", ".join(h.rstrip('.') for h in ptr), source=dns_src, entity=ref)
        elif ptr_err and ptr_err not in ("NXDOMAIN",):
            res.warnings.append(f"reverse DNS: {ptr_err}")
        else:
            res.add_finding("No reverse DNS record", "", source=dns_src, entity=ref, quality=0.7)

        # ASN
        asn, asn_err = _asn_lookup(ctx, ip)
        asn_src = pick_source(ctx, "Team Cymru IP-to-ASN DNS")
        if asn:
            res.add_entity("asn", asn["asn"], label=f"{asn['asn']} {asn.get('as_name', '')}".strip(),
                           attributes={"name": asn.get("as_name"), "country": asn.get("country")})
            res.relate(ref, ("asn", asn["asn"]), "belongs_to_asn", asn_src, 0.9)
            if asn.get("prefix"):
                res.add_entity("network", asn["prefix"])
                res.relate(ref, ("network", asn["prefix"]), "in_network", asn_src, 0.9)
                res.relate(("network", asn["prefix"]), ("asn", asn["asn"]), "announced_by", asn_src, 0.9)
            res.add_finding(f"Announced by {asn['asn']}",
                            f"{asn.get('as_name') or 'unnamed AS'}; prefix {asn.get('prefix') or 'unknown'}.",
                            source=asn_src, entity=ref, data=asn)
        else:
            res.warnings.append(f"ASN lookup: {asn_err}")

        # RDAP
        rdap, rdap_err = rdap_lookup(ctx, "ip", ip.compressed)
        rdap_src = pick_source(ctx, "RDAP registry")
        if rdap:
            name = clean_text(rdap.get("name"), 100)
            orgs = names_by_role(rdap, "registrant", "administrative", "technical", "abuse")
            cidrs = []
            for c in rdap.get("cidr0_cidrs", []) or []:
                pre = c.get("v4prefix") or c.get("v6prefix")
                if pre and c.get("length") is not None:
                    cidrs.append(f"{pre}/{c['length']}")
            for cidr in cidrs[:3]:
                res.add_entity("network", cidr)
                res.relate(ref, ("network", cidr), "in_network", rdap_src, 0.95)
            for org in orgs[:2]:
                res.add_entity("organization", org)
                anchor = ("network", cidrs[0]) if cidrs else ref
                res.relate(anchor, ("organization", org), "owned_by", rdap_src, 0.8)
            summary = (f"Allocation {name or 'n/a'}; range {rdap.get('startAddress', '?')} - "
                       f"{rdap.get('endAddress', '?')}; country {clean_text(rdap.get('country'), 3) or 'n/a'}; "
                       f"holder {', '.join(orgs) or 'not disclosed'}.")
            res.add_finding("Registry allocation (RDAP)", summary, source=rdap_src, entity=ref,
                            observed_at=event_date(rdap, "last changed"),
                            data={"handle": rdap.get("handle"), "cidrs": cidrs})
        else:
            res.warnings.append(f"RDAP: {rdap_err}")

        # geolocation
        geo, geo_err = _geo_lookup(ctx, ip)
        geo_src = pick_source(ctx, "ipwho.is geolocation")
        if geo:
            place = ", ".join(p for p in (geo.get("city"), geo.get("country")) if p) or geo.get("country") or "Unknown"
            res.add_entity("place", place, attributes={"country_code": geo.get("country_code"),
                                                        "region": geo.get("region"), "source": "ip-geolocation"},
                           lat=geo["lat"], lon=geo["lon"], confidence=0.4)
            res.relate(ref, ("place", place), "located_in", geo_src, 0.4)
            res.add_finding(f"Approximate location: {place}",
                            "IP geolocation is statistical and often only accurate to the city or region; it does "
                            "not identify a person or a precise site.",
                            source=geo_src, entity=ref, lat=geo["lat"], lon=geo["lon"], quality=0.5,
                            data={"region": geo.get("region"), "country_code": geo.get("country_code")})
        else:
            res.warnings.append(f"geolocation: {geo_err}")
        return res
