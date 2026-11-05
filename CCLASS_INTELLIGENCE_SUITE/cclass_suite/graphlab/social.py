"""Social-media style transforms built only on public, no-login sources.

What these do: recognise profile URLs, collect the profile links a website itself publishes, read the public
Gravatar profile an e-mail owner chose to publish, list handle variants, and describe a phone number's numbering plan.
What they do not do: log in, read private accounts or messages, look up who owns a phone number, or follow people.
A handle or link found this way is a *lead*, not proof of identity.
"""
from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from ..modules.socialintel import username_variants
from ..utils import clean_text
from . import netsafe

_HANDLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _first(parts: List[str], reserved: set) -> Optional[str]:
    return parts[0] if parts and parts[0].lower() not in reserved else None


def _at(parts: List[str]) -> Optional[str]:
    return parts[0][1:] if parts and parts[0].startswith("@") else None


def _seg(prefixes: Tuple[str, ...]):
    def f(parts: List[str]) -> Optional[str]:
        return parts[1] if len(parts) >= 2 and parts[0].lower() in prefixes else None
    return f


_RES_X = {"i", "home", "share", "intent", "search", "hashtag", "explore", "settings", "login", "messages", "notifications",
          "compose", "tos", "privacy", "about", "signup"}
_RES_IG = {"p", "reel", "reels", "explore", "stories", "accounts", "tv", "direct", "about", "legal"}
_RES_FB = {"profile.php", "pages", "groups", "watch", "sharer", "sharer.php", "share", "events", "marketplace", "plugins",
           "dialog", "login", "tr", "policies", "help", "gaming", "hashtag", "people", "public"}
_RES_TG = {"s", "joinchat", "share", "addstickers", "iv", "proxy", "socks", "login", "setlanguage"}
_RES_GEN = {"about", "login", "signup", "explore", "search", "settings", "help", "terms", "privacy", "features", "pricing",
            "topics", "marketplace", "sponsors", "orgs", "organizations", "enterprise", "collections", "trending", "notifications"}

# (host regex, platform, extractor(path_parts) -> handle)
SOCIAL_PATTERNS = [
    (r"^(?:www\.|mobile\.)?(?:x|twitter)\.com$", "X (Twitter)", lambda p: _first(p, _RES_X)),
    (r"^(?:www\.)?instagram\.com$", "Instagram", lambda p: _first(p, _RES_IG)),
    (r"^(?:www\.|m\.|web\.)?(?:facebook|fb)\.com$", "Facebook", lambda p: _first(p, _RES_FB)),
    (r"^(?:[a-z]{2,3}\.)?linkedin\.com$", "LinkedIn", _seg(("in", "company", "school"))),
    (r"^(?:www\.)?tiktok\.com$", "TikTok", _at),
    (r"^(?:www\.|m\.)?youtube\.com$", "YouTube", lambda p: _at(p) or _seg(("c", "user", "channel"))(p)),
    (r"^(?:t|telegram)\.me$", "Telegram", lambda p: _first(p, _RES_TG)),
    (r"^(?:www\.)?github\.com$", "GitHub", lambda p: _first(p, _RES_GEN)),
    (r"^(?:www\.)?gitlab\.com$", "GitLab", lambda p: _first(p, _RES_GEN)),
    (r"^(?:www\.|old\.)?reddit\.com$", "Reddit", _seg(("user", "u"))),
    (r"^(?:www\.)?medium\.com$", "Medium", _at),
    (r"^(?:www\.)?threads\.net$", "Threads", _at),
    (r"^bsky\.app$", "Bluesky", _seg(("profile",))),
    (r"^(?:www\.)?pinterest\.[a-z.]+$", "Pinterest", lambda p: _first(p, _RES_GEN | {"pin"})),
    (r"^(?:www\.)?snapchat\.com$", "Snapchat", _seg(("add",))),
    (r"^(?:www\.)?twitch\.tv$", "Twitch", lambda p: _first(p, _RES_GEN | {"directory", "videos"})),
    (r"^(?:www\.)?vk\.com$", "VK", lambda p: _first(p, _RES_GEN | {"away.php", "share.php"})),
    (r"^keybase\.io$", "Keybase", lambda p: _first(p, _RES_GEN)),
    (r"^dev\.to$", "Dev.to", lambda p: _first(p, _RES_GEN)),
    (r"^codeberg\.org$", "Codeberg", lambda p: _first(p, _RES_GEN)),
    (r"^news\.ycombinator\.com$", "Hacker News", None),
]
_COMPILED = [(re.compile(h, re.I), name, fn) for h, name, fn in SOCIAL_PATTERNS]


def parse_profile_url(url: str) -> Optional[Dict[str, str]]:
    """Return {platform, handle, url} for a recognised public profile URL, else None. No network access."""
    try:
        p = urlparse(url.strip())
    except ValueError:
        return None
    if p.scheme not in ("http", "https"):
        return None
    host = (p.hostname or "").lower()
    parts = [unquote(x) for x in p.path.split("/") if x]
    for rx, platform, fn in _COMPILED:
        if not rx.match(host):
            continue
        if platform == "Hacker News":
            from urllib.parse import parse_qs
            handle = (parse_qs(p.query).get("id") or [None])[0] if p.path.rstrip("/") == "/user" else None
        else:
            handle = fn(parts) if fn else None
        if handle and _HANDLE.match(handle.lstrip("@")):
            base = f"{p.scheme}://{host}{p.path}".rstrip("/")
            return {"platform": platform, "handle": handle.lstrip("@"),
                    "url": f"{base}?id={handle}" if platform == "Hacker News" else base}
    return None


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag in ("a", "link"):
            for k, v in attrs:
                if k == "href" and v and v.lower().startswith(("http://", "https://")):
                    self.hrefs.append(v.strip()[:500])


def extract_social_links(html: str, limit: int = 40) -> List[Dict[str, str]]:
    parser = _Links()
    try:
        parser.feed(html[:1_000_000])
    except Exception:  # noqa: BLE001 - malformed markup must not break a transform
        pass
    seen, out = set(), []
    for href in parser.hrefs:
        prof = parse_profile_url(href)
        if prof and prof["url"] not in seen:
            seen.add(prof["url"])
            out.append(prof)
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------------------- transforms
def _origin(node):
    return (node["type"], node["norm"])


def url_profile(node, ctx):
    from .transforms import Output
    out = Output()
    prof = parse_profile_url(node["value"])
    if not prof:
        out.error = "Not a recognised public profile URL (supported: X, Instagram, Facebook, LinkedIn, TikTok, YouTube, Telegram, GitHub, GitLab, Reddit, Medium, Threads, Bluesky, Pinterest, Snapchat, Twitch, VK, Keybase, Dev.to, Codeberg, Hacker News)"
        return out
    h = out.ent("username", prof["handle"], attrs={"platform": prof["platform"]})
    out.link(_origin(node), h, f"handle_on_{prof['platform']}", 0.7)
    return out


def domain_social_links(node, ctx):
    from .transforms import Output
    out = Output()
    host = node["value"]
    if ctx.settings.offline_mode:
        sample = (ctx.mctx.sample("sample_site_links.json") or {}).get(host.lower())
        if sample is None:
            out.error = "No offline sample for this domain (try demo-corp.example); online mode reads the site's own public page"
            return out
        links = [p for p in (parse_profile_url(u) for u in sample) if p]
    else:
        html, final, err = None, "", None
        for scheme in ("https", "http"):
            html, final, err = netsafe.fetch_public_html(f"{scheme}://{host}/", ctx.settings.user_agent, min(ctx.settings.http_timeout, 8))
            if html is not None:
                break
        if html is None:
            out.error = f"Could not read the site's public home page: {err}"
            return out
        links = extract_social_links(html)
    if not links:
        out.warnings.append("No links to known social platforms were found on the home page")
        return out
    for prof in links:
        u = out.ent("profile", prof["url"], label=f"{prof['platform']}: {prof['handle']}", attrs={"platform": prof["platform"]})
        h = out.ent("username", prof["handle"], attrs={"platform": prof["platform"]})
        out.link(_origin(node), u, "links_to", 0.8)
        out.link(u, h, f"handle_on_{prof['platform']}", 0.7)
    out.summary_notes.append(f"{len(links)} social profile link(s) published on the home page")
    return out


def email_gravatar(node, ctx):
    from .transforms import Output
    out = Output()
    email = node["value"].strip().lower()
    if ctx.settings.offline_mode:
        data = (ctx.mctx.sample("sample_gravatar.json") or {}).get(email)
    else:
        digest = hashlib.md5(email.encode("utf-8"), usedforsecurity=False).hexdigest()  # Gravatar's documented key
        r = ctx.mctx.http.get(f"https://en.gravatar.com/{digest}.json", timeout=min(ctx.settings.http_timeout, 8), max_bytes=200_000)
        if r.status == 404:
            out.error = "No public Gravatar profile for this address"
            return out
        if not r.ok or not isinstance(r.data, dict):
            out.error = f"Gravatar could not be checked ({r.error})"
            return out
        entries = r.data.get("entry") or []
        data = entries[0] if entries else None
    if not data:
        out.error = "No public Gravatar profile for this address"
        return out
    origin = _origin(node)
    name = clean_text(data.get("displayName") or "", 120)
    if name:
        out.link(origin, out.ent("person", name, attrs={"source": "Gravatar (published by the owner)"}), "published_name", 0.5)
    seen = set()
    for acct in (data.get("accounts") or [])[:20]:
        url = acct.get("url") if isinstance(acct, dict) else None
        if not isinstance(url, str) or url in seen or not url.lower().startswith(("http://", "https://")):
            continue
        seen.add(url)
        prof = parse_profile_url(url)
        u = out.ent("profile", url, label=(f"{prof['platform']}: {prof['handle']}" if prof else clean_text(acct.get("shortname") or url, 80)),
                    attrs={"platform": (prof or {}).get("platform") or acct.get("shortname", "")})
        out.link(origin, u, "linked_account", 0.7)
        if prof:
            out.link(u, out.ent("username", prof["handle"], attrs={"platform": prof["platform"]}), f"handle_on_{prof['platform']}", 0.7)
    for site in (data.get("urls") or [])[:10]:
        v = site.get("value") if isinstance(site, dict) else None
        if isinstance(v, str) and v.lower().startswith(("http://", "https://")) and v not in seen:
            seen.add(v)
            out.link(origin, out.ent("url", v), "published_website", 0.6)
    if not out.entities:
        out.error = "The Gravatar profile publishes no name, accounts or websites"
    return out


def username_variant_nodes(node, ctx):
    from .transforms import Output
    out = Output()
    variants = username_variants(node["value"])
    if not variants:
        out.error = "No separator-based variants for this handle"
        return out
    for v in variants[:12]:
        out.link(_origin(node), out.ent("username", v, attrs={"status": "unverified candidate"}), "possible_variant", 0.3)
    out.warnings.append("Variants are unverified candidates; check them with 'To public profiles' before treating them as leads")
    return out


# Longest-prefix match on a compact calling-code table (numbering plan region only).
CALLING_CODES = {
    "1": "United States / Canada (NANP)", "7": "Russia / Kazakhstan", "20": "Egypt", "27": "South Africa", "30": "Greece", "31": "Netherlands",
    "32": "Belgium", "33": "France", "34": "Spain", "36": "Hungary", "39": "Italy", "40": "Romania", "41": "Switzerland", "43": "Austria",
    "44": "United Kingdom", "45": "Denmark", "46": "Sweden", "47": "Norway", "48": "Poland", "49": "Germany", "51": "Peru", "52": "Mexico",
    "53": "Cuba", "54": "Argentina", "55": "Brazil", "56": "Chile", "57": "Colombia", "58": "Venezuela", "60": "Malaysia", "61": "Australia",
    "62": "Indonesia", "63": "Philippines", "64": "New Zealand", "65": "Singapore", "66": "Thailand", "81": "Japan", "82": "South Korea",
    "84": "Vietnam", "86": "China", "90": "Turkey", "91": "India", "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka", "95": "Myanmar",
    "98": "Iran", "212": "Morocco", "213": "Algeria", "216": "Tunisia", "218": "Libya", "220": "Gambia", "221": "Senegal", "223": "Mali",
    "224": "Guinea", "225": "Cote d'Ivoire", "226": "Burkina Faso", "227": "Niger", "228": "Togo", "229": "Benin", "231": "Liberia",
    "232": "Sierra Leone", "233": "Ghana", "234": "Nigeria", "235": "Chad", "236": "Central African Republic", "237": "Cameroon",
    "238": "Cabo Verde", "241": "Gabon", "242": "Congo", "243": "DR Congo", "244": "Angola", "249": "Sudan", "250": "Rwanda",
    "251": "Ethiopia", "252": "Somalia", "254": "Kenya", "255": "Tanzania", "256": "Uganda", "260": "Zambia", "263": "Zimbabwe",
    "264": "Namibia", "265": "Malawi", "267": "Botswana", "351": "Portugal", "353": "Ireland", "358": "Finland", "380": "Ukraine",
    "420": "Czechia", "880": "Bangladesh", "966": "Saudi Arabia", "971": "United Arab Emirates", "972": "Israel", "977": "Nepal",
}


def phone_region(node, ctx):
    from .transforms import Output
    out = Output()
    digits = re.sub(r"\D", "", node["value"])
    for n in (3, 2, 1):
        region = CALLING_CODES.get(digits[:n])
        if region:
            country = region.split(" / ")[0] if "NANP" not in region else "United States / Canada (NANP)"
            out.link(_origin(node), out.ent("country", country, attrs={"calling_code": "+" + digits[:n]}), "number_plan_region", 0.5)
            out.warnings.append("This is the numbering-plan region of the prefix; it does not show where the holder is or who they are")
            return out
    out.error = "Unknown country calling code (use international format, e.g. +234...)"
    return out
