"""SOCIALINTEL - public username and profile research.

Only publicly reachable profile pages / public JSON APIs are queried, without
logging in, without following private accounts and without scraping content.
A matching handle is a *lead*, not proof of identity: confidence is therefore
deliberately low and the platform list is a small set of open APIs.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote, urlparse

from ..models import ModuleResult
from ..utils import HttpResult, clean_text, valid_username
from .base import Module, ModuleContext

FOUND, NOT_FOUND, UNKNOWN = "found", "not_found", "unknown"


@dataclass(frozen=True)
class Platform:
    name: str
    profile_url: str                     # human-facing page
    api_url: str                         # public endpoint used for the check
    check: Callable[[HttpResult], str]
    host: str = ""


def _status_check(res: HttpResult) -> str:
    if res.status == 200:
        return FOUND
    if res.status == 404:
        return NOT_FOUND
    return UNKNOWN


def _nonempty_list(res: HttpResult) -> str:
    if not res.ok:
        return UNKNOWN
    return FOUND if isinstance(res.data, list) and res.data else NOT_FOUND


def _hn(res: HttpResult) -> str:
    if res.status != 200:
        return UNKNOWN
    return FOUND if res.text.strip() not in ("", "null") else NOT_FOUND


def _keybase(res: HttpResult) -> str:
    if not res.ok or not isinstance(res.data, dict):
        return UNKNOWN
    them = res.data.get("them")
    return FOUND if isinstance(them, list) and them and them[0] else NOT_FOUND


def _wikipedia(res: HttpResult) -> str:
    if not res.ok or not isinstance(res.data, dict):
        return UNKNOWN
    users = (res.data.get("query") or {}).get("users") or []
    if not users:
        return UNKNOWN
    return NOT_FOUND if "missing" in users[0] or "invalid" in users[0] else FOUND


def _bluesky(res: HttpResult) -> str:
    if res.status == 200:
        return FOUND
    return NOT_FOUND if res.status == 400 else UNKNOWN


PLATFORMS: List[Platform] = [
    Platform("GitHub", "https://github.com/{u}", "https://api.github.com/users/{u}", _status_check),
    Platform("GitLab", "https://gitlab.com/{u}", "https://gitlab.com/api/v4/users?username={u}", _nonempty_list),
    Platform("Codeberg", "https://codeberg.org/{u}", "https://codeberg.org/api/v1/users/{u}", _status_check),
    Platform("Hacker News", "https://news.ycombinator.com/user?id={u}",
             "https://hacker-news.firebaseio.com/v0/user/{u}.json", _hn),
    Platform("Dev.to", "https://dev.to/{u}", "https://dev.to/api/users/by_username?url={u}", _status_check),
    Platform("Docker Hub", "https://hub.docker.com/u/{u}", "https://hub.docker.com/v2/users/{u}/", _status_check),
    Platform("Keybase", "https://keybase.io/{u}", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", _keybase),
    Platform("Lichess", "https://lichess.org/@/{u}", "https://lichess.org/api/user/{u}", _status_check),
    Platform("Mastodon (mastodon.social)", "https://mastodon.social/@{u}",
             "https://mastodon.social/api/v1/accounts/lookup?acct={u}", _status_check),
    Platform("Bluesky", "https://bsky.app/profile/{u}.bsky.social",
             "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social", _bluesky),
    Platform("Wikipedia (en)", "https://en.wikipedia.org/wiki/User:{u}",
             "https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={u}&format=json", _wikipedia),
    Platform("PyPI", "https://pypi.org/user/{u}/", "https://pypi.org/user/{u}/", _status_check),
]

_PROFILE_PATTERNS = [
    (re.compile(r"^(?:www\.)?github\.com$"), "GitHub", 1),
    (re.compile(r"^(?:www\.)?gitlab\.com$"), "GitLab", 1),
    (re.compile(r"^codeberg\.org$"), "Codeberg", 1),
    (re.compile(r"^dev\.to$"), "Dev.to", 1),
    (re.compile(r"^keybase\.io$"), "Keybase", 1),
    (re.compile(r"^hub\.docker\.com$"), "Docker Hub", 2),
]


def username_from_url(url: str) -> Optional[Dict[str, str]]:
    """Recognise a public profile URL on a supported platform and return its platform + username."""
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    parts = [p for p in parsed.path.split("/") if p]
    for pattern, platform, idx in _PROFILE_PATTERNS:
        if pattern.match(host) and len(parts) >= idx:
            cand = parts[idx - 1].lstrip("@")
            if valid_username(cand):
                return {"platform": platform, "username": cand}
    return None


def username_variants(username: str) -> List[str]:
    """Common handle variants (separator swaps) - lead generation only."""
    base = username.strip().lower()
    out = {base}
    for sep_from, sep_to in (("_", "."), (".", "_"), ("-", "_"), ("_", ""), (".", ""), ("-", "")):
        if sep_from in base:
            out.add(base.replace(sep_from, sep_to))
    return sorted(v for v in out if v != base and valid_username(v))


class SocialIntel(Module):
    name = "SOCIALINTEL"
    description = "Checks whether a username has a public profile on open platforms (no login, no private data)."
    accepts = ("username",)

    def run(self, query: str, ctx: ModuleContext, **options: Any) -> ModuleResult:
        username = query.strip().lstrip("@")
        res = ModuleResult(self.name, username, offline=ctx.settings.offline_mode)
        if not valid_username(username):
            return res.fail("username must be 3-40 characters: letters, digits, '.', '_' or '-'")
        ref = ("username", username.lower())
        res.add_entity("username", username.lower())

        if ctx.settings.offline_mode:
            sample = (ctx.sample("sample_social.json") or {}).get(username.lower(), {})
            if not sample:
                res.warnings.append("no offline sample data for this username (try 'demo_user')")
            hits = {n: (d["status"], d.get("url", ""), d.get("details", {})) for n, d in sample.items()}
            src = "Offline sample dataset"
        else:
            hits = self._probe_all(username, ctx)
            src = "Public profile probe"

        found = []
        for platform, (status, url, details) in sorted(hits.items()):
            if status == FOUND:
                found.append(platform)
                res.add_entity("profile", url, label=f"{platform}: {username}",
                               attributes={"platform": platform, **details})
                res.relate(ref, ("profile", url), "has_profile", src, 0.5)
            elif status == UNKNOWN:
                res.warnings.append(f"{platform}: could not be checked")
        if found:
            res.add_finding(f"Public profile handle found on {len(found)} platform(s)",
                            "Platforms: " + ", ".join(found) + ". A matching handle is a lead, not proof that the "
                            "accounts belong to the same person.", source=src, entity=ref, quality=0.45,
                            data={"platforms": found})
        else:
            res.add_finding("No public profiles found on checked platforms", f"{len(hits)} platform(s) checked.",
                            source=src, entity=ref, quality=0.4)
        variants = username_variants(username)
        if variants:
            res.add_finding("Possible handle variants", ", ".join(variants[:8]), source="User supplied", entity=ref,
                            quality=0.3)
        res.raw = {"checked": len(hits)}
        return res

    # ------------------------------------------------------------------
    def _probe_all(self, username: str, ctx: ModuleContext) -> Dict[str, tuple]:
        u = quote(username, safe="")

        def probe(p: Platform) -> tuple:
            r = ctx.http.get(p.api_url.format(u=u), timeout=min(ctx.settings.http_timeout, 8), max_bytes=1_000_000,
                             as_json=p.name not in ("Hacker News", "PyPI", "Codeberg"))
            status = p.check(r)
            if r.status in (403, 429) or (r.status is None):
                status = UNKNOWN
            details: Dict[str, Any] = {}
            if status == FOUND and p.name == "GitHub" and isinstance(r.data, dict):
                details = {k: r.data.get(k) for k in ("public_repos", "followers", "created_at")}
            return p.name, (status, p.profile_url.format(u=u), details)

        with ThreadPoolExecutor(max_workers=6) as pool:
            return dict(pool.map(probe, PLATFORMS))
