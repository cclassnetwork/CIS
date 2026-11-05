"""Security primitives: password hashing, password policy, TOTP, tokens, RBAC.

Everything here is standard-library only and free of web-framework imports so it
can be unit-tested in isolation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from typing import List, Optional, Pattern, Tuple
from urllib.parse import quote

# ---------------------------------------------------------------------------
# Password hashing (scrypt)
# ---------------------------------------------------------------------------
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 128 * 1024 * 1024
_DKLEN = 32


def hash_password(password: str, *, n: int = _SCRYPT_N) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=_SCRYPT_R,
                        p=_SCRYPT_P, maxmem=_SCRYPT_MAXMEM, dklen=_DKLEN)
    return "scrypt${}${}${}${}${}".format(
        n, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n), r=int(r),
                            p=int(p), maxmem=_SCRYPT_MAXMEM, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


# A fixed dummy hash lets login spend the same time for unknown usernames.
_DUMMY_HASH = hash_password("dummy-password-for-timing", n=2 ** 14)


def burn_password_time(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


_COMMON = {
    "password", "password1", "password123", "123456789012", "qwertyuiop12",
    "administrator", "welcome12345", "letmein12345", "changeme1234", "cclass123456",
}


def check_password_policy(password: str, username: str = "") -> List[str]:
    """Return a list of human-readable problems (empty list = acceptable)."""
    problems: List[str] = []
    if not isinstance(password, str) or len(password) < 12:
        problems.append("must be at least 12 characters")
    if isinstance(password, str) and len(password) > 256:
        problems.append("must be at most 256 characters")
    if isinstance(password, str):
        classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
        if classes < 3:
            problems.append("must mix at least three of: lowercase, uppercase, digits, symbols")
        low = password.lower()
        if low in _COMMON:
            problems.append("is too common")
        if username and username.lower() in low:
            problems.append("must not contain the username")
        if len(set(password)) < 5:
            problems.append("is too repetitive")
    return problems


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# TOTP (RFC 6238 / RFC 4226) – 30 s step, 6 digits, HMAC-SHA1 (authenticator-app default)
# ---------------------------------------------------------------------------
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = 6, algo=hashlib.sha1) -> str:
    padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(padded)
    mac = hmac.new(key, struct.pack(">Q", counter), algo).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_at(secret_b32: str, for_time: Optional[float] = None, step: int = 30,
            digits: int = 6, algo=hashlib.sha1) -> str:
    t = time.time() if for_time is None else for_time
    return _hotp(secret_b32, int(t // step), digits, algo)


def totp_verify(secret_b32: str, code: str, *, for_time: Optional[float] = None,
                window: int = 1, step: int = 30) -> Optional[int]:
    """Return the matching time-step counter, or None. Accepts +/- ``window`` steps."""
    code = (code or "").strip().replace(" ", "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    t = time.time() if for_time is None else for_time
    base = int(t // step)
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret_b32, base + delta), code):
            return base + delta
    return None


def totp_uri(secret_b32: str, username: str, issuer: str = "CCLASS Intelligence Suite") -> str:
    label = quote(f"{issuer}:{username}")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"
            "&algorithm=SHA1&digits=6&period=30")


# ---------------------------------------------------------------------------
# Roles and RBAC
# ---------------------------------------------------------------------------
ROLES = ("viewer", "analyst", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}


def role_at_least(role: str, minimum: str) -> bool:
    return _RANK.get(role, -1) >= _RANK[minimum]


# (HTTP methods, compiled path regex, minimum role). First match wins.
# "AUTHED" = any signed-in user. Anything not matched requires admin (default-deny).
AUTHED = "viewer"
_READ = ("GET", "HEAD")
_ANY = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")


def _r(methods: Tuple[str, ...], pattern: str, role: str) -> Tuple[Tuple[str, ...], Pattern[str], str]:
    return (methods, re.compile(pattern), role)


RBAC_RULES = [
    # admin-only areas first so broader read rules cannot shadow them
    _r(_ANY, r"^/api/(users|audit|backups|retention)(/.*)?$", "admin"),
    _r(("POST", "PUT", "PATCH", "DELETE"), r"^/api/(settings|demo|sources)(/.*)?$", "admin"),
    _r(("GET",), r"^/api/settings$", "admin"),
    # session / profile endpoints – any signed-in user
    _r(_ANY, r"^/api/auth/(me|logout|password|totp(/.*)?)$", AUTHED),
    # read-only
    _r(_READ, r"^/api/.*$", "viewer"),
    # analyst actions
    _r(("POST", "PUT", "PATCH", "DELETE"), r"^/api/.*$", "analyst"),
]

PUBLIC_PATHS = ("/api/auth/login", "/api/auth/setup", "/api/auth/status", "/api/health")


def required_role(method: str, path: str) -> str:
    method = method.upper()
    for methods, rx, role in RBAC_RULES:
        if method in methods and rx.match(path):
            return role
    return "admin"


def is_public(path: str) -> bool:
    return path in PUBLIC_PATHS
