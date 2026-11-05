"""User accounts, login with lockout and optional TOTP, and server-side sessions."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from . import security
from .db import Database
from .models import utcnow_iso

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,39}$")
MAX_FAILED = 5
LOCK_MINUTES = 15
SESSION_IDLE_MINUTES = 60
SESSION_ABSOLUTE_HOURS = 12

PUBLIC_FIELDS = ("id", "username", "display_name", "role", "totp_enabled", "disabled",
                 "must_change_password", "created_at", "last_login", "locked_until")


class AccountError(ValueError):
    """Raised for invalid account operations; message is safe to show to the user."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def public(user: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if user is None:
        return None
    out = {k: user.get(k) for k in PUBLIC_FIELDS}
    out["totp_enabled"] = bool(out["totp_enabled"])
    out["disabled"] = bool(out["disabled"])
    out["must_change_password"] = bool(out["must_change_password"])
    return out


class AccountStore:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------ users
    def count(self) -> int:
        with self.db.connect() as c:
            return int(c.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def active_admins(self) -> int:
        with self.db.connect() as c:
            return int(c.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0])

    def create_user(self, username: str, password: str, role: str = "analyst",
                    display_name: str = "", must_change: bool = False) -> int:
        username = (username or "").strip()
        if not USERNAME_RE.match(username):
            raise AccountError("Username must be 3-40 characters: letters, digits, '.', '_' or '-'")
        if role not in security.ROLES:
            raise AccountError("Unknown role")
        problems = security.check_password_policy(password, username)
        if problems:
            raise AccountError("Password " + "; ".join(problems))
        with self.db.connect() as c:
            if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise AccountError("That username is already taken")
            cur = c.execute(
                "INSERT INTO users(username, display_name, password_hash, role, "
                "must_change_password, created_at) VALUES (?,?,?,?,?,?)",
                (username, (display_name or username).strip()[:80],
                 security.hash_password(password), role, int(must_change), utcnow_iso()))
            return int(cur.lastrowid)

    def get(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self.db.connect() as c:
            return self.db._row(c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())

    def get_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self.db.connect() as c:
            return self.db._row(c.execute(
                "SELECT * FROM users WHERE username=?", ((username or "").strip(),)).fetchone())

    def list_users(self) -> List[Dict[str, Any]]:
        with self.db.connect() as c:
            rows = c.execute("SELECT * FROM users ORDER BY username COLLATE NOCASE").fetchall()
        return [public(self.db._row(r)) for r in rows]  # type: ignore[misc]

    def _guard_last_admin(self, user: Dict[str, Any], new_role: str, new_disabled: bool) -> None:
        if user["role"] == "admin" and not user["disabled"]:
            if (new_role != "admin" or new_disabled) and self.active_admins() <= 1:
                raise AccountError("You cannot remove or disable the last active administrator")

    def update_user(self, user_id: int, *, role: Optional[str] = None,
                    disabled: Optional[bool] = None, display_name: Optional[str] = None) -> Dict[str, Any]:
        user = self.get(user_id)
        if not user:
            raise AccountError("User not found")
        new_role = role if role is not None else user["role"]
        new_disabled = bool(disabled) if disabled is not None else bool(user["disabled"])
        if new_role not in security.ROLES:
            raise AccountError("Unknown role")
        self._guard_last_admin(user, new_role, new_disabled)
        name = display_name.strip()[:80] if display_name is not None else user["display_name"]
        with self.db.connect() as c:
            c.execute("UPDATE users SET role=?, disabled=?, display_name=? WHERE id=?",
                      (new_role, int(new_disabled), name, user_id))
        if new_disabled or new_role != user["role"]:
            self.delete_user_sessions(user_id)
        return public(self.get(user_id))  # type: ignore[return-value]

    def set_password(self, user_id: int, new_password: str, *, must_change: bool = False,
                     keep_session_token: Optional[str] = None) -> None:
        user = self.get(user_id)
        if not user:
            raise AccountError("User not found")
        problems = security.check_password_policy(new_password, user["username"])
        if problems:
            raise AccountError("Password " + "; ".join(problems))
        with self.db.connect() as c:
            c.execute("UPDATE users SET password_hash=?, must_change_password=?, failed_logins=0, "
                      "locked_until=NULL WHERE id=?",
                      (security.hash_password(new_password), int(must_change), user_id))
        self.delete_user_sessions(user_id, except_token=keep_session_token)

    def unlock(self, user_id: int) -> None:
        with self.db.connect() as c:
            c.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?", (user_id,))

    def delete_user(self, user_id: int) -> None:
        user = self.get(user_id)
        if not user:
            raise AccountError("User not found")
        self._guard_last_admin(user, "viewer", True)
        with self.db.connect() as c:
            c.execute("UPDATE investigations SET assignee_id=NULL WHERE assignee_id=?", (user_id,))
            c.execute("DELETE FROM users WHERE id=?", (user_id,))

    # ------------------------------------------------------------ login
    def authenticate(self, username: str, password: str, totp_code: str = "") -> Dict[str, Any]:
        """Return {'status': 'ok'|'invalid'|'locked'|'totp_required'|'totp_invalid', 'user': ...}.

        Messages never reveal whether the username exists.
        """
        user = self.get_by_username(username)
        if user is None:
            security.burn_password_time(password or "")
            return {"status": "invalid", "user": None}
        locked_until = _parse(user["locked_until"])
        if locked_until and locked_until > _now():
            security.burn_password_time(password or "")
            return {"status": "locked", "user": user}
        if user["disabled"] or not security.verify_password(password or "", user["password_hash"]):
            if not user["disabled"]:
                self._record_failure(user)
            return {"status": "invalid", "user": user}
        if user["totp_enabled"]:
            if not totp_code:
                return {"status": "totp_required", "user": user}
            step = security.totp_verify(user["totp_secret"], totp_code)
            if step is None or step <= int(user["totp_last_step"]):
                self._record_failure(user)
                return {"status": "totp_invalid", "user": user}
            with self.db.connect() as c:
                c.execute("UPDATE users SET totp_last_step=? WHERE id=?", (step, user["id"]))
        with self.db.connect() as c:
            c.execute("UPDATE users SET failed_logins=0, locked_until=NULL, last_login=? WHERE id=?",
                      (utcnow_iso(), user["id"]))
        return {"status": "ok", "user": self.get(user["id"])}

    def _record_failure(self, user: Dict[str, Any]) -> None:
        failed = int(user["failed_logins"]) + 1
        locked = None
        if failed >= MAX_FAILED:
            locked = _iso(_now() + timedelta(minutes=LOCK_MINUTES))
            failed = 0
        with self.db.connect() as c:
            c.execute("UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                      (failed, locked, user["id"]))

    # ------------------------------------------------------------ TOTP
    def begin_totp(self, user_id: int) -> str:
        secret = security.new_totp_secret()
        with self.db.connect() as c:
            c.execute("UPDATE users SET totp_secret=?, totp_enabled=0, totp_last_step=0 WHERE id=?",
                      (secret, user_id))
        return secret

    def confirm_totp(self, user_id: int, code: str) -> bool:
        user = self.get(user_id)
        if not user or not user["totp_secret"]:
            return False
        step = security.totp_verify(user["totp_secret"], code)
        if step is None:
            return False
        with self.db.connect() as c:
            c.execute("UPDATE users SET totp_enabled=1, totp_last_step=? WHERE id=?", (step, user_id))
        return True

    def disable_totp(self, user_id: int) -> None:
        with self.db.connect() as c:
            c.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=0 WHERE id=?",
                      (user_id,))

    # ------------------------------------------------------------ sessions
    def create_session(self, user_id: int, ip: str = "", user_agent: str = "") -> str:
        token = security.new_token()
        now = _now()
        with self.db.connect() as c:
            c.execute("DELETE FROM sessions WHERE expires_at < ?", (_iso(now),))
            c.execute(
                "INSERT INTO sessions(token_hash, user_id, created_at, last_seen, expires_at, ip, user_agent) "
                "VALUES (?,?,?,?,?,?,?)",
                (security.token_hash(token), user_id, _iso(now), _iso(now),
                 _iso(now + timedelta(hours=SESSION_ABSOLUTE_HOURS)), ip[:64], user_agent[:200]))
        return token

    def resolve_session(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        """Return the (non-disabled) user for a live session, sliding the idle timeout."""
        if not token:
            return None
        th = security.token_hash(token)
        now = _now()
        with self.db.connect() as c:
            row = c.execute(
                "SELECT s.id AS sid, s.last_seen, s.expires_at, u.* FROM sessions s "
                "JOIN users u ON u.id = s.user_id WHERE s.token_hash=?", (th,)).fetchone()
            if row is None:
                return None
            d = dict(row)
            expires = _parse(d["expires_at"])
            last_seen = _parse(d["last_seen"])
            idle_dead = last_seen is None or now - last_seen > timedelta(minutes=SESSION_IDLE_MINUTES)
            if d["disabled"] or expires is None or expires < now or idle_dead:
                c.execute("DELETE FROM sessions WHERE id=?", (d["sid"],))
                return None
            c.execute("UPDATE sessions SET last_seen=? WHERE id=?", (_iso(now), d["sid"]))
        d.pop("sid", None)
        return d

    def delete_session(self, token: Optional[str]) -> None:
        if token:
            with self.db.connect() as c:
                c.execute("DELETE FROM sessions WHERE token_hash=?", (security.token_hash(token),))

    def delete_user_sessions(self, user_id: int, except_token: Optional[str] = None) -> None:
        with self.db.connect() as c:
            if except_token:
                c.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?",
                          (user_id, security.token_hash(except_token)))
            else:
                c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
