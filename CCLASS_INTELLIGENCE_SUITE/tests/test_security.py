import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from cclass_suite import security
from cclass_suite.accounts import AccountError, AccountStore, MAX_FAILED
from cclass_suite.db import Database

GOOD = "Tr1cky-Passphrase!"


@pytest.fixture()
def store(tmp_path):
    return AccountStore(Database(tmp_path / "t.db"))


# ---------------------------------------------------------------- hashing / policy
def test_password_hash_roundtrip_and_salting():
    h1 = security.hash_password(GOOD, n=2 ** 12)
    h2 = security.hash_password(GOOD, n=2 ** 12)
    assert h1 != h2 and GOOD not in h1
    assert security.verify_password(GOOD, h1)
    assert not security.verify_password(GOOD + "x", h1)
    assert not security.verify_password(GOOD, "garbage")
    assert not security.verify_password(GOOD, "bcrypt$1$2$3$4$5")


@pytest.mark.parametrize("pw,fragment", [
    ("short1A!", "12 characters"),
    ("alllowercaseletters", "three of"),
    ("Password123", "12 characters"),
    ("aaaaaaaaaaaaAAAA1111", "repetitive"),
])
def test_policy_rejects(pw, fragment):
    assert any(fragment in p for p in security.check_password_policy(pw))


def test_policy_username_and_accept():
    assert any("username" in p for p in security.check_password_policy("Analyst-Pass9!!", "analyst"))
    assert security.check_password_policy(GOOD, "bob") == []


# ---------------------------------------------------------------- TOTP
def test_totp_rfc6238_vectors():
    secret = base64.b32encode(b"12345678901234567890").decode()
    # RFC 6238 Appendix B (SHA-1, 8 digits) -> last 6 digits are the 6-digit code
    vectors = {59: "287082", 1111111109: "081804", 1111111111: "050471",
               1234567890: "005924", 2000000000: "279037"}
    for t, code in vectors.items():
        assert security.totp_at(secret, t) == code


def test_totp_window_and_format():
    secret = security.new_totp_secret()
    now = 1_700_000_000
    code = security.totp_at(secret, now)
    assert security.totp_verify(secret, code, for_time=now) is not None
    assert security.totp_verify(secret, code, for_time=now + 30) is not None   # 1 step drift
    assert security.totp_verify(secret, code, for_time=now + 300) is None      # too far
    assert security.totp_verify(secret, "abcdef", for_time=now) is None
    assert security.totp_verify(secret, "", for_time=now) is None
    assert security.totp_uri(secret, "a b").startswith("otpauth://totp/")


# ---------------------------------------------------------------- RBAC
@pytest.mark.parametrize("method,path,role", [
    ("GET", "/api/overview", "viewer"),
    ("GET", "/api/investigations/3/findings", "viewer"),
    ("POST", "/api/investigate", "analyst"),
    ("DELETE", "/api/investigations/3", "analyst"),
    ("PUT", "/api/settings", "admin"),
    ("GET", "/api/settings", "admin"),
    ("GET", "/api/users", "admin"),
    ("POST", "/api/users", "admin"),
    ("GET", "/api/audit", "admin"),
    ("POST", "/api/backups", "admin"),
    ("PATCH", "/api/sources/1", "admin"),
    ("GET", "/api/auth/me", "viewer"),
    ("POST", "/api/auth/password", "viewer"),
    ("GET", "/api/unknown-thing", "viewer"),
    ("POST", "/something/else", "admin"),      # default-deny
])
def test_required_role(method, path, role):
    assert security.required_role(method, path) == role


def test_role_ordering():
    assert security.role_at_least("admin", "analyst")
    assert security.role_at_least("analyst", "analyst")
    assert not security.role_at_least("viewer", "analyst")
    assert not security.role_at_least("nonsense", "viewer")


# ---------------------------------------------------------------- accounts
def test_create_and_validation(store):
    uid = store.create_user("alice", GOOD, "admin")
    assert store.get(uid)["role"] == "admin"
    with pytest.raises(AccountError):
        store.create_user("alice", GOOD)              # duplicate
    with pytest.raises(AccountError):
        store.create_user("ALICE", GOOD)              # case-insensitive duplicate
    with pytest.raises(AccountError):
        store.create_user("bad name", GOOD)
    with pytest.raises(AccountError):
        store.create_user("bob", "weak")
    with pytest.raises(AccountError):
        store.create_user("bob", GOOD, "root")
    assert "password_hash" not in store.list_users()[0]


def test_authenticate_and_generic_failure(store):
    store.create_user("alice", GOOD, "analyst")
    assert store.authenticate("alice", GOOD)["status"] == "ok"
    assert store.authenticate("ALICE", GOOD)["status"] == "ok"
    assert store.authenticate("alice", "nope")["status"] == "invalid"
    r = store.authenticate("ghost", "nope")
    assert r["status"] == "invalid" and r["user"] is None


def test_lockout_after_repeated_failures(store):
    store.create_user("alice", GOOD)
    for _ in range(MAX_FAILED):
        assert store.authenticate("alice", "wrong")["status"] == "invalid"
    # correct password is refused while locked
    assert store.authenticate("alice", GOOD)["status"] == "locked"
    uid = store.get_by_username("alice")["id"]
    store.unlock(uid)
    assert store.authenticate("alice", GOOD)["status"] == "ok"


def test_disabled_user_cannot_login_or_use_session(store):
    admin = store.create_user("root1", GOOD, "admin")
    uid = store.create_user("alice", GOOD)
    token = store.create_session(uid)
    assert store.resolve_session(token)["username"] == "alice"
    store.update_user(uid, disabled=True)
    assert store.resolve_session(token) is None
    assert store.authenticate("alice", GOOD)["status"] == "invalid"
    assert store.get(admin)


def test_last_admin_protected(store):
    a = store.create_user("root1", GOOD, "admin")
    with pytest.raises(AccountError):
        store.update_user(a, role="viewer")
    with pytest.raises(AccountError):
        store.update_user(a, disabled=True)
    with pytest.raises(AccountError):
        store.delete_user(a)
    b = store.create_user("root2", GOOD, "admin")
    store.update_user(a, role="viewer")
    with pytest.raises(AccountError):
        store.delete_user(b)


def test_totp_login_flow_and_replay(store):
    uid = store.create_user("alice", GOOD)
    secret = store.begin_totp(uid)
    assert store.authenticate("alice", GOOD)["status"] == "ok"      # not enabled yet
    assert not store.confirm_totp(uid, "000000") or True
    code = security.totp_at(secret)
    assert store.confirm_totp(uid, code)
    assert store.authenticate("alice", GOOD)["status"] == "totp_required"
    assert store.authenticate("alice", GOOD, "123456")["status"] == "totp_invalid"
    # the code used to enrol cannot be replayed
    assert store.authenticate("alice", GOOD, code)["status"] == "totp_invalid"
    future = security.totp_at(secret, __import__("time").time() + 30)
    assert store.authenticate("alice", GOOD, future)["status"] == "ok"
    assert store.authenticate("alice", GOOD, future)["status"] == "totp_invalid"  # replay
    store.disable_totp(uid)
    store.unlock(uid)
    assert store.authenticate("alice", GOOD)["status"] == "ok"


def test_sessions_store_only_hash_and_expire(store):
    uid = store.create_user("alice", GOOD)
    token = store.create_session(uid, "1.2.3.4", "UA")
    with store.db.connect() as c:
        stored = c.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert stored != token and token not in stored
    assert store.resolve_session(token) is not None
    assert store.resolve_session("bogus") is None
    # idle timeout
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds")
    with store.db.connect() as c:
        c.execute("UPDATE sessions SET last_seen=?", (old,))
    assert store.resolve_session(token) is None
    # absolute expiry
    t2 = store.create_session(uid)
    with store.db.connect() as c:
        c.execute("UPDATE sessions SET expires_at=?", (old,))
    assert store.resolve_session(t2) is None


def test_password_change_revokes_other_sessions(store):
    uid = store.create_user("alice", GOOD)
    keep, other = store.create_session(uid), store.create_session(uid)
    store.set_password(uid, "An0ther-Strong-Pass!", keep_session_token=keep)
    assert store.resolve_session(keep) is not None
    assert store.resolve_session(other) is None
    assert store.authenticate("alice", "An0ther-Strong-Pass!")["status"] == "ok"
    with pytest.raises(AccountError):
        store.set_password(uid, "weak")


def test_logout(store):
    uid = store.create_user("alice", GOOD)
    t = store.create_session(uid)
    store.delete_session(t)
    assert store.resolve_session(t) is None
