"""Every route declared in web/app.py must have a deliberately chosen role.

This parses the source (no FastAPI needed). Adding a route without classifying it here
fails the test, so a new endpoint cannot silently end up with the wrong access level.
"""
import re
from pathlib import Path

from cclass_suite import security

APP = Path(__file__).resolve().parent.parent / "cclass_suite" / "web" / "app.py"
ADMIN = {("PUT", "/api/settings"), ("GET", "/api/settings"), ("POST", "/api/demo"),
         ("PATCH", "/api/sources/{source_id}")}
PUBLIC = {("GET", "/"), ("GET", "/api/health")}


def declared():
    return re.findall(r'@app\.(get|post|put|patch|delete)\(\s*"([^"]+)"', APP.read_text())


def concrete(path):
    return re.sub(r"\{[^}]+\}", "1", path)


def test_every_route_has_expected_role():
    routes = declared()
    assert len(routes) > 30
    for method, path in routes:
        method = method.upper()
        if (method, path) in PUBLIC:
            continue
        expected = "admin" if (method, path) in ADMIN else ("viewer" if method == "GET" else "analyst")
        got = security.required_role(method, concrete(path))
        assert got == expected, f"{method} {path}: policy gives {got!r}, expected {expected!r}"


def test_no_route_falls_through_to_default_deny_by_accident():
    # every /api route is matched by an explicit rule; only unknown non-/api paths hit the fallback
    for method, path in declared():
        if path.startswith("/api/"):
            matched = [r for r in security.RBAC_RULES if method.upper() in r[0] and r[1].match(concrete(path))]
            assert matched, f"{method} {path} matches no RBAC rule"


def test_state_changing_routes_are_never_viewer_accessible():
    for method, path in declared():
        if method != "get" and path.startswith("/api/"):
            assert security.required_role(method.upper(), concrete(path)) != "viewer"
