#!/usr/bin/env python3
"""CCLASS INTELLIGENCE SUITE - command line entry point.

    python3 cclass.py                 start the web dashboard
    python3 cclass.py --dashboard     start the web dashboard
    python3 cclass.py demo            load the offline demonstration investigation
    python3 cclass.py investigate admin@demo-corp.example
    python3 cclass.py --help          all commands
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, List, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def _reexec_in_venv() -> None:
    """install.sh creates ./.venv (required on Kali/Debian, whose system Python is externally managed).
    Re-launch inside it so that a plain ``python3 cclass.py`` finds the installed dependencies."""
    import os

    venv_python = ROOT / ".venv" / "bin" / "python"
    if os.environ.get("CCLASS_NO_VENV") or not venv_python.exists() or not (ROOT / ".venv" / ".cclass_ready").exists():
        return
    if Path(sys.prefix).resolve() == (ROOT / ".venv").resolve():
        return  # already running inside the virtualenv
    os.execv(str(venv_python), [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]])


_reexec_in_venv()

if sys.version_info < (3, 9):  # pragma: no cover
    sys.exit("CCLASS requires Python 3.9 or newer.")

from cclass_suite import __version__  # noqa: E402
from cclass_suite.config import Settings, SettingsError  # noqa: E402

BANNER = r"""
  ___ ___ _      _   ___ ___
 / __/ __| |    /_\ / __/ __|   INTELLIGENCE SUITE {ver}
| (_| (__| |__ / _ \\__ \__ \   lawful OSINT & cyber threat intelligence
 \___\___|____/_/ \_\___/___/
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cclass.py", description="CCLASS Intelligence Suite - lawful OSINT / CTI platform")
    p.add_argument("--dashboard", action="store_true", help="start the web dashboard (default when no command is given)")
    p.add_argument("--host", help="dashboard bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, help="dashboard port (default 8000)")
    p.add_argument("--offline", action="store_true", help="use bundled sample data only; make no network requests")
    p.add_argument("--data-dir", help="data directory (default ./data or $CCLASS_HOME)")
    p.add_argument("--no-auth", action="store_true",
                   help="disable dashboard login (only for a single-user, loopback-only machine)")
    p.add_argument("--no-demo-prompt", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version=f"CCLASS Intelligence Suite {__version__}")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("init", help="initialise the database and data directories")
    sub.add_parser("demo", help="load the offline demonstration investigation")
    sub.add_parser("modules", help="list modules")

    inv = sub.add_parser("investigate", help="run all matching modules for a selector, then correlate")
    inv.add_argument("query")
    inv.add_argument("-i", "--investigation", type=int, help="add to an existing investigation id")
    inv.add_argument("-m", "--module", action="append", help="restrict to module(s)")
    inv.add_argument("--no-pivot", action="store_true")
    inv.add_argument("--json", action="store_true", help="print JSON")

    srch = sub.add_parser("search", help="search stored intelligence")
    srch.add_argument("query")

    meta = sub.add_parser("metadata", help="analyse a local file's metadata (PDF, DOCX, XLSX, images)")
    meta.add_argument("file")
    meta.add_argument("-i", "--investigation", type=int, help="store results and the file as evidence in this investigation")

    net = sub.add_parser("netscan", help="AUTHORISED local network inventory (private ranges by default)")
    net.add_argument("target", help="CIDR such as 192.168.1.0/24, an IP, or 'local'")
    net.add_argument("--i-am-authorized", action="store_true", dest="authorized",
                     help="confirm you own or have written permission to inventory this network")
    net.add_argument("-i", "--investigation", type=int)

    gw = sub.add_parser("globalwatch", help="international OSINT news watch (security, readiness, cyber, conflict)")
    gw.add_argument("-c", "--country", help="only events for this country, e.g. -c Nigeria")
    gw.add_argument("-s", "--state", help="only events for this state/region, e.g. -s Kano")
    gw.add_argument("--days", type=int, default=3, help="only items from the last N days (1-30, default 3)")
    gw.add_argument("--max", type=int, default=3, dest="max_per_category", help="max events per category (1-10)")
    gw.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH"], default="MEDIUM")
    gw.add_argument("--links", action="store_true", help="show article links")
    gw.add_argument("--no-save", action="store_true", help="print only; do not store results in the database")
    gw.add_argument("-i", "--investigation", type=int, help="store in this investigation (default: 'Global Watch')")

    feeds = sub.add_parser("feeds", help="refresh public threat feeds")
    feeds.add_argument("--sample", action="store_true", help="load the bundled sample feed instead")

    alerts = sub.add_parser("alerts", help="list stored threat alerts")
    alerts.add_argument("-n", type=int, default=20)
    alerts.add_argument("--matched", action="store_true", help="only watchlist matches")

    watch = sub.add_parser("watch", help="manage watchlists")
    watch.add_argument("action", choices=["add", "list", "remove"])
    watch.add_argument("kind", nargs="?")
    watch.add_argument("value", nargs="?")

    rep = sub.add_parser("report", help="generate a report")
    rep.add_argument("investigation", type=int)
    rep.add_argument("-f", "--format", default="html", choices=["html", "pdf", "csv", "json", "txt"])

    usr = sub.add_parser("users", help="manage dashboard accounts")
    usr.add_argument("action", choices=["list", "add", "set-password", "set-role", "disable", "enable", "unlock",
                                         "reset-2fa", "delete"])
    usr.add_argument("username", nargs="?")
    usr.add_argument("--role", choices=["viewer", "analyst", "admin"], default="analyst")
    usr.add_argument("--must-change", action="store_true", help="force a password change at next sign-in")

    aud = sub.add_parser("audit", help="inspect the tamper-evident audit log")
    aud.add_argument("action", choices=["verify", "tail", "export"])
    aud.add_argument("-n", type=int, default=20, help="entries for 'tail'")
    aud.add_argument("--format", choices=["csv", "json"], default="csv")
    aud.add_argument("--out", help="write the export to this file")

    bk = sub.add_parser("backup", help="create a verified backup (database, evidence, reports, settings)")
    bk.add_argument("--out", help="directory to write to (default <data>/backups)")
    bk.add_argument("--verify", metavar="FILE", help="verify an existing backup instead of creating one")
    bk.add_argument("--prune", action="store_true", help="afterwards delete backups beyond the retention count")

    rs = sub.add_parser("restore", help="restore a backup (stop the dashboard first)")
    rs.add_argument("file")
    rs.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    rt = sub.add_parser("retention", help="apply the data-retention policy from Settings")
    rt.add_argument("--apply", action="store_true", help="actually delete (default is a dry-run preview)")

    sched = sub.add_parser("monitor", help="run the scheduler in the foreground (without the dashboard)")
    sched.add_argument("--once", action="store_true", help="run due tasks once and exit")
    return p


def make_context(args: argparse.Namespace):
    from cclass_suite.context import AppContext

    settings = Settings.load(args.data_dir)
    if args.offline:
        settings.offline_mode = True
    if getattr(args, "no_auth", False):
        settings.auth_enabled = False
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port
    try:
        settings.update({"host": settings.host, "port": settings.port})
    except SettingsError as exc:
        sys.exit(f"Invalid setting: {exc}")
    return AppContext(settings, console_log=False)


# ---------------------------------------------------------------------------- output helpers
def print_findings(rows: List[dict], limit: int = 200) -> None:
    for f in rows[:limit]:
        ent = f"  [{f['entity_type']}:{f['entity_value']}]" if f.get("entity_value") else ""
        print(f"  {f['severity'].upper():8} {f['confidence']:.0%}  {f['title']}{ent}")
        if f.get("summary"):
            print(f"           {f['summary'][:200]}")


def print_outcome(out: dict) -> None:
    print(f"Investigation #{out['investigation_id']}  detected type: {out['detected_type']}"
          + ("  (offline sample data)" if out["offline"] else ""))
    for m in out["modules"]:
        status = "ok " if m["ok"] else "ERR"
        extra = f"+{m['stats']['findings_new']} findings, +{m['stats']['entities_new']} entities" if m["ok"] else m["error"]
        print(f"  [{status}] {m['module']:13} {m['query'][:50]:50} {extra}")
        for w in m["warnings"]:
            print(f"        warning: {w}")
    for n in out["notes"]:
        print(f"  note: {n}")
    for i in out["insights"]:
        print(f"  insight [{i['severity']}]: {i['title']}")


# ---------------------------------------------------------------------------- commands
def cmd_dashboard(args: argparse.Namespace) -> int:
    try:
        import uvicorn

        from cclass_suite.web.app import create_app
    except ImportError as exc:
        print(f"Missing dependency: {exc.name}. Run ./install.sh (or: pip install -r requirements.txt).", file=sys.stderr)
        return 2
    ctx = make_context(args)
    s = ctx.settings
    print(BANNER.format(ver=__version__))
    print(f"Dashboard: http://{s.host}:{s.port}   data: {s.data_dir}   mode: {'OFFLINE' if s.offline_mode else 'online'}")
    if not s.auth_enabled:
        print("WARNING: authentication is DISABLED - anyone who can open this page has full access.", file=sys.stderr)
    elif ctx.accounts.count() == 0:
        print("No accounts yet: open the dashboard to create the first administrator, or run\n"
              "  python3 cclass.py users add <name> --role admin")
    if s.host not in ("127.0.0.1", "localhost", "::1") and not s.cookie_secure:
        print("NOTE: this address is network-reachable over plain HTTP. For real use put it behind HTTPS "
              "(see deploy/ and docs/ADMIN_GUIDE.md) and set CCLASS_COOKIE_SECURE=1.", file=sys.stderr)
    if not ctx.db.list_investigations() and not args.no_demo_prompt:
        print("Tip: open the dashboard and press 'Load offline demo data' on the Overview page.")
    print("Press Ctrl+C to stop.\n")
    try:
        app = create_app(ctx)
    except RuntimeError as exc:
        print(f"Refusing to start: {exc}", file=sys.stderr)
        return 2
    if getattr(ctx, "setup_token", ""):
        print(f"First-run setup token (only needed if you create the administrator from another machine): {ctx.setup_token}")
    uvicorn.run(app, host=s.host, port=s.port, log_level="warning",
                proxy_headers=s.trust_proxy, forwarded_allow_ips="*" if s.trust_proxy else None)
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    print(f"Database ready at {ctx.settings.db_path} (schema version {ctx.db.schema_version()}).")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from cclass_suite.demo import load_demo

    ctx = make_context(args)
    r = load_demo(ctx)
    print(f"Demo investigation #{r['investigation_id']} loaded; {r['alerts_added']} sample alert(s) added.")
    print_findings(ctx.db.list_findings(r["investigation_id"], limit=15), 15)
    stats = ctx.db.stats()["totals"]
    print(f"\nTotals: {stats['entities']} entities, {stats['findings']} findings, {stats['alerts']} alerts.")
    print("Start the dashboard with: python3 cclass.py --dashboard")
    return 0


def cmd_modules(args: argparse.Namespace) -> int:
    from cclass_suite.modules import CATALOG

    for m in CATALOG:
        flag = " [authorised use only]" if m.get("requires_authorization") else ""
        print(f"{m['name']:14} {m['description']}{flag}")
    return 0


def cmd_investigate(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    try:
        out = ctx.xkey.investigate(args.query, args.investigation, args.module, not args.no_pivot)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return 0
    print_outcome(out)
    print()
    print_findings(ctx.db.list_findings(out["investigation_id"], limit=60), 60)
    return 0 if any(m["ok"] for m in out["modules"]) or out["notes"] else 1


def cmd_search(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    r = ctx.xkey.search(args.query)
    print(f"Detected type: {r['detected_type']}   matches: {r['total']}")
    for section, rows in r["results"].items():
        for row in rows:
            label = row.get("title") or row.get("value") or row.get("name") or row.get("filename") or ""
            print(f"  {section[:-1]:13} {str(label)[:90]}")
    return 0


def cmd_metadata(args: argparse.Namespace) -> int:
    from cclass_suite.ingest import persist_result
    from cclass_suite.modules import REGISTRY

    ctx = make_context(args)
    path = Path(args.file).expanduser()
    if not path.is_file():
        print("File not found.", file=sys.stderr)
        return 1
    result = REGISTRY["METADATA"].safe_run(str(path), ctx.mctx)
    if not result.ok:
        print(f"Error: {result.error}", file=sys.stderr)
        return 1
    for f in result.findings:
        print(f"  {f.severity.upper():8} {f.title}\n           {f.summary[:220]}")
    for w in result.warnings:
        print(f"  warning: {w}")
    if args.investigation:
        import shutil
        import tempfile

        if ctx.db.get_investigation(args.investigation) is None:
            print("Investigation not found.", file=sys.stderr)
            return 1
        persist_result(ctx.db, args.investigation, result)
        tmp = Path(tempfile.mkstemp(dir=ctx.settings.evidence_dir)[1])
        shutil.copyfile(path, tmp)  # the original is never moved or modified
        info = ctx.add_evidence_from_path(args.investigation, tmp, path.name, "added via CLI")
        print(f"Stored in investigation #{args.investigation} (evidence #{info['id']}{', duplicate' if info['duplicate'] else ''}).")
    return 0


def cmd_netscan(args: argparse.Namespace) -> int:
    from cclass_suite.ingest import persist_result
    from cclass_suite.modules import REGISTRY

    if not args.authorized:
        print("Refusing to run: pass --i-am-authorized to confirm you own, or have written permission to inventory, "
              "this network.", file=sys.stderr)
        return 2
    ctx = make_context(args)
    result = REGISTRY["NETWORKINTEL"].safe_run(args.target, ctx.mctx, authorized=True)
    if not result.ok:
        print(f"Error: {result.error}", file=sys.stderr)
        return 1
    for f in result.findings:
        print(f"  {f.severity.upper():8} {f.title}\n           {f.summary}")
    inv_id = args.investigation or ctx.db.create_investigation(f"Network inventory {args.target}", "Authorised inventory run.")
    persist_result(ctx.db, inv_id, result)
    print(f"Stored in investigation #{inv_id}.")
    return 0


def cmd_feeds(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    r = ctx.feeds.refresh(offline_sample=args.sample)
    for name, f in r["feeds"].items():
        print(f"  {name:18} {'ok' if f['ok'] else 'UNAVAILABLE: ' + str(f['error'])}  (+{f['new']} new)")
    print(f"{r['new_alerts']} new alert(s); {r['matched']} watchlist match(es).")
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    for a in ctx.db.list_alerts(matched_only=args.matched, limit=args.n):
        marks = f"  <- {', '.join(a['matched_watchlists'])}" if a["matched_watchlists"] else ""
        print(f"  {a['severity'].upper():8} {a['title'][:100]}{marks}")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    if args.action == "list":
        for w in ctx.db.list_watchlists():
            print(f"  #{w['id']:<3} {w['kind']:9} {w['value']}  {'(paused)' if not w['active'] else ''}")
        return 0
    if args.action == "add":
        if not args.kind or not args.value:
            print("usage: watch add KIND VALUE", file=sys.stderr)
            return 1
        try:
            wid, created = ctx.db.add_watchlist(args.kind, args.value)
        except Exception as exc:  # noqa: BLE001 - e.g. CHECK constraint on unknown kind
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"{'Added' if created else 'Already present'}: #{wid}; {ctx.feeds.match_watchlists()} alert(s) matched.")
        return 0
    if not args.kind or not args.kind.isdigit():
        print("usage: watch remove ID", file=sys.stderr)
        return 1
    print("Removed." if ctx.db.delete_watchlist(int(args.kind)) else "Not found.")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    try:
        path = ctx.reports.generate(args.investigation, args.format)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Report written: {path}")
    return 0


def cmd_globalwatch(args: argparse.Namespace) -> int:
    from cclass_suite.ingest import persist_result
    from cclass_suite.modules import REGISTRY
    from cclass_suite.modules.globalwatch import format_report
    from datetime import datetime

    ctx = make_context(args)
    result = REGISTRY["GLOBALWATCH"].safe_run(
        args.country or "global", ctx.mctx, state=args.state, days=args.days,
        max_per_category=args.max_per_category, min_severity=args.min_severity)
    if not result.ok:
        print(f"Error: {result.error}", file=sys.stderr)
        return 1
    events = [{**e, "published": datetime.fromisoformat(e["published"])} for e in result.raw.get("events", [])]
    print(format_report(events, args.country, args.state, args.links))
    for w in result.warnings:
        print(f"[warn] {w}", file=sys.stderr)
    if events and not args.no_save:
        inv_id = args.investigation
        if inv_id is None:
            existing = next((i for i in ctx.db.list_investigations() if i["name"] == "Global Watch"), None)
            inv_id = existing["id"] if existing else ctx.db.create_investigation(
                "Global Watch", "International OSINT news events collected by GLOBALWATCH.", "medium")
        elif ctx.db.get_investigation(inv_id) is None:
            print("Investigation not found.", file=sys.stderr)
            return 1
        stats = persist_result(ctx.db, inv_id, result)
        print(f"Saved to investigation #{inv_id}: +{stats['findings_new']} new, {stats['findings_duplicate']} already known.")
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    import time

    ctx = make_context(args)
    if args.once:
        print(f"{ctx.scheduler.run_due()} task(s) run.")
        return 0
    print("Scheduler running in the foreground. Ctrl+C to stop.")
    ctx.scheduler.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ctx.scheduler.stop()
    return 0


def _cli_actor() -> str:
    import getpass as gp
    try:
        return f"cli:{gp.getuser()}"
    except Exception:  # noqa: BLE001
        return "cli"


def _read_new_password(username: str) -> str:
    import getpass
    import os

    env = os.environ.get("CCLASS_NEW_PASSWORD")
    if env:
        return env
    a = getpass.getpass(f"New password for {username}: ")
    if a != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    return a


def cmd_users(args: argparse.Namespace) -> int:
    from cclass_suite.accounts import AccountError

    ctx = make_context(args)
    acc, who = ctx.accounts, _cli_actor()
    if args.action == "list":
        for u in acc.list_users():
            flags = ("2FA " if u["totp_enabled"] else "") + ("DISABLED " if u["disabled"] else "")
            print(f"  {u['username']:20} {u['role']:8} {flags}last login: {u['last_login'] or 'never'}")
        if not acc.count():
            print("  (no accounts yet)")
        return 0
    if not args.username:
        sys.exit("This action needs a username.")
    try:
        if args.action == "add":
            uid = acc.create_user(args.username, _read_new_password(args.username), args.role, must_change=args.must_change)
            ctx.audit.append(who, "user.create", f"user:{uid}", f"role={args.role} via CLI")
            print(f"Created {args.role} account '{args.username}'.")
            return 0
        user = acc.get_by_username(args.username)
        if not user:
            sys.exit(f"No such user: {args.username}")
        uid = user["id"]
        if args.action == "set-password":
            acc.set_password(uid, _read_new_password(args.username), must_change=args.must_change)
        elif args.action == "set-role":
            acc.update_user(uid, role=args.role)
        elif args.action in ("disable", "enable"):
            acc.update_user(uid, disabled=args.action == "disable")
        elif args.action == "unlock":
            acc.unlock(uid)
        elif args.action == "reset-2fa":
            acc.disable_totp(uid)
            acc.delete_user_sessions(uid)
        elif args.action == "delete":
            acc.delete_user(uid)
        ctx.audit.append(who, f"user.{args.action.replace('-', '_')}", f"user:{uid}", "via CLI")
        print("Done.")
        return 0
    except AccountError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_audit(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    if args.action == "verify":
        r = ctx.audit.verify()
        if r["ok"]:
            print(f"Audit chain intact: {r['entries']} entries.\nHead hash: {r['head']}\n"
                  "Record the head hash outside this server to also detect removal of the newest entries.")
            return 0
        print(f"TAMPERING DETECTED at entry #{r['first_bad_seq']}: {r['problem']}", file=sys.stderr)
        return 3
    if args.action == "tail":
        for e in reversed(ctx.audit.list(args.n)):
            print(f"  #{e['seq']:<6} {e['ts']}  {e['actor']:14} {e['action']:22} {e['target']} {e['detail']}")
        return 0
    text = ctx.audit.export(args.format)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    from cclass_suite import backup

    ctx = make_context(args)
    if args.verify:
        r = backup.verify_backup(Path(args.verify))
        print(("OK" if r["ok"] else "FAILED") + f": {r['files']} files, created {r['created_at'] or '?'}")
        for p in r["problems"]:
            print("  -", p)
        return 0 if r["ok"] else 3
    path = backup.create_backup(ctx.settings, Path(args.out) if args.out else None)
    ctx.audit.append(_cli_actor(), "backup.create", path.name, "via CLI")
    print(f"Backup written: {path}\nIt holds case data and password hashes - store it encrypted (e.g. gpg -c).")
    if args.prune:
        print(f"Pruned {len(backup.prune_backups(ctx.settings))} old backup(s).")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    from cclass_suite import backup

    ctx = make_context(args)
    if not args.yes:
        print(f"This REPLACES the current database, evidence and reports in {ctx.settings.data_dir} with {args.file}.")
        print("A safety backup of the current state is made first. The dashboard must be stopped.")
        if input("Type 'restore' to continue: ").strip() != "restore":
            print("Cancelled.")
            return 1
    try:
        res = backup.restore_backup(Path(args.file), ctx.settings)
    except backup.BackupError as exc:
        print(f"Restore refused: {exc}", file=sys.stderr)
        return 2
    from cclass_suite.audit import AuditLog
    from cclass_suite.db import Database

    AuditLog(Database(ctx.settings.db_path)).append(_cli_actor(), "backup.restore", res["restored_from"],
                                                    f"safety={res['safety_backup']}")
    print(f"Restored {res['files']} files from {res['restored_from']} (made {res['backup_created_at']}).")
    if res["safety_backup"]:
        print(f"Previous state saved as {res['safety_backup']} in {ctx.settings.backups_dir}.")
    return 0


def cmd_retention(args: argparse.Namespace) -> int:
    from cclass_suite import backup

    ctx = make_context(args)
    s = ctx.settings
    if not s.retention_alert_days and not s.retention_activity_days:
        print("No retention limits are set (Settings: retention_alert_days / retention_activity_days). Only expired sessions are cleared.")
    res = backup.apply_retention(ctx.db, s.retention_alert_days, s.retention_activity_days, dry_run=not args.apply)
    print(("Removed" if args.apply else "Would remove") + f": {res['alerts']} acknowledged alert(s), "
          f"{res['activity']} activity row(s), {res['sessions']} expired session(s).")
    if args.apply:
        ctx.audit.append(_cli_actor(), "retention.run", "", f"{res} via CLI")
    else:
        print("Dry run - add --apply to delete.")
    return 0


COMMANDS = {"init": cmd_init, "demo": cmd_demo, "modules": cmd_modules, "investigate": cmd_investigate,
            "search": cmd_search, "metadata": cmd_metadata, "netscan": cmd_netscan, "feeds": cmd_feeds,
            "alerts": cmd_alerts, "watch": cmd_watch, "report": cmd_report, "monitor": cmd_monitor,
            "globalwatch": cmd_globalwatch, "users": cmd_users, "audit": cmd_audit,
            "backup": cmd_backup, "restore": cmd_restore, "retention": cmd_retention}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.dashboard or not args.command:
        return cmd_dashboard(args)
    try:
        return COMMANDS[args.command](args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
