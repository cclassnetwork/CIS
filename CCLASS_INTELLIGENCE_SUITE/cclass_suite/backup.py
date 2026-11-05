"""Backups, verified restore, pruning and data-retention.

A backup is one ZIP holding a consistent copy of the database (SQLite online-backup API),
the evidence store, generated reports, the settings file and a MANIFEST.json with a SHA-256
for every file. **A backup contains password hashes and 2FA secrets and your case data:
store it encrypted and access-controlled** (for example ``gpg -c`` or an encrypted volume).

Restore is deliberately command-line only (``cclass.py restore``) and must be run with the
dashboard stopped.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .config import Settings
from .db import MIGRATIONS, Database

MANIFEST = "MANIFEST.json"
NAME_RE = re.compile(r"^cclass_backup_\d{8}T\d{6}Z\.zip$")
MAX_UNCOMPRESSED = 20 * 1024 ** 3        # refuse backups that would expand beyond 20 GiB
ALLOWED_TOP = {"database.db", "settings.json"}
ALLOWED_DIRS = ("evidence/", "reports/")


class BackupError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _files_under(root: Path) -> List[Path]:
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue                       # never follow links out of the data directory
        out.append(p)
    return out


def create_backup(settings: Settings, dest_dir: Optional[Path] = None) -> Path:
    """Write a new backup ZIP and return its path."""
    dest_dir = Path(dest_dir or settings.backups_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    when = datetime.now(timezone.utc)
    while True:                            # two backups within one second get distinct names
        final = dest_dir / f"cclass_backup_{when.strftime('%Y%m%dT%H%M%SZ')}.zip"
        if not final.exists():
            break
        when += timedelta(seconds=1)
    with tempfile.TemporaryDirectory(dir=str(dest_dir)) as tmp:
        tmpdir = Path(tmp)
        snap = tmpdir / "database.db"
        src = sqlite3.connect(settings.db_path)
        try:
            dst = sqlite3.connect(snap)
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
        entries: Dict[str, Path] = {"database.db": snap}
        if settings.settings_file.exists() and not settings.settings_file.is_symlink():
            entries["settings.json"] = settings.settings_file
        for sub, root in (("evidence", settings.evidence_dir), ("reports", settings.reports_dir)):
            if Path(root).is_dir():
                for p in _files_under(Path(root)):
                    entries[f"{sub}/{p.relative_to(root).as_posix()}"] = p
        manifest = {
            "format": 1, "app_version": __version__, "schema_version": max(m[0] for m in MIGRATIONS),
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "files": {name: {"sha256": _sha256(p), "size": p.stat().st_size} for name, p in entries.items()},
        }
        part = tmpdir / "out.zip"
        with zipfile.ZipFile(part, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(MANIFEST, json.dumps(manifest, indent=2))
            for name, p in entries.items():
                z.write(p, name)
        os.chmod(part, 0o600)
        os.replace(part, final)
    return final


def _safe_member(name: str) -> bool:
    if name == MANIFEST or name in ALLOWED_TOP:
        return True
    if not name.startswith(ALLOWED_DIRS) or name.endswith("/"):
        return False
    parts = name.split("/")
    return all(p not in ("", ".", "..") for p in parts) and "\\" not in name and not name.startswith("/")


def verify_backup(path: Path) -> Dict[str, Any]:
    """Check structure and every SHA-256. Never extracts to disk."""
    path = Path(path)
    problems: List[str] = []
    info: Dict[str, Any] = {"ok": False, "files": 0, "created_at": "", "schema_version": 0,
                            "app_version": "", "problems": problems}
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        problems.append(f"not a readable backup: {exc}")
        return info
    with z:
        names = z.namelist()
        total = sum(i.file_size for i in z.infolist())
        if total > MAX_UNCOMPRESSED:
            problems.append("backup expands beyond the safety limit")
            return info
        bad = [n for n in names if not _safe_member(n)]
        if bad:
            problems.append(f"unexpected or unsafe entries: {', '.join(bad[:5])}")
            return info
        if MANIFEST not in names:
            problems.append("MANIFEST.json is missing")
            return info
        try:
            manifest = json.loads(z.read(MANIFEST))
            files = manifest["files"]
        except (ValueError, KeyError, TypeError):
            problems.append("MANIFEST.json is unreadable")
            return info
        info.update(created_at=manifest.get("created_at", ""), schema_version=manifest.get("schema_version", 0),
                    app_version=manifest.get("app_version", ""), files=len(files))
        if "database.db" not in files:
            problems.append("backup has no database")
        listed = set(files)
        extra = set(names) - listed - {MANIFEST}
        if extra:
            problems.append(f"entries not listed in the manifest: {', '.join(sorted(extra)[:5])}")
        for name, meta in files.items():
            if name not in names:
                problems.append(f"missing file: {name}")
                continue
            h = hashlib.sha256()
            with z.open(name) as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            if h.hexdigest() != meta.get("sha256"):
                problems.append(f"checksum mismatch: {name}")
    info["ok"] = not problems
    return info


def list_backups(settings: Settings) -> List[Dict[str, Any]]:
    d = Path(settings.backups_dir)
    if not d.is_dir():
        return []
    rows = []
    for p in sorted(d.iterdir(), reverse=True):
        if NAME_RE.match(p.name) and p.is_file():
            st = p.stat()
            rows.append({"name": p.name, "size": st.st_size,
                         "created_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds")})
    return rows


def prune_backups(settings: Settings, keep: Optional[int] = None) -> List[str]:
    keep = max(1, int(keep if keep is not None else settings.backup_keep))
    removed = []
    for row in list_backups(settings)[keep:]:
        try:
            (Path(settings.backups_dir) / row["name"]).unlink()
            removed.append(row["name"])
        except OSError:
            pass
    return removed


def resolve_backup(settings: Settings, name: str) -> Path:
    """Map a bare backup file name to its path; rejects anything that is not a backup name."""
    if not NAME_RE.match(name or ""):
        raise BackupError("invalid backup name")
    p = Path(settings.backups_dir) / name
    if not p.is_file():
        raise BackupError("backup not found")
    return p


# ---------------------------------------------------------------------------
def restore_backup(path: Path, settings: Settings) -> Dict[str, Any]:
    """Replace the live data with the contents of ``path`` (dashboard must be stopped).

    The backup is verified first, and a safety backup of the current state is written before
    anything is replaced.
    """
    path = Path(path)
    check = verify_backup(path)
    if not check["ok"]:
        raise BackupError("backup failed verification: " + "; ".join(check["problems"]))
    if int(check["schema_version"]) > max(m[0] for m in MIGRATIONS):
        raise BackupError("this backup was made by a newer version of the suite; upgrade first")
    if settings.db_path.exists():
        probe = sqlite3.connect(settings.db_path, timeout=1)
        try:
            probe.execute("BEGIN EXCLUSIVE")
            probe.execute("ROLLBACK")
        except sqlite3.OperationalError as exc:
            raise BackupError("the database is in use - stop the dashboard before restoring") from exc
        finally:
            probe.close()
        safety = create_backup(settings)
    else:
        safety = None

    data = Path(settings.data_dir)
    with tempfile.TemporaryDirectory(dir=str(data)) as tmp:
        stage = Path(tmp)
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name == MANIFEST:
                    continue
                target = (stage / name).resolve()
                if not str(target).startswith(str(stage.resolve()) + os.sep):
                    raise BackupError("unsafe path in backup")
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(name) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        # Confirm the staged database is sound before touching live data.
        probe = sqlite3.connect(stage / "database.db")
        try:
            if probe.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("the database inside the backup is damaged")
        finally:
            probe.close()
        for suffix in ("", "-wal", "-shm"):
            Path(str(settings.db_path) + suffix).unlink(missing_ok=True)
        os.replace(stage / "database.db", settings.db_path)
        for sub, live in (("evidence", settings.evidence_dir), ("reports", settings.reports_dir)):
            shutil.rmtree(live, ignore_errors=True)
            if (stage / sub).is_dir():
                shutil.move(str(stage / sub), str(live))
            else:
                Path(live).mkdir(parents=True, exist_ok=True)
        if (stage / "settings.json").exists():
            os.replace(stage / "settings.json", settings.settings_file)
    Database(settings.db_path)             # runs any newer migrations on the restored data
    return {"restored_from": path.name, "backup_created_at": check["created_at"], "files": check["files"],
            "safety_backup": safety.name if safety else None}


# ---------------------------------------------------------------------------
def apply_retention(db: Database, alert_days: int, activity_days: int, dry_run: bool = False) -> Dict[str, int]:
    """Delete aged operational data. The audit log, findings, evidence and reports are never touched.

    * acknowledged threat alerts older than ``alert_days`` (0 = keep forever)
    * activity-log rows older than ``activity_days`` (0 = keep forever)
    * expired sessions
    """
    now = datetime.now(timezone.utc)
    out = {"alerts": 0, "activity": 0, "sessions": 0}
    with db.connect() as c:
        if alert_days > 0:
            cutoff = (now - timedelta(days=alert_days)).isoformat(timespec="seconds")
            where = "acknowledged=1 AND created_at < ?"
            out["alerts"] = c.execute(f"SELECT COUNT(*) FROM threat_alerts WHERE {where}", (cutoff,)).fetchone()[0]
            if not dry_run:
                c.execute(f"DELETE FROM threat_alerts WHERE {where}", (cutoff,))
        if activity_days > 0:
            cutoff = (now - timedelta(days=activity_days)).isoformat(timespec="seconds")
            out["activity"] = c.execute("SELECT COUNT(*) FROM activity_logs WHERE created_at < ?", (cutoff,)).fetchone()[0]
            if not dry_run:
                c.execute("DELETE FROM activity_logs WHERE created_at < ?", (cutoff,))
        stamp = now.isoformat(timespec="seconds")
        out["sessions"] = c.execute("SELECT COUNT(*) FROM sessions WHERE expires_at < ?", (stamp,)).fetchone()[0]
        if not dry_run:
            c.execute("DELETE FROM sessions WHERE expires_at < ?", (stamp,))
    return out
