"""Application context: wires settings, database, clients, modules and services together."""

from __future__ import annotations

import logging
import mimetypes
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from .accounts import AccountStore
from .audit import AuditLog
from .config import Settings
from .correlation import CorrelationEngine
from .db import Database
from .dnsutil import DnsClient
from .ingest import persist_result
from .modules import REGISTRY, ModuleContext
from .modules.reportgen import ReportGenerator
from .modules.threatmonitor import ThreatFeedManager
from .utils import HttpClient, hash_file, setup_logging
from .xkeysearch import XKeySearch

log = logging.getLogger("cclass.context")


class AppContext:
    def __init__(self, settings: Optional[Settings] = None, console_log: bool = True):
        self.settings = settings or Settings.load()
        self.settings.ensure_dirs()
        setup_logging(self.settings, console=console_log)
        self.db = Database(self.settings.db_path)
        self.http = HttpClient(self.settings)
        self.dns = DnsClient(self.settings)
        self.mctx = ModuleContext(self.settings, self.http, self.dns, self.db)
        self.correlation = CorrelationEngine(self.db)
        self.xkey = XKeySearch(self.db, self.mctx, self.correlation)
        self.feeds = ThreatFeedManager(self.db, self.mctx)
        self.reports = ReportGenerator(self.db, self.settings)
        self.accounts = AccountStore(self.db)
        self.audit = AuditLog(self.db)
        from .graphlab.store import GraphStore

        self.graphs = GraphStore(self.db)
        from .scheduler import MonitorScheduler

        self.scheduler = MonitorScheduler(self)

    # ------------------------------------------------------------------ evidence
    @staticmethod
    def safe_filename(name: str) -> str:
        base = os.path.basename((name or "").replace("\\", "/")) or "upload.bin"
        base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")[:100]
        return base or "upload.bin"

    def add_evidence_from_path(self, investigation_id: int, src: Path, original_name: str, notes: str = "",
                               collected_by: str = "analyst") -> Dict[str, Any]:
        """Hash a file, move it into the evidence store and register it (duplicates are detected by SHA-256)."""
        if self.db.get_investigation(investigation_id) is None:
            raise ValueError("investigation not found")
        hashes = hash_file(src)
        size = Path(src).stat().st_size
        dest_dir = self.settings.evidence_dir / str(int(investigation_id))
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{hashes['sha256'][:16]}_{self.safe_filename(original_name)}"
        mime = mimetypes.guess_type(original_name)[0] or "application/octet-stream"
        existing_id = None
        for ev in self.db.list_evidence(investigation_id):
            if ev["sha256"] == hashes["sha256"]:
                existing_id = ev["id"]
        if existing_id is not None:
            Path(src).unlink(missing_ok=True)
            return {"id": existing_id, "duplicate": True, "sha256": hashes["sha256"], "filename": original_name}
        shutil.move(str(src), dest)
        os.chmod(dest, 0o600)
        ev_id, created = self.db.add_evidence(investigation_id, self.safe_filename(original_name), str(dest),
                                              hashes["sha256"], size, mime, notes, collected_by=collected_by)
        return {"id": ev_id, "duplicate": not created, "sha256": hashes["sha256"],
                "filename": self.safe_filename(original_name), "size_bytes": size}

    def analyze_evidence(self, evidence_id: int) -> Dict[str, Any]:
        ev = self.db.get_evidence(evidence_id)
        if ev is None:
            raise ValueError("evidence not found")
        stored = Path(ev["stored_path"]).resolve()
        if not str(stored).startswith(str(self.settings.evidence_dir.resolve())):
            raise ValueError("evidence path is outside the evidence store")
        result = REGISTRY["METADATA"].safe_run(str(stored), self.mctx)
        stats = persist_result(self.db, ev["investigation_id"], result)
        self.correlation.correlate(ev["investigation_id"])
        return {"ok": result.ok, "error": result.error, "warnings": result.warnings, "stats": stats,
                "findings": len(result.findings)}

    def delete_evidence(self, evidence_id: int) -> bool:
        path = self.db.delete_evidence(evidence_id)
        if path is None:
            return False
        try:
            p = Path(path).resolve()
            if str(p).startswith(str(self.settings.evidence_dir.resolve())):
                p.unlink(missing_ok=True)
        except OSError:
            pass
        return True

    def delete_investigation(self, investigation_id: int) -> bool:
        if self.db.get_investigation(investigation_id) is None:
            return False
        root = self.settings.data_dir.resolve()
        for path in self.db.delete_investigation(investigation_id):
            try:
                p = Path(path).resolve()
                if str(p).startswith(str(root)):
                    p.unlink(missing_ok=True)
            except OSError:
                pass
        shutil.rmtree(self.settings.evidence_dir / str(investigation_id), ignore_errors=True)
        return True

    def temp_upload_path(self) -> Path:
        tmp_dir = self.settings.evidence_dir / ".tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=tmp_dir)
        os.close(fd)
        return Path(name)
