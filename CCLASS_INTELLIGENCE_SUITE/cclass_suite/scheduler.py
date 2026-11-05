"""Scheduled public-feed and watchlist monitoring (background thread, no external dependencies)."""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Optional, Tuple

log = logging.getLogger("cclass.scheduler")

TASK_TYPES = ("feed_refresh", "watchlist_scan", "backup", "retention")
SCANNABLE = {"domain", "ip", "email", "username", "cve"}
MONITOR_NAME = "Watchlist monitoring"


class MonitorScheduler:
    def __init__(self, ctx: Any):
        self.ctx = ctx
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="cclass-scheduler", daemon=True)
        self._thread.start()
        log.info("scheduler started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_due()
            except Exception:  # noqa: BLE001 - the loop must survive any task failure
                log.exception("scheduler iteration failed")
            self._stop.wait(self.ctx.settings.scheduler_poll_seconds)

    # ------------------------------------------------------------------ execution
    def run_due(self) -> int:
        if not self._lock.acquire(blocking=False):
            return 0
        try:
            count = 0
            for task in self.ctx.db.due_tasks():
                self.run_task(task["id"])
                count += 1
            return count
        finally:
            self._lock.release()

    def run_task(self, task_id: int) -> Tuple[str, str]:
        task = self.ctx.db.get_task(task_id)
        if task is None:
            return "error", "task not found"
        try:
            if task["task_type"] == "feed_refresh":
                status, message = self._feed_refresh(task["params"])
            elif task["task_type"] == "watchlist_scan":
                status, message = self._watchlist_scan()
            elif task["task_type"] == "backup":
                status, message = self._backup()
            elif task["task_type"] == "retention":
                status, message = self._retention()
            else:
                status, message = "error", f"unknown task type {task['task_type']}"
        except Exception as exc:  # noqa: BLE001
            log.exception("task %s failed", task_id)
            status, message = "error", f"{exc.__class__.__name__}: {str(exc)[:200]}"
        self.ctx.db.record_task_run(task_id, status, message)
        self.ctx.db.log("scheduled_task", f"{task['name']}: {status} - {message}")
        return status, message

    def _backup(self) -> Tuple[str, str]:
        from . import backup

        path = backup.create_backup(self.ctx.settings)
        removed = backup.prune_backups(self.ctx.settings)
        self.ctx.audit.append("scheduler", "backup.create", path.name, f"scheduled; pruned={len(removed)}")
        return "ok", f"{path.name} written; {len(removed)} old backup(s) pruned"

    def _retention(self) -> Tuple[str, str]:
        from . import backup

        s = self.ctx.settings
        res = backup.apply_retention(self.ctx.db, s.retention_alert_days, s.retention_activity_days)
        self.ctx.audit.append("scheduler", "retention.run", "", str(res))
        return "ok", f"removed {res['alerts']} alert(s), {res['activity']} activity row(s), {res['sessions']} session(s)"

    def _feed_refresh(self, params: Dict[str, Any]) -> Tuple[str, str]:
        summary = self.ctx.feeds.refresh(only=params.get("feeds") or None)
        failed = [n for n, f in summary["feeds"].items() if not f["ok"]]
        msg = f"{summary['new_alerts']} new alert(s); {summary['matched']} watchlist match(es)"
        if failed:
            msg += f"; unavailable: {', '.join(failed)}"
        return ("partial" if failed and len(failed) < len(summary["feeds"]) else "error" if failed else "ok"), msg

    def _watchlist_scan(self) -> Tuple[str, str]:
        db, xkey = self.ctx.db, self.ctx.xkey
        items = [w for w in db.list_watchlists(active_only=True) if w["kind"] in SCANNABLE]
        if not items:
            return "ok", "no active scannable watchlist entries"
        inv = next((i for i in db.list_investigations() if i["name"] == MONITOR_NAME), None)
        inv_id = inv["id"] if inv else db.create_investigation(
            MONITOR_NAME, "Automatic re-checks of watchlist selectors. New findings are added over time.", "medium")
        new_total = errors = 0
        for w in items:
            try:
                out = xkey.investigate(w["value"], investigation_id=inv_id, pivot=False)
                new_total += sum(m["stats"]["findings_new"] for m in out["modules"])
                errors += sum(1 for m in out["modules"] if not m["ok"])
            except ValueError as exc:
                errors += 1
                log.warning("watchlist item %s skipped: %s", w["value"], exc)
        if new_total:
            db.log("watchlist_new_findings", f"{new_total} new finding(s) across {len(items)} watchlist item(s)", inv_id)
        return ("ok" if not errors else "partial"), f"{len(items)} item(s) checked; {new_total} new finding(s); {errors} error(s)"
