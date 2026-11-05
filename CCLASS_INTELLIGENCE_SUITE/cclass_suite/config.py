"""Configurable settings.

Precedence (highest first): environment variables, ``data/settings.json``,
built-in defaults.  Secrets (for example an optional NVD API key) are read
from the environment only and are never written to disk by the suite.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_FEEDS: Dict[str, Dict[str, Any]] = {
    "cisa_kev": {
        "enabled": True,
        "type": "kev",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    },
    "nvd_recent": {
        "enabled": True,
        "type": "nvd",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "days": 3,
    },
    "cisa_advisories": {
        "enabled": True,
        "type": "rss",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    },
}

DEFAULT_SCAN_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443,
]

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class SettingsError(ValueError):
    """Raised when a settings value fails validation."""


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "data")
    host: str = "127.0.0.1"
    port: int = 8000
    offline_mode: bool = False
    http_timeout: float = 10.0
    dns_timeout: float = 5.0
    user_agent: str = "CCLASS-Intelligence-Suite/1.0 (lawful public-source research)"
    log_level: str = "INFO"
    allow_public_network_targets: bool = False
    max_scan_hosts: int = 1024
    scan_ports: List[int] = field(default_factory=lambda: list(DEFAULT_SCAN_PORTS))
    scan_timeout: float = 0.6
    scan_workers: int = 64
    max_upload_mb: int = 50
    subdomain_resolve_limit: int = 20
    scheduler_enabled: bool = True
    scheduler_poll_seconds: int = 30
    backup_keep: int = 14                 # newest N backups kept by pruning
    retention_alert_days: int = 0         # delete ACKNOWLEDGED threat alerts older than N days (0 = keep)
    retention_activity_days: int = 0      # delete activity-log rows older than N days (0 = keep)
    feeds: Dict[str, Dict[str, Any]] = field(default_factory=lambda: copy.deepcopy(DEFAULT_FEEDS))
    # Secret: environment only, never persisted or returned by the API.
    nvd_api_key: str = field(default="", repr=False)
    # Deployment / security switches. Deliberately NOT in PERSISTED: they come from the
    # environment only, so nobody can weaken them through the settings API.
    auth_enabled: bool = True
    cookie_secure: bool = False
    trust_proxy: bool = False
    allowed_hosts: List[str] = field(default_factory=list)

    # ----- derived paths -------------------------------------------------
    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "cclass.db"

    @property
    def evidence_dir(self) -> Path:
        return Path(self.data_dir) / "evidence"

    @property
    def reports_dir(self) -> Path:
        return Path(self.data_dir) / "reports"

    @property
    def logs_dir(self) -> Path:
        return Path(self.data_dir) / "logs"

    @property
    def backups_dir(self) -> Path:
        return Path(self.data_dir) / "backups"

    @property
    def settings_file(self) -> Path:
        return Path(self.data_dir) / "settings.json"

    @property
    def sample_dir(self) -> Path:
        return PROJECT_ROOT / "sample_data"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.evidence_dir, self.reports_dir, self.logs_dir, self.backups_dir):
            Path(d).mkdir(parents=True, exist_ok=True)

    # ----- persistence ---------------------------------------------------
    PERSISTED = (
        "host", "port", "offline_mode", "http_timeout", "dns_timeout", "user_agent",
        "log_level", "allow_public_network_targets", "max_scan_hosts", "scan_ports",
        "scan_timeout", "scan_workers", "max_upload_mb", "subdomain_resolve_limit",
        "scheduler_enabled", "scheduler_poll_seconds", "feeds", "backup_keep",
        "retention_alert_days", "retention_activity_days",
    )

    def to_public_dict(self) -> Dict[str, Any]:
        out = {k: getattr(self, k) for k in self.PERSISTED}
        out["data_dir"] = str(self.data_dir)
        out["nvd_api_key_configured"] = bool(self.nvd_api_key)
        return out

    def save(self) -> None:
        self.ensure_dirs()
        tmp = self.settings_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({k: getattr(self, k) for k in self.PERSISTED}, indent=2))
        os.replace(tmp, self.settings_file)

    def update(self, changes: Dict[str, Any]) -> None:
        """Validate and apply ``changes``; unknown keys raise SettingsError."""
        unknown = set(changes) - set(self.PERSISTED)
        if unknown:
            raise SettingsError(f"Unknown or read-only setting(s): {', '.join(sorted(unknown))}")
        staged = copy.deepcopy(changes)
        _validate(staged)
        for key, value in staged.items():
            setattr(self, key, value)

    @classmethod
    def load(cls, data_dir: Path | str | None = None) -> "Settings":
        home = data_dir or os.environ.get("CCLASS_HOME") or (PROJECT_ROOT / "data")
        settings = cls(data_dir=Path(home))
        if settings.settings_file.exists():
            try:
                stored = json.loads(settings.settings_file.read_text())
                if isinstance(stored, dict):
                    allowed = {k: v for k, v in stored.items() if k in cls.PERSISTED}
                    _validate(allowed)
                    for key, value in allowed.items():
                        setattr(settings, key, value)
            except (OSError, ValueError, SettingsError):
                # Corrupt settings must never prevent start-up; defaults apply.
                pass
        env = os.environ
        if env.get("CCLASS_OFFLINE", "").lower() in ("1", "true", "yes"):
            settings.offline_mode = True
        if env.get("CCLASS_HOST"):
            settings.host = env["CCLASS_HOST"]
        if env.get("CCLASS_PORT", "").isdigit():
            settings.port = int(env["CCLASS_PORT"])
        settings.nvd_api_key = env.get("CCLASS_NVD_API_KEY", "")
        truthy = ("1", "true", "yes", "on")
        if env.get("CCLASS_AUTH", "").lower() in ("0", "false", "no", "off"):
            settings.auth_enabled = False
        settings.cookie_secure = env.get("CCLASS_COOKIE_SECURE", "").lower() in truthy
        settings.trust_proxy = env.get("CCLASS_TRUST_PROXY", "").lower() in truthy
        settings.allowed_hosts = [h.strip().lower() for h in env.get("CCLASS_ALLOWED_HOSTS", "").split(",")
                                  if h.strip()]
        settings.ensure_dirs()
        return settings


def _validate(values: Dict[str, Any]) -> None:
    def num(key: str, lo: float, hi: float, typ: type) -> None:
        if key in values:
            v = values[key]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise SettingsError(f"{key} must be a number")
            if not lo <= v <= hi:
                raise SettingsError(f"{key} must be between {lo} and {hi}")
            values[key] = typ(v)

    num("port", 1, 65535, int)
    num("http_timeout", 1, 120, float)
    num("dns_timeout", 1, 60, float)
    num("scan_timeout", 0.1, 10, float)
    num("scan_workers", 1, 256, int)
    num("max_scan_hosts", 1, 65536, int)
    num("max_upload_mb", 1, 500, int)
    num("subdomain_resolve_limit", 0, 200, int)
    num("scheduler_poll_seconds", 5, 3600, int)
    num("backup_keep", 1, 365, int)
    num("retention_alert_days", 0, 3650, int)
    num("retention_activity_days", 0, 3650, int)

    for key in ("offline_mode", "allow_public_network_targets", "scheduler_enabled"):
        if key in values and not isinstance(values[key], bool):
            raise SettingsError(f"{key} must be true or false")

    if "host" in values:
        host = values["host"]
        if not isinstance(host, str) or not _HOST_RE.match(host):
            raise SettingsError("host must be an IP address or hostname")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
    if "log_level" in values:
        if str(values["log_level"]).upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            raise SettingsError("log_level must be DEBUG, INFO, WARNING or ERROR")
        values["log_level"] = str(values["log_level"]).upper()
    if "user_agent" in values:
        ua = values["user_agent"]
        if not isinstance(ua, str) or not 3 <= len(ua) <= 200 or any(c in ua for c in "\r\n"):
            raise SettingsError("user_agent must be a single line of 3-200 characters")
    if "scan_ports" in values:
        ports = values["scan_ports"]
        if not isinstance(ports, list) or not ports or len(ports) > 200:
            raise SettingsError("scan_ports must be a non-empty list (max 200)")
        clean = []
        for p in ports:
            if isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535:
                raise SettingsError("scan_ports entries must be integers 1-65535")
            clean.append(p)
        values["scan_ports"] = sorted(set(clean))
    if "feeds" in values:
        feeds = values["feeds"]
        if not isinstance(feeds, dict):
            raise SettingsError("feeds must be an object")
        for name, cfg in feeds.items():
            if not isinstance(cfg, dict) or cfg.get("type") not in ("kev", "nvd", "rss"):
                raise SettingsError(f"feed '{name}' needs type kev, nvd or rss")
            if not str(cfg.get("url", "")).lower().startswith("https://"):
                raise SettingsError(f"feed '{name}' url must start with https://")
            if "enabled" in cfg and not isinstance(cfg["enabled"], bool):
                raise SettingsError(f"feed '{name}' enabled must be true or false")
