"""Base class and shared context for intelligence modules."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..config import Settings
from ..db import Database
from ..dnsutil import DnsClient
from ..models import ModuleResult
from ..utils import HttpClient

log = logging.getLogger("cclass.modules")


@dataclass
class ModuleContext:
    settings: Settings
    http: HttpClient
    dns: DnsClient
    db: Optional[Database] = None

    def sample(self, filename: str) -> Any:
        """Load a bundled offline demonstration dataset (None if unavailable)."""
        try:
            return json.loads((self.settings.sample_dir / filename).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None


class Module:
    name = "BASE"
    description = ""
    accepts: Tuple[str, ...] = ()
    cli_only = False  # modules that read server-side file paths are not exposed over the web API
    requires_authorization = False  # active modules must be explicitly authorised by the operator
    api_options: Tuple[str, ...] = ()  # extra keyword options the web API may pass through to run()

    def run(self, query: str, ctx: ModuleContext, **options: Any) -> ModuleResult:  # pragma: no cover
        raise NotImplementedError

    def safe_run(self, query: str, ctx: ModuleContext, **options: Any) -> ModuleResult:
        """Run the module; any unexpected exception becomes a failed result, never a crash."""
        try:
            return self.run(query, ctx, **options)
        except Exception as exc:  # noqa: BLE001
            log.exception("Module %s crashed on %r", self.name, query)
            return ModuleResult(self.name, query, ok=False, error=f"internal error: {exc.__class__.__name__}")

    def info(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description, "accepts": list(self.accepts),
                "cli_only": self.cli_only,
                "requires_authorization": self.requires_authorization}


OFFLINE_SOURCE = "Offline sample dataset"


def pick_source(ctx: ModuleContext, real_name: str) -> str:
    """Findings drawn from bundled sample data are attributed to the (low reliability) sample source."""
    return OFFLINE_SOURCE if ctx.settings.offline_mode else real_name
