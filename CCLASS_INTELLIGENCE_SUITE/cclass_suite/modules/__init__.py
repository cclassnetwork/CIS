"""Module registry."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base import Module, ModuleContext
from .domainintel import DomainIntel
from .emailintel import EmailIntel
from .geoint import GeoInt
from .globalwatch import GlobalWatch
from .ipintel import IpIntel
from .metadata import MetadataAnalyzer
from .networkintel import NetworkIntel
from .socialintel import SocialIntel
from .threatmonitor import ThreatMonitor

REGISTRY: Dict[str, Module] = {
    m.name: m for m in (EmailIntel(), IpIntel(), DomainIntel(), SocialIntel(), GeoInt(), ThreatMonitor(),
                        MetadataAnalyzer(), NetworkIntel(), GlobalWatch())
}

# The platform modules (the ten required ones plus GLOBALWATCH).  XKEYSEARCH and REPORTGEN are orchestration modules exposed as UI views.
CATALOG: List[Dict[str, Any]] = [
    {"name": "XKEYSEARCH", "view": "search", "runnable": False,
     "description": "Unified search across all stored intelligence plus one-click multi-module investigation with correlation."},
] + [{**m.info(), "runnable": True, "view": "modules"} for m in REGISTRY.values()] + [
    {"name": "REPORTGEN", "view": "reports", "runnable": False,
     "description": "HTML, PDF, CSV, JSON and TXT investigation reports."},
]


def get_module(name: str) -> Optional[Module]:
    return REGISTRY.get((name or "").upper())


__all__ = ["REGISTRY", "CATALOG", "Module", "ModuleContext", "get_module"]
