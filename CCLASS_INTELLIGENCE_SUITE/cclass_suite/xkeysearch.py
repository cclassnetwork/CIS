"""XKEYSEARCH - unified search and multi-module investigation orchestration.

Takes any selector (e-mail, IP, domain, URL, username, CVE, coordinates, place
or free text), decides which public-source modules apply, runs them, stores
the results and finally runs the correlation engine.  Active modules (network
inventory) are never started automatically.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .correlation import CorrelationEngine
from .db import Database
from .ingest import persist_result
from .modules import REGISTRY, ModuleContext, get_module
from .modules.ipintel import lookup_allowed
from .modules.socialintel import username_from_url
from .utils import detect_type, valid_domain

log = logging.getLogger("cclass.xkey")

MAX_QUERY_LEN = 500
MAX_PIVOT_IPS = 3
MAX_PIVOT_DEPTH = 2
MAX_PIVOT_STEPS = 8


class XKeySearch:
    def __init__(self, db: Database, mctx: ModuleContext, correlation: CorrelationEngine):
        self.db, self.mctx, self.correlation = db, mctx, correlation

    # ------------------------------------------------------------------ search
    def search(self, query: str, limit: int = 25) -> Dict[str, Any]:
        q = (query or "").strip()
        if len(q) > MAX_QUERY_LEN:
            raise ValueError("query too long")
        results = self.db.search(q, limit=limit)
        return {"query": q, "detected_type": detect_type(q) if q else "text", "results": results,
                "total": sum(len(v) for v in results.values())}

    # ------------------------------------------------------------------ planning
    def plan(self, query: str, qtype: Optional[str] = None) -> List[Tuple[str, str]]:
        q = query.strip()
        qtype = qtype or detect_type(q)
        if qtype == "email":
            return [("EMAILINTEL", q.lower())]
        if qtype == "ip":
            return [("IPINTEL", q)]
        if qtype == "domain":
            return [("DOMAININTEL", q.lower())]
        if qtype == "url":
            parsed = urlparse(q)
            steps: List[Tuple[str, str]] = []
            host = (parsed.hostname or "").lower()
            if host:
                try:
                    ipaddress.ip_address(host)
                    steps.append(("IPINTEL", host))
                except ValueError:
                    if valid_domain(host):
                        steps.append(("DOMAININTEL", host))
            profile = username_from_url(q)
            if profile:
                steps.append(("SOCIALINTEL", profile["username"]))
            return steps
        if qtype == "username":
            return [("SOCIALINTEL", q.lstrip("@"))]
        if qtype == "cve":
            return [("THREATMONITOR", q.upper())]
        if qtype == "coordinates":
            return [("GEOINT", q)]
        if qtype == "text":
            return [("GEOINT", q), ("THREATMONITOR", q)]
        return []

    # ------------------------------------------------------------------ investigate
    def investigate(self, query: str, investigation_id: Optional[int] = None, modules: Optional[List[str]] = None,
                    pivot: bool = True, name: Optional[str] = None) -> Dict[str, Any]:
        q = (query or "").strip()
        if not q:
            raise ValueError("query is empty")
        if len(q) > MAX_QUERY_LEN:
            raise ValueError("query too long")
        qtype = detect_type(q)

        if modules:
            steps: List[Tuple[str, str]] = []
            for m in modules:
                mod = get_module(m)
                if mod is None:
                    raise ValueError(f"unknown module '{m}'")
                if mod.requires_authorization or mod.cli_only:
                    raise ValueError(f"{mod.name} cannot be started from a search; use its own run option")
                steps.append((mod.name, q))
        else:
            steps = self.plan(q, qtype)

        created_investigation = False
        if investigation_id is None:
            investigation_id = self.db.create_investigation(name or f"Auto: {q[:60]}",
                                                            f"Created automatically from selector '{q[:120]}'.")
            created_investigation = True
        elif self.db.get_investigation(investigation_id) is None:
            raise ValueError("investigation not found")

        outcomes: List[Dict[str, Any]] = []
        notes: List[str] = []
        if qtype == "hash":
            self.db.upsert_entity(investigation_id, "hash", q, confidence=0.9)
            notes.append("File hashes are recorded as entities; no public-source module looks them up.")
        if qtype in ("network", "mac"):
            notes.append("Network inventory is an active module: use the NETWORKINTEL run option with authorisation.")
        if not steps and not notes:
            notes.append("No module applies to this selector.")

        seen = set(steps)
        frontier: List[Tuple[str, str]] = []
        for module_name, mq in steps:
            outcome = self._run_step(module_name, mq, investigation_id)
            outcomes.append(outcome)
            found = outcome.pop("_pivots", [])
            if pivot and outcome["ok"]:
                frontier += found

        # Bounded breadth-first pivoting: e-mail -> domain -> addresses, at most MAX_PIVOT_DEPTH levels
        # and MAX_PIVOT_STEPS extra module runs, so one selector can never fan out unboundedly.
        extra = 0
        for _depth in range(MAX_PIVOT_DEPTH if pivot else 0):
            nxt: List[Tuple[str, str]] = []
            for module_name, mq in frontier:
                if (module_name, mq) in seen or extra >= MAX_PIVOT_STEPS:
                    continue
                seen.add((module_name, mq))
                extra += 1
                outcome = {**self._run_step(module_name, mq, investigation_id), "pivot": True}
                found = outcome.pop("_pivots", [])
                outcomes.append(outcome)
                if outcome["ok"]:
                    nxt += found
            frontier = nxt
            if not frontier:
                break

        insights = self.correlation.correlate(investigation_id)
        return {"investigation_id": investigation_id, "created_investigation": created_investigation,
                "detected_type": qtype, "modules": outcomes, "insights": insights, "notes": notes,
                "offline": self.mctx.settings.offline_mode}

    def _run_step(self, module_name: str, mq: str, investigation_id: int) -> Dict[str, Any]:
        mod = REGISTRY[module_name]
        result = mod.safe_run(mq, self.mctx)
        stats = persist_result(self.db, investigation_id, result)
        out: Dict[str, Any] = {"module": module_name, "query": mq, "ok": result.ok, "error": result.error,
                               "warnings": result.warnings, "stats": stats, "_pivots": []}
        if result.ok:
            if module_name == "EMAILINTEL":
                dom = mq.rsplit("@", 1)[-1]
                out["_pivots"].append(("DOMAININTEL", dom))
            if module_name == "DOMAININTEL":
                root_ips = [r.dst[1] for r in result.relations if r.kind == "resolves_to" and r.src[1] == mq]
                for ip in root_ips[:MAX_PIVOT_IPS]:
                    try:
                        if lookup_allowed(self.mctx, ipaddress.ip_address(ip)):
                            out["_pivots"].append(("IPINTEL", ip))
                    except ValueError:
                        continue
            if module_name == "SOCIALINTEL":
                pass
        return out
