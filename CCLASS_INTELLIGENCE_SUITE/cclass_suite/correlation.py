"""Intelligence correlation engine.

Works purely on data already stored for an investigation (plus overlaps with
other investigations in the same local database).  It infers new relationships,
re-scores entity confidence from independent sources and records insights as
findings so they appear in timelines and reports.
"""

from __future__ import annotations

import itertools
import logging
from collections import defaultdict
from typing import Any, Dict, List

from .db import Database
from .scoring import combine

log = logging.getLogger("cclass.correlation")

INFRA_TYPES = {"domain", "hostname"}
PIVOT_DEGREE = 4
MAX_PAIR_LINKS = 45


class CorrelationEngine:
    def __init__(self, db: Database):
        self.db = db

    def correlate(self, investigation_id: int) -> List[Dict[str, Any]]:
        entities = self.db.list_entities(investigation_id, limit=5000)
        rels = self.db.list_relationships(investigation_id)
        by_id = {e["id"]: e for e in entities}
        insights: List[Dict[str, Any]] = []
        insights += self._shared_infrastructure(investigation_id, by_id, rels)
        insights += self._shared_asn(by_id, rels)
        insights += self._username_reuse(by_id, rels)
        insights += self._pivot_candidates(by_id, rels)
        insights += self._cross_investigation(investigation_id, entities)
        self.rescore_entities(investigation_id)
        self._record(investigation_id, insights)
        return insights

    # ------------------------------------------------------------------
    def _shared_infrastructure(self, inv: int, by_id: Dict[int, dict], rels: List[dict]) -> List[Dict[str, Any]]:
        groups: Dict[int, set] = defaultdict(set)
        for r in rels:
            if r["kind"] == "resolves_to" and by_id.get(r["src_entity_id"], {}).get("type") in INFRA_TYPES:
                groups[r["dst_entity_id"]].add(r["src_entity_id"])
        out = []
        src_id = self.db.ensure_source("Correlation engine", kind="analysis", reliability="C")
        for dst, srcs in groups.items():
            if len(srcs) < 2 or dst not in by_id:
                continue
            ordered = sorted(srcs)
            for a, b in itertools.islice(itertools.combinations(ordered, 2), MAX_PAIR_LINKS):
                self.db.add_relationship(inv, a, b, "shares_infrastructure", confidence=0.6, source_id=src_id)
            names = [by_id[i]["value"] for i in ordered]
            out.append({
                "kind": "shared_infrastructure", "severity": "low", "confidence": 0.6,
                "title": f"Shared infrastructure: {len(names)} names resolve to {by_id[dst]['value']}",
                "detail": "Names sharing one address: " + ", ".join(names[:12]) + (" ..." if len(names) > 12 else ""),
                "entity_ids": ordered + [dst],
            })
        return out

    def _shared_asn(self, by_id: Dict[int, dict], rels: List[dict]) -> List[Dict[str, Any]]:
        groups: Dict[int, set] = defaultdict(set)
        for r in rels:
            if r["kind"] == "belongs_to_asn" and by_id.get(r["src_entity_id"], {}).get("type") == "ip":
                groups[r["dst_entity_id"]].add(r["src_entity_id"])
        out = []
        for asn, ips in groups.items():
            if len(ips) >= 2 and asn in by_id:
                names = [by_id[i]["value"] for i in sorted(ips)]
                out.append({
                    "kind": "shared_asn", "severity": "info", "confidence": 0.7,
                    "title": f"{len(names)} addresses are announced by {by_id[asn]['value']}",
                    "detail": ", ".join(names[:12]), "entity_ids": sorted(ips) + [asn],
                })
        return out

    def _username_reuse(self, by_id: Dict[int, dict], rels: List[dict]) -> List[Dict[str, Any]]:
        profiles: Dict[int, set] = defaultdict(set)
        for r in rels:
            if r["kind"] == "has_profile" and by_id.get(r["src_entity_id"], {}).get("type") == "username":
                profiles[r["src_entity_id"]].add(r["dst_entity_id"])
        out = []
        for uid, pids in profiles.items():
            if len(pids) >= 2:
                platforms = [by_id[p].get("label") or by_id[p]["value"] for p in sorted(pids) if p in by_id]
                out.append({
                    "kind": "username_reuse", "severity": "info", "confidence": 0.5,
                    "title": f"Username '{by_id[uid]['value']}' appears on {len(pids)} public platforms",
                    "detail": "Same handle does not prove the same person; verify independently. "
                              + ", ".join(platforms[:12]),
                    "entity_ids": [uid] + sorted(pids),
                })
        return out

    def _pivot_candidates(self, by_id: Dict[int, dict], rels: List[dict]) -> List[Dict[str, Any]]:
        degree: Dict[int, int] = defaultdict(int)
        for r in rels:
            degree[r["src_entity_id"]] += 1
            degree[r["dst_entity_id"]] += 1
        out = []
        for eid, d in sorted(degree.items(), key=lambda kv: -kv[1]):
            if d >= PIVOT_DEGREE and eid in by_id and by_id[eid]["type"] not in ("country", "software"):
                e = by_id[eid]
                out.append({
                    "kind": "pivot_candidate", "severity": "info", "confidence": 0.6,
                    "title": f"Pivot candidate: {e['type']} {e['value']} has {d} connections",
                    "detail": "Highly connected entity - a good starting point for further lawful research.",
                    "entity_ids": [eid],
                })
            if len(out) >= 5:
                break
        return out

    def _cross_investigation(self, inv: int, entities: List[dict]) -> List[Dict[str, Any]]:
        mine = {(e["type"], e["value_norm"]): e for e in entities}
        out = []
        for ov in self.db.cross_investigation_overlaps(limit=500):
            key = (ov["type"], ov["value_norm"])
            if key in mine and inv in ov["investigation_ids"]:
                others = [i for i in ov["investigation_ids"] if i != inv]
                out.append({
                    "kind": "cross_investigation", "severity": "low", "confidence": 0.7,
                    "title": f"{ov['type']} {ov['value']} also appears in investigation(s) "
                             + ", ".join(f"#{i}" for i in others),
                    "detail": "The same artefact recurs across investigations - review for a common actor or campaign.",
                    "entity_ids": [mine[key]["id"]],
                })
        return out

    # ------------------------------------------------------------------
    def rescore_entities(self, investigation_id: int) -> int:
        """Entity confidence = independent combination of its best finding confidence per source."""
        per_entity: Dict[int, Dict[int, float]] = defaultdict(dict)
        for f in self.db.list_findings(investigation_id, limit=10000):
            if f["entity_id"] is None or f["module"] == "CORRELATION":
                continue
            sid = f["source_id"] or 0
            per_entity[f["entity_id"]][sid] = max(per_entity[f["entity_id"]].get(sid, 0.0), f["confidence"])
        for eid, by_source in per_entity.items():
            self.db.set_entity_confidence(eid, combine(by_source.values()))
        return len(per_entity)

    def _record(self, investigation_id: int, insights: List[Dict[str, Any]]) -> None:
        src_id = self.db.ensure_source("Correlation engine", kind="analysis", reliability="C")
        for ins in insights:
            ids = ins.get("entity_ids", [])
            self.db.add_finding(
                investigation_id, "CORRELATION", ins["title"], ins["detail"], ins["severity"],
                confidence=ins["confidence"], entity_id=ids[0] if ids else None, source_id=src_id,
                data={"kind": ins["kind"], "entity_ids": ids},
                entity_key="|".join(str(i) for i in ids),
            )
        if insights:
            self.db.log("correlation_run", f"{len(insights)} insight(s)", investigation_id, actor="CORRELATION")
