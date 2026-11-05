"""Persist ModuleResult objects into the database (with duplicate detection)."""

from __future__ import annotations

import logging
from typing import Dict, Tuple

from .db import Database
from .models import ModuleResult, Ref
from .scoring import finding_confidence, source_defaults

log = logging.getLogger("cclass.ingest")


def persist_result(db: Database, investigation_id: int, result: ModuleResult) -> Dict[str, int]:
    """Store entities, relationships and findings.  Returns counts of new vs duplicate items."""
    stats = {"entities_new": 0, "entities_seen": 0, "findings_new": 0, "findings_duplicate": 0,
             "relations_new": 0}
    source_cache: Dict[str, Tuple[int, str]] = {}

    def source(name: str) -> Tuple[int, str]:
        if name not in source_cache:
            kind, url, reliability = source_defaults(name)
            sid = db.ensure_source(name, kind=kind, url=url or None, reliability=reliability)
            row = db.get_source(sid)
            source_cache[name] = (sid, (row or {}).get("reliability", reliability))
        return source_cache[name]

    ids: Dict[Ref, int] = {}

    def ensure(ref: Ref) -> int:
        if ref not in ids:
            eid, created = db.upsert_entity(investigation_id, ref[0], ref[1])
            ids[ref] = eid
            stats["entities_new" if created else "entities_seen"] += 1
        return ids[ref]

    for e in result.entities:
        eid, created = db.upsert_entity(
            investigation_id, e.type, e.value, label=e.label, attributes=e.attributes,
            lat=e.lat, lon=e.lon, confidence=e.confidence if e.confidence is not None else 0.6,
        )
        ids[(e.type, e.value)] = eid
        stats["entities_new" if created else "entities_seen"] += 1

    for r in result.relations:
        sid, _ = source(r.source)
        _, created = db.add_relationship(investigation_id, ensure(r.src), ensure(r.dst), r.kind,
                                         confidence=r.confidence, source_id=sid)
        if created:
            stats["relations_new"] += 1

    for f in result.findings:
        sid, reliability = source(f.source)
        entity_id = ensure(f.entity) if f.entity else None
        key = f"{f.entity[0]}:{f.entity[1]}" if f.entity else result.query
        _, created = db.add_finding(
            investigation_id, result.module, f.title, f.summary, f.severity,
            confidence=finding_confidence(reliability, f.quality, f.observed_at),
            entity_id=entity_id, source_id=sid, data=f.data, lat=f.lat, lon=f.lon,
            observed_at=f.observed_at, entity_key=key,
        )
        stats["findings_new" if created else "findings_duplicate"] += 1

    db.touch(investigation_id)
    db.log(
        "module_run",
        f"{result.module} '{result.query[:80]}' ok={result.ok} +{stats['findings_new']} findings "
        f"(+{stats['entities_new']} entities, {stats['findings_duplicate']} duplicates)",
        investigation_id, actor=result.module,
    )
    return stats
