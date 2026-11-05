"""Plain data structures exchanged between intelligence modules and storage."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

Ref = Tuple[str, str]  # (entity type, entity value)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Entity:
    type: str
    value: str
    label: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    lat: Optional[float] = None
    lon: Optional[float] = None
    confidence: Optional[float] = None


@dataclass
class Finding:
    title: str
    summary: str = ""
    severity: str = "info"
    source: str = "Unknown"
    entity: Optional[Ref] = None
    data: Dict[str, Any] = field(default_factory=dict)
    lat: Optional[float] = None
    lon: Optional[float] = None
    observed_at: Optional[str] = None
    quality: float = 0.85  # how directly the observation supports the statement (0-1)


@dataclass
class Relation:
    src: Ref
    dst: Ref
    kind: str
    source: str = "Unknown"
    confidence: float = 0.7


@dataclass
class ModuleResult:
    module: str
    query: str
    ok: bool = True
    error: Optional[str] = None
    offline: bool = False
    warnings: List[str] = field(default_factory=list)
    entities: List[Entity] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    relations: List[Relation] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=utcnow_iso)

    def add_entity(self, type: str, value: str, **kw: Any) -> Entity:
        for e in self.entities:
            if e.type == type and e.value == value:
                if kw.get("attributes"):
                    e.attributes.update(kw["attributes"])
                for k in ("label", "lat", "lon", "confidence"):
                    if kw.get(k) is not None:
                        setattr(e, k, kw[k])
                return e
        ent = Entity(type=type, value=value, **kw)
        self.entities.append(ent)
        return ent

    def add_finding(self, title: str, summary: str = "", severity: str = "info", **kw: Any) -> Finding:
        f = Finding(title=title, summary=summary, severity=severity, **kw)
        self.findings.append(f)
        return f

    def relate(self, src: Ref, dst: Ref, kind: str, source: str = "Unknown", confidence: float = 0.7) -> None:
        self.relations.append(Relation(src, dst, kind, source, confidence))

    def fail(self, message: str) -> "ModuleResult":
        self.ok = False
        self.error = message
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "query": self.query,
            "ok": self.ok,
            "error": self.error,
            "offline": self.offline,
            "warnings": self.warnings,
            "started_at": self.started_at,
            "entities": [e.__dict__ for e in self.entities],
            "findings": [f.__dict__ for f in self.findings],
            "relations": [
                {"src": list(r.src), "dst": list(r.dst), "kind": r.kind, "source": r.source,
                 "confidence": r.confidence}
                for r in self.relations
            ],
            "raw": self.raw,
        }


# ---------------------------------------------------------------------------- case management
TLP_LEVELS = ("CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED")   # FIRST Traffic Light Protocol 2.0
_TAG_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9._-]{0,29}$")


def normalise_tags(value) -> str:
    """Accept a comma-separated string or a list; return a clean, de-duplicated, comma-separated string."""
    if value is None:
        return ""
    raw = value.split(",") if isinstance(value, str) else list(value)
    tags = []
    for t in raw:
        t = str(t).strip().lower().replace(" ", "-")
        if not t:
            continue
        if not _TAG_RE.match(t):
            raise ValueError(f"invalid tag '{t[:40]}': use letters, digits, '.', '_' or '-' (max 30 characters)")
        if t not in tags:
            tags.append(t)
    if len(tags) > 10:
        raise ValueError("at most 10 tags per investigation")
    return ",".join(tags)


def validate_due_date(value):
    if value in (None, ""):
        return None
    from datetime import date
    try:
        return date.fromisoformat(str(value)).isoformat()
    except ValueError as exc:
        raise ValueError("due date must be YYYY-MM-DD") from exc
