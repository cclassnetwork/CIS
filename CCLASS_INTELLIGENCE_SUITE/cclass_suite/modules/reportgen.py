"""REPORTGEN - HTML, PDF, CSV, JSON and TXT investigation reports."""

from __future__ import annotations

import csv
import io
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from xml.sax.saxutils import escape

from .. import __version__
from ..config import Settings
from ..db import Database
from ..models import SEVERITIES
from ..scoring import RELIABILITY_LABEL, confidence_label

log = logging.getLogger("cclass.reports")

FORMATS = ("html", "pdf", "csv", "json", "txt")
CONTENT_TYPES = {
    "html": "text/html; charset=utf-8", "pdf": "application/pdf", "csv": "text/csv; charset=utf-8",
    "json": "application/json", "txt": "text/plain; charset=utf-8",
}

HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{{ inv.name }} - CCLASS report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#0a1628;--card:#112240;--line:#1d3a6b;--ink:#dce8ff;--mute:#8aa4cf;--accent:#3b82f6}
body{background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:0;padding:32px}
h1{margin:0 0 4px}h2{border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:32px;color:var(--accent)}
.meta{color:var(--mute)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin:12px 0}
table{width:100%;border-collapse:collapse;background:var(--card)}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:#0d1d38;color:var(--mute)}.sev{padding:1px 8px;border-radius:10px;font-size:12px;color:#fff}
.sev-info{background:#475569}.sev-low{background:#2563eb}.sev-medium{background:#d97706}.sev-high{background:#dc2626}.sev-critical{background:#7f1d1d}
.stats span{display:inline-block;margin-right:18px}code{color:#9cc3ff}
.tlp{display:inline-block;font:700 13px/1 ui-monospace,Consolas,monospace;padding:5px 9px;border-radius:3px;letter-spacing:.5px;background:#000;border:1px solid #444}
.tlp-RED{color:#ff2b2b}.tlp-AMBER,.tlp-AMBER-STRICT{color:#ffc000}.tlp-GREEN{color:#33ff00}.tlp-CLEAR{color:#fff}
.tlp-bar{text-align:right;margin:-12px 0 12px}
footer{margin-top:40px;color:var(--mute);font-size:12px}
</style></head><body>
<div class="tlp-bar"><span class="tlp tlp-{{ inv.tlp|replace('+', '-') }}">TLP:{{ inv.tlp }}</span></div>
<h1>{{ inv.name }}</h1>
<div class="meta">Investigation #{{ inv.id }} &middot; status {{ inv.status }} &middot; priority {{ inv.priority }}{% if inv.assignee %} &middot; assigned to {{ inv.assignee }}{% endif %}{% if inv.due_date %} &middot; due {{ inv.due_date }}{% endif %}{% if inv.tags %} &middot; tags {{ inv.tags }}{% endif %} &middot;
generated {{ generated_at }} by CCLASS Intelligence Suite {{ version }}</div>
{% if inv.description %}<div class="card">{{ inv.description }}</div>{% endif %}
<h2>Summary</h2>
<div class="card stats">
<span><b>{{ entities|length }}</b> entities</span><span><b>{{ findings|length }}</b> findings</span>
<span><b>{{ evidence|length }}</b> evidence items</span><span><b>{{ relationships|length }}</b> relationships</span>
{% for sev, n in severity_counts.items() %}{% if n %}<span class="sev sev-{{ sev }}">{{ sev }}: {{ n }}</span>{% endif %}{% endfor %}
</div>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Finding</th><th>Entity</th><th>Source</th><th>Confidence</th></tr>
{% for f in findings %}<tr><td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
<td><b>{{ f.title }}</b><br><span class="meta">{{ f.summary }}</span></td>
<td>{% if f.entity_value %}{{ f.entity_type }}: <code>{{ f.entity_value }}</code>{% endif %}</td>
<td>{{ f.source_name or '-' }}{% if f.source_reliability %} ({{ f.source_reliability }}){% endif %}<br><span class="meta">{{ f.module }}</span></td>
<td>{{ '%.0f'|format(f.confidence * 100) }}% {{ f.confidence_label }}</td></tr>
{% else %}<tr><td colspan="5">No findings recorded.</td></tr>{% endfor %}</table>
<h2>Entities</h2>
<table><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Sightings</th></tr>
{% for e in entities %}<tr><td>{{ e.type }}</td><td><code>{{ e.value }}</code>{% if e.label and e.label != e.value %}<br><span class="meta">{{ e.label }}</span>{% endif %}</td>
<td>{{ '%.0f'|format(e.confidence * 100) }}%</td><td>{{ e.sightings }}</td></tr>{% endfor %}</table>
<h2>Relationships</h2>
<table><tr><th>From</th><th>Relation</th><th>To</th><th>Confidence</th></tr>
{% for r in relationships %}<tr><td><code>{{ r.src }}</code></td><td>{{ r.kind }}</td><td><code>{{ r.dst }}</code></td><td>{{ '%.0f'|format(r.confidence * 100) }}%</td></tr>
{% else %}<tr><td colspan="4">No relationships recorded.</td></tr>{% endfor %}</table>
<h2>Evidence</h2>
<table><tr><th>File</th><th>SHA-256</th><th>Size</th><th>Collected</th><th>Notes</th></tr>
{% for v in evidence %}<tr><td>{{ v.filename }}</td><td><code>{{ v.sha256 }}</code></td><td>{{ v.size_bytes }}</td><td>{{ v.collected_at }}</td><td>{{ v.notes }}</td></tr>
{% else %}<tr><td colspan="5">No evidence attached.</td></tr>{% endfor %}</table>
<h2>Sources and reliability</h2>
<table><tr><th>Source</th><th>Reliability</th><th>Findings</th></tr>
{% for s in sources %}<tr><td>{{ s.name }}</td><td>{{ s.reliability }} - {{ s.label }}</td><td>{{ s.count }}</td></tr>{% endfor %}</table>
<h2>Timeline (latest 100)</h2>
<table><tr><th>Time (UTC)</th><th>Type</th><th>Event</th></tr>
{% for t in timeline %}<tr><td>{{ t.time }}</td><td>{{ t.kind }}</td><td>{{ t.title }}{% if t.detail %}<br><span class="meta">{{ t.detail }}</span>{% endif %}</td></tr>{% endfor %}</table>
<footer><span class="tlp tlp-{{ inv.tlp|replace('+', '-') }}">TLP:{{ inv.tlp }}</span> Share only as the TLP marking permits.<br>Compiled from public-source and user-provided data. Confidence values are analytic estimates, not facts; verify
critical findings independently. Handle personal data in accordance with applicable law.</footer>
</body></html>"""


def _csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


class ReportGenerator:
    def __init__(self, db: Database, settings: Settings):
        self.db, self.settings = db, settings

    # ------------------------------------------------------------------
    def build_context(self, investigation_id: int) -> Dict[str, Any]:
        inv = self.db.get_investigation(investigation_id)
        if inv is None:
            raise ValueError("investigation not found")
        entities = self.db.list_entities(investigation_id, limit=5000)
        names = {e["id"]: f"{e['type']}:{e['value']}" for e in entities}
        findings = self.db.list_findings(investigation_id, limit=5000)
        for f in findings:
            f["confidence_label"] = confidence_label(f["confidence"])
        rels = [{"src": names.get(r["src_entity_id"], "?"), "dst": names.get(r["dst_entity_id"], "?"),
                 "kind": r["kind"], "confidence": r["confidence"]}
                for r in self.db.list_relationships(investigation_id)]
        counts = Counter(f["severity"] for f in findings)
        by_source: Counter = Counter()
        rel_of: Dict[str, str] = {}
        for f in findings:
            if f.get("source_name"):
                by_source[f["source_name"]] += 1
                rel_of[f["source_name"]] = f.get("source_reliability") or "F"
        return {
            "inv": inv, "entities": entities, "findings": findings, "relationships": rels,
            "evidence": self.db.list_evidence(investigation_id),
            "timeline": self.db.timeline(investigation_id, limit=100),
            "severity_counts": {s: counts.get(s, 0) for s in reversed(SEVERITIES)},
            "sources": [{"name": n, "reliability": rel_of[n], "label": RELIABILITY_LABEL.get(rel_of[n], ""), "count": c}
                        for n, c in by_source.most_common()],
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "version": __version__,
        }

    # ------------------------------------------------------------------
    def generate(self, investigation_id: int, fmt: str) -> Path:
        fmt = fmt.lower()
        if fmt not in FORMATS:
            raise ValueError(f"unsupported format '{fmt}' (choose from {', '.join(FORMATS)})")
        ctx = self.build_context(investigation_id)
        self.settings.reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self.settings.reports_dir / f"investigation_{investigation_id}_{stamp}.{fmt}"
        if fmt == "html":
            path.write_text(self._html(ctx), encoding="utf-8")
        elif fmt == "json":
            path.write_text(json.dumps(ctx, indent=2, default=str), encoding="utf-8")
        elif fmt == "csv":
            path.write_text(self._csv(ctx), encoding="utf-8", newline="")
        elif fmt == "txt":
            path.write_text(self._txt(ctx), encoding="utf-8")
        else:
            self._pdf(ctx, path)
        self.db.add_report(investigation_id, ctx["inv"]["name"], fmt, str(path))
        return path

    # ------------------------------------------------------------------
    def _html(self, ctx: Dict[str, Any]) -> str:
        from jinja2 import Environment

        return Environment(autoescape=True).from_string(HTML_TEMPLATE).render(**ctx)

    def _csv(self, ctx: Dict[str, Any]) -> str:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["id", "severity", "confidence", "module", "title", "summary", "entity_type", "entity_value",
                    "source", "source_reliability", "observed_at", "created_at", "tlp"])
        for f in ctx["findings"]:
            w.writerow([_csv_safe(x) for x in (
                f["id"], f["severity"], f["confidence"], f["module"], f["title"], f["summary"],
                f.get("entity_type"), f.get("entity_value"), f.get("source_name"), f.get("source_reliability"),
                f.get("observed_at"), f["created_at"], ctx["inv"]["tlp"])])
        return buf.getvalue()

    def _txt(self, ctx: Dict[str, Any]) -> str:
        inv = ctx["inv"]
        lines = [f"TLP:{inv['tlp']}", f"CCLASS INTELLIGENCE SUITE {ctx['version']} - INVESTIGATION REPORT", "=" * 72,
                 f"#{inv['id']}  {inv['name']}", f"Status: {inv['status']}   Priority: {inv['priority']}   "
                 f"Assignee: {inv.get('assignee') or '-'}   Due: {inv.get('due_date') or '-'}   Tags: {inv.get('tags') or '-'}",
                 f"Generated: {ctx['generated_at']}", ""]
        if inv["description"]:
            lines += [inv["description"], ""]
        lines.append("SUMMARY")
        lines.append(f"  {len(ctx['entities'])} entities, {len(ctx['findings'])} findings, "
                     f"{len(ctx['evidence'])} evidence items, {len(ctx['relationships'])} relationships")
        lines.append("  " + ", ".join(f"{k}={v}" for k, v in ctx["severity_counts"].items() if v))
        lines += ["", "FINDINGS", "-" * 72]
        for f in ctx["findings"]:
            lines.append(f"[{f['severity'].upper():8}] {f['title']}  (confidence {f['confidence']:.0%}, "
                         f"{f.get('source_name') or 'n/a'})")
            if f["summary"]:
                lines.append(f"            {f['summary']}")
        lines += ["", "ENTITIES", "-" * 72]
        lines += [f"{e['type']:<12} {e['value']}  ({e['confidence']:.0%})" for e in ctx["entities"]]
        lines += ["", "EVIDENCE", "-" * 72]
        lines += [f"{v['filename']}  sha256={v['sha256']}  {v['size_bytes']} bytes" for v in ctx["evidence"]] or ["(none)"]
        lines += ["", "Confidence values are analytic estimates; verify critical findings independently.",
                  f"TLP:{inv['tlp']} - share only as the marking permits."]
        return "\n".join(lines) + "\n"

    def _pdf(self, ctx: Dict[str, Any], path: Path) -> None:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, landscape
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        except ImportError as exc:
            raise RuntimeError("reportlab is not installed; PDF reports are unavailable") from exc
        styles = getSampleStyleSheet()
        small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=8, leading=10)
        inv = ctx["inv"]
        doc = SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=15 * mm, rightMargin=15 * mm,
                                topMargin=15 * mm, bottomMargin=15 * mm, title=inv["name"][:100],
                                author="CCLASS Intelligence Suite")
        p = lambda text, st=small: Paragraph(escape(str(text if text is not None else ""))[:1200], st)  # noqa: E731
        story: List[Any] = [Paragraph(f"<b>TLP:{escape(inv['tlp'])}</b>", styles["BodyText"]),
                            Paragraph(escape(inv["name"]), styles["Title"]),
                            p(f"Investigation #{inv['id']} | status {inv['status']} | priority {inv['priority']} | "
                              f"generated {ctx['generated_at']}"), Spacer(1, 6)]
        if inv["description"]:
            story += [p(inv["description"], styles["BodyText"]), Spacer(1, 6)]
        story.append(p(f"{len(ctx['entities'])} entities | {len(ctx['findings'])} findings | {len(ctx['evidence'])} "
                       f"evidence items | " + ", ".join(f"{k}: {v}" for k, v in ctx["severity_counts"].items() if v),
                       styles["BodyText"]))

        def table(head: List[str], rows: List[List[Any]], widths: List[float]) -> Table:
            data = [[p(h) for h in head]] + [[p(c) for c in r] for r in rows]
            t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe7ff")),
                                   ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9fb4d9")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            return t

        story += [Spacer(1, 8), Paragraph("Findings", styles["Heading2"]),
                  table(["Severity", "Finding", "Entity", "Source", "Conf."],
                        [[f["severity"], f"{f['title']} - {f['summary']}",
                          f"{f.get('entity_type') or ''} {f.get('entity_value') or ''}".strip(),
                          f"{f.get('source_name') or ''} ({f.get('source_reliability') or '-'})",
                          f"{f['confidence']:.0%}"] for f in ctx["findings"]] or [["-", "No findings", "", "", ""]],
                        [20, 130, 55, 45, 15])]
        story += [Spacer(1, 8), Paragraph("Entities", styles["Heading2"]),
                  table(["Type", "Value", "Confidence"],
                        [[e["type"], e["value"], f"{e['confidence']:.0%}"] for e in ctx["entities"]] or [["-", "-", "-"]],
                        [30, 190, 25])]
        story += [Spacer(1, 8), Paragraph("Evidence", styles["Heading2"]),
                  table(["File", "SHA-256", "Size"],
                        [[v["filename"], v["sha256"], v["size_bytes"]] for v in ctx["evidence"]] or [["-", "-", "-"]],
                        [60, 150, 25])]
        story += [Spacer(1, 10), p("Confidence values are analytic estimates; verify critical findings independently.")]
        tlp_label = f"TLP:{inv['tlp']}"

        def footer(canvas, _doc):
            canvas.saveState()
            canvas.setFont("Helvetica-Bold", 8)
            canvas.drawString(15 * mm, 8 * mm, tlp_label)
            canvas.drawRightString(landscape(A4)[0] - 15 * mm, 8 * mm, f"Page {canvas.getPageNumber()}")
            canvas.restoreState()

        doc.build(story, onFirstPage=footer, onLaterPages=footer)
