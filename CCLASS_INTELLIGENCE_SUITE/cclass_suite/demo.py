"""Offline demonstration data loader (uses bundled sample datasets only - never the network)."""

from __future__ import annotations

import dataclasses
import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict

from .context import AppContext
from .dnsutil import DnsClient
from .modules import ModuleContext
from .utils import HttpClient
from .xkeysearch import XKeySearch

log = logging.getLogger("cclass.demo")


def _make_demo_photo(path: Path) -> None:
    """Create a small JPEG with EXIF (device, software, date) and GPS in Lagos, Nigeria."""
    from PIL import Image

    img = Image.new("RGB", (64, 48), (20, 60, 120))
    exif = Image.Exif()
    exif[0x010F] = "DemoCam"
    exif[0x0110] = "D-100"
    exif[0x0131] = "CCLASS Demo Editor 1.0"
    exif[0x0132] = "2026:10:01 09:30:00"
    gps = exif.get_ifd(0x8825)
    gps[1], gps[2] = "N", (6.0, 31.0, 28.0)
    gps[3], gps[4] = "E", (3.0, 22.0, 46.0)
    img.save(path, "JPEG", exif=exif)


def load_demo(ctx: AppContext) -> Dict[str, Any]:
    """Create (or extend) the demo investigation, watchlists, alerts and sample evidence."""
    spec = json.loads((ctx.settings.sample_dir / "sample_investigation.json").read_text(encoding="utf-8"))
    offline = dataclasses.replace(ctx.settings, offline_mode=True)
    mctx = ModuleContext(offline, HttpClient(offline), DnsClient(offline), ctx.db)
    xkey = XKeySearch(ctx.db, mctx, ctx.correlation)

    existing = next((i for i in ctx.db.list_investigations() if i["name"] == spec["name"]), None)
    inv_id = existing["id"] if existing else ctx.db.create_investigation(spec["name"], spec["description"], "medium")

    summaries = []
    for q in spec["queries"]:
        out = xkey.investigate(q, investigation_id=inv_id, pivot=True)
        summaries.append({"query": q, "modules": [m["module"] for m in out["modules"]]})

    for kind, value in spec.get("watchlists", []):
        ctx.db.add_watchlist(kind, value, "demo watchlist")

    # sample threat feed -> alerts, then watchlist matching
    from .modules.threatmonitor import ThreatFeedManager

    feed_summary = ThreatFeedManager(ctx.db, mctx).refresh(offline_sample=True)

    # sample evidence: a generated photo with GPS metadata
    evidence: Dict[str, Any] = {}
    try:
        with tempfile.TemporaryDirectory() as tmp:
            photo = Path(tmp) / "sample_site_photo.jpg"
            _make_demo_photo(photo)
            evidence = ctx.add_evidence_from_path(inv_id, photo, "sample_site_photo.jpg",
                                                  "Generated demo image with EXIF + GPS metadata", "demo")
        if evidence.get("id") and not evidence.get("duplicate"):
            ctx.analyze_evidence(evidence["id"])
    except Exception as exc:  # noqa: BLE001 - the demo must still load without Pillow
        log.warning("demo evidence skipped: %s", exc)

    ctx.correlation.correlate(inv_id)
    if not any(t["name"] == "Demo: refresh threat feeds" for t in ctx.db.list_tasks()):
        ctx.db.add_task("Demo: refresh threat feeds", "feed_refresh", 360, {}, enabled=False)
    ctx.db.log("demo_loaded", spec["name"], inv_id)
    return {"investigation_id": inv_id, "queries": summaries, "alerts_added": feed_summary["new_alerts"],
            "evidence": evidence}
