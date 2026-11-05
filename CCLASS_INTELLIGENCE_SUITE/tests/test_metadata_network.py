import io
import zipfile
from pathlib import Path

import pytest

from cclass_suite.config import Settings
from cclass_suite.modules import REGISTRY
from cclass_suite.modules.networkintel import AuthorizationError, resolve_targets, tcp_state


def make_docx(path: Path, macro=False, external=False):
    core = ('<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
            '<dc:creator>Jane Analyst</dc:creator><cp:lastModifiedBy>John Editor</cp:lastModifiedBy>'
            '<dcterms:created>2026-01-02T03:04:05Z</dcterms:created></cp:coreProperties>')
    app = '<?xml version="1.0"?><Properties><Application>Microsoft Office Word</Application><Company>Demo Corp</Company></Properties>'
    rels = ('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="r1" Type="t" Target="https://tracker.example/x.dotm" TargetMode="External"/></Relationships>')
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("word/document.xml", "<w/>")
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        if macro:
            z.writestr("word/vbaProject.bin", b"x")
        if external:
            z.writestr("word/_rels/document.xml.rels", rels)


def test_metadata_docx(ctx, tmp_path):
    f = tmp_path / "a.docx"
    make_docx(f, macro=True, external=True)
    r = REGISTRY["METADATA"].safe_run(str(f), ctx.mctx)
    assert r.ok
    t = " | ".join(x.title for x in r.findings)
    assert "File hashes" in t and "DOCX document properties" in t and "VBA macro" in t and "external reference" in t
    people = {e.value for e in r.entities if e.type == "person"}
    assert people == {"Jane Analyst", "John Editor"}
    assert any(e.type == "organization" and e.value == "Demo Corp" for e in r.entities)


def test_metadata_xxe_not_expanded(ctx, tmp_path):
    f = tmp_path / "evil.docx"
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><cp:coreProperties xmlns:cp="a" xmlns:dc="b"><dc:creator>&e;</dc:creator></cp:coreProperties>'
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("word/document.xml", "<w/>")
        z.writestr("docProps/core.xml", evil)
    r = REGISTRY["METADATA"].safe_run(str(f), ctx.mctx)
    assert r.ok and not any("root:" in x.summary for x in r.findings)
    assert not any(e.type == "person" for e in r.entities)


def test_metadata_zip_bomb_guard(ctx, tmp_path, monkeypatch):
    import cclass_suite.modules.metadata as md
    monkeypatch.setattr(md, "MAX_ZIP_ENTRIES", 2)
    f = tmp_path / "many.zip"
    with zipfile.ZipFile(f, "w") as z:
        for i in range(5):
            z.writestr(f"f{i}", "x")
    r = REGISTRY["METADATA"].safe_run(str(f), ctx.mctx)
    assert any("decompression bomb" in x.title for x in r.findings)


def test_metadata_pdf(ctx, tmp_path):
    from reportlab.pdfgen import canvas
    f = tmp_path / "a.pdf"
    c = canvas.Canvas(str(f))
    c.setAuthor("Pat Writer"); c.setTitle("Quarterly"); c.drawString(50, 750, "hi"); c.save()
    r = REGISTRY["METADATA"].safe_run(str(f), ctx.mctx)
    assert r.ok and any(e.type == "person" and e.value == "Pat Writer" for e in r.entities)
    assert any("PDF document properties" == x.title for x in r.findings)


def test_metadata_image_gps(ctx, tmp_path):
    from cclass_suite.demo import _make_demo_photo
    f = tmp_path / "p.jpg"
    _make_demo_photo(f)
    r = REGISTRY["METADATA"].safe_run(str(f), ctx.mctx)
    gps = [e for e in r.entities if e.type == "place"]
    assert gps and abs(gps[0].lat - 6.5244) < 0.01 and abs(gps[0].lon - 3.3794) < 0.01
    assert any(e.type == "device" and e.value == "DemoCam D-100" for e in r.entities)


def test_metadata_handles_garbage_and_missing(ctx, tmp_path):
    g = tmp_path / "g.pdf"
    g.write_bytes(b"%PDF-1.4 this is not really a pdf")
    r = REGISTRY["METADATA"].safe_run(str(g), ctx.mctx)
    assert r.ok and r.findings[0].title == "File hashes"  # hashes still recorded, no crash
    assert not REGISTRY["METADATA"].safe_run(str(tmp_path / "nope"), ctx.mctx).ok


def test_metadata_size_limit(ctx, tmp_path):
    ctx.settings.max_upload_mb = 1
    big = tmp_path / "big.bin"
    big.write_bytes(b"0" * (1024 * 1024 + 1))
    assert "exceeds" in REGISTRY["METADATA"].safe_run(str(big), ctx.mctx).error


# --------------------------------------------------------------- network inventory safety
def test_network_requires_authorisation(ctx):
    r = REGISTRY["NETWORKINTEL"].safe_run("127.0.0.1", ctx.mctx)
    assert not r.ok and "authorisation required" in r.error


def test_network_blocks_public_ranges_by_default(ctx):
    for target in ("8.8.8.8", "1.1.1.0/24", "203.0.113.0/24" if False else "93.184.216.0/24"):
        r = REGISTRY["NETWORKINTEL"].safe_run(target, ctx.mctx, authorized=True)
        assert not r.ok and "not a private range" in r.error


def test_network_target_validation(settings):
    with pytest.raises(AuthorizationError):
        resolve_targets("8.8.8.8", settings)
    with pytest.raises(ValueError):
        resolve_targets("not a target", settings)
    with pytest.raises(ValueError):
        resolve_targets("10.0.0.0/8", settings)  # exceeds max_scan_hosts
    with pytest.raises(ValueError):
        resolve_targets("fe80::/64", settings)
    assert len(resolve_targets("192.168.1.0/30", settings)) == 2
    settings.allow_public_network_targets = True
    assert len(resolve_targets("8.8.8.8", settings)) == 1


def test_network_scan_loopback_finds_open_port(ctx):
    import socket
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    port = srv.getsockname()[1]
    try:
        assert tcp_state("127.0.0.1", port, 0.5) == "open"
        r = REGISTRY["NETWORKINTEL"].safe_run("127.0.0.1", ctx.mctx, authorized=True, ports=[port, 1])
        assert r.ok
        ip = next(e for e in r.entities if e.type == "ip")
        assert port in ip.attributes["open_ports"] and 1 not in ip.attributes["open_ports"]
    finally:
        srv.close()
    assert tcp_state("127.0.0.1", port, 0.3) == "closed"
