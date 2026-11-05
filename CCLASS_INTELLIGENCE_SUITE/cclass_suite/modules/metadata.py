"""METADATA - PDF, DOCX/XLSX/PPTX and image metadata analysis for user-provided evidence files.

Files are only *read*: nothing is executed, macros are never run and no
external resource referenced by a document is ever fetched.
"""

from __future__ import annotations

import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import ModuleResult
from ..utils import clean_text, hash_file, safe_xml_fromstring
from .base import Module, ModuleContext

HASH_SRC = "Local file hashing"
META_SRC = "Local file metadata"
MAX_XML_BYTES = 1_000_000
MAX_ZIP_ENTRIES = 20000
MAX_ZIP_UNCOMPRESSED = 2 * 1024**3


def detect_kind(path: Path) -> str:
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return "unreadable"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head[:2] == b"\xff\xd8" or head.startswith((b"\x89PNG", b"GIF8", b"II*\x00", b"MM\x00*")) \
            or (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "image"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    return "other"


def pdf_date(value: Any) -> Optional[str]:
    m = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?", str(value or ""))
    if not m:
        return None
    y, mo, d, h, mi, s = (int(x) if x else dflt for x, dflt in zip(m.groups(), (0, 1, 1, 0, 0, 0)))
    try:
        return datetime(y, mo or 1, d or 1, h, mi, s, tzinfo=timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _dms_to_deg(values: Any, ref: Any) -> Optional[float]:
    try:
        d, m, s = (float(v) for v in values)
        deg = d + m / 60 + s / 3600
        if str(ref).upper() in ("S", "W"):
            deg = -deg
        return deg
    except (TypeError, ValueError, ZeroDivisionError):
        return None


class MetadataAnalyzer(Module):
    name = "METADATA"
    description = "PDF, DOCX, XLSX, PPTX and image metadata (authors, software, dates, GPS, macros, hashes)."
    accepts = ("file",)
    cli_only = True

    def run(self, query: str, ctx: ModuleContext, **options: Any) -> ModuleResult:
        path = Path(query).expanduser()
        res = ModuleResult(self.name, str(path.name), offline=False)
        if not path.is_file():
            return res.fail("file not found")
        max_bytes = ctx.settings.max_upload_mb * 1024 * 1024
        size = path.stat().st_size
        if size > max_bytes:
            return res.fail(f"file exceeds the {ctx.settings.max_upload_mb} MB analysis limit")

        hashes = hash_file(path)
        kind = detect_kind(path)
        fref = ("file", hashes["sha256"])
        res.add_entity("file", hashes["sha256"], label=path.name,
                       attributes={"size_bytes": size, "md5": hashes["md5"], "sha1": hashes["sha1"],
                                   "detected_kind": kind, "extension": path.suffix.lower()}, confidence=0.99)
        res.add_finding("File hashes", f"SHA-256 {hashes['sha256']}; SHA-1 {hashes['sha1']}; MD5 {hashes['md5']}; "
                        f"{size:,} bytes.", source=HASH_SRC, entity=fref, quality=0.99, data=hashes)

        try:
            if kind == "pdf":
                self._pdf(path, res, fref)
            elif kind == "image":
                self._image(path, res, fref)
            elif kind == "zip":
                self._ooxml(path, res, fref)
            else:
                res.add_finding("No document metadata extractor for this file type",
                                f"Detected content: {kind}. Only hashes were recorded.", source=META_SRC,
                                entity=fref, quality=0.5)
        except Exception as exc:  # noqa: BLE001 - corrupt or hostile files must not crash the platform
            res.warnings.append(f"metadata extraction failed: {exc.__class__.__name__}")
        return res

    # ------------------------------------------------------------------ helpers
    def _people(self, res: ModuleResult, fref: Tuple[str, str], names: List[Tuple[str, str]]) -> None:
        for role, name in names:
            name = clean_text(name, 120).strip()
            if not name:
                continue
            res.add_entity("person", name, attributes={"role_in_file": role})
            res.relate(fref, ("person", name), "authored_by" if role != "last_modified_by" else "modified_by",
                       META_SRC, 0.6)
        found = [f"{r}: {clean_text(n, 80)}" for r, n in names if n]
        if found:
            res.add_finding("Author information embedded in file", "; ".join(found), "low", source=META_SRC,
                            entity=fref, quality=0.7)

    def _software(self, res: ModuleResult, fref: Tuple[str, str], name: Optional[str]) -> None:
        name = clean_text(name, 120).strip() if name else ""
        if name:
            res.add_entity("software", name)
            res.relate(fref, ("software", name), "created_with", META_SRC, 0.6)

    # ------------------------------------------------------------------ PDF
    def _pdf(self, path: Path, res: ModuleResult, fref: Tuple[str, str]) -> None:
        try:
            from pypdf import PdfReader
        except ImportError:
            res.warnings.append("pypdf is not installed; PDF metadata skipped")
            return
        reader = PdfReader(str(path))
        encrypted = bool(reader.is_encrypted)
        if encrypted:
            try:
                reader.decrypt("")
            except Exception:  # noqa: BLE001
                res.add_finding("PDF is encrypted", "Metadata is not readable without the password.", "info",
                                source=META_SRC, entity=fref)
                return
        md = reader.metadata or {}
        get = lambda k: clean_text(md.get(k), 300) if md and md.get(k) else None  # noqa: E731
        created, modified = pdf_date(md.get("/CreationDate") if md else None), pdf_date(md.get("/ModDate") if md else None)
        pages = len(reader.pages)
        fields = {"title": get("/Title"), "subject": get("/Subject"), "author": get("/Author"),
                  "creator": get("/Creator"), "producer": get("/Producer"), "created": created,
                  "modified": modified, "pages": pages, "encrypted": encrypted}
        res.entities[0].attributes.update({k: v for k, v in fields.items() if v})
        res.add_finding("PDF document properties",
                        "; ".join(f"{k}={v}" for k, v in fields.items() if v not in (None, False)),
                        source=META_SRC, entity=fref, observed_at=modified or created, data=fields)
        self._people(res, fref, [("author", get("/Author") or "")])
        self._software(res, fref, get("/Producer") or get("/Creator"))
        if created and modified and modified > created:
            res.add_finding("File modified after creation", f"Created {created}, last modified {modified}.", "info",
                            source=META_SRC, entity=fref, observed_at=modified, quality=0.6)
        raw = path.read_bytes()[:20 * 1024 * 1024]
        active = [tok.decode() for tok in (b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/EmbeddedFile")
                  if tok in raw]
        if active:
            res.add_finding("PDF contains active or embedded content markers", ", ".join(active) +
                            ". Markers are informational; the file was not executed.", "medium", source=META_SRC,
                            entity=fref, quality=0.7)
        if not any(fields[k] for k in ("author", "creator", "producer", "title")):
            res.add_finding("PDF metadata is empty or stripped", "", "info", source=META_SRC, entity=fref, quality=0.6)

    # ------------------------------------------------------------------ OOXML
    def _ooxml(self, path: Path, res: ModuleResult, fref: Tuple[str, str]) -> None:
        try:
            zf = zipfile.ZipFile(path)
        except zipfile.BadZipFile:
            res.warnings.append("file is not a valid ZIP container")
            return
        with zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_ZIP_UNCOMPRESSED:
                res.add_finding("Archive looks like a decompression bomb", "Too many entries or too large when "
                                "uncompressed; contents were not read.", "high", source=META_SRC, entity=fref)
                return
            names = [i.filename for i in infos]
            kind = ("docx" if any(n.startswith("word/") for n in names) else
                    "xlsx" if any(n.startswith("xl/") for n in names) else
                    "pptx" if any(n.startswith("ppt/") for n in names) else "zip")
            res.entities[0].attributes["document_type"] = kind

            def read(name: str) -> Optional[bytes]:
                try:
                    info = zf.getinfo(name)
                except KeyError:
                    return None
                return zf.read(name) if info.file_size <= MAX_XML_BYTES else None

            core: Dict[str, str] = {}
            raw = read("docProps/core.xml")
            root = safe_xml_fromstring(raw) if raw else None
            if root is not None:
                for child in root:
                    if child.text and child.text.strip():
                        core[_local(child.tag)] = clean_text(child.text, 300)
            app: Dict[str, str] = {}
            raw = read("docProps/app.xml")
            root = safe_xml_fromstring(raw) if raw else None
            if root is not None:
                for child in root:
                    if child.text and child.text.strip():
                        app[_local(child.tag)] = clean_text(child.text, 300)

            if kind == "zip" and not core and not app:
                res.add_finding("ZIP archive without Office metadata", f"{len(names)} entries.", source=META_SRC,
                                entity=fref, quality=0.6)
                return
            props = {"type": kind, "title": core.get("title"), "subject": core.get("subject"),
                     "creator": core.get("creator"), "last_modified_by": core.get("lastModifiedBy"),
                     "created": core.get("created"), "modified": core.get("modified"),
                     "revision": core.get("revision"), "keywords": core.get("keywords"),
                     "application": app.get("Application"), "app_version": app.get("AppVersion"),
                     "company": app.get("Company"), "total_edit_minutes": app.get("TotalTime")}
            res.entities[0].attributes.update({k: v for k, v in props.items() if v})
            res.add_finding(f"{kind.upper()} document properties",
                            "; ".join(f"{k}={v}" for k, v in props.items() if v), source=META_SRC, entity=fref,
                            observed_at=props["modified"] or props["created"], data=props)
            self._people(res, fref, [("author", props["creator"] or ""), ("last_modified_by", props["last_modified_by"] or "")])
            self._software(res, fref, props["application"])
            if props["company"]:
                res.add_entity("organization", props["company"])
                res.relate(fref, ("organization", props["company"]), "associated_with", META_SRC, 0.5)
                res.add_finding("Organisation name embedded in file", props["company"], "low", source=META_SRC,
                                entity=fref, quality=0.7)
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                res.add_finding("VBA macro project present", "The file contains macros. They were not executed.",
                                "medium", source=META_SRC, entity=fref, quality=0.95)
            externals: List[str] = []
            for n in [x for x in names if x.endswith(".rels")][:60]:
                data = read(n)
                if not data:
                    continue
                root = safe_xml_fromstring(data)
                if root is None:
                    continue
                for rel in root:
                    if rel.attrib.get("TargetMode") == "External":
                        externals.append(clean_text(rel.attrib.get("Target"), 200))
            if externals:
                res.add_finding(f"{len(externals)} external reference(s) in document relationships",
                                "; ".join(externals[:6]) + ". Remote templates or linked content can leak or fetch data "
                                "when opened; the targets were not contacted.", "low", source=META_SRC, entity=fref,
                                quality=0.8, data={"targets": externals[:50]})
            embeds = [n for n in names if "/embeddings/" in n]
            if embeds:
                res.add_finding(f"{len(embeds)} embedded object(s)", ", ".join(embeds[:6]), "low", source=META_SRC,
                                entity=fref, quality=0.9)

    # ------------------------------------------------------------------ images
    def _image(self, path: Path, res: ModuleResult, fref: Tuple[str, str]) -> None:
        try:
            from PIL import ExifTags, Image
        except ImportError:
            res.warnings.append("Pillow is not installed; image metadata skipped")
            return
        with Image.open(path) as img:
            info = {"format": img.format, "width": img.width, "height": img.height, "mode": img.mode}
            exif = img.getexif()
            tags: Dict[str, str] = {}
            for tag_id, value in exif.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if isinstance(value, (bytes, bytearray)) or name in ("MakerNote", "UserComment"):
                    continue
                tags[name] = clean_text(value, 200)
            try:
                for tag_id, value in exif.get_ifd(0x8769).items():
                    name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if not isinstance(value, (bytes, bytearray)) and name not in ("MakerNote", "UserComment"):
                        tags[name] = clean_text(value, 200)
            except (KeyError, ValueError, AttributeError):
                pass
            gps: Dict[int, Any] = {}
            try:
                gps = dict(exif.get_ifd(0x8825))
            except (KeyError, ValueError, AttributeError):
                pass
        res.entities[0].attributes.update(info)
        res.add_finding("Image properties", f"{info['format']} {info['width']}x{info['height']} ({info['mode']}).",
                        source=META_SRC, entity=fref, data=info, quality=0.95)
        if tags:
            interesting = {k: tags[k] for k in ("Make", "Model", "Software", "DateTime", "DateTimeOriginal",
                                                "LensModel", "Artist", "Copyright", "HostComputer") if k in tags}
            res.entities[0].attributes["exif"] = interesting
            when = tags.get("DateTimeOriginal") or tags.get("DateTime")
            observed = None
            if when:
                try:
                    observed = datetime.strptime(when, "%Y:%m:%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
                except ValueError:
                    observed = None
            res.add_finding("EXIF metadata present", "; ".join(f"{k}={v}" for k, v in interesting.items()) or
                            f"{len(tags)} EXIF tags.", source=META_SRC, entity=fref, observed_at=observed,
                            data=interesting, quality=0.7)
            device = " ".join(x for x in (tags.get("Make"), tags.get("Model")) if x)
            if device:
                res.add_entity("device", device)
                res.relate(fref, ("device", device), "captured_with", META_SRC, 0.6)
            self._software(res, fref, tags.get("Software"))
            self._people(res, fref, [("artist", tags.get("Artist", ""))])
        else:
            res.add_finding("No EXIF metadata", "Metadata may have been stripped.", source=META_SRC, entity=fref,
                            quality=0.5)
        lat = _dms_to_deg(gps.get(2), gps.get(1)) if gps.get(2) and gps.get(1) else None
        lon = _dms_to_deg(gps.get(4), gps.get(3)) if gps.get(4) and gps.get(3) else None
        if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180:
            label = f"{lat:.5f},{lon:.5f}"
            res.add_entity("place", label, label=f"Photo location {label}", lat=lat, lon=lon,
                           attributes={"source": "image EXIF GPS"}, confidence=0.75)
            res.relate(fref, ("place", label), "located_at", META_SRC, 0.75)
            res.add_finding("Embedded GPS coordinates", f"The image records where it was taken: {label}. Handle as "
                            "personal data.", "medium", source=META_SRC, entity=fref, lat=lat, lon=lon, quality=0.8)
