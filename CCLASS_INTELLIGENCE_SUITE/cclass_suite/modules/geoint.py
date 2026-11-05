"""GEOINT - geographic intelligence from public datasets.

Offline: a bundled gazetteer of major world cities (lookup, nearest-place,
distance and bearing, bounding box).  Online (optional): OpenStreetMap
Nominatim geocoding for names the gazetteer does not know.
"""

from __future__ import annotations

import csv
import math
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import ModuleResult
from ..utils import clean_text, parse_coordinates
from .base import Module, ModuleContext

EARTH_RADIUS_KM = 6371.0088


def _fold(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)).strip().lower()


@lru_cache(maxsize=4)
def load_places(path: str) -> Tuple[Dict[str, Any], ...]:
    places: List[Dict[str, Any]] = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                try:
                    places.append({"name": row["name"], "country": row["country"], "iso2": row["iso2"],
                                   "lat": float(row["lat"]), "lon": float(row["lon"])})
                except (KeyError, ValueError):
                    continue
    except OSError:
        pass
    return tuple(places)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi, dlmb = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


def bearing_deg(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360) % 360


def compass(deg: float) -> str:
    return ["N", "NE", "E", "SE", "S", "SW", "W", "NW"][int((deg + 22.5) // 45) % 8]


def nearest_places(places: Tuple[Dict[str, Any], ...], lat: float, lon: float, k: int = 5) -> List[Dict[str, Any]]:
    ranked = sorted(({**p, "distance_km": haversine_km(lat, lon, p["lat"], p["lon"])} for p in places),
                    key=lambda p: p["distance_km"])
    return ranked[:k]


def find_place(places: Tuple[Dict[str, Any], ...], name: str) -> Optional[Dict[str, Any]]:
    key = _fold(name)
    for p in places:
        if _fold(p["name"]) == key:
            return p
    for p in places:  # "Lagos, Nigeria" style
        if key in (_fold(f"{p['name']}, {p['country']}"), _fold(f"{p['name']} {p['iso2']}")):
            return p
    return None


def bounding_box(lat: float, lon: float, radius_km: float) -> Dict[str, float]:
    dlat = math.degrees(radius_km / EARTH_RADIUS_KM)
    dlon = math.degrees(radius_km / (EARTH_RADIUS_KM * max(0.01, math.cos(math.radians(lat)))))
    return {"min_lat": max(-90.0, lat - dlat), "max_lat": min(90.0, lat + dlat),
            "min_lon": max(-180.0, lon - dlon), "max_lon": min(180.0, lon + dlon)}


class GeoInt(Module):
    name = "GEOINT"
    description = ("Place and coordinate intelligence: gazetteer lookup, nearest places, distance/bearing "
                   "('Lagos | London') and optional OpenStreetMap geocoding.")
    accepts = ("place", "coordinates", "text")

    def run(self, query: str, ctx: ModuleContext, **options: Any) -> ModuleResult:
        q = clean_text(query, 200).strip()
        res = ModuleResult(self.name, q, offline=ctx.settings.offline_mode)
        if not q:
            return res.fail("empty query")
        places = load_places(str(ctx.settings.sample_dir / "world_places.csv"))
        if not places:
            res.warnings.append("bundled gazetteer is missing")
        src = "Bundled gazetteer"

        if "|" in q:                         # distance between two places or coordinates
            return self._distance(q, places, ctx, res)

        coords = parse_coordinates(q)
        if coords:
            lat, lon = coords
            near = nearest_places(places, lat, lon, 5)
            ref = ("place", f"{lat:.4f},{lon:.4f}")
            res.add_entity("place", ref[1], label=f"Point {lat:.4f}, {lon:.4f}", lat=lat, lon=lon, confidence=0.9)
            if near:
                n0 = near[0]
                res.add_finding(f"Nearest known city: {n0['name']}, {n0['country']} ({n0['distance_km']:.0f} km)",
                                "Nearest in gazetteer: " + "; ".join(f"{p['name']} {p['distance_km']:.0f} km" for p in near),
                                source=src, entity=ref, lat=lat, lon=lon, quality=0.8)
                res.add_entity("place", f"{n0['name']}, {n0['country']}", lat=n0["lat"], lon=n0["lon"],
                               attributes={"iso2": n0["iso2"]})
                res.relate(ref, ("place", f"{n0['name']}, {n0['country']}"), "co_located", src, 0.6)
            box = bounding_box(lat, lon, 25)
            res.add_finding("25 km search box", ", ".join(f"{k}={v:.4f}" for k, v in box.items()), source=src,
                            entity=ref, lat=lat, lon=lon, data=box, quality=0.99)
            return res

        hit = find_place(places, q)
        if hit:
            label = f"{hit['name']}, {hit['country']}"
            ref = ("place", label)
            res.add_entity("place", label, lat=hit["lat"], lon=hit["lon"], attributes={"iso2": hit["iso2"]}, confidence=0.9)
            res.add_entity("country", hit["country"], attributes={"iso2": hit["iso2"]})
            res.relate(ref, ("country", hit["country"]), "located_in", src, 0.99)
            res.add_finding(f"Resolved place: {label}", f"Coordinates {hit['lat']:.4f}, {hit['lon']:.4f}.",
                            source=src, entity=ref, lat=hit["lat"], lon=hit["lon"], quality=0.95)
            near = [p for p in nearest_places(places, hit["lat"], hit["lon"], 4) if p["name"] != hit["name"]][:3]
            if near:
                res.add_finding("Nearby gazetteer cities", "; ".join(f"{p['name']} ({p['distance_km']:.0f} km)" for p in near),
                                source=src, entity=ref, lat=hit["lat"], lon=hit["lon"], quality=0.9)
            return res

        # not in the gazetteer -> optional online geocoder
        geo = self._nominatim(q, ctx)
        if geo:
            label = clean_text(geo["display_name"], 160)
            ref = ("place", label)
            res.add_entity("place", label, lat=geo["lat"], lon=geo["lon"], confidence=0.6)
            res.add_finding(f"Geocoded: {label}", f"Coordinates {geo['lat']:.5f}, {geo['lon']:.5f} (OpenStreetMap).",
                            source="OpenStreetMap Nominatim", entity=ref, lat=geo["lat"], lon=geo["lon"], quality=0.7)
            return res
        msg = "no match in the bundled gazetteer" + ("" if ctx.settings.offline_mode else " or online geocoder")
        res.add_finding("Place not found", f"'{q}': {msg}.", source=src, quality=0.3)
        return res

    # ------------------------------------------------------------------
    def _resolve(self, text: str, places: Tuple[Dict[str, Any], ...], ctx: ModuleContext
                 ) -> Optional[Tuple[str, float, float]]:
        text = text.strip()
        c = parse_coordinates(text)
        if c:
            return f"{c[0]:.4f},{c[1]:.4f}", c[0], c[1]
        p = find_place(places, text)
        if p:
            return f"{p['name']}, {p['country']}", p["lat"], p["lon"]
        g = self._nominatim(text, ctx)
        return (clean_text(g["display_name"], 120), g["lat"], g["lon"]) if g else None

    def _distance(self, q: str, places: Tuple[Dict[str, Any], ...], ctx: ModuleContext, res: ModuleResult) -> ModuleResult:
        parts = [p for p in q.split("|") if p.strip()]
        if len(parts) != 2:
            return res.fail("distance queries need exactly two locations: 'A | B'")
        a, b = self._resolve(parts[0], places, ctx), self._resolve(parts[1], places, ctx)
        if not a or not b:
            return res.fail("could not resolve both locations")
        d = haversine_km(a[1], a[2], b[1], b[2])
        brg = bearing_deg(a[1], a[2], b[1], b[2])
        for label, lat, lon in (a, b):
            res.add_entity("place", label, lat=lat, lon=lon, confidence=0.85)
        res.relate(("place", a[0]), ("place", b[0]), "co_located" if d < 1 else "related_to", "Bundled gazetteer", 0.5)
        res.add_finding(f"Distance {a[0]} -> {b[0]}: {d:,.0f} km",
                        f"Great-circle distance {d:,.1f} km; initial bearing {brg:.0f} deg ({compass(brg)}).",
                        source="Bundled gazetteer", entity=("place", a[0]), lat=a[1], lon=a[2],
                        data={"km": round(d, 2), "bearing": round(brg, 1)}, quality=0.9)
        return res

    def _nominatim(self, text: str, ctx: ModuleContext) -> Optional[Dict[str, Any]]:
        if ctx.settings.offline_mode:
            return None
        r = ctx.http.get("https://nominatim.openstreetmap.org/search",
                         params={"q": text, "format": "jsonv2", "limit": 1})
        if r.ok and isinstance(r.data, list) and r.data:
            try:
                item = r.data[0]
                lat, lon = float(item["lat"]), float(item["lon"])
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    return {"display_name": item.get("display_name", text), "lat": lat, "lon": lon}
            except (KeyError, ValueError, TypeError):
                return None
        return None
