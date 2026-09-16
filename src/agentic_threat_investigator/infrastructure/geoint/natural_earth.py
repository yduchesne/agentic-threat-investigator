# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Natural Earth reference-source adapter (PR 26B-2).

Parses the documented supported Natural Earth GeoJSON feature collections
into normalized source records (identifying attributes + Polygon/
MultiPolygon geometry) consumed by :class:`GeographyCorpusBuilder`:

- ``ne_10m_admin_0_countries``-style collection (explicitly versioned
  country boundaries): per-feature ``iso_a2`` (with deterministic
  ``iso_a2_eh``/``iso_a2_wb`` fallbacks when the primary is unusable) and
  ``name``;
- ``ne_10m_admin_1_states_provinces``-style collection (explicitly
  versioned first-order boundaries): per-feature ``iso_a2``,
  ``iso_3166_2`` subdivision code, ``name``, and raw ``adm1_code`` (kept
  only as a diagnostic identifier).

Geometry is converted from GeoJSON to canonical ``SRID=4326;...`` EWKT with
deterministic 10-decimal coordinate formatting. Non-polygonal, empty, or
unclosed geometry fails closed. The adapter never writes PostgreSQL and
never downloads anything.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

COUNTRY_ISO_FIELDS = ("iso_a2", "iso_a2_eh", "iso_a2_wb")
ADMIN1_SUBDIVISION_FIELD = "iso_3166_2"
ADMIN1_IDENTIFIER_FIELDS = ("adm1_code", "postal")
_COORDINATE_DECIMALS = 10


class NaturalEarthSourceError(ValueError):
    """Raised when a Natural Earth file violates the documented format.

    The message identifies the feature; it never embeds full geometry
    payloads.
    """


def format_coordinate(value: float) -> str:
    """Format one coordinate deterministically without exponent notation.

    Values are rounded to :data:`_COORDINATE_DECIMALS` decimal places
    (~1 cm at equator) and rendered with trailing zeros stripped, so
    identical inputs always produce identical EWKT text. Shared by the
    Natural Earth geometry conversion and the GeoNames city-point builder.
    """
    formatted = format(round(value, _COORDINATE_DECIMALS), f".{_COORDINATE_DECIMALS}f")
    return formatted.rstrip("0").rstrip(".")


def _position_to_wkt(position: list[float], *, path: str) -> str:
    """Render one GeoJSON position as an EWKT coordinate pair, fail-closed."""
    if not isinstance(position, list) or len(position) != 2:
        raise NaturalEarthSourceError(f"{path}: position must have two values")
    try:
        longitude = float(position[0])
        latitude = float(position[1])
    except (TypeError, ValueError) as error:
        raise NaturalEarthSourceError(f"{path}: position must be numeric") from error
    if not (math.isfinite(longitude) and math.isfinite(latitude)):
        raise NaturalEarthSourceError(f"{path}: position must be finite")
    return f"{format_coordinate(longitude)} {format_coordinate(latitude)}"


def _ring_to_wkt(ring: list[Any], *, path: str) -> str:
    """Render one GeoJSON linear ring as WKT, enforcing closure fail-closed."""
    if not isinstance(ring, list) or len(ring) < 4:
        raise NaturalEarthSourceError(f"{path}: ring must have at least 4 positions")
    try:
        first = [float(coordinate) for coordinate in ring[0]]
        last = [float(coordinate) for coordinate in ring[-1]]
    except (TypeError, ValueError) as error:
        raise NaturalEarthSourceError(
            f"{path}: ring position must be numeric"
        ) from error
    if len(first) != 2 or first != last:
        raise NaturalEarthSourceError(f"{path}: ring must be closed")
    coordinates = [_position_to_wkt(position, path=path) for position in ring]
    return "(" + ", ".join(coordinates) + ")"


def _polygon_wkt(polygon: list[Any], *, path: str) -> str:
    """Render one GeoJSON polygon (outer ring + optional holes) as WKT."""
    if not polygon:
        raise NaturalEarthSourceError(f"{path}: polygon must not be empty")
    rings = "".join(f", {_ring_to_wkt(ring, path=path)}" for ring in polygon[1:])
    return f"({_ring_to_wkt(polygon[0], path=path)}{rings})"


def geometry_to_ewkt(geometry: dict[str, Any] | None, *, path: str) -> str | None:
    """Convert one GeoJSON geometry object to canonical EWKT text.

    Only Polygon and MultiPolygon geometries are supported; every other
    shape fails closed. ``None`` geometry (an upstream feature without
    boundary data) is returned as ``None`` and reported by the builder.
    """
    if geometry is None:
        return None
    geometry_type = geometry.get("type")
    coordinates = geometry.get("coordinates")
    if not isinstance(coordinates, list):
        raise NaturalEarthSourceError(f"{path}: geometry coordinates must be a list")
    if geometry_type == "Polygon":
        body = _polygon_wkt(coordinates, path=path)
    elif geometry_type == "MultiPolygon":
        polygons = [_polygon_wkt(polygon, path=path) for polygon in coordinates]
        body = "(" + ", ".join(polygons) + ")"
    else:
        raise NaturalEarthSourceError(
            f"{path}: unsupported geometry type {geometry_type!r}; expected "
            "Polygon or MultiPolygon"
        )
    return f"SRID=4326;{geometry_type.upper()}{body}"


def _feature_collection(
    path: Path, content: str
) -> list[tuple[str, dict[str, Any], dict[str, Any] | None]]:
    """Return (identifier, properties, geometry) tuples for every feature."""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as error:
        raise NaturalEarthSourceError(
            f"{path}: invalid GeoJSON ({error.msg})"
        ) from error
    if not isinstance(payload, dict) or payload.get("type") != "FeatureCollection":
        raise NaturalEarthSourceError(f"{path}: expected a GeoJSON FeatureCollection")
    features = payload.get("features")
    if not isinstance(features, list):
        raise NaturalEarthSourceError(f"{path}: FeatureCollection has no features")
    result: list[tuple[str, dict[str, Any], dict[str, Any] | None]] = []
    for index, feature in enumerate(features):
        identifier = f"{path}:feature[{index}]"
        if not isinstance(feature, dict) or feature.get("type") != "Feature":
            raise NaturalEarthSourceError(f"{identifier}: expected a GeoJSON Feature")
        properties = feature.get("properties")
        if not isinstance(properties, dict):
            properties = {}
        geometry = feature.get("geometry")
        if geometry is not None and not isinstance(geometry, dict):
            raise NaturalEarthSourceError(f"{identifier}: geometry must be an object")
        result.append((identifier, properties, geometry))
    return result


def _iso_code(properties: dict[str, Any]) -> str | None:
    """Resolve the deterministic ISO country code of one feature.

    The primary ``iso_a2`` value is used when it matches the two-letter
    shape; otherwise the Eurostat-harmonized (``iso_a2_eh``) and World
    Bank (``iso_a2_wb``) fallbacks are tried in order. Features without any
    usable code keep ``None`` and are reported by the builder.
    """
    for field in COUNTRY_ISO_FIELDS:
        value = properties.get(field)
        if isinstance(value, str):
            normalized = value.strip().upper()
            if len(normalized) == 2 and normalized.isalpha():
                return normalized
    return None


def _string(
    properties: dict[str, Any], key: str, *, path: str, label: str
) -> str | None:
    """Return one optional textual property element deterministically."""
    value = properties.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise NaturalEarthSourceError(f"{path}: {label} must be a string")
    stripped = value.strip()
    return stripped or None


def _read(path: Path) -> str:
    """Read one local artifact file, translating I/O errors fail-closed."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise NaturalEarthSourceError(
            f"cannot read Natural Earth artifact {path}: {error}"
        ) from error


@dataclass(frozen=True)
class NaturalEarthCountryRecord:
    """One normalized Natural Earth country feature.

    ``iso_code`` is the deterministic resolved ISO code (or ``None`` when
    the feature carries no usable code); ``geometry`` is canonical EWKT or
    ``None`` when the feature has no boundary data.
    """

    iso_code: str | None
    name: str | None
    geometry: str | None
    source_id: str


@dataclass(frozen=True)
class NaturalEarthAdmin1Record:
    """One normalized Natural Earth first-order administrative feature.

    ``subdivision_code`` is the ``iso_3166_2`` subdivision part when
    present; ``adm1_code`` and ``postal`` are retained only as diagnostic
    identifiers and never participate in joins.
    """

    country_code: str | None
    subdivision_code: str | None
    name: str | None
    geometry: str | None
    source_id: str
    adm1_code: str | None
    postal: str | None


class NaturalEarthReferenceSource:
    """Parse the documented supported Natural Earth GeoJSON collections.

    The adapter produces normalized source records only; deterministic
    joining against GeoNames records, geometry attachment, and corpus
    emission belong to :class:`GeographyCorpusBuilder`.
    """

    def parse_countries(self, path: Path) -> list[NaturalEarthCountryRecord]:
        """Parse a country-boundary GeoJSON collection into records."""
        content = _read(path)
        records: list[NaturalEarthCountryRecord] = []
        for identifier, properties, geometry in _feature_collection(path, content):
            iso_code = _iso_code(properties)
            name = _string(properties, "name", path=identifier, label="name")
            ewkt = geometry_to_ewkt(geometry, path=identifier)
            records.append(
                NaturalEarthCountryRecord(
                    iso_code=iso_code,
                    name=name,
                    geometry=ewkt,
                    source_id=identifier,
                )
            )
        return records

    def parse_admin1(self, path: Path) -> list[NaturalEarthAdmin1Record]:
        """Parse a first-order administrative GeoJSON collection."""
        content = _read(path)
        records: list[NaturalEarthAdmin1Record] = []
        for identifier, properties, geometry in _feature_collection(path, content):
            country_code = _iso_code(properties)
            subdivision = _string(
                properties,
                ADMIN1_SUBDIVISION_FIELD,
                path=identifier,
                label="iso_3166_2",
            )
            subdivision_code: str | None = None
            if subdivision is not None and "-" in subdivision:
                _, _, tail = subdivision.partition("-")
                if tail:
                    subdivision_code = tail
            elif subdivision is not None:
                subdivision_code = subdivision
            if subdivision_code is not None:
                subdivision_code = subdivision_code.upper()
            name = _string(properties, "name", path=identifier, label="name")
            adm1_code = _string(
                properties, "adm1_code", path=identifier, label="adm1_code"
            )
            postal = _string(properties, "postal", path=identifier, label="postal")
            records.append(
                NaturalEarthAdmin1Record(
                    country_code=country_code,
                    subdivision_code=subdivision_code,
                    name=name,
                    geometry=geometry_to_ewkt(geometry, path=identifier),
                    source_id=identifier,
                    adm1_code=adm1_code,
                    postal=postal,
                )
            )
        return records
