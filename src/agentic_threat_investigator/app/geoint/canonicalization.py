# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic canonical-reference normalization (PR 26B).

Turns a source-neutral :class:`GeographicReferenceRecord` into the canonical
serialization consumed by the versioned reference write function: canonical
UUIDv5 identity derived from ATI canonical identity (never from external
source identifiers), bounded EWKT geometry with an explicit ``SRID=4326;``
prefix, and deterministic hierarchy wiring.

Geometry is validated syntactically here (declared SRID, geometry type per
Location type, coordinate list shape, WGS84 numeric bounds, parenthesis
balance); full geometric validity (ring validity, emptiness, type enforcement
under PostGIS) is owned by the versioned SQL write function, which is the
sole mutation path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID

from agentic_threat_investigator.app.persistence.repositories import (
    InvalidReferenceGeometryError,
    InvalidReferenceHierarchyError,
)
from agentic_threat_investigator.domain.geo_reference import (
    GeographicReferenceRecord,
    ReferenceParent,
)
from agentic_threat_investigator.domain.geoint import (
    LocationType,
    canonical_location_uuid,
)

_EWKT_MAX_LENGTH = 1_000_000
_SRID_PREFIX_RE = re.compile(r"^SRID=(\d+);")
_WKT_BODY_RE = re.compile(r"^(POINT|POLYGON|MULTIPOLYGON)\b")
_NUMBER_RE = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")

_TYPE_GEOMETRY_TYPES = {
    LocationType.COUNTRY: ("POLYGON", "MULTIPOLYGON"),
    LocationType.ADMINISTRATIVE_AREA: ("POLYGON", "MULTIPOLYGON"),
    LocationType.CITY: ("POINT",),
}


def _declared_srid(ewkt: str) -> int | None:
    """Return the SRID explicitly declared by an EWKT prefix, if any."""
    match = _SRID_PREFIX_RE.match(ewkt.strip())
    return None if match is None else int(match.group(1))


def canonical_geometry_ewkt(
    geometry: str | None, *, location_type: LocationType
) -> str | None:
    """Canonicalize one reference geometry to the documented EWKT contract.

    The canonical form is ``SRID=4326;<body>`` with the body's geometry type
    matching the Location type (polygonal for country/administrative area,
    Point for city). Non-4326 declared SRIDs, malformed coordinate lists,
    unbalanced parentheses, and out-of-WGS84-bounds coordinates fail closed;
    full geometric validity is left to the versioned write function.
    """
    if geometry is None:
        return None
    stripped = geometry.strip()
    if not stripped:
        raise InvalidReferenceGeometryError("geometry must not be blank")
    if len(stripped) > _EWKT_MAX_LENGTH:
        raise InvalidReferenceGeometryError(
            f"geometry exceeds the maximum length of {_EWKT_MAX_LENGTH}"
        )
    srid = _declared_srid(stripped)
    if srid is not None and srid != 4326:
        raise InvalidReferenceGeometryError(f"geometry SRID must be 4326 (got {srid})")
    body = stripped.split(";", 1)[1] if srid is not None else stripped
    expected = _TYPE_GEOMETRY_TYPES[location_type]
    match = _WKT_BODY_RE.match(body)
    if match is None or match.group(1) not in expected:
        raise InvalidReferenceGeometryError(
            f"geometry type must be one of {', '.join(expected)} for "
            f"{location_type.value}"
        )
    if body.count("(") != body.count(")"):
        raise InvalidReferenceGeometryError("geometry parentheses are unbalanced")
    numbers = [float(number) for number in _NUMBER_RE.findall(body)]
    if not numbers or len(numbers) % 2 != 0:
        raise InvalidReferenceGeometryError("geometry coordinate list is malformed")
    for index in range(0, len(numbers), 2):
        longitude, latitude = numbers[index], numbers[index + 1]
        if not (-180.0 <= longitude <= 180.0 and -90.0 <= latitude <= 90.0):
            raise InvalidReferenceGeometryError(
                "geometry coordinates are outside WGS84 bounds"
            )
    return f"SRID=4326;{body}"


def canonical_centroid_ewkt(centroid: str | None) -> str | None:
    """Canonicalize one optional representative point (Point/4326)."""
    if centroid is None:
        return None
    return canonical_geometry_ewkt(centroid, location_type=LocationType.CITY)


def _polygonal_centroid(geometry: str | None, centroid: str | None) -> str | None:
    """Return the effective representative point EWKT for a polygonal record.

    Cities store their canonical point in both spatial columns; polygonal
    objects derive an on-surface representative point when the reference
    geometry is present and no explicit point is supplied. The derivation is
    owned by the SQL write function (``ST_PointOnSurface``), so this helper
    only decides which *inputs* to carry forward deterministically.
    """
    if centroid is not None or geometry is None:
        return centroid
    return None


IdentityTuple = tuple[str, str, str, str, str]


def reference_identity(record: GeographicReferenceRecord) -> IdentityTuple:
    """Return the normalized canonical identity tuple of one record."""
    return (
        record.location_type.value,
        record.country_code,
        record.admin1_code or "",
        record.admin2_code or "",
        record.canonical_name,
    )


def parent_identity(parent: ReferenceParent) -> IdentityTuple:
    """Return the normalized canonical identity tuple of a parent reference."""
    return (
        parent.location_type.value,
        parent.country_code,
        parent.admin1_code or "",
        parent.admin2_code or "",
        parent.canonical_name,
    )


def location_id_for_identity(identity: IdentityTuple) -> UUID:
    """Derive the deterministic UUIDv5 Location identity for an identity tuple."""
    location_type, country_code, admin1_code, admin2_code, canonical_name = identity
    return canonical_location_uuid(
        location_type=LocationType(location_type),
        country_code=country_code,
        admin1_code=admin1_code or None,
        admin2_code=admin2_code or None,
        canonical_name=canonical_name,
    )


@dataclass(frozen=True)
class CanonicalReferenceLocation:
    """One canonical serialization ready for the reference write function.

    ``location_id`` is the deterministic UUIDv5; ``parent_location_id`` is
    the authoritative parent row identifier resolved by the ingestion
    service (existing row or freshly created parent record); spatial fields
    are canonical EWKT strings or ``None``.
    """

    location_id: UUID
    location_type: LocationType
    name: str
    canonical_name: str
    country_code: str
    admin1_code: str | None
    admin2_code: str | None
    parent_location_id: UUID | None
    geometry: str | None
    centroid: str | None


def serialize_reference_location(
    record: GeographicReferenceRecord, *, parent_location_id: UUID | None
) -> CanonicalReferenceLocation:
    """Serialize one record into canonical persistence inputs.

    Applies the deterministic name normalization already performed by the
    DTO, canonicalizes the spatial EWKT, and derives the canonical UUIDv5
    identity. The parent identifier is supplied by the ingestion service
    because it must resolve to the authoritative parent *row*, which may
    pre-exist the batch.
    """
    if record.location_type is LocationType.COUNTRY:
        if parent_location_id is not None:
            raise InvalidReferenceHierarchyError(
                "country record must not receive a parent"
            )
    elif parent_location_id is None:
        raise InvalidReferenceHierarchyError(
            f"{record.location_type.value} record requires a parent"
        )
    geometry = canonical_geometry_ewkt(
        record.geometry, location_type=record.location_type
    )
    centroid = canonical_centroid_ewkt(record.centroid)
    if record.location_type is LocationType.CITY:
        # A city stores exactly one canonical point: the same value in both
        # spatial columns. The SQL function derives the counterpart; here we
        # carry whichever the source supplied.
        if geometry is not None and centroid is not None:
            if _point_ewkt(geometry) != _point_ewkt(centroid):
                raise InvalidReferenceGeometryError(
                    "city geometry and centroid must be the same canonical point"
                )
            centroid = geometry
        elif geometry is not None:
            centroid = geometry
        elif centroid is not None:
            geometry = centroid
    else:
        effective_centroid = _polygonal_centroid(geometry, centroid)
        if (
            effective_centroid is not None
            and geometry is not None
            and not _point_within_polygon_bounds(effective_centroid, geometry)
        ):
            raise InvalidReferenceGeometryError(
                "centroid coordinates must lie within the supplied polygon bounds"
            )
        centroid = effective_centroid
    return CanonicalReferenceLocation(
        location_id=location_id_for_identity(reference_identity(record)),
        location_type=record.location_type,
        name=record.name,
        canonical_name=record.canonical_name,
        country_code=record.country_code,
        admin1_code=record.admin1_code,
        admin2_code=record.admin2_code,
        parent_location_id=parent_location_id,
        geometry=geometry,
        centroid=centroid,
    )


def _point_ewkt(ewkt: str) -> str:
    """Return the numeric body of a Point EWKT for deterministic comparison."""
    _, _, body = ewkt.partition(";")
    if not body.startswith("POINT"):
        raise InvalidReferenceGeometryError("expected a Point geometry")
    return body


def _point_within_polygon_bounds(centroid: str, geometry: str) -> bool:
    """Return whether the centroid's coordinates fall inside the polygon box.

    This is a cheap deterministic sanity check only; exact on-surface
    semantics are owned by the SQL write function. Out-of-range centroids
    for a supplied polygon fail closed instead of silently persisting a
    representative point that is obviously unrelated to the reference
    geometry.
    """
    point_body = _point_ewkt(centroid)
    numbers = [float(number) for number in _NUMBER_RE.findall(point_body)]
    if len(numbers) != 2:
        raise InvalidReferenceGeometryError("centroid must be a single coordinate pair")
    longitude, latitude = numbers
    geometry_numbers = [float(number) for number in _NUMBER_RE.findall(geometry)]
    if not geometry_numbers:
        return False
    longitudes = geometry_numbers[0::2]
    latitudes = geometry_numbers[1::2]
    return (
        min(longitudes) - 1e-9 <= longitude <= max(longitudes) + 1e-9
        and min(latitudes) - 1e-9 <= latitude <= max(latitudes) + 1e-9
    )


def validate_reference_hierarchy(records: list[GeographicReferenceRecord]) -> None:
    """Reject structurally invalid reference hierarchies fail-closed.

    Deterministic parent rules enforced before any mutation: non-country
    records must reference an available parent; administrative areas must
    reference a country; cities must reference an administrative area; and
    child country/admin codes must agree with the parent reference. The
    service additionally resolves the actual parent row; this helper covers
    the corpus-level structural rules.
    """
    for record in records:
        parent = record.parent
        if record.location_type is LocationType.COUNTRY:
            continue
        assert parent is not None  # guaranteed by the DTO shape validator
        if record.location_type is LocationType.ADMINISTRATIVE_AREA:
            if parent.location_type is not LocationType.COUNTRY:
                raise InvalidReferenceHierarchyError(
                    "administrative area parent must be a country"
                )
        else:
            if parent.location_type is not LocationType.ADMINISTRATIVE_AREA:
                raise InvalidReferenceHierarchyError(
                    "city parent must be an administrative area"
                )
        if record.country_code != parent.country_code:
            raise InvalidReferenceHierarchyError(
                "child country_code must equal the parent country_code"
            )
        if parent.location_type is LocationType.ADMINISTRATIVE_AREA:
            # A city's most specific administrative parent must share its
            # admin codes; an administrative area's parent is a country and
            # has no admin code to compare.
            if record.admin1_code != parent.admin1_code:
                raise InvalidReferenceHierarchyError(
                    "child admin1_code must equal the parent admin1_code"
                )
            if (
                parent.admin2_code is not None
                and record.admin2_code != parent.admin2_code
            ):
                raise InvalidReferenceHierarchyError(
                    "child admin2_code must equal the parent admin2_code"
                )
