# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B canonical reference normalization tests.

Covers the deterministic EWKT canonicalization, canonical UUIDv5 identity
serialization, and the fail-closed reference hierarchy structural rules that
run before any database mutation. Full geometry validity remains owned by the
versioned SQL write function and is exercised in the integration matrices.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from agentic_threat_investigator.app.geoint.canonicalization import (
    canonical_centroid_ewkt,
    canonical_geometry_ewkt,
    location_id_for_identity,
    parent_identity,
    reference_identity,
    serialize_reference_location,
    validate_reference_hierarchy,
)
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
    normalize_reference_name,
)

_POLYGON = "SRID=4326;POLYGON((-125 45,-116 45,-116 49.5,-125 49.5,-125 45))"
_POINT = "SRID=4326;POINT(-122.3321 47.6062)"


def _record(**overrides: object) -> GeographicReferenceRecord:
    """Build one valid administrative-area record under a US country."""
    values: dict[str, object] = {
        "location_type": LocationType.ADMINISTRATIVE_AREA,
        "name": "Washington",
        "canonical_name": "Washington",
        "country_code": "US",
        "admin1_code": "WA",
        "parent": ReferenceParent(
            location_type=LocationType.COUNTRY,
            country_code="US",
            canonical_name="United States",
        ),
        "geometry": _POLYGON,
    }
    values.update(overrides)
    return GeographicReferenceRecord.model_validate(values)


def test_canonical_geometry_ewkt_adds_srid_and_normalizes() -> None:
    """EWKT canonicalization adds the explicit 4326 prefix and trims."""
    canonical = canonical_geometry_ewkt(
        "  POLYGON((-125 45,-116 45,-116 49.5,-125 49.5,-125 45))  ",
        location_type=LocationType.ADMINISTRATIVE_AREA,
    )
    assert (
        canonical == "SRID=4326;POLYGON((-125 45,-116 45,-116 49.5,-125 49.5,-125 45))"
    )
    assert canonical_geometry_ewkt(None, location_type=LocationType.COUNTRY) is None


def test_canonical_geometry_rejects_wrong_declared_srid() -> None:
    """A non-4326 declared SRID fails closed instead of silently re-tagging."""
    with pytest.raises(InvalidReferenceGeometryError, match="4326"):
        canonical_geometry_ewkt("SRID=3857;POINT(0 0)", location_type=LocationType.CITY)


def test_canonical_geometry_type_rules() -> None:
    """Geometry type must match the Location type (polygonal vs Point)."""
    with pytest.raises(InvalidReferenceGeometryError, match="one of POLYGON"):
        canonical_geometry_ewkt(
            "SRID=4326;POINT(1 1)", location_type=LocationType.COUNTRY
        )
    with pytest.raises(InvalidReferenceGeometryError, match="one of POINT"):
        canonical_geometry_ewkt(
            "SRID=4326;POLYGON((0 0,1 0,1 1,0 1,0 0))", location_type=LocationType.CITY
        )
    multi = canonical_geometry_ewkt(
        "SRID=4326;MULTIPOLYGON(((0 0,1 0,1 1,0 1,0 0)))",
        location_type=LocationType.ADMINISTRATIVE_AREA,
    )
    assert multi is not None and multi.startswith("SRID=4326;MULTIPOLYGON")


def test_canonical_geometry_rejects_malformed_coordinates() -> None:
    """Malformed coordinate lists and out-of-WGS84 values fail closed."""
    with pytest.raises(InvalidReferenceGeometryError, match="coordinate list"):
        canonical_geometry_ewkt(
            "SRID=4326;POLYGON((0 0,1 0,1))", location_type=LocationType.COUNTRY
        )
    with pytest.raises(InvalidReferenceGeometryError, match="WGS84"):
        canonical_geometry_ewkt(
            "SRID=4326;POINT(181 0)", location_type=LocationType.CITY
        )
    with pytest.raises(InvalidReferenceGeometryError, match="WGS84"):
        canonical_geometry_ewkt(
            "SRID=4326;POINT(1 91)", location_type=LocationType.CITY
        )
    with pytest.raises(InvalidReferenceGeometryError, match="unbalanced"):
        canonical_geometry_ewkt(
            "SRID=4326;POLYGON((0 0,1 0,1 1,0 1)", location_type=LocationType.COUNTRY
        )


def test_canonical_centroid_requires_point() -> None:
    """A representative centroid must be a Point geometry."""
    assert canonical_centroid_ewkt(_POINT) == "SRID=4326;POINT(-122.3321 47.6062)"
    with pytest.raises(InvalidReferenceGeometryError, match="one of POINT"):
        canonical_centroid_ewkt(_POLYGON)


def test_serialize_city_derives_same_canonical_point() -> None:
    """City serialization stores one canonical point in both spatial columns."""
    city = GeographicReferenceRecord(
        location_type=LocationType.CITY,
        name="Seattle",
        canonical_name="Seattle",
        country_code="US",
        admin1_code="WA",
        parent=ReferenceParent(
            location_type=LocationType.ADMINISTRATIVE_AREA,
            country_code="US",
            admin1_code="WA",
            canonical_name="Washington",
        ),
        geometry=_POINT,
    )
    serialized = serialize_reference_location(city, parent_location_id=uuid4())
    assert (
        serialized.geometry
        == serialized.centroid
        == "SRID=4326;POINT(-122.3321 47.6062)"
    )
    # Conflicting city points fail closed.
    conflicting = city.model_copy(update={"centroid": "SRID=4326;POINT(0 0)"})
    with pytest.raises(InvalidReferenceGeometryError, match="canonical point"):
        serialize_reference_location(conflicting, parent_location_id=uuid4())


def test_serialize_reference_location_derives_deterministic_id() -> None:
    """Serialization derives the UUIDv5 from the canonical identity tuple."""
    serialized = serialize_reference_location(_record(), parent_location_id=uuid4())
    assert serialized.location_id == canonical_location_uuid(
        location_type=LocationType.ADMINISTRATIVE_AREA,
        country_code="US",
        admin1_code="WA",
        admin2_code=None,
        canonical_name="Washington",
    )
    assert (
        location_id_for_identity(reference_identity(_record()))
        == serialized.location_id
    )


def test_validate_reference_hierarchy_rules() -> None:
    """Structural hierarchy rules fail closed before any mutation."""
    country = GeographicReferenceRecord(
        location_type=LocationType.COUNTRY,
        name="United States",
        canonical_name="United States",
        country_code="US",
    )
    admin = _record()
    city = GeographicReferenceRecord(
        location_type=LocationType.CITY,
        name="Seattle",
        canonical_name="Seattle",
        country_code="US",
        admin1_code="WA",
        parent=ReferenceParent(
            location_type=LocationType.ADMINISTRATIVE_AREA,
            country_code="US",
            admin1_code="WA",
            canonical_name="Washington",
        ),
        geometry=_POINT,
    )
    validate_reference_hierarchy([country, admin, city])
    # An administrative area under another administrative area is invalid.
    with pytest.raises(InvalidReferenceHierarchyError, match="country"):
        validate_reference_hierarchy(
            [
                country,
                _record(
                    parent=ReferenceParent(
                        location_type=LocationType.ADMINISTRATIVE_AREA,
                        country_code="US",
                        admin1_code="WA",
                        canonical_name="Washington",
                    )
                ),
            ]
        )
    # A city whose admin1 disagrees with its parent fails closed.
    with pytest.raises(InvalidReferenceHierarchyError, match="admin1"):
        validate_reference_hierarchy(
            [country, admin, city.model_copy(update={"admin1_code": "OR"})]
        )
    # A child country code that disagrees with the parent fails closed.
    with pytest.raises(InvalidReferenceHierarchyError, match="country_code"):
        validate_reference_hierarchy([country, _record(country_code="CA")])


def test_reference_identity_strings_normalize_nulls() -> None:
    """Identity tuples normalize null admin codes to the empty string."""
    country_record = GeographicReferenceRecord(
        location_type=LocationType.COUNTRY,
        name="United States",
        canonical_name="United States",
        country_code="us",
    )
    assert reference_identity(country_record) == (
        "country",
        "US",
        "",
        "",
        "United States",
    )
    parent = ReferenceParent(
        location_type=LocationType.COUNTRY,
        country_code="US",
        canonical_name="United States",
    )
    assert parent_identity(parent) == ("country", "US", "", "", "United States")
    assert normalize_reference_name("  A\u00a0B  ") == "A B"
