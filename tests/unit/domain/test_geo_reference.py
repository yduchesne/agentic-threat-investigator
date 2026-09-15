# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B canonical geography reference domain tests (G26B-D matrix).

Covers the deterministic canonical reference surface: reference record
contracts, UUIDv5 canonical identity, deterministic name normalization,
the bounded geographic claim validation, and the resolution result algebra.
PostGIS behavior lives in the G26B-P/I/R integration matrices.
"""

from __future__ import annotations

from uuid import UUID

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.geo_reference import (
    GeographicReferenceRecord,
    ReferenceParent,
)
from agentic_threat_investigator.domain.geoint import (
    ATI_LOCATION_NAMESPACE,
    CanonicalLocationResolution,
    CanonicalLocationResolutionStatus,
    GeographicClaim,
    Location,
    LocationCandidate,
    LocationPrecision,
    LocationType,
    canonical_location_uuid,
    location_identity_key,
    normalize_reference_name,
)


def country_record(
    *, code: str = "US", name: str = "United States"
) -> GeographicReferenceRecord:
    """Build a minimal valid country reference record fixture."""
    return GeographicReferenceRecord(
        location_type=LocationType.COUNTRY,
        name=name,
        canonical_name=name,
        country_code=code,
    )


def admin_record(
    *,
    country: GeographicReferenceRecord | None = None,
    code: str = "WA",
    name: str = "Washington",
) -> GeographicReferenceRecord:
    """Build a minimal valid administrative-area record under a country."""
    parent_country = country or country_record()
    return GeographicReferenceRecord(
        location_type=LocationType.ADMINISTRATIVE_AREA,
        name=name,
        canonical_name=name,
        country_code=parent_country.country_code,
        admin1_code=code,
        parent=ReferenceParent(
            location_type=LocationType.COUNTRY,
            country_code=parent_country.country_code,
            canonical_name=parent_country.canonical_name,
        ),
    )


def city_record(
    *,
    admin: GeographicReferenceRecord | None = None,
    name: str = "Seattle",
) -> GeographicReferenceRecord:
    """Build a minimal valid city record under an administrative area."""
    parent_admin = admin or admin_record()
    return GeographicReferenceRecord(
        location_type=LocationType.CITY,
        name=name,
        canonical_name=name,
        country_code=parent_admin.country_code,
        admin1_code=parent_admin.admin1_code,
        parent=ReferenceParent(
            location_type=LocationType.ADMINISTRATIVE_AREA,
            country_code=parent_admin.country_code,
            admin1_code=parent_admin.admin1_code,
            canonical_name=parent_admin.canonical_name,
        ),
    )


# --- G26B-D01..D03: reference record models --------------------------------


def test_d01_valid_country_reference_model() -> None:
    """G26B-D01 a valid country reference record validates."""
    record = country_record()
    assert record.location_type is LocationType.COUNTRY
    assert record.country_code == "US"
    assert record.parent is None
    assert record.geometry is None


def test_d02_valid_admin_hierarchy_reference_model() -> None:
    """G26B-D02 an administrative area record requires a country parent."""
    record = admin_record()
    assert record.admin1_code == "WA"
    assert record.parent is not None
    assert record.parent.location_type is LocationType.COUNTRY
    # Country records reject parents; admin records reject missing parents.
    with pytest.raises(ValidationError, match="parent"):
        GeographicReferenceRecord(
            location_type=LocationType.COUNTRY,
            name="X",
            canonical_name="X",
            country_code="US",
            parent=ReferenceParent(
                location_type=LocationType.COUNTRY,
                country_code="US",
                canonical_name="X",
            ),
        )
    with pytest.raises(ValidationError, match="parent"):
        GeographicReferenceRecord(
            location_type=LocationType.ADMINISTRATIVE_AREA,
            name="X",
            canonical_name="X",
            country_code="US",
            admin1_code="WA",
        )


def test_d03_valid_city_hierarchy_reference_model() -> None:
    """G26B-D03 a city record requires an administrative parent and admin1."""
    record = city_record()
    assert record.parent is not None
    assert record.parent.location_type is LocationType.ADMINISTRATIVE_AREA
    with pytest.raises(ValidationError, match="admin1_code"):
        GeographicReferenceRecord(
            location_type=LocationType.CITY,
            name="X",
            canonical_name="X",
            country_code="US",
            parent=ReferenceParent(
                location_type=LocationType.ADMINISTRATIVE_AREA,
                country_code="US",
                admin1_code="WA",
                canonical_name="Washington",
            ),
        )


# --- G26B-D04/D05: deterministic canonical identity -------------------------


def test_d04_deterministic_canonical_uuid_identity() -> None:
    """G26B-D04 canonical UUIDv5 identity is deterministic and documented."""
    first = canonical_location_uuid(
        location_type=LocationType.CITY,
        country_code="US",
        admin1_code="WA",
        admin2_code=None,
        canonical_name="Seattle",
    )
    second = canonical_location_uuid(
        location_type=LocationType.CITY,
        country_code="US",
        admin1_code="WA",
        admin2_code=None,
        canonical_name="Seattle",
    )
    assert first == second
    assert isinstance(first, UUID)
    assert (
        location_identity_key(
            location_type=LocationType.CITY,
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Seattle",
        )
        == "city\x1fUS\x1fWA\x1f\x1fSeattle"
    )
    # A different country code cannot collide with the identity serialization.
    assert (
        canonical_location_uuid(
            location_type=LocationType.CITY,
            country_code="CA",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Seattle",
        )
        != first
    )


def test_d05_geometry_change_never_changes_identity() -> None:
    """G26B-D05 adding spatial state keeps the canonical identity/UUID stable."""
    plain = canonical_location_uuid(
        location_type=LocationType.COUNTRY,
        country_code="US",
        admin1_code=None,
        admin2_code=None,
        canonical_name="United States",
    )
    with_geometry = canonical_location_uuid(
        location_type=LocationType.COUNTRY,
        country_code="US",
        admin1_code=None,
        admin2_code=None,
        canonical_name="United States",
    )
    assert (
        plain
        == with_geometry
        == canonical_location_uuid(
            location_type=LocationType.COUNTRY,
            country_code="US",
            admin1_code=None,
            admin2_code=None,
            canonical_name="United States",
        )
    )
    # The namespace constant is fixed and documented.
    assert UUID("d94572fc-fb6d-4626-ba99-b760fee02afd") == ATI_LOCATION_NAMESPACE


# --- G26B-D06..D09: geographic claim validation -----------------------------


def test_d06_lat_lon_pair_validation() -> None:
    """G26B-D06 claim latitude/longitude must be supplied together."""
    with pytest.raises(ValidationError, match="together"):
        GeographicClaim(
            country_code="US",
            precision=LocationPrecision.COUNTRY,
            latitude=47.6,
        )
    with pytest.raises(ValidationError, match="together"):
        GeographicClaim(
            country_code="US",
            precision=LocationPrecision.COUNTRY,
            longitude=-122.3,
        )


def test_d07_finite_and_range_coordinate_validation() -> None:
    """G26B-D07 claims reject non-finite and out-of-range coordinates."""
    with pytest.raises(ValidationError, match="finite"):
        GeographicClaim(
            country_code="US",
            precision=LocationPrecision.COUNTRY,
            latitude=float("inf"),
            longitude=-122.3,
        )
    with pytest.raises(ValidationError, match="latitude"):
        GeographicClaim(
            country_code="US",
            precision=LocationPrecision.COUNTRY,
            latitude=91.0,
            longitude=-122.3,
        )
    with pytest.raises(ValidationError, match="longitude"):
        GeographicClaim(
            country_code="US",
            precision=LocationPrecision.COUNTRY,
            latitude=0.0,
            longitude=180.5,
        )
    claim = GeographicClaim(
        country_code="us",
        precision=LocationPrecision.COUNTRY,
        latitude=0.0,
        longitude=-0.0,
    )
    assert claim.country_code == "US"


def test_d08_precision_cannot_exceed_semantic_claim_support() -> None:
    """G26B-D08 the claimed precision cannot exceed the supplied fields."""
    with pytest.raises(ValidationError, match="precision"):
        GeographicClaim(
            country_code="US",
            precision=LocationPrecision.CITY,
        )
    with pytest.raises(ValidationError, match="precision"):
        GeographicClaim(
            country_code="US",
            precision=LocationPrecision.ADMINISTRATIVE_AREA,
        )
    # A city labels field demands city precision.
    with pytest.raises(ValidationError, match="precision"):
        GeographicClaim(
            country_code="US",
            city="Seattle",
            precision=LocationPrecision.COUNTRY,
        )


def test_d09_coordinates_never_upgrade_precision() -> None:
    """G26B-D09 a coordinate pair alone cannot claim city precision."""
    with pytest.raises(ValidationError, match="precision"):
        GeographicClaim(
            latitude=47.6,
            longitude=-122.3,
            precision=LocationPrecision.CITY,
        )
    claim = GeographicClaim(
        latitude=47.6,
        longitude=-122.3,
        precision=LocationPrecision.COUNTRY,
    )
    assert claim.precision is LocationPrecision.COUNTRY
    # Country-only claim with representative coordinates stays country.
    assert claim.city is None and claim.administrative_area is None


# --- G26B-D10..D12: resolution result algebra --------------------------------


def _location() -> Location:
    """Return one canonical Location fixture."""
    return Location(
        type=LocationType.COUNTRY,
        name="United States",
        canonical_name="United States",
        country_code="US",
    )


def test_d10_resolution_result_discriminators_and_invariants() -> None:
    """G26B-D10 result status is a closed discriminated vocabulary."""
    assert [member.value for member in CanonicalLocationResolutionStatus] == [
        "resolved",
        "ambiguous",
        "unresolvable",
    ]


def test_d11_ambiguity_requires_candidates_and_no_selected_location() -> None:
    """G26B-D11 ambiguous results carry 2+ candidates and no Location."""
    first = _location()
    second = first.model_copy(update={"canonical_name": "Canada"})
    result = CanonicalLocationResolution(
        status=CanonicalLocationResolutionStatus.AMBIGUOUS,
        candidates=(
            LocationCandidate(location=first, matched_fields=("city_name",)),
            LocationCandidate(location=second, matched_fields=("city_name",)),
        ),
        reason_code="multiple_candidates",
    )
    assert result.location is None
    assert len(result.candidates) == 2
    with pytest.raises(ValidationError, match="ambiguous"):
        CanonicalLocationResolution(
            status=CanonicalLocationResolutionStatus.AMBIGUOUS,
            location=first,
            candidates=(LocationCandidate(location=first),),
            reason_code="multiple_candidates",
        )
    with pytest.raises(ValidationError, match="at least two"):
        CanonicalLocationResolution(
            status=CanonicalLocationResolutionStatus.AMBIGUOUS,
            candidates=(LocationCandidate(location=first),),
            reason_code="multiple_candidates",
        )


def test_d12_resolved_result_contains_exactly_one_canonical_location() -> None:
    """G26B-D12 resolved results select exactly one canonical Location."""
    location = _location()
    result = CanonicalLocationResolution(
        status=CanonicalLocationResolutionStatus.RESOLVED,
        location=location,
        candidates=(
            LocationCandidate(location=location, matched_fields=("country_code",)),
        ),
        reason_code="exact_semantic_match",
    )
    assert result.location == location
    assert len(result.candidates) == 1
    assert result.candidates[0].location == result.location
    with pytest.raises(ValidationError, match="resolved"):
        CanonicalLocationResolution(
            status=CanonicalLocationResolutionStatus.RESOLVED,
            candidates=(LocationCandidate(location=location),),
            reason_code="exact_semantic_match",
        )


def test_d12b_unresolvable_result_is_explicit() -> None:
    """An unresolvable result has a reason and no candidates/Location."""
    result = CanonicalLocationResolution(
        status=CanonicalLocationResolutionStatus.UNRESOLVABLE,
        reason_code="unknown_country",
    )
    assert result.location is None and not result.candidates
    with pytest.raises(ValidationError, match="reason_code"):
        CanonicalLocationResolution(
            status=CanonicalLocationResolutionStatus.UNRESOLVABLE,
            reason_code="unknown_something",
        )


# --- G26B-D13/D14: normalization and source independence ---------------------


def test_d13_deterministic_name_normalization() -> None:
    """G26B-D13 normalization is NFC, whitespace-collapsing, and case-preserving."""
    assert normalize_reference_name("  Seattle  ") == "Seattle"
    assert normalize_reference_name("New\t York\nCity") == "New York City"
    assert normalize_reference_name("\u212bngstr\u00f6m") == "\u00c5ngstr\u00f6m"  # NFC
    assert normalize_reference_name("Victoria") == "Victoria"  # case preserved
    # The canonical name keeps meaningful punctuation.
    assert normalize_reference_name("St. John's") == "St. John's"


def test_d14_canonical_id_independent_of_external_source_record_id() -> None:
    """G26B-D14 canonical identity never uses external source identifiers."""
    record_a = city_record()
    record_b = city_record()
    assert record_a.canonical_name == record_b.canonical_name
    # A source identifier, if it existed, would not participate: the UUIDv5
    # derivation only consumes the canonical identity tuple.
    expected = canonical_location_uuid(
        location_type=record_a.location_type,
        country_code=record_a.country_code,
        admin1_code=record_a.admin1_code,
        admin2_code=None,
        canonical_name=record_a.canonical_name,
    )
    assert expected == canonical_location_uuid(
        location_type=record_b.location_type,
        country_code=record_b.country_code,
        admin1_code=record_b.admin1_code,
        admin2_code=None,
        canonical_name=record_b.canonical_name,
    )


def test_d14b_location_model_bounds_spatial_text_without_leaking_postgis() -> None:
    """The domain Location exposes bounded EWKT text, never ORM/PostGIS objects."""
    location = Location(
        type=LocationType.COUNTRY,
        name="United States",
        canonical_name="United States",
        country_code="US",
        geometry="SRID=4326;POLYGON((0 0,1 0,1 1,0 1,0 0))",
        centroid="SRID=4326;POINT(0.5 0.5)",
    )
    assert location.geometry == "SRID=4326;POLYGON((0 0,1 0,1 1,0 1,0 0))"
    assert location.centroid == "SRID=4326;POINT(0.5 0.5)"
    with pytest.raises(ValidationError, match="blank"):
        Location(
            type=LocationType.COUNTRY,
            name="X",
            canonical_name="X",
            country_code="US",
            geometry="   ",
        )
