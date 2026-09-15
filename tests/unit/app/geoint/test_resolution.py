# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B canonical geography resolution contract tests.

Covers the pure resolution result builders, claim validations, deterministic
candidate ordering, and matched-field derivation. The PostgreSQL/PostGIS
narrowing behavior lives in the G26B-R integration matrix.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from agentic_threat_investigator.app.geoint.resolution import (
    ambiguous_result,
    candidate_sort_key,
    ensure_valid_claim,
    matched_fields_for_claim,
    resolved_result,
    unresolvable_result,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvalidGeographicClaimError,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolutionStatus,
    GeographicClaim,
    Location,
    LocationPrecision,
    LocationType,
)


def _location(
    *, canonical_name: str = "United States", country: str = "US"
) -> Location:
    """Return one canonical Location fixture."""
    return Location(
        type=LocationType.COUNTRY,
        name=canonical_name,
        canonical_name=canonical_name,
        country_code=country,
    )


def test_claim_country_code_normalization() -> None:
    """Claim country codes normalize deterministically without reference data."""
    claim = GeographicClaim(country_code="us", precision=LocationPrecision.COUNTRY)
    assert claim.country_code == "US"
    with pytest.raises(ValueError, match="country_code"):
        GeographicClaim(country_code="USA", precision=LocationPrecision.COUNTRY)
    with pytest.raises(ValueError, match="country_code"):
        GeographicClaim(country_code="U1", precision=LocationPrecision.COUNTRY)


def test_claim_names_apply_deterministic_normalization() -> None:
    """Claim geographic names normalize NFC/whitespace without fuzzy matching."""
    claim = GeographicClaim(
        country_code="US",
        administrative_area="  Washington \t",
        precision=LocationPrecision.ADMINISTRATIVE_AREA,
    )
    assert claim.administrative_area == "Washington"
    with pytest.raises(ValueError, match="blank"):
        GeographicClaim(
            country_code="US",
            administrative_area="   ",
            precision=LocationPrecision.ADMINISTRATIVE_AREA,
        )


def test_ensure_valid_claim_rejects_malformed_constructed_input() -> None:
    """A manually-constructed malformed claim fails closed as an error."""
    claim = GeographicClaim.model_construct(  # bypasses construction validation
        country_code="US",
        latitude=1.0,
        precision=LocationPrecision.COUNTRY,
    )
    with pytest.raises(InvalidGeographicClaimError):
        ensure_valid_claim(claim)


def test_claim_precision_must_match_most_specific_field() -> None:
    """The claimed precision is exactly the precision of the fields supplied."""
    with pytest.raises(ValueError, match="precision"):
        GeographicClaim(
            country_code="US",
            administrative_area="Washington",
            city="Seattle",
            precision=LocationPrecision.ADMINISTRATIVE_AREA,
        )
    city_claim = GeographicClaim(
        country_code="US",
        administrative_area="Washington",
        city="Seattle",
        precision=LocationPrecision.CITY,
    )
    assert city_claim.precision is LocationPrecision.CITY


def test_result_builders_validate_invariants() -> None:
    """Result builders produce only the documented invariants."""
    location = _location()
    resolved = resolved_result(
        location, reason_code="exact_semantic_match", matched_fields=("country_code",)
    )
    assert resolved.status is CanonicalLocationResolutionStatus.RESOLVED
    assert resolved.location == location

    ambiguous = ambiguous_result(
        [
            resolved.candidates[0],
            resolved.candidates[0],
        ],
        reason_code="multiple_candidates",
    )
    assert ambiguous.status is CanonicalLocationResolutionStatus.AMBIGUOUS
    assert ambiguous.location is None

    unresolvable = unresolvable_result("unknown_country")
    assert unresolvable.status is CanonicalLocationResolutionStatus.UNRESOLVABLE
    assert unresolvable.reason_code == "unknown_country"

    with pytest.raises(ValueError, match="reason code"):
        resolved_result(location, reason_code="guessed", matched_fields=())
    with pytest.raises(ValueError, match="reason code"):
        unresolvable_result("too_many_results")


def test_matched_fields_reflect_claim_surface() -> None:
    """Matched fields enumerate the semantic fields that narrowed the claim."""
    assert matched_fields_for_claim(
        GeographicClaim(country_code="US", precision=LocationPrecision.COUNTRY)
    ) == ("country_code",)
    assert matched_fields_for_claim(
        GeographicClaim(
            country_code="US",
            administrative_area="Washington",
            precision=LocationPrecision.ADMINISTRATIVE_AREA,
        )
    ) == ("country_code", "administrative_area_name")
    assert matched_fields_for_claim(
        GeographicClaim(
            country_code="US",
            administrative_area_code="WA",
            city="Seattle",
            precision=LocationPrecision.CITY,
        )
    ) == ("country_code", "administrative_area_code", "city_name")


def test_candidate_ordering_is_deterministic() -> None:
    """Candidate ordering is total and independent of insertion order."""
    parent_a = uuid4()
    parent_b = uuid4()
    cities = [
        Location(
            type=LocationType.CITY,
            name="Springfield",
            canonical_name="Springfield",
            country_code="ZZ",
            admin1_code="BETA",
            parent_location_id=parent_b,
        ),
        Location(
            type=LocationType.CITY,
            name="Springfield",
            canonical_name="Springfield",
            country_code="ZZ",
            admin1_code="ALPHA",
            parent_location_id=parent_a,
        ),
    ]
    ordered_forward = sorted(cities, key=candidate_sort_key)
    order_swapped = sorted([cities[1], cities[0]], key=candidate_sort_key)
    assert [candidate_sort_key(city)[1] for city in ordered_forward] == [
        "ALPHA",
        "BETA",
    ]
    assert ordered_forward == order_swapped
