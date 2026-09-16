# SPDX-License-Identifier: AGPL-3.0-only
"""G26C-D matrix: exact GEOLOCATION Evidence -> geographic claim extraction.

Proves the pure conversion boundary of PR 26C: an immutable GEOLOCATION
Evidence observation maps to the bounded GeographicClaim with exact fact
mapping and preserved source precision, and malformed/unsupported payloads
fail closed with typed errors. No database, resolver, or I/O is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.geoint.claims import (
    geographic_claim_from_evidence,
)
from agentic_threat_investigator.app.persistence.repositories import (
    GeoEvidenceTypeError,
    InvalidGeographicClaimError,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.geoint import LocationPrecision

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def evidence_factory(
    *,
    type_: EvidenceType = EvidenceType.GEOLOCATION,
    facts: dict[str, object] | None = None,
) -> Evidence:
    """Build a deterministic immutable Evidence observation fixture."""
    return Evidence(
        id=uuid4(),
        investigation_id=uuid4(),
        type=type_,
        subject=EntityRef(id=uuid4(), type=EntityType.IP_ADDRESS, value="203.0.113.7"),
        source="urn:ati:source:test",
        retrieved_at=_RETRIEVED_AT,
        facts=facts if facts is not None else {"country_code": "US"},
    )


def test_g26c_d01_valid_geolocation_evidence_yields_exact_claim() -> None:
    """G26C-D01 a valid GEOLOCATION Evidence maps to the exact claim facts."""
    claim = geographic_claim_from_evidence(
        evidence_factory(
            facts={
                "country_code": "US",
                "region": "California",
                "city": "San Francisco",
                "latitude": 37.7749,
                "longitude": -122.4194,
                "precision": "city",
            }
        )
    )
    assert claim.country_code == "US"
    assert claim.administrative_area == "California"
    assert claim.city == "San Francisco"
    assert claim.latitude == 37.7749
    assert claim.longitude == -122.4194
    assert claim.precision is LocationPrecision.CITY


def test_g26c_d02_coordinates_do_not_upgrade_semantic_precision() -> None:
    """G26C-D02 coordinates without semantic detail never upgrade precision."""
    claim = geographic_claim_from_evidence(
        evidence_factory(
            facts={
                "country_code": "FR",
                "latitude": 48.8566,
                "longitude": 2.3522,
            }
        )
    )
    assert claim.latitude == 48.8566
    assert claim.longitude == 2.3522
    # No city/admin field: precision stays country even though coordinates
    # are present at a higher nominal resolution.
    assert claim.precision is LocationPrecision.COUNTRY


def test_g26c_d03_non_geolocation_evidence_is_a_typed_error() -> None:
    """G26C-D03 non-GEOLOCATION Evidence fails closed with the typed error."""
    with pytest.raises(GeoEvidenceTypeError):
        geographic_claim_from_evidence(evidence_factory(type_=EvidenceType.DNS))


def test_g26c_d04_malformed_geo_payload_is_a_typed_error() -> None:
    """G26C-D04 malformed geo payloads fail closed with a typed error."""
    # No geographic facts at all.
    with pytest.raises(InvalidGeographicClaimError):
        geographic_claim_from_evidence(evidence_factory(facts={"provider": "x"}))
    # A declared region precision without a region field.
    with pytest.raises(InvalidGeographicClaimError):
        geographic_claim_from_evidence(
            evidence_factory(facts={"country_code": "US", "precision": "region"})
        )
    # A partial coordinate pair.
    with pytest.raises(InvalidGeographicClaimError):
        geographic_claim_from_evidence(
            evidence_factory(facts={"country_code": "US", "latitude": 1.0})
        )


def test_g26c_d04b_region_fact_maps_to_administrative_area_and_derived_precision() -> (
    None
):
    """A region fact without explicit precision derives administrative_area."""
    claim = geographic_claim_from_evidence(
        evidence_factory(facts={"country_code": "GB", "region": "England"})
    )
    assert claim.administrative_area == "England"
    assert claim.precision is LocationPrecision.ADMINISTRATIVE_AREA


def test_g26c_d04c_unknown_precision_vocabulary_fails_closed() -> None:
    """An unsupported declared precision vocabulary is a typed error."""
    with pytest.raises(InvalidGeographicClaimError):
        geographic_claim_from_evidence(
            evidence_factory(
                facts={
                    "country_code": "US",
                    "city": "Springfield",
                    "precision": "continent",
                }
            )
        )
