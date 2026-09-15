# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26A GEOINT domain contract tests (G26A-D matrix)."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import (
    EntityLocation,
    EntityLocationObservation,
    GeoResolution,
    GeoResolutionStatus,
    Location,
    LocationPrecision,
    LocationType,
    location_identity_tuple,
)


def _location(**overrides: object) -> Location:
    """Build a minimal valid country Location fixture."""
    values: dict[str, object] = {
        "type": LocationType.COUNTRY,
        "name": "United States",
        "canonical_name": "United States",
        "country_code": "US",
    }
    values.update(overrides)
    return Location.model_validate(values)


def _observation(**overrides: object) -> EntityLocationObservation:
    """Build a minimal valid immutable observation fixture."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    values: dict[str, object] = {
        "id": uuid4(),
        "entity_id": uuid4(),
        "location_id": uuid4(),
        "evidence_id": uuid4(),
        "precision": LocationPrecision.COUNTRY,
        "observed_at": now,
        "retrieved_at": now,
        "resolved_at": now,
        "resolution_method": "test_method",
    }
    values.update(overrides)
    return EntityLocationObservation.model_validate(values)


def _entity_location(**overrides: object) -> EntityLocation:
    """Build a minimal valid current-association fixture."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    values: dict[str, object] = {
        "entity_id": uuid4(),
        "location_id": uuid4(),
        "precision": LocationPrecision.COUNTRY,
        "latest_observation_id": uuid4(),
        "first_observed_at": now,
        "last_observed_at": now,
    }
    values.update(overrides)
    return EntityLocation.model_validate(values)


def _resolution(**overrides: object) -> GeoResolution:
    """Build a minimal valid initial pending GeoResolution fixture."""
    values: dict[str, object] = {
        "id": uuid4(),
        "entity_id": uuid4(),
        "evidence_id": uuid4(),
    }
    values.update(overrides)
    return GeoResolution.model_validate(values)


# --- G26A-D01/D02: enum vocabularies ---------------------------------------


def test_gd01_location_type_exact_vocabulary() -> None:
    """G26A-D01 LocationType is bounded to country/administrative_area/city."""
    assert [member.value for member in LocationType] == [
        "country",
        "administrative_area",
        "city",
    ]


def test_gd02_location_precision_exact_vocabulary() -> None:
    """G26A-D02 LocationPrecision is bounded to country/administrative_area/city."""
    assert [member.value for member in LocationPrecision] == [
        "country",
        "administrative_area",
        "city",
    ]


# --- G26A-D03..D05: type-specific shape ------------------------------------


def test_gd03_country_rejects_parent_and_admin_codes() -> None:
    """G26A-D03 a country Location rejects parent/admin code fields."""
    _location()
    with pytest.raises(ValidationError, match="parent"):
        _location(parent_location_id=uuid4())
    with pytest.raises(ValidationError, match="admin codes"):
        _location(admin1_code="CA")
    with pytest.raises(ValidationError, match="admin codes"):
        _location(admin2_code="001")


def test_gd04_administrative_area_requires_parent_and_admin1() -> None:
    """G26A-D04 an administrative-area Location requires parent + admin1."""
    _location(
        type=LocationType.ADMINISTRATIVE_AREA,
        parent_location_id=uuid4(),
        admin1_code="CA",
    )
    with pytest.raises(ValidationError, match="parent_location_id"):
        _location(type=LocationType.ADMINISTRATIVE_AREA, admin1_code="CA")
    with pytest.raises(ValidationError, match="admin1_code"):
        _location(type=LocationType.ADMINISTRATIVE_AREA, parent_location_id=uuid4())


def test_gd05_city_requires_parent_and_admin1() -> None:
    """G26A-D05 a city Location requires parent + admin1; admin2 stays optional."""
    _location(
        type=LocationType.CITY,
        parent_location_id=uuid4(),
        admin1_code="CA",
        admin2_code="075",
    )
    _location(type=LocationType.CITY, parent_location_id=uuid4(), admin1_code="CA")
    with pytest.raises(ValidationError, match="parent_location_id"):
        _location(type=LocationType.CITY, admin1_code="CA")
    with pytest.raises(ValidationError, match="admin1_code"):
        _location(type=LocationType.CITY, parent_location_id=uuid4())


# --- G26A-D06/D07: deterministic normalization ------------------------------


def test_gd06_country_code_normalization_is_deterministic() -> None:
    """G26A-D06 country codes normalize deterministically without reference data."""
    lower = _location(country_code="us")
    padded = _location(country_code="  us  ")
    assert lower.country_code == "US"
    assert padded.country_code == "US"
    assert lower.canonical_name == "United States"
    with pytest.raises(ValidationError, match="country_code"):
        _location(country_code="USA")
    with pytest.raises(ValidationError, match="country_code"):
        _location(country_code="U1")
    with pytest.raises(ValidationError, match="country_code"):
        _location(country_code="")


def test_gd07_blank_or_oversized_names_and_codes_fail_closed() -> None:
    """G26A-D07 blank/oversized names and admin codes are rejected."""
    with pytest.raises(ValidationError, match="blank"):
        _location(name="   ")
    with pytest.raises(ValidationError, match="maximum length"):
        _location(name="x" * 201)
    with pytest.raises(ValidationError, match="maximum length"):
        _location(canonical_name="x" * 201)
    with pytest.raises(ValidationError, match="blank"):
        _location(
            type=LocationType.CITY,
            parent_location_id=uuid4(),
            admin1_code="   ",
        )
    with pytest.raises(ValidationError, match="maximum length"):
        _location(
            type=LocationType.CITY,
            parent_location_id=uuid4(),
            admin1_code="x" * 65,
        )
    with pytest.raises(ValidationError, match="maximum length"):
        _location(
            type=LocationType.CITY,
            parent_location_id=uuid4(),
            admin1_code="CA",
            admin2_code="x" * 65,
        )


def test_gd07b_location_rejects_self_parent() -> None:
    """A Location whose parent equals its own id fails closed."""
    location_id = uuid4()
    with pytest.raises(ValidationError, match="parent must not equal"):
        _location(
            type=LocationType.CITY,
            id=location_id,
            parent_location_id=location_id,
            admin1_code="CA",
        )


# --- G26A-D08..D10: EntityLocation / observation ----------------------------


def test_gd08_entity_location_rejects_inverted_times() -> None:
    """G26A-D08 EntityLocation rejects an inverted first/last window."""
    later = datetime(2026, 2, 1, tzinfo=UTC)
    earlier = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValidationError, match="first_observed_at"):
        _entity_location(first_observed_at=later, last_observed_at=earlier)


def test_gd09_observation_normalizes_aware_offsets_to_utc() -> None:
    """G26A-D09 observations reject naive timestamps and normalize offsets."""
    naive = datetime(2026, 1, 1)
    with pytest.raises(ValidationError, match="timezone-aware"):
        _observation(observed_at=naive)
    with pytest.raises(ValidationError, match="timezone-aware"):
        _observation(retrieved_at=naive)
    with pytest.raises(ValidationError, match="timezone-aware"):
        _observation(resolved_at=naive)
    offset = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(hours=2)
    observation = _observation(
        retrieved_at=offset,
        resolved_at=offset,
        observed_at=offset,
    )
    assert observation.retrieved_at == datetime(2026, 1, 1, 2, 0, tzinfo=UTC)
    assert observation.retrieved_at.utcoffset() == timedelta(0)
    assert observation.observed_at == datetime(2026, 1, 1, 2, 0, tzinfo=UTC)
    assert observation.resolved_at == datetime(2026, 1, 1, 2, 0, tzinfo=UTC)


def test_gd10_observation_requires_explicit_identity_ids() -> None:
    """G26A-D10 observations require explicit Entity/Location/Evidence IDs."""
    with pytest.raises(ValidationError, match="entity_id"):
        _observation(entity_id=None)
    with pytest.raises(ValidationError, match="location_id"):
        _observation(location_id=None)
    with pytest.raises(ValidationError, match="evidence_id"):
        _observation(evidence_id=None)
    with pytest.raises(ValidationError, match="id"):
        _observation(id=None)


def test_gd10b_observation_rejects_blank_resolution_method() -> None:
    """A blank or oversized resolution method fails closed."""
    with pytest.raises(ValidationError, match="blank"):
        _observation(resolution_method="  ")
    with pytest.raises(ValidationError, match="maximum length"):
        _observation(resolution_method="x" * 201)


# --- G26A-D11/D12: GeoResolution --------------------------------------------


def test_gd11_geo_resolution_initial_pending_shape_is_valid() -> None:
    """G26A-D11 the initial pending GeoResolution shape validates."""
    resolution = _resolution()
    assert resolution.status is GeoResolutionStatus.PENDING
    assert resolution.attempt_count == 0
    assert resolution.claimed_by is None
    assert resolution.lease_expires_at is None
    assert resolution.resolved_location_id is None
    assert resolution.last_error_code is None


def test_gd12_malformed_status_and_metadata_fail_closed() -> None:
    """G26A-D12 malformed status/error/claim metadata fails closed."""
    assert [member.value for member in GeoResolutionStatus] == [
        "pending",
        "processing",
        "resolved",
        "unresolvable",
        "failed",
    ]
    with pytest.raises(ValidationError):
        _resolution(status="scheduled")
    with pytest.raises(ValidationError, match="attempt_count"):
        _resolution(attempt_count=-1)
    with pytest.raises(ValidationError, match="last_error_code"):
        _resolution(last_error_code="Bad Code!")
    with pytest.raises(ValidationError, match="last_error_code"):
        _resolution(last_error_code="x" * 65)
    with pytest.raises(ValidationError, match="blank"):
        _resolution(claimed_by="   ")
    with pytest.raises(ValidationError, match="maximum length"):
        _resolution(claimed_by="x" * 201)
    with pytest.raises(ValidationError, match="timezone-aware"):
        _resolution(next_attempt_at=datetime(2026, 1, 1))
    with pytest.raises(ValidationError, match="timezone-aware"):
        _resolution(lease_expires_at=datetime(2026, 1, 1))


# --- G26A-D13/D14: scope guards ---------------------------------------------


def test_gd13_models_contain_no_geometry_or_postgis_fields() -> None:
    """G26A-D13 GEOINT models carry no geometry/PostGIS fields."""
    assert not hasattr(Location, "geometry")
    assert not hasattr(Location, "centroid")
    assert not hasattr(EntityLocation, "geometry")
    assert not hasattr(EntityLocationObservation, "geometry")
    assert not hasattr(GeoResolution, "geometry")
    for model in (Location, EntityLocation, EntityLocationObservation, GeoResolution):
        fields = set(model.model_fields)
        assert "geometry" not in fields
        assert "centroid" not in fields
        assert "latitude" not in fields
        assert "longitude" not in fields


def test_gd14_no_location_entity_type_added() -> None:
    """G26A-D14 Location is not an Entity; EntityType vocabulary is unchanged."""
    assert not hasattr(EntityType, "LOCATION")
    assert "location" not in {member.value for member in EntityType}
    assert {member.value for member in EntityType} == {
        "domain",
        "ip_address",
        "url",
        "network_prefix",
        "asn",
        "organization",
        "malware",
        "attack_technique",
        "vulnerability",
    }


def test_gd15_canonical_identity_tuple_excludes_parent() -> None:
    """The deterministic identity tuple matches the approved contract."""
    country = _location()
    assert location_identity_tuple(country) == (
        "country",
        "US",
        None,
        None,
        "United States",
    )
    city = _location(
        type=LocationType.CITY,
        parent_location_id=uuid4(),
        admin1_code="CA",
        admin2_code="075",
        name="San Francisco",
        canonical_name="San Francisco",
    )
    assert location_identity_tuple(city) == (
        "city",
        "US",
        "CA",
        "075",
        "San Francisco",
    )
    # Two Locations that differ only in parent share the identity tuple.
    other_parent = city.model_copy(update={"parent_location_id": uuid4()})
    assert location_identity_tuple(city) == location_identity_tuple(other_parent)
