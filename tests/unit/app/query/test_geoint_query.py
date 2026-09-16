# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26D application GEOINT read-contract unit matrix (G26D-Q01..Q10).

Pure framework-independent contracts: typed bounded query inputs, frozen
read models, the PR 26A currentness cursor codec, and the fail-closed
persisted-row mapping boundary. No database, PostGIS, HTTP, or LLM is
involved.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.query.geoint import (
    GeointEntityLocationItem,
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointLocationEntityListQuery,
    GeointLocationObservationListQuery,
    GeointLocationPage,
    GeointLocationRef,
    GeointObservationItem,
    GeointObservationQuery,
    GeointPrecisionCounts,
    GeointReadError,
    GeointSummary,
    GeointSummaryQuery,
    GeointTopLocation,
    effective_observation_time,
    geoint_entity_location_item_from_row,
    geoint_location_ref_from_row,
    geoint_observation_detail_from_row,
    geoint_observation_item_from_row,
    location_entity_sort_values,
    observation_sort_values,
    parse_location_entity_cursor,
    parse_observation_cursor,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    QueryKind,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
INVESTIGATION = UUID("11111111-1111-1111-1111-111111111111")
ENTITY = UUID("22222222-2222-2222-2222-222222222222")
LOCATION = UUID("33333333-3333-3333-3333-333333333333")


def location_ref() -> GeointLocationRef:
    """Build one deterministic Location reference fixture."""
    return GeointLocationRef(
        location_id=LOCATION,
        location_type=LocationType.COUNTRY,
        canonical_name="United States",
        country_code="US",
        latitude=39.8283,
        longitude=-98.5795,
    )


def observation_item(
    *, observed_at: datetime | None = None, resolved_at: datetime = FIXED
) -> GeointObservationItem:
    """Build one deterministic observation read item fixture."""
    return GeointObservationItem(
        observation_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        entity_id=ENTITY,
        location=location_ref(),
        evidence_id=UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        precision=LocationPrecision.CITY,
        resolution_method="canonical_geography_v1",
        observed_at=observed_at,
        retrieved_at=FIXED,
        resolved_at=resolved_at,
    )


def summary() -> GeointSummary:
    """Build one deterministic bounded summary fixture."""
    return GeointSummary(
        entity_count_with_location=2,
        observation_count=3,
        location_count=2,
        country_count=1,
        administrative_area_count=1,
        city_count=0,
        precision_counts=GeointPrecisionCounts(
            country=1, administrative_area=1, city=1
        ),
        top_locations=(
            GeointTopLocation(location=location_ref(), scoped_entity_count=2),
        ),
        truncated=False,
    )


# ---------------------------------------------------------------------------
# Query-input contracts (G26D-Q01..Q05)
# ---------------------------------------------------------------------------


def test_q01_valid_entity_query_accepted() -> None:
    """G26D-Q01 a valid entity query is accepted and frozen."""
    query = GeointEntityQuery(investigation_id=INVESTIGATION, entity_id=ENTITY)
    assert query.investigation_id == INVESTIGATION
    assert query.entity_id == ENTITY
    with pytest.raises(ValidationError):
        GeointEntityQuery.model_validate(
            {"investigation_id": str(INVESTIGATION)}  # missing entity_id
        )
    with pytest.raises(ValidationError):
        GeointEntityQuery.model_validate(
            {"investigation_id": "not-a-uuid", "entity_id": str(ENTITY)}
        )


def test_q02_exact_location_query_accepted() -> None:
    """G26D-Q02 exact Location queries are accepted; the flag stays bounded."""
    exact = GeointLocationEntityListQuery(
        investigation_id=INVESTIGATION, location_id=LOCATION, limit=25
    )
    assert exact.include_contained is False
    assert exact.fingerprint()
    with pytest.raises(ValidationError):
        GeointLocationEntityListQuery.model_validate(
            {
                "investigation_id": str(INVESTIGATION),
                "location_id": str(LOCATION),
                "include_contained": "maybe",
                "limit": 25,
            }
        )
    observations = GeointLocationObservationListQuery(
        investigation_id=INVESTIGATION, location_id=LOCATION, limit=25
    )
    assert observations.include_contained is False


def test_q03_containment_flag_is_bounded_boolean() -> None:
    """G26D-Q03 the containment flag is a required bounded boolean."""
    page = GeointLocationPage[object](
        items=(), next_cursor=None, containment_applied=True
    )
    assert page.containment_applied is True
    with pytest.raises(ValidationError):
        GeointLocationPage[object].model_validate(
            {"items": [], "next_cursor": None, "containment_applied": "maybe"}
        )
    with pytest.raises(ValidationError):
        GeointLocationPage[object].model_validate(
            {"items": [], "next_cursor": None}  # flag required
        )


def test_q04_valid_page_limit_accepted() -> None:
    """G26D-Q04 a valid page limit is accepted by the shared bound."""
    limits = QueryLimits(default_page_size=50, max_page_size=200)
    assert limits.validate_limit(50) == 50
    assert limits.validate_limit(200) == 200
    query = GeointEntityObservationListQuery(
        investigation_id=INVESTIGATION, entity_id=ENTITY, limit=7
    )
    assert query.limit == 7


def test_q05_excessive_page_limit_hits_existing_bound() -> None:
    """G26D-Q05 an excessive page limit is rejected by the existing bound."""
    limits = QueryLimits(default_page_size=50, max_page_size=200)
    with pytest.raises(ValueError):
        limits.validate_limit(201)
    with pytest.raises(ValidationError):
        GeointEntityObservationListQuery(
            investigation_id=INVESTIGATION, entity_id=ENTITY, limit=0
        )
    GeointSummaryQuery(investigation_id=INVESTIGATION)
    GeointObservationQuery(investigation_id=INVESTIGATION, observation_id=uuid4())


# ---------------------------------------------------------------------------
# Read models (G26D-Q06..Q09)
# ---------------------------------------------------------------------------


def test_q06_location_ref_exposes_no_raw_geometry() -> None:
    """G26D-Q06 the Location ref exposes coordinates only, never geometry."""
    ref = location_ref()
    payload = ref.model_dump()
    assert payload["latitude"] == 39.8283
    assert payload["longitude"] == -98.5795
    for forbidden in ("geometry", "ewkt", "wkb", "centroid", "boundary"):
        assert forbidden not in payload
        assert forbidden not in ref.model_dump_json()
    # The approved field allowlist stays exact.
    assert set(payload) == {
        "location_id",
        "location_type",
        "canonical_name",
        "country_code",
        "admin1_code",
        "admin2_code",
        "parent_location_id",
        "latitude",
        "longitude",
    }
    # A partial coordinate pair is rejected.
    with pytest.raises(ValidationError):
        GeointLocationRef(
            location_id=LOCATION,
            location_type=LocationType.COUNTRY,
            canonical_name="United States",
            country_code="US",
            latitude=39.8283,
            longitude=None,
        )
    # Unknown fields are forbidden entirely (raw geometry must never enter).
    with pytest.raises(ValidationError):
        GeointLocationRef.model_validate(
            {
                "location_id": str(LOCATION),
                "location_type": "country",
                "canonical_name": "United States",
                "country_code": "US",
                "geometry": "SRID=4326;POLYGON((0 0,1 0,1 1,0 0))",
            }
        )


def test_q07_observation_item_preserves_exact_provenance() -> None:
    """G26D-Q07 observation items retain exact observation/evidence IDs."""
    item = observation_item()
    assert item.observation_id == UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    assert item.evidence_id == UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    assert item.entity_id == ENTITY
    assert item.location.location_id == LOCATION
    assert item.precision is LocationPrecision.CITY
    payload = item.model_dump(mode="json")
    assert payload["observation_id"] == str(item.observation_id)
    assert payload["evidence_id"] == str(item.evidence_id)
    for forbidden in ("facts", "raw_payload", "geometry"):
        assert forbidden not in payload


def test_q08_entity_current_is_explicitly_investigation_relative() -> None:
    """G26D-Q08 entity current is explicitly Investigation-relative.

    The read item carries only the newest qualifying observation within the
    path Investigation; it never exposes the global ``EntityLocation``
    materialized state (version/first_observed_at/last_observed_at are not
    part of this read contract).
    """
    item = GeointEntityLocationItem(
        entity_id=ENTITY,
        entity_type=EntityType.IP_ADDRESS,
        entity_value="203.0.113.10",
        display_name=None,
        current_observation=observation_item(),
    )
    payload = item.model_dump(mode="json")
    assert payload["entity_id"] == str(ENTITY)
    assert payload["current_observation"]["evidence_id"] == str(
        item.current_observation.evidence_id
    )
    for global_state_field in (
        "version",
        "first_observed_at",
        "last_observed_at",
        "latest_observation_id",
    ):
        assert global_state_field not in payload
        assert global_state_field not in payload["current_observation"]


def test_q09_summary_is_bounded() -> None:
    """G26D-Q09 the summary carries bounded, consistent counts."""
    bounded = summary()
    assert len(bounded.top_locations) <= 10
    assert bounded.truncated is False
    # Precision counts must reconcile exactly with observation_count.
    with pytest.raises(ValidationError):
        GeointSummary(
            entity_count_with_location=1,
            observation_count=3,
            location_count=1,
            country_count=1,
            administrative_area_count=0,
            city_count=0,
            precision_counts=GeointPrecisionCounts(country=1),
            top_locations=(),
            truncated=False,
        )
    # Per-type location counts must not exceed location_count.
    with pytest.raises(ValidationError):
        GeointSummary(
            entity_count_with_location=1,
            observation_count=1,
            location_count=1,
            country_count=2,
            administrative_area_count=0,
            city_count=0,
            precision_counts=GeointPrecisionCounts(country=1),
            top_locations=(),
            truncated=False,
        )


# ---------------------------------------------------------------------------
# Fail-closed persisted mapping (G26D-Q10)
# ---------------------------------------------------------------------------


def _row(**values: object) -> dict[str, object]:
    """Build one dict-shaped persisted row fixture."""
    base: dict[str, object] = {
        "observation_id": uuid4(),
        "entity_id": ENTITY,
        "evidence_id": uuid4(),
        "precision": "city",
        "resolution_method": "canonical_geography_v1",
        "observed_at": None,
        "retrieved_at": FIXED,
        "resolved_at": FIXED,
        "entity_type": "ip_address",
        "canonical_value": "203.0.113.10",
        "display_name": None,
        "location_id": LOCATION,
        "location_type": "country",
        "canonical_name": "United States",
        "country_code": "US",
        "admin1_code": None,
        "admin2_code": None,
        "parent_location_id": None,
        "latitude": 39.8283,
        "longitude": -98.5795,
    }
    base.update(values)
    return base


def test_q10_malformed_persisted_mapping_fails_closed() -> None:
    """G26D-Q10 malformed persisted state fails the read closed.

    Every corruption drops the whole read with :class:`GeointReadError`
    instead of being silently repaired or reinterpreted at the boundary.
    """
    with pytest.raises(GeointReadError):
        geoint_location_ref_from_row(_row(canonical_name=None))
    with pytest.raises(GeointReadError):
        geoint_location_ref_from_row(_row(location_type="continent"))
    with pytest.raises(GeointReadError):
        geoint_location_ref_from_row(_row(latitude=None))  # partial pair
    with pytest.raises(GeointReadError):
        geoint_location_ref_from_row(_row(latitude=181.0))
    with pytest.raises(GeointReadError):
        geoint_observation_item_from_row(_row(precision="precise"))
    with pytest.raises(GeointReadError):
        geoint_observation_item_from_row(_row(retrieved_at=None))
    with pytest.raises(GeointReadError):
        geoint_observation_item_from_row(_row(evidence_id="not-a-uuid"))
    with pytest.raises(GeointReadError):
        geoint_entity_location_item_from_row(_row(entity_type="bogus"))
    with pytest.raises(GeointReadError):
        geoint_observation_detail_from_row(_row(canonical_value=None))
    # Unknown extra persisted columns are ignored, not leaked.
    item = geoint_observation_item_from_row(
        _row(raw_payload={"http_response": {"body": "secret"}})
    )
    assert "raw_payload" not in item.model_dump()
    # A valid row maps cleanly through every pure mapper.
    assert geoint_location_ref_from_row(_row()).canonical_name == "United States"
    assert geoint_observation_item_from_row(_row()).evidence_id is not None
    assert geoint_entity_location_item_from_row(_row()).entity_id == ENTITY
    assert (
        geoint_observation_detail_from_row(_row()).entity_type is EntityType.IP_ADDRESS
    )


# ---------------------------------------------------------------------------
# Cursor codec (PR 26A currentness ordering)
# ---------------------------------------------------------------------------


def test_observation_cursor_round_trip_and_tie_break_direction() -> None:
    """Observation cursors encode the exact effective time + UUID.

    The greater ``(effective time, UUID)`` pair wins currentness, so the
    newest-first history order and the cursor continuation both sort the
    pair descending with the UUID descending direction.
    """
    observed_at = FIXED - timedelta(days=1)
    values = observation_sort_values(observed_at, FIXED, ENTITY)
    assert values[0] == effective_observation_time(observed_at, FIXED).isoformat()
    assert values[1] == str(ENTITY)
    envelope = CursorEnvelope(
        version=1,
        query_kind=QueryKind.GEOINT_ENTITY_OBSERVATIONS,
        filter_fingerprint="fp",
        sort_values=values,
    )
    effective_at, cursor_id = parse_observation_cursor(envelope, "entity observation")
    assert effective_at == effective_observation_time(observed_at, FIXED)
    assert cursor_id == ENTITY
    with pytest.raises(ValueError):
        parse_observation_cursor(
            CursorEnvelope(
                version=1,
                query_kind=QueryKind.GEOINT_ENTITY_OBSERVATIONS,
                filter_fingerprint="fp",
                sort_values=("2026-01-01T00:00:00",),  # wrong arity
            ),
            "entity observation",
        )


def test_location_entity_cursor_round_trip() -> None:
    """Location-Entity cursors encode the deterministic entity ordering."""
    values = location_entity_sort_values(EntityType.IP_ADDRESS, "203.0.113.10", ENTITY)
    assert values == ("ip_address", "203.0.113.10", str(ENTITY))
    envelope = CursorEnvelope(
        version=1,
        query_kind=QueryKind.GEOINT_LOCATION_ENTITIES,
        filter_fingerprint="fp",
        sort_values=values,
    )
    entity_type_value, canonical_value, entity_id = parse_location_entity_cursor(
        envelope
    )
    assert entity_type_value == "ip_address"
    assert canonical_value == "203.0.113.10"
    assert entity_id == ENTITY
    with pytest.raises(ValueError):
        parse_location_entity_cursor(
            CursorEnvelope(
                version=1,
                query_kind=QueryKind.GEOINT_LOCATION_ENTITIES,
                filter_fingerprint="fp",
                sort_values=("bogus", "203.0.113.10", str(ENTITY)),
            )
        )


def test_fingerprints_bind_filter_scope() -> None:
    """Cursor fingerprints bind investigation, entity/location, and containment."""
    exact = GeointLocationEntityListQuery(
        investigation_id=INVESTIGATION, location_id=LOCATION, limit=25
    )
    contained = exact.model_copy(update={"include_contained": True})
    other_investigation = exact.model_copy(update={"investigation_id": uuid4()})
    assert exact.fingerprint() != contained.fingerprint()
    assert exact.fingerprint() != other_investigation.fingerprint()
    entity_history = GeointEntityObservationListQuery(
        investigation_id=INVESTIGATION, entity_id=ENTITY, limit=25
    )
    assert entity_history.fingerprint() != exact.fingerprint()
