# SPDX-License-Identifier: AGPL-3.0-only
"""G26F-S matrix: model-visible GEOINT contracts (PR 26F).

Proves the frozen ``extra="forbid"`` analyst GEOINT context DTOs and the
bounded structured geographic output contract: extra fields, invalid UUIDs,
unsupported kinds, empty/duplicate support, oversize collections, and
context-shape violations are all rejected deterministically.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.analyst import (
    AnalystEntityGeointContext,
    AnalystGeointContext,
    AnalystGeointLocation,
    AnalystGeointObservation,
    EvidenceAnalystDecision,
    GeographicFinding,
    GeographicFindingKind,
    GeographicTemporalInterpretation,
)
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import (
    LocationType,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from tests.support.geoint_fixtures import analyst_observation, analyst_summary


def observation() -> AnalystGeointObservation:
    """Build one deterministic model-visible observation."""
    return analyst_observation(
        observation_id=uuid4(), entity_id=uuid4(), evidence_id=uuid4()
    )


def entity_context(*, entity_id: UUID | None = None) -> AnalystEntityGeointContext:
    """Build one deterministic model-visible Entity context."""
    entity_id = entity_id or uuid4()
    current = analyst_observation(
        observation_id=uuid4(), entity_id=entity_id, evidence_id=uuid4()
    )
    return AnalystEntityGeointContext(
        entity_id=entity_id,
        entity_type=EntityType.IP_ADDRESS,
        entity_value="203.0.113.10",
        current_observation=current,
        history=(),
    )


def context(
    *, entities: tuple[AnalystEntityGeointContext, ...] = ()
) -> AnalystGeointContext:
    """Build one valid model-visible GEOINT context."""
    return AnalystGeointContext(
        summary=analyst_summary(
            observation_count=1, entity_count_with_location=1, location_count=1
        ),
        entities=entities,
    )


def geographic_finding(
    *,
    kind: GeographicFindingKind = GeographicFindingKind.SHARED_LOCATION,
    observation_ids: tuple[UUID, ...] | None = None,
    evidence_observation_ids: tuple[UUID, ...] | None = None,
    entity_ids: tuple[UUID, ...] | None = None,
    location_ids: tuple[UUID, ...] | None = None,
) -> GeographicFinding:
    """Build a structurally valid geographic finding with distinct IDs."""
    first = uuid4()
    second = uuid4()
    return GeographicFinding(
        kind=kind,
        statement="Both entities were observed in the same city.",
        observation_ids=(first, second) if observation_ids is None else observation_ids,
        evidence_observation_ids=(
            (first, second)
            if evidence_observation_ids is None
            else evidence_observation_ids
        ),
        entity_ids=(first, second) if entity_ids is None else entity_ids,
        location_ids=(first,) if location_ids is None else location_ids,
        temporal_interpretation=(
            GeographicTemporalInterpretation.DIFFERENT_OBSERVATION_TIMES
            if kind is GeographicFindingKind.SHARED_LOCATION
            else (
                GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED
                if kind is GeographicFindingKind.LOCATION_CHANGE_OBSERVED
                else GeographicTemporalInterpretation.DIFFERENT_OBSERVATION_TIMES
            )
        ),
    )


def test_g26f_s01_representative_context_validates() -> None:
    """G26F-S01 a representative context DTO tree validates."""
    entity = entity_context()
    data = context(entities=(entity,))
    assert data.entities[0].entity_id == entity.entity_id
    assert data.summary.observation_count == 1


def test_g26f_s02_extra_field_rejected() -> None:
    """G26F-S02 extra fields are forbidden on every GEOINT contract."""
    with pytest.raises(ValidationError, match="extra"):
        AnalystGeointObservation.model_validate(
            {
                **observation().model_dump(),
                "hotspot_label": "high risk",
            }
        )
    with pytest.raises(ValidationError, match="extra"):
        GeographicFinding.model_validate(
            {
                **geographic_finding().model_dump(),
                "attribution": "suspected APT",
            }
        )


def test_g26f_s03_invalid_uuid_rejected() -> None:
    """G26F-S03 malformed UUID identities are rejected."""
    payload = observation().model_dump()
    payload["observation_id"] = "not-a-uuid"
    with pytest.raises(ValidationError):
        AnalystGeointObservation.model_validate(payload)


def test_g26f_s04_unsupported_kind_rejected() -> None:
    """G26F-S04 inferential finding kinds are structurally impossible."""
    payload = geographic_finding().model_dump()
    for forbidden in (
        "coordinated_activity",
        "common_owner",
        "campaign_match",
        "targeting",
        "attribution",
        "malicious_location",
        "travel",
        "movement_route",
    ):
        payload["kind"] = forbidden
        with pytest.raises(ValidationError):
            GeographicFinding.model_validate(payload)


def test_g26f_s05_empty_support_rejected() -> None:
    """G26F-S05 empty geographic support collections are rejected."""
    with pytest.raises(ValidationError, match="must not be empty"):
        geographic_finding(observation_ids=(), evidence_observation_ids=())


def test_g26f_s06_duplicate_support_rejected() -> None:
    """G26F-S06 duplicate support identities are rejected."""
    shared = uuid4()
    with pytest.raises(ValidationError, match="duplicates"):
        geographic_finding(
            observation_ids=(shared, shared), evidence_observation_ids=(shared, shared)
        )


def test_g26f_s07_serialization_is_stable_json() -> None:
    """G26F-S07 the context serializes to stable JSON-compatible output."""
    data = context(entities=(entity_context(),))
    dumped = data.model_dump_json()
    assert '"observation_id"' in dumped
    assert '"evidence_observation_id"' in dumped
    assert '"precision"' in dumped
    assert '"location"' in dumped
    assert "latitude" not in dumped  # representative coordinates never enter context
    assert "longitude" not in dumped


def test_g26f_s08_collection_bounds_enforced() -> None:
    """G26F-S08 finding support collections are hard-bounded."""
    many = tuple(uuid4() for _ in range(26))
    with pytest.raises(ValidationError, match="exceeds the maximum"):
        geographic_finding(observation_ids=many, evidence_observation_ids=many)


def test_parallel_evidence_lists_must_match_length() -> None:
    """Observation and Evidence lists are parallel with equal length."""
    with pytest.raises(ValidationError, match="parallel"):
        geographic_finding(evidence_observation_ids=(uuid4(),))


def test_context_rejects_repeated_entity_and_foreign_observation() -> None:
    """A context must not repeat Entities nor carry foreign observations."""
    entity_id = uuid4()
    first = entity_context(entity_id=entity_id)
    with pytest.raises(ValidationError, match="must not repeat an entity_id"):
        context(entities=(first, entity_context(entity_id=entity_id)))
    foreign = analyst_observation(
        observation_id=uuid4(), entity_id=uuid4(), evidence_id=uuid4()
    )
    with pytest.raises(ValidationError, match="entity context"):
        AnalystEntityGeointContext(
            entity_id=entity_id,
            entity_type=EntityType.IP_ADDRESS,
            entity_value="203.0.113.10",
            current_observation=foreign,
        )


def test_decision_geographic_findings_default_empty() -> None:
    """The geographic-findings field is an additive, default-empty contract."""
    decision = EvidenceAnalystDecision(
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Analysis summary.",
        disposition=AnalysisDisposition.SUFFICIENT,
    )
    assert decision.geographic_findings == ()


def test_geoint_context_field_default_is_none() -> None:
    """No-GEOINT inputs keep ``geoint_context=None`` (backward compatible)."""
    from agentic_threat_investigator.domain.analyst import EvidenceAnalystInput

    analyst_input = EvidenceAnalystInput(
        investigation_id=uuid4(), objective="Assess the root indicator."
    )
    assert analyst_input.geoint_context is None


def test_allowed_kind_vocabulary_is_descriptive_only() -> None:
    """The kind vocabulary contains exactly the approved descriptive kinds."""
    assert set(GeographicFindingKind) == {
        GeographicFindingKind.SHARED_LOCATION,
        GeographicFindingKind.LOCATION_HISTORY,
        GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
        GeographicFindingKind.GEOGRAPHIC_DISTRIBUTION,
        GeographicFindingKind.CONTAINED_LOCATION_CONTEXT,
    }
    assert set(GeographicTemporalInterpretation) == {
        GeographicTemporalInterpretation.NONE,
        GeographicTemporalInterpretation.SAME_OBSERVATION_WINDOW,
        GeographicTemporalInterpretation.DIFFERENT_OBSERVATION_TIMES,
        GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED,
    }


def test_location_dto_omits_coordinates() -> None:
    """The model-visible Location carries no representative coordinates."""
    location = AnalystGeointLocation.model_validate(
        {
            "location_id": str(uuid4()),
            "location_type": LocationType.CITY.value,
            "canonical_location_name": "Seattle",
            "country_code": "US",
            "admin1_code": "WA",
        }
    )
    assert location.canonical_location_name == "Seattle"
    assert "latitude" not in location.model_dump()
    with pytest.raises(ValidationError):
        AnalystGeointLocation.model_validate(
            {
                "location_id": str(uuid4()),
                "location_type": LocationType.CITY.value,
                "canonical_location_name": "Seattle",
                "country_code": "US",
                "latitude": 47.6,
            }
        )
