# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 28A global Evidence domain contract tests.

Pins the unit matrix E28A-01..61: the stable global ``Evidence``, the
immutable per-Evidence ``EvidenceObservation`` (version >= 1, UTC-aware
timestamps, deep JSON immutability), the explicit material-state comparison,
the create/unchanged/append transition truth table (fail closed on impossible
combinations), the canonical material diff contract, observation-level
Entity association, exact Investigation admission with bounded vocabularies,
and the global ``RelationshipObservation``. No database, network, or
persistence is involved.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceMaterialState,
    EvidenceObservation,
    EvidenceObservationCandidate,
    EvidenceObservationEntity,
    EvidenceTransition,
    EvidenceType,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
    decide_evidence_transition,
    material_state_diff,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)

pytestmark = pytest.mark.unit

_ID = UUID("11111111-2222-3333-4444-555555555555")
_EVIDENCE_ID = UUID("22222222-3333-4444-5555-666666666666")
_OBSERVATION_ID = UUID("33333333-4444-5555-6666-777777777777")
_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def _evidence(**overrides: object) -> Evidence:
    """Build one deterministic global Evidence."""
    values = {
        "id": _EVIDENCE_ID,
        "type": EvidenceType.THREAT_INTELLIGENCE,
        "source": "urn:ati:source:threatfox",
        "source_record_id": "864201",
    }
    values.update(overrides)
    return Evidence.model_validate(values)


def _observation(**overrides: object) -> EvidenceObservation:
    """Build one deterministic persisted observation."""
    values: dict[str, object] = {
        "id": _OBSERVATION_ID,
        "evidence_id": _EVIDENCE_ID,
        "version": 1,
        "source_url": "https://threatfox-api.abuse.ch/api/v1/",
        "retrieved_at": _TS,
        "facts": {"matches": [{"threatfox_id": "864201"}]},
        "raw_payload": None,
        "diff": None,
    }
    values.update(overrides)
    return EvidenceObservation.model_validate(values)


def _candidate(**overrides: object) -> EvidenceObservationCandidate:
    """Build one deterministic observation candidate."""
    values: dict[str, object] = {
        "evidence_id": _EVIDENCE_ID,
        "source_url": "https://threatfox-api.abuse.ch/api/v1/",
        "retrieved_at": _TS + timedelta(minutes=5),
        "facts": {"matches": [{"threatfox_id": "864201"}]},
        "raw_payload": None,
    }
    values.update(overrides)
    return EvidenceObservationCandidate.model_validate(values)


class TestGlobalEvidence:
    """E28A-01..04: stable global Evidence contract."""

    def test_e28a_01_valid_immutable_evidence(self) -> None:
        """E28A-01: a valid global Evidence is accepted and immutable."""
        evidence = _evidence()
        assert evidence.id == _EVIDENCE_ID
        assert evidence.type is EvidenceType.THREAT_INTELLIGENCE
        assert evidence.source == "urn:ati:source:threatfox"
        assert evidence.source_record_id == "864201"
        assert evidence.model_config.get("frozen") is True

    def test_e28a_02_missing_evidence_id_rejected(self) -> None:
        """E28A-02: an Evidence without its required ID is rejected."""
        with pytest.raises(ValidationError):
            Evidence.model_validate(
                {
                    "type": EvidenceType.THREAT_INTELLIGENCE,
                    "source": "urn:ati:source:threatfox",
                    "source_record_id": "864201",
                }
            )

    def test_e28a_03_missing_source_record_identity_rejected(self) -> None:
        """E28A-03: an Evidence without its stable source-record identity fails."""
        with pytest.raises(ValidationError):
            Evidence.model_validate(
                {
                    "id": _EVIDENCE_ID,
                    "type": EvidenceType.THREAT_INTELLIGENCE,
                    "source": "urn:ati:source:threatfox",
                }
            )

    def test_e28a_04_no_investigation_subject_or_state_fields(self) -> None:
        """E28A-04: Investigation/subject/state fields are absent from Evidence."""
        fields = set(_evidence().model_dump())
        assert fields == {"id", "type", "source", "source_record_id"}
        for absent in (
            "investigation_id",
            "subject",
            "observed_at",
            "retrieved_at",
            "facts",
            "raw_payload",
            "source_url",
        ):
            assert absent not in fields


class TestEvidenceObservation:
    """E28A-10..14: immutable per-Evidence observation contract."""

    def test_e28a_10_observation_v1_valid(self) -> None:
        """E28A-10: a version-1 observation is valid."""
        observation = _observation()
        assert observation.version == 1
        assert observation.evidence_id == _EVIDENCE_ID
        assert observation.diff is None

    def test_e28a_11_version_zero_rejected(self) -> None:
        """E28A-11: observation version 0 is rejected."""
        with pytest.raises(ValidationError, match="version"):
            _observation(version=0)

    def test_e28a_12_naive_timestamps_rejected(self) -> None:
        """E28A-12: naive timestamps are rejected on observations."""
        with pytest.raises(ValidationError, match="timezone-aware"):
            _observation(retrieved_at=datetime(2026, 6, 1, 12, 0, 0))
        with pytest.raises(ValidationError, match="timezone-aware"):
            _observation(observed_at=datetime(2026, 5, 1, 12, 0, 0))

    def test_e28a_13_offset_timestamps_normalized_to_utc(self) -> None:
        """E28A-13: aware offset timestamps normalize to UTC."""
        observation = _observation(
            retrieved_at=datetime(
                2026, 6, 1, 14, 0, 0, tzinfo=timezone(timedelta(hours=2))
            ),
            observed_at=datetime(
                2026, 5, 1, 10, 0, 0, tzinfo=timezone(timedelta(hours=-5))
            ),
        )
        assert observation.retrieved_at == _TS
        assert observation.retrieved_at.utcoffset() == timedelta(0)
        assert observation.observed_at == datetime(2026, 5, 1, 15, 0, 0, tzinfo=UTC)

    def test_e28a_14_nested_facts_raw_diff_mutation_rejected(self) -> None:
        """E28A-14: nested facts/raw payload/diff are deeply immutable."""
        observation = _observation(
            facts={"matches": [{"threatfox_id": "864201", "tags": ["a"]}]},
            raw_payload={"nested": {"key": ["x"]}},
            diff={"facts": {"old": None, "new": {"matches": []}}},
        )
        raw_payload = observation.raw_payload
        diff = observation.diff
        assert raw_payload is not None and diff is not None
        mutated: list[Callable[[], object]] = [
            lambda: observation.facts.__setitem__("new", 1),
            lambda: observation.facts["matches"].__setitem__(0, "x"),
            lambda: observation.facts["matches"][0].__setitem__("ioc", "x"),
            lambda: observation.facts["matches"][0]["tags"].__setitem__(0, "y"),
            lambda: raw_payload["nested"]["key"].__setitem__(0, "y"),
            lambda: diff["facts"].__setitem__("x", 1),
        ]
        for attempt in mutated:
            with pytest.raises((TypeError, AttributeError)):
                attempt()


class TestMaterialState:
    """E28A-20..24: explicit material-state comparison and diff."""

    def test_e28a_20_same_material_state_later_retrieved_at_equal(self) -> None:
        """E28A-20: a later retrieval time alone never changes the state."""
        later = _candidate(retrieved_at=_TS + timedelta(hours=6))
        assert EvidenceMaterialState.from_observation(
            _observation()
        ) == EvidenceMaterialState.from_candidate(later)

    def test_e28a_21_facts_change_is_material(self) -> None:
        """E28A-21: a normalized facts change is a material difference."""
        changed = _candidate(facts={"matches": [{"threatfox_id": "864299"}]})
        assert EvidenceMaterialState.from_observation(
            _observation()
        ) != EvidenceMaterialState.from_candidate(changed)

    def test_e28a_22_observed_at_change_is_material(self) -> None:
        """E28A-22: an observed_at change is a material difference."""
        changed = _candidate(observed_at=_TS + timedelta(days=1))
        assert EvidenceMaterialState.from_observation(
            _observation()
        ) != EvidenceMaterialState.from_candidate(changed)

    def test_e28a_23_raw_payload_change_is_material(self) -> None:
        """E28A-23: a raw payload change is a material difference."""
        changed = _candidate(raw_payload={"key": "value"})
        assert EvidenceMaterialState.from_observation(
            _observation()
        ) != EvidenceMaterialState.from_candidate(changed)

    def test_e28a_24_only_id_version_diff_changes_state_equal(self) -> None:
        """E28A-24: ID/version/diff changes never alter the material state."""
        observation = _observation(
            version=3,
            diff={"facts": {"old": None, "new": {}}},
        )
        candidate = _candidate()
        assert EvidenceMaterialState.from_observation(
            observation
        ) == EvidenceMaterialState.from_candidate(candidate)

    def test_diff_knows_changed_keys_with_old_and_new(self) -> None:
        """The canonical diff records {old, new} per changed top-level key."""
        diff = material_state_diff(
            EvidenceMaterialState.from_observation(_observation()),
            EvidenceMaterialState.from_candidate(
                _candidate(facts={"matches": [{"threatfox_id": "864299"}]})
            ),
        )
        assert thaw_json(diff["facts"]["new"]) == {
            "matches": [{"threatfox_id": "864299"}]
        }
        assert thaw_json(diff["facts"]["old"]) == {
            "matches": [{"threatfox_id": "864201"}]
        }

    def test_diff_absent_vs_json_null_distinct(self) -> None:
        """Absent and JSON null remain distinct in the canonical diff."""
        diff = material_state_diff(
            EvidenceMaterialState.from_observation(_observation(raw_payload=None)),
            EvidenceMaterialState.from_candidate(
                _candidate(raw_payload={"url": "https://example.test"})
            ),
        )
        assert "raw_payload" in diff
        assert diff["raw_payload"]["old"] is None
        assert diff["raw_payload"]["new"] == {"url": "https://example.test"}

    def test_diff_equal_states_empty(self) -> None:
        """Equal material states produce an empty diff."""
        diff = material_state_diff(
            EvidenceMaterialState.from_observation(_observation()),
            EvidenceMaterialState.from_candidate(_candidate()),
        )
        assert diff == {}

    def test_first_observation_diff_is_none(self) -> None:
        """The first observation carries no diff (``None``), never ``{}``."""
        observation = _observation()
        assert observation.diff is None

    def test_material_state_excludes_operational_fields(self) -> None:
        """Material state has exactly the four material fields."""
        fields = set(EvidenceMaterialState.from_observation(_observation()).model_dump())
        assert fields == {"observed_at", "source_url", "facts", "raw_payload"}


class TestTransition:
    """E28A-30..34: pure create/unchanged/append decision truth table."""

    def test_e28a_30_absent_evidence_no_latest_create(self) -> None:
        """E28A-30: no Evidence and no observation -> CREATE."""
        assert (
            decide_evidence_transition(
                evidence_exists=False,
                latest_observation=None,
                candidate=_candidate(),
            )
            is EvidenceTransition.CREATE_EVIDENCE_AND_OBSERVATION
        )

    def test_e28a_31_existing_unchanged_no_change(self) -> None:
        """E28A-31: existing Evidence with equal material state -> NO_CHANGE."""
        assert (
            decide_evidence_transition(
                evidence_exists=True,
                latest_observation=_observation(),
                candidate=_candidate(),
            )
            is EvidenceTransition.NO_CHANGE
        )

    def test_e28a_32_existing_changed_append(self) -> None:
        """E28A-32: existing Evidence with changed material state -> APPEND."""
        assert (
            decide_evidence_transition(
                evidence_exists=True,
                latest_observation=_observation(),
                candidate=_candidate(
                    facts={"matches": [{"threatfox_id": "864299"}]}
                ),
            )
            is EvidenceTransition.APPEND_OBSERVATION
        )

    def test_e28a_33_existing_evidence_no_latest_fails_closed(self) -> None:
        """E28A-33: Evidence without any observation fails closed."""
        with pytest.raises(ValueError, match="at least one observation"):
            decide_evidence_transition(
                evidence_exists=True,
                latest_observation=None,
                candidate=_candidate(),
            )

    def test_e28a_34_absent_evidence_with_latest_fails_closed(self) -> None:
        """E28A-34: no Evidence yet a latest observation exists fails closed."""
        with pytest.raises(ValueError):
            decide_evidence_transition(
                evidence_exists=False,
                latest_observation=_observation(),
                candidate=_candidate(),
            )


class TestEvidenceObservationEntity:
    """E28A-50..51: observation-level Entity association."""

    def test_e28a_50_entity_pair_valid_immutable(self) -> None:
        """E28A-50: an observation-Entity pair is valid and immutable."""
        association = EvidenceObservationEntity(
            evidence_observation_id=_OBSERVATION_ID,
            entity_id=UUID("44444444-5555-6666-7777-888888888888"),
        )
        assert association.evidence_observation_id == _OBSERVATION_ID
        assert association.model_dump() == {
            "evidence_observation_id": _OBSERVATION_ID,
            "entity_id": UUID("44444444-5555-6666-7777-888888888888"),
        }

    def test_e28a_51_one_observation_many_entities(self) -> None:
        """E28A-51: one observation may associate many canonical Entities."""
        associations = tuple(
            EvidenceObservationEntity(
                evidence_observation_id=_OBSERVATION_ID, entity_id=uuid4()
            )
            for _ in range(3)
        )
        assert len(associations) == 3
        assert len({item.entity_id for item in associations}) == 3


class TestInvestigationEvidence:
    """E28A-52..54: exact Investigation admission with bounded vocabularies."""

    def test_e28a_52_exact_observation_admission_valid(self) -> None:
        """E28A-52: exact observation admission is valid and immutable."""
        admission = InvestigationEvidence(
            investigation_id=_ID,
            evidence_observation_id=_OBSERVATION_ID,
            inclusion_reason=InvestigationEvidenceReason.PROVIDER_RESULT,
            discovered_from_evidence_observation_id=None,
            added_at=_TS,
            added_by=InvestigationEvidenceActor.SYSTEM,
        )
        assert admission.investigation_id == _ID
        assert admission.evidence_observation_id == _OBSERVATION_ID
        assert admission.added_at == _TS

    def test_e28a_53_same_investigation_admits_multiple_observations(self) -> None:
        """E28A-53: one Investigation may admit several exact observations."""
        admissions = tuple(
            InvestigationEvidence(
                investigation_id=_ID,
                evidence_observation_id=uuid4(),
                inclusion_reason=InvestigationEvidenceReason.CORRELATION,
                added_at=_TS,
                added_by=InvestigationEvidenceActor.AGENT,
            )
            for _ in range(2)
        )
        assert len(admissions) == 2
        assert len({item.evidence_observation_id for item in admissions}) == 2

    def test_e28a_54_free_form_reason_and_actor_rejected(self) -> None:
        """E28A-54: only bounded reason/actor vocabularies are accepted."""
        with pytest.raises((ValidationError, ValueError)):
            InvestigationEvidence(
                investigation_id=_ID,
                evidence_observation_id=_OBSERVATION_ID,
                inclusion_reason="anything",  # type: ignore[arg-type]
                added_at=_TS,
                added_by=InvestigationEvidenceActor.SYSTEM,
            )
        with pytest.raises((ValidationError, ValueError)):
            InvestigationEvidence(
                investigation_id=_ID,
                evidence_observation_id=_OBSERVATION_ID,
                inclusion_reason=InvestigationEvidenceReason.INITIAL,
                added_at=_TS,
                added_by="anyone",  # type: ignore[arg-type]
            )

    def test_naive_admission_timestamp_rejected(self) -> None:
        """Admission timestamps must be timezone-aware and normalize to UTC."""
        with pytest.raises(ValidationError, match="timezone-aware"):
            InvestigationEvidence(
                investigation_id=_ID,
                evidence_observation_id=_OBSERVATION_ID,
                inclusion_reason=InvestigationEvidenceReason.INITIAL,
                added_at=datetime(2026, 6, 1, 12, 0, 0),
                added_by=InvestigationEvidenceActor.SYSTEM,
            )
        offset = InvestigationEvidence(
            investigation_id=_ID,
            evidence_observation_id=_OBSERVATION_ID,
            inclusion_reason=InvestigationEvidenceReason.ANALYST_ADDED,
            added_at=datetime(
                2026, 6, 1, 14, 0, 0, tzinfo=timezone(timedelta(hours=2))
            ),
            added_by=InvestigationEvidenceActor.ANALYST,
        )
        assert offset.added_at == _TS


class TestRelationshipObservationGlobal:
    """E28A-60..61: RelationshipObservation references the exact observation."""

    def test_e28a_60_exact_observation_reference_valid(self) -> None:
        """E28A-60: a RelationshipObservation referencing an exact EO is valid."""
        observation = RelationshipObservation(
            id=uuid4(),
            relationship_id=uuid4(),
            evidence_observation_id=_OBSERVATION_ID,
            retrieved_at=_TS,
            source="urn:ati:source:threatfox",
            confidence=0.8,
        )
        assert observation.evidence_observation_id == _OBSERVATION_ID
        assert observation.confidence == 0.8

    def test_e28a_61_old_evidence_and_investigation_fields_absent(self) -> None:
        """E28A-61: the old evidence_id/investigation_id fields are absent."""
        fields = set(
            RelationshipObservation(
                id=uuid4(),
                relationship_id=uuid4(),
                evidence_observation_id=_OBSERVATION_ID,
                retrieved_at=_TS,
                source="urn:ati:source:threatfox",
            ).model_dump()
        )
        assert fields == {
            "id",
            "relationship_id",
            "evidence_observation_id",
            "observed_at",
            "retrieved_at",
            "source",
            "confidence",
        }


class TestConvertedEvidence:
    """Cohesion of the converter output wrapper (E28A-70 family)."""

    def test_converted_evidence_wraps_global_evidence_and_candidate(self) -> None:
        """One ConvertedEvidence carries evidence plus its candidate."""
        evidence = _evidence()
        candidate = _candidate()
        converted = ConvertedEvidence(evidence=evidence, observation=candidate)
        assert converted.evidence == evidence
        assert converted.observation == candidate
        assert converted.observation.evidence_id == evidence.id

    def test_relationship_identity_unaffected(self) -> None:
        """Relationship identity/types remain unchanged (compatibility regression)."""
        relationship = Relationship(
            id=_ID,
            source_entity_id=uuid4(),
            target_entity_id=uuid4(),
            type=RelationshipType.RESOLVES_TO,
        )
        assert relationship.type is RelationshipType.RESOLVES_TO
