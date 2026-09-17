# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 28A semantic vertical slices D28A-V01..V04.

Runs the production conversion architecture — real ThreatFox semantic
record validation, the real ``ToEvidenceConverterRegistry``, and the real
``ThreatFoxToEvidenceConverter`` — through the pure PR 28A observation
transition contracts. Only external/nondeterministic boundaries are faked:
a synthetic validated ``ThreatFoxRecord`` (the same deterministic corpus the
parser-converter suites use). No database and no persistence are involved.

- D28A-V01: first ThreatFox record with Evidence absent -> CREATE with the
  deterministic pinned identity and a normalized candidate.
- D28A-V02: unchanged re-retrieval (same record, later ``retrieved_at``)
  -> NO_CHANGE against a synthetic latest observation.
- D28A-V03: material update (same record identity, changed fact)
  -> APPEND with the canonical material diff.
- D28A-V04: conversion with no Investigation/Entity subject context is
  globally successful.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    EvidenceConversionContext,
    convert_semantic_source_objects,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.evidence import (
    EvidenceMaterialState,
    EvidenceObservation,
    EvidenceTransition,
    decide_evidence_transition,
    evidence_id_for_source_record,
    material_state_diff,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    build_threatfox_conversion_registry,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
)
from tests.support.threatfox_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    asyncrat_domain_record,
)

pytestmark = pytest.mark.unit

_TS = datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)
_OBSERVATION_ID = UUID("33333333-4444-5555-6666-777777777777")
_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)


def _record(*, record_id: str = "864201", **overrides: object) -> ThreatFoxRecord:
    """Build one validated ThreatFox record from the corpus fixture."""
    return ThreatFoxRecord.model_validate(
        asyncrat_domain_record(id=record_id, **overrides)
    )


def _context(retrieved_at: datetime = _TS) -> EvidenceConversionContext:
    """Build the global conversion context over the real semantics path."""
    semantic = SemanticSourceContext.from_definition(
        _DEFINITION,
        retrieved_at=retrieved_at,
        source_reference="https://threatfox-api.abuse.ch/api/v1/",
    )
    return EvidenceConversionContext(semantic_source=semantic)


def _synthetic_latest(
    candidate_material: dict[str, object],
    *,
    version: int = 1,
    retrieved_at: datetime = _TS,
) -> EvidenceObservation:
    """Build a synthetic persisted latest observation for transition decisions."""
    return EvidenceObservation.model_validate(
        {
            "id": _OBSERVATION_ID,
            "evidence_id": evidence_id_for_source_record(
                SemanticFormatId.THREATFOX, SourceId.THREATFOX, "864201"
            ),
            "version": version,
            "source_url": "https://threatfox-api.abuse.ch/api/v1/",
            "observed_at": candidate_material.get("observed_at"),
            "retrieved_at": retrieved_at,
            "facts": candidate_material.get("facts", {}),
            "raw_payload": candidate_material.get("raw_payload"),
            "diff": None if version == 1 else {"facts": {"old": {}, "new": {}}},
        }
    )


class TestFirstThreatFoxRecord:
    """D28A-V01: first record -> CREATE with pinned identity and candidate."""

    def test_v01_first_record_create_transition(self) -> None:
        """One record converts; Evidence absent -> CREATE with exact provenance."""
        registry = build_threatfox_conversion_registry()
        record = _record()
        converted = convert_semantic_source_objects((record,), _context(), registry)
        assert len(converted) == 1
        item = converted[0]

        # Deterministic pinned identity and exact source record identity.
        expected_id = evidence_id_for_source_record(
            SemanticFormatId.THREATFOX, SourceId.THREATFOX, "864201"
        )
        assert item.evidence.id == expected_id
        assert item.evidence.source_record_id == "864201"
        assert item.evidence.source == SourceId.THREATFOX.value

        # Normalized candidate: last_seen observed_at, UTC-normalized facts.
        assert item.observation.evidence_id == expected_id
        assert item.observation.observed_at == datetime(
            2026, 8, 21, 12, 0, 0, tzinfo=UTC
        )
        match = thaw_json(item.observation.facts)["matches"][0]
        assert match["threatfox_id"] == "864201"
        assert match["ioc"] == CANONICAL_ASYNCRAT_DOMAIN
        assert item.observation.raw_payload is None

        # No Investigation/subject binding anywhere on the output.
        assert not hasattr(item.evidence, "investigation_id")
        assert not hasattr(item.evidence, "subject")
        assert not hasattr(item.observation, "subject")

        # Evidence absent + no latest observation -> CREATE.
        transition = decide_evidence_transition(
            evidence_exists=False,
            latest_observation=None,
            candidate=item.observation,
        )
        assert transition is EvidenceTransition.CREATE_EVIDENCE_AND_OBSERVATION

    def test_v01_first_observation_diff_none(self) -> None:
        """The first observation's diff is ``None``, never ``{}``."""
        item = convert_semantic_source_objects(
            (_record(),), _context(), build_threatfox_conversion_registry()
        )[0]
        material = EvidenceMaterialState.from_candidate(item.observation)
        # The first observation is version 1 with no prior state to diff.
        first = _synthetic_latest(
            {
                "observed_at": material.observed_at,
                "facts": material.facts,
                "raw_payload": material.raw_payload,
            },
            version=1,
        )
        assert first.version == 1
        assert first.diff is None


class TestUnchangedReRetrieval:
    """D28A-V02: same record, later retrieval -> NO_CHANGE."""

    def test_v02_unchanged_retrieval_no_change(self) -> None:
        """Same material state with a later retrieved_at compares equal."""
        registry = build_threatfox_conversion_registry()
        first = convert_semantic_source_objects(
            (_record(),), _context(retrieved_at=_TS), registry
        )[0]
        later = convert_semantic_source_objects(
            (_record(),),
            _context(retrieved_at=_TS + timedelta(hours=6)),
            registry,
        )[0]

        # Same deterministic Evidence identity regardless of retrieval time.
        assert first.evidence.id == later.evidence.id
        assert EvidenceMaterialState.from_candidate(
            first.observation
        ) == EvidenceMaterialState.from_candidate(later.observation)

        synthetic_latest = _synthetic_latest(
            {
                "observed_at": first.observation.observed_at,
                "facts": first.observation.facts,
                "raw_payload": first.observation.raw_payload,
            }
        )
        transition = decide_evidence_transition(
            evidence_exists=True,
            latest_observation=synthetic_latest,
            candidate=later.observation,
        )
        assert transition is EvidenceTransition.NO_CHANGE


class TestMaterialUpdate:
    """D28A-V03: same record identity, changed material fact -> APPEND + diff."""

    def test_v03_material_update_appends_with_diff(self) -> None:
        """A changed material fact appends and yields the canonical diff."""
        registry = build_threatfox_conversion_registry()
        first = convert_semantic_source_objects((_record(),), _context(), registry)[0]
        changed = convert_semantic_source_objects(
            (_record(ioc="changed.example"),), _context(), registry
        )[0]

        # Same Evidence identity: the record identity is unchanged.
        assert first.evidence.id == changed.evidence.id
        assert EvidenceMaterialState.from_candidate(
            first.observation
        ) != EvidenceMaterialState.from_candidate(changed.observation)

        synthetic_latest = _synthetic_latest(
            {
                "observed_at": first.observation.observed_at,
                "facts": first.observation.facts,
                "raw_payload": first.observation.raw_payload,
            }
        )
        transition = decide_evidence_transition(
            evidence_exists=True,
            latest_observation=synthetic_latest,
            candidate=changed.observation,
        )
        assert transition is EvidenceTransition.APPEND_OBSERVATION

        diff = material_state_diff(
            EvidenceMaterialState.from_observation(synthetic_latest),
            EvidenceMaterialState.from_candidate(changed.observation),
        )
        assert "facts" in diff
        changed_match = thaw_json(diff["facts"]["new"])["matches"][0]
        assert changed_match["ioc"] == "changed.example"


class TestInvestigationIndependence:
    """D28A-V04: conversion requires no Investigation/Entity subject context."""

    def test_v04_conversion_succeeds_without_investigation_binding(self) -> None:
        """Global conversion is successful with no Investigation or subject."""
        registry = build_threatfox_conversion_registry()
        record = _record(record_id="864299")
        converted = convert_semantic_source_objects((record,), _context(), registry)
        assert len(converted) == 1
        assert converted[0].evidence.id == evidence_id_for_source_record(
            SemanticFormatId.THREATFOX, SourceId.THREATFOX, "864299"
        )
        # Nothing in the pipeline ever introduces an Investigation identity.
        assert not hasattr(converted[0].evidence, "investigation_id")
        assert not hasattr(converted[0].observation, "investigation_id")
