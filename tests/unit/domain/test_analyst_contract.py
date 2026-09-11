# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 20B Evidence Analyst domain contracts.

Covers the immutable ``EvidenceAnalystInput`` DTOs and the semantic-only
``EvidenceAnalystDecision`` output: strict schema, forbidden extras,
blank-text rejection, facts freezing, and the absence of persistence-owned
fields the model must never supply.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.analyst import (
    AnalystEntity,
    AnalystEvidenceItem,
    AnalystRelationshipObservation,
    EvidenceAnalystDecision,
    EvidenceAnalystInput,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.immutable_json import FrozenDict
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.domain.relationships import RelationshipType

_RETRIEVED_AT = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)


def decision_factory(**overrides: object) -> EvidenceAnalystDecision:
    """Build a deterministic valid EvidenceAnalystDecision."""
    kwargs: dict[str, object] = {
        "verdict": Verdict.SUSPICIOUS,
        "confidence": AssessmentConfidence.MEDIUM,
        "summary": "Evidence supports the verdict.",
        "disposition": AnalysisDisposition.SUFFICIENT,
        "findings": (
            AnalyticalFinding(
                category=FindingCategory.NETWORK,
                disposition=FindingDisposition.SUPPORTING,
                statement="The domain resolves to the address.",
                confidence=AssessmentConfidence.MEDIUM,
                support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
            ),
        ),
        "limitations": ("limited provider coverage",),
        "unresolved_questions": ("Is the target still active?",),
        "recommended_next_steps": ("Query reputation sources daily.",),
    }
    kwargs.update(overrides)
    return EvidenceAnalystDecision.model_validate(kwargs)


def input_factory(**overrides: object) -> EvidenceAnalystInput:
    """Build a deterministic valid EvidenceAnalystInput."""
    source_id = uuid4()
    target_id = uuid4()
    evidence_id = uuid4()
    kwargs: dict[str, object] = {
        "investigation_id": uuid4(),
        "objective": "Assess the root indicator.",
        "root_entities": (
            AnalystEntity(
                entity_id=source_id,
                entity_type=EntityType.DOMAIN,
                value="example.com",
            ),
        ),
        "evidence": (
            AnalystEvidenceItem(
                evidence_id=evidence_id,
                type=EvidenceType.DNS,
                subject=AnalystEntity(
                    entity_id=source_id,
                    entity_type=EntityType.DOMAIN,
                    value="example.com",
                ),
                source="urn:ati:source:google_public_dns",
                retrieved_at=_RETRIEVED_AT,
                facts={"resolves_to": ["192.0.2.1"]},
            ),
        ),
        "relationship_observations": (
            AnalystRelationshipObservation(
                relationship_observation_id=uuid4(),
                evidence_id=evidence_id,
                relationship_id=uuid4(),
                relationship_type=RelationshipType.RESOLVES_TO,
                source_entity=AnalystEntity(
                    entity_id=source_id,
                    entity_type=EntityType.DOMAIN,
                    value="example.com",
                ),
                target_entity=AnalystEntity(
                    entity_id=target_id,
                    entity_type=EntityType.IP_ADDRESS,
                    value="192.0.2.1",
                ),
                retrieved_at=_RETRIEVED_AT,
                source="urn:ati:source:google_public_dns",
            ),
        ),
    }
    kwargs.update(overrides)
    return EvidenceAnalystInput.model_validate(kwargs)


def test_valid_decision_round_trips_through_json() -> None:
    """A valid decision serializes to stable JSON and back unchanged."""
    decision = decision_factory()

    loaded = EvidenceAnalystDecision.model_validate_json(decision.model_dump_json())

    assert loaded == decision
    assert loaded.model_dump(mode="json") == decision.model_dump(mode="json")


@pytest.mark.parametrize(
    "field",
    ["verdict", "confidence", "summary"],
)
def test_decision_requires_core_fields(field: str) -> None:
    """Core semantic fields are required."""
    kwargs = {
        "verdict": Verdict.BENIGN,
        "confidence": AssessmentConfidence.HIGH,
        "summary": "Evidence supports the verdict.",
    }
    del kwargs[field]
    with pytest.raises(ValidationError):
        EvidenceAnalystDecision.model_validate(kwargs)


def test_decision_rejects_unknown_fields() -> None:
    """The model must not accept fields the application owns or invents."""
    with pytest.raises(ValidationError):
        EvidenceAnalystDecision.model_validate(
            {
                "verdict": Verdict.BENIGN,
                "confidence": AssessmentConfidence.HIGH,
                "summary": "ok",
                "analyzed_evidence_ids": (uuid4(),),
                "persistence_id": uuid4(),
                "chain_of_thought": "hidden reasoning",
            }
        )


@pytest.mark.parametrize(
    "field",
    ["findings", "limitations", "unresolved_questions", "recommended_next_steps"],
)
def test_decision_empty_collections_are_allowed(field: str) -> None:
    """Ordered text/finding collections may be empty by default."""
    decision = decision_factory(**{field: ()})

    assert getattr(decision, field) == ()


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_decision_rejects_blank_summary(value: str) -> None:
    """Blank summaries are rejected."""
    with pytest.raises(ValidationError):
        decision_factory(summary=value)


def test_decision_rejects_blank_text_entries() -> None:
    """Blank entries inside ordered text collections are rejected."""
    with pytest.raises(ValidationError):
        decision_factory(limitations=("real limitation", "   "))


def test_decision_is_immutable() -> None:
    """The decision model is frozen and its mappings are deeply immutable."""
    decision = decision_factory()

    with pytest.raises(ValidationError, match="is frozen"):
        decision.summary = "changed"


def test_evidence_item_freezes_facts() -> None:
    """Facts are stored as a deeply immutable JSON object."""
    item = input_factory().evidence[0]

    assert isinstance(item.facts, FrozenDict)
    with pytest.raises(TypeError):
        item.facts["new"] = "x"


def test_evidence_item_defaults_facts_to_empty_frozen() -> None:
    """An Evidence item without facts carries an empty immutable mapping."""
    item = AnalystEvidenceItem(
        evidence_id=uuid4(),
        type=EvidenceType.NETWORK,
        subject=AnalystEntity(
            entity_id=uuid4(), entity_type=EntityType.IP_ADDRESS, value="192.0.2.1"
        ),
        source="urn:ati:source:rdap",
        retrieved_at=_RETRIEVED_AT,
    )

    assert item.facts == {}
    with pytest.raises(TypeError):
        item.facts["x"] = 1


def test_input_rejects_blank_objective() -> None:
    """A blank investigation objective is rejected."""
    with pytest.raises(ValidationError):
        input_factory(objective="   ")


def test_input_rejects_unknown_fields() -> None:
    """The input DTO never carries raw payloads, URLs, or tracing state."""
    with pytest.raises(ValidationError):
        EvidenceAnalystInput.model_validate(
            {
                "investigation_id": uuid4(),
                "objective": "Assess the root indicator.",
                "raw_payload": {"http_headers": {"x": "y"}},
                "source_url": "https://untrusted.example/",
            }
        )


def test_input_ordering_is_preserved() -> None:
    """Tuple collections preserve the deterministic loader order."""
    analyst_input = input_factory()

    assert [item.evidence_id for item in analyst_input.evidence]
    assert [
        obs.relationship_observation_id
        for obs in analyst_input.relationship_observations
    ]
    assert [entity.value for entity in analyst_input.root_entities] == ["example.com"]


def test_frozen_models_do_not_allow_mutation() -> None:
    """Every analyst DTO and the decision are frozen."""
    analyst_input = input_factory()

    with pytest.raises(ValidationError, match="is frozen"):
        analyst_input.objective = "changed"
    with pytest.raises(ValidationError, match="is frozen"):
        analyst_input.evidence[0].source = "changed"
