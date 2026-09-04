# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for core domain model construction and defaults."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    EvidenceReference,
    Verdict,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.geolocation import GeoLocation, GeoPrecision
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_entity_defaults() -> None:
    """Entities default their identity, display name, and attributes."""

    entity = Entity(type=EntityType.DOMAIN, value="example.com")

    assert entity.id is None
    assert entity.display_name is None
    assert entity.attributes == {}


def test_evidence_requires_core_observation_fields() -> None:
    """Evidence requires its type, subject, source, and retrieval time."""

    evidence = Evidence(
        investigation_id=uuid4(),
        type=EvidenceType.DNS,
        subject=EntityRef(type=EntityType.DOMAIN, value="example.com"),
        source="urn:ati:source:google_public_dns",
        retrieved_at=_RETRIEVED_AT,
    )

    assert evidence.observed_at is None
    assert evidence.facts == {}
    assert evidence.raw_payload is None
    assert evidence.source_record_id is None


def test_evidence_is_deeply_immutable() -> None:
    """Nested evidence data and its subject cannot be modified in place."""
    facts = {"answer": {"addresses": ["192.0.2.1"]}}
    evidence = Evidence(
        investigation_id=uuid4(),
        type=EvidenceType.DNS,
        subject=EntityRef(type=EntityType.DOMAIN, value="example.com"),
        source="urn:ati:source:google_public_dns",
        retrieved_at=_RETRIEVED_AT,
        facts=facts,
    )
    facts["answer"]["addresses"].append("192.0.2.2")

    with pytest.raises(TypeError, match="immutable"):
        evidence.facts["answer"]["extra"] = True
    with pytest.raises(ValidationError, match="frozen"):
        evidence.subject.value = "changed.example"

    assert evidence.facts["answer"]["addresses"] == ("192.0.2.1",)


def test_evidence_rejects_missing_subject() -> None:
    """Evidence without a subject is invalid."""

    with pytest.raises(ValidationError):
        Evidence(
            investigation_id=uuid4(),
            type=EvidenceType.DNS,
            source="urn:ati:source:google_public_dns",
            retrieved_at=_RETRIEVED_AT,
        )  # type: ignore[call-arg]


def test_relationship_requires_both_entity_ends() -> None:
    """Relationships bind an id, a type, and both entity ids."""

    relationship = Relationship(
        id=uuid4(),
        source_entity_id=uuid4(),
        target_entity_id=uuid4(),
        type=RelationshipType.RESOLVES_TO,
    )

    assert relationship.type == RelationshipType.RESOLVES_TO

    with pytest.raises(ValidationError):
        Relationship(
            id=uuid4(),
            source_entity_id=uuid4(),
            type=RelationshipType.RESOLVES_TO,
        )  # type: ignore[call-arg]


def test_relationship_observation_is_historical() -> None:
    """Observations record when and by which source a relationship was seen."""

    observation = RelationshipObservation(
        id=uuid4(),
        relationship_id=uuid4(),
        evidence_id=uuid4(),
        retrieved_at=_RETRIEVED_AT,
        source="urn:ati:source:google_public_dns",
    )

    assert observation.investigation_id is None
    assert observation.observed_at is None
    assert observation.confidence is None


def test_assessment_requires_verdict_confidence_and_summary() -> None:
    """Assessments require their analytical core and analyzed evidence."""

    assessment = Assessment(
        investigation_id=uuid4(),
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Registration and DNS evidence is inconsistent.",
        analyzed_evidence_ids=[uuid4(), uuid4()],
    )

    assert assessment.supporting_evidence == []
    assert assessment.contradicting_evidence == []
    assert assessment.limitations == []
    assert assessment.unresolved_questions == []
    assert assessment.recommended_next_steps == []


def test_assessment_rejects_missing_analyzed_evidence() -> None:
    """Assessments must trace to analyzed evidence."""

    with pytest.raises(ValidationError):
        Assessment(
            investigation_id=uuid4(),
            verdict=Verdict.INCONCLUSIVE,
            confidence=AssessmentConfidence.LOW,
            summary="Insufficient evidence.",
        )  # type: ignore[call-arg]


def test_evidence_reference_requires_rationale() -> None:
    """Evidence references pair an evidence id with its rationale."""

    reference = EvidenceReference(
        evidence_id=uuid4(),
        rationale="Domain resolves to a known-bad address.",
    )

    assert reference.evidence_id is not None

    with pytest.raises(ValidationError):
        EvidenceReference(evidence_id=uuid4())  # type: ignore[call-arg]


def test_geo_location_requires_provider_and_precision() -> None:
    """Geolocations always name their provider and precision."""

    location = GeoLocation(
        provider="urn:ati:source:dbip_city_lite",
        precision=GeoPrecision.CITY,
        country_code="DE",
        city="Munich",
        latitude=48.137,
        longitude=11.575,
    )

    assert location.region is None

    with pytest.raises(ValidationError):
        GeoLocation(country_code="DE", city="Munich")  # type: ignore[call-arg]
