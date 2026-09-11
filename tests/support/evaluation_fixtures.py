# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared deterministic builders for PR 20C unit tests.

The unit suites construct :class:`AnalystScenario` fixtures and their
:class:`AnalystScenarioResolution` maps programmatically (never through the
database); the UUIDs mirror the materializer's stable derivation so the same
identity rules apply. Test-only duplication of the URN scheme is accepted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid5

from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    RelationshipSupport,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType
from agentic_threat_investigator.evaluation.analyst.materializer import (
    DEFAULT_SCENARIO_NAMESPACE,
)
from agentic_threat_investigator.evaluation.analyst.models import (
    AnalystFixture,
    AnalystScenario,
    AnalystScenarioResolution,
    ExpectedAssessment,
    FixtureEntity,
    FixtureEvidence,
    FixtureObservation,
    FixtureRelationship,
)

FindingSupport = EvidenceSupport | RelationshipSupport
UNIT_SCENARIO_ID = "unit_scenario"
EVIDENCE_A = "provider_a"
EVIDENCE_B = "provider_b"
OBSERVATION = "obs_one"
RELATIONSHIP = "unit_relationship"

_FIXED = datetime(2026, 1, 2, tzinfo=UTC)


def unit_scenario(*, expected: ExpectedAssessment | None = None) -> AnalystScenario:
    """Build the canonical two-evidence, one-observation unit scenario."""
    fixture = AnalystFixture(
        objective="Assess the root indicator.",
        root_entity="target_ip",
        entities=(
            FixtureEntity(
                label="target_ip", type=EntityType.IP_ADDRESS, value="203.0.113.42"
            ),
            FixtureEntity(
                label="malware_family", type=EntityType.MALWARE, value="unit_malware"
            ),
        ),
        evidence=(
            FixtureEvidence(
                label=EVIDENCE_A,
                type=EvidenceType.REPUTATION,
                subject="target_ip",
                source="urn:ati:source:abuseipdb",
                facts={"score": 90},
            ),
            FixtureEvidence(
                label=EVIDENCE_B,
                type=EvidenceType.REPUTATION,
                subject="target_ip",
                source="urn:ati:source:threatfox",
                facts={"found": False},
            ),
        ),
        relationships=(
            FixtureRelationship(
                label=RELATIONSHIP,
                type=RelationshipType.ASSOCIATED_WITH,
                source="target_ip",
                target="malware_family",
            ),
        ),
        observations=(
            FixtureObservation(
                label=OBSERVATION,
                relationship=RELATIONSHIP,
                evidence=EVIDENCE_A,
                source="urn:ati:source:abuseipdb",
            ),
        ),
    )
    envelope = expected or ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
    )
    return AnalystScenario(
        id=UNIT_SCENARIO_ID,
        version=1,
        description="Deterministic unit-test scenario.",
        fixture=fixture,
        expected=envelope,
    )


def unit_resolution(
    scenario: AnalystScenario | None = None,
) -> AnalystScenarioResolution:
    """Build the label resolution mirroring the materializer's stable UUIDs."""
    scenario = scenario or unit_scenario()

    def stable(kind: str, label: str) -> UUID:
        """Derive one stable identity for a scenario label and kind."""
        return uuid5(
            DEFAULT_SCENARIO_NAMESPACE,
            f"urn:ati:scenario:{scenario.id}:v{scenario.version}:{kind}:{label}",
        )

    return AnalystScenarioResolution(
        evidence_ids={
            item.label: stable("evidence", item.label)
            for item in scenario.fixture.evidence
        },
        relationship_observation_ids={
            item.label: stable("observation", item.label)
            for item in scenario.fixture.observations
        },
        entity_ids={
            item.label: stable("entity", item.label)
            for item in scenario.fixture.entities
        },
        relationship_ids={
            item.label: stable("relationship", item.label)
            for item in scenario.fixture.relationships
        },
    )


def unit_assessment(
    *,
    verdict: Verdict = Verdict.MALICIOUS,
    confidence: AssessmentConfidence = AssessmentConfidence.MEDIUM,
    findings: tuple[AnalyticalFinding, ...] = (),
    limitations: tuple[str, ...] = (),
    unresolved_questions: tuple[str, ...] = (),
    next_steps: tuple[str, ...] = (),
    analyzed_evidence_ids: tuple[UUID, ...] | None = None,
) -> Assessment:
    """Build a structurally valid unit Assessment for the canonical scenario."""
    return Assessment(
        investigation_id=UUID("00000000-0000-0000-0000-000000000001"),
        verdict=verdict,
        confidence=confidence,
        summary="Unit-test assessment.",
        analyzed_evidence_ids=analyzed_evidence_ids or (UUID(int=1), UUID(int=2)),
        findings=findings,
        limitations=limitations,
        unresolved_questions=unresolved_questions,
        recommended_next_steps=next_steps,
    )


def finding(
    *,
    category: FindingCategory = FindingCategory.REPUTATION,
    disposition: FindingDisposition = FindingDisposition.SUPPORTING,
    confidence: AssessmentConfidence = AssessmentConfidence.MEDIUM,
    support: tuple[FindingSupport, ...] = (),
) -> AnalyticalFinding:
    """Build one deterministic Finding carrying typed support references."""
    return AnalyticalFinding(
        category=category,
        disposition=disposition,
        statement="Unit-test finding.",
        confidence=confidence,
        support=support,
    )


def evidence_support(evidence_id: UUID) -> EvidenceSupport:
    """Build a direct Evidence support reference."""
    return EvidenceSupport(kind="evidence", evidence_id=evidence_id)


def observation_support(observation_id: UUID) -> RelationshipSupport:
    """Build a RelationshipObservation support reference."""
    return RelationshipSupport(
        kind="relationship_observation", relationship_observation_id=observation_id
    )
