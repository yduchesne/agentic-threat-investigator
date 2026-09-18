# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared deterministic builders for PR 26G unit tests.

The unit suites construct :class:`GeointScenario` fixtures and their
:class:`GeointScenarioResolution` maps programmatically (never through the
database); the UUIDs mirror the materializer's stable derivation so the same
identity rules apply. Test-only duplication of the URN scheme is accepted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid5

from agentic_threat_investigator.domain.analyst import (
    AnalystGeointSummary,
    EvidenceAnalystDecision,
    GeographicFinding,
    GeographicFindingKind,
    GeographicTemporalInterpretation,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.evaluation.geoint.materializer import (
    DEFAULT_GEOINT_SCENARIO_NAMESPACE,
    scenario_investigation_id,
)
from agentic_threat_investigator.evaluation.geoint.models import (
    ExpectedAgentContext,
    ExpectedAgentOutput,
    ExpectedCurrentState,
    ExpectedGeointOutcome,
    ExpectedHistory,
    ExpectedResolutionOutcome,
    GeointAgentEvaluationInput,
    GeointFixture,
    GeointFixtureEntity,
    GeointFixtureEvidence,
    GeointFixtureLocation,
    GeointFixtureResolution,
    GeointScenario,
    GeointScenarioResolution,
    GeointValidationExpectation,
    GeointValidationOutcome,
)

UNIT_SCENARIO_ID = "unit_geoint_scenario"

_FIXED = datetime(2026, 1, 2, tzinfo=UTC)

US_GEOMETRY = "SRID=4326;POLYGON((-126 24,-66 24,-66 49,-126 49,-126 24))"
WA_GEOMETRY = "SRID=4326;POLYGON((-125 45,-116 45,-116 48.9,-125 48.9,-125 45))"
SEATTLE_POINT = "SRID=4326;POINT(-122.3321 47.6062)"


def _seattle_geography() -> tuple[GeointFixtureLocation, ...]:
    """Return the canonical US -> Washington -> Seattle reference corpus."""
    return (
        GeointFixtureLocation(
            label="us",
            location_type=LocationType.COUNTRY,
            name="United States",
            country_code="US",
            geometry=US_GEOMETRY,
        ),
        GeointFixtureLocation(
            label="washington",
            location_type=LocationType.ADMINISTRATIVE_AREA,
            name="Washington",
            country_code="US",
            admin1_code="WA",
            parent="us",
            geometry=WA_GEOMETRY,
        ),
        GeointFixtureLocation(
            label="seattle",
            location_type=LocationType.CITY,
            name="Seattle",
            country_code="US",
            admin1_code="WA",
            parent="washington",
            geometry=SEATTLE_POINT,
        ),
    )


def unit_geoint_scenario(
    *,
    expected: ExpectedGeointOutcome | None = None,
    fixture: GeointFixture | None = None,
) -> GeointScenario:
    """Build the canonical single-observation unit GEOINT scenario."""
    default_fixture = fixture or GeointFixture(
        objective="Assess whether the target IP is malicious.",
        root_entity="target_ip",
        geography=_seattle_geography(),
        entities=(
            GeointFixtureEntity(
                label="target_ip", type=EntityType.IP_ADDRESS, value="203.0.113.42"
            ),
        ),
        evidence=(
            GeointFixtureEvidence(
                label="seattle_evidence",
                subject="target_ip",
                source="urn:ati:source:test",
                facts={
                    "country_code": "US",
                    "region": "Washington",
                    "city": "Seattle",
                    "precision": "city",
                },
            ),
        ),
        resolutions=(
            GeointFixtureResolution(
                label="seattle_obs",
                entity="target_ip",
                evidence="seattle_evidence",
            ),
        ),
    )
    envelope = expected or ExpectedGeointOutcome(
        resolutions=(
            ExpectedResolutionOutcome(
                label="seattle_obs",
                status="resolved",
                location="seattle",
                precision=LocationPrecision.CITY,
            ),
        ),
        current=(
            ExpectedCurrentState(
                entity="target_ip",
                location="seattle",
                precision=LocationPrecision.CITY,
            ),
        ),
        histories=(ExpectedHistory(entity="target_ip", locations=("seattle",)),),
        agent_context=ExpectedAgentContext(),
        agent_output=ExpectedAgentOutput(
            expected_validation=GeointValidationExpectation.ACCEPTED,
            allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
        ),
    )
    return GeointScenario(
        id=UNIT_SCENARIO_ID,
        version=1,
        description="Deterministic unit-test GEOINT scenario.",
        fixture=default_fixture,
        expected=envelope,
    )


def overstatement_scenario() -> GeointScenario:
    """Build the unit overstatement scenario (two Entities, two cities).

    The delivered validator rejects a ``shared_location`` finding over
    observations in different cities; the evaluator independently proves the
    same structural predicate.
    """
    geography = _seattle_geography() + (
        GeointFixtureLocation(
            label="texas",
            location_type=LocationType.ADMINISTRATIVE_AREA,
            name="Texas",
            country_code="US",
            admin1_code="TX",
            parent="us",
            geometry=(
                "SRID=4326;POLYGON((-106.6 25.8,-93.5 25.8,-93.5 36.5,"
                "-106.6 36.5,-106.6 25.8))"
            ),
        ),
        GeointFixtureLocation(
            label="dallas",
            location_type=LocationType.CITY,
            name="Dallas",
            country_code="US",
            admin1_code="TX",
            parent="texas",
            geometry="SRID=4326;POINT(-96.7969 32.7767)",
        ),
    )
    fixture = GeointFixture(
        objective="Assess whether the two target IPs are malicious.",
        root_entity="ip_a",
        geography=geography,
        entities=(
            GeointFixtureEntity(
                label="ip_a", type=EntityType.IP_ADDRESS, value="203.0.113.221"
            ),
            GeointFixtureEntity(
                label="ip_b", type=EntityType.IP_ADDRESS, value="203.0.113.222"
            ),
        ),
        evidence=(
            GeointFixtureEvidence(
                label="a_evidence",
                subject="ip_a",
                source="urn:ati:source:test",
                facts={
                    "country_code": "US",
                    "region": "Washington",
                    "city": "Seattle",
                    "precision": "city",
                },
            ),
            GeointFixtureEvidence(
                label="b_evidence",
                subject="ip_b",
                source="urn:ati:source:test",
                facts={
                    "country_code": "US",
                    "region": "Texas",
                    "city": "Dallas",
                    "precision": "city",
                },
            ),
        ),
        resolutions=(
            GeointFixtureResolution(
                label="a_obs", entity="ip_a", evidence="a_evidence"
            ),
            GeointFixtureResolution(
                label="b_obs", entity="ip_b", evidence="b_evidence"
            ),
        ),
    )
    return GeointScenario(
        id="unit_overstatement_scenario",
        version=1,
        description="Deterministic unit-test overstatement scenario.",
        fixture=fixture,
        expected=ExpectedGeointOutcome(
            resolutions=(
                ExpectedResolutionOutcome(
                    label="a_obs",
                    status="resolved",
                    location="seattle",
                    precision=LocationPrecision.CITY,
                ),
                ExpectedResolutionOutcome(
                    label="b_obs",
                    status="resolved",
                    location="dallas",
                    precision=LocationPrecision.CITY,
                ),
            ),
            agent_context=ExpectedAgentContext(),
            agent_output=ExpectedAgentOutput(
                expected_validation=GeointValidationExpectation.REJECTED,
                allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
            ),
        ),
    )


def unit_geoint_resolution(
    scenario: GeointScenario | None = None,
) -> GeointScenarioResolution:
    """Build the label resolution mirroring the materializer's stable UUIDs."""
    scenario = scenario or unit_geoint_scenario()

    def stable(kind: str, label: str) -> UUID:
        """Derive one stable identity for a scenario label and kind."""
        return uuid5(
            DEFAULT_GEOINT_SCENARIO_NAMESPACE,
            f"urn:ati:scenario:{scenario.id}:v{scenario.version}:{kind}:{label}",
        )

    return GeointScenarioResolution(
        investigation_id=scenario_investigation_id(scenario),
        geography_ids={
            item.label: stable("geography", item.label)
            for item in scenario.fixture.geography
        },
        entity_ids={
            item.label: stable("entity", item.label)
            for item in scenario.fixture.entities
        },
        evidence_ids={
            item.label: stable("evidence", item.label)
            for item in scenario.fixture.evidence
        },
        resolution_ids={
            item.label: stable("resolution", item.label)
            for item in scenario.fixture.resolutions
        },
        observation_ids={
            item.label: stable("observation", item.label)
            for item in scenario.fixture.resolutions
        },
    )


def empty_summary() -> AnalystGeointSummary:
    """Build one empty model-visible summary DTO."""
    from agentic_threat_investigator.domain.analyst import (
        AnalystGeointPrecisionCounts,
    )

    return AnalystGeointSummary(
        entity_count_with_location=0,
        observation_count=0,
        location_count=0,
        country_count=0,
        administrative_area_count=0,
        city_count=0,
        precision_counts=AnalystGeointPrecisionCounts(
            country=0, administrative_area=0, city=0
        ),
        top_locations=(),
        truncated=False,
    )


def accepted_decision(
    *,
    verdict: Verdict = Verdict.INCONCLUSIVE,
    findings: tuple[AnalyticalFinding, ...] = (),
    geographic_findings: tuple[GeographicFinding, ...] = (),
) -> EvidenceAnalystDecision:
    """Build a minimal structurally valid decision."""
    return EvidenceAnalystDecision(
        verdict=verdict,
        confidence=AssessmentConfidence.LOW,
        summary="Descriptive assessment.",
        disposition=AnalysisDisposition.EXHAUSTED,
        findings=findings,
        geographic_findings=geographic_findings,
    )


def shared_location_finding(
    *,
    observation_ids: tuple[UUID, ...],
    evidence_observation_ids: tuple[UUID, ...],
    entity_ids: tuple[UUID, ...],
    location_ids: tuple[UUID, ...],
) -> GeographicFinding:
    """Build one descriptive SHARED_LOCATION finding."""
    return GeographicFinding(
        kind=GeographicFindingKind.SHARED_LOCATION,
        statement="The entities were observed in the same city.",
        temporal_interpretation=GeographicTemporalInterpretation.NONE,
        observation_ids=observation_ids,
        evidence_observation_ids=evidence_observation_ids,
        entity_ids=entity_ids,
        location_ids=location_ids,
    )


def accepted_input(
    *,
    decision: EvidenceAnalystDecision | None = None,
    validation: GeointValidationOutcome = GeointValidationOutcome.ACCEPTED,
) -> GeointAgentEvaluationInput:
    """Build a minimal agent evaluation input."""
    return GeointAgentEvaluationInput(
        decision=decision,
        validation=validation,
        assessment=None,
    )
