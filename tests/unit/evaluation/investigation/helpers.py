# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared helpers for the PR 30F Investigation evaluation unit tests."""

from __future__ import annotations

from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationStatus,
    StopReason,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationTarget,
    ExpectedBehavior,
    ScenarioSpecification,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    AssessmentExpectation,
    EfficiencyExpectation,
    EvidenceExpectation,
    ExpectedInvestigationOutcome,
    InvestigationRoot,
    InvestigationScenario,
    RelationshipExpectation,
    ReportExpectation,
    ResearchExpectation,
    TerminalExpectation,
    TrajectoryExpectation,
)


def scenario_specification(
    *, target: EvaluationTarget = EvaluationTarget.INVESTIGATION
) -> ScenarioSpecification:
    """Build one valid common scenario specification."""
    return ScenarioSpecification(
        title="Deterministic end-to-end investigation scenario",
        description="A deterministic investigation world exercising the production end-to-end path.",
        target=target,
        purpose="Exercise the production end-to-end path deterministically.",
        operational_relevance="A canonical scenario for the repository-owned end-to-end benchmark.",
        regression_risk="Protects against regressions in the production end-to-end path.",
        expected_behavior=ExpectedBehavior(
            required=("The investigation completes with a final Assessment.",)
        ),
        tags=frozenset({"unit-test"}),
        architecture_refs=("coordinator-policy",),
    )


def default_outcome() -> ExpectedInvestigationOutcome:
    """Build one valid expected outcome envelope."""
    return ExpectedInvestigationOutcome(
        terminal=TerminalExpectation(
            status=InvestigationStatus.COMPLETED,
            stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        ),
        assessment=AssessmentExpectation(
            verdict=Verdict.MALICIOUS,
            confidence=AssessmentConfidence.HIGH,
        ),
        evidence=EvidenceExpectation(
            required_sources=("urn:ati:source:google_public_dns",),
            required_entity_labels=("resolved_ip",),
        ),
        relationships=RelationshipExpectation(
            required=("urn:ati:relationship:dns:resolves_to",)
        ),
        research=ResearchExpectation(),
        report=ReportExpectation(
            required=True,
            verdict=Verdict.MALICIOUS,
            confidence=AssessmentConfidence.HIGH,
        ),
        trajectory=TrajectoryExpectation(
            required_actions=(
                "urn:ati:action:provider_query",
                "urn:ati:action:assessment_requested",
                "urn:ati:action:investigation_stopped",
            ),
            max_depth=2,
        ),
        efficiency=EfficiencyExpectation(
            max_provider_calls=12,
            max_llm_calls=12,
            max_replans=2,
            max_pivots=6,
            max_duplicate_provider_calls=0,
            max_duplicate_entity_investigations=0,
            max_total_actions=60,
        ),
    )


def scenario(
    *,
    scenario_id: str = "inv-test-01",
    fixture: str = "f02-malicious-multi-source",
    expected: ExpectedInvestigationOutcome | None = None,
) -> InvestigationScenario:
    """Build one valid investigation scenario for unit tests."""
    return InvestigationScenario(
        id=scenario_id,
        version=1,
        specification=scenario_specification(),
        fixture=fixture,
        root=InvestigationRoot(
            entity_label="root_domain",
            entity_type=EntityType.DOMAIN,
            value="update-package.test",
        ),
        expected=expected or default_outcome(),
    )
