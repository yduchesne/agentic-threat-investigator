# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the end-to-end Investigation evaluator (PR 30F).

Covers every outcome, trajectory, provenance, and efficiency predicate
independently, plus all-true -> PASS, one semantic violation -> FAIL,
envelope PASS regardless of numeric variation, and exception -> ERROR
through the common runner.
"""

from __future__ import annotations

from uuid import uuid4

from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationStatus,
    StopReason,
)
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
    ReportNarrativeStatement,
    ResearchClaimRef,
)
from agentic_threat_investigator.evaluation.coordinator import CoordinatorActionRecord
from agentic_threat_investigator.evaluation.investigation.evaluator import (
    InvestigationEvaluator,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    InvestigationEvaluationOutput,
    InvestigationExecutionMetrics,
    InvestigationFailureCode,
    InvestigationScenario,
    InvestigationScenarioResolution,
)
from tests.unit.evaluation.investigation.helpers import scenario
from tests.unit.evaluation.investigation.output_fixtures import (
    ASSESSMENT_ID,
    INVESTIGATION_ID,
    MALWARE_ID,
    OBSERVATION_ID,
    RESEARCH_CLAIM_ID,
    RESEARCH_RESULT,
    RESEARCH_RESULT_ID,
    RESOLVED_IP_ID,
    ROOT_ID,
    assessment,
    output,
    report,
    research_claim_snapshot,
    terminal_state,
)
from tests.unit.evaluation.investigation.output_fixtures import (
    actions as fixture_actions,
)


def _resolution() -> InvestigationScenarioResolution:
    """Build the label resolution matching the fixture output."""
    return InvestigationScenarioResolution(
        investigation_id=INVESTIGATION_ID,
        entity_ids={
            "root_domain": ROOT_ID,
            "resolved_ip": RESOLVED_IP_ID,
            "malware_family": MALWARE_ID,
        },
    )


def test_all_required_predicates_true_passes() -> None:
    """A fully conforming output passes (all predicates true -> PASS)."""
    passed, failures = _evaluate_case(scenario(), output())
    assert passed
    assert failures == ()


def test_terminal_status_mismatch_fails() -> None:
    """A non-terminal status violates the terminal expectation."""
    failing = output(
        final_investigation=terminal_state(
            status=InvestigationStatus.PARTIAL,
            stop_reason=StopReason.FATAL_ERROR,
        )
    )
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.TERMINAL_STATUS_MISMATCH in failures


def _evaluate_case(
    case: InvestigationScenario, value: InvestigationEvaluationOutput
) -> tuple[bool, tuple[InvestigationFailureCode, ...]]:
    """Evaluate one scenario against one explicit output value."""
    result = InvestigationEvaluator().evaluate(
        scenario=case, resolution=_resolution(), output=value
    )
    return result.passed, result.failures


def test_stop_reason_mismatch_fails() -> None:
    """A different stop reason violates the terminal expectation."""
    failing = output(
        final_investigation=terminal_state(stop_reason=StopReason.DEPTH_LIMIT_REACHED)
    )
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.TERMINAL_STATUS_MISMATCH in failures


def test_termination_missing_fails() -> None:
    """A terminal state without a stop reason fails termination_present."""
    failing = output(final_investigation=terminal_state(stop_reason=None))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.TERMINATION_MISSING in failures


def test_missing_final_assessment_fails() -> None:
    """An output without a final Assessment fails closed."""
    failing = output(final_assessment=None)
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.FINAL_ASSESSMENT_MISSING in failures


def test_assessment_verdict_mismatch_fails() -> None:
    """A benign verdict violates the malicious expectation."""
    failing = output(final_assessment=assessment(verdict=Verdict.BENIGN))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.ASSESSMENT_VERDICT_MISMATCH in failures
    assert InvestigationFailureCode.REPORT_VERDICT_MISMATCH in failures


def test_assessment_confidence_mismatch_fails() -> None:
    """A low confidence violates the high-confidence expectation."""
    failing = output(final_assessment=assessment(confidence=AssessmentConfidence.LOW))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.ASSESSMENT_CONFIDENCE_MISMATCH in failures


def test_required_finding_missing_fails() -> None:
    """A required finding code absent from the Assessment fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["assessment"]["required_findings"] = ["association:supporting"]
    required_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(required_case, output())
    assert not passed
    assert InvestigationFailureCode.REQUIRED_FINDING_MISSING in failures


def test_forbidden_finding_included_fails() -> None:
    """A forbidden finding code present in the Assessment fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["assessment"]["forbidden_findings"] = ["reputation:supporting"]
    forbidden_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(forbidden_case, output())
    assert not passed
    assert InvestigationFailureCode.FORBIDDEN_FINDING_INCLUDED in failures


def test_required_evidence_source_missing_fails() -> None:
    """A required Evidence source absent from the observations fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["evidence"]["required_sources"] = ["urn:ati:source:threatfox"]
    source_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(source_case, output())
    assert not passed
    assert InvestigationFailureCode.REQUIRED_EVIDENCE_SOURCE_MISSING in failures


def test_required_entity_missing_fails() -> None:
    """A required entity label absent from the investigation fails."""
    failing = output(final_investigation=terminal_state(entity_ids=(ROOT_ID,)))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.REQUIRED_ENTITY_MISSING in failures


def test_forbidden_entity_included_fails() -> None:
    """A forbidden entity label present in the investigation fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["evidence"]["forbidden_entity_labels"] = ["malware_family"]
    forbidden_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(forbidden_case, output())
    assert not passed
    assert InvestigationFailureCode.FORBIDDEN_ENTITY_INCLUDED in failures


def test_required_relationship_missing_fails() -> None:
    """A required relationship type absent from the investigation fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["relationships"]["required"] = [
        "urn:ati:relationship:threat:associated_with"
    ]
    rel_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(rel_case, output())
    assert not passed
    assert InvestigationFailureCode.REQUIRED_RELATIONSHIP_MISSING in failures


def test_forbidden_relationship_included_fails() -> None:
    """A forbidden relationship type present in the investigation fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["relationships"]["required"] = []
    payload["expected"]["relationships"]["forbidden"] = [
        "urn:ati:relationship:dns:resolves_to"
    ]
    forbidden_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(forbidden_case, output())
    assert not passed
    assert InvestigationFailureCode.FORBIDDEN_RELATIONSHIP_INCLUDED in failures


def test_required_research_missing_fails() -> None:
    """A required research subject without a persisted result fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["research"]["required_subject_labels"] = ["malware_family"]
    research_case = InvestigationScenario.model_validate(payload)
    failing = output(research_results=())
    passed, failures = _evaluate_case(research_case, failing)
    assert not passed
    assert InvestigationFailureCode.REQUIRED_RESEARCH_MISSING in failures


def test_research_authorization_missing_fails() -> None:
    """A required research subject without a request action fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["trajectory"]["required_research"] = ["malware_family"]
    research_case = InvestigationScenario.model_validate(payload)
    failing = output(actions=fixture_actions(include_research=False))
    passed, failures = _evaluate_case(research_case, failing)
    assert not passed
    assert InvestigationFailureCode.RESEARCH_AUTHORIZATION_MISSING in failures


def test_research_evidence_separation_fails() -> None:
    """ResearchResult identities colliding with Evidence identities fail."""

    collision = RESEARCH_RESULT.model_copy(update={"id": OBSERVATION_ID})
    failing = output(research_results=(collision,))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.RESEARCH_EVIDENCE_SEPARATION in failures


def test_relationship_observation_provenance_fails() -> None:
    """A RelationshipObservation referencing unadmitted Evidence fails."""
    from tests.unit.evaluation.investigation.output_fixtures import (
        RELATIONSHIP_OBSERVATION,
    )

    broken = RELATIONSHIP_OBSERVATION.model_copy(
        update={"evidence_observation_id": uuid4()}
    )
    failing = output(relationship_observations=(broken,))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.RELATIONSHIP_OBSERVATION_PROVENANCE in failures


def test_unsupported_assessment_reference_fails() -> None:
    """An Assessment finding referencing unadmitted Evidence fails."""
    from agentic_threat_investigator.domain.assessment import (
        AnalyticalFinding,
        EvidenceSupport,
        FindingCategory,
        FindingDisposition,
    )

    broken_finding = AnalyticalFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement="Unsupported evidence.",
        confidence=AssessmentConfidence.MEDIUM,
        support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
    )
    failing = output(final_assessment=assessment(findings=(broken_finding,)))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.UNSUPPORTED_MATERIAL_REFERENCE in failures


def test_report_missing_fails() -> None:
    """A required report absent from the output fails."""
    failing = output(include_report=False)
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.REPORT_MISSING in failures


def test_report_verdict_mismatch_fails() -> None:
    """A report verdict contradicting the Assessment fails."""
    failing = output(report_value=report(verdict=Verdict.BENIGN))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.REPORT_VERDICT_MISMATCH in failures


def test_report_finding_ordinal_missing_fails() -> None:
    """A required report finding ordinal absent from the report fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["report"]["required_finding_ordinals"] = [2]
    ordinal_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(ordinal_case, output())
    assert not passed
    assert InvestigationFailureCode.REPORT_REQUIRED_FINDING_MISSING in failures


def test_report_invalid_reference_fails() -> None:
    """A report referencing unadmitted Evidence fails reference closure."""
    invalid = InvestigationReport(
        **{
            **report().model_dump(mode="python"),
            "source_evidence_ids": (uuid4(),),
        }
    )
    failing = output(report_value=invalid)
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.INVALID_REPORT_REFERENCE in failures


def test_report_research_context_envelope_fails() -> None:
    """A report below the authored research-context envelope fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["report"]["min_research_context"] = 1
    envelope_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(envelope_case, output())
    assert not passed
    assert InvestigationFailureCode.REPORT_RESEARCH_CONTEXT_MISSING in failures


def test_required_limitation_missing_fails() -> None:
    """A required report limitation phrase absent from the report fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["report"]["required_limitations"] = ["evidence is sparse"]
    limitation_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(limitation_case, output())
    assert not passed
    assert InvestigationFailureCode.REQUIRED_LIMITATION_MISSING in failures


def test_required_action_missing_fails() -> None:
    """A required trajectory action absent from the actions fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["trajectory"]["required_actions"] = [
        "urn:ati:action:pivot_skipped"
    ]
    action_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(action_case, output())
    assert not passed
    assert InvestigationFailureCode.REQUIRED_ACTION_MISSING in failures


def test_forbidden_action_included_fails() -> None:
    """A forbidden trajectory action present in the actions fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["trajectory"]["forbidden_actions"] = [
        "urn:ati:action:research_requested"
    ]
    forbidden_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(forbidden_case, output())
    assert not passed
    assert InvestigationFailureCode.FORBIDDEN_ACTION_INCLUDED in failures


def test_depth_policy_violation_fails() -> None:
    """An executed pivot beyond the authored depth fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["trajectory"]["max_depth"] = 0
    depth_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(depth_case, output())
    assert not passed
    assert InvestigationFailureCode.DEPTH_POLICY_VIOLATION in failures


def test_terminal_action_missing_fails() -> None:
    """A trajectory without the stop action fails termination_required."""
    failing = output(
        actions=tuple(
            action
            for action in fixture_actions()
            if action.action != "urn:ati:action:investigation_stopped"
        )
    )
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.TERMINAL_ACTION_MISSING in failures


def test_action_after_terminal_fails() -> None:
    """An action appearing after the stop action fails."""
    actions = list(fixture_actions())
    actions.append(
        CoordinatorActionRecord(
            action="urn:ati:action:provider_query",
            entity_id=ROOT_ID,
            provider="urn:ati:source:rdap",
            depth=0,
        )
    )
    failing = output(actions=tuple(actions))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.ACTION_AFTER_TERMINAL in failures


def test_provider_call_envelope_exceeded_fails() -> None:
    """An observed provider-call count above the envelope fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["efficiency"]["max_provider_calls"] = 3
    envelope_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(envelope_case, output())
    assert not passed
    assert InvestigationFailureCode.PROVIDER_CALL_LIMIT_EXCEEDED in failures


def test_llm_call_envelope_exceeded_fails() -> None:
    """An observed model-call count above the envelope fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["efficiency"]["max_llm_calls"] = 5
    envelope_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(envelope_case, output())
    assert not passed
    assert InvestigationFailureCode.LLM_CALL_LIMIT_EXCEEDED in failures


def test_duplicate_provider_call_envelope_exceeded_fails() -> None:
    """An observed duplicate provider-work count above the envelope fails."""
    metrics = InvestigationExecutionMetrics(
        provider_calls=5,
        llm_calls=6,
        analysis_calls=2,
        research_calls=1,
        report_calls=1,
        replans=0,
        pivot_count=1,
        duplicate_provider_calls=1,
        duplicate_entity_investigations=0,
        total_actions=6,
        maximum_depth_observed=1,
    )
    passed, failures = _evaluate_case(scenario(), output(metrics=metrics))
    assert not passed
    assert InvestigationFailureCode.DUPLICATE_PROVIDER_CALL_LIMIT_EXCEEDED in failures


def test_duplicate_entity_envelope_exceeded_fails() -> None:
    """An observed duplicate entity-investigation count above the envelope fails."""
    metrics = InvestigationExecutionMetrics(
        provider_calls=4,
        llm_calls=6,
        analysis_calls=2,
        research_calls=1,
        report_calls=1,
        replans=0,
        pivot_count=2,
        duplicate_provider_calls=0,
        duplicate_entity_investigations=1,
        total_actions=6,
        maximum_depth_observed=1,
    )
    passed, failures = _evaluate_case(scenario(), output(metrics=metrics))
    assert not passed
    assert InvestigationFailureCode.DUPLICATE_ENTITY_LIMIT_EXCEEDED in failures


def test_total_actions_envelope_exceeded_fails() -> None:
    """An observed total-action count above the envelope fails."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["efficiency"]["max_total_actions"] = 4
    envelope_case = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(envelope_case, output())
    assert not passed
    assert InvestigationFailureCode.TOTAL_ACTIONS_LIMIT_EXCEEDED in failures


def test_values_within_envelope_pass_regardless_of_variation() -> None:
    """Numeric variation within an envelope never changes the verdict."""
    for provider_calls in (4, 7, 11):
        metrics = InvestigationExecutionMetrics(
            provider_calls=provider_calls,
            llm_calls=6,
            analysis_calls=2,
            research_calls=1,
            report_calls=1,
            replans=0,
            pivot_count=1,
            duplicate_provider_calls=0,
            duplicate_entity_investigations=0,
            total_actions=5,
            maximum_depth_observed=1,
        )
        passed, failures = _evaluate_case(scenario(), output(metrics=metrics))
        assert passed
        assert failures == ()


def test_report_reference_closure_passes_with_research_context() -> None:
    """A report with valid research context passes reference closure."""
    snapshot = research_claim_snapshot()
    research_report = report(
        research_context=(snapshot,),
        narrative=(
            ReportNarrativeStatement(
                text="The family context supports the finding.",
                support=(
                    ResearchClaimRef(
                        kind="research_claim",
                        research_result_id=RESEARCH_RESULT_ID,
                        research_claim_id=RESEARCH_CLAIM_ID,
                    ),
                ),
            ),
        ),
    )
    passed, failures = _evaluate_case(scenario(), output(report_value=research_report))
    assert passed
    assert failures == ()


def test_report_narrative_assessment_ref_closure_passes() -> None:
    """A narrative Assessment finding reference resolves against the Assessment."""
    narrative = report(
        narrative=(
            ReportNarrativeStatement(
                text="The verdict is supported by the first finding.",
                support=(
                    AssessmentFindingRef(
                        kind="assessment_finding",
                        assessment_id=ASSESSMENT_ID,
                        finding_ordinal=1,
                    ),
                ),
            ),
        )
    )
    passed, failures = _evaluate_case(scenario(), output(report_value=narrative))
    assert passed


def test_report_narrative_unknown_finding_ordinal_fails() -> None:
    """A narrative reference to an out-of-range finding ordinal fails."""
    narrative = report(
        narrative=(
            ReportNarrativeStatement(
                text="Invalid finding ordinal.",
                support=(
                    AssessmentFindingRef(
                        kind="assessment_finding",
                        assessment_id=ASSESSMENT_ID,
                        finding_ordinal=99,
                    ),
                ),
            ),
        )
    )
    passed, failures = _evaluate_case(scenario(), output(report_value=narrative))
    assert not passed
    assert InvestigationFailureCode.INVALID_REPORT_REFERENCE in failures


def test_report_unknown_research_claim_fails() -> None:
    """A report research context referencing an unknown claim fails."""
    snapshot = research_claim_snapshot()
    broken = snapshot.model_copy(update={"research_claim_id": uuid4()})
    failing = output(report_value=report(research_context=(broken,)))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.INVALID_REPORT_REFERENCE in failures


def test_unknown_pivot_entity_execution_fails() -> None:
    """An executed pivot outside the investigation's entities fails."""
    actions = list(fixture_actions())
    actions.insert(
        0,
        CoordinatorActionRecord(
            action="urn:ati:action:pivot_executed",
            entity_id=uuid4(),
            depth=0,
        ),
    )
    failing = output(actions=tuple(actions))
    passed, failures = _evaluate_case(scenario(), failing)
    assert not passed
    assert InvestigationFailureCode.UNKNOWN_ENTITY_EXECUTION in failures


def test_unresolved_expectation_label_is_deterministic_fail() -> None:
    """A required label missing from the resolution fails (never crashes)."""
    case = scenario()
    payload = case.model_dump(mode="python")
    payload["expected"]["evidence"]["required_entity_labels"] = ["unknown_label"]
    bad = InvestigationScenario.model_validate(payload)
    passed, failures = _evaluate_case(bad, output())
    assert not passed
    assert InvestigationFailureCode.REQUIRED_ENTITY_MISSING in failures
