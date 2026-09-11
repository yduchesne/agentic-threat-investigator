# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Behavioral unit tests for the pure EvidenceAnalystEvaluator.

Every failure code has a passing and a failing case, failure ordering is
deterministic, and unknown fixture labels fail closed.
"""

from __future__ import annotations

import pytest

from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.evaluation.analyst.evaluator import (
    EvidenceAnalystEvaluator,
)
from agentic_threat_investigator.evaluation.analyst.models import (
    AnalystEvaluationFailureCode,
    AnalystEvaluationResult,
    AnalystScenario,
    AnalystScenarioResolution,
    ExpectedAssessment,
    ExpectedFinding,
    ForbiddenFinding,
    RequiredContradiction,
    UnknownFixtureLabelError,
)
from tests.support.evaluation_fixtures import (
    EVIDENCE_A,
    EVIDENCE_B,
    OBSERVATION,
    evidence_support,
    finding,
    observation_support,
    unit_assessment,
    unit_resolution,
    unit_scenario,
)


def evaluate(
    *,
    scenario: AnalystScenario | None = None,
    expected: ExpectedAssessment | None = None,
    resolution: AnalystScenarioResolution | None = None,
    assessment: Assessment | None = None,
) -> AnalystEvaluationResult:
    """Run the evaluator with the unit scenario/resolution by default."""
    selected = scenario or unit_scenario(expected=expected)
    selected_resolution = resolution or unit_resolution(selected)
    selected_assessment = assessment or unit_assessment()
    return EvidenceAnalystEvaluator().evaluate(
        scenario=selected,
        resolution=selected_resolution,
        assessment=selected_assessment,
    )


def codes(result: AnalystEvaluationResult) -> list[AnalystEvaluationFailureCode]:
    """Return the failure codes of one evaluation result in order."""
    return [failure.code for failure in result.failures]


def test_verdict_allowed_passes() -> None:
    """An allowed verdict produces no verdict failure."""
    result = evaluate()
    assert codes(result) == []
    assert result.passed


def test_verdict_not_allowed_fails() -> None:
    """A disallowed verdict emits VERDICT_NOT_ALLOWED."""
    result = evaluate(assessment=unit_assessment(verdict=Verdict.SUSPICIOUS))
    assert AnalystEvaluationFailureCode.VERDICT_NOT_ALLOWED in codes(result)


def test_confidence_allowed_passes() -> None:
    """An allowed confidence produces no confidence failure."""
    result = evaluate()
    assert codes(result) == []


def test_confidence_not_allowed_fails() -> None:
    """A disallowed confidence emits CONFIDENCE_NOT_ALLOWED."""
    result = evaluate(assessment=unit_assessment(confidence=AssessmentConfidence.LOW))
    assert AnalystEvaluationFailureCode.CONFIDENCE_NOT_ALLOWED in codes(result)


def test_required_finding_present_passes() -> None:
    """A required Finding present in the Assessment satisfies the expectation."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed
    assert codes(result) == []


def test_required_finding_absent_fails() -> None:
    """A required Finding with no candidate emits REQUIRED_FINDING_MISSING."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    result = evaluate(expected=expected, assessment=unit_assessment(findings=()))
    assert AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING in codes(result)


def test_required_evidence_support_present_passes() -> None:
    """Required Evidence support satisfied by exact identity passes."""
    expectation = ExpectedFinding(
        category=None,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed


def test_required_evidence_support_absent_fails() -> None:
    """Required Evidence support absent from every candidate emits REQUIRED_SUPPORT_MISSING."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_B]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.REQUIRED_SUPPORT_MISSING in codes(result)


def test_required_relationship_support_present_passes() -> None:
    """Required RelationshipObservation support passes by exact identity."""
    expectation = ExpectedFinding(
        category=FindingCategory.ASSOCIATION,
        disposition=FindingDisposition.SUPPORTING,
        required_relationship_support=frozenset({OBSERVATION}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                category=FindingCategory.ASSOCIATION,
                support=(
                    observation_support(
                        resolution.relationship_observation_ids[OBSERVATION]
                    ),
                ),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed


def test_required_relationship_support_absent_fails() -> None:
    """Missing RelationshipObservation support emits REQUIRED_SUPPORT_MISSING."""
    expectation = ExpectedFinding(
        category=FindingCategory.ASSOCIATION,
        disposition=FindingDisposition.SUPPORTING,
        required_relationship_support=frozenset({OBSERVATION}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    # A candidate exists in the right category but cites only direct evidence,
    # never the required RelationshipObservation.
    assessment = unit_assessment(
        findings=(
            finding(
                category=FindingCategory.ASSOCIATION,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.REQUIRED_SUPPORT_MISSING in codes(result)


def test_forbidden_support_absent_passes() -> None:
    """A clean candidate satisfies even though the expectation forbids labels."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        forbidden_evidence_support=frozenset({EVIDENCE_B}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed


def test_forbidden_support_present_fails() -> None:
    """A candidate citing forbidden support emits FORBIDDEN_SUPPORT_USED."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        forbidden_evidence_support=frozenset({EVIDENCE_B}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(
                    evidence_support(resolution.evidence_ids[EVIDENCE_A]),
                    evidence_support(resolution.evidence_ids[EVIDENCE_B]),
                ),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.FORBIDDEN_SUPPORT_USED in codes(result)


def test_required_finding_confidence_constraint() -> None:
    """A finding with a disallowed confidence cannot satisfy an expectation."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        allowed_confidence=frozenset({AssessmentConfidence.HIGH}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING in codes(result)


def test_contradiction_represented_passes() -> None:
    """Both contradiction sides present satisfy the requirement."""
    contradiction = RequiredContradiction(
        supporting_finding=ExpectedFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            required_evidence_support=frozenset({EVIDENCE_A}),
        ),
        contradicting_finding=ExpectedFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.CONTRADICTING,
            required_evidence_support=frozenset({EVIDENCE_B}),
        ),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.SUSPICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_contradictions=(contradiction,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        verdict=Verdict.SUSPICIOUS,
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
            finding(
                disposition=FindingDisposition.CONTRADICTING,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_B]),),
            ),
        ),
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed
    assert codes(result) == []


def test_contradiction_missing_fails() -> None:
    """One missing contradiction side emits REQUIRED_CONTRADICTION_MISSING."""
    contradiction = RequiredContradiction(
        supporting_finding=ExpectedFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            required_evidence_support=frozenset({EVIDENCE_A}),
        ),
        contradicting_finding=ExpectedFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.CONTRADICTING,
            required_evidence_support=frozenset({EVIDENCE_B}),
        ),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.SUSPICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_contradictions=(contradiction,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        verdict=Verdict.SUSPICIOUS,
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        ),
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.REQUIRED_CONTRADICTION_MISSING in codes(result)


def test_contradiction_supporting_side_missing_message() -> None:
    """The contradicting-side message is deterministic and safe."""
    contradiction = RequiredContradiction(
        supporting_finding=ExpectedFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            required_evidence_support=frozenset({EVIDENCE_A}),
        ),
        contradicting_finding=ExpectedFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.CONTRADICTING,
            required_evidence_support=frozenset({EVIDENCE_B}),
        ),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.SUSPICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_contradictions=(contradiction,),
    )
    result = evaluate(expected=expected, assessment=unit_assessment(findings=()))
    failure = next(
        item
        for item in result.failures
        if item.code is AnalystEvaluationFailureCode.REQUIRED_CONTRADICTION_MISSING
    )
    assert "supporting(" in failure.message
    assert "contradicting(" in failure.message


def test_required_limitation_present_passes() -> None:
    """A required canonical limitation present in the Assessment passes."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_limitations=frozenset({"  Evidence is approximate.  "}),
    )
    result = evaluate(
        expected=expected,
        assessment=unit_assessment(limitations=("Evidence is  approximate.",)),
    )
    assert result.passed


def test_required_limitation_missing_fails() -> None:
    """A missing canonical limitation emits REQUIRED_LIMITATION_MISSING."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_limitations=frozenset({"Evidence is approximate."}),
    )
    result = evaluate(expected=expected, assessment=unit_assessment(limitations=()))
    assert AnalystEvaluationFailureCode.REQUIRED_LIMITATION_MISSING in codes(result)


def test_required_unresolved_question_present_passes() -> None:
    """A required canonical unresolved question present in the Assessment passes."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_unresolved_questions=frozenset({"Is the host still active?"}),
    )
    result = evaluate(
        expected=expected,
        assessment=unit_assessment(unresolved_questions=("Is the host still active?",)),
    )
    assert result.passed


def test_required_unresolved_question_missing_fails() -> None:
    """A missing canonical unresolved question emits the stable code."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_unresolved_questions=frozenset({"Is the host still active?"}),
    )
    result = evaluate(expected=expected, assessment=unit_assessment())
    assert AnalystEvaluationFailureCode.REQUIRED_UNRESOLVED_QUESTION_MISSING in codes(
        result
    )


def test_required_next_step_present_passes() -> None:
    """A required canonical next step present in the Assessment passes."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_next_steps=frozenset({"Revalidate the indicator."}),
    )
    result = evaluate(
        expected=expected,
        assessment=unit_assessment(next_steps=("Revalidate the indicator.",)),
    )
    assert result.passed


def test_required_next_step_missing_fails() -> None:
    """A missing canonical next step emits REQUIRED_NEXT_STEP_MISSING."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_next_steps=frozenset({"Revalidate the indicator."}),
    )
    result = evaluate(expected=expected, assessment=unit_assessment(next_steps=()))
    assert AnalystEvaluationFailureCode.REQUIRED_NEXT_STEP_MISSING in codes(result)


def test_contextual_support_allowed_as_context() -> None:
    """A contextual-only label may appear inside a GEOLOCATION SUPPORTING Finding."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
        allowed_confidence=frozenset({AssessmentConfidence.LOW}),
        forbidden_evidence_support=frozenset({EVIDENCE_A}),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        findings=(
            finding(
                category=FindingCategory.GEOLOCATION,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        ),
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed


def test_contextual_support_rejected_as_maliciousness_support() -> None:
    """A material Finding citing a contextual-only label is CONTEXTUAL_EVIDENCE_MISUSED."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
        allowed_confidence=frozenset({AssessmentConfidence.LOW}),
        forbidden_evidence_support=frozenset({EVIDENCE_A}),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        verdict=Verdict.MALICIOUS,
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        ),
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.CONTEXTUAL_EVIDENCE_MISUSED in codes(result)


def test_entirely_contextual_finding_is_unsupported_material() -> None:
    """A material Finding supported entirely by contextual-only labels is unsupported."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
        allowed_confidence=frozenset({AssessmentConfidence.LOW}),
        forbidden_evidence_support=frozenset({EVIDENCE_A}),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        verdict=Verdict.MALICIOUS,
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        ),
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.UNSUPPORTED_MATERIAL_FINDING in codes(result)


def test_partial_contextual_support_is_misuse_but_not_unsupported() -> None:
    """Mixed contextual plus valid support fails misuse but not unsupported-material."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
        allowed_confidence=frozenset({AssessmentConfidence.LOW}),
        forbidden_evidence_support=frozenset({EVIDENCE_A}),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        verdict=Verdict.MALICIOUS,
        findings=(
            finding(
                support=(
                    evidence_support(resolution.evidence_ids[EVIDENCE_A]),
                    evidence_support(resolution.evidence_ids[EVIDENCE_B]),
                ),
            ),
        ),
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    codes_out = codes(result)
    assert AnalystEvaluationFailureCode.CONTEXTUAL_EVIDENCE_MISUSED in codes_out
    assert AnalystEvaluationFailureCode.UNSUPPORTED_MATERIAL_FINDING not in codes_out


def test_contextual_contradicting_finding_is_misuse() -> None:
    """A CONTRADICTING Finding citing a contextual-only label is also misuse."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
        allowed_confidence=frozenset({AssessmentConfidence.LOW}),
        forbidden_evidence_support=frozenset({EVIDENCE_A}),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        verdict=Verdict.MALICIOUS,
        findings=(
            finding(
                disposition=FindingDisposition.CONTRADICTING,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        ),
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.CONTEXTUAL_EVIDENCE_MISUSED in codes(result)


def test_no_forbidden_declarations_never_misuse() -> None:
    """Without scenario declarations the evaluator never reports contextual misuse."""
    resolution = unit_resolution()
    result = evaluate(
        assessment=unit_assessment(
            verdict=Verdict.MALICIOUS,
            findings=(
                finding(
                    category=FindingCategory.REPUTATION,
                    support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
                ),
            ),
        ),
        resolution=resolution,
    )
    assert AnalystEvaluationFailureCode.CONTEXTUAL_EVIDENCE_MISUSED not in codes(result)


def test_multiple_findings_exactly_one_satisfies() -> None:
    """Exactly one of several candidates satisfying the expectation is enough."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_B]),),
            ),
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed


def test_extra_valid_findings_allowed() -> None:
    """Extra structurally valid Findings do not fail evaluation."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
            finding(
                category=FindingCategory.REGISTRATION,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_B]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed


def test_extra_allowed_but_forbidden_pattern_still_fires() -> None:
    """Extra findings are allowed unless they match a forbidden expectation."""
    pattern = ForbiddenFinding(
        disposition=FindingDisposition.SUPPORTING,
        evidence_support=frozenset({EVIDENCE_B}),
    )
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
        forbidden_findings=(pattern,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
            finding(
                category=FindingCategory.NETWORK,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_B]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.FORBIDDEN_FINDING_PRESENT in codes(result)


def test_category_scoped_forbidden_pattern() -> None:
    """ForbiddenFinding category scoping narrows matches deterministically."""
    pattern = ForbiddenFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        evidence_support=frozenset({EVIDENCE_B}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        forbidden_findings=(pattern,),
    )
    resolution = unit_resolution()
    # NETWORK-category finding citing the label does NOT match the pattern.
    assessment = unit_assessment(
        findings=(
            finding(
                category=FindingCategory.NETWORK,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_B]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed
    # A REPUTATION finding citing it does match.
    assessment_matching = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_B]),),
            ),
        )
    )
    result_matching = evaluate(
        expected=expected, resolution=resolution, assessment=assessment_matching
    )
    assert AnalystEvaluationFailureCode.FORBIDDEN_FINDING_PRESENT in codes(
        result_matching
    )


def test_support_only_forbidden_pattern() -> None:
    """Support-only ForbiddenFinding matches any finding citing the label."""
    pattern = ForbiddenFinding(evidence_support=frozenset({EVIDENCE_A}))
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        forbidden_findings=(pattern,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                category=FindingCategory.NETWORK,
                disposition=FindingDisposition.CONTRADICTING,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.FORBIDDEN_FINDING_PRESENT in codes(result)


def test_failure_ordering_deterministic() -> None:
    """Failures follow the documented group order on identical input."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.HIGH}),
        required_findings=(expectation,),
        required_limitations=frozenset({"Missing."}),
        required_unresolved_questions=frozenset({"Question?"}),
    )
    assessment = unit_assessment(confidence=AssessmentConfidence.LOW)
    first = evaluate(expected=expected, assessment=assessment)
    second = evaluate(expected=expected, assessment=assessment)
    assert first == second
    assert [item.code for item in first.failures] == [
        AnalystEvaluationFailureCode.CONFIDENCE_NOT_ALLOWED,
        AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING,
        AnalystEvaluationFailureCode.REQUIRED_LIMITATION_MISSING,
        AnalystEvaluationFailureCode.REQUIRED_UNRESOLVED_QUESTION_MISSING,
    ]


def test_metrics_derive_from_the_same_comparison() -> None:
    """Metrics reflect exactly the same satisfaction the failures report."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
        required_limitations=frozenset({"Evidence is approximate."}),
    )
    result = evaluate(expected=expected, assessment=unit_assessment(findings=()))
    metrics = result.metrics
    assert metrics.required_findings_total == 1
    assert metrics.required_findings_satisfied == 0
    assert metrics.required_support_total == 1
    assert metrics.required_support_satisfied == 0
    assert metrics.required_limitations_total == 1
    assert metrics.required_limitations_satisfied == 0
    assert not result.passed


def test_metrics_reflect_satisfied_requirements() -> None:
    """Satisfied requirements surface in the metrics."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
        required_limitations=frozenset({"Evidence is approximate."}),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        ),
        limitations=("Evidence is approximate.",),
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    assert metrics.required_findings_satisfied == 1
    assert metrics.required_support_satisfied == 1
    assert metrics.required_limitations_satisfied == 1
    assert metrics.required_finding_recall == 1.0
    assert result.passed


def test_partial_support_reports_partial_satisfaction() -> None:
    """A candidate carrying one of two required labels reports half coverage."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        required_relationship_support=frozenset({OBSERVATION}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    assert metrics.required_support_total == 2
    assert metrics.required_support_satisfied == 1
    assert metrics.required_support_recall == 0.5
    failure = next(
        item
        for item in result.failures
        if item.code is AnalystEvaluationFailureCode.REQUIRED_SUPPORT_MISSING
    )
    assert "observations=[obs_one]" in failure.message
    assert "missing evidence=[]" in failure.message


def test_split_support_across_candidates_is_not_satisfied() -> None:
    """Two candidates each carrying one required label do not satisfy a Finding."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        required_relationship_support=frozenset({OBSERVATION}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
            finding(
                category=FindingCategory.ASSOCIATION,
                support=(
                    observation_support(
                        resolution.relationship_observation_ids[OBSERVATION]
                    ),
                ),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    # Best single candidate carries one label; the union never counts twice.
    assert metrics.required_support_satisfied == 1
    assert metrics.required_support_total == 2
    assert metrics.required_findings_satisfied == 0
    assert any(
        item.code is AnalystEvaluationFailureCode.REQUIRED_SUPPORT_MISSING
        for item in result.failures
    )


def test_confidence_does_not_erase_support_satisfaction() -> None:
    """All support present with disallowed Finding confidence still counts as satisfied."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        allowed_confidence=frozenset({AssessmentConfidence.HIGH}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    assert metrics.required_support_total == 1
    assert metrics.required_support_satisfied == 1
    assert metrics.required_findings_satisfied == 0
    assert AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING in {
        item.code for item in result.failures
    }


def test_later_fully_supported_finding_with_allowed_confidence_satisfies() -> None:
    """A later complete confidence-allowed Finding satisfies despite an earlier tie.

    Regression for fixes-03 HIGH 1: an earlier equally supported Finding with
    disallowed confidence must not produce a false REQUIRE_FINDING_MISSING.
    """
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        allowed_confidence=frozenset({AssessmentConfidence.HIGH}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    support = (evidence_support(resolution.evidence_ids[EVIDENCE_A]),)
    assessment = unit_assessment(
        findings=(
            finding(confidence=AssessmentConfidence.LOW, support=support),
            finding(confidence=AssessmentConfidence.HIGH, support=support),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    assert result.passed
    assert metrics.required_findings_satisfied == 1
    assert metrics.required_support_satisfied == metrics.required_support_total
    assert AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING not in {
        item.code for item in result.failures
    }


def test_fully_supported_finding_order_does_not_change_semantics() -> None:
    """Reversing the two Findings yields the same satisfaction and metrics."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        allowed_confidence=frozenset({AssessmentConfidence.HIGH}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    support = (evidence_support(resolution.evidence_ids[EVIDENCE_A]),)

    def run(
        order: tuple[AssessmentConfidence, AssessmentConfidence],
    ) -> AnalystEvaluationResult:
        """Run the evaluator for one confidence ordering."""
        assessment = unit_assessment(
            findings=(
                finding(confidence=order[0], support=support),
                finding(confidence=order[1], support=support),
            )
        )
        return evaluate(expected=expected, resolution=resolution, assessment=assessment)

    forward = run((AssessmentConfidence.LOW, AssessmentConfidence.HIGH))
    reversed_order = run((AssessmentConfidence.HIGH, AssessmentConfidence.LOW))
    assert forward.passed
    assert reversed_order.passed
    assert forward.metrics == reversed_order.metrics


def test_all_fully_supported_candidates_disallowed_confidence() -> None:
    """Every complete candidate with disallowed confidence fails the Finding."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        allowed_confidence=frozenset({AssessmentConfidence.HIGH}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    support = (evidence_support(resolution.evidence_ids[EVIDENCE_A]),)
    assessment = unit_assessment(
        findings=(
            finding(confidence=AssessmentConfidence.LOW, support=support),
            finding(confidence=AssessmentConfidence.MEDIUM, support=support),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    assert metrics.required_findings_satisfied == 0
    assert metrics.required_support_satisfied == metrics.required_support_total
    assert [
        item.code
        for item in result.failures
        if item.code is AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING
    ] == [AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING]


def test_finding_satisfaction_ignores_metric_best_selection() -> None:
    """Best-tie to a disallowed Finding never blocks a later allowed one.

    This regression pins the exact fixes-03 false-negative shape: the metric
    best tie resolves to the first Finding whose confidence is disallowed;
    the later equally supported Finding carries allowed confidence and must
    still satisfy the requirement.
    """
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A, EVIDENCE_B}),
        allowed_confidence=frozenset({AssessmentConfidence.HIGH}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    full_support = (
        evidence_support(resolution.evidence_ids[EVIDENCE_A]),
        evidence_support(resolution.evidence_ids[EVIDENCE_B]),
    )
    assessment = unit_assessment(
        findings=(
            finding(confidence=AssessmentConfidence.LOW, support=full_support),
            finding(confidence=AssessmentConfidence.HIGH, support=full_support),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    assert result.passed
    assert metrics.required_findings_satisfied == 1
    assert metrics.required_support_total == 2
    assert metrics.required_support_satisfied == 2
    assert AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING not in {
        item.code for item in result.failures
    }


def test_tainted_candidate_contributes_no_support() -> None:
    """A candidate using forbidden support never counts toward support metrics."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        forbidden_evidence_support=frozenset({EVIDENCE_B}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(
                    evidence_support(resolution.evidence_ids[EVIDENCE_A]),
                    evidence_support(resolution.evidence_ids[EVIDENCE_B]),
                ),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    assert metrics.required_support_total == 1
    assert metrics.required_support_satisfied == 0
    assert AnalystEvaluationFailureCode.FORBIDDEN_SUPPORT_USED in {
        item.code for item in result.failures
    }


def test_later_candidate_with_more_support_is_selected() -> None:
    """The best candidate is chosen by coverage, not declaration position."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A, EVIDENCE_B}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
            finding(
                support=(
                    evidence_support(resolution.evidence_ids[EVIDENCE_A]),
                    evidence_support(resolution.evidence_ids[EVIDENCE_B]),
                ),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    # The later candidate carries both labels and drives the metric.
    assert metrics.required_support_satisfied == 2
    assert metrics.required_findings_satisfied == 1
    assert result.passed


def test_equal_count_candidates_preserve_declaration_order() -> None:
    """Tied candidates resolve deterministically to the first declared Finding."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A, EVIDENCE_B}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    first_assessment = unit_assessment(
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
                confidence=AssessmentConfidence.LOW,
            ),
        )
    )
    first = evaluate(
        expected=expected, resolution=resolution, assessment=first_assessment
    )
    second = evaluate(
        expected=expected, resolution=resolution, assessment=first_assessment
    )
    assert first == second
    assert first.metrics.required_support_satisfied == 1
    # The first declared finding is the stable best candidate.
    missing = next(
        item
        for item in first.failures
        if item.code is AnalystEvaluationFailureCode.REQUIRED_SUPPORT_MISSING
    )
    assert "missing evidence=[provider_b]" in missing.message


def test_unknown_resolution_label_fails_closed() -> None:
    """A resolution missing an expectation label raises UnknownFixtureLabelError."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    resolution = resolution.model_copy(
        update={
            "evidence_ids": {
                key: value
                for key, value in resolution.evidence_ids.items()
                if key != EVIDENCE_A
            }
        }
    )
    with pytest.raises(UnknownFixtureLabelError):
        evaluate(expected=expected, resolution=resolution)


def test_unknown_observation_resolution_label_fails_closed() -> None:
    """A resolution missing an observation label fails closed identically."""
    contradiction = RequiredContradiction(
        supporting_finding=ExpectedFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            required_evidence_support=frozenset({EVIDENCE_A}),
        ),
        contradicting_finding=ExpectedFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.CONTRADICTING,
            required_relationship_support=frozenset({OBSERVATION}),
        ),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_contradictions=(contradiction,),
    )
    resolution = unit_resolution()
    resolution = resolution.model_copy(
        update={
            "relationship_observation_ids": {
                key: value
                for key, value in resolution.relationship_observation_ids.items()
                if key != OBSERVATION
            }
        }
    )
    with pytest.raises(UnknownFixtureLabelError):
        evaluate(expected=expected, resolution=resolution)


def test_contradiction_satisfies_every_structural_branch() -> None:
    """Each structural mismatch branch on a contradiction side fails the pair.

    Successive expectations constrain category, required evidence, required
    observation, forbidden support, and confidence; in every case the missing
    side forces REQUIRED_CONTRADICTION_MISSING and no side sub-failure leaks.
    """
    resolution = unit_resolution()
    evidence_a = evidence_support(resolution.evidence_ids[EVIDENCE_A])
    evidence_b = evidence_support(resolution.evidence_ids[EVIDENCE_B])
    observation = observation_support(
        resolution.relationship_observation_ids[OBSERVATION]
    )

    cases: list[tuple[ExpectedFinding, tuple[AnalyticalFinding, ...], str]] = [
        (
            ExpectedFinding(
                category=FindingCategory.NETWORK,
                disposition=FindingDisposition.SUPPORTING,
                required_evidence_support=frozenset({EVIDENCE_A}),
            ),
            (finding(support=(evidence_a,)),),
            "category",
        ),
        (
            ExpectedFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                required_evidence_support=frozenset({EVIDENCE_A}),
            ),
            (finding(support=(evidence_b,)),),
            "required evidence",
        ),
        (
            ExpectedFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                required_relationship_support=frozenset({OBSERVATION}),
            ),
            (finding(support=(evidence_a,)),),
            "required observation",
        ),
        (
            ExpectedFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                required_evidence_support=frozenset({EVIDENCE_A}),
                forbidden_evidence_support=frozenset({EVIDENCE_B}),
            ),
            (finding(support=(evidence_a, evidence_b)),),
            "forbidden support",
        ),
        (
            ExpectedFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                required_evidence_support=frozenset({EVIDENCE_A}),
                allowed_confidence=frozenset({AssessmentConfidence.HIGH}),
            ),
            (finding(support=(evidence_a, observation)),),
            "confidence",
        ),
    ]
    for expectation, actual_findings, label in cases:
        contradiction = RequiredContradiction(
            supporting_finding=expectation,
            contradicting_finding=ExpectedFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.CONTRADICTING,
                required_evidence_support=frozenset({EVIDENCE_B}),
            ),
        )
        expected = ExpectedAssessment(
            allowed_verdicts=frozenset({Verdict.MALICIOUS}),
            allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
            required_contradictions=(contradiction,),
        )
        result = evaluate(
            expected=expected,
            resolution=resolution,
            assessment=unit_assessment(findings=actual_findings),
        )
        failure_codes = codes(result)
        assert (
            AnalystEvaluationFailureCode.REQUIRED_CONTRADICTION_MISSING in failure_codes
        ), f"{label} mismatch should fail the contradiction"
        assert (
            AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING not in failure_codes
        ), f"{label} mismatch leaks no finding sub-failure"


def test_finding_without_contextual_labels_is_clean() -> None:
    """Findings citing no contextual-only label are untouched by the misuse check."""
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
        allowed_confidence=frozenset({AssessmentConfidence.LOW}),
        forbidden_evidence_support=frozenset({EVIDENCE_A}),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        verdict=Verdict.MALICIOUS,
        findings=(
            finding(
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_B]),),
            ),
        ),
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.CONTEXTUAL_EVIDENCE_MISUSED not in codes(result)


def test_forbidden_pattern_disposition_mismatch_ignored() -> None:
    """A disposition-scoped forbidden pattern ignores other dispositions."""
    pattern = ForbiddenFinding(
        disposition=FindingDisposition.SUPPORTING,
        evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        forbidden_findings=(pattern,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                disposition=FindingDisposition.CONTRADICTING,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed


def test_forbidden_pattern_category_only_matches_any_support() -> None:
    """A category-only forbidden pattern matches regardless of support."""
    pattern = ForbiddenFinding(category=FindingCategory.NETWORK)
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        forbidden_findings=(pattern,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                category=FindingCategory.NETWORK,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert AnalystEvaluationFailureCode.FORBIDDEN_FINDING_PRESENT in codes(result)


def test_forbidden_relationship_support_pattern() -> None:
    """A forbidden pattern may constrain RelationshipObservation support."""
    pattern = ForbiddenFinding(
        disposition=FindingDisposition.SUPPORTING,
        relationship_support=frozenset({OBSERVATION}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        forbidden_findings=(pattern,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                category=FindingCategory.ASSOCIATION,
                support=(
                    observation_support(
                        resolution.relationship_observation_ids[OBSERVATION]
                    ),
                ),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    failure = next(
        item
        for item in result.failures
        if item.code is AnalystEvaluationFailureCode.FORBIDDEN_FINDING_PRESENT
    )
    assert "observations=[obs_one]" in failure.message


def test_evaluator_does_not_mutate_inputs() -> None:
    """Evaluation never mutates the scenario, resolution, or Assessment."""
    scenario = unit_scenario()
    resolution = unit_resolution(scenario)
    before_resolution = resolution.model_dump()
    assessment = unit_assessment(findings=())
    EvidenceAnalystEvaluator().evaluate(
        scenario=scenario, resolution=resolution, assessment=assessment
    )
    assert resolution.model_dump() == before_resolution
    assert scenario.version == 1
    assert assessment.findings == ()


def test_support_identity_not_order_compared() -> None:
    """Only support identity matters; support serialization order never does."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
        required_relationship_support=frozenset({OBSERVATION}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                support=(
                    observation_support(
                        resolution.relationship_observation_ids[OBSERVATION]
                    ),
                    evidence_support(resolution.evidence_ids[EVIDENCE_A]),
                ),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    assert result.passed


def test_all_tainted_candidates_without_required_support() -> None:
    """All-tainted candidates with zero required support emit REQUIRED_FINDING_MISSING."""
    expectation = ExpectedFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        forbidden_evidence_support=frozenset({EVIDENCE_A}),
    )
    expected = ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        required_findings=(expectation,),
    )
    resolution = unit_resolution()
    assessment = unit_assessment(
        findings=(
            finding(
                category=FindingCategory.REPUTATION,
                support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
            ),
        )
    )
    result = evaluate(expected=expected, resolution=resolution, assessment=assessment)
    metrics = result.metrics
    assert metrics.required_support_total == 0
    assert metrics.required_support_satisfied == 0
    assert AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING in {
        item.code for item in result.failures
    }
    assert AnalystEvaluationFailureCode.FORBIDDEN_SUPPORT_USED in {
        item.code for item in result.failures
    }
