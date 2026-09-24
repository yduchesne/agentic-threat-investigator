# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C evaluator adapter tests (EA-E01..E10).

The thin PR 30 adapter over the existing EvidenceAnalystEvaluator is tested
offline with the repository-owned typed fashion helpers: PASS when the
existing evaluator passes, FAIL with a deterministic nonblank explanation and
JSON-safe descriptive diagnostics when it fails, and ERROR through the common
runner when the adapter boundary breaks. No numeric correctness, recall
threshold, or coverage-derived verdict is ever produced.
"""

from __future__ import annotations

import asyncio

import pytest

from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.evaluation.analyst.models import AnalystScenario
from agentic_threat_investigator.evaluation.analyst.pr30 import (
    EVIDENCE_ANALYST_ASSESSMENT_CONTRACT_EVALUATOR_ID,
    EvidenceAnalystContractEvaluator,
)
from agentic_threat_investigator.evaluation.analyst.target import (
    AnalystScenarioLookup,
    EvidenceAnalystEvaluationOutput,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationContext,
    EvaluationExecutionStatus,
    EvaluationRunner,
    EvaluationVerdict,
    evaluation_case_from,
)
from tests.support.evaluation_common import unit_dataset
from tests.support.evaluation_fixtures import (
    EVIDENCE_A,
    evidence_support,
    finding,
    unit_assessment,
    unit_resolution,
    unit_scenario,
)


def _output(
    scenario: AnalystScenario,
    *,
    assessment: Assessment | None = None,
) -> EvidenceAnalystEvaluationOutput:
    """Build one typed executor output for the given scenario."""
    return EvidenceAnalystEvaluationOutput(
        assessment=assessment or unit_assessment(),
        resolution=unit_resolution(scenario),
    )


def _context(case_id: str) -> EvaluationContext:
    """Build one minimal EvaluationContext bound to the unit dataset."""
    return EvaluationContext(dataset_id=unit_dataset().canonical, case_id=case_id)


class TestContractEvaluator:
    """EA-E01..E10 adapter verdict/explanation/diagnostics contract."""

    @pytest.mark.asyncio
    async def test_e01_existing_evaluator_pass_maps_to_pass(self) -> None:
        """E01 a passing existing-evaluator result maps to COMPLETED/PASS."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)
        result = await evaluator.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(scenario),
            context=_context(scenario.id),
        )
        assert result.evaluator_id == EVIDENCE_ANALYST_ASSESSMENT_CONTRACT_EVALUATOR_ID
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS
        assert result.explanation.strip()

    @pytest.mark.asyncio
    async def test_e02_existing_evaluator_fail_maps_to_fail(self) -> None:
        """E02 a failing existing-evaluator result maps to COMPLETED/FAIL."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)
        wrong = unit_assessment(verdict=Verdict.BENIGN)
        result = await evaluator.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(scenario, assessment=wrong),
            context=_context(scenario.id),
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.FAIL

    @pytest.mark.asyncio
    async def test_e03_explanation_deterministic_and_nonblank(self) -> None:
        """E03 the FAIL explanation is deterministic and nonblank."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)
        wrong = unit_assessment(verdict=Verdict.BENIGN)
        first = await evaluator.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(scenario, assessment=wrong),
            context=_context(scenario.id),
        )
        second = await evaluator.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(scenario, assessment=wrong),
            context=_context(scenario.id),
        )
        assert first.explanation == second.explanation
        assert first.explanation.strip()
        assert "verdict_not_allowed" in first.explanation

    @pytest.mark.asyncio
    async def test_e04_metrics_are_json_safe_descriptive_diagnostics(self) -> None:
        """E04 diagnostics carry JSON-safe descriptive counts, never ratios."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)
        wrong = unit_assessment(verdict=Verdict.BENIGN)
        result = await evaluator.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(scenario, assessment=wrong),
            context=_context(scenario.id),
        )
        assert result.diagnostics["verdict_acceptable"] is False
        assert result.diagnostics["required_findings_total"] == 0
        assert result.diagnostics["required_findings_satisfied"] == 0
        assert "required_finding_recall" not in result.diagnostics
        import json

        json.dumps(dict(result.diagnostics))  # JSON-safe round trip

    @pytest.mark.asyncio
    async def test_e05_partial_coverage_never_decides_verdict(self) -> None:
        """E05 descriptive counts never form a threshold-derived verdict."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)
        wrong = unit_assessment(verdict=Verdict.BENIGN)
        result = await evaluator.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(scenario, assessment=wrong),
            context=_context(scenario.id),
        )
        # The verdict depends only on the existing evaluator's binary decision.
        assert result.verdict is EvaluationVerdict.FAIL
        diagnostics = dict(result.diagnostics)
        assert diagnostics["required_findings_total"] == 0
        assert diagnostics["verdict_acceptable"] is False

    @pytest.mark.asyncio
    async def test_e06_no_numeric_correctness_anywhere(self) -> None:
        """E06 the adapter result exposes no score, float, or percentage."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)
        result = await evaluator.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(scenario),
            context=_context(scenario.id),
        )
        assert isinstance(result.verdict, EvaluationVerdict)
        assert not isinstance(result.verdict.value, float)
        assert "score" not in " ".join(str(key) for key in result.diagnostics)

    @pytest.mark.asyncio
    async def test_e07_identity_mismatch_is_error_via_runner(self) -> None:
        """E07 an unknown scenario identity surfaces as a runner ERROR."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)

        class ReturningTarget:
            """Target double returning a typed output for any case."""

            async def execute(self, *, case: object, context: object) -> object:
                """Return the unit output regardless of the case identity."""
                return _output(scenario)

        unknown = evaluation_case_from(scenario).model_copy(
            update={"case_id": "unknown_case"}
        )
        result = await EvaluationRunner().run(
            dataset_id=unit_dataset(),
            cases=[unknown],
            target=ReturningTarget(),
            evaluators=(evaluator,),  # type: ignore[arg-type]
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None
        case_result = result.cases[0]
        assert case_result.execution_status is EvaluationExecutionStatus.ERROR
        assert case_result.evaluator_results[0].execution_status is (
            EvaluationExecutionStatus.ERROR
        )

    @pytest.mark.asyncio
    async def test_e08_cancellation_propagates(self) -> None:
        """E08 asyncio.CancelledError propagates unchanged through the adapter."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])

        class CancellingEvaluatorDouble:
            """Existing-evaluator double raising cancellation from evaluate."""

            def evaluate(self, **_: object) -> object:
                """Raise cancellation exactly like a cancelled transport would."""
                raise asyncio.CancelledError("cancelled")

        evaluator = EvidenceAnalystContractEvaluator(
            scenario_lookup=lookup,
            evaluator=CancellingEvaluatorDouble(),  # type: ignore[arg-type]
        )
        with pytest.raises(asyncio.CancelledError):
            await evaluator.evaluate(
                case=evaluation_case_from(scenario),
                output=_output(scenario),
                context=_context(scenario.id),
            )

    @pytest.mark.asyncio
    async def test_e09_forbidden_support_is_fail(self) -> None:
        """E09 contextual-only support in a material finding FAILs."""
        from agentic_threat_investigator.evaluation.analyst.models import (
            ExpectedAssessment,
        )

        scenario = unit_scenario(
            expected=ExpectedAssessment(
                allowed_verdicts=frozenset({Verdict.MALICIOUS}),
                allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
                forbidden_evidence_support=frozenset({EVIDENCE_A}),
            )
        )
        lookup = AnalystScenarioLookup([scenario])
        evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)
        resolution = unit_resolution(scenario)
        misplaced = unit_assessment(
            verdict=Verdict.MALICIOUS,
            confidence=AssessmentConfidence.MEDIUM,
            findings=(
                finding(
                    category=FindingCategory.REPUTATION,
                    disposition=FindingDisposition.SUPPORTING,
                    support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
                ),
            ),
        )
        result = await evaluator.evaluate(
            case=evaluation_case_from(scenario),
            output=EvidenceAnalystEvaluationOutput(
                assessment=misplaced, resolution=resolution
            ),
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "contextual_evidence_misused" in result.explanation

    @pytest.mark.asyncio
    async def test_e10_missing_required_contradiction_is_fail(self) -> None:
        """E10 an unsatisfied required contradiction FAILs through the adapter."""
        from agentic_threat_investigator.domain.assessment import (
            FindingDisposition as FD,
        )
        from agentic_threat_investigator.evaluation.analyst.models import (
            ExpectedAssessment,
            ExpectedFinding,
            RequiredContradiction,
        )

        supporting = ExpectedFinding(
            disposition=FD.SUPPORTING,
            required_evidence_support=frozenset({EVIDENCE_A}),
        )
        contradicting = ExpectedFinding(
            disposition=FD.CONTRADICTING,
            required_evidence_support=frozenset({EVIDENCE_A}),
        )
        scenario = unit_scenario(
            expected=ExpectedAssessment(
                allowed_verdicts=frozenset({Verdict.MALICIOUS}),
                allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
                required_contradictions=(
                    RequiredContradiction(
                        supporting_finding=supporting,
                        contradicting_finding=contradicting,
                    ),
                ),
            )
        )
        lookup = AnalystScenarioLookup([scenario])
        evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)
        resolution = unit_resolution(scenario)
        # Only the SUPPORTING side is represented: the contradiction is missing.
        one_sided = unit_assessment(
            verdict=Verdict.MALICIOUS,
            confidence=AssessmentConfidence.MEDIUM,
            findings=(
                finding(
                    disposition=FD.SUPPORTING,
                    support=(evidence_support(resolution.evidence_ids[EVIDENCE_A]),),
                ),
            ),
        )
        result = await evaluator.evaluate(
            case=evaluation_case_from(scenario),
            output=EvidenceAnalystEvaluationOutput(
                assessment=one_sided, resolution=resolution
            ),
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "required_contradiction_missing" in result.explanation
