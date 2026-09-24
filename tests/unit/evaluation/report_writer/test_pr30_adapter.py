# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30E Report Writer evaluator adapter tests (RPT-E01..E13).

Deterministic and offline: the existing :class:`ReportWriterEvaluator` (the
semantic authority) is exercised through the thin PR 30 adapter over
in-memory scenarios, resolutions, and reports built from the committed
corpus. Proves PASS/FAIL mapping, bounded stable-code explanations,
diagnostics-only metrics (no threshold verdict), evaluator-exception ERROR,
and cancellation propagation. No LangSmith, LLM, or database participates.
"""

from __future__ import annotations

import asyncio
from uuid import UUID

import pytest

from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.report import (
    ReportNarrativeStatement,
    ReportResearchClaimSnapshot,
)
from agentic_threat_investigator.evaluation.analyst.models import (
    FixtureEntity,
    FixtureEvidence,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationCase,
    EvaluationContext,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationRunner,
    EvaluationTarget,
    EvaluationVerdict,
    evaluation_case_from,
)
from agentic_threat_investigator.evaluation.report_writer.evaluator import (
    ReportWriterEvaluator,
)
from agentic_threat_investigator.evaluation.report_writer.fixtures import (
    FixtureFinding,
    FixtureResearchCitation,
    FixtureResearchClaim,
    FixtureResearchResult,
    ReportWriterFixture,
    build_fixture_report_input,
    report_scenario_resolution,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ExpectedReportWriterOutput,
    ReportWriterEvaluationInput,
    ReportWriterScenario,
    ReportWriterScenarioResolution,
)
from agentic_threat_investigator.evaluation.report_writer.pr30 import (
    REPORT_WRITER_CONTRACT_EVALUATOR_ID,
    ReportWriterContractEvaluator,
)
from agentic_threat_investigator.evaluation.report_writer.target import (
    ReportWriterEvaluationOutput,
    ReportWriterScenarioLookup,
)
from tests.support.evaluation_common import unit_specification
from tests.support.report_writer_evaluation import (
    canonical_report,
    corpus_scenario,
    scenario_resolution,
)

S01 = "rpt-s01-clearly-malicious"
S06 = "rpt-s06-unsupported-reference"


def _dataset() -> EvaluationDatasetId:
    """Build the canonical report-writer/v1 dataset identity."""
    return EvaluationDatasetId(target=EvaluationTarget.REPORT_WRITER, version=1)


def _context(scenario: ReportWriterScenario) -> EvaluationContext:
    """Build the stable execution context for one scenario."""
    return EvaluationContext(dataset_id=_dataset().canonical, case_id=scenario.id)


def _output(
    scenario: ReportWriterScenario,
    resolution: ReportWriterScenarioResolution,
    evaluation_input: ReportWriterEvaluationInput,
) -> ReportWriterEvaluationOutput:
    """Build one typed evaluation output for the adapter."""
    del scenario
    return ReportWriterEvaluationOutput(
        resolution=resolution,
        evaluation_input=evaluation_input,
    )


def _adapter(
    scenarios: tuple[ReportWriterScenario, ...],
) -> ReportWriterContractEvaluator:
    """Build one adapter bound to a lookup over the given scenarios."""
    return ReportWriterContractEvaluator(
        scenario_lookup=ReportWriterScenarioLookup(scenarios),
        evaluator=ReportWriterEvaluator(),
    )


async def _evaluate(
    adapter: ReportWriterContractEvaluator,
    scenario: ReportWriterScenario,
    output: ReportWriterEvaluationOutput,
) -> EvaluationResult:
    """Evaluate one output through the adapter with a stable context."""
    return await adapter.evaluate(
        case=evaluation_case_from(scenario),
        output=output,
        context=_context(scenario),
    )


class TestExistingEvaluatorAuthority:
    """E01/E02/E08/E09/E11: the existing evaluator remains the authority."""

    @pytest.mark.asyncio
    async def test_e01_existing_evaluator_pass_is_completed_pass(self) -> None:
        """E01 a passing existing-evaluator decision is COMPLETED/PASS."""
        scenario = corpus_scenario(S01)
        resolution = scenario_resolution(scenario)
        report = canonical_report(scenario, resolution)
        adapter = _adapter((scenario,))
        result = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=report, llm_calls=1),
            ),
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS
        assert result.evaluator_id == REPORT_WRITER_CONTRACT_EVALUATOR_ID
        assert result.explanation

    @pytest.mark.asyncio
    async def test_e02_existing_evaluator_fail_is_completed_fail(self) -> None:
        """E02 a failing existing-evaluator decision is COMPLETED/FAIL."""
        scenario = corpus_scenario(S01)
        resolution = scenario_resolution(scenario)
        report = canonical_report(scenario, resolution).model_copy(
            update={"verdict": Verdict.INCONCLUSIVE}
        )
        adapter = _adapter((scenario,))
        result = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=report, llm_calls=1),
            ),
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.FAIL

    @pytest.mark.asyncio
    async def test_e08_verdict_mismatch_fails(self) -> None:
        """E08 a verdict mismatch through the existing evaluator is FAIL."""
        scenario = corpus_scenario(S01)
        resolution = scenario_resolution(scenario)
        report = canonical_report(scenario, resolution).model_copy(
            update={"verdict": Verdict.BENIGN}
        )
        adapter = _adapter((scenario,))
        result = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=report, llm_calls=1),
            ),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "verdict_mismatch" in result.explanation

    @pytest.mark.asyncio
    async def test_e09_missing_finding_fails(self) -> None:
        """E09 a report omitting a required finding is FAIL."""
        scenario = corpus_scenario(S01)
        resolution = scenario_resolution(scenario)
        report = canonical_report(scenario, resolution).model_copy(
            update={"findings": ()}
        )
        adapter = _adapter((scenario,))
        result = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=report, llm_calls=1),
            ),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "required_assessment_finding_missing" in result.explanation

    @pytest.mark.asyncio
    async def test_e11_phrase_envelope_violation_fails(self) -> None:
        """E11 a narrative phrase-envelope violation is FAIL."""
        scenario = corpus_scenario(S01)
        resolution = scenario_resolution(scenario)
        canonical = canonical_report(scenario, resolution)
        support = canonical.executive_summary[0].support
        report = canonical.model_copy(
            update={
                "executive_summary": (
                    ReportNarrativeStatement(text="unrelated prose", support=support),
                )
            }
        )
        adapter = _adapter((scenario,))
        result = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=report, llm_calls=1),
            ),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "report_statement_envelope_violation" in result.explanation


class TestFailureExplanationAndMetrics:
    """E03/E04/E05: bounded explanations and diagnostics-only metrics."""

    @pytest.mark.asyncio
    async def test_e03_explanation_bounded_stable_codes_only(self) -> None:
        """E03 the FAIL explanation carries bounded stable codes, never prose."""
        scenario = corpus_scenario(S01)
        resolution = scenario_resolution(scenario)
        report = canonical_report(scenario, resolution).model_copy(
            update={"verdict": Verdict.BENIGN}
        )
        adapter = _adapter((scenario,))
        result = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=report, llm_calls=1),
            ),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "verdict_mismatch" in result.explanation
        assert "malicious indicator" not in result.explanation
        assert len(result.explanation) <= 2000

    @pytest.mark.asyncio
    async def test_e04_metrics_diagnostics_only(self) -> None:
        """E04 diagnostics expose only the descriptive envelope measurements."""
        scenario = corpus_scenario(S01)
        resolution = scenario_resolution(scenario)
        report = canonical_report(scenario, resolution)
        adapter = _adapter((scenario,))
        result = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=report, llm_calls=1),
            ),
        )
        assert set(result.diagnostics) == {
            "narrative_statement_count",
            "included_finding_ordinals",
            "included_research_claim_count",
            "required_finding_coverage",
            "required_research_coverage",
        }
        assert result.diagnostics["included_finding_ordinals"] == [1]

    @pytest.mark.asyncio
    async def test_e05_metric_variation_never_changes_verdict(self) -> None:
        """E05 diagnostic metric variation alone never decides a verdict.

        Two reports that both satisfy the envelope (different narrative
        statement counts) both PASS; a coverage-reducing omission FAILs only
        through the deterministic missing-finding check, never a threshold.
        """
        scenario = corpus_scenario(S01)
        resolution = scenario_resolution(scenario)
        one = canonical_report(scenario, resolution)
        support = one.executive_summary[0].support
        two = one.model_copy(
            update={
                "executive_summary": (
                    one.executive_summary[0],
                    ReportNarrativeStatement(
                        text="malicious indicator with high confidence",
                        support=support,
                    ),
                )
            }
        )
        adapter = _adapter((scenario,))
        first = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=one, llm_calls=1),
            ),
        )
        second = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=two, llm_calls=1),
            ),
        )
        assert first.verdict is EvaluationVerdict.PASS
        assert second.verdict is EvaluationVerdict.PASS
        assert first.diagnostics["narrative_statement_count"] == 1
        assert second.diagnostics["narrative_statement_count"] == 2
        # Coverage-reducing omission FAILs through the structural check.
        omitted = one.model_copy(update={"findings": ()})
        failed = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=omitted, llm_calls=1),
            ),
        )
        assert failed.verdict is EvaluationVerdict.FAIL
        assert failed.diagnostics["required_finding_coverage"] == 0.0


class TestNoReportSemantics:
    """E12/E13: declared no-report outcomes are behavioral PASS/FAIL."""

    @pytest.mark.asyncio
    async def test_e12_expected_no_report_correct_code_passes(self) -> None:
        """E12 an expected no-report with the exact code is COMPLETED/PASS."""
        scenario = corpus_scenario(S06)
        resolution = scenario_resolution(scenario)
        adapter = _adapter((scenario,))
        result = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(
                    report=None,
                    execution_error_code="report_provenance_error",
                    llm_calls=1,
                ),
            ),
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS

    @pytest.mark.asyncio
    async def test_e13_expected_no_report_wrong_code_fails(self) -> None:
        """E13 an expected no-report with the wrong code is COMPLETED/FAIL."""
        scenario = corpus_scenario(S06)
        resolution = scenario_resolution(scenario)
        adapter = _adapter((scenario,))
        result = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(
                    report=None,
                    execution_error_code="stale_report_input",
                    llm_calls=1,
                ),
            ),
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.FAIL
        assert "report_structure_invalid" in result.explanation


class TestForbiddenResearchClaim:
    """E10: a forbidden research claim through the existing evaluator is FAIL.

    Uses a programmatic two-claim fixture so the forbidden claim label exists
    in the resolution universe (required to exercise the evaluator's
    forbidden-claim gate without tripping the unsupported-source hard gate).
    """

    @pytest.mark.asyncio
    async def test_e10_forbidden_research_claim_fails(self) -> None:
        """E10 a report including a forbidden research claim is FAIL."""
        entity = FixtureEntity(
            label="target_ip", type=EntityType.IP_ADDRESS, value="203.0.113.42"
        )
        evidence = FixtureEvidence(
            label="reputation_hit",
            type=EvidenceType.REPUTATION,
            subject="target_ip",
            source="urn:ati:source:abuseipdb",
            facts={"score": 90},
        )
        fixture = ReportWriterFixture(
            objective="Assess the root indicator.",
            root_entity="target_ip",
            entities=(entity,),
            evidence=(evidence,),
            verdict=Verdict.MALICIOUS,
            confidence=AssessmentConfidence.HIGH,
            findings=(
                FixtureFinding(
                    category=FindingCategory.REPUTATION,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="Reputation evidence indicates malicious activity.",
                    confidence=AssessmentConfidence.HIGH,
                    evidence_labels=("reputation_hit",),
                ),
            ),
            research_results=(
                FixtureResearchResult(
                    subject_label="target_ip",
                    query="context query",
                    claims=(
                        FixtureResearchClaim(
                            label="allowed_claim",
                            text="Allowed context claim.",
                            citation_labels=("citation_a",),
                        ),
                        FixtureResearchClaim(
                            label="forbidden_claim",
                            text="Forbidden context claim.",
                            citation_labels=("citation_b",),
                        ),
                    ),
                    citations=(
                        FixtureResearchCitation(
                            label="citation_a",
                            title="Allowed citation",
                            source_id="urn:ati:source:mitre_attack",
                            source_record_id="report--a",
                            text="Allowed citation text.",
                        ),
                        FixtureResearchCitation(
                            label="citation_b",
                            title="Forbidden citation",
                            source_id="urn:ati:source:mitre_attack",
                            source_record_id="report--b",
                            text="Forbidden citation text.",
                        ),
                    ),
                ),
            ),
        )
        scenario = ReportWriterScenario(
            id="unit-forbidden-claim",
            version=1,
            specification=unit_specification(target=EvaluationTarget.REPORT_WRITER),
            fixture="unit-forbidden-claim-fixture",
            expected=ExpectedReportWriterOutput(
                verdict=Verdict.MALICIOUS,
                confidence=AssessmentConfidence.HIGH,
                required_assessment_finding_ordinals=(1,),
                required_research_claim_labels=("allowed_claim",),
                forbidden_research_claim_labels=("forbidden_claim",),
            ),
        )
        resolution = report_scenario_resolution(scenario, fixture)
        report_input = build_fixture_report_input(fixture, resolution)
        result = report_input.research_results[0]
        snapshots = tuple(
            ReportResearchClaimSnapshot(
                research_result_id=result.id,
                research_claim_id=claim.id,
                subject_entity_id=result.subject_entity_id,
                claim_text=claim.text,
                citation_ids=claim.citation_ids,
                citations=tuple(
                    citation
                    for citation in result.citations
                    if citation.citation_id in claim.citation_ids
                ),
            )
            for claim in result.claims
        )
        from agentic_threat_investigator.app.report_writer.validator import (
            build_investigation_report,
        )
        from agentic_threat_investigator.evaluation.report_writer.fixtures import (
            build_canonical_report_output,
        )

        output = build_canonical_report_output(scenario, resolution, fixture)
        report = build_investigation_report(report_input, output).model_copy(
            update={"research_context": snapshots}
        )
        # Sanity: the report research context is provenance-valid (both
        # claims belong to the resolution universe).
        assert {snapshot.research_claim_id for snapshot in snapshots} == set(
            resolution.research_claim_ids.values()
        )
        adapter = _adapter((scenario,))
        outcome = await _evaluate(
            adapter,
            scenario,
            _output(
                scenario,
                resolution,
                ReportWriterEvaluationInput(report=report, llm_calls=1),
            ),
        )
        assert outcome.verdict is EvaluationVerdict.FAIL
        assert "forbidden_research_claim_included" in outcome.explanation


class TestAdapterErrorsAndCancellation:
    """E06/E07: adapter exceptions are ERROR and cancellation propagates."""

    @pytest.mark.asyncio
    async def test_e06_evaluator_exception_is_error(self) -> None:
        """E06 an existing-evaluator exception becomes ERROR (never FAIL)."""
        scenario = corpus_scenario(S01)

        class ExplodingEvaluator:
            """Existing-evaluator double that raises on evaluate."""

            def evaluate(self, **_kwargs: object) -> object:
                """Raise a runtime failure."""
                raise RuntimeError("evaluator exploded")

        adapter = ReportWriterContractEvaluator(
            scenario_lookup=ReportWriterScenarioLookup((scenario,)),
            evaluator=ExplodingEvaluator(),  # type: ignore[arg-type]
        )
        result = await EvaluationRunner().run(
            dataset_id=_dataset(),
            cases=(evaluation_case_from(scenario),),
            target=_TrivialTarget(),
            evaluators=(adapter,),  # type: ignore[arg-type]
        )
        case = result.cases[0]
        assert case.execution_status is EvaluationExecutionStatus.ERROR
        assert case.verdict is None

    @pytest.mark.asyncio
    async def test_e07_cancellation_propagates(self) -> None:
        """E07 asyncio.CancelledError propagates unchanged from the adapter."""
        scenario = corpus_scenario(S01)

        class CancellingEvaluator:
            """Existing-evaluator double that cancels."""

            def evaluate(self, **_kwargs: object) -> object:
                """Raise cancellation unchanged."""
                raise asyncio.CancelledError("cancelled")

        adapter = ReportWriterContractEvaluator(
            scenario_lookup=ReportWriterScenarioLookup((scenario,)),
            evaluator=CancellingEvaluator(),  # type: ignore[arg-type]
        )
        with pytest.raises(asyncio.CancelledError):
            await EvaluationRunner().run(
                dataset_id=_dataset(),
                cases=(evaluation_case_from(scenario),),
                target=_TrivialTarget(),
                evaluators=(adapter,),  # type: ignore[arg-type]
            )


class _TrivialTarget:
    """Target double returning an empty typed output for runner tests."""

    async def execute(
        self, *, case: EvaluationCase, context: EvaluationContext
    ) -> ReportWriterEvaluationOutput:
        """Return an empty output; the adapter never inspects it here."""
        del case, context
        return ReportWriterEvaluationOutput(
            resolution=_empty_resolution(),
            evaluation_input=ReportWriterEvaluationInput(report=None, llm_calls=0),
        )


def _empty_resolution() -> ReportWriterScenarioResolution:
    """Build an empty resolution for runner tests (never evaluated)."""
    return ReportWriterScenarioResolution(
        investigation_id=UUID(int=1),
        assessment_id=UUID(int=2),
    )
