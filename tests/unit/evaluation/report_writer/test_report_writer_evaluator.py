# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the deterministic Report Writer evaluator (PR 23B).

The evaluator is exercised against the repository scenario corpus with the
canonical fixture materialization (in-memory resolutions) and the canonical
output builder, so scenario expectations and the evaluator can never drift.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from agentic_threat_investigator.domain.report import (
    ReportResearchClaimSnapshot,
    ReportWriterInput,
)
from agentic_threat_investigator.evaluation.report_writer.evaluator import (
    ReportWriterEvaluator,
)
from agentic_threat_investigator.evaluation.report_writer.loader import (
    load_report_writer_scenarios_directory,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ReportWriterEvaluationInput,
    ReportWriterEvaluationResult,
    ReportWriterFailureCode,
    ReportWriterScenario,
    ReportWriterScenarioResolution,
)
from tests.support.report_writer_fixtures import (
    ReportWriterFixture,
    build_canonical_report_output,
    report_scenario_resolution,
)
from tests.support.report_writer_scenarios import report_writer_fixture

_CORPUS = Path(__file__).parents[4] / "evals/scenarios/report_writer"


def _scenarios() -> dict[str, ReportWriterScenario]:
    """Load the repository corpus into a stable id-keyed map."""
    return {
        scenario.id: scenario
        for scenario in load_report_writer_scenarios_directory(_CORPUS)
    }


def _resolution(scenario: ReportWriterScenario) -> ReportWriterScenarioResolution:
    """Return the planned in-memory resolution for one scenario."""
    return report_scenario_resolution(scenario, report_writer_fixture(scenario.fixture))


def _evaluate(
    scenario: ReportWriterScenario, evaluation_input: ReportWriterEvaluationInput
) -> ReportWriterEvaluationResult:
    """Evaluate one scenario and return the immutable result."""
    return ReportWriterEvaluator().evaluate(
        scenario, _resolution(scenario), evaluation_input
    )


def test_s01_malicious_passes_with_canonical_output() -> None:
    """RPT-S01: the canonical malicious output passes the envelope."""
    scenario = _scenarios()["rpt-s01-clearly-malicious"]
    fixture = report_writer_fixture(scenario.fixture)
    resolution = _resolution(scenario)
    output = build_canonical_report_output(scenario, resolution, fixture)
    # Build the report through the real application assembly path.
    from agentic_threat_investigator.app.report_writer.validator import (
        build_investigation_report,
    )

    report = build_investigation_report(_input(resolution, fixture), output)
    result = _evaluate(
        scenario, ReportWriterEvaluationInput(report=report, llm_calls=1)
    )
    assert result.passed, result.failures
    assert result.metrics.narrative_statement_count == 1
    assert result.metrics.required_finding_coverage == 1.0


def test_s02_inconclusive_passes() -> None:
    """RPT-S02: the inconclusive report preserves caveats and no verdict drift."""
    scenario = _scenarios()["rpt-s02-inconclusive-sparse"]
    fixture = report_writer_fixture(scenario.fixture)
    resolution = _resolution(scenario)
    output = build_canonical_report_output(scenario, resolution, fixture)
    from agentic_threat_investigator.app.report_writer.validator import (
        build_investigation_report,
    )

    report = build_investigation_report(_input(resolution, fixture), output)
    result = _evaluate(
        scenario, ReportWriterEvaluationInput(report=report, llm_calls=1)
    )
    assert result.passed, result.failures
    assert report.verdict.value == "inconclusive"
    assert report.findings == ()


def test_s03_conflicting_passes() -> None:
    """RPT-S03: both conflicting findings are represented."""
    scenario = _scenarios()["rpt-s03-conflicting-evidence"]
    fixture = report_writer_fixture(scenario.fixture)
    resolution = _resolution(scenario)
    output = build_canonical_report_output(scenario, resolution, fixture)
    from agentic_threat_investigator.app.report_writer.validator import (
        build_investigation_report,
    )

    report = build_investigation_report(_input(resolution, fixture), output)
    result = _evaluate(
        scenario, ReportWriterEvaluationInput(report=report, llm_calls=1)
    )
    assert result.passed, result.failures
    assert [f.assessment_finding_ordinal for f in report.findings] == [1, 2]


def test_s06_unsupported_reference_no_report_passes() -> None:
    """RPT-S06: the unsupported-reference failure passes the no-report envelope."""
    scenario = _scenarios()["rpt-s06-unsupported-reference"]
    result = _evaluate(
        scenario,
        ReportWriterEvaluationInput(
            report=None,
            execution_error_code="report_provenance_error",
            llm_calls=1,
        ),
    )
    assert result.passed, result.failures


def test_s06_wrong_error_code_fails() -> None:
    """RPT-S06: a mismatched execution error code fails structurally."""
    scenario = _scenarios()["rpt-s06-unsupported-reference"]
    result = _evaluate(
        scenario,
        ReportWriterEvaluationInput(
            report=None,
            execution_error_code="something_else",
            llm_calls=1,
        ),
    )
    assert not result.passed
    assert ReportWriterFailureCode.REPORT_STRUCTURE_INVALID in result.failures


def test_s07_verdict_override_no_report_passes() -> None:
    """RPT-S07: the verdict-override rejection passes the no-report envelope."""
    scenario = _scenarios()["rpt-s07-verdict-override-attempt"]
    result = _evaluate(
        scenario,
        ReportWriterEvaluationInput(
            report=None,
            execution_error_code="invalid_structured_output",
            llm_calls=2,
        ),
    )
    assert result.passed, result.failures


def test_s08_stale_race_no_report_passes() -> None:
    """RPT-S08: the stale Assessment race passes the no-report envelope."""
    scenario = _scenarios()["rpt-s08-stale-assessment-race"]
    result = _evaluate(
        scenario,
        ReportWriterEvaluationInput(
            report=None,
            execution_error_code="stale_report_input",
            llm_calls=1,
        ),
    )
    assert result.passed, result.failures


def test_verdict_mismatch_detected() -> None:
    """A wrong persisted verdict is detected as a hard gate."""
    scenario = _scenarios()["rpt-s05-no-research"]
    fixture = report_writer_fixture(scenario.fixture)
    resolution = _resolution(scenario)
    output = build_canonical_report_output(scenario, resolution, fixture)
    from agentic_threat_investigator.app.report_writer.validator import (
        build_investigation_report,
    )

    report = build_investigation_report(_input(resolution, fixture), output)
    report = report.model_copy(update={"verdict": "suspicious"})
    result = _evaluate(
        scenario, ReportWriterEvaluationInput(report=report, llm_calls=1)
    )
    assert not result.passed
    assert ReportWriterFailureCode.VERDICT_MISMATCH in result.failures


def test_required_finding_missing_detected() -> None:
    """A missing required finding is detected."""
    scenario = _scenarios()["rpt-s03-conflicting-evidence"]
    fixture = report_writer_fixture(scenario.fixture)
    resolution = _resolution(scenario)
    output = build_canonical_report_output(scenario, resolution, fixture)
    from agentic_threat_investigator.app.report_writer.validator import (
        build_investigation_report,
    )

    report = build_investigation_report(_input(resolution, fixture), output)
    report = report.model_copy(update={"findings": (report.findings[0],)})
    result = _evaluate(
        scenario, ReportWriterEvaluationInput(report=report, llm_calls=1)
    )
    assert not result.passed
    assert (
        ReportWriterFailureCode.REQUIRED_ASSESSMENT_FINDING_MISSING in result.failures
    )


def test_unsupported_research_reference_detected() -> None:
    """Research beyond the declared claim universe is detected."""
    scenario = _scenarios()["rpt-s05-no-research"]
    fixture = report_writer_fixture(scenario.fixture)
    resolution = _resolution(scenario)
    output = build_canonical_report_output(scenario, resolution, fixture)

    from agentic_threat_investigator.app.report_writer.validator import (
        build_investigation_report,
    )

    report = build_investigation_report(_input(resolution, fixture), output)
    report = report.model_copy(
        update={"research_context": (_stray_snapshot(resolution.investigation_id),)}
    )
    result = _evaluate(
        scenario, ReportWriterEvaluationInput(report=report, llm_calls=1)
    )
    assert not result.passed
    assert ReportWriterFailureCode.UNSUPPORTED_SOURCE_REFERENCE in result.failures


def test_forbidden_phrase_detected() -> None:
    """A forbidden canonical phrase is detected in the narrative envelope."""
    scenario = _scenarios()["rpt-s02-inconclusive-sparse"]
    fixture = report_writer_fixture(scenario.fixture)
    resolution = _resolution(scenario)
    output = build_canonical_report_output(scenario, resolution, fixture)
    from agentic_threat_investigator.app.report_writer.validator import (
        build_investigation_report,
    )

    report = build_investigation_report(_input(resolution, fixture), output)
    # The builder produces no statements for S02; inject a forbidden phrase.
    from agentic_threat_investigator.domain.report import (
        AssessmentFindingRef,
        ReportNarrativeStatement,
    )

    report = report.model_copy(
        update={
            "executive_summary": (
                ReportNarrativeStatement(
                    text="The indicator is benign.",
                    support=(
                        AssessmentFindingRef(
                            kind="assessment_finding",
                            assessment_id=resolution.assessment_id,
                            finding_ordinal=1,
                        ),
                    ),
                ),
            )
        }
    )
    result = _evaluate(
        scenario, ReportWriterEvaluationInput(report=report, llm_calls=1)
    )
    assert not result.passed
    assert (
        ReportWriterFailureCode.REPORT_STATEMENT_ENVELOPE_VIOLATION in result.failures
    )


def _input(
    resolution: ReportWriterScenarioResolution, fixture: ReportWriterFixture
) -> ReportWriterInput:
    """Build the in-memory report input for one resolution.

    Uses the planned identities and the fixture's authoritative Assessment
    content without a database.
    """
    from agentic_threat_investigator.domain.assessment import (
        AnalyticalFinding,
        Assessment,
        EvidenceSupport,
    )
    from agentic_threat_investigator.domain.report import ReportWriterInput
    from agentic_threat_investigator.domain.research import (
        ResearchCitation,
        ResearchClaim,
        ResearchResult,
    )

    findings: list[AnalyticalFinding] = []
    for finding in fixture.findings:
        support = tuple(
            EvidenceSupport(
                kind="evidence",
                evidence_id=resolution.evidence_ids[label],
            )
            for label in finding.evidence_labels
        )
        findings.append(
            AnalyticalFinding(
                category=finding.category,
                disposition=finding.disposition,
                statement=finding.statement,
                confidence=finding.confidence,
                support=support,
            )
        )
    assessment = Assessment(
        id=resolution.assessment_id,
        investigation_id=resolution.investigation_id,
        verdict=fixture.verdict,
        confidence=fixture.confidence,
        summary=fixture.summary,
        analyzed_evidence_ids=tuple(resolution.evidence_ids.values()),
        findings=tuple(findings),
        limitations=fixture.limitations,
        unresolved_questions=fixture.unresolved_questions,
        recommended_next_steps=fixture.recommended_next_steps,
    )
    research_results: tuple[ResearchResult, ...] = ()
    if resolution.research_claim_ids:
        result_id = next(iter(resolution.research_result_ids.values()))
        claim_id = next(iter(resolution.research_claim_ids.values()))
        citation_id = (
            next(iter(resolution.citation_ids.values()))
            if resolution.citation_ids
            else None
        )
        citation = (
            ResearchCitation(
                citation_id=citation_id,
                document_id=uuid4(),
                source_id="urn:ati:source:mitre_attack",
                source_record_id="report--x",
                document_type="test",
                chunk_sequence=1,
                text="citation text",
                title="title",
            )
            if citation_id
            else None
        )
        research_results = (
            ResearchResult(
                id=result_id,
                investigation_id=resolution.investigation_id,
                subject_entity_id=next(iter(resolution.entity_ids.values())),
                query="context query",
                claims=(
                    ResearchClaim(
                        id=claim_id,
                        text="context claim",
                        citation_ids=(citation_id,) if citation_id else (),
                    ),
                ),
                citations=(citation,) if citation else (),
                created_at=datetime(2026, 1, 2, tzinfo=UTC),
            ),
        )
    return ReportWriterInput(
        investigation_id=resolution.investigation_id,
        objective="Assess the root indicator.",
        assessment=assessment,
        research_results=research_results,
    )


def _stray_snapshot(investigation_id: UUID) -> ReportResearchClaimSnapshot:
    """Build a research snapshot outside the declared claim universe."""
    from agentic_threat_investigator.domain.report import ReportResearchClaimSnapshot

    return ReportResearchClaimSnapshot(
        research_result_id=uuid4(),
        research_claim_id=uuid4(),
        subject_entity_id=investigation_id,
        claim_text="stray claim",
        citation_ids=(),
        citations=(),
    )
