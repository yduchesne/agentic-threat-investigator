# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical PR 23B Report Writer evaluation slices (RPT-S01..S08).

Exercises the delivered PR 23B path — persisted Investigation/Evidence/
Assessment/ResearchResult, production ReportWriterInputLoader, deterministic
prompts, FakeLlmClient at the model boundary only, production Report Writer
service, provenance validation, report persistence — and evaluates the
outcome with the repository-owned deterministic evaluator against the
scenario corpus. Scenarios that must fail before persistence (unsupported
references, verdict-override attempts, stale Assessment races) are asserted
through safe execution metadata; no report row may exist.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.persistence.repositories import (
    StaleReportInputError,
)
from agentic_threat_investigator.app.report_writer.errors import (
    ReportProvenanceError,
)
from agentic_threat_investigator.app.report_writer.input_loader import (
    ReportWriterInputLoader,
)
from agentic_threat_investigator.app.report_writer.persistence import (
    InvestigationReportPersistenceService,
)
from agentic_threat_investigator.app.report_writer.validator import (
    build_investigation_report,
)
from agentic_threat_investigator.domain.report import (
    InvestigationReport,
    ReportResearchSelection,
    ReportWriterOutput,
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
    ReportWriterScenario,
    ReportWriterScenarioResolution,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.report_writer_composition import (
    build_report_writer,
)
from tests.support.llm_fixtures import FakeLlmClient
from tests.support.report_writer_fixtures import (
    ReportWriterFixture,
    ReportWriterScenarioMaterializer,
    build_canonical_report_output,
)
from tests.support.report_writer_scenarios import report_writer_fixture

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

UOW_FACTORY = Callable[[], PostgresUnitOfWork]

_CORPUS = "evals/scenarios/report_writer"


def _scenario(scenario_id: str) -> ReportWriterScenario:
    """Load one scenario from the canonical corpus."""
    return next(
        scenario
        for scenario in load_report_writer_scenarios_directory(_CORPUS)
        if scenario.id == scenario_id
    )


async def _materialize(
    uow_factory: UOW_FACTORY, scenario_id: str
) -> tuple[ReportWriterScenario, ReportWriterFixture, ReportWriterScenarioResolution]:
    """Materialize one scenario fixture and return its resolution."""
    scenario = _scenario(scenario_id)
    fixture = report_writer_fixture(scenario.fixture)
    resolution = await ReportWriterScenarioMaterializer(uow_factory).materialize(
        scenario, fixture
    )
    return scenario, fixture, resolution


async def _run_and_evaluate(
    uow_factory: UOW_FACTORY,
    scenario: ReportWriterScenario,
    fixture: ReportWriterFixture,
    resolution: ReportWriterScenarioResolution,
    *,
    output: ReportWriterOutput | None = None,
    llm_failures: list[BaseException] | None = None,
    pre_persist_report: InvestigationReport | None = None,
) -> tuple[
    ReportWriterEvaluationResult,
    InvestigationReport | None,
    str | None,
    ReportWriterScenarioResolution,
]:
    """Run the scenario path and evaluate the outcome."""
    fake_llm = FakeLlmClient()
    if output is not None:
        fake_llm.set_default(output)
    for llm_failure in llm_failures or ():
        fake_llm.enqueue(llm_failure)
    writer = build_report_writer(uow_factory=uow_factory, llm_client=fake_llm)

    report: InvestigationReport | None = None
    error_code: str | None = None
    try:
        if pre_persist_report is not None:
            await InvestigationReportPersistenceService(uow_factory).persist(
                pre_persist_report
            )
        else:
            report = await writer.write(resolution.investigation_id)
    except ReportProvenanceError as error:
        error_code = "report_provenance_error"
        del error
    except LlmError as error:
        error_code = "invalid_structured_output"
        del error
    except StaleReportInputError:
        error_code = "stale_report_input"
    except LookupError as error:
        if "stale" in str(error).lower():
            error_code = "stale_report_input"
        else:
            raise
    except ValueError as error:
        if "stale" in str(error).lower():
            error_code = "stale_report_input"
        else:
            raise

    result = ReportWriterEvaluator().evaluate(
        scenario,
        resolution,
        ReportWriterEvaluationInput(
            report=report,
            execution_error_code=error_code,
            llm_calls=len(fake_llm.calls),
        ),
    )
    return result, report, error_code, resolution


async def _assert_no_report_rows(
    uow_factory: UOW_FACTORY,
    resolution: ReportWriterScenarioResolution,
) -> None:
    """Assert no report row or pointer exists for the investigation."""
    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(resolution.investigation_id)
        assert state is not None
        assert state.report_id is None
        assert uow.session is not None
        from sqlalchemy import text

        result = await uow.session.execute(
            text(
                "SELECT count(*) FROM ati.investigation_report "
                "WHERE investigation_id = :investigation_id"
            ),
            {"investigation_id": resolution.investigation_id},
        )
        assert result.scalar_one() == 0


async def test_rpt_s01_malicious(uow_factory: UOW_FACTORY) -> None:
    """RPT-S01: clearly malicious passes the envelope."""
    scenario, fixture, resolution = await _materialize(
        uow_factory, "rpt-s01-clearly-malicious"
    )
    result, report, _error, _resolution = await _run_and_evaluate(
        uow_factory,
        scenario,
        fixture,
        resolution,
        output=build_canonical_report_output(scenario, resolution, fixture),
    )
    assert result.passed, result.failures
    assert report is not None
    assert report.verdict is fixture.verdict
    assert report.confidence is fixture.confidence


async def test_rpt_s02_inconclusive(uow_factory: UOW_FACTORY) -> None:
    """RPT-S02: inconclusive/sparse passes with caveats preserved."""
    scenario, _fixture, resolution = await _materialize(
        uow_factory, "rpt-s02-inconclusive-sparse"
    )
    fixture = report_writer_fixture(scenario.fixture)
    result, report, _error, _resolution = await _run_and_evaluate(
        uow_factory,
        scenario,
        fixture,
        resolution,
        output=build_canonical_report_output(scenario, resolution, fixture),
    )
    assert result.passed, result.failures
    assert report is not None
    assert report.verdict.value == "inconclusive"
    assert report.limitations == fixture.limitations


async def test_rpt_s03_conflicting(uow_factory: UOW_FACTORY) -> None:
    """RPT-S03: conflicting evidence preserves both sides."""
    scenario, fixture, resolution = await _materialize(
        uow_factory, "rpt-s03-conflicting-evidence"
    )
    result, report, _error, _resolution = await _run_and_evaluate(
        uow_factory,
        scenario,
        fixture,
        resolution,
        output=build_canonical_report_output(scenario, resolution, fixture),
    )
    assert result.passed, result.failures
    assert report is not None
    assert [f.assessment_finding_ordinal for f in report.findings] == [1, 2]


async def test_rpt_s04_research_is_context(uow_factory: UOW_FACTORY) -> None:
    """RPT-S04: research remains context, never a finding or verdict source."""
    scenario, fixture, resolution = await _materialize(
        uow_factory, "rpt-s04-research-is-context"
    )
    result, report, _error, _resolution = await _run_and_evaluate(
        uow_factory,
        scenario,
        fixture,
        resolution,
        output=build_canonical_report_output(scenario, resolution, fixture),
    )
    assert result.passed, result.failures
    assert report is not None
    assert report.verdict.value == "suspicious"
    assert len(report.findings) == 1
    assert len(report.research_context) == 1


async def test_rpt_s05_no_research(uow_factory: UOW_FACTORY) -> None:
    """RPT-S05: a valid report with no research context is produced."""
    scenario, fixture, resolution = await _materialize(
        uow_factory, "rpt-s05-no-research"
    )
    result, report, _error, _resolution = await _run_and_evaluate(
        uow_factory,
        scenario,
        fixture,
        resolution,
        output=build_canonical_report_output(scenario, resolution, fixture),
    )
    assert result.passed, result.failures
    assert report is not None
    assert report.research_context == ()


async def test_rpt_s06_unsupported_reference(uow_factory: UOW_FACTORY) -> None:
    """RPT-S06: an unsupported reference fails validation, no report persists."""
    scenario, fixture, resolution = await _materialize(
        uow_factory, "rpt-s06-unsupported-reference"
    )
    unsupported = build_canonical_report_output(scenario, resolution, fixture)
    # Inject a research selection that was never supplied (the fixture has
    # no ResearchResults at all).
    unsupported = unsupported.model_copy(
        update={
            "research_context": (
                ReportResearchSelection(
                    research_result_id=uuid4(), research_claim_id=uuid4()
                ),
            )
        }
    )
    result, report, error_code, resolution = await _run_and_evaluate(
        uow_factory,
        scenario,
        fixture,
        resolution,
        output=unsupported,
    )
    assert result.passed, result.failures
    assert report is None
    assert error_code == "report_provenance_error"
    await _assert_no_report_rows(uow_factory, resolution)


async def test_rpt_s07_verdict_override_attempt(uow_factory: UOW_FACTORY) -> None:
    """RPT-S07: verdict/confidence cannot be authored; provider rejection passes."""
    scenario, fixture, resolution = await _materialize(
        uow_factory, "rpt-s07-verdict-override-attempt"
    )
    result, report, error_code, resolution = await _run_and_evaluate(
        uow_factory,
        scenario,
        fixture,
        resolution,
        llm_failures=[
            LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True),
            LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True),
        ],
    )
    assert result.passed, result.failures
    assert report is None
    assert error_code == "invalid_structured_output"
    await _assert_no_report_rows(uow_factory, resolution)


async def test_rpt_s08_stale_assessment_race(uow_factory: UOW_FACTORY) -> None:
    """RPT-S08: materializing against A then advancing to B fails atomically."""
    scenario, fixture, resolution = await _materialize(
        uow_factory, "rpt-s08-stale-assessment-race"
    )
    # Materialize the report input against the still-current Assessment A.
    loader = ReportWriterInputLoader(uow_factory)
    report_input = await loader.load(resolution.investigation_id)
    output = build_canonical_report_output(scenario, resolution, fixture)
    report = build_investigation_report(report_input, output)
    # Advance the Investigation to Assessment B.
    evidence_id = resolution.evidence_ids["reputation_hit"]
    await _second_assessment(uow_factory, resolution, evidence_id)
    # Persisting the A-based report must now fail typed with no side effects.
    result, _report, error_code, resolution = await _run_and_evaluate(
        uow_factory,
        scenario,
        fixture,
        resolution,
        pre_persist_report=report,
    )
    assert result.passed, result.failures
    assert error_code == "stale_report_input"
    await _assert_no_report_rows(uow_factory, resolution)


async def _second_assessment(
    uow_factory: UOW_FACTORY,
    resolution: ReportWriterScenarioResolution,
    evidence_id: UUID,
) -> object:
    """Build and persist Assessment B for the stale-race scenario."""
    from agentic_threat_investigator.domain.assessment import (
        AnalyticalFinding,
        Assessment,
        AssessmentConfidence,
        EvidenceSupport,
        FindingCategory,
        FindingDisposition,
        Verdict,
    )

    assessment_b = Assessment(
        investigation_id=resolution.investigation_id,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Second assessment summary.",
        analyzed_evidence_ids=(evidence_id,),
        findings=(
            AnalyticalFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="Updated analytical statement.",
                confidence=AssessmentConfidence.MEDIUM,
                support=(EvidenceSupport(kind="evidence", evidence_id=evidence_id),),
            ),
        ),
        limitations=("a second limitation",),
    )
    return await AssessmentPersistenceService(uow_factory).persist_assessment(
        assessment_b
    )
