# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30F end-to-end Investigation evaluation vertical slice (real PostgreSQL).

Executes the PR 30F end-to-end pipeline against real PostgreSQL + pgvector:

.. code-block:: text

    real investigation JSON scenarios
     -> strict typed loader
     -> repository-owned fixture world (strict catalog validation)
     -> run-scoped Investigation materialization (execution identity)
     -> production LocalInvestigationRunner (production Coordinator graph)
     -> production fixture providers/extraction/persistence
     -> production Evidence Analyst (FakeLlmClient only at the model boundary)
     -> production Research Agent where authorized (FakeLlmClient only)
     -> terminal durable InvestigationState
     -> final current Assessment (persistence)
     -> production ReportWriter after terminal state (FakeLlmClient only)
     -> persisted InvestigationReport
     -> authoritative durable snapshot + structured trajectory actions
     -> InvestigationEvaluator through the PR 30F adapter
     -> common EvaluationRunner

Covers I01..I11: canonical PASS worlds (malicious, benign, inconclusive,
conflicting, research-required, cycle/duplicate), a deliberate semantic FAIL
(structurally valid but scenario-wrong model output), an unexpected model
ERROR, a report-stage ERROR, cancellation propagation, rerun isolation, and a
full-corpus smoke. No live LLM or LangSmith participates.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.evidence_analyst.prompts import (
    OPERATION_EVIDENCE_ANALYSIS,
)
from agentic_threat_investigator.app.llm import (
    LlmClient,
    LlmError,
    LlmErrorCode,
    ResponseT,
)
from agentic_threat_investigator.app.orchestration.research import (
    RESEARCH_QUERY_TEMPLATE,
)
from agentic_threat_investigator.app.report_writer.prompts import (
    OPERATION_REPORT_WRITING,
)
from agentic_threat_investigator.app.research_agent.prompts import (
    OPERATION_RESEARCH_SYNTHESIS,
)
from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    RelationshipSupport,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    ReportNarrativeStatement,
    ReportResearchSelection,
    ReportWriterOutput,
    ResearchClaimRef,
)
from agentic_threat_investigator.domain.research import ResearchQuery
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationRunResult,
    EvaluationTarget,
    EvaluationVerdict,
)
from agentic_threat_investigator.evaluation.investigation.loader import (
    load_investigation_scenarios_directory,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    InvestigationScenario,
)
from agentic_threat_investigator.evaluation.investigation.run import (
    run_investigation_evaluation,
)
from agentic_threat_investigator.evaluation.research.composition import (
    REPOSITORY_RESEARCH_FIXTURES,
    bootstrap_research_corpus,
)
from agentic_threat_investigator.infrastructure.embeddings import (
    HashingEmbeddingClient,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)
from tests.support.llm_fixtures import FakeLlmCall, FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

SCENARIOS_DIRECTORY = Path("evals/scenarios/investigation")
DATASET_ID = EvaluationDatasetId(target=EvaluationTarget.INVESTIGATION, version=1)

UOW_FACTORY = Callable[[], PostgresUnitOfWork]

S01 = "inv-s01-malicious-multi-source"
S02 = "inv-s02-benign"
S03 = "inv-s03-inconclusive-sparse"
S04 = "inv-s04-conflicting-evidence"
S05 = "inv-s05-research-required"
S06 = "inv-s06-cycle-duplicate-bounded"

_ASSOCIATED_WITH = "urn:ati:relationship:threat:associated_with"


@dataclass(frozen=True)
class ScenarioScript:
    """Deterministic model-boundary script for one scenario world."""

    verdict: Verdict
    confidence: AssessmentConfidence
    needs_more_rounds: int
    malware: str | None = None
    findings: tuple[tuple[str, str, str], ...] = ()
    limitations: tuple[str, ...] = ()
    report_lm_error: LlmError | None = None


_SCRIPTS: dict[str, ScenarioScript] = {
    S01: ScenarioScript(
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        needs_more_rounds=3,
        malware="malware.badloader_v2",
        findings=(("reputation", "supporting", "evidence"),),
    ),
    S02: ScenarioScript(
        verdict=Verdict.BENIGN,
        confidence=AssessmentConfidence.MEDIUM,
        needs_more_rounds=2,
        findings=(("reputation", "contradicting", "evidence"),),
    ),
    S03: ScenarioScript(
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        needs_more_rounds=1,
        limitations=("sparse evidence does not support a confident verdict",),
    ),
    S04: ScenarioScript(
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        needs_more_rounds=1,
        malware="conflict-loader",
        findings=(
            ("association", "supporting", "relationship"),
            ("reputation", "contradicting", "evidence"),
        ),
    ),
    S05: ScenarioScript(
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        needs_more_rounds=1,
        malware="stealth-loader",
        findings=(("reputation", "supporting", "evidence"),),
    ),
    S06: ScenarioScript(
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        needs_more_rounds=2,
        findings=(("reputation", "supporting", "evidence"),),
    ),
}


def _evidence_id_by_type(prompt: str, evidence_type: str) -> UUID | None:
    """Extract the first exact evidence observation id of one evidence type.

    Parses the deterministic production analyst prompt format; never a probe
    and never production code.
    """
    for block in re.split(r"Evidence item \d+", prompt)[1:]:
        observation = re.search(r"evidence_observation_id: (\S+)", block)
        detected = re.search(r"type: (\S+)", block)
        if observation and detected and detected.group(1) == evidence_type:
            return UUID(observation.group(1))
    return None


def _relationship_id_by_type(prompt: str, relationship_type: str) -> UUID | None:
    """Extract the first exact relationship observation id of one type."""
    for block in re.split(r"Relationship observation \d+", prompt)[1:]:
        observation = re.search(r"relationship_observation_id: (\S+)", block)
        detected = re.search(r"relationship_type: (\S+)", block)
        if observation and detected and detected.group(1) == relationship_type:
            return UUID(observation.group(1))
    return None


def _analyst_decision(
    call: FakeLlmCall,
    script: ScenarioScript,
    queue: list[AnalysisDisposition],
) -> EvidenceAnalystDecision:
    """Build one scripted analysis decision for the exact analyst call.

    Findings cite the exact evidence/relationship observation identities the
    production analyst prompt supplied, so the provenance of the persisted
    Assessment always closes.
    """
    disposition = queue.pop(0) if queue else AnalysisDisposition.SUFFICIENT
    findings: list[AnalyticalFinding] = []
    for category, disposition_code, support_kind in script.findings:
        support: tuple[EvidenceSupport | RelationshipSupport, ...] = ()
        if support_kind == "evidence":
            evidence_id = _evidence_id_by_type(
                call.user_prompt, "urn:ati:evidence:reputation"
            )
            if evidence_id is not None:
                support = (EvidenceSupport(kind="evidence", evidence_id=evidence_id),)
        elif support_kind == "relationship":
            observation_id = _relationship_id_by_type(
                call.user_prompt, _ASSOCIATED_WITH
            )
            if observation_id is not None:
                support = (
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=observation_id,
                    ),
                )
        if support:
            findings.append(
                AnalyticalFinding(
                    category=FindingCategory(category),
                    disposition=FindingDisposition(disposition_code),
                    statement=f"Deterministic {category}:{disposition_code} finding.",
                    confidence=script.confidence,
                    support=support,
                )
            )
    return EvidenceAnalystDecision(
        verdict=script.verdict,
        confidence=script.confidence,
        summary="Deterministic end-to-end investigation analysis.",
        disposition=disposition,
        findings=tuple(findings),
        limitations=script.limitations,
    )


def _report_output_from_prompt(
    prompt: str, script: ScenarioScript, *, research_payload: bool
) -> ReportWriterOutput:
    """Build the deterministic report output from the exact report prompt.

    Derives the Assessment id and research claim identities from the stable
    production report prompt rendering; the report consumes the actual final
    Assessment/Research of the run.
    """
    assessment_match = re.search(r"assessment_id: (\S+)", prompt)
    if (
        assessment_match is None
    ):  # pragma: no cover - production prompt always renders it
        raise AssertionError("report prompt lacks an assessment identity")
    assessment_id = UUID(assessment_match.group(1))

    claim_pairs = re.findall(
        r"ResearchResult \d+ \[result_id (\S+)\].*?claim_id (\S+) \[label RC-",
        prompt,
        re.DOTALL,
    )
    selections = tuple(
        ReportResearchSelection(
            research_result_id=UUID(result_id), research_claim_id=UUID(claim_id)
        )
        for result_id, claim_id in claim_pairs[:1]
    )
    narrative: list[ReportNarrativeStatement] = []
    if script.findings:
        narrative.append(
            ReportNarrativeStatement(
                text="The first assessment finding supports the verdict.",
                support=(
                    AssessmentFindingRef(
                        kind="assessment_finding",
                        assessment_id=assessment_id,
                        finding_ordinal=1,
                    ),
                ),
            )
        )
    for selection in selections:
        narrative.append(
            ReportNarrativeStatement(
                text="The research context supports the assessment.",
                support=(
                    ResearchClaimRef(
                        kind="research_claim",
                        research_result_id=selection.research_result_id,
                        research_claim_id=selection.research_claim_id,
                    ),
                ),
            )
        )
    del research_payload
    return ReportWriterOutput(
        title="Deterministic investigation report",
        executive_summary=tuple(narrative),
        finding_order=(1,) if script.findings else (),
        research_context=selections,
    )


async def _primed_citation(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    malware: str,
    objective: str,
) -> UUID | None:
    """Pre-retrieve the exact planned malware research query's top chunk."""
    retriever = PgVectorResearchRetriever(session_factory, HashingEmbeddingClient())
    query = RESEARCH_QUERY_TEMPLATE.format(
        entity_type="malware", value=malware, objective=objective
    )
    chunks = await retriever.retrieve(
        ResearchQuery(investigation_id=uuid4(), query=query, max_results=8)
    )
    if not chunks:
        return None
    return chunks[0].citation_id


async def _scripted_llm(
    scenario: InvestigationScenario,
    session_factory: async_sessionmaker[AsyncSession],
    *,
    script_override: ScenarioScript | None = None,
    failing_analysis: bool = False,
) -> FakeLlmClient:
    """Build one scripted FakeLlmClient for a scenario world.

    The analyst queue drives the deterministic collection rounds; the
    research boundary pre-retrieves the exact planned query and cites the
    deterministic top chunk; the report boundary consumes the actual final
    Assessment/Research from the report prompt.
    """
    script = script_override or _SCRIPTS[scenario.id]
    llm = FakeLlmClient()
    queue = [AnalysisDisposition.NEEDS_MORE_EVIDENCE] * script.needs_more_rounds
    objective = (
        f"Execute investigation scenario {scenario.id} against the "
        "deterministic fixture world."
    )
    citation_id = (
        await _primed_citation(
            session_factory, malware=script.malware, objective=objective
        )
        if script.malware is not None
        else None
    )

    from pydantic import BaseModel

    def factory(call: FakeLlmCall) -> BaseModel | BaseException:
        if call.operation_name == OPERATION_EVIDENCE_ANALYSIS:
            if failing_analysis:
                raise LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False)
            return _analyst_decision(call, script, queue)
        if call.operation_name == OPERATION_RESEARCH_SYNTHESIS:
            if citation_id is None:
                return ResearchAgentDecision(claims=())
            return ResearchAgentDecision(
                claims=(
                    ResearchAgentClaim(
                        text="The malware family operates command-and-control infrastructure.",
                        citation_ids=(citation_id,),
                    ),
                )
            )
        if call.operation_name == OPERATION_REPORT_WRITING:
            if script.report_lm_error is not None:
                raise script.report_lm_error
            return _report_output_from_prompt(
                call.user_prompt,
                script,
                research_payload=citation_id is not None,
            )
        raise AssertionError(f"unexpected llm operation: {call.operation_name}")

    llm.set_response_factory(factory)
    return llm


async def _bootstrapped(uow_factory: UOW_FACTORY, tmp_path: Path) -> None:
    """Ingest and index the deterministic research corpus into tmp storage."""
    await bootstrap_research_corpus(
        uow_factory=uow_factory,
        data_dir=tmp_path,
        fixture_files=(REPOSITORY_RESEARCH_FIXTURES["mitre-attack-small"],),
    )


def _scenario(scenario_id: str) -> InvestigationScenario:
    """Return one exact typed scenario from the corpus."""
    return next(
        scenario
        for scenario in load_investigation_scenarios_directory(SCENARIOS_DIRECTORY)
        if scenario.id == scenario_id
    )


def _diag_int(diagnostics: Mapping[str, object], key: str) -> int:
    """Return one int-typed evaluator diagnostic value."""
    value = diagnostics[key]
    assert isinstance(value, int), f"diagnostic {key!r} is not an int: {value!r}"
    return value


async def _run_case(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    scenario: InvestigationScenario,
    *,
    llm: LlmClient | None = None,
    script_override: ScenarioScript | None = None,
    failing_analysis: bool = False,
) -> EvaluationRunResult:
    """Run one scenario through the full PR 30F pipeline."""
    if llm is None:
        llm = await _scripted_llm(
            scenario,
            session_factory,
            script_override=script_override,
            failing_analysis=failing_analysis,
        )
    return await run_investigation_evaluation(
        dataset_id=DATASET_ID,
        llm=llm,
        uow_factory=uow_factory,
        session_factory=session_factory,
        scenarios=(scenario,),
        recursion_limit=120,
    )


async def _pass_for(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    scenario_id: str,
    *,
    script_override: ScenarioScript | None = None,
) -> EvaluationRunResult:
    """Run one scenario and assert a COMPLETED/PASS verdict."""
    result = await _run_case(
        uow_factory,
        session_factory,
        _scenario(scenario_id),
        script_override=script_override,
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.PASS, (
        scenario_id,
        [result.cases[0].evaluator_results[0].explanation],
    )
    return result


async def test_i01_malicious_multi_source_passes(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I01 canonical malicious multi-source world completes PASS."""
    await _bootstrapped(uow_factory, tmp_path)
    result = await _pass_for(uow_factory, session_factory, S01)
    diagnostics = result.cases[0].evaluator_results[0].diagnostics
    assert _diag_int(diagnostics, "duplicate_provider_calls") == 0
    assert _diag_int(diagnostics, "duplicate_entity_investigations") == 0
    assert _diag_int(diagnostics, "research_calls") >= 1
    assert _diag_int(diagnostics, "report_calls") == 1


async def test_i02_benign_passes(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I02 benign world reaches an honest benign verdict with a report."""
    await _bootstrapped(uow_factory, tmp_path)
    await _pass_for(uow_factory, session_factory, S02)


async def test_i03_inconclusive_sparse_passes(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I03 sparse evidence preserves uncertainty and the report limitation."""
    await _bootstrapped(uow_factory, tmp_path)
    result = await _pass_for(uow_factory, session_factory, S03)
    assert _diag_int(result.cases[0].evaluator_results[0].diagnostics, "llm_calls") >= 1


async def test_i04_conflicting_evidence_passes(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I04 conflicting evidence keeps the disagreement visible."""
    await _bootstrapped(uow_factory, tmp_path)
    await _pass_for(uow_factory, session_factory, S04)


async def test_i05_research_required_passes(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I05 malware research executes with citation closure and report context."""
    await _bootstrapped(uow_factory, tmp_path)
    result = await _pass_for(uow_factory, session_factory, S05)
    diagnostics = result.cases[0].evaluator_results[0].diagnostics
    assert _diag_int(diagnostics, "research_calls") >= 1


async def test_i06_cycle_duplicate_bounded_passes(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I06 shared infrastructure never re-executes duplicates and terminates."""
    await _bootstrapped(uow_factory, tmp_path)
    result = await _pass_for(uow_factory, session_factory, S06)
    diagnostics = result.cases[0].evaluator_results[0].diagnostics
    assert _diag_int(diagnostics, "duplicate_provider_calls") == 0
    assert _diag_int(diagnostics, "duplicate_entity_investigations") == 0
    assert _diag_int(diagnostics, "maximum_depth_observed") <= 2


async def test_i07_semantic_fail_completes_with_fail(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I07 scenario-wrong model output is a deterministic COMPLETED/FAIL.

    The world completes with structurally valid output whose final Assessment
    contradicts the authored expectation (benign instead of malicious).
    """
    await _bootstrapped(uow_factory, tmp_path)
    result = await _run_case(
        uow_factory,
        session_factory,
        _scenario(S01),
        script_override=ScenarioScript(
            verdict=Verdict.BENIGN,
            confidence=AssessmentConfidence.HIGH,
            needs_more_rounds=3,
            malware="malware.badloader_v2",
            findings=(("reputation", "supporting", "evidence"),),
        ),
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.FAIL
    explanation = result.cases[0].evaluator_results[0].explanation
    assert "assessment_verdict_mismatch" in explanation


async def test_i08_unexpected_model_error_is_error(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I08 an unexpected model failure is case ERROR (never FAIL)."""
    await _bootstrapped(uow_factory, tmp_path)
    result = await _run_case(
        uow_factory,
        session_factory,
        _scenario(S01),
        failing_analysis=True,
    )
    assert result.execution_status is EvaluationExecutionStatus.ERROR
    assert result.verdict is None


async def test_i09_report_stage_error_is_error(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I09 a Report Writer failure after a completed investigation is ERROR."""
    await _bootstrapped(uow_factory, tmp_path)
    result = await _run_case(
        uow_factory,
        session_factory,
        _scenario(S02),
        script_override=ScenarioScript(
            verdict=Verdict.BENIGN,
            confidence=AssessmentConfidence.MEDIUM,
            needs_more_rounds=2,
            findings=(("reputation", "contradicting", "evidence"),),
            report_lm_error=LlmError(
                LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False
            ),
        ),
    )
    assert result.execution_status is EvaluationExecutionStatus.ERROR
    assert result.verdict is None


class BlockingCancellableClient(FakeLlmClient):
    """Deterministic sleep-free cancellation at the model boundary.

    Blocks the first model invocation on an asyncio Event so the outer task
    can be cancelled deterministically; ``CancelledError`` then propagates
    unchanged through the graph, runner, and common runner.
    """

    def __init__(self) -> None:
        """Initialize the entered/release events."""
        super().__init__()
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Block deterministically until the test cancels the outer task."""
        self.entered.set()
        await self.release.wait()
        return await super().generate_structured(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            operation_name=operation_name,
        )


async def test_i10_cancellation_propagates(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I10 cancellation propagates unchanged through the end-to-end path."""
    await _bootstrapped(uow_factory, tmp_path)
    llm = BlockingCancellableClient()
    task = asyncio.create_task(
        _run_case(uow_factory, session_factory, _scenario(S02), llm=llm)
    )
    await llm.entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_i11_rerun_isolation(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I11 rerunning one scenario creates isolated worlds without cleanup.

    Two executions of the benign scenario produce distinct Investigation and
    report identities; the first world stays untouched (no destructive
    cleanup).
    """
    await _bootstrapped(uow_factory, tmp_path)
    first = await _run_case(uow_factory, session_factory, _scenario(S02))
    second = await _run_case(uow_factory, session_factory, _scenario(S02))
    assert first.verdict is EvaluationVerdict.PASS
    assert second.verdict is EvaluationVerdict.PASS
    investigation_ids = await _durable_investigation_ids(uow_factory)
    assert len(investigation_ids) >= 2


async def _durable_investigation_ids(uow_factory: UOW_FACTORY) -> list[UUID]:
    """Return the durable Investigation identities of the benchmark worlds."""
    async with uow_factory() as uow:
        assert uow.session is not None
        result = await uow.session.execute(
            text(
                "SELECT id FROM ati.investigation "
                "WHERE objective LIKE 'Execute investigation scenario %' "
                "ORDER BY started_at"
            )
        )
        return [UUID(str(row[0])) for row in result.fetchall()]


async def test_full_corpus_smoke_never_crashes(
    uow_factory: UOW_FACTORY,
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """Every corpus scenario executes; each reports PASS/FAIL/ERROR."""
    await _bootstrapped(uow_factory, tmp_path)
    scenarios = load_investigation_scenarios_directory(SCENARIOS_DIRECTORY)
    for scenario in scenarios:
        result = await _run_case(uow_factory, session_factory, scenario)
        assert result.execution_status in {
            EvaluationExecutionStatus.COMPLETED,
            EvaluationExecutionStatus.ERROR,
        }
        assert len(result.cases) == 1
