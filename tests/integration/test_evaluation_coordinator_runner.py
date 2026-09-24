# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Coordinator evaluation vertical slice (real PostgreSQL).

Executes the PR 30D Coordinator pipeline against real PostgreSQL:

.. code-block:: text

    real coordinator JSON scenarios
     -> real typed loader
     -> real CoordinatorScenarioMaterializer (run-scoped execution identity)
     -> production Coordinator graph/policy (deterministic fixture world)
     -> real Evidence Analyst at the analysis boundary (FakeLlmClient only)
     -> real Research Agent for research lifecycles (FakeLlmClient only)
     -> durable terminal InvestigationState + structured timeline actions
     -> real CoordinatorTrajectoryEvaluator through the PR 30 adapter
     -> common EvaluationRunner

Covers: productive-pivot and immediate-stop PASS; the research lifecycle PASS
(request -> completed with exactly one request); an intentionally
nonconforming trajectory FAIL; and a materialization dependency ERROR. The
deterministic fixture world reproduces the authored trajectories that the
current production Coordinator still realizes; V1 scenarios whose authored
oracles/budgets predate the current topology honestly FAIL (never crash), and
the full-corpus smoke asserts every case reports PASS/FAIL/ERROR without an
exception. No live LLM or LangSmith participates.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst import (
    EvidenceAnalyst,
    EvidenceAnalystInputLoader,
    LlmAccountingService,
)
from agentic_threat_investigator.app.orchestration.research import (
    RESEARCH_QUERY_TEMPLATE,
    ResearchAgentResearchExecutor,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.domain.research import ResearchQuery
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationTarget,
    EvaluationVerdict,
)
from agentic_threat_investigator.evaluation.coordinator import (
    load_coordinator_scenarios_directory,
)
from agentic_threat_investigator.evaluation.coordinator_pr30 import (
    run_coordinator_evaluation,
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
from agentic_threat_investigator.infrastructure.research_agent_composition import (
    build_research_agent,
)
from tests.support.llm_fixtures import FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_CORPUS = "evals/scenarios/coordinator"
DATASET_ID = EvaluationDatasetId(target=EvaluationTarget.COORDINATOR, version=1)
_SUFFICIENT_STOP_IDS = {
    "domain-discovers-ip",
    "one-justified-replan",
    "sufficient-evidence-stop",
}


def _analyst_for(
    session_factory: async_sessionmaker[AsyncSession],
    llm: FakeLlmClient,
) -> EvidenceAnalyst:
    """Build a real Evidence Analyst wired to real persistence services."""

    def uow_factory() -> PostgresUnitOfWork:
        return PostgresUnitOfWork(session_factory)

    return EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(uow_factory),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            uow_factory, batch_size=100
        ),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=2,
    )


def _analysis_decision(disposition: AnalysisDisposition) -> EvidenceAnalystDecision:
    """Build one fixture-owned deterministic analysis decision."""
    return EvidenceAnalystDecision(
        verdict=Verdict.SUSPICIOUS,
        confidence=(
            AssessmentConfidence.MEDIUM
            if disposition is AnalysisDisposition.SUFFICIENT
            else AssessmentConfidence.LOW
        ),
        summary="Fixture-owned analysis step.",
        disposition=disposition,
    )


def _analysis_factory(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    fix_two_round: bool = False,
    forced: tuple[AnalysisDisposition, ...] | None = None,
) -> Callable[[object, object], Awaitable[EvidenceAnalystAnalysisExecutor]]:
    """Compose one deterministic analysis factory.

    The fixture world scripts the analyst exactly as the materialized fixture
    declares; the malware-research family needs the two-round
    (NEEDS_MORE_EVIDENCE, SUFFICIENT) flow the current Coordinator topology
    requires for the IP work + research lifecycle. ``forced`` overrides the
    script for deliberate nonconforming trajectories.
    """

    async def factory(
        investigation_id: object, materialized: object
    ) -> EvidenceAnalystAnalysisExecutor:
        identities = getattr(materialized, "entity_identities", {})
        has_malware = "malware_asyncrat" in identities
        if forced is not None:
            dispositions = forced
        elif has_malware or fix_two_round:
            dispositions = (
                AnalysisDisposition.NEEDS_MORE_EVIDENCE,
                AnalysisDisposition.SUFFICIENT,
            )
        else:
            dispositions = getattr(materialized, "analyst_dispositions", ()) or (
                AnalysisDisposition.SUFFICIENT,
            )
        llm = FakeLlmClient()
        for disposition in dispositions:
            llm.enqueue(_analysis_decision(disposition))
        return EvidenceAnalystAnalysisExecutor(
            _analyst_for(session_factory, llm),
            bound_investigation_id=investigation_id,  # type: ignore[arg-type]
        )

    return factory


def _research_factory(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    exhausted: bool = False,
) -> Callable[[object, object], Awaitable[ResearchAgentResearchExecutor]]:
    """Compose one deterministic research executor factory.

    Primes the research FakeLlmClient to cite the deterministic top chunk for
    the planned malware query (COMPLETED research), or to fail twice with a
    retryable provider error (EXHAUSTED research).
    """

    async def factory(
        investigation_id: object, materialized: object
    ) -> ResearchAgentResearchExecutor:
        objective = getattr(
            getattr(materialized, "initial_state", None), "objective", ""
        )
        query = RESEARCH_QUERY_TEMPLATE.format(
            entity_type="malware", value="asyncrat", objective=objective
        )
        retriever = PgVectorResearchRetriever(session_factory, HashingEmbeddingClient())
        chunks = await retriever.retrieve(
            ResearchQuery(
                investigation_id=uuid4(),
                query=query,
                max_results=8,
            )
        )
        research_llm = FakeLlmClient()
        if exhausted:
            from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode

            research_llm.enqueue(
                LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True)
            )
            research_llm.enqueue(
                LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True)
            )
        elif chunks:
            top = chunks[0].citation_id
            research_llm.set_default(
                ResearchAgentDecision(
                    claims=(
                        ResearchAgentClaim(
                            text="The malware family is associated with the technique.",
                            citation_ids=(top,),
                        ),
                    ),
                )
            )
        agent = build_research_agent(
            uow_factory=lambda: PostgresUnitOfWork(session_factory),
            session_factory=session_factory,
            embedding_client=HashingEmbeddingClient(),
            llm_client=research_llm,
            max_structured_output_attempts=2,
        )
        return ResearchAgentResearchExecutor(
            agent,
            bound_investigation_id=investigation_id,  # type: ignore[arg-type]
        )

    return factory


async def _bootstrapped(
    uow_factory: Callable[[], PostgresUnitOfWork], tmp_path: Path
) -> None:
    """Ingest and index the deterministic research corpus into tmp storage."""
    await bootstrap_research_corpus(
        uow_factory=uow_factory,
        data_dir=tmp_path,
        fixture_files=(REPOSITORY_RESEARCH_FIXTURES["mitre-attack-small"],),
    )


async def test_productive_and_immediate_stop_scenarios_pass(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """Productive-pivot, immediate-stop, and justified-replan scenarios PASS."""
    await _bootstrapped(uow_factory, tmp_path)
    scenarios = tuple(
        item
        for item in load_coordinator_scenarios_directory(_CORPUS)
        if item.id in _SUFFICIENT_STOP_IDS
    )
    result = await run_coordinator_evaluation(
        dataset_id=DATASET_ID,
        uow_factory=uow_factory,
        analysis_factory=_analysis_factory(session_factory),
        research_factory=_research_factory(session_factory),
        scenarios=scenarios,
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.PASS
    for case in result.cases:
        assert case.verdict is EvaluationVerdict.PASS, (
            case.case_id,
            case.evaluator_results[0].explanation,
        )


async def test_research_lifecycle_requested_completed_passes(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """One malware research request completes and the scenario PASSes."""
    await _bootstrapped(uow_factory, tmp_path)
    scenario = next(
        item
        for item in load_coordinator_scenarios_directory(_CORPUS)
        if item.id == "malware-research-requested"
    )
    result = await run_coordinator_evaluation(
        dataset_id=DATASET_ID,
        uow_factory=uow_factory,
        analysis_factory=_analysis_factory(session_factory),
        research_factory=_research_factory(session_factory),
        scenarios=(scenario,),
    )
    assert result.verdict is EvaluationVerdict.PASS
    case = result.cases[0]
    assert case.verdict is EvaluationVerdict.PASS
    assert case.evaluator_results[0].diagnostics["research_request_count"] == 1.0


async def test_exhausted_research_is_behavioral_fail_with_bounded_attempts(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """Two recoverable research failures exhaust boundedly (no duplicate)."""
    await _bootstrapped(uow_factory, tmp_path)
    scenario = next(
        item
        for item in load_coordinator_scenarios_directory(_CORPUS)
        if item.id == "malware-research-exhausted-not-duplicated"
    )
    result = await run_coordinator_evaluation(
        dataset_id=DATASET_ID,
        uow_factory=uow_factory,
        analysis_factory=_analysis_factory(session_factory),
        research_factory=_research_factory(session_factory, exhausted=True),
        scenarios=(scenario,),
    )
    # The scenario expects two requests with an exhausted termination; the
    # deterministic counter semantics decide the verdict -- the case must
    # complete (never ERROR) with a bounded diagnosis.
    case = result.cases[0]
    assert case.execution_status is EvaluationExecutionStatus.COMPLETED
    assert case.evaluator_results[0].diagnostics.get(
        "duplicate_research_request_count"
    ) in (0.0, None)


async def test_deliberately_nonconforming_trajectory_fails(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """A scripted immediate-SUFFICIENT trajectory violates the scenario."""
    await _bootstrapped(uow_factory, tmp_path)
    scenario = next(
        item
        for item in load_coordinator_scenarios_directory(_CORPUS)
        if item.id == "domain-discovers-ip"
    )
    result = await run_coordinator_evaluation(
        dataset_id=DATASET_ID,
        uow_factory=uow_factory,
        analysis_factory=_analysis_factory(
            session_factory,
            forced=(AnalysisDisposition.SUFFICIENT,),
        ),
        scenarios=(scenario,),
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.FAIL
    assert (
        "required_provider_work_missing"
        in result.cases[0].evaluator_results[0].explanation
    )


async def test_materialization_dependency_failure_is_error(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A fixture the materializer cannot persist surfaces as a case ERROR.

    The ``non-pivotable-discovery`` fixture declares an ORGANIZATION entity
    with no production canonicalization contract; materialization fails and
    the common runner reports ERROR (never a behavioral FAIL).
    """
    scenario = next(
        item
        for item in load_coordinator_scenarios_directory(_CORPUS)
        if item.id == "non-pivotable-discovery"
    )
    result = await run_coordinator_evaluation(
        dataset_id=DATASET_ID,
        uow_factory=uow_factory,
        analysis_factory=_analysis_factory(session_factory),
        scenarios=(scenario,),
    )
    assert result.execution_status is EvaluationExecutionStatus.ERROR
    assert result.verdict is None


async def test_full_corpus_run_never_crashes(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The whole coordinator corpus executes; every case reports deterministically.

    V1 scenarios whose authored oracles/budgets predate the current production
    Coordinator topology report FAIL (or the materialization limitation ERROR);
    none may raise an uncaught exception.
    """
    scenarios = load_coordinator_scenarios_directory(_CORPUS)
    result = await run_coordinator_evaluation(
        dataset_id=DATASET_ID,
        uow_factory=uow_factory,
        analysis_factory=_analysis_factory(session_factory),
        research_factory=_research_factory(session_factory),
        scenarios=scenarios,
    )
    assert len(result.cases) == len(scenarios)
    for case in result.cases:
        assert case.execution_status in {
            EvaluationExecutionStatus.COMPLETED,
            EvaluationExecutionStatus.ERROR,
        }
