# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical PR 22D research trajectory evaluation slices (22D-I07/I08).

Runs the complete production research lifecycle — real CoordinatorPolicy,
production LangGraph, ``LocalInvestigationRunner``, real-format MITRE ATT&CK
corpus, real PostgreSQL/pgvector research execution, ``FakeLlmClient`` at the
model boundary — then evaluates the durable timeline/state with the extended
``CoordinatorTrajectoryEvaluator`` against the repository-owned coordinator
research scenarios (C-R01..C-R04).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.evidence_analyst.analyst import EvidenceAnalyst
from agentic_threat_investigator.app.evidence_analyst.loader import (
    EvidenceAnalystInputLoader,
)
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.orchestration.research import (
    RESEARCH_QUERY_TEMPLATE,
)
from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    convert_timeline_actions,
)
from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
)
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
)
from agentic_threat_investigator.evaluation.coordinator import (
    CoordinatorEvaluationResult,
    CoordinatorScenario,
    CoordinatorTrajectoryEvaluator,
    load_coordinator_scenarios_directory,
)
from agentic_threat_investigator.evaluation.scenario_fixtures import (
    CoordinatorMaterializedFixture,
    CoordinatorScenarioMaterializer,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from tests.integration.test_provider_execution_pipeline import (
    HostAllowlistASGITransport,
    _build_stub_app,
)
from tests.integration.test_research_trajectory import (
    _GOOGLE_DNS_HOST,
    _MALWARE_VALUE,
    _configure_analyst_llm,
    _dns_a_response,
    _dns_empty_response,
    _DomainDnsProvider,
    _research_executor_factory,
    _ThreatFoxIpProvider,
    _top_chunk_for_query,
)
from tests.support.llm_fixtures import FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
_CORPUS = "evals/scenarios/coordinator"
_MATERIALIZER = CoordinatorScenarioMaterializer()


def _analyst_for(
    session_factory: async_sessionmaker[AsyncSession], llm: FakeLlmClient
) -> EvidenceAnalyst:
    """Build a real Evidence Analyst wired to real persistence services."""
    return EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(
            lambda: PostgresUnitOfWork(session_factory)
        ),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            lambda: PostgresUnitOfWork(session_factory), batch_size=100
        ),
        llm_accounting=LlmAccountingService(
            lambda: PostgresUnitOfWork(session_factory)
        ),
        max_structured_output_attempts=2,
    )


def _load_scenario(scenario_id: str) -> CoordinatorScenario:
    """Load one repository coordinator scenario by stable id."""
    return next(
        item
        for item in load_coordinator_scenarios_directory(_CORPUS)
        if item.id == scenario_id
    )


_DNS_RRTYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


def _dns_responses_for(domain: str) -> dict[tuple[str, str], dict[str, object]]:
    """Build scripted DNS responses that echo the queried domain name."""
    canonical = f"{domain}."
    response = _dns_a_response()
    response["Question"] = [{"name": canonical, "type": 1}]
    response["Answer"] = [
        {"name": canonical, "type": 1, "TTL": 300, "data": "203.0.113.42"}
    ]
    empty = _dns_empty_response()
    empty["Question"] = [{"name": canonical, "type": 1}]
    return {
        (domain, rrtype): response if rrtype == "A" else empty
        for rrtype in _DNS_RRTYPES
    }


async def _run_materialized_trajectory(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    *,
    materialized: CoordinatorMaterializedFixture,
    research_llm: FakeLlmClient,
) -> InvestigationState:
    """Run the production runner from one materialized fixture state.

    The analyst follows the canonical two-round decision sequence
    (NEEDS_MORE_EVIDENCE then SUFFICIENT) that drives the replan,
    ThreatFox malware discovery, and research execution exactly as the
    canonical PR 22C trajectory does.
    """
    root_domain_value = materialized.entity_identities["root_domain"][1]
    app = _build_stub_app()
    app.state.dns_responses.update(_dns_responses_for(root_domain_value))
    transport = HostAllowlistASGITransport(app, allowed_hosts={_GOOGLE_DNS_HOST})
    async with httpx.AsyncClient(transport=transport) as client:
        http = ProviderHttpClient(client=client)
        analyst_llm = FakeLlmClient()
        _configure_analyst_llm(analyst_llm)
        analyst = _analyst_for(session_factory, analyst_llm)
        dummy_dns = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
        registry: dict[SourceId, EvidenceProvider] = {
            SourceId.GOOGLE_PUBLIC_DNS: _DomainDnsProvider(dummy_dns),
            SourceId.THREATFOX: _ThreatFoxIpProvider(),
        }
        research_executor_factory = await _research_executor_factory(
            session_factory, research_llm
        )
        runner = LocalInvestigationRunner(
            uow_factory=uow_factory,
            provider_registry=registry,
            analysis_executor_factory=lambda investigation_id: (
                EvidenceAnalystAnalysisExecutor(
                    analyst, bound_investigation_id=investigation_id
                )
            ),
            research_executor_factory=research_executor_factory,
            clock=lambda: _FIXED_TS,
            recursion_limit=40,
        )
        return await runner.run(materialized.initial_state.investigation_id)


async def _evaluate_trajectory(
    uow_factory: Callable[[], PostgresUnitOfWork],
    scenario: CoordinatorScenario,
    final: InvestigationState,
    *,
    initial_version: int | None,
) -> CoordinatorEvaluationResult:
    """Evaluate the durable timeline against one coordinator scenario.

    ``observed_transitions`` is the deterministic observable span of durable
    Investigation versions across the run (at least one), bounded by the
    scenario's explicit ``max_transitions``.
    """
    async with uow_factory() as uow:
        events = await uow.timeline_events.list_by_investigation(final.investigation_id)
    actions = tuple(convert_timeline_actions(tuple(events)))
    resolution = await _MATERIALIZER.resolve_persisted(scenario, uow_factory)
    span = max(1, (final.version or 0) - (initial_version or 0) + 1)
    result = CoordinatorTrajectoryEvaluator().evaluate(
        scenario=scenario,
        resolution=resolution,
        final_state=final,
        actions=actions,
        observed_transitions=span,
    )
    assert result.passed, (scenario.id, result.failures, result.metrics)
    return result


def _planned_query(objective: str) -> str:
    """Build the deterministic research query for one scenario objective."""
    return RESEARCH_QUERY_TEMPLATE.format(
        entity_type="malware", value=_MALWARE_VALUE, objective=objective
    )


async def _research_llm_for(
    session_factory: async_sessionmaker[AsyncSession],
    materialized: CoordinatorMaterializedFixture,
    *,
    objective: str,
) -> FakeLlmClient:
    """Build a canonical research LLM citing the deterministic top chunk."""
    query = _planned_query(objective)
    top = await _top_chunk_for_query(session_factory, query)
    llm = FakeLlmClient()
    if top is not None:
        llm.set_default(
            ResearchAgentDecision(
                claims=(
                    ResearchAgentClaim(
                        text="The malware family is associated with the technique.",
                        citation_ids=(top[0],),
                    ),
                ),
            )
        )
    return llm


async def _index_corpus(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """Ingest and index the real-format ATT&CK fixture once."""
    from tests.integration.test_research_trajectory import (
        _index_corpus as _index_canonical,
    )

    await _index_canonical(uow_factory, session_factory, tmp_path)


async def test_c_r01_malware_research_requested(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """C-R01: the RESEARCHABLE malware requires and receives one research request."""
    await _index_corpus(uow_factory, session_factory, tmp_path)
    scenario = _load_scenario("malware-research-requested")
    materialized = await _MATERIALIZER.materialize(scenario, uow_factory)
    objective = materialized.initial_state.objective
    research_llm = await _research_llm_for(
        session_factory, materialized, objective=objective
    )
    final = await _run_materialized_trajectory(
        uow_factory,
        session_factory,
        materialized=materialized,
        research_llm=research_llm,
    )
    assert final.research_required_for_entity_ids
    [execution] = final.research_executions
    assert execution.status.value == "completed"
    result = await _evaluate_trajectory(
        uow_factory,
        scenario,
        final,
        initial_version=materialized.initial_state.version,
    )
    assert result.metrics["research_request_count"] == 1.0


async def test_c_r02_completed_research_not_duplicated(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """C-R02: an unchanged completed research context never requests again."""
    await _index_corpus(uow_factory, session_factory, tmp_path)
    scenario = _load_scenario("malware-research-completed-not-duplicated")
    materialized = await _MATERIALIZER.materialize(scenario, uow_factory)
    objective = materialized.initial_state.objective
    research_llm = await _research_llm_for(
        session_factory, materialized, objective=objective
    )
    final = await _run_materialized_trajectory(
        uow_factory,
        session_factory,
        materialized=materialized,
        research_llm=research_llm,
    )
    async with uow_factory() as uow:
        before_events = await uow.timeline_events.list_by_investigation(
            final.investigation_id
        )
    before_requests = len(
        [event for event in before_events if event.type.value == "research_requested"]
    )
    assert before_requests == 1

    # Re-running the runner against the terminal state is an idempotent
    # no-op: a fresh research LLM must never be called.
    rerun_llm = FakeLlmClient()
    rerun = await _run_materialized_trajectory(
        uow_factory,
        session_factory,
        materialized=materialized,
        research_llm=rerun_llm,
    )
    assert rerun == final
    assert rerun_llm.calls == []
    async with uow_factory() as uow:
        after_events = await uow.timeline_events.list_by_investigation(
            final.investigation_id
        )
    after_requests = len(
        [e for e in after_events if e.type.value == "research_requested"]
    )
    assert after_requests == before_requests
    result = await _evaluate_trajectory(
        uow_factory,
        scenario,
        rerun,
        initial_version=materialized.initial_state.version,
    )
    assert result.metrics["research_request_count"] == 1.0
    assert result.metrics["duplicate_research_request_count"] == 0.0


async def test_c_r03_exhausted_research_not_duplicated(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """C-R03: two recoverable failures exhaust the unchanged context boundedly."""
    await _index_corpus(uow_factory, session_factory, tmp_path)
    scenario = _load_scenario("malware-research-exhausted-not-duplicated")
    materialized = await _MATERIALIZER.materialize(scenario, uow_factory)
    research_llm = FakeLlmClient()
    research_llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True))
    research_llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True))
    final = await _run_materialized_trajectory(
        uow_factory,
        session_factory,
        materialized=materialized,
        research_llm=research_llm,
    )
    [execution] = final.research_executions
    assert execution.status.value == "exhausted"
    assert execution.attempts == 2
    assert len(research_llm.calls) == 2
    result = await _evaluate_trajectory(
        uow_factory,
        scenario,
        final,
        initial_version=materialized.initial_state.version,
    )
    assert result.metrics["research_request_count"] == 2.0
    assert result.metrics["duplicate_research_request_count"] == 0.0
    assert result.metrics["research_terminated"] == 1.0


async def test_c_r04_research_no_pivot_authority(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """C-R04: research completion grants no direct pivot authority."""
    await _index_corpus(uow_factory, session_factory, tmp_path)
    scenario = _load_scenario("malware-research-no-pivot-authority")
    materialized = await _MATERIALIZER.materialize(scenario, uow_factory)
    objective = materialized.initial_state.objective
    research_llm = await _research_llm_for(
        session_factory, materialized, objective=objective
    )
    final = await _run_materialized_trajectory(
        uow_factory,
        session_factory,
        materialized=materialized,
        research_llm=research_llm,
    )
    assert final.stop_reason == "sufficient_evidence"
    # The researched malware was never pivoted.
    assert all(
        pivot.entity_id not in set(final.research_required_for_entity_ids)
        for pivot in final.pending_pivots
    )
    result = await _evaluate_trajectory(
        uow_factory,
        scenario,
        final,
        initial_version=materialized.initial_state.version,
    )
    assert result.metrics["research_request_count"] == 1.0
