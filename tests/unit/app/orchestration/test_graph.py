# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic LangGraph orchestration skeleton tests (PR 19A)."""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-few-public-methods

from typing import cast

import pytest

from agentic_threat_investigator.app.orchestration import (
    build_investigation_graph,
    enqueue_provider_work,
)
from agentic_threat_investigator.app.orchestration.executor import WorkExecutor
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationError,
    InvestigationState,
    ProviderExecutionOutcome,
    ProviderExecutionStatus,
    ProviderWorkItem,
)
from tests.support.orchestration_fixtures import (
    SCENARIO_IP_ID,
    FakeWorkExecutor,
    scenario_dns_work_item,
    scenario_executor,
    scenario_initial_state,
    scenario_investigation_state,
    scenario_rdap_outcome,
    scenario_rdap_work_item,
)


async def _run(
    initial_state: InvestigationState | None = None,
    executor: WorkExecutor | None = None,
) -> InvestigationState:
    state = initial_state if initial_state is not None else scenario_initial_state()
    work_executor = executor if executor is not None else scenario_executor()
    result = await build_investigation_graph(work_executor).ainvoke(
        {"investigation": state}
    )
    return cast(InvestigationState, result["investigation"])


class TestGraphTermination:
    """Deterministic graph termination behavior."""

    @pytest.mark.asyncio
    async def test_zero_work_graph_terminates_deterministically(self) -> None:
        executor = scenario_executor()
        state = await _run(scenario_investigation_state(), executor)
        assert not executor.requested
        assert state.pending_provider_work == []
        assert state.current_provider_work is None
        assert state.budget.provider_calls_used == 0

    @pytest.mark.asyncio
    async def test_one_work_item_executes_exactly_once(self) -> None:
        executor = scenario_executor()
        state = await _run(
            enqueue_provider_work(
                scenario_investigation_state(), [scenario_dns_work_item()]
            ),
            executor,
        )
        assert executor.requested == [scenario_dns_work_item()]
        assert state.completed_provider_work == [scenario_dns_work_item()]

    @pytest.mark.asyncio
    async def test_multiple_work_items_execute_fifo(self) -> None:
        executor = scenario_executor()
        state = await _run(scenario_initial_state(), executor)
        assert executor.requested == [
            scenario_dns_work_item(),
            scenario_rdap_work_item(),
        ]
        assert state.completed_provider_work == [
            scenario_dns_work_item(),
            scenario_rdap_work_item(),
        ]

    @pytest.mark.asyncio
    async def test_graph_terminates_when_pending_work_exhausted(self) -> None:
        state = await _run()
        assert state.pending_provider_work == []
        assert state.current_provider_work is None


class TestGraphWorkMechanics:
    """Work execution, discovery, and counter mechanics in the graph."""

    @pytest.mark.asyncio
    async def test_discovered_ids_appear_in_working_set(self) -> None:
        state = await _run()
        assert state.discovered_entity_ids == [SCENARIO_IP_ID]

    @pytest.mark.asyncio
    async def test_discovery_does_not_enqueue_adaptive_work(self) -> None:
        state = await _run()
        assert len(state.completed_provider_work) == 2
        assert all(item.depth == 0 for item in state.completed_provider_work)
        assert all(
            item.provider in (SourceId.GOOGLE_PUBLIC_DNS, SourceId.RDAP)
            for item in state.completed_provider_work
        )
        assert len(state.pending_provider_work) == 0

    @pytest.mark.asyncio
    async def test_failed_work_recorded_and_graph_proceeds(self) -> None:
        failure = ProviderExecutionOutcome(
            work_item=scenario_dns_work_item(),
            status=ProviderExecutionStatus.FAILED,
            error=InvestigationError(
                source="urn:ati:source:google_public_dns",
                code="provider_failure",
                message="DNS resolution failed",
                recoverable=True,
            ),
        )
        executor = FakeWorkExecutor(
            {
                scenario_dns_work_item(): failure,
                scenario_rdap_work_item(): scenario_rdap_outcome(),
            }
        )
        state = await _run(scenario_initial_state(), executor)
        assert executor.requested == [
            scenario_dns_work_item(),
            scenario_rdap_work_item(),
        ]
        assert state.completed_provider_work == [
            scenario_dns_work_item(),
            scenario_rdap_work_item(),
        ]
        assert len(state.errors) == 1
        assert state.errors[0].code == "provider_failure"

    @pytest.mark.asyncio
    async def test_duplicate_queued_work_executes_only_once(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(),
            [scenario_dns_work_item(), scenario_dns_work_item()],
        )
        executor = scenario_executor()
        state = await _run(state, executor)
        assert executor.requested == [scenario_dns_work_item()]
        assert state.completed_provider_work == [scenario_dns_work_item()]

    @pytest.mark.asyncio
    async def test_final_provider_calls_equal_executed_unique_items(self) -> None:
        state = await _run()
        assert state.budget.provider_calls_used == 2

    @pytest.mark.asyncio
    async def test_executor_outcome_mismatch_rejected(self) -> None:
        class MismatchedExecutor(WorkExecutor):
            """Executor returning an outcome for a different work item."""

            async def execute(
                self, work_item: ProviderWorkItem
            ) -> ProviderExecutionOutcome:
                return ProviderExecutionOutcome(
                    work_item=scenario_rdap_work_item(),
                    status=ProviderExecutionStatus.SUCCEEDED,
                )

        graph = build_investigation_graph(MismatchedExecutor())
        with pytest.raises(ValueError, match="does not match"):
            await graph.ainvoke({"investigation": scenario_initial_state()})
