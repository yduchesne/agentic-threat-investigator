# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic LangGraph orchestration skeleton tests (PR 19A/C).

Primary graph tests exercise the injected :class:`TaskDispatcher` seam
(``FakeTaskDispatcher``) and do not require ``LocalTaskDispatcher`` or
``ProviderWorkExecutor``. ``build_investigation_graph`` accepts only a
``TaskDispatcher``; investigation binding is additionally covered through the
production-style ``LocalTaskDispatcher`` wrapping a bound executor.
"""

from typing import cast
from uuid import UUID

import pytest

from agentic_threat_investigator.app.orchestration import (
    InvestigationGraphBindingConflictError,
    InvestigationGraphContextMismatchError,
    build_investigation_graph,
    enqueue_provider_work,
)
from agentic_threat_investigator.app.orchestration.dispatcher import (
    LocalTaskDispatcher,
    TaskDispatcher,
)
from agentic_threat_investigator.app.orchestration.executor import (
    InvestigationBoundWorkExecutor,
)
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
    FakeTaskDispatcher,
    scenario_dispatcher,
    scenario_dns_outcome,
    scenario_dns_work_item,
    scenario_initial_state,
    scenario_investigation_state,
    scenario_rdap_outcome,
    scenario_rdap_work_item,
)


async def _run(
    initial_state: InvestigationState | None = None,
    dispatcher: TaskDispatcher | None = None,
) -> InvestigationState:
    state = initial_state if initial_state is not None else scenario_initial_state()
    task_dispatcher = dispatcher if dispatcher is not None else scenario_dispatcher()
    result = await build_investigation_graph(task_dispatcher).ainvoke(
        {"investigation": state}
    )
    return cast(InvestigationState, result["investigation"])


class TestGraphTermination:
    """Deterministic graph termination behavior through the dispatcher."""

    @pytest.mark.asyncio
    async def test_zero_work_graph_terminates_deterministically(self) -> None:
        dispatcher = scenario_dispatcher()
        state = await _run(scenario_investigation_state(), dispatcher)
        assert not dispatcher.requested
        assert state.pending_provider_work == []
        assert state.current_provider_work is None
        assert state.budget.provider_calls_used == 0

    @pytest.mark.asyncio
    async def test_one_work_item_dispatches_exactly_once(self) -> None:
        dispatcher = scenario_dispatcher()
        state = await _run(
            enqueue_provider_work(
                scenario_investigation_state(), [scenario_dns_work_item()]
            ),
            dispatcher,
        )
        assert dispatcher.requested == [scenario_dns_work_item()]
        assert state.completed_provider_work == [scenario_dns_work_item()]

    @pytest.mark.asyncio
    async def test_multiple_work_items_dispatched_fifo(self) -> None:
        dispatcher = scenario_dispatcher()
        state = await _run(scenario_initial_state(), dispatcher)
        assert dispatcher.requested == [
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
        dispatcher = FakeTaskDispatcher(
            {
                scenario_dns_work_item(): failure,
                scenario_rdap_work_item(): scenario_rdap_outcome(),
            }
        )
        state = await _run(scenario_initial_state(), dispatcher)
        assert dispatcher.requested == [
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
    async def test_duplicate_queued_work_dispatched_only_once(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(),
            [scenario_dns_work_item(), scenario_dns_work_item()],
        )
        dispatcher = scenario_dispatcher()
        state = await _run(state, dispatcher)
        assert dispatcher.requested == [scenario_dns_work_item()]
        assert state.completed_provider_work == [scenario_dns_work_item()]

    @pytest.mark.asyncio
    async def test_final_provider_calls_equal_executed_unique_items(self) -> None:
        state = await _run()
        assert state.budget.provider_calls_used == 2


class TestGraphDispatcherSafety:
    """The graph rejects crossed outcomes and propagates dispatcher errors."""

    @pytest.mark.asyncio
    async def test_outcome_mismatch_rejected_before_bookkeeping(self) -> None:
        """A dispatcher outcome for another item fails before record_outcome."""
        dispatcher = FakeTaskDispatcher(
            {
                scenario_dns_work_item(): ProviderExecutionOutcome(
                    work_item=scenario_rdap_work_item(),
                    status=ProviderExecutionStatus.SUCCEEDED,
                )
            }
        )
        graph = build_investigation_graph(dispatcher)
        with pytest.raises(ValueError, match="dispatcher outcome does not match"):
            await graph.ainvoke({"investigation": scenario_initial_state()})
        # The mismatched item was dispatched once and then rejected: no
        # completion, outcome recording, or counter increment happened.
        assert dispatcher.requested == [scenario_dns_work_item()]

    @pytest.mark.asyncio
    async def test_dispatcher_exception_reaches_caller_unchanged(self) -> None:
        """A dispatcher exception propagates and records no outcome."""

        class RaisingDispatcher(TaskDispatcher):
            def __init__(self, exc: BaseException) -> None:
                self._exc = exc
                self.requested: list[ProviderWorkItem] = []

            async def dispatch(
                self, work_item: ProviderWorkItem
            ) -> ProviderExecutionOutcome:
                self.requested.append(work_item)
                raise self._exc

        exc = RuntimeError("dispatch failed upstream")
        dispatcher = RaisingDispatcher(exc)
        graph = build_investigation_graph(dispatcher)
        with pytest.raises(RuntimeError) as raised:
            await graph.ainvoke({"investigation": scenario_initial_state()})
        # The exact exception object reaches the caller unchanged; the graph
        # never continued into record_outcome, so no outcome was recorded.
        assert raised.value is exc
        assert dispatcher.requested == [scenario_dns_work_item()]


class TestGraphContextBinding:
    """Graphs bound to one investigation reject state for another."""

    @pytest.mark.asyncio
    async def test_matching_investigation_id_runs_normally(self) -> None:
        """A bound graph accepts its own investigation ID unchanged."""
        dispatcher = scenario_dispatcher()
        state = scenario_investigation_state()
        graph = build_investigation_graph(
            dispatcher,
            expected_investigation_id=state.investigation_id,
        )
        result = await graph.ainvoke(
            {"investigation": enqueue_provider_work(state, [scenario_dns_work_item()])}
        )
        recorded = cast(InvestigationState, result["investigation"])
        # Existing deterministic outcome/counter behavior is unchanged.
        assert dispatcher.requested == [scenario_dns_work_item()]
        assert recorded.completed_provider_work == [scenario_dns_work_item()]
        assert recorded.budget.provider_calls_used == 1
        assert recorded.investigation_id == state.investigation_id

    @pytest.mark.asyncio
    async def test_mismatched_investigation_id_fails_before_dispatcher(self) -> None:
        """A bound graph rejects another investigation before any dispatch."""

        state = scenario_investigation_state()
        expected = UUID("00000000-0000-0000-0000-0000000000bb")
        assert expected != state.investigation_id

        class ExplodingDispatcher(TaskDispatcher):
            """Fail the test if the dispatcher is ever invoked."""

            async def dispatch(
                self, work_item: ProviderWorkItem
            ) -> ProviderExecutionOutcome:
                raise AssertionError("dispatcher must not be called")

        graph = build_investigation_graph(
            ExplodingDispatcher(),
            expected_investigation_id=expected,
        )
        with pytest.raises(InvestigationGraphContextMismatchError) as raised:
            await graph.ainvoke(
                {
                    "investigation": enqueue_provider_work(
                        state, [scenario_dns_work_item()]
                    )
                }
            )
        # The fixed safe message contains neither UUID string.
        message = str(raised.value)
        assert message == (
            "orchestration graph state does not match the bound investigation context"
        )
        assert str(expected) not in message
        assert str(state.investigation_id) not in message

    @pytest.mark.asyncio
    async def test_unbound_dispatcher_remains_usable(self) -> None:
        """An unbound fake dispatcher works without an expected investigation ID."""
        dispatcher = scenario_dispatcher()
        result = await build_investigation_graph(dispatcher).ainvoke(
            {"investigation": scenario_initial_state()}
        )
        state = cast(InvestigationState, result["investigation"])
        assert dispatcher.requested == [
            scenario_dns_work_item(),
            scenario_rdap_work_item(),
        ]
        assert state.completed_provider_work == [
            scenario_dns_work_item(),
            scenario_rdap_work_item(),
        ]


class BoundFakeExecutor(InvestigationBoundWorkExecutor):
    """Deterministic bound executor recording executions.

    Matching invocations succeed with the scenario DNS outcome; a
    binding-rejected state must never reach execution, so any unexpected call
    fails the test.
    """

    def __init__(self, investigation_id: UUID) -> None:
        self._investigation_id = investigation_id
        self.executed: list[ProviderWorkItem] = []

    @property
    def bound_investigation_id(self) -> UUID:
        """Return the configured bound investigation identity."""
        return self._investigation_id

    async def execute(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        """Execute one item when matching; fail any unexpected call."""
        self.executed.append(work_item)
        if work_item != scenario_dns_work_item():
            raise AssertionError("bound executor received unexpected work")
        return scenario_dns_outcome()


class TestGraphBindingThroughLocalDispatcher:
    """Binding is preserved across the production LocalTaskDispatcher seam."""

    @pytest.mark.asyncio
    async def test_omitted_expected_id_adopts_wrapped_binding(self) -> None:
        """A local dispatcher's wrapped executor binding is adopted."""
        state = scenario_investigation_state()
        executor = BoundFakeExecutor(state.investigation_id)
        graph = build_investigation_graph(LocalTaskDispatcher(executor))
        result = await graph.ainvoke(
            {"investigation": enqueue_provider_work(state, [scenario_dns_work_item()])}
        )
        recorded = cast(InvestigationState, result["investigation"])
        assert executor.executed == [scenario_dns_work_item()]
        assert recorded.completed_provider_work == [scenario_dns_work_item()]
        assert recorded.budget.provider_calls_used == 1

    @pytest.mark.asyncio
    async def test_wrapped_binding_rejects_mismatched_state(self) -> None:
        """A bound local dispatcher rejects another investigation's state."""
        state = scenario_investigation_state()
        other = UUID("00000000-0000-0000-0000-0000000000bb")
        assert other != state.investigation_id
        executor = BoundFakeExecutor(other)
        graph = build_investigation_graph(LocalTaskDispatcher(executor))
        with pytest.raises(InvestigationGraphContextMismatchError):
            await graph.ainvoke(
                {
                    "investigation": enqueue_provider_work(
                        state, [scenario_dns_work_item()]
                    )
                }
            )
        # The dispatcher/executor was never called for the rejected state.
        assert not executor.executed

    @pytest.mark.asyncio
    async def test_explicit_matching_binding_executes(self) -> None:
        """An explicit expected ID equal to the wrapped binding is accepted."""
        state = scenario_investigation_state()
        executor = BoundFakeExecutor(state.investigation_id)
        graph = build_investigation_graph(
            LocalTaskDispatcher(executor),
            expected_investigation_id=state.investigation_id,
        )
        result = await graph.ainvoke(
            {"investigation": enqueue_provider_work(state, [scenario_dns_work_item()])}
        )
        recorded = cast(InvestigationState, result["investigation"])
        assert executor.executed == [scenario_dns_work_item()]
        assert recorded.completed_provider_work == [scenario_dns_work_item()]

    def test_construction_time_conflict_rejected(self) -> None:
        """A conflicting explicit binding fails at graph construction."""
        state = scenario_investigation_state()
        other = UUID("00000000-0000-0000-0000-0000000000bb")
        executor = BoundFakeExecutor(state.investigation_id)
        with pytest.raises(InvestigationGraphBindingConflictError) as raised:
            build_investigation_graph(
                LocalTaskDispatcher(executor),
                expected_investigation_id=other,
            )
        message = str(raised.value)
        assert message == (
            "orchestration graph binding conflicts with the dispatcher "
            "investigation context"
        )
        assert str(state.investigation_id) not in message
        assert str(other) not in message

    @pytest.mark.asyncio
    async def test_unbound_dispatcher_with_explicit_expected_id(self) -> None:
        """A generic unbound dispatcher honors an explicit expected ID."""
        state = scenario_investigation_state()
        dispatcher = scenario_dispatcher()
        graph = build_investigation_graph(
            dispatcher,
            expected_investigation_id=state.investigation_id,
        )
        result = await graph.ainvoke(
            {"investigation": enqueue_provider_work(state, [scenario_dns_work_item()])}
        )
        recorded = cast(InvestigationState, result["investigation"])
        assert dispatcher.requested == [scenario_dns_work_item()]
        assert recorded.completed_provider_work == [scenario_dns_work_item()]
        assert recorded.budget.provider_calls_used == 1
