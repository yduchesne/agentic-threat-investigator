# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Direct unit tests for the PR 19C task dispatch boundary."""

import asyncio
from uuid import UUID

import pytest

from agentic_threat_investigator.app.orchestration.dispatcher import LocalTaskDispatcher
from agentic_threat_investigator.app.orchestration.executor import (
    InvestigationBoundWorkExecutor,
    WorkExecutor,
)
from agentic_threat_investigator.app.orchestration.models import enqueue_provider_work
from agentic_threat_investigator.domain.investigation import (
    ProviderExecutionOutcome,
    ProviderWorkItem,
)
from tests.support.orchestration_fixtures import (
    FakeWorkExecutor,
    scenario_dns_outcome,
    scenario_dns_work_item,
    scenario_investigation_state,
)


class RecordingExecutor(WorkExecutor):
    """Work executor recording calls and returning one configured outcome."""

    def __init__(self, outcome: ProviderExecutionOutcome) -> None:
        self._outcome = outcome
        self.requested: list[ProviderWorkItem] = []

    async def execute(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        """Record and return the exact configured outcome."""
        self.requested.append(work_item)
        return self._outcome


class RaisingExecutor(WorkExecutor):
    """Work executor raising an injected exception for every call."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.requested: list[ProviderWorkItem] = []

    async def execute(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        self.requested.append(work_item)
        raise self._exc


class BoundRecordingExecutor(InvestigationBoundWorkExecutor):
    """Bound executor recording calls for binding-exposure assertions."""

    def __init__(
        self, investigation_id: UUID, outcome: ProviderExecutionOutcome
    ) -> None:
        self._investigation_id = investigation_id
        self._outcome = outcome
        self.requested: list[ProviderWorkItem] = []

    @property
    def bound_investigation_id(self) -> UUID:
        """Return the configured bound investigation identity."""
        return self._investigation_id

    async def execute(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        self.requested.append(work_item)
        return self._outcome


class TestLocalTaskDispatcherDelegation:
    """Dispatch delegates exactly once and preserves the exact outcome."""

    @pytest.mark.asyncio
    async def test_dispatches_exact_work_item_exactly_once(self) -> None:
        item = scenario_dns_work_item()
        outcome = scenario_dns_outcome()
        executor = RecordingExecutor(outcome)
        dispatcher = LocalTaskDispatcher(executor)

        assert await dispatcher.dispatch(item) is outcome
        assert executor.requested == [item]
        assert outcome.work_item == item

    @pytest.mark.asyncio
    async def test_outcome_returns_exact_value(self) -> None:
        outcome = scenario_dns_outcome()
        dispatcher = LocalTaskDispatcher(RecordingExecutor(outcome))
        result = await dispatcher.dispatch(scenario_dns_work_item())
        assert result == outcome
        assert result is outcome

    @pytest.mark.asyncio
    async def test_normal_exception_propagates_unchanged(self) -> None:
        exc = RuntimeError("dispatch exploded")
        executor = RaisingExecutor(exc)
        dispatcher = LocalTaskDispatcher(executor)
        with pytest.raises(RuntimeError) as raised:
            await dispatcher.dispatch(scenario_dns_work_item())
        assert raised.value is exc
        assert executor.requested == [scenario_dns_work_item()]

    @pytest.mark.asyncio
    async def test_cancellation_propagates_unchanged(self) -> None:
        """asyncio.CancelledError propagates; it is never caught or converted."""
        exc = asyncio.CancelledError()
        executor = RaisingExecutor(exc)
        dispatcher = LocalTaskDispatcher(executor)
        with pytest.raises(asyncio.CancelledError) as raised:
            await dispatcher.dispatch(scenario_dns_work_item())
        assert raised.value is exc
        assert executor.requested == [scenario_dns_work_item()]

    @pytest.mark.asyncio
    async def test_dispatch_does_not_mutate_investigation_state(self) -> None:
        outcome = scenario_dns_outcome()
        dispatcher = LocalTaskDispatcher(RecordingExecutor(outcome))
        state = enqueue_provider_work(
            scenario_investigation_state(), [scenario_dns_work_item()]
        )
        before = state.model_copy(deep=True)
        assert state.current_provider_work is None
        work_item = state.pending_provider_work[0]
        dispatched = await dispatcher.dispatch(work_item)
        assert dispatched == outcome
        # The wrapped investigation state is untouched by dispatch.
        assert state == before
        assert state.current_provider_work is None
        assert state.pending_provider_work == [work_item]


class TestLocalTaskDispatcherBinding:
    """The local dispatcher exposes the wrapped executor's binding only."""

    @pytest.mark.asyncio
    async def test_bound_executor_binding_exposed(self) -> None:
        investigation_id = UUID("00000000-0000-0000-0000-0000000000ee")
        outcome = scenario_dns_outcome()
        dispatcher = LocalTaskDispatcher(
            BoundRecordingExecutor(investigation_id, outcome)
        )
        assert dispatcher.bound_investigation_id == investigation_id

    @pytest.mark.asyncio
    async def test_unbound_executor_binding_is_none(self) -> None:
        dispatcher = LocalTaskDispatcher(
            FakeWorkExecutor({scenario_dns_work_item(): scenario_dns_outcome()})
        )
        assert dispatcher.bound_investigation_id is None
