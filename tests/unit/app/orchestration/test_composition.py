# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 19B production graph composition factory."""

from typing import cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.extraction.models import ExtractionResult
from agentic_threat_investigator.app.orchestration import (
    InvestigationGraphBindingConflictError,
    InvestigationGraphContextMismatchError,
    build_investigation_graph,
    enqueue_provider_work,
)
from agentic_threat_investigator.app.orchestration.composition import (
    build_provider_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.dispatcher import LocalTaskDispatcher
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
    ProviderWorkExecutor,
)
from agentic_threat_investigator.app.providers import EvidenceProvider, ProviderResult
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    ProviderExecutionOutcome,
    ProviderWorkItem,
    default_investigation_budget,
)
from tests.support.orchestration_fixtures import (
    SCENARIO_DOMAIN_ID,
    scenario_dns_outcome,
    scenario_dns_work_item,
)
from tests.support.provider_executor_fixtures import (
    FakeEntityReader,
    FakePersistenceService,
    domain_entity,
    fixed_clock,
    null_uow_factory,
)


class _FakeProvider(EvidenceProvider):
    def __init__(self) -> None:
        self.supports_calls = 0
        self.investigate_calls = 0

    @property
    def id(self) -> str:
        return SourceId.GOOGLE_PUBLIC_DNS.value

    def supports(self, entity: Entity) -> bool:
        self.supports_calls += 1
        return True

    async def investigate(
        self, investigation_id: object, entity: Entity
    ) -> ProviderResult:
        self.investigate_calls += 1
        raise AssertionError("factory test must not invoke the provider")


def _state_for(investigation_id: UUID) -> InvestigationState:
    """Build a RUNNING state for the given investigation with one pending work item."""
    return enqueue_provider_work(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[SCENARIO_DOMAIN_ID],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=fixed_clock(),
        ),
        [scenario_dns_work_item()],
    )


def _exploding_uow_factory() -> object:
    """Return a factory that fails the test if the UoW is ever opened."""
    raise AssertionError("uow_factory must not be called")


@pytest.mark.asyncio
async def test_factory_assembles_graph_without_global_state() -> None:
    """The factory wires production seams into the existing graph topology."""
    registry: dict[SourceId, EvidenceProvider] = {
        SourceId.GOOGLE_PUBLIC_DNS: _FakeProvider()
    }
    context = ProviderExecutionContext(
        investigation_id=uuid4(),
        clock=fixed_clock,
    )
    graph = build_provider_investigation_graph(
        uow_factory=null_uow_factory,
        provider_registry=registry,
        context=context,
    )
    # The compiled graph exposes exactly the deterministic PR 19A topology;
    # dispatching adds no node and no dispatch timeline event seam.
    assert {"initialize", "select_work", "execute_work", "record_outcome"} <= set(
        graph.nodes
    )
    assert "dispatch" not in set(graph.nodes)


@pytest.mark.asyncio
async def test_mismatched_investigation_fails_before_any_seam() -> None:
    """A graph built for investigation A rejects state B before every I/O seam.

    The mismatch is raised during initialize, so the UnitOfWork factory, the
    provider, and every persistence/timeline seam must never run. The fixed
    exception message contains neither UUID.
    """
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    investigation_b = UUID("00000000-0000-0000-0000-0000000000bb")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    graph = build_provider_investigation_graph(
        uow_factory=_exploding_uow_factory,  # type: ignore[arg-type]
        provider_registry=registry,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    with pytest.raises(InvestigationGraphContextMismatchError) as raised:
        await graph.ainvoke({"investigation": _state_for(investigation_b)})
    assert provider.supports_calls == 0
    assert provider.investigate_calls == 0
    message = str(raised.value)
    assert str(investigation_a) not in message
    assert str(investigation_b) not in message
    assert message == (
        "orchestration graph state does not match the bound investigation context"
    )


@pytest.mark.asyncio
async def test_factory_graph_executes_through_local_dispatcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The factory's real graph path executes through LocalTaskDispatcher.

    A recording spy on ``LocalTaskDispatcher.dispatch`` proves the compiled
    graph calls ``TaskDispatcher.dispatch()`` and that the production
    executor binding is preserved on the dispatcher instance. The spy stands
    in for the executor, so no provider, UoW, extraction, persistence, or
    timeline seam runs.
    """
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    dispatched: list[ProviderWorkItem] = []
    observed_bindings: list[UUID | None] = []

    async def recording_dispatch(
        self: LocalTaskDispatcher, work_item: ProviderWorkItem
    ) -> ProviderExecutionOutcome:
        dispatched.append(work_item)
        observed_bindings.append(self.bound_investigation_id)
        return scenario_dns_outcome()

    monkeypatch.setattr(LocalTaskDispatcher, "dispatch", recording_dispatch)
    graph = build_provider_investigation_graph(
        uow_factory=null_uow_factory,
        provider_registry=registry,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    result = await graph.ainvoke({"investigation": _state_for(investigation_a)})
    recorded = cast(InvestigationState, result["investigation"])
    # The graph dispatched the queued item exactly once through the local
    # dispatcher seam, preserving the production executor binding.
    assert dispatched == [scenario_dns_work_item()]
    assert observed_bindings == [investigation_a]
    assert provider.supports_calls == 0
    assert provider.investigate_calls == 0
    assert recorded.completed_provider_work == [scenario_dns_work_item()]
    assert recorded.budget.provider_calls_used == 1


def test_factory_dispatcher_derives_binding_from_production_executor() -> None:
    """The factory's local dispatcher exposes the provider executor binding.

    Direct construction of the factory seam (matching composition.py) proves
    ``LocalTaskDispatcher`` derives its binding from the wrapped production
    ``ProviderWorkExecutor``: no second mutable investigation ID exists in
    the dispatcher layer.
    """
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    executor = ProviderWorkExecutor(
        entity_reader=FakeEntityReader({uuid4(): domain_entity()}),
        provider_registry={SourceId.GOOGLE_PUBLIC_DNS: _FakeProvider()},
        extractor=lambda _evidence: ExtractionResult(),
        persistence_service=FakePersistenceService(),
        timeline_service=None,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    dispatcher = LocalTaskDispatcher(executor)
    assert dispatcher.bound_investigation_id == investigation_a


@pytest.mark.asyncio
async def test_factory_graph_mismatch_never_reaches_dispatcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A factory graph mismatch is rejected before dispatch is invoked.

    The dispatcher spy records calls; a mismatched state must fail during
    initialization with zero dispatch calls, zero provider calls, and zero
    UoW opens.
    """
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    investigation_b = UUID("00000000-0000-0000-0000-0000000000bb")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    dispatched: list[ProviderWorkItem] = []

    async def recording_dispatch(
        _self: LocalTaskDispatcher, work_item: ProviderWorkItem
    ) -> ProviderExecutionOutcome:
        dispatched.append(work_item)
        raise AssertionError("dispatcher must not be called for a mismatch")

    monkeypatch.setattr(LocalTaskDispatcher, "dispatch", recording_dispatch)
    graph = build_provider_investigation_graph(
        uow_factory=_exploding_uow_factory,  # type: ignore[arg-type]
        provider_registry=registry,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    with pytest.raises(InvestigationGraphContextMismatchError):
        await graph.ainvoke({"investigation": _state_for(investigation_b)})
    assert not dispatched
    assert provider.supports_calls == 0
    assert provider.investigate_calls == 0


@pytest.mark.asyncio
async def test_matching_investigation_zero_work_terminates() -> None:
    """A matching investigation with no work terminates without any seam call."""
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    graph = build_provider_investigation_graph(
        uow_factory=_exploding_uow_factory,  # type: ignore[arg-type]
        provider_registry=registry,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    state = InvestigationState(
        investigation_id=investigation_a,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[SCENARIO_DOMAIN_ID],
        objective="Assess the root indicator.",
        budget=default_investigation_budget(),
        started_at=fixed_clock(),
    )
    result = await graph.ainvoke({"investigation": state})
    recorded = cast(InvestigationState, result["investigation"])
    assert recorded.investigation_id == investigation_a
    assert provider.supports_calls == 0
    assert provider.investigate_calls == 0
    assert recorded.budget.provider_calls_used == 0


@pytest.mark.asyncio
async def test_local_dispatcher_bound_by_wrapped_production_executor() -> None:
    """A LocalTaskDispatcher exposes its wrapped executor's binding.

    A caller who wraps the production executor for investigation A in a
    ``LocalTaskDispatcher`` and builds the generic graph without an expected
    ID still gets automatic binding: invoking the graph with state B raises
    the typed mismatch error before the entity reader, provider, or any
    persistence/timeline seam runs. The graph never accepts the executor
    directly; the dispatcher is the explicit seam.
    """
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    investigation_b = UUID("00000000-0000-0000-0000-0000000000bb")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    executor = ProviderWorkExecutor(
        entity_reader=FakeEntityReader({uuid4(): domain_entity()}),
        provider_registry=registry,
        extractor=lambda _evidence: ExtractionResult(),
        persistence_service=FakePersistenceService(),
        timeline_service=None,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    dispatcher = LocalTaskDispatcher(executor)
    graph = build_investigation_graph(dispatcher)
    with pytest.raises(InvestigationGraphContextMismatchError) as raised:
        await graph.ainvoke({"investigation": _state_for(investigation_b)})
    assert provider.supports_calls == 0
    assert provider.investigate_calls == 0
    message = str(raised.value)
    assert str(investigation_a) not in message
    assert str(investigation_b) not in message
    assert message == (
        "orchestration graph state does not match the bound investigation context"
    )


def test_local_dispatcher_conflict_rejected_at_construction() -> None:
    """An explicit conflicting ID with a wrapped provider executor fails early."""
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    investigation_b = UUID("00000000-0000-0000-0000-0000000000bb")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    executor = ProviderWorkExecutor(
        entity_reader=FakeEntityReader({uuid4(): domain_entity()}),
        provider_registry=registry,
        extractor=lambda _: ExtractionResult(),
        persistence_service=FakePersistenceService(),
        timeline_service=None,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    dispatcher = LocalTaskDispatcher(executor)
    with pytest.raises(InvestigationGraphBindingConflictError) as raised:
        build_investigation_graph(
            dispatcher,
            expected_investigation_id=investigation_b,
        )
    message = str(raised.value)
    assert message == (
        "orchestration graph binding conflicts with the dispatcher "
        "investigation context"
    )
    assert str(investigation_a) not in message
    assert str(investigation_b) not in message
