# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 21C application-level investigation runner.

Covers every runner contract with fakes only: no PostgreSQL, HTTP, or LLM.
The graph composition seam (``build_provider_investigation_graph``) is
monkeypatched with a recording spy except where the real factory's own
binding validation is the behavior under test (U6). The fake UnitOfWork
tracks open/close so tests can prove the initial load transaction is closed
before graph execution.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.orchestration import runner as runner_module
from agentic_threat_investigator.app.orchestration.coordinator import (
    AnalysisExecutor,
    AnalysisOutcome,
)
from agentic_threat_investigator.app.orchestration.runner import (
    InvestigationRunnerLifecycleError,
    InvestigationRunnerPersistenceMismatchError,
    LocalInvestigationRunner,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
)
from agentic_threat_investigator.app.providers import EvidenceProvider, ProviderResult
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    StopReason,
    default_investigation_budget,
)

_FIXED_TS = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)

INVESTIGATION_A = UUID("00000000-0000-0000-0000-0000000000aa")
INVESTIGATION_B = UUID("00000000-0000-0000-0000-0000000000bb")
INVESTIGATION_C = UUID("00000000-0000-0000-0000-0000000000cc")


class _UowTracker:
    """Record every UnitOfWork open/close event across instances."""

    def __init__(self) -> None:
        self.events: list[str] = []

    @property
    def current_open(self) -> int:
        """Return how many UnitOfWorks are currently open."""
        return self.events.count("open") - self.events.count("close")

    def open_count(self) -> int:
        """Return the total number of opened UnitOfWorks."""
        return self.events.count("open")


class _FakeInvestigationRepository:
    """In-memory get_by_id over one shared mutable store."""

    def __init__(self, store: dict[UUID, InvestigationState]) -> None:
        self._store = store

    async def get_by_id(self, investigation_id: UUID) -> InvestigationState | None:
        """Return the stored state, or ``None`` when absent."""
        return self._store.get(investigation_id)


class _FakeUnitOfWork:
    """Instrumented async context manager exposing one investigation repository."""

    def __init__(
        self, store: dict[UUID, InvestigationState], tracker: _UowTracker
    ) -> None:
        self.investigations = _FakeInvestigationRepository(store)
        self._tracker = tracker

    async def __aenter__(self) -> "_FakeUnitOfWork":
        """Record the open and expose the fake repositories."""
        self._tracker.events.append("open")
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        """Record the close; a committed read leaves no open transaction."""
        self._tracker.events.append("close")


def _uow_factory_for(
    store: dict[UUID, InvestigationState], tracker: _UowTracker
) -> Callable[[], _FakeUnitOfWork]:
    """Return a factory creating instrumented fakes over the shared store."""

    def factory() -> _FakeUnitOfWork:
        return _FakeUnitOfWork(store, tracker)

    return factory


def _state(
    investigation_id: UUID, *, status: InvestigationStatus
) -> InvestigationState:
    """Build one deterministic persisted Investigation state."""
    return InvestigationState(
        investigation_id=investigation_id,
        status=status,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[uuid4()],
        objective="Assess the root indicator through the runner.",
        budget=default_investigation_budget(),
        started_at=_FIXED_TS,
        version=1,
    )


def _terminal_like(state: InvestigationState) -> InvestigationState:
    """Return a COMPLETED copy of a running state with a stop reason."""
    return state.model_copy(
        update={
            "status": InvestigationStatus.COMPLETED,
            "stop_reason": StopReason.SUFFICIENT_EVIDENCE.value,
            "version": (state.version or 0) + 1,
        }
    )


class _NeverCallProvider(EvidenceProvider):
    """Provide identity while failing if provider I/O is ever attempted."""

    def __init__(self) -> None:
        self.calls: list[object] = []

    @property
    def id(self) -> str:
        """Return the deterministic source URN."""
        return SourceId.GOOGLE_PUBLIC_DNS.value

    def supports(self, entity: Entity) -> bool:
        """Declare support for the scenario domain entity."""
        return entity.type is EntityType.DOMAIN

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        del investigation_id, entity
        self.calls.append(("investigate",))
        raise AssertionError("runner unit tests must never invoke a provider")


class _RecordingAnalysisExecutor(AnalysisExecutor):
    """Analysis executor spy that records requests and validates bindings."""

    def __init__(self, *, bound_investigation_id: UUID | None = None) -> None:
        self._bound_investigation_id = bound_investigation_id
        self.calls: list[UUID] = []

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the configured binding."""
        return self._bound_investigation_id

    async def analyze(self, investigation_id: UUID) -> AnalysisOutcome:
        """Record the request; unit tests must never analyze."""
        self.calls.append(investigation_id)
        raise AssertionError("runner unit tests must never invoke analysis")


class _AnalysisFactorySpy:
    """Record every analysis-executor construction request."""

    def __init__(self, tracker: _UowTracker | None = None) -> None:
        self._tracker = tracker
        self.calls: list[UUID] = []
        self.executors: list[_RecordingAnalysisExecutor] = []

    def __call__(self, investigation_id: UUID) -> _RecordingAnalysisExecutor:
        """Create a fresh executor bound to the requested investigation."""
        if self._tracker is not None:
            assert self._tracker.current_open == 0
        self.calls.append(investigation_id)
        executor = _RecordingAnalysisExecutor(bound_investigation_id=investigation_id)
        self.executors.append(executor)
        return executor


class _FakeGraph:
    """Minimal compiled-graph stand-in recording inputs and configs."""

    def __init__(
        self, handler: Callable[[object, object], Awaitable[dict[str, object]]]
    ) -> None:
        self._handler = handler
        self.inputs: list[object] = []
        self.configs: list[object] = []

    async def ainvoke(
        self, input: object, config: object | None = None, **kwargs: object
    ) -> dict[str, object]:
        """Record the invocation and delegate to the scripted handler."""
        del kwargs
        self.inputs.append(input)
        self.configs.append(config)
        return await self._handler(input, config)


class _GraphFactorySpy:
    """Record how the production graph factory is composed per run."""

    def __init__(self, graph: _FakeGraph) -> None:
        self._graph = graph
        self.calls: list[tuple[object, object, object, object]] = []

    def __call__(
        self,
        *,
        uow_factory: object,
        provider_registry: object,
        context: object,
        analysis_executor: object,
        **kwargs: object,
    ) -> _FakeGraph:
        """Record the composed seams and return the scripted graph."""
        del kwargs
        self.calls.append((uow_factory, provider_registry, context, analysis_executor))
        return self._graph


def _default_registry() -> dict[SourceId, EvidenceProvider]:
    """Return the default never-call provider registry."""
    return {SourceId.GOOGLE_PUBLIC_DNS: _NeverCallProvider()}


def _runner(
    store: dict[UUID, InvestigationState],
    tracker: _UowTracker,
    analysis_factory: Callable[[UUID], _RecordingAnalysisExecutor],
    *,
    registry: dict[SourceId, EvidenceProvider] | None = None,
    recursion_limit: int = 40,
) -> LocalInvestigationRunner:
    """Build a runner over the fake store and tracker."""
    return LocalInvestigationRunner(
        uow_factory=cast(Callable[[], object], _uow_factory_for(store, tracker)),  # type: ignore[arg-type]
        provider_registry=registry if registry is not None else _default_registry(),
        analysis_executor_factory=analysis_factory,
        clock=lambda: _FIXED_TS,
        recursion_limit=recursion_limit,
    )


@pytest.mark.asyncio
async def test_u1_missing_investigation_raises_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U1: a missing Investigation raises the typed existing error."""
    store: dict[UUID, InvestigationState] = {}
    tracker = _UowTracker()
    analysis_factory = _AnalysisFactorySpy()
    exploding_graph = _FakeGraph(
        lambda _input, _config: (_ for _ in ()).throw(
            AssertionError("graph must not be built for a missing investigation")
        )
    )
    spy = _GraphFactorySpy(exploding_graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, analysis_factory)
    with pytest.raises(InvestigationNotFoundError):
        await runner.run(INVESTIGATION_A)
    assert analysis_factory.calls == []
    assert spy.calls == []
    assert tracker.open_count() == 1
    assert tracker.current_open == 0


@pytest.mark.asyncio
async def test_u2_completed_investigation_is_side_effect_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U2: a COMPLETED Investigation is returned without graph execution."""
    persisted = _state(INVESTIGATION_A, status=InvestigationStatus.COMPLETED)
    store = {INVESTIGATION_A: persisted}
    tracker = _UowTracker()
    analysis_factory = _AnalysisFactorySpy()
    spy = _GraphFactorySpy(
        _FakeGraph(
            lambda _input, _config: (_ for _ in ()).throw(
                AssertionError("graph must not run for a terminal investigation")
            )
        )
    )
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, analysis_factory)
    result = await runner.run(INVESTIGATION_A)
    assert result == persisted
    assert analysis_factory.calls == []
    assert spy.calls == []
    assert tracker.open_count() == 1


@pytest.mark.asyncio
async def test_u3_failed_investigation_is_side_effect_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U3: a FAILED Investigation is returned without graph execution."""
    persisted = _state(INVESTIGATION_A, status=InvestigationStatus.FAILED)
    store = {INVESTIGATION_A: persisted}
    tracker = _UowTracker()
    analysis_factory = _AnalysisFactorySpy()
    spy = _GraphFactorySpy(
        _FakeGraph(
            lambda _input, _config: (_ for _ in ()).throw(
                AssertionError("graph must not run for a terminal investigation")
            )
        )
    )
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, analysis_factory)
    result = await runner.run(INVESTIGATION_A)
    assert result == persisted
    assert analysis_factory.calls == []
    assert spy.calls == []
    assert tracker.current_open == 0


@pytest.mark.asyncio
async def test_u4_running_investigation_executes_one_bound_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U4: one RUNNING investigation gets one bound execution."""

    async def handler(input: object, config: object) -> dict[str, object]:
        del config
        assert isinstance(input, dict)
        investigation = input["investigation"]
        assert isinstance(investigation, InvestigationState)
        terminal = _terminal_like(investigation)
        store[INVESTIGATION_A] = terminal
        return {"investigation": terminal}

    persisted = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    store = {INVESTIGATION_A: persisted}
    tracker = _UowTracker()
    analysis_factory = _AnalysisFactorySpy()
    graph = _FakeGraph(handler)
    spy = _GraphFactorySpy(graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    expected_registry = _default_registry()
    runner = _runner(store, tracker, analysis_factory, registry=expected_registry)
    result = await runner.run(INVESTIGATION_A)
    assert result.investigation_id == INVESTIGATION_A
    assert result.status is InvestigationStatus.COMPLETED
    assert analysis_factory.calls == [INVESTIGATION_A]
    assert len(spy.calls) == 1
    _factory, registry, context, executor = spy.calls[0]
    created = analysis_factory.executors[0]
    assert executor is created
    assert created.bound_investigation_id == INVESTIGATION_A
    assert context.investigation_id == INVESTIGATION_A  # type: ignore[attr-defined]
    assert cast(dict[SourceId, EvidenceProvider], registry) == expected_registry
    assert graph.inputs[0] == {"investigation": persisted}


@pytest.mark.asyncio
async def test_u5_same_runner_runs_two_investigations_with_fresh_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U5: one runner executes A then B with fresh per-run bindings."""

    async def handler(input: object, config: object) -> dict[str, object]:
        del config
        assert isinstance(input, dict)
        investigation = input["investigation"]
        assert isinstance(investigation, InvestigationState)
        terminal = _terminal_like(investigation)
        store[investigation.investigation_id] = terminal
        return {"investigation": terminal}

    state_a = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    state_b = _state(INVESTIGATION_B, status=InvestigationStatus.RUNNING)
    store = {INVESTIGATION_A: state_a, INVESTIGATION_B: state_b}
    tracker = _UowTracker()
    analysis_factory = _AnalysisFactorySpy()
    graph = _FakeGraph(handler)
    spy = _GraphFactorySpy(graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, analysis_factory)
    result_a = await runner.run(INVESTIGATION_A)
    result_b = await runner.run(INVESTIGATION_B)
    assert result_a.investigation_id == INVESTIGATION_A
    assert result_b.investigation_id == INVESTIGATION_B
    assert analysis_factory.calls == [INVESTIGATION_A, INVESTIGATION_B]
    assert len(analysis_factory.executors) == 2
    assert [e.bound_investigation_id for e in analysis_factory.executors] == [
        INVESTIGATION_A,
        INVESTIGATION_B,
    ]
    assert len(spy.calls) == 2
    contexts = [call[2].investigation_id for call in spy.calls]  # type: ignore[attr-defined]
    assert contexts == [INVESTIGATION_A, INVESTIGATION_B]
    executors = [call[3] for call in spy.calls]
    assert executors == analysis_factory.executors


@pytest.mark.asyncio
async def test_u6_conflicting_analysis_binding_fails_before_execution() -> None:
    """U6: a B-bound executor for investigation A fails at composition."""
    persisted = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    store = {INVESTIGATION_A: persisted}
    tracker = _UowTracker()
    analysis_factory = _AnalysisFactorySpy()
    # Returning a B-bound executor triggers the real factory's binding check,
    # which must fire before any provider or graph work begins.
    analysis_factory.executors = [
        _RecordingAnalysisExecutor(bound_investigation_id=INVESTIGATION_B)
    ]
    provider = _NeverCallProvider()
    registry = {SourceId.GOOGLE_PUBLIC_DNS: provider}

    def bad_factory(investigation_id: UUID) -> _RecordingAnalysisExecutor:
        analysis_factory.calls.append(investigation_id)
        return analysis_factory.executors[0]

    runner = LocalInvestigationRunner(
        uow_factory=cast(Callable[[], object], _uow_factory_for(store, tracker)),  # type: ignore[arg-type]
        provider_registry=registry,
        analysis_executor_factory=bad_factory,
        clock=lambda: _FIXED_TS,
    )
    # The real production graph factory performs the binding validation.
    with pytest.raises(ValueError, match="binding conflict"):
        await runner.run(INVESTIGATION_A)
    assert analysis_factory.calls == [INVESTIGATION_A]
    assert provider.calls == []
    assert tracker.current_open == 0
    # Investigation B's durable state was never touched.
    assert INVESTIGATION_B not in store


@pytest.mark.asyncio
async def test_u7_graph_receives_exact_persisted_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U7: the graph input is the exact authoritative persisted state."""
    capture: list[object] = []

    async def handler(input: object, config: object) -> dict[str, object]:
        del config
        capture.append(input)
        assert isinstance(input, dict)
        investigation = input["investigation"]
        assert isinstance(investigation, InvestigationState)
        terminal = _terminal_like(investigation)
        store[INVESTIGATION_A] = terminal
        return {"investigation": terminal}

    persisted = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    store = {INVESTIGATION_A: persisted}
    tracker = _UowTracker()
    graph = _FakeGraph(handler)
    spy = _GraphFactorySpy(graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, _AnalysisFactorySpy())
    await runner.run(INVESTIGATION_A)
    assert isinstance(capture[0], dict)
    assert capture[0]["investigation"] == persisted


@pytest.mark.asyncio
async def test_u8_non_terminal_graph_output_raises_lifecycle_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U8: a graph result still RUNNING raises the typed lifecycle error."""
    store: dict[UUID, InvestigationState] = {
        INVESTIGATION_A: _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    }

    async def handler(input: object, config: object) -> dict[str, object]:
        del config
        assert isinstance(input, dict)
        investigation = input["investigation"]
        assert isinstance(investigation, InvestigationState)
        return {"investigation": investigation}

    tracker = _UowTracker()
    graph = _FakeGraph(handler)
    spy = _GraphFactorySpy(graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, _AnalysisFactorySpy())
    with pytest.raises(InvestigationRunnerLifecycleError):
        await runner.run(INVESTIGATION_A)
    assert tracker.current_open == 0


@pytest.mark.asyncio
async def test_u9_graph_durable_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U9: graph output and durable state disagreeing fails closed."""
    persisted = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    store = {INVESTIGATION_A: persisted}

    async def handler(input: object, config: object) -> dict[str, object]:
        del config
        assert isinstance(input, dict)
        investigation = input["investigation"]
        assert isinstance(investigation, InvestigationState)
        terminal = _terminal_like(investigation)
        # The durable row contradicts the graph output on the stop reason.
        store[INVESTIGATION_A] = terminal.model_copy(
            update={"stop_reason": StopReason.NO_ELIGIBLE_PIVOTS.value}
        )
        return {"investigation": terminal}

    tracker = _UowTracker()
    graph = _FakeGraph(handler)
    spy = _GraphFactorySpy(graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, _AnalysisFactorySpy())
    with pytest.raises(InvestigationRunnerPersistenceMismatchError):
        await runner.run(INVESTIGATION_A)
    assert tracker.current_open == 0


@pytest.mark.asyncio
async def test_u10_matching_durable_state_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U10: a graph/durable agreement returns the durable reload."""
    persisted = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    store = {INVESTIGATION_A: persisted}

    async def handler(input: object, config: object) -> dict[str, object]:
        del config
        assert isinstance(input, dict)
        investigation = input["investigation"]
        assert isinstance(investigation, InvestigationState)
        terminal = _terminal_like(investigation)
        store[INVESTIGATION_A] = terminal
        return {"investigation": terminal}

    tracker = _UowTracker()
    graph = _FakeGraph(handler)
    spy = _GraphFactorySpy(graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, _AnalysisFactorySpy())
    result = await runner.run(INVESTIGATION_A)
    # The returned state is the durable reload, not the graph snapshot: its
    # identity object is the store's terminal state and the tracked loads
    # prove the final reload happened after graph completion.
    assert result is store[INVESTIGATION_A]
    assert result.status is InvestigationStatus.COMPLETED
    assert tracker.events == ["open", "close", "open", "close"]


@pytest.mark.asyncio
async def test_u11_cancellation_propagates_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U11: asyncio.CancelledError propagates without a fatal stop."""
    store: dict[UUID, InvestigationState] = {
        INVESTIGATION_A: _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    }
    tracker = _UowTracker()
    graph = _FakeGraph(
        lambda _input, _config: (_ for _ in ()).throw(asyncio.CancelledError())
    )
    spy = _GraphFactorySpy(graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, _AnalysisFactorySpy())
    with pytest.raises(asyncio.CancelledError):
        await runner.run(INVESTIGATION_A)
    # The durable row stays RUNNING: cancellation never translates into a
    # terminal transition, and no analysis executor or graph side effects ran.
    assert store[INVESTIGATION_A].status is InvestigationStatus.RUNNING
    assert tracker.current_open == 0


@pytest.mark.asyncio
async def test_u12_short_transaction_boundary_closed_during_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U12: no UnitOfWork is open during graph execution, and the final
    reload starts only after graph completion."""
    persisted = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    store = {INVESTIGATION_A: persisted}
    tracker = _UowTracker()
    analysis_factory = _AnalysisFactorySpy(tracker=tracker)
    observed_during_graph: list[int] = []

    async def handler(input: object, config: object) -> dict[str, object]:
        del config
        observed_during_graph.append(tracker.current_open)
        assert isinstance(input, dict)
        investigation = input["investigation"]
        assert isinstance(investigation, InvestigationState)
        terminal = _terminal_like(investigation)
        store[INVESTIGATION_A] = terminal
        return {"investigation": terminal}

    graph = _FakeGraph(handler)
    spy = _GraphFactorySpy(graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, analysis_factory)
    await runner.run(INVESTIGATION_A)
    assert observed_during_graph == [0]
    # The initial load closed before graph execution and the final reload
    # closed before return: the runner never holds a transaction open.
    assert tracker.events == ["open", "close", "open", "close"]


@pytest.mark.parametrize("recursion_limit", [0, -1])
def test_u13_non_positive_recursion_limit_is_rejected(recursion_limit: int) -> None:
    """U13: a non-positive recursion limit is rejected at construction."""
    store: dict[UUID, InvestigationState] = {}
    tracker = _UowTracker()
    with pytest.raises(ValueError, match="recursion_limit must be positive"):
        _runner(
            store,
            tracker,
            _AnalysisFactorySpy(),
            recursion_limit=recursion_limit,
        )


@pytest.mark.asyncio
async def test_unsupported_non_terminal_status_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invariant H: a PENDING Investigation fails closed before any seam."""
    persisted = _state(INVESTIGATION_A, status=InvestigationStatus.PENDING)
    store = {INVESTIGATION_A: persisted}
    tracker = _UowTracker()
    analysis_factory = _AnalysisFactorySpy()
    spy = _GraphFactorySpy(
        _FakeGraph(
            lambda _input, _config: (_ for _ in ()).throw(
                AssertionError("graph must not run for a PENDING investigation")
            )
        )
    )
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, analysis_factory)
    with pytest.raises(InvestigationRunnerLifecycleError):
        await runner.run(INVESTIGATION_A)
    assert analysis_factory.calls == []
    assert spy.calls == []
    assert tracker.current_open == 0


@pytest.mark.asyncio
async def test_non_state_graph_output_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A graph result that is not an InvestigationState is rejected."""
    store: dict[UUID, InvestigationState] = {
        INVESTIGATION_A: _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
    }

    async def handler(input: object, config: object) -> dict[str, object]:
        del input, config
        return {"investigation": "not-an-investigation-state"}

    tracker = _UowTracker()
    graph = _FakeGraph(handler)
    spy = _GraphFactorySpy(graph)
    monkeypatch.setattr(runner_module, "build_provider_investigation_graph", spy)
    runner = _runner(store, tracker, _AnalysisFactorySpy())
    with pytest.raises(InvestigationRunnerLifecycleError):
        await runner.run(INVESTIGATION_A)
    assert tracker.current_open == 0
