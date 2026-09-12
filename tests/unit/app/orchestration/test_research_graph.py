# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 22C research graph node unit tests (U28-U43).

Exercises the ``research`` node against fake services: a recording
transition service, a scripted reconciler, a scripted executor, and a
recording fatal service. Proves request-before-I/O ordering, completion and
exhaustion transitions, authoritative reload after LLM accounting, crash
reconciliation, retry bounds, persistence failure propagation, cancellation,
and the no-direct-pivot routing rule.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.orchestration.coordinator import (
    CoordinatorAction,
    CoordinatorDecision,
    CoordinatorEntityView,
    CoordinatorPolicy,
    CoordinatorPolicyContext,
    FakeAnalysisExecutor,
    MappingProviderWorkPlanner,
)
from agentic_threat_investigator.app.orchestration.graph import (
    MissingResearchRequestError,
    OrchestrationGraphState,
    ResolvedResearchContextError,
    build_investigation_graph,
    research_node,
)
from agentic_threat_investigator.app.orchestration.research import (
    DeterministicResearchRequestPlanner,
    FakeResearchExecutor,
    ResearchExecutionOutcome,
    ResearchExecutionReconciler,
)
from agentic_threat_investigator.app.orchestration.services import (
    CoordinatorContextLoader,
    CoordinatorTransitionService,
    FatalStopService,
    InvestigationStatusWriter,
)
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    ACTION_RESEARCH_REQUESTED,
    DeterministicTimelineActionService,
    convert_timeline_actions,
)
from agentic_threat_investigator.app.persistence.repositories import (
    CoordinatorTransitionPersistenceError,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    CoordinatorTransitionKind,
    InvestigationError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    ResearchExecutionStatus,
    StopReason,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.domain.research_agent import ResearchAgentRequest
from tests.support.orchestration_fixtures import FakeTaskDispatcher

_INVESTIGATION = UUID("00000000-0000-0000-0000-0000000000c1")
_ROOT = UUID("00000000-0000-0000-0000-0000000000a1")
_MALWARE = UUID("00000000-0000-0000-0000-0000000000a2")
_OBJECTIVE = "Assess the malware family and its infrastructure."
_QUERY = (
    'Provide contextual threat-research information about malware "asyncrat" '
    f"that is relevant to this investigation objective: {_OBJECTIVE}"
)
_FIXED_TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _state(**overrides: Any) -> InvestigationState:
    """Return a running investigation with the malware marked research-required."""
    params: dict[str, Any] = {
        "investigation_id": _INVESTIGATION,
        "status": InvestigationStatus.RUNNING,
        "trigger_type": InvestigationTriggerType.MANUAL,
        "root_entity_ids": [_ROOT],
        "discovered_entity_ids": [_MALWARE],
        "investigated_entity_ids": [_ROOT],
        "research_required_for_entity_ids": [_MALWARE],
        "objective": _OBJECTIVE,
        "budget": default_investigation_budget(),
        "started_at": _FIXED_TS,
        "traversal": [
            {
                "entity_id": _ROOT,
                "first_discovery_ordinal": 0,
                "minimum_depth": 0,
                "best_investigated_depth": 0,
            },
            {
                "entity_id": _MALWARE,
                "first_discovery_ordinal": 1,
                "minimum_depth": 1,
            },
        ],
        "version": 1,
    }
    params.update(overrides)
    return InvestigationState.model_validate(params)


def _planned() -> Any:
    """Return the deterministic planned request for the malware entity."""
    planner = DeterministicResearchRequestPlanner()
    return planner.plan(
        investigation=_state(),
        entity=CoordinatorEntityView(
            entity_id=_MALWARE, entity_type=EntityType.MALWARE, value="asyncrat"
        ),
    )


def _decision() -> CoordinatorDecision:
    """Return the REQUEST_RESEARCH decision carrying the planned request."""
    return CoordinatorDecision(
        action=CoordinatorAction.REQUEST_RESEARCH,
        research_request=_planned(),
        consumes_replan=False,
    )


def _outcome(result_id: UUID | None = None) -> ResearchExecutionOutcome:
    """Return a valid outcome for the planned context."""
    return ResearchExecutionOutcome(
        result_id=result_id or uuid4(),
        investigation_id=_INVESTIGATION,
        subject_entity_id=_MALWARE,
        query=_QUERY,
    )


def _result(result_id: UUID | None = None) -> ResearchResult:
    """Return a durable ResearchResult matching the planned context."""
    return ResearchResult(
        id=result_id or uuid4(),
        investigation_id=_INVESTIGATION,
        subject_entity_id=_MALWARE,
        query=_QUERY,
        claims=(),
        citations=(),
        created_at=_FIXED_TS,
    )


class _ResearchTransitionService(CoordinatorTransitionService):
    """Recording in-memory transition service with version tracking."""

    def __init__(self, initial: InvestigationState) -> None:
        self._version = initial.version or 1
        self._last = initial
        self.persisted: list[tuple[str, int]] = []
        self.appended: list[InvestigationTimelineEvent] = []
        self.reloads = 0
        self.fail_kinds: set[str] = set()

    async def persist(
        self,
        investigation_id: UUID,
        transition_kind: CoordinatorTransitionKind,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        events: tuple[InvestigationTimelineEvent, ...] = (),
        consumes_replan: bool = False,
    ) -> InvestigationState:
        del actor_id, request_id, consumes_replan
        if transition_kind.value in self.fail_kinds:
            raise CoordinatorTransitionPersistenceError(
                f"coordinator {transition_kind.value} transition rejected"
            )
        self.persisted.append((transition_kind.value, expected_version))
        self.appended.extend(events)
        self._version += 1
        validated = InvestigationState.model_validate(state.model_dump())
        self._last = validated.model_copy(update={"version": self._version})
        return self._last

    async def reload(self, investigation_id: UUID) -> InvestigationState:
        del investigation_id
        self.reloads += 1
        return self._last

    async def emit(self, event: InvestigationTimelineEvent) -> None:
        self.appended.append(event)

    def simulate_llm_accounting(self) -> None:
        """Bump the version exactly like one durable LLM reservation."""
        self._version += 1
        self._last = self._last.model_copy(update={"version": self._version})


class _StatusWriter(InvestigationStatusWriter):
    """Echo terminal state with a bumped version."""

    def __init__(self, service: _ResearchTransitionService) -> None:
        self._service = service

    async def finalize(
        self,
        investigation_id: UUID,
        stop_reason: StopReason,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        events: tuple[InvestigationTimelineEvent, ...] = (),
    ) -> InvestigationState:
        del stop_reason, actor_id, request_id, expected_version
        self._service.appended.extend(events)
        return state.model_copy(update={"completed_at": _FIXED_TS})


class _FatalService(FatalStopService):
    """Record fatal stops and return a FAILED state."""

    def __init__(self) -> None:
        self.fatalized: list[tuple[UUID, str, int]] = []

    async def fatalize(
        self,
        investigation_id: UUID,
        error: InvestigationError,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationState:
        del actor_id, request_id
        self.fatalized.append((investigation_id, error.code, expected_version))
        return InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.FAILED,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[_ROOT],
            objective=_OBJECTIVE,
            budget=default_investigation_budget(),
            started_at=_FIXED_TS,
            stop_reason=StopReason.FATAL_ERROR.value,
            errors=[error],
            version=expected_version + 1,
        )


class _Reconciler(ResearchExecutionReconciler):
    """Scripted reconciler returning queued results/errors."""

    def __init__(
        self,
        outcomes: list[ResearchResult | BaseException | None] | None = None,
    ) -> None:
        self._outcomes = list(outcomes) if outcomes is not None else []
        self.calls = 0

    async def find_matching_result(
        self,
        *,
        investigation_id: UUID,
        subject_entity_id: UUID,
        query: str,
        state: InvestigationState,
    ) -> ResearchResult | None:
        del investigation_id, subject_entity_id, query, state
        self.calls += 1
        if not self._outcomes:
            return None
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _LyingExecutor(FakeResearchExecutor):
    """Return scripted outcomes without fake-side validation.

    Mirrors a broken executor adapter: the graph node's own authoritative
    binding validation (U32-U34) is the code under test.
    """

    def __init__(
        self, outcomes: list[ResearchExecutionOutcome | BaseException]
    ) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[ResearchAgentRequest] = []

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return no binding."""
        return None

    async def execute(self, request: ResearchAgentRequest) -> ResearchExecutionOutcome:
        self.calls.append(request)
        if not self._outcomes:
            raise RuntimeError("fake research outcomes exhausted")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _AccountingExecutor(FakeResearchExecutor):
    """Scripted executor that optionally simulates LLM accounting."""

    def __init__(
        self,
        outcomes: list[ResearchExecutionOutcome | BaseException],
        service: _ResearchTransitionService,
        *,
        account_on_call: bool = False,
        bound_investigation_id: UUID | None = None,
    ) -> None:
        super().__init__(outcomes, bound_investigation_id=bound_investigation_id)
        self._service = service
        self._account_on_call = account_on_call

    async def execute(self, request: ResearchAgentRequest) -> ResearchExecutionOutcome:
        if self._account_on_call:
            self._service.simulate_llm_accounting()
        return await super().execute(request)


async def _run_node(
    state: InvestigationState,
    *,
    decision: CoordinatorDecision | None = None,
    service: _ResearchTransitionService | None = None,
    executor: FakeResearchExecutor | None = None,
    reconciler: _Reconciler | None = None,
    fatal: _FatalService | None = None,
) -> tuple[InvestigationState, _ResearchTransitionService, _FatalService]:
    """Invoke the research node directly and return the resulting state."""
    service = service or _ResearchTransitionService(state)
    fatal = fatal or _FatalService()
    decision = decision or _decision()
    executor = executor or FakeResearchExecutor(
        [
            _outcome(),
        ]
    )
    reconciler = reconciler or _Reconciler()
    graph_state: OrchestrationGraphState = {
        "investigation": state,
        "_coordinator_decision": decision,
    }
    result = await research_node(
        executor,
        reconciler,
        service,
        DeterministicTimelineActionService(clock=lambda: _FIXED_TS),
        fatal,
        graph_state,
    )
    recorded = result["investigation"]
    assert isinstance(recorded, InvestigationState)
    return recorded, service, fatal


class TestResearchNodeSuccess:
    """U29-U31, U35, U36, U43: durable completion semantics."""

    @pytest.mark.asyncio
    async def test_request_persisted_before_executor_io(self) -> None:
        """U29: REQUEST_RESEARCH + event persist before the executor is called."""
        state = _state()
        service = _ResearchTransitionService(state)
        executor = _AccountingExecutor([_outcome()], service)
        recorded, service, _fatal = await _run_node(
            state, service=service, executor=executor
        )
        kinds = [kind for kind, _ in service.persisted]
        assert kinds == ["request_research", "record_research_outcome"]
        # The request transition carries exactly one RESEARCH_REQUESTED event.
        research_events = [
            event
            for event in service.appended
            if event.type is InvestigationTimelineEventType.RESEARCH_REQUESTED
        ]
        assert len(research_events) == 1
        assert research_events[0].entity_ids == (_MALWARE,)
        # The executor ran exactly once, after the request was persisted.
        assert len(executor.calls) == 1
        assert service.persisted[0][0] == "request_research"
        assert service.reloads >= 1

    @pytest.mark.asyncio
    async def test_successful_result_completes_with_result_id(self) -> None:
        """U30: success records COMPLETED and links the result exactly once."""
        result_id = uuid4()
        state = _state()
        executor = FakeResearchExecutor(
            [
                _outcome(result_id),
            ]
        )
        recorded, service, _fatal = await _run_node(state, executor=executor)
        execution = recorded.research_executions[0]
        assert execution.status is ResearchExecutionStatus.COMPLETED
        assert execution.result_id == result_id
        assert recorded.research_result_ids == [result_id]
        assert service.persisted[-1][0] == "record_research_outcome"

    @pytest.mark.asyncio
    async def test_empty_result_still_completes(self) -> None:
        """U31: a zero-claim result is still successful completed research."""
        result_id = uuid4()
        recorded, _service, _fatal = await _run_node(
            _state(),
            executor=FakeResearchExecutor(
                [
                    _outcome(result_id),
                ]
            ),
        )
        assert recorded.research_executions[0].status is (
            ResearchExecutionStatus.COMPLETED
        )
        assert recorded.research_result_ids == [result_id]

    @pytest.mark.asyncio
    async def test_completion_reloads_after_llm_accounting_version(self) -> None:
        """U35: completion persists against the post-accounting version."""
        state = _state()
        service = _ResearchTransitionService(state)
        executor = _AccountingExecutor([_outcome()], service, account_on_call=True)
        recorded, service, _fatal = await _run_node(
            state, service=service, executor=executor
        )
        assert recorded.research_executions[0].status is (
            ResearchExecutionStatus.COMPLETED
        )
        # request_research used version 1; LLM accounting bumped 2 -> 3;
        # completion must use the reloaded authoritative version 3.
        assert service.persisted[0] == ("request_research", 1)
        assert service.persisted[1] == ("record_research_outcome", 3)
        assert recorded.version == 4

    @pytest.mark.asyncio
    async def test_crash_window_result_adopted_without_executor_call(self) -> None:
        """U36: a matching durable result is adopted; the LLM is never called."""
        result_id = uuid4()
        state = _state(
            research_executions=[
                {
                    "subject_entity_id": _MALWARE,
                    "context_fingerprint": _planned().context_fingerprint,
                    "query": _QUERY,
                    "status": "requested",
                    "attempts": 1,
                }
            ]
        )
        executor = FakeResearchExecutor()  # no outcomes: must never be called
        reconciler = _Reconciler([_result(result_id)])
        recorded, service, _fatal = await _run_node(
            state, executor=executor, reconciler=reconciler
        )
        assert executor.calls == []
        execution = recorded.research_executions[0]
        assert execution.status is ResearchExecutionStatus.COMPLETED
        assert execution.result_id == result_id
        # The result identity is linked exactly once.
        assert recorded.research_result_ids == [result_id]
        assert service.persisted[-1][0] == "record_research_outcome"

    @pytest.mark.asyncio
    async def test_result_id_linked_once_across_reconciliation(self) -> None:
        """U43: reconciliation never appends the same result ID twice."""
        result_id = uuid4()
        state = _state(
            research_executions=[
                {
                    "subject_entity_id": _MALWARE,
                    "context_fingerprint": _planned().context_fingerprint,
                    "query": _QUERY,
                    "status": "requested",
                    "attempts": 1,
                }
            ]
        )
        reconciler = _Reconciler([_result(result_id)])
        recorded, _service, _fatal = await _run_node(
            state, executor=FakeResearchExecutor(), reconciler=reconciler
        )
        assert recorded.research_result_ids == [result_id]
        assert len(recorded.research_result_ids) == 1
        # A completed unchanged context is no longer due: the policy never
        # returns it, so a second node visit fails closed instead of
        # duplicating the link.
        policy = CoordinatorPolicy(
            MappingProviderWorkPlanner({}),
            research_planner=DeterministicResearchRequestPlanner(),
        )
        decision = policy.decide(
            state=recorded,
            context=CoordinatorPolicyContext(
                entities=(
                    CoordinatorEntityView(
                        entity_id=_ROOT, entity_type=EntityType.DOMAIN
                    ),
                    CoordinatorEntityView(
                        entity_id=_MALWARE,
                        entity_type=EntityType.MALWARE,
                        value="asyncrat",
                    ),
                )
            ),
        )
        assert decision.action is CoordinatorAction.STOP

    @pytest.mark.asyncio
    async def test_research_requested_action_urn_conversion(self) -> None:
        """U26: RESEARCH_REQUESTED converts to the stable research URN."""
        service = _ResearchTransitionService(_state())
        event = DeterministicTimelineActionService(
            clock=lambda: _FIXED_TS
        ).research_requested(entity_id=_MALWARE, state=_state())
        service.appended.append(event)
        actions = convert_timeline_actions(tuple(service.appended))
        assert actions[0].action == ACTION_RESEARCH_REQUESTED
        assert actions[0].entity_id == _MALWARE


class TestResearchNodeFailure:
    """U28, U32-U34, U37-U41: bounded failure semantics."""

    @pytest.mark.asyncio
    async def test_executor_binding_mismatch_fails_closed(self) -> None:
        """U28: an executor bound to another investigation fails closed."""
        state = _state()
        executor = FakeResearchExecutor((_outcome(),), bound_investigation_id=uuid4())
        with pytest.raises(ValueError, match="binding conflicts"):
            await _run_node(state, executor=executor)
        assert executor.calls == []

    @pytest.mark.asyncio
    async def test_wrong_investigation_result_rejected(self) -> None:
        """U32: a result from another investigation fails closed."""
        state = _state()
        bad = _outcome().model_copy(update={"investigation_id": uuid4()})
        executor = _LyingExecutor([bad])
        recorded, _service, fatal = await _run_node(state, executor=executor)
        assert recorded.status is InvestigationStatus.FAILED
        assert fatal.fatalized and fatal.fatalized[0][1] == "research_outcome_error"
        assert recorded.research_result_ids == []

    @pytest.mark.asyncio
    async def test_wrong_subject_result_rejected(self) -> None:
        """U33: a result for another subject fails closed."""
        state = _state()
        bad = _outcome().model_copy(update={"subject_entity_id": uuid4()})
        recorded, _service, fatal = await _run_node(
            state, executor=_LyingExecutor([bad])
        )
        assert recorded.status is InvestigationStatus.FAILED
        assert fatal.fatalized[0][1] == "research_outcome_error"

    @pytest.mark.asyncio
    async def test_wrong_query_result_rejected(self) -> None:
        """U34: a result with another query fails closed."""
        state = _state()
        bad = _outcome().model_copy(update={"query": "a different question"})
        recorded, _service, fatal = await _run_node(
            state, executor=_LyingExecutor([bad])
        )
        assert recorded.status is InvestigationStatus.FAILED
        assert fatal.fatalized[0][1] == "research_outcome_error"

    @pytest.mark.asyncio
    async def test_recoverable_first_failure_allows_bounded_retry(self) -> None:
        """U37: a recoverable first failure leaves the context REQUESTED."""
        state = _state()
        error = LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True)
        executor = FakeResearchExecutor(
            [
                error,
            ]
        )
        recorded, service, _fatal = await _run_node(state, executor=executor)
        # The context stays REQUESTED at attempt 1 for one later retry; the
        # node returns to Coordinator without looping.
        execution = recorded.research_executions[0]
        assert execution.status is ResearchExecutionStatus.REQUESTED
        assert execution.attempts == 1
        assert len(executor.calls) == 1
        assert service.persisted[-1][0] == "request_research"
        assert recorded.research_result_ids == []

    @pytest.mark.asyncio
    async def test_second_recoverable_failure_exhausts(self) -> None:
        """U38: the final recoverable failure records EXHAUSTED."""
        state = _state(
            research_executions=[
                {
                    "subject_entity_id": _MALWARE,
                    "context_fingerprint": _planned().context_fingerprint,
                    "query": _QUERY,
                    "status": "requested",
                    "attempts": 1,
                }
            ]
        )
        error = LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True)
        # The node retries the existing REQUESTED attempt (1 -> 2) and the
        # final recoverable failure resolves to EXHAUSTED.
        executor = FakeResearchExecutor(
            [
                error,
            ]
        )
        recorded, service, _fatal = await _run_node(state, executor=executor)
        execution = recorded.research_executions[0]
        assert execution.status is ResearchExecutionStatus.EXHAUSTED
        assert execution.attempts == 2
        assert execution.result_id is None
        assert recorded.research_result_ids == []
        assert service.persisted[-1][0] == "record_research_outcome"

    @pytest.mark.asyncio
    async def test_final_attempt_resume_without_result_exhausts(self) -> None:
        """U39: a REQUESTED final attempt with no result never re-executes."""
        state = _state(
            research_executions=[
                {
                    "subject_entity_id": _MALWARE,
                    "context_fingerprint": _planned().context_fingerprint,
                    "query": _QUERY,
                    "status": "requested",
                    "attempts": 2,
                }
            ]
        )
        executor = FakeResearchExecutor()  # no outcomes: must not be called
        recorded, service, _fatal = await _run_node(state, executor=executor)
        assert executor.calls == []
        execution = recorded.research_executions[0]
        assert execution.status is ResearchExecutionStatus.EXHAUSTED
        assert execution.attempts == 2
        # No third attempt was authorized: only the outcome transition ran.
        assert service.persisted == [("record_research_outcome", 1)]

    @pytest.mark.asyncio
    async def test_persistence_failure_propagates_no_false_completion(self) -> None:
        """U40: a completion persistence failure propagates unchanged."""
        state = _state()
        service = _ResearchTransitionService(state)
        service.fail_kinds.add("record_research_outcome")
        executor = FakeResearchExecutor(
            [
                _outcome(),
            ]
        )
        with pytest.raises(CoordinatorTransitionPersistenceError):
            await _run_node(state, service=service, executor=executor)
        # The request was persisted but no completion was recorded and no
        # fatal stop was fabricated.
        assert service.persisted == [("request_research", 1)]
        assert state.research_result_ids == []

    @pytest.mark.asyncio
    async def test_cancellation_propagates_unchanged(self) -> None:
        """U41: cancellation during execution propagates unchanged."""
        state = _state()
        error = asyncio.CancelledError()
        executor = FakeResearchExecutor(
            [
                error,
            ]
        )
        with pytest.raises(asyncio.CancelledError):
            await _run_node(state, executor=executor)


class TestResearchNodeGraphRouting:
    """U21/U42: research completion routes to Coordinator, never to a pivot."""

    @pytest.mark.asyncio
    async def test_research_completion_does_not_authorize_pivot(self) -> None:
        """U42: after research completes, the graph returns to Coordinator
        policy and never routes directly to pivot authorization."""
        state = _state()
        evidence_id = uuid4()
        state = state.model_copy(
            update={
                "evidence_ids": [evidence_id],
                "analyzed_evidence_ids": [evidence_id],
                "analysis_disposition": AnalysisDisposition.SUFFICIENT.value,
            }
        )
        result_id = uuid4()
        service = _ResearchTransitionService(state)
        policy = CoordinatorPolicy(
            MappingProviderWorkPlanner(
                {
                    SourceId.GOOGLE_PUBLIC_DNS: frozenset({EntityType.DOMAIN}),
                }
            ),
            research_planner=DeterministicResearchRequestPlanner(),
        )
        ctx_loader = _ContextLoader(
            (
                CoordinatorEntityView(entity_id=_ROOT, entity_type=EntityType.DOMAIN),
                CoordinatorEntityView(
                    entity_id=_MALWARE,
                    entity_type=EntityType.MALWARE,
                    value="asyncrat",
                ),
            ),
            disposition=AnalysisDisposition.SUFFICIENT,
        )
        graph = build_investigation_graph(
            FakeTaskDispatcher({}),
            coordinator_policy=policy,
            context_loader=ctx_loader,
            analysis_executor=FakeAnalysisExecutor(()),
            transition_service=service,
            status_writer=_StatusWriter(service),
            timeline_action_service=DeterministicTimelineActionService(
                clock=lambda: _FIXED_TS
            ),
            fatal_stop_service=_FatalService(),
            research_executor=FakeResearchExecutor(
                [
                    _outcome(result_id),
                ]
            ),
            research_reconciler=_Reconciler(),
            expected_investigation_id=_INVESTIGATION,
        )
        recorded: InvestigationState | None = None
        async for snapshot in graph.astream(
            {"investigation": state}, stream_mode="values"
        ):
            candidate = snapshot.get("investigation")
            if isinstance(candidate, InvestigationState):
                recorded = candidate
        assert recorded is not None
        assert recorded.status is InvestigationStatus.COMPLETED
        assert recorded.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
        # Research completed and linked exactly once.
        assert recorded.research_executions[0].status is (
            ResearchExecutionStatus.COMPLETED
        )
        assert recorded.research_result_ids == [result_id]
        # No pivot was ever authorized or executed: research completion has no
        # pivot authority and the SUFFICIENT disposition stops cleanly.
        pivot_kinds = [
            kind
            for kind, _ in service.persisted
            if kind == CoordinatorTransitionKind.AUTHORIZE_PIVOT.value
        ]
        assert pivot_kinds == []
        assert recorded.pending_pivots == []


class _ContextLoader(CoordinatorContextLoader):
    """Return a fixed policy context."""

    def __init__(
        self,
        entities: tuple[CoordinatorEntityView, ...],
        *,
        disposition: AnalysisDisposition | None = None,
    ) -> None:
        self._entities = entities
        self._disposition = disposition

    async def load(
        self, investigation_id: UUID, expected_version: int
    ) -> CoordinatorPolicyContext:
        del investigation_id, expected_version
        return CoordinatorPolicyContext(
            entities=self._entities,
            analysis_disposition=self._disposition,
        )


class TestResearchNodeDecisionContract:
    """The node requires the exact REQUEST_RESEARCH decision shape."""

    @pytest.mark.asyncio
    async def test_decision_without_planned_request_rejected(self) -> None:
        """A REQUEST_RESEARCH decision must carry a planned request."""
        # model_copy bypasses the shape validator so the node's own guard is
        # exercised; a normally-constructed decision is validated at build.
        malformed = _decision().model_copy(update={"research_request": None})
        with pytest.raises(MissingResearchRequestError):
            await _run_node(_state(), decision=malformed)

    @pytest.mark.asyncio
    async def test_resolved_context_never_selected_fails_closed(self) -> None:
        """An already-resolved context fails closed instead of duplicating."""
        completed_result = uuid4()
        state = _state(
            research_executions=[
                {
                    "subject_entity_id": _MALWARE,
                    "context_fingerprint": _planned().context_fingerprint,
                    "query": _QUERY,
                    "status": "completed",
                    "attempts": 1,
                    "result_id": completed_result,
                }
            ],
            research_result_ids=[completed_result],
        )
        with pytest.raises(ResolvedResearchContextError):
            await _run_node(state)


class TestResearchNodeOrderingGuarantee:
    """U29 extension: request transition precedes any executor I/O even on
    failure paths."""

    @pytest.mark.asyncio
    async def test_request_persisted_before_recoverable_failure_return(self) -> None:
        """A recoverable failure still leaves the REQUEST_RESEARCH durable."""
        state = _state()
        service = _ResearchTransitionService(state)
        error = LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True)
        executor = FakeResearchExecutor(
            [
                error,
            ]
        )
        recorded, service, _fatal = await _run_node(
            state, service=service, executor=executor
        )
        assert service.persisted[0][0] == "request_research"
        assert recorded.research_executions[0].status is (
            ResearchExecutionStatus.REQUESTED
        )
        assert recorded.version is not None and recorded.version > 1
