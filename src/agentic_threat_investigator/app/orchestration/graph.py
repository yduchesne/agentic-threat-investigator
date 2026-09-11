# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator-integrated LangGraph orchestration (PR 19A + PR 21).

Implements the deterministic workflow:

    START -> initialize -> coordinator -> { EXECUTE_PROVIDER_WORK
                                          | REQUEST_ANALYSIS
                                          | AUTHORIZE_PIVOT
                                          | STOP }

Provider work path: select_work -> execute_work -> record_outcome -> coordinator
Analysis path:       analyze -> coordinator
Pivot path:          authorize_pivot -> coordinator
Stop path:           finalize_stop -> END

The coordinator node applies deterministic policy (CoordinatorPolicy) to
decide the next action. Queue exhaustion no longer routes directly to END.
"""

from __future__ import annotations

import asyncio
from typing import NotRequired, TypedDict
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from agentic_threat_investigator.app.orchestration.coordinator import (
    AnalysisExecutor,
    CoordinatorAction,
    CoordinatorDecision,
    CoordinatorPolicy,
)
from agentic_threat_investigator.app.orchestration.dispatcher import TaskDispatcher
from agentic_threat_investigator.app.orchestration.models import (
    apply_work_selection,
    complete_drained_pivots,
    finalize_stop_state,
    record_provider_outcome,
    select_provider_work,
)
from agentic_threat_investigator.app.orchestration.services import (
    CoordinatorContextLoader,
    CoordinatorTransitionService,
    FatalStopService,
    InvestigationStatusWriter,
)
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    TimelineActionService,
)
from agentic_threat_investigator.domain.investigation import (
    CoordinatorTransitionKind,
    InvestigationError,
    InvestigationState,
    PivotRequest,
    ProviderWorkItem,
    StopReason,
    is_terminal_status,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)


class InvestigationGraphContextMismatchError(ValueError):
    """Raised when graph input does not match its bound investigation.

    A graph built for one investigation must never process an
    ``InvestigationState`` belonging to another investigation. The message is a
    fixed safe string that never embeds identifiers.
    """

    def __init__(self) -> None:
        """Build the fixed safe composition-error message."""
        super().__init__(
            "orchestration graph state does not match the bound investigation context"
        )


class InvestigationGraphBindingConflictError(ValueError):
    """Raised when an explicit graph binding conflicts with the dispatcher.

    The caller supplied an explicit ``expected_investigation_id`` that differs
    from the dispatcher's bound execution destination identity. The message is
    a fixed safe string.
    """

    def __init__(self) -> None:
        """Build the fixed safe binding-conflict message."""
        super().__init__(
            "orchestration graph binding conflicts with the dispatcher "
            "investigation context"
        )


class CoordinatorDependencyError(ValueError):
    """Raised when coordinator dependencies are partially injected.

    The PR 21 coordinator graph requires the policy, context loader, analysis
    executor, transition service, and status writer together. Partial
    composition fails closed at construction instead of silently falling back
    to legacy queue-exhaustion termination.
    """

    def __init__(self) -> None:
        """Build the fixed safe composition-error message."""
        super().__init__(
            "coordinator graph requires all coordinator dependencies; "
            "partial composition is rejected"
        )


class MissingCoordinatorDecisionError(ValueError):
    """Raised when a transition node runs without a stored decision.

    Routing must never fall back to a loop or a silent stop when the decision
    channel is absent; the graph fails closed instead.
    """

    def __init__(self) -> None:
        """Build the fixed safe missing-decision message."""
        super().__init__("coordinator transition requires a stored decision")


class UnknownCoordinatorActionError(ValueError):
    """Raised when a stored decision carries an unknown action."""

    def __init__(self, action: str) -> None:
        """Record the unknown action value without embedding free text."""
        super().__init__(f"unknown coordinator action: {action}")
        self.action = action


class StopWithoutReasonError(ValueError):
    """Raised when a STOP decision lacks a stop reason."""

    def __init__(self) -> None:
        """Build the fixed safe stop-without-reason message."""
        super().__init__("coordinator stop decision requires a stop reason")


class AuthorizeWithoutPivotError(ValueError):
    """Raised when an authorize-with-work decision lacks a matching pivot."""

    def __init__(self) -> None:
        """Build the fixed safe authorize-without-pivot message."""
        super().__init__(
            "coordinator authorize decision with work requires a matching pivot"
        )


class AnalysisPersistenceMismatchError(ValueError):
    """Raised when an analysis outcome does not match the durable state.

    The graph adopts only already-persisted analysis results; an outcome that
    disagrees with the durable Assessment pointer, analyzed Evidence set,
    disposition, or Investigation version fails closed with this typed error
    and no coordinator persistence.
    """

    def __init__(self, message: str) -> None:
        """Record a safe fixed detail message."""
        super().__init__(message)


class OrchestrationGraphState(TypedDict):
    """LangGraph channel state wrapping one serializable investigation state.

    Caller input supplies only ``investigation``; the private decision
    channel is populated by graph nodes and is not required on input.
    """

    investigation: InvestigationState
    _coordinator_decision: NotRequired[CoordinatorDecision | None]


async def initialize(state: OrchestrationGraphState) -> OrchestrationGraphState:
    """Validate that the graph state is usable; perform no I/O or synthesis."""
    if not isinstance(state.get("investigation"), InvestigationState):
        raise ValueError("orchestration state must wrap an InvestigationState")
    return state


def _require_decision(
    state: OrchestrationGraphState, expected: CoordinatorAction
) -> CoordinatorDecision:
    """Return the stored decision, failing closed on any invariant violation."""
    decision = state.get("_coordinator_decision")
    if decision is None:
        raise MissingCoordinatorDecisionError()
    if decision.action is not expected:
        raise UnknownCoordinatorActionError(decision.action.value)
    return decision


async def coordinator_node(
    policy: CoordinatorPolicy,
    context_loader: CoordinatorContextLoader,
    fatal_stop_service: FatalStopService,
    state: OrchestrationGraphState,
) -> OrchestrationGraphState:
    """Decide the next deterministic investigative action.

    Loads the policy context, applies the coordinator policy, and stores the
    complete CoordinatorDecision for routing and execution. An unrecoverable
    context failure (cross-Investigation or stale-version context) is mapped
    to a bounded fatal stop rather than escaping the graph.
    """
    investigation = state["investigation"]
    try:
        context = await context_loader.load(
            investigation.investigation_id, _require_version(investigation)
        )
        decision: CoordinatorDecision = policy.decide(
            state=investigation, context=context
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if _persistence_error(exc):
            raise
        fatal = await fatal_stop_service.fatalize(
            investigation.investigation_id,
            InvestigationError(
                source="orchestration",
                code="coordinator_context_error",
                message="coordinator policy context could not be loaded",
                recoverable=False,
            ),
            expected_version=_require_version(investigation),
        )
        return {
            "investigation": fatal,
            "_coordinator_decision": CoordinatorDecision(
                action=CoordinatorAction.STOP,
                stop_reason=StopReason.FATAL_ERROR,
            ),
        }
    return {
        "investigation": investigation,
        "_coordinator_decision": decision,
    }


async def authorize_pivot_node(
    transition_service: CoordinatorTransitionService,
    timeline_action_service: TimelineActionService,
    state: OrchestrationGraphState,
) -> OrchestrationGraphState:
    """Authorize pivots using the exact stored coordinator decision.

    Applies the decision that was produced and routed, never re-running
    policy, and persists the transition atomically through the transition
    service together with the PIVOT_ENQUEUED action(s).
    """
    decision = _require_decision(state, CoordinatorAction.AUTHORIZE_PIVOT)
    investigation = state["investigation"]

    if decision.work_items:
        if not decision.pivots:
            raise AuthorizeWithoutPivotError()
        pivot = decision.pivots[0]
        # Apply the exact authorized pivot + work + optional replan increment.
        from agentic_threat_investigator.app.orchestration.models import (
            authorize_pivot,
        )

        updated = authorize_pivot(investigation, pivot, list(decision.work_items))
        if decision.consumes_replan:
            budget = updated.budget.model_copy(
                update={"replans_used": updated.budget.replans_used + 1}
            )
            updated = updated.model_copy(update={"budget": budget})
        events = (
            *_rejection_events(decision, timeline_action_service, updated),
            timeline_action_service.pivot_enqueued(pivot=pivot, state=updated),
        )
        persisted = await transition_service.persist(
            investigation.investigation_id,
            CoordinatorTransitionKind.AUTHORIZE_PIVOT,
            updated,
            expected_version=_require_version(investigation),
            events=events,
            consumes_replan=decision.consumes_replan,
        )
        return {
            "investigation": persisted,
            "_coordinator_decision": None,
        }

    # Research-only path: append unique research markers in decision order;
    # never consumes a replan and never creates a pivot or changes the
    # investigated set (matching the MARK_RESEARCH_REQUIRED allowlist).
    research_ids = [
        entity_id
        for entity_id in decision.research_entity_ids
        if entity_id not in investigation.research_required_for_entity_ids
    ]
    updated = investigation.model_copy(
        update={
            "research_required_for_entity_ids": [
                *investigation.research_required_for_entity_ids,
                *research_ids,
            ],
        }
    )
    persisted = await transition_service.persist(
        investigation.investigation_id,
        CoordinatorTransitionKind.MARK_RESEARCH_REQUIRED,
        updated,
        expected_version=_require_version(investigation),
        events=_rejection_events(decision, timeline_action_service, updated),
    )
    return {
        "investigation": persisted,
        "_coordinator_decision": None,
    }


async def select_work(
    transition_service: CoordinatorTransitionService,
    timeline_action_service: TimelineActionService,
    fatal_stop_service: FatalStopService,
    state: OrchestrationGraphState,
) -> OrchestrationGraphState:
    """Select the next FIFO work item and persist the selection atomically.

    The pure FIFO selection is applied, the matching PENDING pivot moves to
    IN_PROGRESS for its first work, the traversal entry records the executed
    depth, and the selection is persisted as ``SELECT_PROVIDER_WORK`` (with a
    PIVOT_EXECUTED action) BEFORE any dispatcher/provider I/O, so a crash
    cannot repeat an external provider call.

    Resume guard: a persisted (non-null) ``current_provider_work`` means the
    item was already selected and provider I/O may have started. PR 21 has no
    delivery-attempt/idempotent retry token, so the graph fails to a bounded
    fatal stop rather than silently re-issuing an external call.
    """
    investigation = state["investigation"]
    if investigation.current_provider_work is not None:
        fatal = await fatal_stop_service.fatalize(
            investigation.investigation_id,
            InvestigationError(
                source="orchestration",
                code="persisted_provider_work_resume",
                message="provider work was persisted in-progress and may have "
                "executed; no retry token exists",
                recoverable=False,
            ),
            expected_version=_require_version(investigation),
        )
        return {
            "investigation": fatal,
            "_coordinator_decision": CoordinatorDecision(
                action=CoordinatorAction.STOP,
                stop_reason=StopReason.FATAL_ERROR,
            ),
        }
    try:
        selected_state = select_provider_work(investigation)
        updated = apply_work_selection(selected_state)
        validated = InvestigationState.model_validate(updated.model_dump())
    except ValueError, TypeError:
        fatal = await fatal_stop_service.fatalize(
            investigation.investigation_id,
            InvestigationError(
                source="orchestration",
                code="provider_selection_error",
                message="provider work selection could not complete safely",
                recoverable=False,
            ),
            expected_version=_require_version(investigation),
        )
        return {
            "investigation": fatal,
            "_coordinator_decision": CoordinatorDecision(
                action=CoordinatorAction.STOP,
                stop_reason=StopReason.FATAL_ERROR,
            ),
        }
    events: tuple[InvestigationTimelineEvent, ...] = ()
    executed_pivot = _matched_pivot(investigation, selected_state.current_provider_work)
    if executed_pivot is not None:
        events = (
            timeline_action_service.pivot_executed(
                pivot=executed_pivot, state=validated
            ),
        )
    persisted = await transition_service.persist(
        investigation.investigation_id,
        CoordinatorTransitionKind.SELECT_PROVIDER_WORK,
        validated,
        expected_version=_require_version(investigation),
        events=events,
    )
    return {
        "investigation": persisted,
        "_coordinator_decision": None,
    }


async def execute_work(
    dispatcher: TaskDispatcher,
    state: OrchestrationGraphState,
    fatal_stop_service: FatalStopService | None = None,
) -> OrchestrationGraphState:
    """Execute provider work, fatalizing only unexpected execution failures."""
    investigation = state["investigation"]
    work_item = investigation.current_provider_work
    if work_item is None:
        raise ValueError("execute_work requires a selected current provider work item")
    try:
        outcome = await dispatcher.dispatch(work_item)
        if outcome.work_item != work_item:
            raise ValueError("dispatcher outcome does not match dispatched work")
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if _persistence_error(exc) or fatal_stop_service is None:
            raise
        fatal = await fatal_stop_service.fatalize(
            investigation.investigation_id,
            InvestigationError(
                source="orchestration",
                code="provider_dispatch_error",
                message="provider dispatch could not complete safely",
                recoverable=False,
            ),
            expected_version=_require_version(investigation),
        )
        return {
            "investigation": fatal,
            "_coordinator_decision": CoordinatorDecision(
                action=CoordinatorAction.STOP,
                stop_reason=StopReason.FATAL_ERROR,
            ),
        }
    return {
        "investigation": investigation.model_copy(
            update={"last_provider_outcome": outcome}
        ),
        "_coordinator_decision": None,
    }


async def record_outcome(
    transition_service: CoordinatorTransitionService,
    timeline_action_service: TimelineActionService,
    state: OrchestrationGraphState,
) -> OrchestrationGraphState:
    """Apply deterministic outcome bookkeeping and persist it atomically.

    The pure bookkeeping is applied first, the resulting state is fully
    validated, then the exact outcome (pending/current/completed work, last
    outcome, the single provider-counter increment, evidence/relationship/
    discovered IDs, traversal metadata, safe errors) is persisted through the
    transition service before the coordinator reads the context again. This
    makes provider-call accounting and discovery durable at the
    synchronization point.
    """
    investigation = state["investigation"]
    outcome = investigation.last_provider_outcome
    if outcome is None:
        raise ValueError("record_outcome requires a recorded provider outcome")
    updated = complete_drained_pivots(record_provider_outcome(investigation, outcome))
    validated = InvestigationState.model_validate(updated.model_dump())
    # Emit one ENTITIES_DISCOVERED action for the newly appended discovery IDs
    # in the same transaction as the outcome state change.
    prior_discovered = set(investigation.discovered_entity_ids)
    new_discoveries = tuple(
        entity_id
        for entity_id in updated.discovered_entity_ids
        if entity_id not in prior_discovered
    )
    events: tuple[InvestigationTimelineEvent, ...] = ()
    if new_discoveries:
        events = (
            timeline_action_service.entities_discovered(
                entity_ids=new_discoveries, state=validated
            ),
        )
    persisted = await transition_service.persist(
        investigation.investigation_id,
        CoordinatorTransitionKind.RECORD_PROVIDER_OUTCOME,
        validated,
        expected_version=_require_version(investigation),
        events=events,
    )
    return {
        "investigation": persisted,
        "_coordinator_decision": None,
    }


async def analyze(
    analysis_executor: AnalysisExecutor,
    transition_service: CoordinatorTransitionService,
    timeline_action_service: TimelineActionService,
    fatal_stop_service: FatalStopService,
    state: OrchestrationGraphState,
) -> OrchestrationGraphState:
    """Run the Evidence Analyst and adopt the authoritative persisted state.

    The executor runs outside any UoW and returns only information about
    already-persisted analysis. The authoritative Investigation is then
    reloaded and required to match the outcome exactly: Assessment pointer,
    ordered analyzed Evidence identities, typed disposition, and version.
    Any mismatch raises a typed analysis-persistence error; the graph never
    manufactures analytical provenance from a fake or unpersisted outcome.
    """
    investigation = state["investigation"]
    if (
        analysis_executor.bound_investigation_id is not None
        and analysis_executor.bound_investigation_id != investigation.investigation_id
    ):
        raise InvestigationGraphBindingConflictError()
    # Event persistence failures propagate; no fatal stop is claimed when the
    # durable request event itself cannot be written.
    await transition_service.emit(
        timeline_action_service.assessment_requested(state=investigation)
    )
    try:
        outcome = await analysis_executor.analyze(investigation.investigation_id)
        authoritative = await transition_service.reload(investigation.investigation_id)
        if authoritative.investigation_id != investigation.investigation_id:
            raise InvestigationGraphContextMismatchError()
        if authoritative.assessment_id != outcome.assessment_id:
            raise AnalysisPersistenceMismatchError(
                "analysis outcome Assessment pointer does not match durable state"
            )
        if list(authoritative.analyzed_evidence_ids) != list(
            outcome.analyzed_evidence_ids
        ):
            raise AnalysisPersistenceMismatchError(
                "analysis outcome Evidence set does not match durable state"
            )
        if authoritative.analysis_disposition != outcome.disposition.value:
            raise AnalysisPersistenceMismatchError(
                "analysis outcome disposition does not match durable state"
            )
        if authoritative.version != outcome.investigation_version:
            raise AnalysisPersistenceMismatchError(
                "analysis outcome version does not match durable state"
            )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if _persistence_error(exc):
            raise
        latest = await transition_service.reload(investigation.investigation_id)
        fatal = await fatal_stop_service.fatalize(
            investigation.investigation_id,
            InvestigationError(
                source="evidence_analyst",
                code="analysis_execution_error",
                message="evidence analysis could not complete safely",
                recoverable=False,
            ),
            expected_version=_require_version(latest),
        )
        return {
            "investigation": fatal,
            "_coordinator_decision": CoordinatorDecision(
                action=CoordinatorAction.STOP,
                stop_reason=StopReason.FATAL_ERROR,
            ),
        }

    return {"investigation": authoritative, "_coordinator_decision": None}


async def finalize_stop_node(
    status_writer: InvestigationStatusWriter,
    timeline_action_service: TimelineActionService,
    state: OrchestrationGraphState,
) -> OrchestrationGraphState:
    """Finalize using the exact stored stop reason.

    Applies the decision that was produced and routed, never re-running
    policy to determine the stop reason again, and persists the terminal
    transition through the status writer (the database owns ``completed_at``).
    """
    decision = _require_decision(state, CoordinatorAction.STOP)
    stop_reason = decision.stop_reason
    if stop_reason is None:
        raise StopWithoutReasonError()

    investigation = state["investigation"]
    # A bounded fatal stop may already have transitioned the state to FAILED
    # before this node runs; an already-terminal state is adopted as-is.
    if is_terminal_status(investigation.status):
        return {
            "investigation": investigation,
            "_coordinator_decision": None,
        }
    terminal = finalize_stop_state(investigation, stop_reason)
    stop_event = timeline_action_service.investigation_stopped(
        stop_reason=stop_reason, state=terminal
    )
    events = (
        *_rejection_events(decision, timeline_action_service, terminal),
        stop_event,
    )
    persisted = await status_writer.finalize(
        investigation.investigation_id,
        stop_reason,
        terminal,
        expected_version=_require_version(investigation),
        events=events,
    )
    return {
        "investigation": persisted,
        "_coordinator_decision": None,
    }


def _rejection_events(
    decision: CoordinatorDecision,
    timeline_action_service: TimelineActionService,
    state: InvestigationState,
) -> tuple[InvestigationTimelineEvent, ...]:
    """Build ordered skipped actions for the decision's rejected candidates."""
    return tuple(
        timeline_action_service.pivot_skipped(
            entity_id=rejection.entity_id,
            depth=rejection.proposed_depth,
            reason_code=rejection.reason.value,
            state=state,
        )
        for rejection in decision.rejections
    )


def _matched_pivot(
    state: InvestigationState, work_item: ProviderWorkItem | None
) -> PivotRequest | None:
    """Return the PENDING pivot entering execution for this work item."""
    if work_item is None:
        return None
    for pivot in state.pending_pivots:
        if (
            pivot.status.value == "pending"
            and pivot.entity_id == work_item.entity_id
            and pivot.depth == work_item.depth
        ):
            return pivot
    return None


def _persistence_error(exc: BaseException) -> bool:
    """Return True when the exception is a typed persistence failure.

    Persistence-layer failures propagate unchanged: a fatal stop is never
    claimed when the fatal write itself could not be persisted.
    """
    from agentic_threat_investigator.app.persistence.repositories import (
        CoordinatorTransitionPersistenceError,
        InvestigationNotFoundError,
        InvestigationVersionConflictError,
    )

    return isinstance(
        exc,
        (
            CoordinatorTransitionPersistenceError,
            InvestigationNotFoundError,
            InvestigationVersionConflictError,
        ),
    )


def _require_version(investigation: InvestigationState) -> int:
    """Return the persisted Investigation version or fail closed.

    Coordinator transitions require pessimistic concurrency: a missing version
    means the state was never durably persisted, so a write cannot be
    authorized.
    """
    if investigation.version is None:
        raise ValueError(
            "coordinator transition requires a persisted investigation version"
        )
    return investigation.version


def _route_after_select(state: OrchestrationGraphState) -> str:
    """Route fatalized selection to stop, otherwise execute selected work."""
    if is_terminal_status(state["investigation"].status):
        return "finalize_stop"
    return (
        "execute_work"
        if state["investigation"].current_provider_work is not None
        else "coordinator"
    )


def _route_after_coordinator(state: OrchestrationGraphState) -> str:
    """Route based on the stored coordinator decision."""
    decision = state.get("_coordinator_decision")
    if decision is None:
        raise MissingCoordinatorDecisionError()
    action = decision.action
    if action is CoordinatorAction.EXECUTE_PROVIDER_WORK:
        return "select_work"
    if action is CoordinatorAction.REQUEST_ANALYSIS:
        return "analyze"
    if action is CoordinatorAction.AUTHORIZE_PIVOT:
        return "authorize_pivot"
    if action is CoordinatorAction.STOP:
        return "finalize_stop"
    raise UnknownCoordinatorActionError(action.value)


def _route_after_execute(state: OrchestrationGraphState) -> str:
    """Route fatalized execution directly to finalization."""
    return (
        "finalize_stop"
        if is_terminal_status(state["investigation"].status)
        else "record_outcome"
    )


def _route_after_record(_state: OrchestrationGraphState) -> str:
    """After recording an outcome, return to the coordinator."""
    return "coordinator"


def _route_after_authorize(state: OrchestrationGraphState) -> str:
    """After authorization, route to work selection or coordinator."""
    if is_terminal_status(state["investigation"].status):
        return "coordinator"
    if state["investigation"].pending_provider_work:
        return "select_work"
    return "coordinator"


def _route_after_analyze(_state: OrchestrationGraphState) -> str:
    """After analysis, return to the coordinator."""
    return "coordinator"


def build_investigation_graph(
    dispatcher: TaskDispatcher,
    *,
    coordinator_policy: CoordinatorPolicy,
    context_loader: CoordinatorContextLoader,
    analysis_executor: AnalysisExecutor,
    transition_service: CoordinatorTransitionService,
    status_writer: InvestigationStatusWriter,
    timeline_action_service: TimelineActionService,
    fatal_stop_service: FatalStopService,
    expected_investigation_id: UUID | None = None,
) -> CompiledStateGraph[
    OrchestrationGraphState, None, OrchestrationGraphState, OrchestrationGraphState
]:
    """Build the deterministic PR 21 coordinator-driven orchestration graph.

    All coordinator dependencies are required; partial composition raises
    :class:`CoordinatorDependencyError`. The legacy PR 19A topology is
    available only through :func:`build_legacy_investigation_graph` for
    isolated mechanics tests.

    Binding derivation: when the dispatcher exposes a bound investigation
    identity, that identity is adopted automatically as the graph's binding
    even when the caller omits the explicit argument, so direct public
    composition cannot bypass investigation isolation. An explicit
    ``expected_investigation_id`` that conflicts with the dispatcher's own
    bound identity raises :class:`InvestigationGraphBindingConflictError` at
    construction. Every invocation validates the wrapped state's investigation
    ID during ``initialize`` and raises :class:`InvestigationGraphContextMismatchError`
    on mismatch, before work selection and every I/O seam.
    """
    dispatcher_investigation_id = dispatcher.bound_investigation_id
    if (
        expected_investigation_id is not None
        and dispatcher_investigation_id is not None
        and expected_investigation_id != dispatcher_investigation_id
    ):
        raise InvestigationGraphBindingConflictError()
    effective_investigation_id = (
        expected_investigation_id
        if expected_investigation_id is not None
        else dispatcher_investigation_id
    )
    if effective_investigation_id is not None:
        dependency_bindings = (
            context_loader.bound_investigation_id,
            analysis_executor.bound_investigation_id,
            transition_service.bound_investigation_id,
            status_writer.bound_investigation_id,
            fatal_stop_service.bound_investigation_id,
        )
        if any(
            binding is not None and binding != effective_investigation_id
            for binding in dependency_bindings
        ):
            raise InvestigationGraphBindingConflictError()

    builder: StateGraph[OrchestrationGraphState] = StateGraph(OrchestrationGraphState)

    async def initialize_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        validated = await initialize(state)
        if (
            effective_investigation_id is not None
            and validated["investigation"].investigation_id
            != effective_investigation_id
        ):
            raise InvestigationGraphContextMismatchError()
        return validated

    builder.add_node("initialize", initialize_node)

    async def select_work_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        return await select_work(
            transition_service,
            timeline_action_service,
            fatal_stop_service,
            state,
        )

    builder.add_node("select_work", select_work_node)

    async def execute_work_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        return await execute_work(dispatcher, state, fatal_stop_service)

    builder.add_node("execute_work", execute_work_node)

    async def record_outcome_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        try:
            return await record_outcome(
                transition_service, timeline_action_service, state
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if _persistence_error(exc):
                raise
            investigation = state["investigation"]
            fatal = await fatal_stop_service.fatalize(
                investigation.investigation_id,
                InvestigationError(
                    source="orchestration",
                    code="provider_outcome_error",
                    message="provider outcome could not be recorded safely",
                    recoverable=False,
                ),
                expected_version=_require_version(investigation),
            )
            return {
                "investigation": fatal,
                "_coordinator_decision": CoordinatorDecision(
                    action=CoordinatorAction.STOP,
                    stop_reason=StopReason.FATAL_ERROR,
                ),
            }

    builder.add_node("record_outcome", record_outcome_node)

    async def coord_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        return await coordinator_node(
            coordinator_policy, context_loader, fatal_stop_service, state
        )

    builder.add_node("coordinator", coord_node)

    async def auth_pivot_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        try:
            return await authorize_pivot_node(
                transition_service, timeline_action_service, state
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if _persistence_error(exc):
                raise
            investigation = state["investigation"]
            fatal = await fatal_stop_service.fatalize(
                investigation.investigation_id,
                InvestigationError(
                    source="orchestration",
                    code="pivot_authorization_error",
                    message="pivot authorization could not complete safely",
                    recoverable=False,
                ),
                expected_version=_require_version(investigation),
            )
            return {
                "investigation": fatal,
                "_coordinator_decision": CoordinatorDecision(
                    action=CoordinatorAction.STOP,
                    stop_reason=StopReason.FATAL_ERROR,
                ),
            }

    builder.add_node("authorize_pivot", auth_pivot_node)

    async def analyze_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        return await analyze(
            analysis_executor,
            transition_service,
            timeline_action_service,
            fatal_stop_service,
            state,
        )

    builder.add_node("analyze", analyze_node)

    async def stop_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        return await finalize_stop_node(status_writer, timeline_action_service, state)

    builder.add_node("finalize_stop", stop_node)

    builder.add_edge(START, "initialize")
    builder.add_edge("initialize", "coordinator")
    builder.add_conditional_edges(
        "coordinator",
        _route_after_coordinator,
        {
            "select_work": "select_work",
            "analyze": "analyze",
            "authorize_pivot": "authorize_pivot",
            "finalize_stop": "finalize_stop",
        },
    )
    builder.add_conditional_edges(
        "select_work",
        _route_after_select,
        {
            "execute_work": "execute_work",
            "coordinator": "coordinator",
            "finalize_stop": "finalize_stop",
        },
    )
    builder.add_conditional_edges(
        "execute_work",
        _route_after_execute,
        {"record_outcome": "record_outcome", "finalize_stop": "finalize_stop"},
    )
    builder.add_conditional_edges(
        "record_outcome",
        _route_after_record,
        {"coordinator": "coordinator"},
    )
    builder.add_conditional_edges(
        "authorize_pivot",
        _route_after_authorize,
        {"select_work": "select_work", "coordinator": "coordinator"},
    )
    builder.add_conditional_edges(
        "analyze",
        _route_after_analyze,
        {"coordinator": "coordinator"},
    )
    builder.add_edge("finalize_stop", END)

    return builder.compile()


def build_legacy_investigation_graph(
    dispatcher: TaskDispatcher,
    *,
    expected_investigation_id: UUID | None = None,
) -> CompiledStateGraph[
    OrchestrationGraphState, None, OrchestrationGraphState, OrchestrationGraphState
]:
    """Build the legacy PR 19A topology for isolated mechanics tests.

    Queue exhaustion routes to ``END``. This builder exists only so legacy
    queue/bookkeeping tests can run without coordinator dependencies;
    production composition must always use :func:`build_investigation_graph`.
    """
    dispatcher_investigation_id = dispatcher.bound_investigation_id
    if (
        expected_investigation_id is not None
        and dispatcher_investigation_id is not None
        and expected_investigation_id != dispatcher_investigation_id
    ):
        raise InvestigationGraphBindingConflictError()
    effective_investigation_id = (
        expected_investigation_id
        if expected_investigation_id is not None
        else dispatcher_investigation_id
    )

    builder: StateGraph[OrchestrationGraphState] = StateGraph(OrchestrationGraphState)

    async def initialize_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        validated = await initialize(state)
        if (
            effective_investigation_id is not None
            and validated["investigation"].investigation_id
            != effective_investigation_id
        ):
            raise InvestigationGraphContextMismatchError()
        return validated

    builder.add_node("initialize", initialize_node)

    async def legacy_select_work_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        return {
            "investigation": select_provider_work(state["investigation"]),
            "_coordinator_decision": None,
        }

    builder.add_node("select_work", legacy_select_work_node)

    async def execute_work_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        return await execute_work(dispatcher, state)

    builder.add_node("execute_work", execute_work_node)

    async def legacy_record_outcome_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        investigation = state["investigation"]
        outcome = investigation.last_provider_outcome
        if outcome is None:
            raise ValueError("record_outcome requires a recorded provider outcome")
        return {
            "investigation": record_provider_outcome(investigation, outcome),
            "_coordinator_decision": None,
        }

    builder.add_node("record_outcome", legacy_record_outcome_node)

    builder.add_edge(START, "initialize")
    builder.add_edge("initialize", "select_work")
    builder.add_conditional_edges(
        "select_work",
        _route_after_select_legacy,
        {"execute_work": "execute_work", END: END},
    )
    builder.add_edge("execute_work", "record_outcome")
    builder.add_edge("record_outcome", "select_work")

    return builder.compile()


def _route_after_select_legacy(state: OrchestrationGraphState) -> str:
    """Legacy routing: no pending work -> END."""
    return (
        "execute_work"
        if state["investigation"].current_provider_work is not None
        else END
    )
