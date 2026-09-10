# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic LangGraph orchestration skeleton (PR 19A).

Implements the minimal deterministic workflow:

    START -> initialize -> select_work -> execute_work -> record_outcome
          -> select_work -> (pending work -> execute_work | no work -> END)

This is orchestration mechanics only: no real provider calls, LLM behavior,
adaptive pivots, budget enforcement, or stopping policy. The dispatcher is
injected; no dependency is hidden in module globals.
"""

from typing import TypedDict
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from agentic_threat_investigator.app.orchestration.dispatcher import (
    TaskDispatcher,
    ensure_task_dispatcher,
)
from agentic_threat_investigator.app.orchestration.executor import WorkExecutor
from agentic_threat_investigator.app.orchestration.models import (
    record_provider_outcome,
    select_provider_work,
)
from agentic_threat_investigator.domain.investigation import InvestigationState


class InvestigationGraphContextMismatchError(ValueError):
    """Raised when graph input does not match its bound investigation.

    A graph built for one ``ProviderExecutionContext.investigation_id`` must
    never process an ``InvestigationState`` belonging to another investigation:
    the executor would otherwise call providers, persist evidence, and write
    timeline events under the bound investigation while the unchanged
    ``record_outcome`` node merges the outcome into the unrelated in-memory
    state. This is an application-level composition error, independent of
    LangGraph runtime internals and persistence, raised during graph
    initialization before work selection and every I/O seam. The message is a
    fixed safe string that never embeds identifiers, entity values, provider
    results, or payloads.
    """

    def __init__(self) -> None:
        """Build the fixed safe composition-error message."""
        super().__init__(
            "orchestration graph state does not match the bound investigation "
            "context"
        )


class InvestigationGraphBindingConflictError(ValueError):
    """Raised when an explicit graph binding conflicts with its executor.

    The caller supplied an explicit ``expected_investigation_id`` that differs
    from the executor's own bound investigation identity. Building the graph
    would produce an executor that writes under one investigation while the
    initialize node accepts another. The conflict is rejected at graph
    construction, before any invocation or I/O. The message is a fixed safe
    string that never embeds identifiers, entity values, provider results, or
    payloads.
    """

    def __init__(self) -> None:
        """Build the fixed safe binding-conflict message."""
        super().__init__(
            "orchestration graph binding conflicts with the executor "
            "investigation context"
        )


class OrchestrationGraphState(TypedDict):
    """LangGraph channel state wrapping one serializable investigation state.

    The wrapped :class:`InvestigationState` carries only typed operational
    data; no executor instances, providers, repositories, or LangGraph
    runtime objects are stored in state.
    """

    investigation: InvestigationState


async def initialize(state: OrchestrationGraphState) -> OrchestrationGraphState:
    """Validate that the graph state is usable; perform no I/O or synthesis.

    Initialization only validates that a wrapped investigation state is
    present. No provider, database, or LLM call happens here, and no work
    is synthesized.
    """

    if not isinstance(state.get("investigation"), InvestigationState):
        raise ValueError("orchestration state must wrap an InvestigationState")
    return state


async def select_work(state: OrchestrationGraphState) -> OrchestrationGraphState:
    """Select the next pending work item (FIFO) as the current work item."""

    return {
        "investigation": select_provider_work(state["investigation"]),
    }


async def execute_work(
    dispatcher: TaskDispatcher, state: OrchestrationGraphState
) -> OrchestrationGraphState:
    """Execute the current work item through the injected dispatcher.

    The node requires a selected current work item, delegates dispatch,
    and records the outcome; it does not update completed collections or
    counters directly.
    """

    investigation = state["investigation"]
    work_item = investigation.current_provider_work
    if work_item is None:
        raise ValueError("execute_work requires a selected current provider work item")
    outcome = await dispatcher.dispatch(work_item)
    if outcome.work_item != work_item:
        raise ValueError("executor outcome does not match the executed work item")
    return {
        "investigation": investigation.model_copy(
            update={"last_provider_outcome": outcome}
        ),
    }


async def record_outcome(state: OrchestrationGraphState) -> OrchestrationGraphState:
    """Apply deterministic outcome bookkeeping; no external I/O."""

    investigation = state["investigation"]
    outcome = investigation.last_provider_outcome
    if outcome is None:
        raise ValueError("record_outcome requires a recorded provider outcome")
    return {"investigation": record_provider_outcome(investigation, outcome)}


def _route_after_select(state: OrchestrationGraphState) -> str:
    """Route to work execution when pending work exists, otherwise end."""

    return (
        "execute_work"
        if state["investigation"].current_provider_work is not None
        else END
    )


def build_investigation_graph(
    dispatcher: TaskDispatcher | WorkExecutor,
    *,
    expected_investigation_id: UUID | None = None,
) -> CompiledStateGraph[
    OrchestrationGraphState, None, OrchestrationGraphState, OrchestrationGraphState
]:
    """Build the deterministic PR 19A orchestration graph.

    The dispatcher is injected by the caller; no global mutable registry,
    service locator, provider bootstrap, database connection, or checkpointer
    is involved.

    Binding derivation: when the dispatcher exposes a bound investigation
    identity, that identity is adopted automatically as the graph's binding
    even when the caller omits the explicit argument, so direct public
    composition cannot bypass investigation isolation. An explicit
    ``expected_investigation_id`` that conflicts with the dispatcher's own
    bound identity raises :class:`InvestigationGraphBindingConflictError` at
    construction. Every invocation validates the wrapped state's investigation
    ID during ``initialize`` and raises :class:`InvestigationGraphContextMismatchError`
    on mismatch, before work selection and every I/O seam. The effective ID
    is an injected graph-instance invariant, never copied into checkpoint
    state. Ordinary unbound dispatchers remain generic. A bare WorkExecutor
    is accepted only as a backward-compatible local adaptation of the old
    builder contract.
    """
    effective_dispatcher = ensure_task_dispatcher(dispatcher)
    dispatcher_investigation_id = effective_dispatcher.bound_investigation_id
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
        """Validate the wrapped state and its bound investigation identity.

        Runs the existing public :func:`initialize` contract first, then, when
        the graph is bound to one investigation, rejects any state belonging to
        a different investigation. The closure is registered under the existing
        ``initialize`` node name so no node or edge is added.
        """
        validated = await initialize(state)
        if effective_investigation_id is not None:
            if (
                validated["investigation"].investigation_id
                != effective_investigation_id
            ):
                raise InvestigationGraphContextMismatchError()
        return validated

    builder.add_node("initialize", initialize_node)
    builder.add_node("select_work", select_work)

    async def execute_work_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        return await execute_work(effective_dispatcher, state)

    builder.add_node("execute_work", execute_work_node)
    builder.add_node("record_outcome", record_outcome)
    builder.add_edge(START, "initialize")
    builder.add_edge("initialize", "select_work")
    builder.add_conditional_edges(
        "select_work",
        _route_after_select,
        {"execute_work": "execute_work", END: END},
    )
    builder.add_edge("execute_work", "record_outcome")
    builder.add_edge("record_outcome", "select_work")
    return builder.compile()
