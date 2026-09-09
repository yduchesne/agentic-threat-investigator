# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic LangGraph orchestration skeleton (PR 19A).

Implements the minimal deterministic workflow:

    START -> initialize -> select_work -> execute_work -> record_outcome
          -> select_work -> (pending work -> execute_work | no work -> END)

This is orchestration mechanics only: no real provider calls, LLM behavior,
adaptive pivots, budget enforcement, or stopping policy. The executor is
injected; no dependency is hidden in module globals.
"""

from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from agentic_threat_investigator.app.orchestration.executor import WorkExecutor
from agentic_threat_investigator.app.orchestration.models import (
    record_provider_outcome,
    select_provider_work,
)
from agentic_threat_investigator.domain.investigation import InvestigationState


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
    executor: WorkExecutor, state: OrchestrationGraphState
) -> OrchestrationGraphState:
    """Execute the current work item through the injected executor.

    The node requires a selected current work item, delegates execution,
    and records the outcome; it does not update completed collections or
    counters directly.
    """

    investigation = state["investigation"]
    work_item = investigation.current_provider_work
    if work_item is None:
        raise ValueError("execute_work requires a selected current provider work item")
    outcome = await executor.execute(work_item)
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
    executor: WorkExecutor,
) -> CompiledStateGraph[
    OrchestrationGraphState, None, OrchestrationGraphState, OrchestrationGraphState
]:
    """Build the deterministic PR 19A orchestration graph.

    The executor is injected by the caller; no global mutable registry,
    service locator, provider bootstrap, database connection, or checkpointer
    is involved.
    """

    builder: StateGraph[OrchestrationGraphState] = StateGraph(OrchestrationGraphState)
    builder.add_node("initialize", initialize)
    builder.add_node("select_work", select_work)

    async def execute_work_node(
        state: OrchestrationGraphState,
    ) -> OrchestrationGraphState:
        return await execute_work(executor, state)

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
