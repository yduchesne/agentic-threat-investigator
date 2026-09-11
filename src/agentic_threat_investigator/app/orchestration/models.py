# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic provider-work queue helpers and coordinator helpers for the
investigation orchestration graph.

These pure helpers implement the PR 19A mechanics (FIFO selection, duplicate
suppression, deterministic outcome bookkeeping) and the PR 21 coordinator
helpers (pivot authorization, analysis tracking, stop-state finalization).
They make no pivot-policy, budget-enforcement, or stopping decisions; those
belong to the coordinated policy layer.
"""

from uuid import UUID

from agentic_threat_investigator.domain.investigation import (
    EntityTraversalState,
    EntityTraversalStateBuilder,
    InvestigationState,
    InvestigationStatus,
    PivotStatus,
    ProviderExecutionOutcome,
    ProviderWorkItem,
    StopReason,
    require_status_transition,
)


def _merge_unique_ids(
    existing: list[UUID], additional: tuple[UUID, ...] | list[UUID]
) -> list[UUID]:
    """Merge entity IDs preserving first-seen deterministic order."""

    seen = set(existing)
    merged = list(existing)
    for entity_id in additional:
        if entity_id not in seen:
            seen.add(entity_id)
            merged.append(entity_id)
    return merged


def enqueue_provider_work(
    state: InvestigationState, work_items: list[ProviderWorkItem]
) -> InvestigationState:
    """Queue provider work in input order, skipping already known work.

    A work item is skipped when an identical work identity
    ``(provider, entity_id, depth)`` is already pending or already
    completed. The input state is not mutated; a new state is returned.
    """

    known = set(state.pending_provider_work) | set(state.completed_provider_work)
    queued: list[ProviderWorkItem] = []
    for work_item in work_items:
        if work_item in known:
            continue
        known.add(work_item)
        queued.append(work_item)
    return state.model_copy(
        update={
            "pending_provider_work": [*state.pending_provider_work, *queued],
        }
    )


def select_next_provider_work(
    state: InvestigationState,
) -> ProviderWorkItem | None:
    """Return the first pending work item (FIFO), or ``None`` when empty.

    Selection is purely positional: no semantic priority, evidence
    inspection, or pivot policy is applied.
    """

    pending = state.pending_provider_work
    return pending[0] if pending else None


def select_provider_work(state: InvestigationState) -> InvestigationState:
    """Select the next pending work item as the current work item.

    Deterministic FIFO selection; a no-op state is returned when no pending
    work exists so ``current_provider_work`` stays ``None``.
    """

    selected = select_next_provider_work(state)
    return state.model_copy(update={"current_provider_work": selected})


def record_provider_outcome(
    state: InvestigationState, outcome: ProviderExecutionOutcome
) -> InvestigationState:
    """Apply deterministic bookkeeping for one executed work item.

    Moves the executed work item from pending to completed (exactly once),
    records the outcome, merges discovered entity, evidence, and relationship
    IDs preserving first-seen order, appends the outcome error when present,
    increments ``provider_calls_used`` exactly once, and clears
    ``current_provider_work``. Failure is still completed work; retries are
    out of scope.
    """

    work_item = outcome.work_item
    if state.current_provider_work != work_item:
        raise ValueError(
            "recorded outcome does not correspond to the current provider work item"
        )
    if work_item in state.completed_provider_work:
        raise ValueError("provider work item was already completed")
    # Reject provider-budget overflow before changing any state: one increment
    # per actually executed work item, never above the configured maximum.
    if state.budget.provider_calls_used >= state.budget.max_provider_calls:
        raise ValueError("provider call would exceed max_provider_calls")
    pending = [item for item in state.pending_provider_work if item != work_item]
    budget = state.budget.model_copy(
        update={"provider_calls_used": state.budget.provider_calls_used + 1}
    )
    errors = (
        [*state.errors, outcome.error] if outcome.error is not None else state.errors
    )

    # Track discovery order and minimum depth deterministically through the
    # typed traversal builder: new discoveries are appended in provider-result
    # order at work depth + 1; rediscovery keeps the first ordinal and lowers
    # only the minimum depth. Roots are seeded by the builder from
    # root_entity_ids; only non-root entries are replayed.
    builder = EntityTraversalStateBuilder(state.root_entity_ids)
    # Replay non-root discoveries first, then re-apply each root's recorded
    # best investigated depth so rediscovery rebuilds never erase execution
    # history of root entities.
    for entry in state.traversal:
        if entry.entity_id in state.root_entity_ids:
            continue
        builder.record_discovery_at_ordinal(
            entry.entity_id,
            entry.first_discovery_ordinal,
            entry.minimum_depth,
            best_depth=entry.best_investigated_depth,
        )
    for entity_id in outcome.discovered_entity_ids:
        builder.record_discovery(entity_id, work_item.depth)
    traversal = [
        entry
        if entry.entity_id not in state.root_entity_ids
        else _with_recorded_best_depth(entry, state)
        for entry in builder.entries()
    ]

    return state.model_copy(
        update={
            "pending_provider_work": pending,
            "completed_provider_work": [
                *state.completed_provider_work,
                work_item,
            ],
            "current_provider_work": None,
            "last_provider_outcome": outcome,
            "evidence_ids": _merge_unique_ids(state.evidence_ids, outcome.evidence_ids),
            "relationship_ids": _merge_unique_ids(
                state.relationship_ids, outcome.relationship_ids
            ),
            "discovered_entity_ids": _merge_unique_ids(
                state.discovered_entity_ids, outcome.discovered_entity_ids
            ),
            "traversal": traversal,
            "errors": errors,
            "budget": budget,
        }
    )


def authorize_pivot(
    state: InvestigationState,
    pivot_request: object,
    work_items: list[ProviderWorkItem],
) -> InvestigationState:
    """Record an authorized pivot and enqueue its provider work.

    Accepts a ``PivotRequest`` from the coordinator policy and adds it to
    ``pending_pivots``. The entity is also added to ``investigated_entity_ids``
    to prevent re-investigation. Work items are enqueued for execution.

    This is a pure helper function that does not validate eligibility (that
    is the coordinator policy's responsibility).
    """
    from agentic_threat_investigator.domain.investigation import PivotRequest

    assert isinstance(pivot_request, PivotRequest)

    investigated = list(state.investigated_entity_ids)
    if pivot_request.entity_id not in investigated:
        investigated.append(pivot_request.entity_id)

    known = set(state.pending_provider_work) | set(state.completed_provider_work)
    queued: list[ProviderWorkItem] = []
    for work_item in work_items:
        if work_item not in known:
            known.add(work_item)
            queued.append(work_item)

    return state.model_copy(
        update={
            "pending_pivots": [*state.pending_pivots, pivot_request],
            "pending_provider_work": [*state.pending_provider_work, *queued],
            "investigated_entity_ids": investigated,
        }
    )


def record_analysis(
    state: InvestigationState,
    assessment_id: UUID,
    analyzed_evidence_ids: list[UUID],
) -> InvestigationState:
    """Record a completed analysis outcome in the investigation state.

    Updates ``assessment_id`` and ``analyzed_evidence_ids``. Does not
    increment LLM-budget counters (those are owned by PR 20B).
    """
    return state.model_copy(
        update={
            "assessment_id": assessment_id,
            "analyzed_evidence_ids": analyzed_evidence_ids,
        }
    )


def finalize_stop_state(
    state: InvestigationState,
    stop_reason: StopReason,
) -> InvestigationState:
    """Set the investigation state to its terminal stop configuration.

    Transitions the status to COMPLETED and records the stop reason. The
    status transition is validated against the lifecycle. Terminal
    timestamps are database-owned: the persisted transition service calls
    the stored function which sets ``completed_at``; this pure helper never
    reads a clock.
    """
    require_status_transition(state.status, InvestigationStatus.COMPLETED)
    return state.model_copy(
        update={
            "status": InvestigationStatus.COMPLETED,
            "stop_reason": stop_reason.value,
        }
    )


def apply_work_selection(
    state: InvestigationState,
) -> InvestigationState:
    """Apply deterministic bookkeeping for one FIFO work selection.

    The selected ``current_provider_work`` item's matching PENDING pivot
    (same entity and depth) transitions to IN_PROGRESS when this is its first
    work, and the entity's traversal entry records the executed depth in
    ``best_investigated_depth`` (retaining the shallowest recorded depth).
    Pure helper; persistence is the caller's responsibility.
    """
    selected = state.current_provider_work
    if selected is None:
        return state

    pivots = list(state.pending_pivots)
    changed = False
    for index, pivot in enumerate(pivots):
        if (
            pivot.entity_id == selected.entity_id
            and pivot.depth == selected.depth
            and pivot.status is PivotStatus.PENDING
        ):
            pivots[index] = pivot.model_copy(update={"status": PivotStatus.IN_PROGRESS})
            changed = True
            break

    # Seed root traversal entries from root_entity_ids when none exist yet so
    # an executed root reliably records best_investigated_depth before any
    # provider outcome exists (traversal is otherwise built by outcomes).
    traversal = list(state.traversal)
    if not traversal:
        builder = EntityTraversalStateBuilder(state.root_entity_ids)
        traversal = list(builder.entries())
    traversal_changed = False
    for index, entry in enumerate(traversal):
        if entry.entity_id == selected.entity_id:
            recorded = entry.record_investigation(selected.depth)
            if recorded != entry:
                traversal[index] = recorded
                traversal_changed = True
            break

    if not changed and not traversal_changed:
        return state
    return state.model_copy(
        update={
            "pending_pivots": pivots,
            "traversal": traversal if traversal_changed else state.traversal,
        }
    )


def complete_drained_pivots(
    state: InvestigationState,
) -> InvestigationState:
    """Mark IN_PROGRESS pivots COMPLETED once their exact work drains.

    An IN_PROGRESS pivot with no remaining pending or current provider work
    for the same entity and depth is transitioned to COMPLETED, including
    after failed provider outcomes. Completed pivots stay in the append-only
    ``pending_pivots`` collection with their final status.
    """
    has_work = {(item.entity_id, item.depth) for item in state.pending_provider_work}
    if state.current_provider_work is not None:
        current = state.current_provider_work
        has_work.add((current.entity_id, current.depth))

    pivots = list(state.pending_pivots)
    changed = False
    for index, pivot in enumerate(pivots):
        if (
            pivot.status is PivotStatus.IN_PROGRESS
            and (pivot.entity_id, pivot.depth) not in has_work
        ):
            pivots[index] = pivot.model_copy(update={"status": PivotStatus.COMPLETED})
            changed = True
    if not changed:
        return state
    return state.model_copy(update={"pending_pivots": pivots})


def _with_recorded_best_depth(
    entry: EntityTraversalState, state: InvestigationState
) -> EntityTraversalState:
    """Return the root entry with the persisted best investigated depth.

    The builder seeds roots fresh (best depth unset); the durable traversal
    carries the actual execution history and must win.
    """
    for prior in state.traversal:
        if (
            prior.entity_id == entry.entity_id
            and prior.best_investigated_depth is not None
        ):
            return entry.model_copy(
                update={"best_investigated_depth": prior.best_investigated_depth}
            )
    return entry
