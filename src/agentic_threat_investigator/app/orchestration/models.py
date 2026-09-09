# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic provider-work queue helpers for investigation orchestration.

These pure helpers implement the PR 19A mechanics only: FIFO selection,
duplicate suppression for identical work, and deterministic outcome
bookkeeping. They make no pivot-policy, budget-enforcement, or stopping
decisions; those belong to later PRs.
"""

from uuid import UUID

from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    ProviderExecutionOutcome,
    ProviderWorkItem,
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
    pending = [item for item in state.pending_provider_work if item != work_item]
    budget = state.budget.model_copy(
        update={"provider_calls_used": state.budget.provider_calls_used + 1}
    )
    errors = (
        [*state.errors, outcome.error] if outcome.error is not None else state.errors
    )
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
            "errors": errors,
            "budget": budget,
        }
    )
