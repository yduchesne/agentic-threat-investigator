# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Durable coordinator action timeline (PR 21).

The coordinator action timeline is the single durable source of the
structured coordinator actions consumed by trajectory evaluation. The pure
:class:`TimelineActionService` builds events; graph nodes pass the built
events to :class:`CoordinatorTransitionService` which appends them through
the caller's UnitOfWork — in the same short transaction as the state
transition that produced them, so an action can never be observed without
its state change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.domain.investigation import (
    InvestigationBudget,
    InvestigationState,
    PivotRequest,
    StopReason,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)

# Stable PR 21 action URNs shared by emission and evaluation.
ACTION_PROVIDER_QUERY = "urn:ati:action:provider_query"
ACTION_ENTITY_DISCOVERED = "urn:ati:action:entity_discovered"
ACTION_PIVOT_ENQUEUED = "urn:ati:action:pivot_enqueued"
ACTION_PIVOT_EXECUTED = "urn:ati:action:pivot_executed"
ACTION_PIVOT_SKIPPED = "urn:ati:action:pivot_skipped"
ACTION_ASSESSMENT_REQUESTED = "urn:ati:action:assessment_requested"
ACTION_INVESTIGATION_STOPPED = "urn:ati:action:investigation_stopped"


class TimelineActionService(ABC):
    """Build coordinator timeline events (pure; appends happen in the caller's UoW)."""

    @abstractmethod
    def pivot_enqueued(
        self, *, pivot: PivotRequest, state: InvestigationState
    ) -> InvestigationTimelineEvent:
        """Build PIVOT_ENQUEUED for one authorized pivot."""

    @abstractmethod
    def pivot_executed(
        self, *, pivot: PivotRequest, state: InvestigationState
    ) -> InvestigationTimelineEvent:
        """Build PIVOT_EXECUTED exactly once when the pivot enters execution."""

    @abstractmethod
    def pivot_skipped(
        self,
        *,
        entity_id: UUID,
        depth: int | None,
        reason_code: str,
        state: InvestigationState,
    ) -> InvestigationTimelineEvent:
        """Build PIVOT_SKIPPED with the bounded rejection reason."""

    @abstractmethod
    def entities_discovered(
        self,
        *,
        entity_ids: tuple[UUID, ...],
        state: InvestigationState,
    ) -> InvestigationTimelineEvent:
        """Build ENTITIES_DISCOVERED for newly appended discovery IDs."""

    @abstractmethod
    def assessment_requested(
        self, *, state: InvestigationState
    ) -> InvestigationTimelineEvent:
        """Build ASSESSMENT_REQUESTED immediately before analyst execution."""

    @abstractmethod
    def investigation_stopped(
        self,
        *,
        stop_reason: StopReason,
        state: InvestigationState,
    ) -> InvestigationTimelineEvent:
        """Build INVESTIGATION_STOPPED carrying the stable stop reason."""


class DeterministicTimelineActionService(TimelineActionService):
    """Build bounded coordinator timeline events from an injected clock."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        """Bind the deterministic clock; defaults to ``datetime.now(UTC)``."""
        self._clock: Callable[[], datetime] = clock if clock is not None else _utc_now

    @staticmethod
    def _counters(state: InvestigationState) -> dict[str, int | None]:
        """Return the bounded budget counters for evaluation."""
        budget: InvestigationBudget = state.budget
        return {
            "provider_calls_used": budget.provider_calls_used,
            "replans_used": budget.replans_used,
            "entity_count": len(
                set(state.root_entity_ids) | set(state.discovered_entity_ids)
            ),
        }

    def pivot_enqueued(
        self, *, pivot: PivotRequest, state: InvestigationState
    ) -> InvestigationTimelineEvent:
        """Build PIVOT_ENQUEUED carrying the pivot entity and depth."""
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=state.investigation_id,
            type=InvestigationTimelineEventType.PIVOT_ENQUEUED,
            occurred_at=self._clock(),
            entity_ids=(pivot.entity_id,),
            pivot_depth=pivot.depth,
        ).model_copy(update=self._counters(state))

    def pivot_executed(
        self, *, pivot: PivotRequest, state: InvestigationState
    ) -> InvestigationTimelineEvent:
        """Build PIVOT_EXECUTED exactly once for the executed pivot."""
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=state.investigation_id,
            type=InvestigationTimelineEventType.PIVOT_EXECUTED,
            occurred_at=self._clock(),
            entity_ids=(pivot.entity_id,),
            pivot_depth=pivot.depth,
        ).model_copy(update=self._counters(state))

    def pivot_skipped(
        self,
        *,
        entity_id: UUID,
        depth: int | None,
        reason_code: str,
        state: InvestigationState,
    ) -> InvestigationTimelineEvent:
        """Build PIVOT_SKIPPED with the bounded rejection reason."""
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=state.investigation_id,
            type=InvestigationTimelineEventType.PIVOT_SKIPPED,
            occurred_at=self._clock(),
            entity_ids=(entity_id,),
            pivot_depth=depth,
            reason_code=reason_code,
        ).model_copy(update=self._counters(state))

    def entities_discovered(
        self,
        *,
        entity_ids: tuple[UUID, ...],
        state: InvestigationState,
    ) -> InvestigationTimelineEvent:
        """Build ENTITIES_DISCOVERED for newly appended discovery IDs."""
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=state.investigation_id,
            type=InvestigationTimelineEventType.ENTITIES_DISCOVERED,
            occurred_at=self._clock(),
            entity_ids=entity_ids,
        ).model_copy(update=self._counters(state))

    def assessment_requested(
        self, *, state: InvestigationState
    ) -> InvestigationTimelineEvent:
        """Build ASSESSMENT_REQUESTED immediately before analyst execution."""
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=state.investigation_id,
            type=InvestigationTimelineEventType.ASSESSMENT_REQUESTED,
            occurred_at=self._clock(),
        ).model_copy(update=self._counters(state))

    def investigation_stopped(
        self,
        *,
        stop_reason: StopReason,
        state: InvestigationState,
    ) -> InvestigationTimelineEvent:
        """Build INVESTIGATION_STOPPED carrying the stable stop reason."""
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=state.investigation_id,
            type=InvestigationTimelineEventType.INVESTIGATION_STOPPED,
            occurred_at=self._clock(),
            reason_code=stop_reason.value,
        ).model_copy(update=self._counters(state))


def _utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(UTC)


def convert_timeline_actions(
    events: tuple[InvestigationTimelineEvent, ...] | list[InvestigationTimelineEvent],
) -> tuple[object, ...]:
    """Convert ordered timeline events into CoordinatorActionRecord values.

    Deterministic converter: every coordinator/provider event maps to exactly
    one structured action record with the documented action URN, entity ID,
    provider, and depth; logs and prose are never inspected.
    """
    from agentic_threat_investigator.evaluation.coordinator import (
        CoordinatorActionRecord,
    )

    records: list[CoordinatorActionRecord] = []
    for event in events:
        if event.type is InvestigationTimelineEventType.PROVIDER_WORK_STARTED:
            records.append(
                CoordinatorActionRecord(
                    action=ACTION_PROVIDER_QUERY,
                    entity_id=event.target_entity_id,
                    provider=event.provider.value if event.provider else None,
                    depth=event.pivot_depth,
                    provider_calls_used=event.provider_calls_used,
                    replans_used=event.replans_used,
                    entity_count=event.entity_count,
                )
            )
        elif event.type is InvestigationTimelineEventType.ENTITIES_DISCOVERED:
            for entity_id in event.entity_ids:
                records.append(
                    CoordinatorActionRecord(
                        action=ACTION_ENTITY_DISCOVERED, entity_id=entity_id
                    )
                )
        elif event.type is InvestigationTimelineEventType.PIVOT_ENQUEUED:
            for entity_id in event.entity_ids:
                records.append(
                    CoordinatorActionRecord(
                        action=ACTION_PIVOT_ENQUEUED,
                        entity_id=entity_id,
                        depth=event.pivot_depth,
                        provider_calls_used=event.provider_calls_used,
                        replans_used=event.replans_used,
                        entity_count=event.entity_count,
                    )
                )
        elif event.type is InvestigationTimelineEventType.PIVOT_EXECUTED:
            for entity_id in event.entity_ids:
                records.append(
                    CoordinatorActionRecord(
                        action=ACTION_PIVOT_EXECUTED,
                        entity_id=entity_id,
                        depth=event.pivot_depth,
                        provider_calls_used=event.provider_calls_used,
                        replans_used=event.replans_used,
                        entity_count=event.entity_count,
                    )
                )
        elif event.type is InvestigationTimelineEventType.PIVOT_SKIPPED:
            for entity_id in event.entity_ids:
                records.append(
                    CoordinatorActionRecord(
                        action=ACTION_PIVOT_SKIPPED,
                        entity_id=entity_id,
                        depth=event.pivot_depth,
                        reason=event.reason_code,
                        provider_calls_used=event.provider_calls_used,
                        replans_used=event.replans_used,
                        entity_count=event.entity_count,
                    )
                )
        elif event.type is InvestigationTimelineEventType.ASSESSMENT_REQUESTED:
            records.append(CoordinatorActionRecord(action=ACTION_ASSESSMENT_REQUESTED))
        elif event.type is InvestigationTimelineEventType.INVESTIGATION_STOPPED:
            records.append(
                CoordinatorActionRecord(
                    action=ACTION_INVESTIGATION_STOPPED,
                    reason=event.reason_code,
                    provider_calls_used=event.provider_calls_used,
                    replans_used=event.replans_used,
                    entity_count=event.entity_count,
                )
            )
    return tuple(records)
