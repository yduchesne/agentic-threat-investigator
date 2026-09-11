# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure deterministic coordinator policy for adaptive investigations.

This module deliberately contains no persistence, provider, network, clock, or
LLM access.  It turns a read-only snapshot into a bounded decision; callers
own materialising the snapshot and committing the resulting state.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_threat_investigator.domain.assessment import Assessment
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    InvestigationState,
    PivotClass,
    PivotRequest,
    PivotStatus,
    ProviderWorkItem,
    StopReason,
    pivot_class,
)


class PivotRejectionReason(str, Enum):
    """Bounded reasons why a candidate entity is rejected for pivoting."""

    UNKNOWN_TARGET = "unknown_target"
    DELETED_TARGET = "deleted_target"
    UNSUPPORTED_CLASS = "unsupported_class"
    NO_PROVIDER_PATH = "no_provider_path"
    DUPLICATE_PIVOT = "duplicate_pivot"
    DUPLICATE_PROVIDER_WORK = "duplicate_provider_work"
    ALREADY_INVESTIGATED = "already_investigated"
    DEPTH_LIMIT = "depth_limit"
    ENTITY_BUDGET = "entity_budget"
    PROVIDER_BUDGET = "provider_budget"


class PivotRejection(BaseModel):
    """One deterministic candidate rejection with bounded provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    proposed_depth: int | None = Field(default=None, ge=0)
    reason: PivotRejectionReason


class CoordinatorEntityView(BaseModel):
    """Immutable policy view of one visible persisted entity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    entity_type: EntityType
    value: str = ""
    deleted: bool = False


class CoordinatorPolicyContext(BaseModel):
    """Authoritative, short-lived snapshot supplied to the pure policy.

    ``missing_entity_ids`` carries candidate identities that do not resolve
    to a persisted visible or soft-deleted row, in root/discovery order, so
    the policy can emit an explicit ``UNKNOWN_TARGET`` rejection instead of
    silently ignoring them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entities: tuple[CoordinatorEntityView, ...] = ()
    missing_entity_ids: tuple[UUID, ...] = ()
    current_assessment: Assessment | None = None
    analysis_disposition: AnalysisDisposition | None = None
    analyzed_evidence_ids: tuple[UUID, ...] = ()


class CoordinatorAction(str, Enum):
    """Bounded coordinator actions understood by orchestration."""

    EXECUTE_PROVIDER_WORK = "execute_provider_work"
    REQUEST_ANALYSIS = "request_analysis"
    AUTHORIZE_PIVOT = "authorize_pivot"
    STOP = "stop"


class CoordinatorDecision(BaseModel):
    """A machine-readable coordinator decision with no prose plan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: CoordinatorAction
    work_items: tuple[ProviderWorkItem, ...] = ()
    pivots: tuple[PivotRequest, ...] = ()
    research_entity_ids: tuple[UUID, ...] = ()
    stop_reason: StopReason | None = None
    rejection_reasons: tuple[PivotRejectionReason, ...] = ()
    rejections: tuple[PivotRejection, ...] = ()
    consumes_replan: bool = False
    """True when authorization of this decision consumes one replan budget unit.

    Set only when at least one additional provider-work item is authorized
    after a NEEDS_MORE_EVIDENCE disposition. Never incremented for
    research-only marking, skipped duplicates, provider errors, or LLM repair
    attempts.
    """


class ProviderWorkPlanner(ABC):
    """Plan deterministic work using an injected applicability matrix."""

    @abstractmethod
    def plan(
        self, *, entity: CoordinatorEntityView, depth: int, state: InvestigationState
    ) -> tuple[ProviderWorkItem, ...]:
        """Return provider work in explicit stable order."""


class MappingProviderWorkPlanner(ProviderWorkPlanner):
    """Small production/test planner backed by a stable source/type matrix."""

    def __init__(self, applicability: dict[SourceId, frozenset[EntityType]]) -> None:
        """Copy and retain the already-composed provider applicability map."""
        self._applicability = dict(applicability)

    def plan(
        self, *, entity: CoordinatorEntityView, depth: int, state: InvestigationState
    ) -> tuple[ProviderWorkItem, ...]:
        """Produce work in mapping insertion order, without mutating state."""
        del state
        return tuple(
            ProviderWorkItem(provider=source, entity_id=entity.entity_id, depth=depth)
            for source, types in self._applicability.items()
            if entity.entity_type in types
        )


class CoordinatorPolicy:
    """Pure policy enforcing provenance, duplicate, depth, and budget rules."""

    def __init__(self, planner: ProviderWorkPlanner) -> None:
        """Bind the deterministic provider-work planner."""
        self._planner = planner

    def decide(
        self, *, state: InvestigationState, context: CoordinatorPolicyContext
    ) -> CoordinatorDecision:
        """Choose exactly one bounded next action from an authoritative snapshot."""
        # 1. Already stopped — stay stopped.
        if state.stop_reason is not None:
            return CoordinatorDecision(
                action=CoordinatorAction.STOP,
                stop_reason=StopReason(state.stop_reason),
            )

        # 2. Pending provider work always executes first, but never beyond
        #    the provider budget: the policy reports provider-budget
        #    exhaustion when pre-existing pending work cannot be executed
        #    within the remaining capacity.
        if state.pending_provider_work:
            remaining = (
                state.budget.max_provider_calls - state.budget.provider_calls_used
            )
            if len(state.pending_provider_work) > remaining:
                return CoordinatorDecision(
                    action=CoordinatorAction.STOP,
                    stop_reason=StopReason.PROVIDER_BUDGET_EXHAUSTED,
                    rejection_reasons=(PivotRejectionReason.PROVIDER_BUDGET,),
                )
            return CoordinatorDecision(action=CoordinatorAction.EXECUTE_PROVIDER_WORK)

        # 3. Derive current disposition. Invalid stored values must fail closed
        #    (typed state validation rejects them before policy runs); the
        #    resolver below only parses values the validator already accepted.
        disposition = self._resolve_disposition(state, context)
        analyzed_ids = self._resolve_analyzed_ids(state, context)
        current_evidence = set(state.evidence_ids)
        new_evidence = current_evidence - analyzed_ids

        # 3b. Discovered RESEARCHABLE entities are marked research-required
        #     with duplicate suppression as soon as the coordinator observes
        #     them, before any analysis or pivot round: marking research is a
        #     pure marker side effect, never a collection round, and never a
        #     reason to skip the analysis synchronization point that follows.
        researchable = self._new_researchable_markers(state, context)
        if researchable:
            return CoordinatorDecision(
                action=CoordinatorAction.AUTHORIZE_PIVOT,
                research_entity_ids=tuple(researchable),
                consumes_replan=False,
            )

        # 4. New evidence since the last analysis always requests analysis,
        #    even when the stored disposition says SUFFICIENT: a stale
        #    disposition must never skip the analysis synchronization point.
        if new_evidence:
            return CoordinatorDecision(action=CoordinatorAction.REQUEST_ANALYSIS)
        if disposition is None and current_evidence:
            # Evidence exists but no analysis has been performed yet.
            return CoordinatorDecision(action=CoordinatorAction.REQUEST_ANALYSIS)

        # 5. SUFFICIENT stops only when the disposition is current for the
        #    exact analyzed evidence set (guaranteed above).
        if disposition is AnalysisDisposition.SUFFICIENT:
            return CoordinatorDecision(
                action=CoordinatorAction.STOP,
                stop_reason=StopReason.SUFFICIENT_EVIDENCE,
            )

        # 6. NEEDS_MORE_EVIDENCE — try another round if replan budget allows.
        if disposition is AnalysisDisposition.NEEDS_MORE_EVIDENCE:
            if state.budget.replans_used >= state.budget.max_replans:
                return CoordinatorDecision(
                    action=CoordinatorAction.STOP,
                    stop_reason=StopReason.REPLAN_LIMIT_REACHED,
                )
            return self._authorize_candidates(state, context, consumes_replan=True)

        # 7. EXHAUSTED — try candidates; stop if none remain.
        if disposition is AnalysisDisposition.EXHAUSTED:
            return self._authorize_candidates(state, context, consumes_replan=False)

        # 8. No disposition yet and no new evidence — try candidates.
        return self._authorize_candidates(state, context, consumes_replan=False)

    @staticmethod
    def _resolve_disposition(
        state: InvestigationState,
        context: CoordinatorPolicyContext,
    ) -> AnalysisDisposition | None:
        """Resolve the current analysis disposition from context or state."""
        if context.analysis_disposition is not None:
            return context.analysis_disposition
        return state.analysis_disposition

    @staticmethod
    def _resolve_analyzed_ids(
        state: InvestigationState,
        context: CoordinatorPolicyContext,
    ) -> set[UUID]:
        """Resolve analyzed evidence IDs from context or state."""
        if context.analyzed_evidence_ids:
            return set(context.analyzed_evidence_ids)
        return set(state.analyzed_evidence_ids)

    def _candidate_order(
        self,
        state: InvestigationState,
        context: CoordinatorPolicyContext,
    ) -> tuple[UUID, ...]:
        """Return candidate identities in deterministic order.

        Roots first in ``root_entity_ids`` order, then discoveries by
        first-discovery ordinal. Missing traversal metadata for a discovered
        entity is a malformed-state error: it must never be silently treated
        as depth zero. No set iteration is involved.
        """
        known = set(state.root_entity_ids) | set(state.discovered_entity_ids)

        candidates: list[UUID] = []
        seen: set[UUID] = set()

        for entity_id in state.root_entity_ids:
            if entity_id in known and entity_id not in seen:
                candidates.append(entity_id)
                seen.add(entity_id)

        for entry in state.traversal:
            if (
                entry.entity_id in state.discovered_entity_ids
                and entry.entity_id not in seen
            ):
                candidates.append(entry.entity_id)
                seen.add(entry.entity_id)

        # A discovered entity without traversal metadata is malformed state.
        # The guard does not depend on traversal being non-empty: even a
        # completely empty traversal with discoveries present fails closed.
        missing = set(state.discovered_entity_ids) - {
            entry.entity_id for entry in state.traversal
        }
        if missing:
            raise ValueError(
                "discovered entity lacks traversal metadata after discovery"
            )

        # Missing persisted identities remain in the ordered ID stream and
        # are resolved to UNKNOWN_TARGET by the evaluation loop.
        for entity_id in context.missing_entity_ids:
            if entity_id in known and entity_id not in seen:
                candidates.append(entity_id)
                seen.add(entity_id)

        return tuple(candidates)

    @staticmethod
    def _admitted_entity_ids(state: InvestigationState) -> tuple[UUID, ...]:
        """Return the deterministic admitted working set within ``max_entities``.

        Admission is derived, never stored: unique roots in
        ``root_entity_ids`` order first, then discovered entities in durable
        first-discovery traversal order, deduplicated by entity ID, truncated
        to ``budget.max_entities``. Persisted overflow discoveries remain
        represented as discoveries but are not admitted: provider expansion
        through them is rejected with ``ENTITY_BUDGET`` while nothing is ever
        deleted (Invariant B). A discovered entity without traversal metadata
        is malformed state and fails closed exactly like candidate ordering.
        """
        missing = set(state.discovered_entity_ids) - {
            entry.entity_id for entry in state.traversal
        }
        # The guard does not depend on traversal being non-empty: even a
        # completely empty traversal with discoveries present fails closed.
        if missing:
            raise ValueError(
                "discovered entity lacks traversal metadata after discovery"
            )
        admitted: list[UUID] = []
        seen: set[UUID] = set()
        capacity = state.budget.max_entities
        for entity_id in state.root_entity_ids:
            if entity_id in seen or len(admitted) >= capacity:
                continue
            seen.add(entity_id)
            admitted.append(entity_id)
        for entry in state.traversal:
            if entry.entity_id not in state.discovered_entity_ids:
                continue
            if entry.entity_id in seen or len(admitted) >= capacity:
                continue
            seen.add(entry.entity_id)
            admitted.append(entry.entity_id)
        return tuple(admitted)

    @staticmethod
    def _new_researchable_markers(
        state: InvestigationState, context: CoordinatorPolicyContext
    ) -> list[UUID]:
        """Return discovered RESEARCHABLE entity IDs not yet marked.

        Ordered deterministically by candidate order (roots then discovery
        order); duplicate markers are suppressed.
        """
        known = set(state.root_entity_ids) | set(state.discovered_entity_ids)
        already = set(state.research_required_for_entity_ids)
        views = {entity.entity_id: entity for entity in context.entities}
        ordered: list[UUID] = []
        seen: set[UUID] = set()
        for entity_id in state.root_entity_ids:
            if entity_id in known and entity_id not in seen:
                seen.add(entity_id)
                ordered.append(entity_id)
        for entry in state.traversal:
            if entry.entity_id in known and entry.entity_id not in seen:
                seen.add(entry.entity_id)
                ordered.append(entry.entity_id)
        markers: list[UUID] = []
        for entity_id in ordered:
            entity = views.get(entity_id)
            if entity is None or entity.deleted:
                continue
            try:
                cls = pivot_class(entity.entity_type)
            except KeyError:
                continue
            if cls is PivotClass.RESEARCHABLE and entity_id not in already:
                markers.append(entity_id)
        return markers

    def _authorize_candidates(
        self,
        state: InvestigationState,
        context: CoordinatorPolicyContext,
        *,
        consumes_replan: bool,
    ) -> CoordinatorDecision:
        """Evaluate candidates in deterministic order and authorize the first eligible pivot."""
        candidates = self._candidate_order(state, context)
        admitted_entity_ids = self._admitted_entity_ids(state)
        views = {entity.entity_id: entity for entity in context.entities}
        missing = set(context.missing_entity_ids)

        work: list[ProviderWorkItem] = []
        pivots: list[PivotRequest] = []
        research: list[UUID] = []
        rejections: list[PivotRejection] = []
        blocked: dict[PivotRejectionReason, int] = {}

        def reject(
            entity_id: UUID,
            depth: int | None,
            reason: PivotRejectionReason,
        ) -> None:
            rejections.append(
                PivotRejection(entity_id=entity_id, proposed_depth=depth, reason=reason)
            )
            self._count_blocked(blocked, reason)

        for entity_id in candidates:
            depth = self._minimum_depth(entity_id, state)
            entity = views.get(entity_id)
            if entity_id in missing or entity is None:
                reject(entity_id, depth, PivotRejectionReason.UNKNOWN_TARGET)
                continue
            if entity.deleted:
                reject(entity_id, depth, PivotRejectionReason.DELETED_TARGET)
                continue
            try:
                pc = pivot_class(entity.entity_type)
            except KeyError:
                reject(entity_id, depth, PivotRejectionReason.UNSUPPORTED_CLASS)
                continue
            if pc is PivotClass.RESEARCHABLE:
                if entity_id not in state.research_required_for_entity_ids:
                    research.append(entity_id)
                continue
            if depth > state.budget.max_depth:
                reject(entity_id, depth, PivotRejectionReason.DEPTH_LIMIT)
                continue

            planned = tuple(
                item
                for item in self._planner.plan(entity=entity, depth=depth, state=state)
                if not self._work_exists(item, state)
            )
            if not planned:
                reject(entity_id, depth, PivotRejectionReason.NO_PROVIDER_PATH)
                continue
            if self._investigated_at_or_better(entity_id, depth, state):
                reject(entity_id, depth, PivotRejectionReason.ALREADY_INVESTIGATED)
                continue
            if self._equivalent_pivot_exists(entity_id, depth, state):
                reject(entity_id, depth, PivotRejectionReason.DUPLICATE_PIVOT)
                continue

            known = set(state.root_entity_ids) | set(state.discovered_entity_ids)
            if entity_id not in known:
                reject(entity_id, depth, PivotRejectionReason.UNKNOWN_TARGET)
                continue
            # Admission is deterministic capacity over unique roots (in order)
            # then discoveries (in first-discovery order). A persisted
            # overflow discovery is not authorized for expansion, but an
            # already-admitted entity is eligible even at exact capacity.
            if entity_id not in admitted_entity_ids:
                reject(entity_id, depth, PivotRejectionReason.ENTITY_BUDGET)
                continue

            remaining_capacity = (
                state.budget.max_provider_calls
                - state.budget.provider_calls_used
                - len(work)
            )
            if remaining_capacity < len(planned):
                reject(entity_id, depth, PivotRejectionReason.PROVIDER_BUDGET)
                continue

            work.extend(planned)
            pivots.append(
                PivotRequest(
                    entity_id=entity_id,
                    reason="eligible_pivot",
                    depth=depth,
                    status=PivotStatus.PENDING,
                )
            )
            break

        rejection_tuple = tuple(rejections)
        reason_tuple = tuple(item.reason for item in rejections)
        if research and not work and not pivots:
            return CoordinatorDecision(
                action=CoordinatorAction.AUTHORIZE_PIVOT,
                research_entity_ids=tuple(research),
                rejection_reasons=reason_tuple,
                rejections=rejection_tuple,
                consumes_replan=False,
            )
        if work:
            return CoordinatorDecision(
                action=CoordinatorAction.AUTHORIZE_PIVOT,
                work_items=tuple(work),
                pivots=tuple(pivots),
                rejection_reasons=reason_tuple,
                rejections=rejection_tuple,
                consumes_replan=consumes_replan,
            )
        return self._stop_for_blocked_candidates(
            blocked,
            replan=consumes_replan,
            state=state,
            rejections=rejection_tuple,
        )

    @staticmethod
    def _count_blocked(
        blocked: dict[PivotRejectionReason, int], reason: PivotRejectionReason
    ) -> None:
        """Increment the blocker count for one reason."""
        blocked[reason] = blocked.get(reason, 0) + 1

    @staticmethod
    def _minimum_depth(entity_id: UUID, state: InvestigationState) -> int:
        """Return the minimum depth of an entity from traversal metadata.

        Roots are depth zero. A discovered entity missing traversal metadata
        is malformed state and fails closed rather than defaulting to zero.
        """
        if entity_id in state.root_entity_ids:
            return 0
        for entry in state.traversal:
            if entry.entity_id == entity_id:
                return entry.minimum_depth
        raise ValueError(f"discovered entity {entity_id} lacks traversal metadata")

    @staticmethod
    def _work_exists(item: ProviderWorkItem, state: InvestigationState) -> bool:
        """Return True when equivalent provider work exists at same-or-better depth."""
        for pending in state.pending_provider_work:
            if (
                pending.provider == item.provider
                and pending.entity_id == item.entity_id
                and pending.depth <= item.depth
            ):
                return True
        if state.current_provider_work is not None:
            current = state.current_provider_work
            if (
                current.provider == item.provider
                and current.entity_id == item.entity_id
                and current.depth <= item.depth
            ):
                return True
        for completed in state.completed_provider_work:
            if (
                completed.provider == item.provider
                and completed.entity_id == item.entity_id
                and completed.depth <= item.depth
            ):
                return True
        return False

    @staticmethod
    def _equivalent_pivot_exists(
        entity_id: UUID, depth: int, state: InvestigationState
    ) -> bool:
        """Return True when an equivalent pivot exists at same-or-better depth.

        Only pending pivots count: a completed pivot is represented by
        ``investigated_entity_ids`` and the same-or-better-depth rule.
        """
        for pivot in state.pending_pivots:
            if (
                pivot.status is not PivotStatus.SKIPPED
                and pivot.entity_id == entity_id
                and pivot.depth <= depth
            ):
                return True
        return False

    @staticmethod
    def _investigated_at_or_better(
        entity_id: UUID, depth: int, state: InvestigationState
    ) -> bool:
        """Return True when the entity was already investigated at <= depth.

        The previous execution depth is the durable ``best_investigated_depth``
        from traversal — never the current minimum discovery depth, which can
        be lowered by a rediscovery and would otherwise falsely suppress a
        valid shallower pivot.
        """
        if entity_id not in state.investigated_entity_ids:
            return False
        previous_depth = None
        for entry in state.traversal:
            if entry.entity_id == entity_id:
                previous_depth = entry.best_investigated_depth
                break
        if previous_depth is None:
            # No executed depth recorded: conservatively treat a legacy
            # investigated marker as same-or-better suppression.
            return True
        return previous_depth <= depth

    def _stop_for_blocked_candidates(
        self,
        blocked: dict[PivotRejectionReason, int],
        *,
        replan: bool,
        state: InvestigationState,
        rejections: tuple[PivotRejection, ...],
    ) -> CoordinatorDecision:
        """Determine the specific stop reason and retain candidate rejections."""
        total_blocked = sum(blocked.values())
        if total_blocked == 0:
            reason = (
                StopReason.REPLAN_LIMIT_REACHED
                if replan and state.budget.replans_used >= state.budget.max_replans
                else StopReason.NO_ELIGIBLE_PIVOTS
            )
            return CoordinatorDecision(
                action=CoordinatorAction.STOP,
                stop_reason=reason,
                rejections=rejections,
            )

        depth_count = blocked.get(PivotRejectionReason.DEPTH_LIMIT, 0)
        entity_count = blocked.get(PivotRejectionReason.ENTITY_BUDGET, 0)
        provider_count = blocked.get(PivotRejectionReason.PROVIDER_BUDGET, 0)
        # Duplicate/already-exhausted/non-provider candidates are not valid
        # expansion candidates and therefore do not dilute the actual resource
        # blocker for another otherwise-actionable candidate.
        depth_only = depth_count > 0 and entity_count == provider_count == 0
        entity_only = entity_count > 0 and depth_count == provider_count == 0
        provider_only = provider_count > 0 and depth_count == entity_count == 0
        reasons: tuple[PivotRejectionReason, ...]
        if provider_only:
            reason = StopReason.PROVIDER_BUDGET_EXHAUSTED
            reasons = (PivotRejectionReason.PROVIDER_BUDGET,)
        elif entity_only:
            reason = StopReason.ENTITY_BUDGET_EXHAUSTED
            reasons = (PivotRejectionReason.ENTITY_BUDGET,)
        elif depth_only:
            reason = StopReason.DEPTH_LIMIT_REACHED
            reasons = (PivotRejectionReason.DEPTH_LIMIT,)
        elif replan and state.budget.replans_used >= state.budget.max_replans:
            reason = StopReason.REPLAN_LIMIT_REACHED
            reasons = tuple(blocked.keys())
        else:
            reason = StopReason.NO_ELIGIBLE_PIVOTS
            reasons = tuple(blocked.keys())
        return CoordinatorDecision(
            action=CoordinatorAction.STOP,
            stop_reason=reason,
            rejection_reasons=reasons,
            rejections=rejections,
        )


class AnalysisExecutor(ABC):
    """Execution boundary for the existing Evidence Analyst service."""

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the investigation binding, or ``None`` for unbound executors."""
        return None

    @abstractmethod
    async def analyze(self, investigation_id: UUID) -> AnalysisOutcome:
        """Analyze persisted evidence outside orchestration transactions."""


class AnalysisOutcome(BaseModel):
    """Minimal analyst result needed by coordinator policy.

    ``investigation_version`` is the authoritative Investigation version after
    the Assessment persistence transaction; the graph requires an exact match
    with the durable row it reloads.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_id: UUID
    disposition: AnalysisDisposition
    analyzed_evidence_ids: tuple[UUID, ...] = ()
    investigation_version: int = Field(ge=0)


class FakeAnalysisExecutor(AnalysisExecutor):
    """Deterministic scripted analyst used by unit and integration tests."""

    def __init__(
        self,
        outcomes: tuple[AnalysisOutcome, ...],
        *,
        bound_investigation_id: UUID | None = None,
    ) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0
        self.called_with: list[UUID] = []
        self._bound_investigation_id = bound_investigation_id

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the configured binding when set."""
        return self._bound_investigation_id

    async def analyze(self, investigation_id: UUID) -> AnalysisOutcome:
        """Return the next scripted outcome, failing closed when exhausted."""
        if (
            self._bound_investigation_id is not None
            and investigation_id != self._bound_investigation_id
        ):
            raise ValueError(
                "analysis executor investigation does not match the requested "
                "investigation"
            )
        self.called_with.append(investigation_id)
        if not self._outcomes:
            raise RuntimeError("fake analysis outcomes exhausted")
        self.calls += 1
        return self._outcomes.pop(0)
