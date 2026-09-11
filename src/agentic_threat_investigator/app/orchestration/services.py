# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator application services (PR 21).

Narrow application-layer adapters that sit between the pure
``CoordinatorPolicy`` and the graph/LLM/persistence boundaries:

- :class:`CoordinatorPolicyContextLoader` materializes the read-only policy
  context from a short UnitOfWork and closes it before policy execution;
- :class:`CoordinatorTransitionService` persists coordinator transitions
  through the versioned Investigation repository operation;
- :class:`EvidenceAnalystAnalysisExecutor` wraps the PR 20B Evidence Analyst
  and returns the typed :class:`AnalysisOutcome` used by the graph.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from agentic_threat_investigator.app.analysis_result import EvidenceAnalysisResult
from agentic_threat_investigator.app.evidence_analyst.analyst import EvidenceAnalyst
from agentic_threat_investigator.app.orchestration.coordinator import (
    AnalysisExecutor,
    AnalysisOutcome,
    CoordinatorEntityView,
    CoordinatorPolicyContext,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    UnitOfWork,
)
from agentic_threat_investigator.domain.assessment import Assessment
from agentic_threat_investigator.domain.investigation import (
    CoordinatorTransitionKind,
    InvestigationError,
    InvestigationState,
    InvestigationStatus,
    StopReason,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)


class CoordinatorContextLoader(ABC):
    """Load the authoritative read-only policy context for one investigation."""

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return an optional fixed Investigation binding."""
        return None

    @abstractmethod
    async def load(
        self, investigation_id: UUID, expected_version: int
    ) -> CoordinatorPolicyContext:
        """Return the policy context; the read transaction is already closed.

        ``expected_version`` is the durable Investigation version the policy
        is deciding against; a loader that observes a different durable
        version rejects the context so policy never mixes an in-memory state
        with a context built from a different persisted version.
        """


class UowCoordinatorContextLoader(CoordinatorContextLoader):
    """Load the policy context through one short read-only UnitOfWork.

    The transaction is fully closed before the context is returned, so no
    database transaction is ever held across policy, provider, or LLM
    execution.
    """

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        *,
        bound_investigation_id: UUID | None = None,
    ) -> None:
        """Bind the loader to a UnitOfWork factory and optional identity."""
        self._uow_factory = uow_factory
        self._bound_investigation_id = bound_investigation_id

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the configured Investigation binding."""
        return self._bound_investigation_id

    async def load(
        self, investigation_id: UUID, expected_version: int
    ) -> CoordinatorPolicyContext:
        """Load entities and the current Assessment, then close the UoW.

        The durable Investigation version must equal ``expected_version`` or
        the context is rejected: the loaded entity/Assessment snapshot derives
        exclusively from the durable row policy is decided against.
        """
        if (
            self._bound_investigation_id is not None
            and investigation_id != self._bound_investigation_id
        ):
            raise ValueError("context loader investigation binding mismatch")
        async with self._uow_factory() as uow:
            investigation = await uow.investigations.get_by_id(investigation_id)
            if investigation is None:
                raise InvestigationNotFoundError(str(investigation_id))
            if investigation.version != expected_version:
                raise ValueError(
                    "coordinator policy context version does not match the "
                    "graph state version"
                )

            # Preserve root/discovery order deterministically: roots in
            # root_entity_ids order, then discoveries in traversal ordinal
            # order. Entities are read with include_deleted=True so deleted
            # and missing targets remain distinguishable; identities that do
            # not resolve are carried explicitly as missing.
            candidate_ids: list[UUID] = []
            seen: set[UUID] = set()
            for entity_id in investigation.root_entity_ids:
                if entity_id not in seen:
                    seen.add(entity_id)
                    candidate_ids.append(entity_id)
            for entry in investigation.traversal:
                if entry.entity_id not in seen:
                    seen.add(entry.entity_id)
                    candidate_ids.append(entry.entity_id)
            for entity_id in investigation.discovered_entity_ids:
                if entity_id not in seen:
                    seen.add(entity_id)
                    candidate_ids.append(entity_id)

            views: list[CoordinatorEntityView] = []
            missing: list[UUID] = []
            for entity_id in candidate_ids:
                entity = await uow.entities.get_by_id(entity_id, include_deleted=True)
                if entity is None:
                    missing.append(entity_id)
                    continue
                views.append(
                    CoordinatorEntityView(
                        entity_id=entity.id or entity_id,
                        entity_type=entity.type,
                        value=entity.value,
                        deleted=entity.deleted_at is not None,
                    )
                )

            assessment: Assessment | None = None
            if investigation.assessment_id is not None:
                assessment = await uow.assessments.get_by_id(
                    investigation.assessment_id
                )
                if assessment is None:
                    raise ValueError(
                        "coordinator current Assessment is missing or deleted"
                    )
                if assessment.investigation_id != investigation_id:
                    raise ValueError(
                        "coordinator current Assessment belongs to another investigation"
                    )
                if tuple(assessment.analyzed_evidence_ids) != tuple(
                    investigation.analyzed_evidence_ids
                ):
                    raise ValueError(
                        "coordinator analysis metadata does not match Assessment"
                    )
                if investigation.analysis_disposition is None:
                    raise ValueError(
                        "coordinator current Assessment lacks analysis disposition"
                    )

            return CoordinatorPolicyContext(
                entities=tuple(views),
                missing_entity_ids=tuple(missing),
                current_assessment=assessment,
                analysis_disposition=investigation.analysis_disposition,
                analyzed_evidence_ids=tuple(investigation.analyzed_evidence_ids),
            )


class CoordinatorTransitionService(ABC):
    """Persist one coordinator transition atomically with version/history."""

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return an optional fixed Investigation binding."""
        return None

    @abstractmethod
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
        """Persist the transition and return the authoritative state.

        ``events`` are appended through the same UnitOfWork transaction as
        the state change, so a coordinator action is never persisted without
        the transition that produced it.
        """

    @abstractmethod
    async def reload(self, investigation_id: UUID) -> InvestigationState:
        """Return the authoritative durable Investigation state."""

    @abstractmethod
    async def emit(self, event: InvestigationTimelineEvent) -> None:
        """Append one coordinator event in a short committed UoW."""


class UowCoordinatorTransitionService(CoordinatorTransitionService):
    """Persist transitions through one short UnitOfWork write transaction."""

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        *,
        bound_investigation_id: UUID | None = None,
    ) -> None:
        """Bind the service to a UnitOfWork factory and optional identity."""
        self._uow_factory = uow_factory
        self._bound_investigation_id = bound_investigation_id

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the configured Investigation binding."""
        return self._bound_investigation_id

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
        """Persist the state atomically and return the authoritative row."""
        if (
            self._bound_investigation_id is not None
            and investigation_id != self._bound_investigation_id
        ):
            raise ValueError("transition service investigation binding mismatch")
        if state.investigation_id != investigation_id:
            raise ValueError(
                "coordinator transition state investigation does not match "
                "the target investigation"
            )
        if any(event.investigation_id != investigation_id for event in events):
            raise ValueError(
                "coordinator timeline event investigation does not match transition"
            )
        validated = InvestigationState.model_validate(state.model_dump())
        async with self._uow_factory() as uow:
            result = await uow.investigations.update_coordinator_state(
                investigation_id,
                transition_kind,
                validated,
                actor_id=actor_id,
                request_id=request_id,
                expected_version=expected_version,
                consumes_replan=consumes_replan,
            )
            for event in events:
                await uow.timeline_events.append(event)
            refreshed = await uow.investigations.get_by_id(investigation_id)
        if refreshed is None:
            raise InvestigationNotFoundError(str(investigation_id))
        return refreshed.model_copy(update={"version": result.version})

    async def reload(self, investigation_id: UUID) -> InvestigationState:
        """Return the authoritative durable Investigation state."""
        if (
            self._bound_investigation_id is not None
            and investigation_id != self._bound_investigation_id
        ):
            raise ValueError("transition reload investigation binding mismatch")
        async with self._uow_factory() as uow:
            refreshed = await uow.investigations.get_by_id(investigation_id)
        if refreshed is None:
            raise InvestigationNotFoundError(str(investigation_id))
        return refreshed

    async def emit(self, event: InvestigationTimelineEvent) -> None:
        """Append one coordinator event in a short committed UoW."""
        if (
            self._bound_investigation_id is not None
            and event.investigation_id != self._bound_investigation_id
        ):
            raise ValueError("timeline event investigation binding mismatch")
        async with self._uow_factory() as uow:
            await uow.timeline_events.append(event)


class EvidenceAnalystAnalysisExecutor(AnalysisExecutor):
    """Production AnalysisExecutor adapter around the PR 20B Evidence Analyst.

    The disposition is the approved typed output of the analyst decision
    (never derived from verdict). LLM reservation/accounting remains entirely
    in ``LlmAccountingService``. The requested investigation ID is validated
    against the bound identity before any LLM/persistence work.
    """

    def __init__(
        self,
        analyst: EvidenceAnalyst,
        *,
        bound_investigation_id: UUID | None = None,
    ) -> None:
        """Bind the analyst and optional investigation identity."""
        self._analyst = analyst
        self._bound_investigation_id = bound_investigation_id
        self.requested_ids: list[UUID] = []

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the configured investigation binding, if any."""
        return self._bound_investigation_id

    async def analyze(self, investigation_id: UUID) -> AnalysisOutcome:
        """Analyze persisted evidence and return the typed outcome.

        The analyst loads, analyzes, and persists the Assessment outside any
        orchestration transaction; cancellation propagates unchanged. The
        disposition is the required typed analyst output; an empty analyzed
        Evidence set is preserved exactly and never substituted, and a
        missing persisted Assessment identity is rejected rather than
        fabricated.
        """
        if (
            self._bound_investigation_id is not None
            and investigation_id != self._bound_investigation_id
        ):
            raise ValueError(
                "analysis executor investigation does not match the requested "
                "investigation"
            )
        self.requested_ids.append(investigation_id)
        result = await self._analyst.analyze_with_result(investigation_id)
        return self._outcome_from_result(result)

    @staticmethod
    def _outcome_from_result(result: EvidenceAnalysisResult) -> AnalysisOutcome:
        """Build the typed outcome from the authoritative persisted result.

        The disposition is the required typed semantic output of the analyst
        decision; it is never inferred from verdict, confidence, findings,
        or recommendation prose. An empty analyzed Evidence set is preserved
        exactly and a missing persisted Assessment ID is rejected.
        """
        if result.assessment.id is None:
            raise ValueError(
                "analysis persistence returned an Assessment without identity"
            )
        return AnalysisOutcome(
            assessment_id=result.assessment.id,
            disposition=result.disposition,
            analyzed_evidence_ids=tuple(result.assessment.analyzed_evidence_ids),
            investigation_version=result.investigation_version,
        )


class InvestigationStatusWriter(ABC):
    """Write a terminal status transition under lifecycle rules."""

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return an optional fixed Investigation binding."""
        return None

    @abstractmethod
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
        """Persist the terminal status and stop reason atomically.

        ``state`` carries the terminal in-memory transition (status
        COMPLETED/FAILED plus the stable stop reason); the database owns
        ``completed_at`` and the version/history. ``events`` (for example
        INVESTIGATION_STOPPED) are appended in the same transaction.
        """


class UowInvestigationStatusWriter(InvestigationStatusWriter):
    """Persist the terminal transition through one short write UnitOfWork."""

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        *,
        bound_investigation_id: UUID | None = None,
    ) -> None:
        """Bind the writer to a UnitOfWork factory and optional identity."""
        self._uow_factory = uow_factory
        self._bound_investigation_id = bound_investigation_id

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the configured Investigation binding."""
        return self._bound_investigation_id

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
        """Persist status COMPLETED + stop_reason; the DB owns completed_at."""
        del stop_reason  # the terminal state already carries the stop reason
        if (
            self._bound_investigation_id is not None
            and investigation_id != self._bound_investigation_id
        ):
            raise ValueError("status writer investigation binding mismatch")
        if state.investigation_id != investigation_id:
            raise ValueError("terminal state investigation does not match target")
        if any(event.investigation_id != investigation_id for event in events):
            raise ValueError("terminal event investigation does not match target")
        async with self._uow_factory() as uow:
            current = await uow.investigations.get_by_id(investigation_id)
            if current is None:
                raise InvestigationNotFoundError(str(investigation_id))
            result = await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.FINALIZE_STOP,
                state,
                actor_id=actor_id,
                request_id=request_id,
                expected_version=expected_version,
            )
            for event in events:
                await uow.timeline_events.append(event)
            refreshed = await uow.investigations.get_by_id(investigation_id)
        if refreshed is None:
            raise InvestigationNotFoundError(str(investigation_id))
        return refreshed.model_copy(update={"version": result.version})


class FatalStopService(ABC):
    """Persist one bounded fatal stop for an unrecoverable error.

    Provider failure outcomes remain ordinary recoverable coordinator input;
    this service is reserved for unrecoverable analysis/context/orchestration
    errors mapped to the approved fatal stop. Persistence failures propagate
    unchanged — a fatal stop is never claimed when it was not persisted.
    """

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return an optional fixed Investigation binding."""
        return None

    @abstractmethod
    async def fatalize(
        self,
        investigation_id: UUID,
        error: InvestigationError,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationState:
        """Append the bounded error, transition RUNNING -> FAILED with
        ``StopReason.FATAL_ERROR``, and append INVESTIGATION_STOPPED in one
        short transaction."""


class UowFatalStopService(FatalStopService):
    """Persist the fatal stop through one short write UnitOfWork."""

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        clock: Callable[[], datetime] | None = None,
        *,
        bound_investigation_id: UUID | None = None,
    ) -> None:
        """Bind the UoW factory, clock, and optional identity."""
        self._uow_factory = uow_factory
        self._bound_investigation_id = bound_investigation_id
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the configured Investigation binding."""
        return self._bound_investigation_id

    async def fatalize(
        self,
        investigation_id: UUID,
        error: InvestigationError,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationState:
        """Append the error and persist RUNNING -> FAILED FATAL_ERROR."""
        if (
            self._bound_investigation_id is not None
            and investigation_id != self._bound_investigation_id
        ):
            raise ValueError("fatal service investigation binding mismatch")
        from agentic_threat_investigator.app.orchestration.timeline_actions import (
            DeterministicTimelineActionService,
        )

        async with self._uow_factory() as uow:
            current = await uow.investigations.get_by_id(investigation_id)
            if current is None:
                raise InvestigationNotFoundError(str(investigation_id))
            terminal = InvestigationState.model_validate(
                current.model_copy(
                    update={
                        "status": InvestigationStatus.FAILED,
                        "stop_reason": StopReason.FATAL_ERROR.value,
                        "errors": [*current.errors, error],
                    }
                ).model_dump()
            )
            result = await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.FINALIZE_STOP,
                terminal,
                actor_id=actor_id,
                request_id=request_id,
                expected_version=expected_version,
            )
            stop_event = DeterministicTimelineActionService(
                self._clock
            ).investigation_stopped(stop_reason=StopReason.FATAL_ERROR, state=terminal)
            await uow.timeline_events.append(stop_event)
            refreshed = await uow.investigations.get_by_id(investigation_id)
        if refreshed is None:
            raise InvestigationNotFoundError(str(investigation_id))
        return refreshed.model_copy(update={"version": result.version})
