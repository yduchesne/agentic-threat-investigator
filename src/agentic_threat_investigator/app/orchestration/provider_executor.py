# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Production provider execution adapter for investigation orchestration (PR 19B).

Connects one deterministic PR 19A work item to the existing ATI seams:

    ProviderWorkItem
        -> resolve persisted target Entity (short transaction, closed
           before any provider I/O)
        -> validate provider applicability
        -> call the existing EvidenceProvider (outside all transactions)
        -> per normalized Evidence, in provider-return order:
               PR 18B deterministic extraction (outside transactions)
               PR 18C atomic provider-observation persistence
        -> persisted analyst-facing timeline events
        -> ProviderExecutionOutcome for the existing record_outcome node

The executor owns orchestration only. Providers retrieve and normalize;
PR 18B extracts; PR 18C is the sole atomic evidence/graph persistence seam.
No pivot policy, scheduling of discovered entities, LLM behavior, budget
enforcement, or stopping policy lives here.

Every provider result is bound to the selected work before any extraction
or persistence: the returned provider identity, each Evidence's owning
investigation, and each Evidence subject must match the selected provider,
the selected work item, and the authoritative persisted target. A binding
violation fails the work deterministically with a safe stable code and
writes no observation.

Provider output may legally contain normalized evidence together with typed
errors (``ProviderResult`` validates the two collections independently,
e.g. after independent RR-type lookups). Under the approved PR 19B
outcome-status contract, a mixed result is a valid partial provider result:
valid evidence is processed and persisted in provider-return order; when at
least one Evidence observation committed and no extraction, persistence, or
timeline failure followed, the status is ``SUCCEEDED`` and only the first
provider error (provider-return order) is retained — its stable code and
retryability, never its free-form message. The retained code is carried on
the ``PROVIDER_WORK_COMPLETED`` event's ``error_code`` so the timeline
accurately exposes the partial result. If extraction, persistence, or
timeline processing fails after Evidence commits, ``FAILED`` takes precedence
and all previously committed IDs remain in the outcome. Errors without
Evidence remain ``FAILED``; an all-empty result remains ``SUCCEEDED``. No
PARTIAL execution status exists in PR 19B.

Failed work outcomes always retain every ID from observations that already
committed before the failure; later failures never compensate earlier
commits. Caught exceptions are never attached to logs: provider,
persistence, and timeline failures are logged as bounded fixed-format
summaries carrying stable operational identifiers only.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionError,
    ExtractionResult,
)
from agentic_threat_investigator.app.investigation_timeline import (
    InvestigationTimelineSink,
)
from agentic_threat_investigator.app.orchestration.executor import (
    InvestigationBoundWorkExecutor,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceResult,
    ProviderObservationPersistenceService,
)
from agentic_threat_investigator.app.providers import EvidenceProvider, ProviderResult
from agentic_threat_investigator.domain.entities import Entity, EntityType, canonicalize
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationError,
    ProviderExecutionOutcome,
    ProviderExecutionStatus,
    ProviderWorkItem,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)

LOGGER = logging.getLogger(__name__)

ERROR_TARGET_NOT_FOUND = "target_not_found"
ERROR_PROVIDER_NOT_CONFIGURED = "provider_not_configured"
ERROR_UNSUPPORTED_INDICATOR = "unsupported_indicator"
ERROR_PROVIDER_ERROR = "provider_error"
ERROR_EXTRACTION_ERROR = "extraction_error"
ERROR_PERSISTENCE_ERROR = "persistence_error"
ERROR_TIMELINE_ERROR = "timeline_error"
ERROR_PROVIDER_BINDING = "provider_binding"


def _append_unique(target: list[UUID], candidate: UUID) -> None:
    """Append ``candidate`` to ``target`` only when not already present.

    Preserves first-seen deterministic order so the successful outcome, a
    failed partial outcome, the aggregate ``PROVIDER_WORK_COMPLETED`` event,
    and the merged state all carry the same canonical ID lists. Deduplication
    happens while accumulating operational summaries only; provider-returned
    Evidence is still processed exactly once in provider-return order.
    """
    if candidate not in target:
        target.append(candidate)


def _canonicalize_or_none(entity_type: EntityType, value: str) -> str | None:
    """Return the canonical value, or ``None`` when canonicalization raises.

    Narrowly converts canonicalization failures (malformed values, unsupported
    identity contracts) into a binding sentinel so defective provider or reader
    output fails closed instead of escaping the executor. No exception text or
    raw value is ever logged or stored.
    """
    try:
        return canonicalize(entity_type, value)
    except ValueError:
        return None


def _target_binding_error(work_item: ProviderWorkItem, target: Entity) -> str | None:
    """Validate the authoritative persisted target against the selected work item.

    Returns ``ERROR_PROVIDER_BINDING`` when the target cannot be the
    authoritative Entity selected by ``work_item.entity_id``: a missing
    identifier, an identifier different from the work item, or a value that is
    not already canonical for its type. Canonicalization failures fold into the
    same deterministic code; the exception never escapes and no raw value or
    message is exposed.
    """
    if target.id is None or target.id != work_item.entity_id:
        return ERROR_PROVIDER_BINDING
    canonical_value = _canonicalize_or_none(target.type, target.value)
    if canonical_value is None or target.value != canonical_value:
        return ERROR_PROVIDER_BINDING
    return None


@dataclass(frozen=True)
class ProviderExecutionContext:
    """Per-run execution context injected at composition time.

    Carries the owning investigation identity, correlation identifiers, and
    the deterministic clock used for timeline timestamps. No configuration
    reads, environment access, or service locators.
    """

    investigation_id: UUID
    actor_id: UUID | None = None
    request_id: UUID | None = None
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))


class EntityReader(ABC):
    """Read one persisted canonical entity by identifier.

    Implementations must use a short transaction that is fully closed before
    any provider network I/O occurs, and must return ``None`` for missing or
    soft-deleted entities.
    """

    @abstractmethod
    async def get(self, entity_id: UUID) -> Entity | None:
        """Return the visible entity, or ``None`` when missing or soft-deleted."""


class UowEntityReader(EntityReader):
    """Read one persisted entity through a short UnitOfWork transaction.

    The transaction is fully closed before any provider network I/O occurs;
    the persisted Entity remains authoritative and is converted to the
    provider input contract by the caller.
    """

    def __init__(self, uow_factory: Callable[[], UnitOfWork]) -> None:
        self._uow_factory = uow_factory

    async def get(self, entity_id: UUID) -> Entity | None:
        """Return the visible entity, or ``None`` when missing or deleted."""
        async with self._uow_factory() as uow:
            return await uow.entities.get_by_id(entity_id)


class ProviderWorkExecutor(InvestigationBoundWorkExecutor):
    """Execute one approved provider work item through the real ATI seams.

    Bound to exactly one ``ProviderExecutionContext.investigation_id``: every
    provider call, Evidence validation/persistence, and timeline event uses
    that identity. Exposing it as :class:`InvestigationBoundWorkExecutor` lets
    the generic graph builder adopt it automatically as the graph binding so
    direct composition cannot bypass investigation isolation.
    """

    @property
    def bound_investigation_id(self) -> UUID:
        """Return the authoritative investigation identity of this executor."""
        return self._context.investigation_id

    # The explicit constructor dependencies are the injected composition seam.
    def __init__(
        self,
        *,
        entity_reader: EntityReader,
        provider_registry: Mapping[SourceId, EvidenceProvider],
        extractor: Callable[[Evidence], ExtractionResult],
        persistence_service: ProviderObservationPersistenceService,
        timeline_service: InvestigationTimelineSink | None,
        context: ProviderExecutionContext,
    ) -> None:
        self._entity_reader = entity_reader
        self._provider_registry = provider_registry
        self._extractor = extractor
        self._persistence_service = persistence_service
        self._timeline_service = timeline_service
        self._context = context

    async def execute(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        """Execute one work item and return its typed operational outcome."""
        # The return count is intrinsic to the distinct deterministic failure
        # gates; the narrow disable follows repository convention for such
        # validation-heavy flows.
        provider = self._provider_registry.get(work_item.provider)
        if provider is None:
            return await self._fail_work(
                work_item,
                ERROR_PROVIDER_NOT_CONFIGURED,
                recoverable=False,
            )
        if provider.id != work_item.provider.value:
            # The registry maps a source URN to a provider that claims a
            # different identity: a composition defect. The provider must not
            # be invoked and only the safe failure event is emitted.
            return await self._fail_work(work_item, ERROR_PROVIDER_BINDING)

        target = await self._entity_reader.get(work_item.entity_id)
        if target is None or target.deleted_at is not None:
            return await self._fail_work(work_item, ERROR_TARGET_NOT_FOUND)

        # The persisted Entity is authoritative: it must be the exact Entity
        # selected by the work item with an already-canonical value, or a
        # faulty reader could substitute another Entity while timeline events
        # retain the requested target ID. A violation fails before the
        # provider is invoked and before any event besides the safe failure.
        target_error = _target_binding_error(work_item, target)
        if target_error is not None:
            return await self._fail_work(work_item, target_error)

        if not provider.supports(target):
            return await self._fail_work(work_item, ERROR_UNSUPPORTED_INDICATOR)

        timeline_error = await self._emit(
            self._started_event(work_item),
        )
        if timeline_error is not None:
            return self._failed_outcome(work_item, timeline_error)

        try:
            # Cancellation is never a provider failure: asyncio.CancelledError
            # propagates unchanged and no completion or failure event is
            # emitted for the interrupted work (PR 19B cancellation contract;
            # the narrow handler is documented, hence the W0706 disable).
            result = await provider.investigate(self._context.investigation_id, target)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - provider failures become bounded failure events
            self._log_bounded_failure(
                ERROR_PROVIDER_ERROR,
                source_id=work_item.provider.value,
                target_entity_id=work_item.entity_id,
            )
            return await self._fail_work(work_item, ERROR_PROVIDER_ERROR)

        binding_error = self._binding_violation(
            work_item,
            target,
            provider,
            result,
            self._context.investigation_id,
        )
        if binding_error is not None:
            return await self._fail_work(work_item, binding_error)

        return await self._process_result(work_item, result)

    @staticmethod
    def _binding_violation(
        work_item: ProviderWorkItem,
        target: Entity,
        provider: EvidenceProvider,
        result: ProviderResult,
        investigation_id: UUID,
    ) -> str | None:
        """Return a stable error code when provider output is not bound to the work.

        Pure contract validation over the complete returned tuple. The ``target``
        argument was already validated by ``execute()`` against the work item
        (identifier equality and an already-canonical value) before any provider
        invocation; it is authoritative and immutable for the remainder of the
        call. The result must declare the selected provider, and every returned
        Evidence must belong to the selected provider, the owning investigation,
        and the authoritative target. Each Evidence subject must be already
        canonical and equal the persisted target's canonical value exactly —
        canonical equivalence after normalization is not accepted — and carry
        the target identifier when present. The complete tuple is validated
        before any Evidence identity is assigned or extracted, so one invalid
        item never lets an earlier item commit. Canonicalization failures return
        ``ERROR_PROVIDER_BINDING``; they never escape and no source values,
        subject values, exception text, or payload content can reach the
        failure message built from the stable code.
        """
        # The return count is intrinsic to the independent binding gates; the
        # narrow disable follows repository convention.
        if provider.id != work_item.provider.value:
            return ERROR_PROVIDER_BINDING
        if (
            result.provider != work_item.provider.value
            or result.provider != provider.id
        ):
            return ERROR_PROVIDER_BINDING
        for evidence in result.evidence:
            if evidence.source != work_item.provider.value:
                return ERROR_PROVIDER_BINDING
            if evidence.investigation_id != investigation_id:
                return ERROR_PROVIDER_BINDING
            if evidence.subject.type is not target.type:
                return ERROR_PROVIDER_BINDING
            canonical_subject = _canonicalize_or_none(
                evidence.subject.type, evidence.subject.value
            )
            if canonical_subject is None:
                return ERROR_PROVIDER_BINDING
            if evidence.subject.value != canonical_subject:
                return ERROR_PROVIDER_BINDING
            if evidence.subject.value != target.value:
                return ERROR_PROVIDER_BINDING
            if evidence.subject.id is not None and evidence.subject.id != target.id:
                return ERROR_PROVIDER_BINDING
        return None

    def _log_bounded_failure(
        self,
        category: str,
        *,
        source_id: str,
        target_entity_id: UUID | None,
        event_type: str | None = None,
    ) -> None:
        """Log a fixed-format, secret-free failure summary for diagnostics.

        The caught exception is never attached as ``exc_info``, interpolated,
        or otherwise rendered: provider, persistence, and timeline exceptions
        can embed URLs, response details, SQL parameters, IOC data, or
        credentials. Only stable operational fields are logged: the failure
        category, source identifier, investigation UUID, target Entity UUID,
        and optional timeline event type.
        """
        event_field = f" event_type={event_type}" if event_type is not None else ""
        LOGGER.error(
            "provider work failure category=%s source_id=%s investigation_id=%s"
            " target_entity_id=%s%s",
            category,
            source_id,
            self._context.investigation_id,
            target_entity_id,
            event_field,
        )

    async def _process_result(
        self,
        work_item: ProviderWorkItem,
        result: ProviderResult,
    ) -> ProviderExecutionOutcome:
        """Process one provider result deterministically in provider-return order.

        The accumulated ID lists and per-Evidence working variables are the
        intrinsic cost of deterministic per-observation sequencing; the narrow
        disable follows repository convention.
        """
        evidence_ids: list[UUID] = []
        relationship_ids: list[UUID] = []
        discovered: list[UUID] = []
        provider_error: InvestigationError | None = None

        for evidence in result.evidence:
            normalized = (
                evidence
                if evidence.id is not None
                else evidence.model_copy(update={"id": uuid4()})
            )
            try:
                extraction = self._extractor(normalized)
            except EvidenceExtractionError:
                LOGGER.warning(
                    "extraction failed for evidence from %s",
                    work_item.provider.value,
                )
                return await self._fail_work(
                    work_item,
                    ERROR_EXTRACTION_ERROR,
                    evidence_ids=evidence_ids,
                    discovered=discovered,
                    relationship_ids=relationship_ids,
                )

            try:
                persisted = await self._persistence_service.persist(
                    normalized,
                    extraction,
                    actor_id=self._context.actor_id,
                    request_id=self._context.request_id,
                )
            except Exception:  # noqa: BLE001 - persistence failures become bounded failure events
                self._log_bounded_failure(
                    ERROR_PERSISTENCE_ERROR,
                    source_id=work_item.provider.value,
                    target_entity_id=work_item.entity_id,
                )
                return await self._fail_work(
                    work_item,
                    ERROR_PERSISTENCE_ERROR,
                    evidence_ids=evidence_ids,
                    discovered=discovered,
                    relationship_ids=relationship_ids,
                )

            assert persisted.evidence.id is not None  # DB invariant
            _append_unique(evidence_ids, persisted.evidence.id)
            for relationship in persisted.relationships:
                if relationship.id is not None:
                    _append_unique(relationship_ids, relationship.id)
            for entity in persisted.entities:
                if entity.id is not None and entity.id != work_item.entity_id:
                    _append_unique(discovered, entity.id)

            timeline_error = await self._emit(
                self._evidence_persisted_event(work_item, persisted)
            )
            if timeline_error is not None:
                return self._failed_outcome(
                    work_item,
                    timeline_error,
                    evidence_ids=evidence_ids,
                    discovered=tuple(discovered),
                    relationship_ids=relationship_ids,
                )

        if not evidence_ids and result.errors:
            first_error = result.errors[0]
            return await self._fail_work(
                work_item,
                first_error.code.value,
                recoverable=first_error.retryable,
            )

        # Mixed evidence + provider errors (approved PR 19B outcome-status
        # contract): valid evidence commits in provider-return order, the
        # status is SUCCEEDED, and only the first provider error is retained
        # by stable code and retryability — never its free-form message.
        retained_error_code: str | None = None
        if result.errors:
            first_error = result.errors[0]
            provider_error = InvestigationError(
                source=work_item.provider.value,
                code=first_error.code.value,
                message=f"provider returned {first_error.code.value}",
                recoverable=first_error.retryable,
            )
            retained_error_code = first_error.code.value

        timeline_error = await self._emit(
            self._completed_event(
                work_item,
                evidence_ids,
                discovered,
                relationship_ids,
                error_code=retained_error_code,
            )
        )
        if timeline_error is not None:
            return self._failed_outcome(
                work_item,
                timeline_error,
                evidence_ids=evidence_ids,
                discovered=tuple(discovered),
                relationship_ids=relationship_ids,
            )

        return ProviderExecutionOutcome(
            work_item=work_item,
            status=ProviderExecutionStatus.SUCCEEDED,
            evidence_ids=tuple(evidence_ids),
            discovered_entity_ids=tuple(discovered),
            relationship_ids=tuple(relationship_ids),
            error=provider_error,
        )

    async def _fail_work(
        self,
        work_item: ProviderWorkItem,
        error_code: str,
        *,
        recoverable: bool = False,
        evidence_ids: list[UUID] | None = None,
        discovered: list[UUID] | None = None,
        relationship_ids: list[UUID] | None = None,
    ) -> ProviderExecutionOutcome:
        """Fail the work, retaining every committed operational identifier.

        All three committed-ID snapshots (Evidence, discovered Entity, and
        Relationship IDs) survive whether the safe failure event appends or
        the append itself fails and the surfaced error becomes
        ``timeline_error``. IDs from an observation whose PR 18C call never
        committed are never included.
        """
        timeline_error = await self._emit(
            self._failed_event(work_item, error_code),
        )
        if timeline_error is not None:
            return self._failed_outcome(
                work_item,
                timeline_error,
                evidence_ids=evidence_ids,
                discovered=tuple(discovered) if discovered else (),
                relationship_ids=relationship_ids,
            )
        return self._failed_outcome(
            work_item,
            self._work_error(work_item, error_code, recoverable=recoverable),
            evidence_ids=evidence_ids,
            discovered=tuple(discovered) if discovered else (),
            relationship_ids=relationship_ids,
        )

    @staticmethod
    def _failed_outcome(
        work_item: ProviderWorkItem,
        error: InvestigationError,
        *,
        evidence_ids: list[UUID] | None = None,
        discovered: tuple[UUID, ...] = (),
        relationship_ids: list[UUID] | None = None,
    ) -> ProviderExecutionOutcome:
        """Build the deterministic failed outcome carrying the typed error."""
        return ProviderExecutionOutcome(
            work_item=work_item,
            status=ProviderExecutionStatus.FAILED,
            evidence_ids=tuple(evidence_ids) if evidence_ids else (),
            discovered_entity_ids=discovered,
            relationship_ids=tuple(relationship_ids) if relationship_ids else (),
            error=error,
        )

    @staticmethod
    def _work_error(
        work_item: ProviderWorkItem,
        error_code: str,
        *,
        recoverable: bool = False,
    ) -> InvestigationError:
        """Build the deterministic safe error for one failed work item."""
        return InvestigationError(
            source=work_item.provider.value,
            code=error_code,
            message=f"provider work failed: {error_code}",
            recoverable=recoverable,
        )

    def _started_event(self, work_item: ProviderWorkItem) -> InvestigationTimelineEvent:
        """Build the event emitted after target/provider validation succeeds."""
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=self._context.investigation_id,
            type=InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            occurred_at=self._context.clock(),
            provider=work_item.provider,
            target_entity_id=work_item.entity_id,
            pivot_depth=work_item.depth,
        )

    def _evidence_persisted_event(
        self,
        work_item: ProviderWorkItem,
        persisted: ProviderObservationPersistenceResult,
    ) -> InvestigationTimelineEvent:
        """Build the event emitted only after one observation committed."""
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=self._context.investigation_id,
            type=InvestigationTimelineEventType.EVIDENCE_PERSISTED,
            occurred_at=self._context.clock(),
            provider=work_item.provider,
            target_entity_id=work_item.entity_id,
            evidence_ids=(
                (persisted.evidence.id,) if persisted.evidence.id is not None else ()
            ),
            entity_ids=tuple(
                entity.id for entity in persisted.entities if entity.id is not None
            ),
            relationship_ids=tuple(
                relationship.id
                for relationship in persisted.relationships
                if relationship.id is not None
            ),
        )

    def _completed_event(
        self,
        work_item: ProviderWorkItem,
        evidence_ids: list[UUID],
        discovered: list[UUID],
        relationship_ids: list[UUID],
        *,
        error_code: str | None = None,
    ) -> InvestigationTimelineEvent:
        """Build the aggregate completion event with committed identifiers.

        ``error_code`` carries the retained first provider-error code for a
        mixed partial result so the timeline accurately exposes the partial
        outcome; a clean completion carries ``None``.
        """
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=self._context.investigation_id,
            type=InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
            occurred_at=self._context.clock(),
            provider=work_item.provider,
            target_entity_id=work_item.entity_id,
            evidence_ids=tuple(evidence_ids),
            entity_ids=tuple(discovered),
            relationship_ids=tuple(relationship_ids),
            error_code=error_code,
        )

    def _failed_event(
        self,
        work_item: ProviderWorkItem,
        error_code: str,
    ) -> InvestigationTimelineEvent:
        """Build the safe failure event: no raw bodies, traces, or reasoning."""
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=self._context.investigation_id,
            type=InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
            occurred_at=self._context.clock(),
            provider=work_item.provider,
            target_entity_id=work_item.entity_id,
            error_code=error_code,
        )

    async def _emit(
        self, event: InvestigationTimelineEvent
    ) -> InvestigationError | None:
        """Append one timeline event, mapping failure to a typed error.

        A failed append never rolls back already committed domain data; the
        typed operational failure is returned so the caller can surface it.
        """
        if self._timeline_service is None:
            return None
        try:
            await self._timeline_service.append(event)
        except Exception:  # noqa: BLE001 - timeline failures never escape the sink
            self._log_bounded_failure(
                ERROR_TIMELINE_ERROR,
                source_id=(
                    event.provider.value
                    if event.provider is not None
                    else "orchestration"
                ),
                target_entity_id=event.target_entity_id,
                event_type=event.type.value,
            )
            return InvestigationError(
                source="orchestration",
                code=ERROR_TIMELINE_ERROR,
                message=f"provider work failed: {ERROR_TIMELINE_ERROR}",
                recoverable=False,
            )
        return None
