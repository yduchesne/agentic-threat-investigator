# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Generic producer-side Evidence publication seam (PR 28F-2).

PR 28F-2 closes the producer-side application seam of the v0.2 Global
Evidence pipeline:

```text
DatasourceDefinition
 -> SemanticAcquirer[T] (PR 27C, records ACQUIRED/DECODED)
 -> SemanticAcquisitionResult[T]
 -> EvidenceConversionContext + ToEvidenceConverterRegistry
    (selected only by semantic_format, PR 27D)
 -> convert_semantic_source_objects (deterministic 0..N flattening)
 -> CONVERTED(N)
 -> evidence_message_from_converted (PR 28C) with execution-local sequence
 -> EvidencePublisher.publish (PR 28D), exactly one ordered call
 -> PUBLISHED(len(messages))
 -> COMPLETED
```

:class:`DatasourceEvidenceProducer` owns one execution recorder per
``produce()`` call, the acquisition invocation, pure conversion, message
construction, and exactly one ordered publication. It depends only on the
``EvidencePublisher`` ABC — never on a concrete in-memory adapter, a
consumer, database Evidence persistence, or Investigation admission. Producer ``COMPLETED`` means the injected publisher accepted every
message of the execution, **not** that the database consumed or persisted
them; completion never waits for the PR 28E consumer.

Boundary rules:

- one execution ID (the recorder's) propagates to every message; sequence
  is zero-based over the whole flattened converted output of the execution,
  in source-then-converter order, with no sorting or deduplication;
- zero converted output still calls ``publish(())`` and records
  ``PUBLISHED(0)`` before ``COMPLETED``;
- a typed acquisition stage error records ``FAILED`` with the bounded code
  and returns a failed result; cancellation records ``CANCELLED`` (best
  effort) and always propagates; conversion, message-construction, and
  publication failures record their bounded ``FAILED`` codes (best effort)
  and propagate;
- after a successful publish, a lifecycle append failure is propagated
  without republishing and without appending ``COMPLETED``: datasource
  lifecycle logging and publication are separate durable boundaries
  (section 1.12 of the PR 28F-2 plan), never one distributed transaction;
- no UnitOfWork is ever held across HTTP, conversion, message construction,
  or publication; no raw exception text, source body, or credential is
  persisted.

The module reuses the PR 27B recorder, the PR 27C acquisition contracts,
the PR 27D/28A conversion boundary, the PR 28C message builder, and the
PR 28D publisher. It does not create another converter registry, message
schema, flattening algorithm, log, or execution framework, and it does not
publish and synchronously persist the same Evidence (no dual write).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Generic, TypeVar
from uuid import UUID

from agentic_threat_investigator.app.datasource_execution import (
    DatasourceExecutionRecorder,
)
from agentic_threat_investigator.app.datasource_provider import (
    CollectionSemanticAcquirer,
    SemanticAcquirer,
    observe_collection_acquisition,
    observe_semantic_acquisition,
)
from agentic_threat_investigator.app.datasource_semantics import (
    CollectionAcquisitionProgress,
    SemanticAcquisitionResult,
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    EvidenceConversionContext,
    ToEvidenceConverterRegistry,
    convert_semantic_source_objects,
)
from agentic_threat_investigator.app.evidence_log import EvidencePublisher
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    evidence_message_from_converted,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
)
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import ConvertedEvidence

__all__ = [
    "CollectionDatasourceEvidenceProducer",
    "DatasourceProducerOutcome",
    "DatasourceProducerResult",
    "DatasourceEvidenceProducer",
]

T = TypeVar("T")
"""One validated source-native semantic object type."""

_DATASOURCE_DEFAULT_ERROR_CODE = "unexpected_error"
"""Bounded safe terminal code for unexpected acquisition/conversion exceptions."""

_ERROR_CODE_UNSUPPORTED = "unsupported_indicator"
"""Bounded code recorded on a failed result when the acquirer cannot act on the entity.

No lifecycle is started for an unsupported entity; the code mirrors the
PR 27C ThreatFox ``unsupported_indicator`` semantic-validation code.
"""

_ERROR_CODE_CONVERSION = "conversion_failed"
"""Bounded FAILED code for a conversion-boundary violation (PR 27D)."""

_ERROR_CODE_MESSAGE_CONSTRUCTION = "message_construction_failed"
"""Bounded FAILED code for a PR 28C message-construction/validation failure."""

_ERROR_CODE_PUBLICATION = "publication_failed"
"""Bounded FAILED code for a documented ``EvidencePublisher.publish`` failure."""


class DatasourceProducerOutcome(StrEnum):
    """Terminal caller-facing outcome of one producer execution.

    ``COMPLETED`` means the publisher accepted every message (and ``PUBLISHED``
    and ``COMPLETED`` lifecycle events were appended); ``FAILED`` means a
    typed acquisition error was recorded or the entity was unsupported. It is
    a producer-caller vocabulary, never a datasource-log event type: the
    durable lifecycle vocabulary stays ``DatasourceExecutionEventType``.
    Cancellation always propagates and never returns a result.
    """

    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class DatasourceProducerResult:
    """The deterministic result summary of one producer execution.

    ``execution_id`` is the exact recorder execution ID of the execution
    (``None`` only when no execution was started because the entity was
    unsupported); ``published_count`` is the number of messages the publisher
    accepted on completion; ``error_code`` is the bounded safe code of a
    failed result and is ``None`` on completion. No message content, broker
    position, observation identity, or database state is exposed.
    """

    outcome: DatasourceProducerOutcome
    execution_id: UUID | None
    published_count: int = 0
    error_code: str | None = None

    def __post_init__(self) -> None:
        """Reject negative counts and codes on completion."""
        if self.published_count < 0:
            raise ValueError("published_count must be non-negative")
        if (
            self.outcome is DatasourceProducerOutcome.COMPLETED
            and self.error_code is not None
        ):
            raise ValueError("a completed execution cannot carry an error_code")


def _utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(UTC)


def _build_messages(
    *,
    execution_id: UUID,
    semantic_source: SemanticSourceContext,
    converted: tuple[ConvertedEvidence, ...],
) -> tuple[EvidenceMessage, ...]:
    """Build the ordered EvidenceMessage tuple of one flattened execution.

    ``sequence`` is zero-based over the **entire** flattened converted output
    of the execution (source-object order, then converter return order),
    preserving the ``convert_semantic_source_objects`` order exactly. No
    sorting or deduplication happens here; the PR 28C builder owns all
    deterministic identities and provenance validation.
    """
    return tuple(
        evidence_message_from_converted(
            item,
            datasource_execution_id=execution_id,
            semantic_source=semantic_source,
            sequence=sequence,
        )
        for sequence, item in enumerate(converted)
    )


async def _convert_and_publish(
    *,
    recorder: DatasourceExecutionRecorder,
    result: SemanticAcquisitionResult[T],
    registry: ToEvidenceConverterRegistry,
    publisher: EvidencePublisher,
) -> tuple[EvidenceMessage, ...]:
    """Run the shared post-acquisition conversion/message/publication pipeline.

    This is the single implementation behind both the entity-triggered and
    the collection producer shapes; it is never copied. It preserves exactly:
    the PR 28A Evidence identity and the PR 28C message identity, zero-based
    sequence over the whole flattened converted output, source/converter
    order, zero-output ``publish(())``, exactly one ``EvidencePublisher``
    call, the existing bounded failure codes (``conversion_failed``,
    ``message_construction_failed``, ``publication_failed``), cancellation
    behavior, and no republish when a later lifecycle append fails.

    On success the recorder receives ``CONVERTED(len)`` and then
    ``PUBLISHED(len)``; the caller owns the terminal ``COMPLETED``/``FAILED``
    append and the returned messages. PR 27D/28A conversion is global and
    Investigation-independent: the context carries only the cross-cutting
    semantic provenance and the converter is selected by semantic format
    through the injected registry, never by source identity.
    """
    context = EvidenceConversionContext(semantic_source=result.context)
    try:
        converted = convert_semantic_source_objects(result.objects, context, registry)
    except asyncio.CancelledError:
        await _best_effort_terminal(recorder, cancelled=True)
        raise
    except Exception:
        await _best_effort_terminal(
            recorder, cancelled=False, error_code=_ERROR_CODE_CONVERSION
        )
        raise

    await recorder.converted(item_count=len(converted))

    try:
        messages = _build_messages(
            execution_id=recorder.execution_id,
            semantic_source=result.context,
            converted=converted,
        )
    except asyncio.CancelledError:
        await _best_effort_terminal(recorder, cancelled=True)
        raise
    except Exception:
        await _best_effort_terminal(
            recorder,
            cancelled=False,
            error_code=_ERROR_CODE_MESSAGE_CONSTRUCTION,
        )
        raise

    try:
        await publisher.publish(messages)
    except asyncio.CancelledError:
        await _best_effort_terminal(recorder, cancelled=True)
        raise
    except Exception:
        await _best_effort_terminal(
            recorder,
            cancelled=False,
            error_code=_ERROR_CODE_PUBLICATION,
        )
        raise

    await recorder.published(item_count=len(messages))
    return messages


class DatasourceEvidenceProducer(Generic[T]):
    """Generic producer seam of one configured semantic datasource (PR 28F-2).

    Composes the PR 27A definition, PR 27C acquirer, PR 27D converter
    registry, PR 28C message builder, and PR 28D publisher into one narrow
    producer execution. Converter selection stays purely semantic-format
    driven through the injected registry; the producer never branches on
    provider/source identity and never understands a source's semantic model.
    """

    def __init__(
        self,
        *,
        definition: DatasourceDefinition,
        acquirer: SemanticAcquirer[T],
        registry: ToEvidenceConverterRegistry,
        publisher: EvidencePublisher,
        uow_factory: Callable[[], UnitOfWork],
        clock: Callable[[], datetime] | None = None,
        execution_id: UUID | None = None,
    ) -> None:
        """Bind the producer to its configured datasource and injected seams.

        ``uow_factory`` backs the PR 27B recorder's short lifecycle
        transactions; ``publisher`` is the broker-neutral PR 28D
        ``EvidencePublisher`` (never a concrete in-memory adapter reference);
        the UTC clock stamps lifecycle events. ``execution_id`` is normally
        ``None`` (the recorder generates a fresh UUID per execution);
        injecting a fixed value is supported only for deterministic test
        fixtures, mirroring the recorder's own fixture seam.
        """
        self._definition = definition
        self._acquirer = acquirer
        self._registry = registry
        self._publisher = publisher
        self._uow_factory = uow_factory
        self._clock: Callable[[], datetime] = clock if clock is not None else _utc_now
        self._execution_id = execution_id

    @property
    def definition(self) -> DatasourceDefinition:
        """Return the configured datasource definition owned by this producer."""
        return self._definition

    async def produce(self, entity: Entity) -> DatasourceProducerResult:
        """Produce one complete execution and publish its ordered messages.

        A deterministic entity-type gate mirrors the PR 27E adapter: an
        unsupported entity returns a ``FAILED`` result with
        ``unsupported_indicator`` and starts no lifecycle or recorder. For a
        supported entity the producer owns one recorder: STARTED, the
        acquirer's stage appends (ACQUIRED/DECODED when the source path
        emits them), pure conversion through the semantic-format-selected
        converter, and CONVERTED with the exact produced count; then the
        whole flattened tuple becomes one ordered PR 28C message tuple
        (execution-local zero-based sequence), published with exactly one
        ``EvidencePublisher.publish`` call, followed by PUBLISHED with the
        accepted message count and COMPLETED. A typed acquisition stage error
        records FAILED with the bounded code and returns a failed result;
        conversion, message-construction, and publication failures record
        their bounded FAILED codes (best effort) and propagate; cancellation
        records CANCELLED (best effort) and always propagates. A lifecycle
        append failure after a successful publish propagates without
        republishing and without COMPLETED. No Evidence is ever persisted
        here and no consumer is waited on.
        """
        if not self._acquirer.supports(entity):
            return DatasourceProducerResult(
                outcome=DatasourceProducerOutcome.FAILED,
                execution_id=None,
                error_code=_ERROR_CODE_UNSUPPORTED,
            )

        recorder = DatasourceExecutionRecorder(
            self._definition.datasource_id,
            self._uow_factory,
            clock=self._clock,
            execution_id=self._execution_id,
        )
        await recorder.start()
        try:
            result = await observe_semantic_acquisition(
                self._acquirer,
                definition=self._definition,
                entity=entity,
                recorder=recorder,
            )
        except asyncio.CancelledError:
            await _best_effort_terminal(recorder, cancelled=True)
            raise
        except Exception:
            await _best_effort_terminal(recorder, cancelled=False)
            raise

        if result.error is not None:
            await recorder.fail(error_code=result.error.code)
            return DatasourceProducerResult(
                outcome=DatasourceProducerOutcome.FAILED,
                execution_id=recorder.execution_id,
                error_code=result.error.code,
            )

        messages = await _convert_and_publish(
            recorder=recorder,
            result=result,
            registry=self._registry,
            publisher=self._publisher,
        )
        await recorder.complete()
        return DatasourceProducerResult(
            outcome=DatasourceProducerOutcome.COMPLETED,
            execution_id=recorder.execution_id,
            published_count=len(messages),
        )


class CollectionDatasourceEvidenceProducer(Generic[T]):
    """Collection datasource Evidence producer seam (PR 32D).

    The collection twin of :class:`DatasourceEvidenceProducer`: it owns one
    execution recorder per ``produce()`` call and runs the **same shared
    post-acquisition pipeline** (conversion through the semantic-format
    registry, CONVERTED, PR 28C message construction, exactly one ordered
    ``EvidencePublisher.publish`` call, PUBLISHED, COMPLETED). It differs in
    the acquisition contract only: the injected acquirer is a
    :class:`CollectionSemanticAcquirer`, so ``produce()`` takes no Entity
    argument and there is no ``supports(entity)`` gate. The producer is
    source-neutral — nothing here understands MISP or any other source's
    semantic model, and no Entity, Investigation admission, or Evidence
    persistence is involved.

    Lifecycle on success: ``STARTED, ACQUIRED, DECODED, CONVERTED(N),
    PUBLISHED(N), COMPLETED`` where ``ACQUIRED``/``DECODED`` come from the
    acquirer's own stage appends. Zero conversion is valid:
    ``CONVERTED(0), publish(()), PUBLISHED(0), COMPLETED``. Failure rules
    mirror the entity producer exactly: a typed acquisition stage error
    records ``FAILED`` with the bounded code and returns a failed result;
    conversion, message-construction, and publication failures record their
    bounded ``FAILED`` codes (best effort) and propagate; cancellation
    records ``CANCELLED`` (best effort) and always propagates; a lifecycle
    append failure after a successful publish propagates without republish
    and without COMPLETED. No application-level publication retry exists.
    No Evidence is ever persisted here and no consumer is waited on.
    """

    def __init__(
        self,
        *,
        definition: DatasourceDefinition,
        acquirer: CollectionSemanticAcquirer[T],
        registry: ToEvidenceConverterRegistry,
        publisher: EvidencePublisher,
        uow_factory: Callable[[], UnitOfWork],
        clock: Callable[[], datetime] | None = None,
        execution_id: UUID | None = None,
        progress_committer: (
            Callable[[DatasourceId, CollectionAcquisitionProgress], Awaitable[None]]
            | None
        ) = None,
    ) -> None:
        """Bind the producer to its configured collection datasource and seams.

        ``uow_factory`` backs the PR 27B recorder's short lifecycle
        transactions; ``publisher`` is the broker-neutral PR 28D
        ``EvidencePublisher`` (never a concrete in-memory adapter reference);
        the UTC clock stamps lifecycle events. ``execution_id`` is normally
        ``None`` (the recorder generates a fresh UUID per execution);
        injecting a fixed value is supported only for deterministic test
        fixtures, mirroring the recorder's own fixture seam.

        ``progress_committer`` (PR 33E) is the source-neutral post-publication
        progress seam: when the acquirer returned an acquisition-progress
        candidate (TAXII ``added_after``), the producer invokes this committer
        **after** PUBLISHED and **before** COMPLETED so the durable
        checkpoint can never advance past publication. ``None`` means the
        producer has no progress to commit; an acquirer that does return
        progress while no committer is injected fails closed.
        """
        self._definition = definition
        self._acquirer = acquirer
        self._registry = registry
        self._publisher = publisher
        self._uow_factory = uow_factory
        self._clock: Callable[[], datetime] = clock if clock is not None else _utc_now
        self._execution_id = execution_id
        self._progress_committer = progress_committer

    @property
    def definition(self) -> DatasourceDefinition:
        """Return the configured datasource definition owned by this producer."""
        return self._definition

    async def produce(self) -> DatasourceProducerResult:
        """Produce one complete collection execution and publish its messages.

        Owns one recorder: STARTED, the acquirer's stage appends
        (ACQUIRED/DECODED when the source path emits them), the shared
        post-acquisition conversion/message/publication pipeline
        (CONVERTED, one ``EvidencePublisher.publish`` call, PUBLISHED), and
        COMPLETED. A typed acquisition stage error records FAILED with the
        bounded code and returns a failed result; conversion,
        message-construction, and publication failures record their bounded
        FAILED codes (best effort) and propagate; cancellation records
        CANCELLED (best effort) and always propagates. A lifecycle append
        failure after a successful publish propagates without republishing
        and without COMPLETED. No Entity argument exists: this is the
        collection contract, never a hidden Investigation trigger.
        """
        recorder = DatasourceExecutionRecorder(
            self._definition.datasource_id,
            self._uow_factory,
            clock=self._clock,
            execution_id=self._execution_id,
        )
        await recorder.start()
        try:
            result = await observe_collection_acquisition(
                self._acquirer,
                definition=self._definition,
                recorder=recorder,
            )
        except asyncio.CancelledError:
            await _best_effort_terminal(recorder, cancelled=True)
            raise
        except Exception:
            await _best_effort_terminal(recorder, cancelled=False)
            raise

        if result.error is not None:
            await recorder.fail(error_code=result.error.code)
            return DatasourceProducerResult(
                outcome=DatasourceProducerOutcome.FAILED,
                execution_id=recorder.execution_id,
                error_code=result.error.code,
            )

        messages = await _convert_and_publish(
            recorder=recorder,
            result=result,
            registry=self._registry,
            publisher=self._publisher,
        )
        if result.progress is not None:
            if self._progress_committer is None:
                raise ValueError(
                    "acquisition returned progress but no progress committer "
                    "was injected"
                )
            # Publication-safe checkpoint advancement (PR 33E Part 7): the
            # durable candidate is committed only after the execution's one
            # ordered EvidencePublisher call succeeded and PUBLISHED was
            # appended. A commit failure propagates without COMPLETED and
            # without republishing: the execution may be replayed from the
            # old checkpoint because deterministic Evidence identity makes
            # replay safe (at-least-once, never at-most-once).
            await self._progress_committer(
                self._definition.datasource_id, result.progress
            )
        await recorder.complete()
        return DatasourceProducerResult(
            outcome=DatasourceProducerOutcome.COMPLETED,
            execution_id=recorder.execution_id,
            published_count=len(messages),
        )


async def _best_effort_terminal(
    recorder: DatasourceExecutionRecorder,
    *,
    cancelled: bool,
    error_code: str = _DATASOURCE_DEFAULT_ERROR_CODE,
) -> None:
    """Best-effort terminal recording that never masks the original outcome.

    Cancellation appends CANCELLED; other terminal recording appends FAILED
    with the given bounded safe code (``conversion_failed``,
    ``message_construction_failed``, or ``publication_failed``). A database
    failure during the append is ignored so the original outcome always
    propagates (mirrors the PR 27B recorder contract).
    """
    try:
        if cancelled:
            await recorder.cancel()
        else:
            await recorder.fail(error_code=error_code)
    except Exception:  # noqa: BLE001 - best-effort terminal recording must not mask the original outcome
        return
