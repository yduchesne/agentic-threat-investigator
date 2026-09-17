# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Datasource-backed ``EvidenceProvider`` compatibility seam (PR 27E).

Migrates one PR 27A-D acquisition stack onto the existing Investigation
runtime contract without redesigning the mature executor/persistence
architecture:

```text
EvidenceProvider compatibility
 -> DatasourceDefinition
 -> semantic datasource acquisition (SemanticAcquirer[T])
 -> SemanticAcquisitionResult[T]
 -> EvidenceConversionContext
 -> ToEvidenceConverterRegistry (selected by semantic_format)
 -> ProviderResult
```

:class:`DatasourceProvider` is the small generic adapter: it owns the
acquisition/conversion lifecycle through the PR 27B
:class:`DatasourceExecutionRecorder` (STARTED + the acquirer's stage appends
+ CONVERTED with the exact produced Evidence count) and defers the terminal
outcome. A typed acquisition failure records FAILED with the bounded
source-stage error code and returns a mapped legacy ``ProviderResult``
error; conversion failure records FAILED(``conversion_failed``) and raises;
cancellation records CANCELLED (best effort) and always propagates. A
successful acquisition+conversion returns a :class:`DatasourceEvidenceResult`
(``ProviderResult`` plus an explicit :class:`DatasourceExecutionCompletion`)
so the terminating COMPLETED/FAILED/CANCELLED decision belongs to the
Investigation executor only after required Evidence extraction/persistence
processing succeeds.

The adapter constructs its ``EntityRef`` from the exact canonical persisted
``Entity`` passed by ``ProviderWorkExecutor`` — it never re-resolves or
substitutes the subject — and performs no I/O from ``supports()``. Nothing
in this module understands ThreatFox (or any other source's) semantic
model; the source-specific acquirer, converter, and legacy error mapping
are injected. No UoW is ever held across acquisition, parsing, conversion,
or extraction, and no raw exception text, source body, or credential is
persisted.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Generic, Protocol, TypeVar
from uuid import UUID

from pydantic import PrivateAttr

from agentic_threat_investigator.app.datasource_execution import (
    DatasourceExecutionRecorder,
)
from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStageError,
    SemanticAcquisitionResult,
)
from agentic_threat_investigator.app.evidence_conversion import (
    EvidenceConversionContext,
    ToEvidenceConverterRegistry,
    convert_semantic_source_objects,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderResult,
    validate_investigation_entity,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
)
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import EntityRef, Evidence

T = TypeVar("T")
"""One validated source-native semantic object type."""

_DATASOURCE_DEFAULT_ERROR_CODE = "unexpected_error"
"""Bounded safe terminal code for unexpected acquisition exceptions."""


class DatasourceExecutionCompletion(ABC):
    """Deferred terminal lifecycle of one datasource-backed provider execution.

    The adapter records STARTED and the acquisition/conversion stage events
    but leaves the terminal outcome open; the Investigation executor calls
    exactly one terminal method after required Evidence runtime processing:

    - ``complete()`` only after every returned Evidence was extracted and
      committed through the observation persistence boundary;
    - ``fail(code=...)`` with a bounded safe runtime code when binding,
      extraction, persistence, or timeline processing fails;
    - ``cancel()`` when cancellation is observed (best effort, never a
      failure).

    Implementations append through the PR 27B recorder in short committed
    UnitOfWork transactions; a caller who already appended a terminal
    outcome never proposes a second one.
    """

    @abstractmethod
    async def complete(self) -> None:
        """Append the COMPLETED terminal outcome."""

    @abstractmethod
    async def fail(self, *, code: str) -> None:
        """Append the FAILED terminal outcome with one bounded safe code."""

    @abstractmethod
    async def cancel(self) -> None:
        """Append the CANCELLED terminal outcome."""


class RecorderDatasourceExecutionCompletion(DatasourceExecutionCompletion):
    """Terminal facade over one ``DatasourceExecutionRecorder``.

    Delegates the three terminal methods unchanged; the recorder continues
    to own local fail-fast lifecycle checks and short-transaction appends.
    """

    def __init__(self, recorder: DatasourceExecutionRecorder) -> None:
        """Bind the facade to exactly one executor-bound recorder."""
        self._recorder = recorder

    @property
    def execution_id(self) -> UUID:
        """Return the single execution identity of the wrapped recorder."""
        return self._recorder.execution_id

    @property
    def datasource_id(self) -> DatasourceId:
        """Return the single datasource identity of the wrapped recorder."""
        return self._recorder.datasource_id

    async def complete(self) -> None:
        """Delegate the COMPLETED append to the recorder."""
        await self._recorder.complete()

    async def fail(self, *, code: str) -> None:
        """Delegate the FAILED append with the bounded code to the recorder."""
        await self._recorder.fail(error_code=code)

    async def cancel(self) -> None:
        """Delegate the CANCELLED append to the recorder."""
        await self._recorder.cancel()


class DatasourceEvidenceResult(ProviderResult):
    """A successful datasource-backed provider result carrying its completion.

    A plain ``ProviderResult`` subclass: the returned Evidence is validated
    and bound exactly like any other provider result, while the deferred
    terminal lifecycle is exposed through :attr:`completion` for the
    executor's generic lifecycle-aware seam. The presence of this type —
    never a provider identity — is what the executor recognizes.
    """

    _completion: DatasourceExecutionCompletion = PrivateAttr()

    @property
    def completion(self) -> DatasourceExecutionCompletion:
        """Return the deferred terminal completion of this execution."""
        return self._completion


def datasource_evidence_result(
    *,
    provider: str,
    evidence: tuple[Evidence, ...],
    completion: DatasourceExecutionCompletion,
) -> DatasourceEvidenceResult:
    """Build one lifecycle-aware provider result with its completion.

    The completion is a model-private attribute (pydantic ``extra="forbid"``
    inheritance prevents constructor keywords), so it is attached after
    construction; the result remains immutable to every pydantic caller.
    """
    result = DatasourceEvidenceResult(provider=provider, evidence=evidence)
    object.__setattr__(result, "_completion", completion)
    return result


class SemanticAcquirer(Protocol, Generic[T]):
    """One semantic acquisition seam over a configured datasource.

    Shape-compatible with :meth:`ThreatFoxDatasource.acquire`: the
    acquirer appends its own stage events to the recorder in short
    committed transactions, performs acquisition/parse work with no
    database transaction open, and returns validated source-native objects
    or one typed bounded stage error. ``supports`` is deterministic
    entity-type applicability with no external I/O.
    """

    @abstractmethod
    def supports(self, entity: Entity) -> bool:
        """Return deterministic applicability without external I/O."""

    @abstractmethod
    async def acquire(
        self,
        *,
        definition: DatasourceDefinition,
        entity: Entity,
        recorder: DatasourceExecutionRecorder,
    ) -> SemanticAcquisitionResult[T]:
        """Acquire and parse one semantic acquisition for the entity."""


def _utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(UTC)


class DatasourceProvider(EvidenceProvider, Generic[T]):
    """Generic ``EvidenceProvider`` adapter over one semantic datasource.

    Composes the PR 27A definition, the PR 27C semantic acquirer, and the
    PR 27D semantic-format converter registry into the existing provider
    runtime contract. Conversion is selected only by
    ``semantic_format`` through the injected registry; the adapter never
    branches on provider/source identity and never depends on a
    source-specific semantic model.
    """

    def __init__(
        self,
        *,
        definition: DatasourceDefinition,
        acquirer: SemanticAcquirer[T],
        registry: ToEvidenceConverterRegistry,
        uow_factory: Callable[[], UnitOfWork],
        error_mapper: Callable[[DatasourceStageError], ProviderResult],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the adapter to its configured datasource and injected seams.

        ``uow_factory`` backs the PR 27B recorder's short lifecycle
        transactions; ``error_mapper`` deterministically maps bounded
        source-stage failures onto the legacy ``ProviderResult`` error
        vocabulary; the UTC clock stamps lifecycle events.
        """
        self._definition = definition
        self._acquirer = acquirer
        self._registry = registry
        self._uow_factory = uow_factory
        self._error_mapper = error_mapper
        self._clock: Callable[[], datetime] = clock if clock is not None else _utc_now

    @property
    def definition(self) -> DatasourceDefinition:
        """Return the configured datasource definition owned by this adapter."""
        return self._definition

    @property
    def id(self) -> str:
        """Return the stable source URN of the configured datasource."""
        return self._definition.source_id.value

    def supports(self, entity: Entity) -> bool:
        """Return deterministic applicability with no external I/O.

        Delegates to the acquirer's own deterministic entity-type contract;
        unknown entity types never raise.
        """
        return self._acquirer.supports(entity)

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Acquire, parse, and convert one semantic acquisition for the entity.

        Reuses the shared provider input validation (unsupported or
        uncanonicalizable values return UNSUPPORTED_INDICATOR before any
        HTTP and before any lifecycle event). Otherwise the adapter owns
        one recorder: STARTED, the acquirer's stage appends (ACQUIRED and
        DECODED when the source path emits them), pure conversion through
        the semantic-format-selected converter, and CONVERTED with the
        exact produced Evidence count. A typed acquisition failure appends
        FAILED with the bounded source-stage code and returns one mapped
        legacy error result; a conversion violation appends
        FAILED(``conversion_failed``) and raises; cancellation appends
        CANCELLED (best effort) and always propagates. On success the
        terminal outcome stays open: the returned
        :class:`DatasourceEvidenceResult` carries the completion for the
        executor's terminal decision. No Evidence is persisted here.
        """
        validation = validate_investigation_entity(self, entity)
        rejection = validation[1]
        if rejection is not None:
            return rejection

        recorder = DatasourceExecutionRecorder(
            self._definition.datasource_id,
            self._uow_factory,
            clock=self._clock,
        )
        await recorder.start()
        try:
            result = await self._acquirer.acquire(
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
            return self._error_mapper(result.error)

        # The exact persisted Entity passed by the executor is authoritative;
        # the subject is never re-resolved or substituted.
        subject = EntityRef(id=entity.id, type=entity.type, value=entity.value)
        context = EvidenceConversionContext(
            investigation_id=investigation_id,
            subject=subject,
            semantic_source=result.context,
        )
        try:
            converted = convert_semantic_source_objects(
                result.objects, context, self._registry
            )
        except asyncio.CancelledError:
            await _best_effort_terminal(recorder, cancelled=True)
            raise
        except Exception:
            await _best_effort_terminal(
                recorder, cancelled=False, error_code="conversion_failed"
            )
            raise

        await recorder.converted(item_count=len(converted))
        return datasource_evidence_result(
            provider=self.id,
            evidence=converted,
            completion=RecorderDatasourceExecutionCompletion(recorder),
        )


async def _best_effort_terminal(
    recorder: DatasourceExecutionRecorder,
    *,
    cancelled: bool,
    error_code: str = _DATASOURCE_DEFAULT_ERROR_CODE,
) -> None:
    """Best-effort terminal recording that never masks the original outcome.

    Cancellation appends CANCELLED; other terminal recording appends FAILED
    with the given bounded safe code. A database failure during the append
    is ignored so the original outcome always propagates (mirrors the
    PR 27B recorder contract).
    """
    try:
        if cancelled:
            await recorder.cancel()
        else:
            await recorder.fail(error_code=error_code)
    except Exception:  # noqa: BLE001 - best-effort terminal recording must not mask the original outcome
        return
