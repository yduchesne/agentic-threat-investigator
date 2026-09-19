# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Application-level acquisition-execution recorder (PR 27B).

One :class:`DatasourceExecutionRecorder` owns one fresh UUID ``execution_id``
and one ``datasource_id``; every appended event carries both unchanged. Each
append happens in its own short UnitOfWork transaction that commits before
the caller performs any external acquisition/decode/conversion work, so no
database transaction is ever held across external I/O.

The recorder centralizes event creation and local fail-fast lifecycle checks
(no stage before STARTED, no duplicate STARTED, no second terminal, no stage
after terminal). The database remains the durable authority for lifecycle
validity across processes: every append still routes through the versioned
stored function, which re-validates the same invariants under a
per-execution serialization lock.

The recorder never acquires source data, never decodes, never converts, and
never persists Evidence. ``run`` is the narrow exception-classifying helper:
cancellation stays cancellation (``CancelledError`` propagates after a
best-effort CANCELLED append) and failures persist only the caller-supplied
bounded ``error_code`` — ``str(exc)`` and tracebacks are never persisted.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.datasource import (
    DatasourceExecutionEventType,
    DatasourceId,
    DatasourceLogEvent,
)


class DatasourceExecutionRecorderError(ValueError):
    """Local fail-fast lifecycle violation of one execution recorder.

    The recorder rejects impossible local sequences (duplicate STARTED,
    stage before STARTED, second terminal, stage after terminal) before any
    database round trip. Cross-process validity is still database-owned.
    """


def _utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(UTC)


class DatasourceExecutionRecorder:
    """Record one acquisition execution's lifecycle as durable log events.

    Create one recorder per acquisition execution; the fresh ``execution_id``
    is generated once at construction and reused unchanged by every event.
    All appends run in short committed transactions through the injected
    UnitOfWork factory.
    """

    def __init__(
        self,
        datasource_id: DatasourceId,
        uow_factory: Callable[[], UnitOfWork],
        *,
        clock: Callable[[], datetime] | None = None,
        execution_id: UUID | None = None,
    ) -> None:
        """Bind the recorder to one execution identity and the caller's UoW factory.

        ``execution_id`` is normally generated fresh (``uuid4``); injecting a
        fixed value is supported only for deterministic test fixtures.
        """
        self._datasource_id = datasource_id
        self._uow_factory = uow_factory
        self._clock: Callable[[], datetime] = clock if clock is not None else _utc_now
        self._execution_id = execution_id if execution_id is not None else uuid4()
        self._started = False
        self._terminal = False

    @property
    def execution_id(self) -> UUID:
        """Return the single execution identity of this recorder."""
        return self._execution_id

    @property
    def datasource_id(self) -> DatasourceId:
        """Return the single datasource identity of this recorder."""
        return self._datasource_id

    async def start(self) -> None:
        """Append STARTED in a short committed transaction.

        Executes once per recorder; a duplicate or post-terminal start is
        rejected locally before any database round trip.
        """
        if self._terminal:
            raise DatasourceExecutionRecorderError(
                "cannot start after a terminal outcome"
            )
        if self._started:
            raise DatasourceExecutionRecorderError(
                "cannot start the same execution twice"
            )
        await self._append(DatasourceExecutionEventType.STARTED)
        self._started = True

    async def acquired(self, *, byte_count: int | None = None) -> None:
        """Append ACQUIRED with the stage-local acquired byte count."""
        await self._stage(DatasourceExecutionEventType.ACQUIRED, byte_count=byte_count)

    async def decoded(self, *, item_count: int | None = None) -> None:
        """Append DECODED with the stage-local decoded object count."""
        await self._stage(DatasourceExecutionEventType.DECODED, item_count=item_count)

    async def converted(self, *, item_count: int | None = None) -> None:
        """Append CONVERTED with the stage-local produced Evidence count."""
        await self._stage(DatasourceExecutionEventType.CONVERTED, item_count=item_count)

    async def published(self, *, item_count: int | None = None) -> None:
        """Append PUBLISHED with the accepted EvidenceMessage count (PR 28F-2).

        The stage-local ``item_count`` is the number of ``EvidenceMessage``
        values the producer's one ordered ``EvidencePublisher.publish`` call
        accepted; zero output is a valid publication of an empty tuple.
        """
        await self._stage(DatasourceExecutionEventType.PUBLISHED, item_count=item_count)

    async def complete(self) -> None:
        """Append the COMPLETED terminal outcome."""
        await self._terminal_outcome(DatasourceExecutionEventType.COMPLETED)

    async def fail(self, *, error_code: str) -> None:
        """Append the FAILED terminal outcome with a bounded safe error code."""
        await self._terminal_outcome(
            DatasourceExecutionEventType.FAILED, error_code=error_code
        )

    async def cancel(self) -> None:
        """Append the CANCELLED terminal outcome.

        Cancellation is never a failure and never carries an error code.
        """
        await self._terminal_outcome(DatasourceExecutionEventType.CANCELLED)

    async def run(
        self,
        work: Callable[[], Awaitable[None]],
        *,
        error_code: str = "unexpected_error",
    ) -> None:
        """Run one acquisition execution with deterministic terminal outcomes.

        The narrow exception-classifying wrapper: STARTED, the caller's
        ``work``, then COMPLETED. ``asyncio.CancelledError`` appends
        CANCELLED (best effort) and always propagates; any other exception
        appends FAILED with the caller-supplied bounded ``error_code`` and
        propagates. ``str(exc)`` is never persisted.
        """
        try:
            await self.start()
            await work()
            await self.complete()
        except asyncio.CancelledError:
            await self._cancel_best_effort()
            raise
        except Exception:
            await self._fail_best_effort(error_code)
            raise

    async def _stage(
        self,
        event_type: DatasourceExecutionEventType,
        *,
        item_count: int | None = None,
        byte_count: int | None = None,
    ) -> None:
        """Append one non-terminal stage after a valid STARTED execution."""
        if not self._started:
            raise DatasourceExecutionRecorderError(
                "stage events require a STARTED execution"
            )
        if self._terminal:
            raise DatasourceExecutionRecorderError(
                "cannot append a stage after a terminal outcome"
            )
        await self._append(event_type, item_count=item_count, byte_count=byte_count)

    async def _terminal_outcome(
        self,
        event_type: DatasourceExecutionEventType,
        *,
        error_code: str | None = None,
    ) -> None:
        """Append exactly one terminal outcome for a started execution."""
        if not self._started:
            raise DatasourceExecutionRecorderError(
                "terminal outcomes require a STARTED execution"
            )
        if self._terminal:
            raise DatasourceExecutionRecorderError(
                "the execution already has a terminal outcome"
            )
        await self._append(event_type, error_code=error_code)
        self._terminal = True

    async def _append(
        self,
        event_type: DatasourceExecutionEventType,
        *,
        item_count: int | None = None,
        byte_count: int | None = None,
        error_code: str | None = None,
    ) -> None:
        """Append one typed event in a short committed transaction."""
        event = DatasourceLogEvent(
            execution_id=self._execution_id,
            datasource_id=self._datasource_id,
            event_type=event_type,
            occurred_at=self._clock(),
            item_count=item_count,
            byte_count=byte_count,
            error_code=error_code,
        )
        async with self._uow_factory() as uow:
            await uow.datasource_logs.append(event)

    async def _cancel_best_effort(self) -> None:
        """Best-effort CANCELLED append that never suppresses cancellation.

        A database failure during the append is recorded as a warning-only
        outcome; the original ``CancelledError`` always propagates.
        """
        try:
            await self.cancel()
        except Exception:  # noqa: BLE001 - best-effort terminal recording must not suppress CancelledError propagation
            return

    async def _fail_best_effort(self, error_code: str) -> None:
        """Best-effort FAILED append for a non-cancellation exception."""
        try:
            await self.fail(error_code=error_code)
        except Exception:  # noqa: BLE001 - best-effort terminal recording must not suppress the original failure
            return
