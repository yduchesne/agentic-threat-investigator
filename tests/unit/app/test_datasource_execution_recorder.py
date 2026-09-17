# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27B application execution-recorder lifecycle tests.

Stable matrix IDs D27B-U01/U02/U07..U12 pin the recorder contract: fresh
per-execution UUIDs, identity stability across events, success/failure/
cancellation lifecycles, terminal exclusivity, post-terminal rejection, and
legal omitted stages. The fake in-memory UnitOfWork records appends and
commit boundaries; no database is involved.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Self

import pytest

from agentic_threat_investigator.app.datasource_execution import (
    DatasourceExecutionRecorder,
    DatasourceExecutionRecorderError,
)
from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.domain.datasource import (
    DatasourceExecutionEventType,
    DatasourceId,
    DatasourceLogEvent,
)

_THREATFOX = DatasourceId("threatfox-live")
_EPOCH = datetime(2026, 2, 1, 12, 30, 0, tzinfo=UTC)


class _Logs:
    """In-memory append-only datasource-log fake."""

    def __init__(self, state: "_State") -> None:
        """Bind to the shared test state."""
        self.state = state

    async def append(self, event: DatasourceLogEvent) -> None:
        """Record the pending append; the UoW commit applies it."""
        self.state.pending_append = event

    def commit(self) -> None:
        """Apply the pending append to the durable in-memory log."""
        if self.state.pending_append is not None:
            self.state.events.append(self.state.pending_append)
            self.state.pending_append = None


class _State:
    """Shared recorder-test state: durable events and commit accounting."""

    def __init__(self) -> None:
        """Start with an empty durable log."""
        self.events: list[DatasourceLogEvent] = []
        self.pending_append: DatasourceLogEvent | None = None
        self.commits = 0
        self.active = 0

    @property
    def types(self) -> list[str]:
        """Return the durable event types in append order."""
        return [event.event_type.value for event in self.events]

    @property
    def execution_ids(self) -> set[str]:
        """Return the durable execution identities."""
        return {str(event.execution_id) for event in self.events}

    @property
    def datasource_ids(self) -> set[str]:
        """Return the durable datasource identities."""
        return {event.datasource_id.value for event in self.events}


class _Uow(UnitOfWork):
    """In-memory UnitOfWork fake for recorder tests."""

    def __init__(self, state: _State) -> None:
        """Bind the fake UoW to the shared test state."""
        self.state = state
        self._logs = _Logs(state)
        self.datasource_logs = self._logs  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        """Support the test aenter behavior."""
        assert self.state.active == 0
        self.state.active += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit on success and roll back when the block raised."""
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()
        self.state.active -= 1

    async def commit(self) -> None:
        """Support the test commit behavior."""
        self._logs.commit()
        self.state.commits += 1

    async def rollback(self) -> None:
        """Support the test rollback behavior."""
        self.state.pending_append = None


def _factory(state: _State) -> Callable[[], UnitOfWork]:
    """Return a recorder UoW factory bound to the shared state."""
    return lambda: _Uow(state)


def _recorder(
    state: _State,
    *,
    execution_id: object = None,
    clock: Callable[[], datetime] | None = None,
) -> DatasourceExecutionRecorder:
    """Build one recorder over the fake UoW with a deterministic clock."""
    return DatasourceExecutionRecorder(
        _THREATFOX,
        _factory(state),
        clock=clock if clock is not None else (lambda: _EPOCH),
        execution_id=execution_id,  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_d27b_u01_fresh_execution_ids_per_recorder() -> None:
    """D27B-U01: two recorders for the same datasource get distinct UUIDs."""
    state = _State()
    first = _recorder(state)
    second = _recorder(state)
    assert isinstance(first.execution_id, object) and isinstance(
        second.execution_id, object
    )
    assert first.execution_id != second.execution_id


@pytest.mark.asyncio
async def test_d27b_u02_identity_stability_across_events() -> None:
    """D27B-U02: every event of one recorder shares execution and datasource IDs."""
    state = _State()
    recorder = _recorder(state)
    await recorder.start()
    await recorder.acquired(byte_count=512)
    await recorder.decoded(item_count=3)
    await recorder.converted(item_count=2)
    await recorder.complete()
    assert state.execution_ids == {str(recorder.execution_id)}
    assert state.datasource_ids == {"threatfox-live"}
    assert len(state.events) == 5
    assert all(event.execution_id == recorder.execution_id for event in state.events)
    assert all(event.datasource_id is _THREATFOX for event in state.events)


@pytest.mark.asyncio
async def test_d27b_u07_success_lifecycle() -> None:
    """D27B-U07: STARTED, selected stages, COMPLETED with stable identity."""
    state = _State()
    recorder = _recorder(state)
    await recorder.start()
    await recorder.decoded(item_count=4)
    await recorder.converted(item_count=4)
    await recorder.complete()
    assert state.types == ["started", "decoded", "converted", "completed"]
    assert all(event.occurred_at == _EPOCH for event in state.events)
    # Each append committed in its own short transaction.
    assert state.commits == 4


@pytest.mark.asyncio
async def test_d27b_u08_failure_lifecycle() -> None:
    """D27B-U08: STARTED then FAILED with the safe code."""
    state = _State()
    recorder = _recorder(state)
    await recorder.start()
    await recorder.fail(error_code="acquisition_failed")
    assert state.types == ["started", "failed"]
    assert state.events[-1].error_code == "acquisition_failed"


@pytest.mark.asyncio
async def test_d27b_u09_cancellation_propagates_and_records_cancelled() -> None:
    """D27B-U09: CANCELLED is recorded and CancelledError always propagates."""
    state = _State()
    recorder = _recorder(state)

    async def work() -> None:
        """Raise cancellation after STARTED was persisted."""
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await recorder.run(work)
    assert state.types == ["started", "cancelled"]
    assert state.events[-1].event_type is DatasourceExecutionEventType.CANCELLED
    assert state.events[-1].error_code is None


@pytest.mark.asyncio
async def test_d27b_u09b_failure_inside_run_persists_safe_code() -> None:
    """The run helper maps a non-cancellation failure to the safe code."""
    state = _State()
    recorder = _recorder(state)

    async def work() -> None:
        """Raise an ordinary exception."""
        raise RuntimeError("secret internal detail")

    with pytest.raises(RuntimeError, match="secret internal detail"):
        await recorder.run(work, error_code="decode_failed")
    assert state.types == ["started", "failed"]
    assert state.events[-1].error_code == "decode_failed"
    # The raw exception text never entered the durable log.
    assert "secret internal detail" not in str(state.events)


@pytest.mark.asyncio
async def test_d27b_u10_second_terminal_rejected_locally() -> None:
    """D27B-U10: the recorder rejects a second terminal call."""
    state = _State()
    recorder = _recorder(state)
    await recorder.start()
    await recorder.complete()
    with pytest.raises(DatasourceExecutionRecorderError):
        await recorder.fail(error_code="unexpected_error")
    with pytest.raises(DatasourceExecutionRecorderError):
        await recorder.cancel()
    with pytest.raises(DatasourceExecutionRecorderError):
        await recorder.complete()
    assert state.types == ["started", "completed"]


@pytest.mark.asyncio
async def test_d27b_u11_stage_after_terminal_rejected_locally() -> None:
    """D27B-U11: the recorder rejects a stage append after terminal."""
    state = _State()
    recorder = _recorder(state)
    await recorder.start()
    await recorder.cancel()
    with pytest.raises(DatasourceExecutionRecorderError):
        await recorder.decoded(item_count=1)
    with pytest.raises(DatasourceExecutionRecorderError):
        await recorder.acquired(byte_count=1)
    assert state.types == ["started", "cancelled"]


@pytest.mark.asyncio
async def test_d27b_u11b_stage_before_start_rejected_locally() -> None:
    """Stages and terminals require a STARTED execution locally."""
    state = _State()
    recorder = _recorder(state)
    with pytest.raises(DatasourceExecutionRecorderError):
        await recorder.acquired(byte_count=1)
    with pytest.raises(DatasourceExecutionRecorderError):
        await recorder.complete()
    with pytest.raises(DatasourceExecutionRecorderError):
        await recorder.fail(error_code="unexpected_error")
    assert state.events == []


@pytest.mark.asyncio
async def test_d27b_u11c_duplicate_start_rejected_locally() -> None:
    """A second start call is rejected locally."""
    state = _State()
    recorder = _recorder(state)
    await recorder.start()
    with pytest.raises(DatasourceExecutionRecorderError):
        await recorder.start()
    assert state.types == ["started"]


@pytest.mark.asyncio
async def test_d27b_u12_omitted_stages_legal() -> None:
    """D27B-U12: STARTED -> COMPLETED is a valid execution."""
    state = _State()
    recorder = _recorder(state)
    await recorder.start()
    await recorder.complete()
    assert state.types == ["started", "completed"]
