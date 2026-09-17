# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27B datasource-log lifecycle matrices on real PostgreSQL.

D27B-P01..P14 matrix: append/persist correlation, STARTED-first and
STARTED-unique enforcement, datasource identity stability, terminal
exclusivity, post-terminal rejection, concurrent terminal/STARTED races,
independent executions, database-owned count/error-code constraints, and
append-only repository shape. The deterministic application vertical slice
and cancellation propagation live in the same module (D27B-V01, D27B-C01).

All lifecycle mutations route through ``ati.append_datasource_log_event``
(SQL API v0025); the repository never issues a direct INSERT/UPDATE/DELETE.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceLogAppendAfterTerminalError,
    DatasourceLogDatasourceMismatchError,
    DatasourceLogDuplicateStartedError,
    DatasourceLogFirstEventError,
    DatasourceLogInvalidInputError,
    DatasourceLogRepository,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceExecutionEventType,
    DatasourceId,
    DatasourceLogEvent,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

pytestmark = pytest.mark.integration

_OCCURRED_AT = datetime(2026, 2, 1, 12, 30, 0, tzinfo=UTC)
_THREATFOX = DatasourceId("threatfox-live")
_MITRE = DatasourceId("mitre-attack-enterprise")


def _event(
    *,
    execution_id: UUID,
    datasource_id: DatasourceId = _THREATFOX,
    event_type: DatasourceExecutionEventType = DatasourceExecutionEventType.STARTED,
    occurred_at: datetime = _OCCURRED_AT,
    item_count: int | None = None,
    byte_count: int | None = None,
    error_code: str | None = None,
) -> DatasourceLogEvent:
    """Build one typed datasource-log event fixture."""
    return DatasourceLogEvent(
        execution_id=execution_id,
        datasource_id=datasource_id,
        event_type=event_type,
        occurred_at=occurred_at,
        item_count=item_count,
        byte_count=byte_count,
        error_code=error_code,
    )


async def _append(
    uow_factory: Callable[[], PostgresUnitOfWork],
    event: DatasourceLogEvent,
) -> None:
    """Append one event in a short committed transaction."""
    async with uow_factory() as uow:
        await uow.datasource_logs.append(event)


async def _log_rows(
    integration_engine: AsyncEngine, execution_id: UUID
) -> list[tuple[Any, ...]]:
    """Return the durable log rows of one execution in deterministic order."""
    async with integration_engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT id, execution_id, datasource_id, event_type, occurred_at, "
                "item_count, byte_count, error_code, created_at "
                "FROM ati.datasource_log WHERE execution_id = :execution_id "
                "ORDER BY id ASC"
            ),
            {"execution_id": execution_id},
        )
        return [tuple(row) for row in result.fetchall()]


async def _count(integration_engine: AsyncEngine, table: str) -> int:
    """Return the row count of one ati table."""
    async with integration_engine.connect() as connection:
        value = await connection.scalar(text(f"SELECT count(*) FROM ati.{table}"))
    return int(value or 0)


@pytest.mark.asyncio
async def test_p01_append_started_persists_exact_values(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-P01: STARTED persists exact execution/datasource/event/timestamp."""
    execution_id = uuid4()
    await _append(uow_factory, _event(execution_id=execution_id))
    rows = await _log_rows(integration_engine, execution_id)
    assert len(rows) == 1
    row = rows[0]
    assert row[1] == execution_id
    assert row[2] == "threatfox-live"
    assert row[3] == "started"
    assert row[4].astimezone(UTC) == _OCCURRED_AT
    assert row[5] is None and row[6] is None and row[7] is None
    assert row[8] is not None  # created_at is database-assigned


@pytest.mark.asyncio
async def test_p02_correlated_success_lifecycle(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-P02: STARTED -> ACQUIRED -> DECODED -> CONVERTED -> COMPLETED."""
    execution_id = uuid4()
    for event in (
        _event(execution_id=execution_id),
        _event(
            execution_id=execution_id,
            event_type=DatasourceExecutionEventType.ACQUIRED,
            byte_count=4096,
        ),
        _event(
            execution_id=execution_id,
            event_type=DatasourceExecutionEventType.DECODED,
            item_count=3,
        ),
        _event(
            execution_id=execution_id,
            event_type=DatasourceExecutionEventType.CONVERTED,
            item_count=2,
        ),
        _event(
            execution_id=execution_id,
            event_type=DatasourceExecutionEventType.COMPLETED,
        ),
    ):
        await _append(uow_factory, event)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "completed",
    ]
    assert {row[1] for row in rows} == {execution_id}
    assert {row[2] for row in rows} == {"threatfox-live"}
    ids = [row[0] for row in rows]
    assert ids == sorted(ids)  # deterministic persisted ordering
    assert rows[1][6] == 4096  # ACQUIRED byte_count
    assert rows[2][5] == 3 and rows[3][5] == 2  # DECODED/CONVERTED item counts
    assert all(row[7] is None for row in rows)  # no error codes on success


@pytest.mark.asyncio
async def test_p03_correlated_failure(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-P03: STARTED -> FAILED persists the exact safe error code."""
    execution_id = uuid4()
    await _append(uow_factory, _event(execution_id=execution_id))
    await _append(
        uow_factory,
        _event(
            execution_id=execution_id,
            event_type=DatasourceExecutionEventType.FAILED,
            error_code="acquisition_failed",
        ),
    )
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == ["started", "failed"]
    assert rows[1][7] == "acquisition_failed"


@pytest.mark.asyncio
async def test_p04_correlated_cancellation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-P04: STARTED -> CANCELLED is a distinct terminal outcome."""
    execution_id = uuid4()
    await _append(uow_factory, _event(execution_id=execution_id))
    await _append(
        uow_factory,
        _event(
            execution_id=execution_id,
            event_type=DatasourceExecutionEventType.CANCELLED,
        ),
    )
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == ["started", "cancelled"]
    assert all(row[7] is None for row in rows)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "event_type",
    [
        DatasourceExecutionEventType.ACQUIRED,
        DatasourceExecutionEventType.FAILED,
        DatasourceExecutionEventType.COMPLETED,
        DatasourceExecutionEventType.CANCELLED,
    ],
)
async def test_p05_first_event_must_be_started(
    uow_factory: Callable[[], PostgresUnitOfWork],
    event_type: DatasourceExecutionEventType,
) -> None:
    """D27B-P05: the DB rejects a first event that is not STARTED."""
    execution_id = uuid4()
    kwargs: dict[str, object] = {}
    if event_type is DatasourceExecutionEventType.FAILED:
        kwargs["error_code"] = "unexpected_error"
    with pytest.raises(DatasourceLogFirstEventError):
        await _append(
            uow_factory,
            _event(execution_id=execution_id, event_type=event_type, **kwargs),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_p06_duplicate_started_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """D27B-P06: a second STARTED for one execution is rejected."""
    execution_id = uuid4()
    await _append(uow_factory, _event(execution_id=execution_id))
    with pytest.raises(DatasourceLogDuplicateStartedError):
        await _append(uow_factory, _event(execution_id=execution_id))


@pytest.mark.asyncio
async def test_p07_datasource_mismatch_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """D27B-P07: one execution cannot carry two datasource identities."""
    execution_id = uuid4()
    await _append(uow_factory, _event(execution_id=execution_id))
    with pytest.raises(DatasourceLogDatasourceMismatchError):
        await _append(
            uow_factory,
            _event(
                execution_id=execution_id,
                datasource_id=_MITRE,
                event_type=DatasourceExecutionEventType.ACQUIRED,
            ),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal",
    [
        DatasourceExecutionEventType.COMPLETED,
        DatasourceExecutionEventType.FAILED,
        DatasourceExecutionEventType.CANCELLED,
    ],
)
@pytest.mark.parametrize(
    "second",
    [
        DatasourceExecutionEventType.COMPLETED,
        DatasourceExecutionEventType.FAILED,
        DatasourceExecutionEventType.CANCELLED,
    ],
)
async def test_p08_terminal_exclusivity(
    uow_factory: Callable[[], PostgresUnitOfWork],
    terminal: DatasourceExecutionEventType,
    second: DatasourceExecutionEventType,
) -> None:
    """D27B-P08: after any terminal, every other terminal append is rejected."""
    execution_id = uuid4()
    await _append(uow_factory, _event(execution_id=execution_id))
    terminal_kwargs: dict[str, object] = {}
    if terminal is DatasourceExecutionEventType.FAILED:
        terminal_kwargs["error_code"] = "unexpected_error"
    await _append(
        uow_factory,
        _event(execution_id=execution_id, event_type=terminal, **terminal_kwargs),  # type: ignore[arg-type]
    )
    second_kwargs: dict[str, object] = {}
    if second is DatasourceExecutionEventType.FAILED:
        second_kwargs["error_code"] = "decode_failed"
    with pytest.raises(DatasourceLogAppendAfterTerminalError):
        await _append(
            uow_factory,
            _event(execution_id=execution_id, event_type=second, **second_kwargs),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage",
    [
        DatasourceExecutionEventType.ACQUIRED,
        DatasourceExecutionEventType.DECODED,
        DatasourceExecutionEventType.CONVERTED,
    ],
)
@pytest.mark.parametrize(
    "terminal",
    [
        DatasourceExecutionEventType.COMPLETED,
        DatasourceExecutionEventType.FAILED,
        DatasourceExecutionEventType.CANCELLED,
    ],
)
async def test_p09_post_terminal_stage_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    stage: DatasourceExecutionEventType,
    terminal: DatasourceExecutionEventType,
) -> None:
    """D27B-P09: no stage may be appended after a terminal outcome."""
    execution_id = uuid4()
    await _append(uow_factory, _event(execution_id=execution_id))
    terminal_kwargs: dict[str, object] = {}
    if terminal is DatasourceExecutionEventType.FAILED:
        terminal_kwargs["error_code"] = "unexpected_error"
    await _append(
        uow_factory,
        _event(execution_id=execution_id, event_type=terminal, **terminal_kwargs),  # type: ignore[arg-type]
    )
    with pytest.raises(DatasourceLogAppendAfterTerminalError):
        await _append(uow_factory, _event(execution_id=execution_id, event_type=stage))


@pytest.mark.asyncio
async def test_p10_concurrent_terminal_race(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-P10: concurrent terminal writers yield exactly one terminal row."""
    execution_id = uuid4()
    await _append(uow_factory, _event(execution_id=execution_id))

    async def terminal_attempt(event_type: DatasourceExecutionEventType) -> str:
        """Attempt one terminal append in its own transaction."""
        kwargs: dict[str, object] = {}
        if event_type is DatasourceExecutionEventType.FAILED:
            kwargs["error_code"] = "unexpected_error"
        try:
            await _append(
                uow_factory,
                _event(execution_id=execution_id, event_type=event_type, **kwargs),  # type: ignore[arg-type]
            )
            return "ok"
        except DatasourceLogAppendAfterTerminalError:
            return "rejected"
        except DatasourceLogInvalidInputError:  # pragma: no cover - defensive
            return "rejected"

    outcomes = await asyncio.gather(
        terminal_attempt(DatasourceExecutionEventType.COMPLETED),
        terminal_attempt(DatasourceExecutionEventType.FAILED),
    )
    assert sorted(outcomes) == ["ok", "rejected"]
    rows = await _log_rows(integration_engine, execution_id)
    terminal_rows = [
        row for row in rows if row[3] in ("completed", "failed", "cancelled")
    ]
    assert len(terminal_rows) == 1
    assert len(rows) == 2  # STARTED + exactly one terminal


@pytest.mark.asyncio
async def test_p11_concurrent_initial_started_race(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-P11: two concurrent initial STARTED writes yield exactly one row."""
    execution_id = uuid4()

    async def started_attempt() -> str:
        """Attempt the initial STARTED append in its own transaction."""
        try:
            await _append(uow_factory, _event(execution_id=execution_id))
            return "ok"
        except DatasourceLogDuplicateStartedError:
            return "rejected"

    outcomes = await asyncio.gather(started_attempt(), started_attempt())
    assert sorted(outcomes) == ["ok", "rejected"]
    rows = await _log_rows(integration_engine, execution_id)
    assert len(rows) == 1
    assert rows[0][3] == "started"


@pytest.mark.asyncio
async def test_p12_independent_executions(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-P12: concurrent executions share no identity and do not block."""
    execution_id_a = uuid4()
    execution_id_b = uuid4()

    async def run(execution_id: UUID) -> UUID:
        """Run one independent short lifecycle."""
        await _append(uow_factory, _event(execution_id=execution_id))
        await _append(
            uow_factory,
            _event(
                execution_id=execution_id,
                event_type=DatasourceExecutionEventType.COMPLETED,
            ),
        )
        return execution_id

    first, second = await asyncio.gather(run(execution_id_a), run(execution_id_b))
    assert first != second
    rows_a = await _log_rows(integration_engine, execution_id_a)
    rows_b = await _log_rows(integration_engine, execution_id_b)
    assert [row[3] for row in rows_a] == ["started", "completed"]
    assert [row[3] for row in rows_b] == ["started", "completed"]


@pytest.mark.asyncio
async def test_p13_database_rejects_invalid_values_bypassing_python(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-P13: the DB rejects invalid counts/error codes even if bypassed.

    Direct INSERTs are outside the normal application path but prove the
    CHECK constraints are database-owned backstops, not Python-only rules.
    """
    execution_id = uuid4()

    async def direct_insert(
        item_count: int | None,
        byte_count: int | None,
        error_code: str | None,
    ) -> None:
        """Insert one raw row with the supplied raw column values."""
        async with integration_engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO ati.datasource_log ("
                    "execution_id, datasource_id, event_type, occurred_at, "
                    "item_count, byte_count, error_code) VALUES "
                    "(:execution_id, :datasource_id, :event_type, :occurred_at, "
                    ":item_count, :byte_count, :error_code)"
                ),
                {
                    "execution_id": execution_id,
                    "datasource_id": "threatfox-live",
                    "event_type": "started",
                    "occurred_at": _OCCURRED_AT,
                    "item_count": item_count,
                    "byte_count": byte_count,
                    "error_code": error_code,
                },
            )

    # Negative counts violate the count checks.
    with pytest.raises(IntegrityError):
        await direct_insert(-1, None, None)
    with pytest.raises(IntegrityError):
        await direct_insert(None, -1, None)
    # Malformed/padded error codes violate the grammar check.
    with pytest.raises(IntegrityError):
        await direct_insert(None, None, " bad_code")
    with pytest.raises(IntegrityError):
        await direct_insert(None, None, "x" * 65)
    # error_code on a non-failed event violates the compatibility check.
    with pytest.raises(IntegrityError):
        await direct_insert(None, None, "unexpected_error")
    # No rows were persisted by any rejected insert.
    assert await _count(integration_engine, "datasource_log") == 0


@pytest.mark.asyncio
async def test_p14_repository_is_append_only() -> None:
    """D27B-P14: the append port exposes no update/delete mutation."""
    abstract_methods = set(DatasourceLogRepository.__abstractmethods__)
    assert abstract_methods == {"append"}
    # No alternative mutation path exists on the concrete adapter either.
    from agentic_threat_investigator.infrastructure.persistence.postgresql.datasource_log_repositories import (
        PostgresDatasourceLogRepository,
    )

    concrete_public = {
        name
        for name in dir(PostgresDatasourceLogRepository)
        if not name.startswith("_")
    }
    assert "append" in concrete_public
    assert not {"update", "delete", "soft_delete", "upsert"} & concrete_public


@pytest.mark.asyncio
async def test_v01_application_vertical_slice(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-V01: deterministic application vertical slice over real PostgreSQL.

    The real recorder/port/repository/stored-function path runs an entire
    acquisition lifecycle with simulated local work between short committed
    transactions; the durable log is inspected afterwards.
    """
    from agentic_threat_investigator.app.datasource_execution import (
        DatasourceExecutionRecorder,
    )
    from agentic_threat_investigator.domain.datasource import (
        DatasourceDefinition,
        DatasourceProtocol,
        SerializationFormat,
    )
    from agentic_threat_investigator.domain.identifiers import (
        SemanticFormatId,
        SourceId,
    )

    definition = DatasourceDefinition(
        datasource_id=DatasourceId("threatfox-live"),
        source_id=SourceId.THREATFOX,
        protocol=DatasourceProtocol.HTTPS,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.THREATFOX,
    )
    recorder = DatasourceExecutionRecorder(
        definition.datasource_id, uow_factory=uow_factory, clock=lambda: _OCCURRED_AT
    )
    await recorder.start()
    # Simulated external acquisition work happens with NO database transaction
    # held; each recorder call opened and committed its own short UoW.
    await recorder.acquired(byte_count=4096)
    await recorder.decoded(item_count=3)
    await recorder.converted(item_count=2)
    await recorder.complete()

    rows = await _log_rows(integration_engine, recorder.execution_id)
    assert len(rows) == 5
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "completed",
    ]
    assert {row[1] for row in rows} == {recorder.execution_id}
    assert {row[2] for row in rows} == {"threatfox-live"}
    ids = [row[0] for row in rows]
    assert ids == sorted(ids)
    assert all(row[4].astimezone(UTC) == _OCCURRED_AT for row in rows)
    assert rows[1][6] == 4096
    assert rows[2][5] == 3 and rows[3][5] == 2
    assert rows[0][5] is None and rows[0][6] is None and rows[4][5] is None
    assert all(row[7] is None for row in rows)

    # Schema carries no source/Evidence/credential payload surface.
    async with integration_engine.connect() as connection:
        columns = {
            row[0]
            for row in await connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'ati' AND table_name = 'datasource_log'"
                )
            )
        }
        tables = {
            row[0]
            for row in await connection.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'ati'"
                )
            )
        }
    assert columns == {
        "id",
        "execution_id",
        "datasource_id",
        "event_type",
        "occurred_at",
        "item_count",
        "byte_count",
        "error_code",
        "created_at",
    }
    assert "datasource_execution" not in tables


@pytest.mark.asyncio
async def test_v02_failure_variant_persists_only_safe_code(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-V02: a failing slice persists STARTED + FAILED with the safe code."""
    from agentic_threat_investigator.app.datasource_execution import (
        DatasourceExecutionRecorder,
    )

    recorder = DatasourceExecutionRecorder(
        _THREATFOX, uow_factory=uow_factory, clock=lambda: _OCCURRED_AT
    )

    async def work() -> None:
        """Simulate a decode failure with sensitive detail."""
        raise ValueError("malformed payload with secret token")

    with pytest.raises(ValueError, match="malformed payload"):
        await recorder.run(work, error_code="decode_failed")
    rows = await _log_rows(integration_engine, recorder.execution_id)
    assert [row[3] for row in rows] == ["started", "failed"]
    assert rows[1][7] == "decode_failed"
    # The raw exception detail never entered the durable log.
    assert all("secret token" not in str(row) for row in rows)


@pytest.mark.asyncio
async def test_c01_cancellation_is_deterministic_and_propagates(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27B-C01: deterministic sleep-free cancellation over real PostgreSQL.

    STARTED persists, fake work signals entry through an ``asyncio.Event``,
    the task is cancelled, the helper records CANCELLED, ``CancelledError``
    propagates, and the durable log holds STARTED + CANCELLED only.
    """
    from agentic_threat_investigator.app.datasource_execution import (
        DatasourceExecutionRecorder,
    )

    recorder = DatasourceExecutionRecorder(
        _THREATFOX, uow_factory=uow_factory, clock=lambda: _OCCURRED_AT
    )
    entered = asyncio.Event()
    never = asyncio.Event()

    async def work() -> None:
        """Signal entry and wait for cancellation (no timing sleeps)."""
        entered.set()
        await never.wait()

    task = asyncio.create_task(recorder.run(work))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    rows = await _log_rows(integration_engine, recorder.execution_id)
    assert [row[3] for row in rows] == ["started", "cancelled"]
    assert all(row[7] is None for row in rows)
    assert not any(row[3] in ("failed", "completed") for row in rows)


@pytest.mark.asyncio
async def test_s01_log_schema_is_bounded_and_operational() -> None:
    """D27B-S01: the durable log schema is exactly the bounded operational set.

    Typed schema absence proves source bodies, decoded objects, Evidence
    bodies, credentials, headers, URIs, and tracebacks cannot be persisted.
    """
    from agentic_threat_investigator.infrastructure.persistence.postgresql.datasource_log_repositories import (
        PostgresDatasourceLogRepository,
    )

    assert not hasattr(PostgresDatasourceLogRepository, "insert")
    assert not hasattr(PostgresDatasourceLogRepository, "update")
    # The domain model carries no payload/exception/credential field at all.
    from agentic_threat_investigator.domain.datasource import DatasourceLogEvent

    fields = set(DatasourceLogEvent.model_fields)
    assert fields == {
        "execution_id",
        "datasource_id",
        "event_type",
        "occurred_at",
        "item_count",
        "byte_count",
        "error_code",
    }
