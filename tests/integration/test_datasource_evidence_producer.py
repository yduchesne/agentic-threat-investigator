# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 28F-2 datasource Evidence producer real-stack vertical slices.

The canonical vertical slices run the full producer path over real
PostgreSQL: deterministic real-format ThreatFox HTTP fixture via
``httpx.MockTransport`` -> real ``ProviderHttpClient`` -> real
``ThreatFoxDatasource`` -> real ThreatFox semantic parser -> real
``ThreatFoxToEvidenceConverter`` -> real ``evidence_message_from_converted``
builder -> real ``InMemoryEvidenceLog.publisher()`` as the injected
``EvidencePublisher`` -> real ``DatasourceExecutionRecorder`` -> real
``PostgresUnitOfWork`` -> real ``ati.append_datasource_log_event`` stored
function (SQL API v0028) -> real ``ati.datasource_log``. Only the external
Internet endpoint is faked; ATI's acquisition, conversion, message, publish,
lifecycle, and PostgreSQL architecture are all real.

Matrix IDs V28F2-01..07 cover ThreatFox success with exact
``STARTED, ACQUIRED, DECODED, CONVERTED, PUBLISHED, COMPLETED`` lifecycle,
multi-record order (semantic order == converted order == message sequence ==
log order), valid zero result (``PUBLISHED(0)``), publisher failure via
``InMemoryEvidenceLog.fail_next_publish()``, deterministic cancellation at
the publisher boundary, real-PostgreSQL PUBLISHED lifecycle acceptance and
post-terminal rejection, and producer/consumer separation (the producer
completes without any ``EvidencePersistenceConsumer`` running).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.datasource_evidence_producer import (
    DatasourceEvidenceProducer,
    DatasourceProducerOutcome,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceConsumerId,
    EvidencePublisher,
    EvidencePublishError,
    EvidencePublishResult,
    InMemoryEvidenceLog,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    evidence_message_id,
)
from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceLogAppendAfterTerminalError,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceExecutionEventType,
    DatasourceId,
    DatasourceLogEvent,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox import (
    ThreatFoxDatasource,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    build_threatfox_conversion_registry,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from tests.support.provider_http import no_op_sleep, zero_jitter
from tests.support.threatfox_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    FIXED_KEY,
    asyncrat_domain_record,
    threatfox_search_response,
)

pytestmark = pytest.mark.integration

_OCCURRED_AT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)
_DOMAIN_ENTITY = Entity(type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN)

_BODY = json.dumps(threatfox_search_response(asyncrat_domain_record())).encode("utf-8")
"""Deterministic response body; its exact byte length is asserted on ACQUIRED."""


def _json_response(payload: object, *, status: int = 200) -> httpx.Response:
    """Build one deterministic JSON response with an explicit body length."""
    return httpx.Response(
        status,
        content=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def _client(handler: Callable[[httpx.Request], Any]) -> httpx.AsyncClient:
    """Build a real ``httpx`` mock-transport client for the local fixture."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _datasource(client: httpx.AsyncClient) -> ThreatFoxDatasource:
    """Build the real acquirer over the real bounded HTTP client."""
    return ThreatFoxDatasource(
        ProviderHttpClient(
            client=client,
            policy=ProviderHttpPolicy(max_retries=0, base_delay_seconds=0.01),
            sleep=no_op_sleep,
            jitter_fn=zero_jitter,
        ),
        auth_key=FIXED_KEY,
        clock=lambda: _OCCURRED_AT,
    )


def _producer(
    datasource: ThreatFoxDatasource,
    publisher: EvidencePublisher,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> DatasourceEvidenceProducer[Any]:
    """Compose the real producer over the real datasource/recorder/publisher."""
    return DatasourceEvidenceProducer(
        definition=_DEFINITION,
        acquirer=datasource,
        registry=build_threatfox_conversion_registry(),
        publisher=publisher,
        uow_factory=uow_factory,
        clock=lambda: _OCCURRED_AT,
    )


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


async def _only_execution(
    integration_engine: AsyncEngine, datasource_value: str = "threatfox-live"
) -> UUID:
    """Return the single durable execution recorded for the datasource."""
    async with integration_engine.connect() as connection:
        value = await connection.scalar(
            text(
                "SELECT DISTINCT execution_id FROM ati.datasource_log "
                "WHERE datasource_id = :datasource_id"
            ),
            {"datasource_id": datasource_value},
        )
    assert value is not None
    return UUID(str(value))


async def _count(integration_engine: AsyncEngine, table: str) -> int:
    """Return the row count of one ati table."""
    async with integration_engine.connect() as connection:
        count = await connection.scalar(text(f"SELECT count(*) FROM ati.{table}"))
    return int(count or 0)


async def _poll_messages(log: InMemoryEvidenceLog) -> tuple[EvidenceMessage, ...]:
    """Return every published message of one log in position order."""
    consumer = log.consumer(EvidenceConsumerId("vertical-slice"))
    batch = await consumer.poll(500)
    return tuple(record.message for record in batch.records)


async def _append_event(
    uow_factory: Callable[[], PostgresUnitOfWork],
    event: DatasourceLogEvent,
) -> None:
    """Append one event in a short committed transaction."""
    async with uow_factory() as uow:
        await uow.datasource_logs.append(event)


@pytest.mark.asyncio
async def test_v28f2_01_threatfox_success_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """V28F2-01: one ThreatFox record -> one message with exact lifecycle.

    The full real path records STARTED -> ACQUIRED -> DECODED -> CONVERTED
    (item_count=1) -> PUBLISHED (item_count=1) -> COMPLETED under exactly one
    execution ID; the message carries the exact execution ID/provenance and
    sequence 0; the log contains the message; the producer completes without
    any consumer; and no global Evidence is persisted merely because the
    producer completed.
    """
    log = InMemoryEvidenceLog()
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        outcome = await _producer(
            _datasource(client), log.publisher(), uow_factory
        ).produce(_DOMAIN_ENTITY)

    assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
    assert outcome.published_count == 1
    assert outcome.error_code is None

    execution_id = outcome.execution_id
    assert execution_id is not None
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    assert {row[1] for row in rows} == {execution_id}
    assert {row[2] for row in rows} == {"threatfox-live"}
    assert rows[1][6] == len(_BODY)
    assert rows[2][5] == 1
    assert rows[3][5] == 1
    assert rows[4][5] == 1
    assert all(row[7] is None for row in rows)

    (message,) = await _poll_messages(log)
    assert message.sequence == 0
    assert message.datasource_execution_id == execution_id
    assert message.source_id is SourceId.THREATFOX
    assert message.semantic_format is SemanticFormatId.THREATFOX
    assert message.source_record_id == "864201"
    assert message.message_id == evidence_message_id(
        execution_id, 0, message.evidence_id
    )

    # The producer never waits for or runs the PR 28E consumer, and no
    # global Evidence was persisted merely because it completed.
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "source_record") == 0
    assert await _count(integration_engine, "investigation") == 0


@pytest.mark.asyncio
async def test_v28f2_02_multi_record_order_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """V28F2-02: semantic order == converted order == message sequence == log order.

    Two distinct validated records matching the same queried domain are
    converted in source order, flattened to sequences 0,1, published in one
    ordered call, and appear in the log in the same order with PUBLISHED(2).
    """
    log = InMemoryEvidenceLog()
    payload = threatfox_search_response(
        asyncrat_domain_record(),
        asyncrat_domain_record(id="864299", last_seen=None),
    )
    async with _client(lambda _: _json_response(payload)) as client:
        outcome = await _producer(
            _datasource(client), log.publisher(), uow_factory
        ).produce(_DOMAIN_ENTITY)

    assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
    assert outcome.published_count == 2
    messages = await _poll_messages(log)
    assert [message.sequence for message in messages] == [0, 1]
    assert [message.source_record_id for message in messages] == ["864201", "864299"]

    execution_id = outcome.execution_id
    assert execution_id is not None
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    assert rows[2][5] == 2
    assert rows[3][5] == 2
    assert rows[4][5] == 2
    assert await _count(integration_engine, "evidence") == 0


@pytest.mark.asyncio
async def test_v28f2_03_zero_result_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """V28F2-03: a valid no-result records CONVERTED(0), PUBLISHED(0), COMPLETED.

    The empty publish is a no-op: the in-memory log holds no records.
    """
    log = InMemoryEvidenceLog()
    async with _client(
        lambda _: _json_response({"query_status": "no_result"})
    ) as client:
        outcome = await _producer(
            _datasource(client), log.publisher(), uow_factory
        ).produce(_DOMAIN_ENTITY)

    assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
    assert outcome.published_count == 0
    assert await _poll_messages(log) == ()

    execution_id = outcome.execution_id
    assert execution_id is not None
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    assert rows[3][5] == 0
    assert rows[4][5] == 0
    assert await _count(integration_engine, "evidence") == 0


@pytest.mark.asyncio
async def test_v28f2_04_publisher_failure_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """V28F2-04: a publish failure records FAILED(publication_failed).

    CONVERTED exists in the durable lifecycle, PUBLISHED/COMPLETED are
    absent, the bounded ``publication_failed`` code is recorded, the
    in-memory log is unchanged, and there is no direct-persistence fallback.
    """
    log = InMemoryEvidenceLog()
    log.fail_next_publish()
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        with pytest.raises(EvidencePublishError):
            await _producer(_datasource(client), log.publisher(), uow_factory).produce(
                _DOMAIN_ENTITY
            )

    assert await _poll_messages(log) == ()
    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "failed",
    ]
    assert rows[-1][7] == "publication_failed"
    assert "published" not in [row[3] for row in rows]
    assert "completed" not in [row[3] for row in rows]
    assert await _count(integration_engine, "evidence") == 0


class _BlockingPublisher(EvidencePublisher):
    """Test-only publisher that blocks until cancelled, deterministically."""

    def __init__(self) -> None:
        """Start with an unentered gate and a never-completing wait."""
        self.entered = asyncio.Event()
        self._never = asyncio.Event()

    async def publish(
        self, messages: Sequence[EvidenceMessage]
    ) -> EvidencePublishResult:
        """Signal entry, then block until the task is cancelled."""
        self.entered.set()
        await self._never.wait()
        return EvidencePublishResult(records=())


@pytest.mark.asyncio
async def test_v28f2_05_cancellation_at_publisher_boundary(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """V28F2-05: deterministic cancellation at the publisher boundary.

    STARTED/ACQUIRED/DECODED/CONVERTED persist, the publisher blocks, the
    task is cancelled, CANCELLED is recorded (best effort), the cancellation
    propagates, and no PUBLISHED/FAILED/COMPLETED event is durable.
    """
    log = InMemoryEvidenceLog()
    blocking = _BlockingPublisher()
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        task = asyncio.create_task(
            _producer(_datasource(client), blocking, uow_factory).produce(
                _DOMAIN_ENTITY
            )
        )
        await blocking.entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert await _poll_messages(log) == ()
    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "cancelled",
    ]
    assert all(row[7] is None for row in rows)
    assert not any(row[3] in ("published", "failed", "completed") for row in rows)
    assert await _count(integration_engine, "evidence") == 0


@pytest.mark.asyncio
async def test_v28f2_06_db_lifecycle_published_acceptance_and_post_terminal(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """V28F2-06: real PostgreSQL accepts PUBLISHED and rejects it after terminal.

    The exact ``STARTED, ACQUIRED, DECODED, CONVERTED, PUBLISHED, COMPLETED``
    order persists under one execution ID through the versioned stored
    function (SQL API v0028); a PUBLISHED append after a terminal outcome
    fails atomically with the typed append-after-terminal error.
    """
    from uuid import uuid4

    execution_id = uuid4()
    occurred_at = _OCCURRED_AT

    async def event(
        event_type: DatasourceExecutionEventType,
        *,
        item_count: int | None = None,
        byte_count: int | None = None,
    ) -> DatasourceLogEvent:
        return DatasourceLogEvent(
            execution_id=execution_id,
            datasource_id=_DEFINITION.datasource_id,
            event_type=event_type,
            occurred_at=occurred_at,
            item_count=item_count,
            byte_count=byte_count,
        )

    await _append_event(uow_factory, await event(DatasourceExecutionEventType.STARTED))
    await _append_event(
        uow_factory,
        await event(DatasourceExecutionEventType.ACQUIRED, byte_count=1234),
    )
    await _append_event(
        uow_factory,
        await event(DatasourceExecutionEventType.DECODED, item_count=2),
    )
    await _append_event(
        uow_factory,
        await event(DatasourceExecutionEventType.CONVERTED, item_count=2),
    )
    await _append_event(
        uow_factory,
        await event(DatasourceExecutionEventType.PUBLISHED, item_count=2),
    )
    await _append_event(
        uow_factory, await event(DatasourceExecutionEventType.COMPLETED)
    )

    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    assert [row[1] for row in rows] == [execution_id] * 6
    assert rows[4][5] == 2
    assert all(row[7] is None for row in rows)

    # PUBLISHED after a terminal outcome fails atomically.
    with pytest.raises(DatasourceLogAppendAfterTerminalError):
        await _append_event(
            uow_factory,
            await event(DatasourceExecutionEventType.PUBLISHED, item_count=1),
        )
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]


@pytest.mark.asyncio
async def test_v28f2_07_producer_consumer_separation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """V28F2-07: the producer completes without the PR 28E consumer running.

    A real ThreatFox-derived message is published, the producer reaches
    COMPLETED, and no ``EvidencePersistenceConsumer`` is started: the log
    still holds the message and no global Evidence/observation receipt row
    exists.
    """
    log = InMemoryEvidenceLog()
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        outcome = await _producer(
            _datasource(client), log.publisher(), uow_factory
        ).produce(_DOMAIN_ENTITY)

    assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
    assert outcome.published_count == 1
    execution_id = outcome.execution_id
    assert execution_id is not None
    rows = await _log_rows(integration_engine, execution_id)
    assert rows[-1][3] == "completed"
    # The message is still in the log: no consumer polled or committed it.
    (message,) = await _poll_messages(log)
    assert message.source_record_id == "864201"
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 0
    assert await _count(integration_engine, "investigation") == 0
