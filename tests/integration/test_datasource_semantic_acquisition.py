# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27C ThreatFox acquisition-to-semantic real-stack vertical slice.

The canonical PR 27C vertical slice runs the production path over real
PostgreSQL: deterministic local HTTP fixture via ``httpx.MockTransport`` ->
real ``ProviderHttpClient`` -> real ``ThreatFoxDatasource`` acquirer -> real
ThreatFox semantic parser -> real ``DatasourceExecutionRecorder`` -> real
``PostgresUnitOfWork`` -> real ``ati.append_datasource_log_event`` stored
function -> real ``ati.datasource_log``. Only the external Internet endpoint
is faked; ATI's acquisition, parsing, logging, and PostgreSQL architecture
are all real. Assertions cover the exact success/failure/cancellation
lifecycles, one execution identity, bounded counts, no Evidence/SourceRecord
persistence, and no raw body/credential leakage.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
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
    acquire_threatfox_execution,
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


def _json_response(payload: object) -> httpx.Response:
    """Build one deterministic JSON response with an explicit body length."""
    return httpx.Response(
        200,
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


@pytest.mark.asyncio
async def test_success_lifecycle_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """Success: one execution, exact lifecycle, bounded counts, no persistence.

    The full real path (real HTTP client, real acquirer, real parser, real
    recorder, real PostgreSQL stored function) records STARTED -> ACQUIRED ->
    DECODED -> COMPLETED under exactly one execution ID, with the exact
    acquired byte count and decoded record count, and creates no Evidence,
    no SourceRecord, and no investigation.
    """
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        result = await acquire_threatfox_execution(
            datasource=_datasource(client),
            definition=_DEFINITION,
            entity=_DOMAIN_ENTITY,
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )

    # The semantic result carries validated source-native records only.
    assert result.error is None
    assert result.context.datasource_id == _DEFINITION.datasource_id
    assert result.context.source_id is SourceId.THREATFOX
    assert len(result.objects) == 1
    assert result.objects[0].id == "864201"
    assert result.objects[0].ioc == CANONICAL_ASYNCRAT_DOMAIN

    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "completed",
    ]
    assert {row[1] for row in rows} == {execution_id}
    assert {row[2] for row in rows} == {"threatfox-live"}
    assert all(row[4].astimezone(UTC) == _OCCURRED_AT for row in rows)
    # ACQUIRED carries the exact serialized fixture byte length.
    assert rows[1][6] == len(_BODY)
    # DECODED carries the number of unique validated semantic records.
    assert rows[2][5] == 1
    # No CONVERTED event; no error codes on success.
    assert "converted" not in [row[3] for row in rows]
    assert all(row[7] is None for row in rows)

    # The reference path persists no Evidence, no SourceRecord, and needs no
    # Investigation.
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "source_record") == 0
    assert await _count(integration_engine, "investigation") == 0


@pytest.mark.asyncio
async def test_no_raw_body_or_credential_in_durable_log(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """The durable log carries no body bytes and no Auth-Key."""
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        await acquire_threatfox_execution(
            datasource=_datasource(client),
            definition=_DEFINITION,
            entity=_DOMAIN_ENTITY,
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )
    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    serialized = str(rows)
    # The response body fragment and the credential never enter the log.
    assert "asyncrat" not in serialized
    assert '"ok"' not in serialized.replace(" ", "")
    assert FIXED_KEY not in serialized
    # The bounded schema cannot represent a body: no payload/credential columns.
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
    assert "payload" not in columns
    assert "body" not in columns
    assert {"filename", "url", "credential", "auth"} & columns == set()


@pytest.mark.asyncio
async def test_semantic_failure_lifecycle_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """Semantic failure: STARTED -> ACQUIRED -> FAILED with the safe code.

    Valid JSON with a malformed ThreatFox record reaches the semantic
    validator: ACQUIRED records the acquired bytes, the execution FAILs with
    ``semantic_validation_failed``, no DECODED is appended, and no raw
    record content or body persists.
    """
    malformed = {"query_status": "ok", "data": [{"id": "not-decimal"}]}
    async with _client(lambda _: _json_response(malformed)) as client:
        result = await acquire_threatfox_execution(
            datasource=_datasource(client),
            definition=_DEFINITION,
            entity=_DOMAIN_ENTITY,
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )

    assert result.objects == ()
    assert result.error is not None
    assert result.error.code == "semantic_validation_failed"

    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == ["started", "acquired", "failed"]
    assert rows[-1][7] == "semantic_validation_failed"
    assert "decoded" not in [row[3] for row in rows]
    assert "not-decimal" not in str(rows)
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "source_record") == 0


@pytest.mark.asyncio
async def test_serialization_failure_lifecycle_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """Serialization failure: STARTED -> FAILED; no ACQUIRED/DECODED.

    Malformed JSON is classified deterministically as a serialization stage
    failure and records the bounded ``serialization_failed`` code with no
    intermediate stage events.
    """
    async with _client(
        lambda _: httpx.Response(
            200,
            content=b"{not json",
            headers={"Content-Type": "application/json"},
        )
    ) as client:
        result = await acquire_threatfox_execution(
            datasource=_datasource(client),
            definition=_DEFINITION,
            entity=_DOMAIN_ENTITY,
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )

    assert result.objects == ()
    assert result.error is not None
    assert result.error.code == "serialization_failed"

    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == ["started", "failed"]
    assert rows[-1][7] == "serialization_failed"
    assert not any(
        row[3] in ("acquired", "decoded", "completed", "converted") for row in rows
    )


@pytest.mark.asyncio
async def test_http_failure_lifecycle_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """Acquisition failure: STARTED -> FAILED with ``provider_unavailable``."""
    async with _client(lambda _: httpx.Response(503, json={})) as client:
        result = await acquire_threatfox_execution(
            datasource=_datasource(client),
            definition=_DEFINITION,
            entity=_DOMAIN_ENTITY,
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )

    assert result.objects == ()
    assert result.error is not None
    assert result.error.code == "provider_unavailable"
    assert result.error.retryable is True

    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == ["started", "failed"]
    assert rows[-1][7] == "provider_unavailable"


@pytest.mark.asyncio
async def test_cancellation_real_stack_propagates_and_records_cancelled(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """Cancellation: CANCELLED recorded best-effort; CancelledError propagates.

    Deterministic sleep-free cancellation during the HTTP wait: STARTED
    persists, the transport blocks on an event, the task is cancelled, the
    runner records CANCELLED, ``CancelledError`` propagates, and the durable
    log holds exactly STARTED + CANCELLED — never FAILED or COMPLETED.
    """
    entered = asyncio.Event()
    never = asyncio.Event()

    async def handler(_: httpx.Request) -> httpx.Response:
        entered.set()
        await never.wait()
        return _json_response({})

    async with _client(handler) as client:
        task = asyncio.create_task(
            acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=uow_factory,
                clock=lambda: _OCCURRED_AT,
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == ["started", "cancelled"]
    assert all(row[7] is None for row in rows)
    assert not any(row[3] in ("failed", "completed") for row in rows)
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "source_record") == 0
