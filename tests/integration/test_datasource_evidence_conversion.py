# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27D ThreatFox acquisition -> semantic -> conversion real-stack slice.

The canonical PR 27D vertical slice runs the production path over real
PostgreSQL: deterministic local ThreatFox HTTP fixture via
``httpx.MockTransport`` -> real ``ProviderHttpClient`` -> real
``ThreatFoxDatasource`` -> real ThreatFox semantic parser -> real
``SemanticSourceContext`` -> real ``ToEvidenceConverterRegistry`` -> real
``ThreatFoxToEvidenceConverter`` -> in-memory ``LegacyEvidence`` -> real
``DatasourceExecutionRecorder`` -> real ``PostgresUnitOfWork`` -> real
``ati.append_datasource_log_event`` stored function -> real
``ati.datasource_log``. Only the external Internet endpoint is faked;
ATI's acquisition, semantic, conversion, logging, and PostgreSQL
architecture are all real. Matrix IDs D27D-I01..I06 cover one-record
success, valid no-result (CONVERTED 0), two semantic records, conversion
failure (bounded ``conversion_failed``), cancellation, and minimization.
No LegacyEvidence is ever persisted by this slice.
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

from agentic_threat_investigator.app.evidence_conversion import (
    ConversionError,
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.infrastructure.datasources.threatfox import (
    ThreatFoxDatasource,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    acquire_and_convert_threatfox_execution,
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
_INVESTIGATION_ID = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
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
async def test_i01_one_record_success_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27D-I01: one LegacyEvidence with exact provenance and a full lifecycle.

    The full real path records STARTED -> ACQUIRED -> DECODED -> CONVERTED
    (item_count=1) -> COMPLETED under exactly one execution ID with the
    exact acquired byte count and decoded record count, and the in-memory
    LegacyEvidence carries exact provenance. No LegacyEvidence, SourceRecord, or
    Investigation is persisted.
    """
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        result, evidence = await acquire_and_convert_threatfox_execution(
            datasource=_datasource(client),
            definition=_DEFINITION,
            entity=_DOMAIN_ENTITY,
            registry=build_threatfox_conversion_registry(),
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )

    # The semantic result carries validated source-native records only.
    assert result.error is None
    assert result.context.datasource_id == _DEFINITION.datasource_id
    assert result.context.source_id is SourceId.THREATFOX
    assert result.context.semantic_format is SemanticFormatId.THREATFOX
    assert len(result.objects) == 1

    # The conversion produced exactly one in-memory LegacyEvidence with provenance.
    assert len(evidence) == 1
    item = evidence[0]
    assert item.evidence.type == EvidenceType.THREAT_INTELLIGENCE
    # PR 28A: conversion is global and Investigation-independent.
    assert item.evidence.id == evidence_id_for_source_record(
        SemanticFormatId.THREATFOX, SourceId.THREATFOX, "864201"
    )
    assert item.evidence.source == SourceId.THREATFOX.value
    assert item.evidence.source_record_id == "864201"
    assert item.observation.source_url == _ENDPOINT
    assert item.observation.retrieved_at == _OCCURRED_AT
    assert item.observation.observed_at == datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)
    assert item.observation.raw_payload is None
    match = item.observation.facts["matches"][0]
    assert thaw_json(match)["threatfox_id"] == "864201"
    assert thaw_json(match)["confidence_level"] == 100
    assert thaw_json(match)["malware"] == "win.asyncrat"

    execution_id = await _only_execution(integration_engine)
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
    assert all(row[4].astimezone(UTC) == _OCCURRED_AT for row in rows)
    assert rows[1][6] == len(_BODY)
    assert rows[2][5] == 1
    assert rows[3][5] == 1
    assert all(row[7] is None for row in rows)

    # No LegacyEvidence is persisted by the PR 27D slice.
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "source_record") == 0
    assert await _count(integration_engine, "investigation") == 0


@pytest.mark.asyncio
async def test_i02_valid_no_result_converted_zero_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27D-I02: a valid no-result records CONVERTED(0) then COMPLETED.

    ``CONVERTED`` with ``item_count=0`` explicitly proves conversion ran and
    found no ATI-supported assertion; the lifecycle never records FAILED.
    """
    async with _client(
        lambda _: _json_response({"query_status": "no_result"})
    ) as client:
        result, evidence = await acquire_and_convert_threatfox_execution(
            datasource=_datasource(client),
            definition=_DEFINITION,
            entity=_DOMAIN_ENTITY,
            registry=build_threatfox_conversion_registry(),
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )

    assert result.error is None
    assert result.objects == ()
    assert evidence == ()

    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "completed",
    ]
    assert rows[3][5] == 0
    assert all(row[7] is None for row in rows)
    assert "failed" not in [row[3] for row in rows]
    assert await _count(integration_engine, "evidence") == 0


@pytest.mark.asyncio
async def test_i03_two_semantic_records_two_evidence_in_order_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27D-I03: two records yield two LegacyEvidence in semantic source order.

    Two distinct validated records matching the same queried domain are
    converted in source order with CONVERTED item_count=2.
    """
    payload = threatfox_search_response(
        asyncrat_domain_record(),
        asyncrat_domain_record(id="864299", last_seen=None),
    )
    async with _client(lambda _: _json_response(payload)) as client:
        result, evidence = await acquire_and_convert_threatfox_execution(
            datasource=_datasource(client),
            definition=_DEFINITION,
            entity=_DOMAIN_ENTITY,
            registry=build_threatfox_conversion_registry(),
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )

    assert result.error is None
    assert len(result.objects) == 2
    assert len(evidence) == 2
    assert [item.evidence.source_record_id for item in evidence] == [
        "864201",
        "864299",
    ]
    assert [item.observation.observed_at for item in evidence] == [
        datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC),
        datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC),
    ]

    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "completed",
    ]
    assert rows[2][5] == 2
    assert rows[3][5] == 2
    assert await _count(integration_engine, "evidence") == 0


class _FailingConverter(ToEvidenceConverter[Any]):
    """Test-only deterministic conversion-failure converter."""

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Claim the ThreatFox semantic format."""
        return SemanticFormatId.THREATFOX

    def convert(
        self,
        source: Any,
        context: EvidenceConversionContext,
    ) -> tuple[Any, ...]:
        """Raise the typed deterministic conversion failure."""
        raise ConversionError("deterministic local conversion failure")


def _failing_registry() -> ToEvidenceConverterRegistry:
    """Build a registry whose only ThreatFox converter always fails."""
    return ToEvidenceConverterRegistry(converters=(_FailingConverter(),))


@pytest.mark.asyncio
async def test_i04_conversion_failure_real_stack(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27D-I04: conversion failure records only bounded ``conversion_failed``.

    After real semantic acquisition the failing converter yields
    STARTED/ACQUIRED/DECODED/FAILED with ``error_code=conversion_failed`` —
    never CONVERTED, never COMPLETED — while the typed ``ConversionError``
    propagates and no exception text, body, or credential is persisted.
    """
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        with pytest.raises(ConversionError):
            await acquire_and_convert_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                registry=_failing_registry(),
                uow_factory=uow_factory,
                clock=lambda: _OCCURRED_AT,
            )

    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert [row[3] for row in rows] == ["started", "acquired", "decoded", "failed"]
    assert rows[-1][7] == "conversion_failed"
    assert "converted" not in [row[3] for row in rows]
    assert "completed" not in [row[3] for row in rows]
    # The bounded schema carries no exception text or raw body.
    serialized = str(rows)
    assert "deterministic local" not in serialized
    assert "asyncrat" not in serialized
    assert FIXED_KEY not in serialized
    assert await _count(integration_engine, "evidence") == 0


@pytest.mark.asyncio
async def test_i05_cancellation_real_stack_propagates(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27D-I05: cancellation records CANCELLED and propagates.

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
            acquire_and_convert_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                registry=build_threatfox_conversion_registry(),
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


@pytest.mark.asyncio
async def test_i06_minimization_no_credentials_or_bodies(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27D-I06: Auth-Key, raw body, credential URL, exception text absent.

    The full success path persists only the bounded operational log and
    returns in-memory LegacyEvidence; the Auth-Key, raw HTTP body fragments, and
    credential-bearing content never reach durable logs or LegacyEvidence.
    """
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        result, evidence = await acquire_and_convert_threatfox_execution(
            datasource=_datasource(client),
            definition=_DEFINITION,
            entity=_DOMAIN_ENTITY,
            registry=build_threatfox_conversion_registry(),
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )

    execution_id = await _only_execution(integration_engine)
    rows = await _log_rows(integration_engine, execution_id)
    assert await _count(integration_engine, "evidence") == 0

    # The durable log carries no body bytes and no credential.
    serialized = str(rows)
    assert "asyncrat" not in serialized
    assert '"ok"' not in serialized.replace(" ", "")
    assert FIXED_KEY not in serialized

    # The LegacyEvidence is credential-free and payload-free.
    assert result.error is None
    item = evidence[0]
    assert item.observation.source_url == _ENDPOINT
    assert FIXED_KEY not in str(item.observation.facts)
    assert item.observation.raw_payload is None
    assert "auth" not in item.observation.source_url.lower()

    # The bounded schema cannot represent a body or credential: no such
    # columns exist.
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
    assert await _count(integration_engine, "investigation") == 0
