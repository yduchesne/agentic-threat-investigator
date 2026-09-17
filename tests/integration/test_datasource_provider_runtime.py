# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27E real-PostgreSQL vertical slices for the datasource-backed runtime.

Matrix IDs D27E-P01..P09 run the migrated ThreatFox runtime end to end over
real isolation PostgreSQL:

    persisted Investigation + Entity
      -> real ProviderWorkExecutor
      -> migrated datasource-backed ThreatFox provider
      -> MockTransport only at the external Internet boundary
      -> real ProviderHttpClient
      -> real ThreatFoxDatasource / semantic parser / converter registry
      -> real extractor
      -> real ProviderObservationPersistenceService
      -> real PostgresUnitOfWork / stored functions

Assertions cover exact per-record Evidence provenance, graph/audit rows,
execution lifecycle (one STARTED, exactly one terminal, stable
execution/datasource identity), SUCCEEDED/FAILED/CANCELLED outcomes,
cross-Investigation and subject binding fail-closed behavior, later-item
persistence failure preserving earlier commits, and extraction failure
with no persistence for the failed item. Only the external ThreatFox
endpoint is faked; ATI acquisition, conversion, extraction, persistence,
recorder, UnitOfWork, and PostgreSQL are all real.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.evidence_conversion import (
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
)
from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.investigation_timeline import (
    UnitOfWorkInvestigationTimelineSink,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
    ProviderWorkExecutor,
    UowEntityReader,
)
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceService,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    ProviderExecutionStatus,
    ProviderWorkItem,
    default_investigation_budget,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox import (
    ThreatFoxDatasource,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    ThreatFoxToEvidenceConverter,
    build_threatfox_datasource_provider,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
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
    CANONICAL_ASYNCRAT_MALWARE,
    FIXED_KEY,
    asyncrat_domain_record,
    threatfox_search_response,
)

pytestmark = pytest.mark.integration

_OCCURRED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)
_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"
_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)


def _json_response(payload: object, *, status: int = 200) -> httpx.Response:
    """Build one deterministic JSON response."""
    return httpx.Response(
        status,
        content=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def _client(handler: Callable[[httpx.Request], Any]) -> httpx.AsyncClient:
    """Build a real ``httpx`` mock-transport client for the local fixture."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _provider(
    client: httpx.AsyncClient,
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    registry: ToEvidenceConverterRegistry | None = None,
) -> Any:
    """Build the migrated datasource-backed provider over the real stack."""
    datasource = ThreatFoxDatasource(
        ProviderHttpClient(
            client=client,
            policy=ProviderHttpPolicy(max_retries=0, base_delay_seconds=0.01),
            sleep=no_op_sleep,
            jitter_fn=zero_jitter,
        ),
        auth_key=FIXED_KEY,
        clock=lambda: _OCCURRED_AT,
    )
    return build_threatfox_datasource_provider(
        definition=_DEFINITION,
        datasource=datasource,
        uow_factory=uow_factory,
        clock=lambda: _OCCURRED_AT,
        registry=registry,
    )


async def _seed_investigation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> tuple[UUID, Entity]:
    """Persist one RUNNING investigation rooted at the canonical domain."""
    investigation_id = uuid4()
    root_id = uuid4()
    root = Entity(id=root_id, type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN)
    async with uow_factory() as uow:
        root = await uow.entities.upsert(root)
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[root_id],
                objective="Assess the root indicator.",
                budget=default_investigation_budget(),
                started_at=_OCCURRED_AT,
            )
        )
        await uow.commit()
    assert root.id is not None
    return investigation_id, root


async def _executor(
    uow_factory: Callable[[], PostgresUnitOfWork],
    provider: Any,
    investigation_id: UUID,
) -> ProviderWorkExecutor:
    """Compose the production executor over the real seams."""
    return ProviderWorkExecutor(
        entity_reader=UowEntityReader(uow_factory),
        provider_registry={SourceId.THREATFOX: provider},
        extractor=extract,
        persistence_service=ProviderObservationPersistenceService(uow_factory),
        timeline_service=UnitOfWorkInvestigationTimelineSink(uow_factory),
        context=ProviderExecutionContext(
            investigation_id=investigation_id, clock=lambda: _OCCURRED_AT
        ),
    )


async def _log_rows(
    integration_engine: AsyncEngine, execution_id: UUID
) -> list[tuple[Any, ...]]:
    """Return the durable log rows of one execution in append order."""
    async with integration_engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT id, execution_id, datasource_id, event_type, item_count, "
                "byte_count, error_code FROM ati.datasource_log "
                "WHERE execution_id = :execution_id ORDER BY id ASC"
            ),
            {"execution_id": execution_id},
        )
        return [tuple(row) for row in result.fetchall()]


async def _scalar(integration_engine: AsyncEngine, query: str, **params: object) -> Any:
    """Run one bounded scalar verification query."""
    async with integration_engine.connect() as connection:
        return await connection.scalar(text(query), params)


async def _row(
    integration_engine: AsyncEngine, query: str, **params: object
) -> tuple[Any, ...] | None:
    """Run one bounded single-row verification query."""
    async with integration_engine.connect() as connection:
        result = await connection.execute(text(query), params)
        fetched = result.fetchone()
    return None if fetched is None else tuple(fetched)


async def _count(
    integration_engine: AsyncEngine, table: str, where: str = "TRUE"
) -> int:
    """Count one table with an optional deterministic filter."""
    value = await _scalar(
        integration_engine, f"SELECT count(*) FROM ati.{table} WHERE {where}"
    )
    return int(value or 0)


@pytest.mark.asyncio
async def test_p01_one_record_persisted_vertical_slice(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P01: one record persists exact provenance, graph, audit, lifecycle."""
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        provider = _provider(client, uow_factory)
        executor = await _executor(uow_factory, provider, investigation_id)
        outcome = await executor.execute(
            ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=root.id, depth=0)
        )

    assert outcome.status is ProviderExecutionStatus.SUCCEEDED
    assert len(outcome.evidence_ids) == 1
    evidence_id = outcome.evidence_ids[0]

    # Exact per-record provenance on the durable Evidence row.
    row = await _row(
        integration_engine,
        "SELECT investigation_id, evidence_type, subject_entity_id, source, "
        "source_record_id, source_url, raw_payload FROM ati.evidence WHERE id=:id",
        id=evidence_id,
    )
    assert row is not None
    assert str(row[0]) == str(investigation_id)
    assert row[1] == EvidenceType.THREAT_INTELLIGENCE.value
    assert str(row[2]) == str(root.id)
    assert row[3] == SourceId.THREATFOX.value
    assert row[4] == "864201"
    assert row[5] == _ENDPOINT
    assert row[6] is None

    # The canonical graph: one MALWARE entity and one ASSOCIATED_WITH edge
    # with one historical observation.
    assert (
        await _count(
            integration_engine,
            "entity",
            f"entity_type='malware' AND canonical_value='{CANONICAL_ASYNCRAT_MALWARE}'",
        )
        == 1
    )
    assert (
        await _count(
            integration_engine,
            "relationship",
            "relationship_type_urn = 'urn:ati:relationship:threat:associated_with'",
        )
        == 1
    )
    assert await _count(integration_engine, "relationship_observation") == 1
    assert (
        await _scalar(
            integration_engine,
            "SELECT count(*) FROM ati.audit_event "
            "WHERE object_type = 'evidence' AND object_id = :id",
            id=evidence_id,
        )
        == 1
    )

    # Lifecycle: STARTED -> ACQUIRED -> DECODED -> CONVERTED(1) -> COMPLETED
    # under exactly one execution/datasource identity.
    execution_id = await _scalar(
        integration_engine,
        "SELECT DISTINCT execution_id FROM ati.datasource_log",
    )
    rows = await _log_rows(integration_engine, UUID(str(execution_id)))
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "completed",
    ]
    assert rows[3][4] == 1
    assert {row[2] for row in rows} == {"threatfox-live"}


@pytest.mark.asyncio
async def test_p02_two_records_two_evidence_and_graph_semantics(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P02: two per-record Evidence, one CONVERTED(count=2), one COMPLETED.

    Multiple Evidence IDs and RelationshipObservation rows are expected
    because provenance is now per record; graph semantics stay canonical.
    """
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    payload = threatfox_search_response(
        asyncrat_domain_record(),
        asyncrat_domain_record(id="864299", last_seen=None),
    )
    async with _client(lambda _: _json_response(payload)) as client:
        provider = _provider(client, uow_factory)
        executor = await _executor(uow_factory, provider, investigation_id)
        outcome = await executor.execute(
            ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=root.id, depth=0)
        )

    assert outcome.status is ProviderExecutionStatus.SUCCEEDED
    assert len(outcome.evidence_ids) == 2
    records = await _scalar(
        integration_engine,
        "SELECT array_agg(source_record_id ORDER BY source_record_id) FROM ati.evidence "
        "WHERE source = :source",
        source=SourceId.THREATFOX.value,
    )
    assert list(records) == ["864201", "864299"]
    # Deterministic per-record graph semantics: one shared edge, two
    # historical observations (one per Evidence).
    assert (
        await _count(
            integration_engine,
            "relationship",
            "relationship_type_urn = 'urn:ati:relationship:threat:associated_with'",
        )
        == 1
    )
    assert await _count(integration_engine, "relationship_observation") == 2
    # Exactly one CONVERTED reporting the total Evidence count and one
    # COMPLETED — never multiplied per Evidence.
    execution_id = await _scalar(
        integration_engine,
        "SELECT DISTINCT execution_id FROM ati.datasource_log",
    )
    rows = await _log_rows(integration_engine, UUID(str(execution_id)))
    converted = [row for row in rows if row[3] == "converted"]
    assert len(converted) == 1
    assert converted[0][4] == 2
    assert [row[3] for row in rows].count("completed") == 1


@pytest.mark.asyncio
async def test_p03_no_result_converted_zero_completed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P03: a valid no-result persists nothing and still COMPLETES."""
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    async with _client(
        lambda _: _json_response({"query_status": "no_result"})
    ) as client:
        provider = _provider(client, uow_factory)
        executor = await _executor(uow_factory, provider, investigation_id)
        outcome = await executor.execute(
            ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=root.id, depth=0)
        )

    assert outcome.status is ProviderExecutionStatus.SUCCEEDED
    assert outcome.evidence_ids == ()
    assert await _count(integration_engine, "evidence") == 0
    execution_id = await _scalar(
        integration_engine,
        "SELECT DISTINCT execution_id FROM ati.datasource_log",
    )
    rows = await _log_rows(integration_engine, UUID(str(execution_id)))
    assert [row[3] for row in rows] == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "completed",
    ]
    assert [row for row in rows if row[3] == "converted"][0][4] == 0


class _ForeignInvestigationConverter(ToEvidenceConverter[Any]):
    """Converter mis-binding Evidence to a foreign investigation."""

    def __init__(self, foreign_investigation_id: UUID) -> None:
        """Bind the mis-targeted investigation identity."""
        self._foreign = foreign_investigation_id

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Claim the ThreatFox semantic format."""
        return SemanticFormatId.THREATFOX

    def convert(
        self,
        source: Any,
        context: EvidenceConversionContext,
    ) -> tuple[Evidence, ...]:
        """Return one Evidence bound to the foreign investigation."""
        del source
        return (
            Evidence(
                investigation_id=self._foreign,
                type=EvidenceType.THREAT_INTELLIGENCE,
                subject=context.subject,
                source=context.semantic_source.source_id.value,
                source_record_id="864201",
                retrieved_at=context.semantic_source.retrieved_at,
                facts={"matches": [{"threatfox_id": "864201"}]},
                raw_payload=None,
            ),
        )


class _WrongSubjectConverter(ToEvidenceConverter[Any]):
    """Converter substituting a different canonical subject."""

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Claim the ThreatFox semantic format."""
        return SemanticFormatId.THREATFOX

    def convert(
        self,
        source: Any,
        context: EvidenceConversionContext,
    ) -> tuple[Evidence, ...]:
        """Return one Evidence whose subject is not the persisted target."""
        del source
        return (
            Evidence(
                investigation_id=context.investigation_id,
                type=EvidenceType.THREAT_INTELLIGENCE,
                subject=EntityRef(
                    id=context.subject.id,
                    type=context.subject.type,
                    value="substituted.test",
                ),
                source=context.semantic_source.source_id.value,
                source_record_id="864201",
                retrieved_at=context.semantic_source.retrieved_at,
                facts={"matches": [{"threatfox_id": "864201"}]},
                raw_payload=None,
            ),
        )


class _ExtractionFailureConverter(ToEvidenceConverter[Any]):
    """Converter that strips matches from the second semantic record."""

    def __init__(self, inner: ThreatFoxToEvidenceConverter) -> None:
        """Wrap the real converter."""
        self._inner = inner

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Claim the ThreatFox semantic format."""
        return SemanticFormatId.THREATFOX

    def convert(
        self,
        source: ThreatFoxRecord,
        context: EvidenceConversionContext,
    ) -> tuple[Evidence, ...]:
        """Convert then empty the second record's match facts."""
        converted = self._inner.convert(source, context)
        if source.id != "864201":
            return tuple(
                item.model_copy(update={"facts": {"matches": []}}) for item in converted
            )
        return converted


@pytest.mark.asyncio
async def test_p04_cross_investigation_binding_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P04: cross-Investigation Evidence is rejected with no writes."""
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    foreign = uuid4()
    registry = ToEvidenceConverterRegistry(
        converters=(_ForeignInvestigationConverter(foreign),)
    )
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        provider = _provider(client, uow_factory, registry=registry)
        executor = await _executor(uow_factory, provider, investigation_id)
        outcome = await executor.execute(
            ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=root.id, depth=0)
        )

    assert outcome.status is ProviderExecutionStatus.FAILED
    assert outcome.evidence_ids == ()
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "relationship_observation") == 0
    execution_id = await _scalar(
        integration_engine,
        "SELECT DISTINCT execution_id FROM ati.datasource_log",
    )
    rows = await _log_rows(integration_engine, UUID(str(execution_id)))
    assert rows[-1][3] == "failed"
    assert rows[-1][6] == "provider_binding_failed"
    assert "completed" not in [row[3] for row in rows]


@pytest.mark.asyncio
async def test_p05_subject_binding_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P05: a substituted subject is rejected before persistence."""
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    registry = ToEvidenceConverterRegistry(converters=(_WrongSubjectConverter(),))
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        provider = _provider(client, uow_factory, registry=registry)
        executor = await _executor(uow_factory, provider, investigation_id)
        outcome = await executor.execute(
            ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=root.id, depth=0)
        )

    assert outcome.status is ProviderExecutionStatus.FAILED
    assert outcome.evidence_ids == ()
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "relationship_observation") == 0
    execution_id = await _scalar(
        integration_engine,
        "SELECT DISTINCT execution_id FROM ati.datasource_log",
    )
    rows = await _log_rows(integration_engine, UUID(str(execution_id)))
    assert rows[-1][3] == "failed"
    assert rows[-1][6] == "provider_binding_failed"


class _FixedSecondEvidenceIdConverter(ThreatFoxToEvidenceConverter):
    """The real converter assigning one collision-bound Evidence ID."""

    def __init__(self, second_evidence_id: UUID) -> None:
        """Bind the pre-inserted Evidence identity of the second record."""
        self._second_id = second_evidence_id

    def convert(
        self,
        source: ThreatFoxRecord,
        context: EvidenceConversionContext,
    ) -> tuple[Evidence, ...]:
        """Convert normally, then pin the second record's Evidence identity."""
        converted = super().convert(source, context)
        if source.id == "864299":
            return tuple(
                item.model_copy(update={"id": self._second_id}) for item in converted
            )
        return converted


@pytest.mark.asyncio
async def test_p06_second_persistence_failure_preserves_first_commit(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P06: E1 commits, E2 rolls back, datasource FAILED, no compensation.

    The second Evidence identity is pre-inserted as a durable replay
    conflict; the observation transaction for E2 rolls back atomically
    while E1 (the same execution's earlier Evidence) stays durable.
    """
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    second_id = uuid4()
    # A pre-existing immutable Evidence row with the collision identity.
    async with uow_factory() as uow:
        await uow.evidence.insert(
            Evidence(
                id=second_id,
                investigation_id=investigation_id,
                type=EvidenceType.THREAT_INTELLIGENCE,
                subject=EntityRef(
                    id=root.id, type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN
                ),
                source=SourceId.THREATFOX.value,
                source_record_id="pre-seeded",
                retrieved_at=_OCCURRED_AT,
            ),
            actor_id=None,
            request_id=None,
        )
        await uow.commit()

    registry = ToEvidenceConverterRegistry(
        converters=(_FixedSecondEvidenceIdConverter(second_id),)
    )
    payload = threatfox_search_response(
        asyncrat_domain_record(),
        asyncrat_domain_record(id="864299", last_seen=None),
    )
    async with _client(lambda _: _json_response(payload)) as client:
        provider = _provider(client, uow_factory, registry=registry)
        executor = await _executor(uow_factory, provider, investigation_id)
        outcome = await executor.execute(
            ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=root.id, depth=0)
        )

    assert outcome.status is ProviderExecutionStatus.FAILED
    assert len(outcome.evidence_ids) == 1
    # E1 (the first record's Evidence) remains committed; only E2 rolled back.
    assert await _count(integration_engine, "evidence") == 2  # pre-seeded + E1
    assert outcome.evidence_ids[0] != second_id
    execution_id = await _scalar(
        integration_engine,
        "SELECT DISTINCT execution_id FROM ati.datasource_log",
    )
    rows = await _log_rows(integration_engine, UUID(str(execution_id)))
    assert rows[-1][3] == "failed"
    assert rows[-1][6] == "persistence_failed"
    assert "completed" not in [row[3] for row in rows]


@pytest.mark.asyncio
async def test_p07_extraction_failure_no_persistence_for_failed_item(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P07: extraction failure persists nothing for the failed item."""
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    registry = ToEvidenceConverterRegistry(
        converters=(_ExtractionFailureConverter(ThreatFoxToEvidenceConverter()),)
    )
    payload = threatfox_search_response(
        asyncrat_domain_record(),
        asyncrat_domain_record(id="864299", last_seen=None),
    )
    async with _client(lambda _: _json_response(payload)) as client:
        provider = _provider(client, uow_factory, registry=registry)
        executor = await _executor(uow_factory, provider, investigation_id)
        outcome = await executor.execute(
            ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=root.id, depth=0)
        )

    assert outcome.status is ProviderExecutionStatus.FAILED
    assert len(outcome.evidence_ids) == 1
    assert await _count(integration_engine, "evidence") == 1
    execution_id = await _scalar(
        integration_engine,
        "SELECT DISTINCT execution_id FROM ati.datasource_log",
    )
    rows = await _log_rows(integration_engine, UUID(str(execution_id)))
    assert rows[-1][3] == "failed"
    assert rows[-1][6] == "extraction_failed"
    assert "completed" not in [row[3] for row in rows]


@pytest.mark.asyncio
async def test_p08_acquisition_cancellation_cancelled_and_propagates(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P08: acquisition cancellation records CANCELLED and propagates."""
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    entered = asyncio.Event()
    never = asyncio.Event()

    async def handler(_: httpx.Request) -> httpx.Response:
        """Block the transport until cancelled."""
        entered.set()
        await never.wait()
        return _json_response({})

    async with _client(handler) as client:
        provider = _provider(client, uow_factory)
        executor = await _executor(uow_factory, provider, investigation_id)
        task = asyncio.create_task(
            executor.execute(
                ProviderWorkItem(
                    provider=SourceId.THREATFOX, entity_id=root.id, depth=0
                )
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert await _count(integration_engine, "evidence") == 0
    execution_id = await _scalar(
        integration_engine,
        "SELECT DISTINCT execution_id FROM ati.datasource_log",
    )
    rows = await _log_rows(integration_engine, UUID(str(execution_id)))
    assert [row[3] for row in rows] == ["started", "cancelled"]
    assert all(row[6] is None for row in rows)
    assert not any(row[3] in ("failed", "completed") for row in rows)


@pytest.mark.asyncio
async def test_p09_lifecycle_database_invariants(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P09: one STARTED, one terminal, stable identity, no append.

    The durable datasource_log owns the lifecycle invariants: exactly one
    STARTED per execution, exactly one terminal, one execution/datasource
    identity, and no event after the terminal (database-enforced).
    """
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    async with _client(
        lambda _: _json_response(threatfox_search_response(asyncrat_domain_record()))
    ) as client:
        provider = _provider(client, uow_factory)
        executor = await _executor(uow_factory, provider, investigation_id)
        outcome = await executor.execute(
            ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=root.id, depth=0)
        )
    assert outcome.status is ProviderExecutionStatus.SUCCEEDED

    execution_id_value = await _scalar(
        integration_engine,
        "SELECT DISTINCT execution_id FROM ati.datasource_log",
    )
    execution_id = UUID(str(execution_id_value))
    started = await _count(
        integration_engine,
        "datasource_log",
        f"execution_id = '{execution_id}' AND event_type = 'started'",
    )
    terminal = await _count(
        integration_engine,
        "datasource_log",
        f"execution_id = '{execution_id}' "
        "AND event_type IN ('completed', 'failed', 'cancelled')",
    )
    assert started == 1
    assert terminal == 1
    assert (
        await _scalar(
            integration_engine,
            "SELECT count(DISTINCT execution_id) FROM ati.datasource_log",
        )
        == 1
    )
    assert (
        await _scalar(
            integration_engine,
            "SELECT count(DISTINCT datasource_id) FROM ati.datasource_log "
            "WHERE execution_id = :execution_id",
            execution_id=execution_id,
        )
        == 1
    )
    # The database owns the lifecycle backstop: an append after the
    # terminal outcome is rejected through the versioned stored function.
    from agentic_threat_investigator.app.persistence.repositories import (
        DatasourceLogAppendAfterTerminalError,
    )
    from agentic_threat_investigator.domain.datasource import (
        DatasourceExecutionEventType,
        DatasourceId,
        DatasourceLogEvent,
    )

    stale_event = DatasourceLogEvent(
        execution_id=execution_id,
        datasource_id=DatasourceId("threatfox-live"),
        event_type=DatasourceExecutionEventType.CONVERTED,
        occurred_at=_OCCURRED_AT,
        item_count=1,
    )
    with pytest.raises(DatasourceLogAppendAfterTerminalError):
        async with uow_factory() as uow:
            await uow.datasource_logs.append(stale_event)

    assert (
        await _count(
            integration_engine,
            "datasource_log",
            f"execution_id = '{execution_id}'",
        )
        == 5
    )
