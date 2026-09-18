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

Assertions cover exact per-record LegacyEvidence provenance, graph/audit rows,
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
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from agentic_threat_investigator.app.evidence_conversion import (
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
)
from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.extraction.models import (
    ExtractionResult,
)
from agentic_threat_investigator.app.investigation_timeline import (
    UnitOfWorkInvestigationTimelineSink,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
    ProviderWorkExecutor,
    UowEntityReader,
)
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceResult,
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
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    evidence_id_for_source_record,
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
    """Run one bounded scalar verification query on a fresh engine.

    The vertical slices write through the shared pool and then verify with
    the same pooled connections; a fresh engine isolates the read transaction
    so the verification deterministically observes the committed write.
    """
    engine = create_async_engine(
        integration_engine.url.render_as_string(hide_password=False),
        poolclass=NullPool,
    )
    try:
        async with engine.connect() as connection:
            return await connection.scalar(text(query), params)
    finally:
        await engine.dispose()


async def _row(
    integration_engine: AsyncEngine, query: str, **params: object
) -> tuple[Any, ...] | None:
    """Run one bounded single-row verification query on a fresh engine."""
    engine = create_async_engine(
        integration_engine.url.render_as_string(hide_password=False),
        poolclass=NullPool,
    )
    try:
        async with engine.connect() as connection:
            result = await connection.execute(text(query), params)
            fetched = result.fetchone()
    finally:
        await engine.dispose()
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

    # Exact per-record provenance on the durable global observation:
    # the stable Evidence carries type/source/record identity, the
    # EvidenceObservation carries source_url, and the Investigation scope
    # comes from the exact admission.
    row = await _row(
        integration_engine,
        "SELECT ie.investigation_id, ev.evidence_type, ev.source, "
        "ev.source_record_id, eo.source_url, eo.raw_payload, eo.id "
        "FROM ati.evidence_observation eo "
        "JOIN ati.evidence ev ON ev.id = eo.evidence_id "
        "JOIN ati.investigation_evidence ie "
        "  ON ie.evidence_observation_id = eo.id "
        "WHERE eo.id = :id",
        id=evidence_id,
    )
    assert row is not None
    assert str(row[0]) == str(investigation_id)
    assert row[1] == EvidenceType.THREAT_INTELLIGENCE.value
    assert row[2] == SourceId.THREATFOX.value
    assert row[3] == "864201"
    assert row[4] == _ENDPOINT
    assert row[5] is None
    assert str(row[6]) == str(evidence_id)

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
            "WHERE object_type = 'evidence_observation' AND object_id = :id",
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
    """D27E-P02: two per-record LegacyEvidence, one CONVERTED(count=2), one COMPLETED.

    Multiple LegacyEvidence IDs and RelationshipObservation rows are expected
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
    # historical observations (one per LegacyEvidence).
    assert (
        await _count(
            integration_engine,
            "relationship",
            "relationship_type_urn = 'urn:ati:relationship:threat:associated_with'",
        )
        == 1
    )
    assert await _count(integration_engine, "relationship_observation") == 2
    # Exactly one CONVERTED reporting the total LegacyEvidence count and one
    # COMPLETED — never multiplied per LegacyEvidence.
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


class _ForeignSourceConverter(ToEvidenceConverter[Any]):
    """Converter emitting global Evidence claiming a different source URN."""

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Claim the ThreatFox semantic format."""
        return SemanticFormatId.THREATFOX

    def convert(
        self,
        source: Any,
        context: EvidenceConversionContext,
    ) -> tuple[ConvertedEvidence, ...]:
        """Return one ConvertedEvidence whose Evidence source mismatches the work item.

        PR 28A: conversion is global, so a converter can no longer mis-bind
        an Investigation or subject (the adapter always binds the executor's
        own investigation and subject); the remaining converter binding
        surface is the emitted Evidence's ``source``.
        """
        del source
        evidence_id = evidence_id_for_source_record(
            SemanticFormatId.THREATFOX,
            context.semantic_source.source_id,
            "864201",
        )
        return (
            ConvertedEvidence(
                evidence=Evidence(
                    id=evidence_id,
                    type=EvidenceType.THREAT_INTELLIGENCE,
                    source=SourceId.URLHAUS.value,
                    source_record_id="864201",
                ),
                observation=EvidenceObservationCandidate(
                    evidence_id=evidence_id,
                    source_url=context.semantic_source.source_reference,
                    retrieved_at=context.semantic_source.retrieved_at,
                    facts={"matches": [{"threatfox_id": "864201"}]},
                    raw_payload=None,
                ),
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
    ) -> tuple[ConvertedEvidence, ...]:
        """Convert then empty the second record's match facts."""
        converted = self._inner.convert(source, context)
        if source.id != "864201":
            return tuple(
                item.model_copy(
                    update={
                        "observation": item.observation.model_copy(
                            update={"facts": {"matches": []}}
                        )
                    }
                )
                for item in converted
            )
        return converted


class _FailingSecondPersistenceService(ProviderObservationPersistenceService):
    """Real persistence service failing deterministically on the second call.

    Injects a bounded persistence failure for the second item of one
    execution so the real atomic persistence boundary is still exercised for
    the first item; mirrors the unit-level probe seam at the runtime slice.
    """

    def __init__(self, uow_factory: Callable[[], PostgresUnitOfWork]) -> None:
        """Bind the real service and reset the call counter."""
        super().__init__(uow_factory)
        self.calls = 0

    async def persist(
        self,
        converted: ConvertedEvidence,
        invocation_entity: Entity,
        extraction: ExtractionResult,
        *,
        investigation_id: UUID,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> ProviderObservationPersistenceResult:
        """Fail the second call, then delegate to the real atomic service."""
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError("injected deterministic persistence failure")
        return await super().persist(
            converted,
            invocation_entity,
            extraction,
            investigation_id=investigation_id,
            actor_id=actor_id,
            request_id=request_id,
        )


@pytest.mark.asyncio
async def test_p04_wrong_source_binding_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P04: a converter source mismatch is rejected with no writes.

    PR 28A: conversion is global, so a converter can no longer mis-bind an
    Investigation or subject (the adapter binds the executor's own
    investigation and subject). The remaining binding surface is the emitted
    global Evidence's ``source``; a mismatch fails the execution with the
    bounded binding code and persists nothing.
    """
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    registry = ToEvidenceConverterRegistry(converters=(_ForeignSourceConverter(),))
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
async def test_p06_second_persistence_failure_preserves_first_commit(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-P06: E1 commits, E2 persists nothing, datasource FAILED.

    PR 28A: the v0.1 runtime assigns fresh per-observation Evidence IDs via
    the adapter (the deterministic global identity is authoritative on the
    domain model only), so a durable replay conflict cannot be pre-seeded
    through the converter anymore. A probe persistence seam fails the second
    item deterministically; the first item stays durably committed and the
    execution terminates FAILED with ``persistence_failed`` without
    compensation.
    """
    investigation_id, root = await _seed_investigation(uow_factory)
    assert root.id is not None
    payload = threatfox_search_response(
        asyncrat_domain_record(),
        asyncrat_domain_record(id="864299", last_seen=None),
    )
    async with _client(lambda _: _json_response(payload)) as client:
        provider = _provider(client, uow_factory)
        executor = ProviderWorkExecutor(
            entity_reader=UowEntityReader(uow_factory),
            provider_registry={SourceId.THREATFOX: provider},
            extractor=extract,
            persistence_service=_FailingSecondPersistenceService(uow_factory),
            timeline_service=UnitOfWorkInvestigationTimelineSink(uow_factory),
            context=ProviderExecutionContext(
                investigation_id=investigation_id, clock=lambda: _OCCURRED_AT
            ),
        )
        outcome = await executor.execute(
            ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=root.id, depth=0)
        )

    assert outcome.status is ProviderExecutionStatus.FAILED
    assert len(outcome.evidence_ids) == 1
    # E1 (the first record's Evidence) remains durably committed; E2 never
    # reached the atomic persistence boundary.
    assert await _count(integration_engine, "evidence") == 1
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
