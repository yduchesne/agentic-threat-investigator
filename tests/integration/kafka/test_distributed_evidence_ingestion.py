# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 28H real-stack distributed Evidence ingestion closure (H28H matrix).

The canonical v0.2 vertical slice runs every layer through its production
implementation:

```text
deterministic ThreatFox-format fixture
 -> real ProviderHttpClient boundary (httpx.MockTransport only, no Internet)
 -> real ThreatFoxDatasource semantic acquirer + parser
 -> real ThreatFoxToEvidenceConverter (build_threatfox_conversion_registry)
 -> DatasourceEvidenceProducer
 -> EvidenceMessage V1 (PR 28C codec)
 -> KafkaEvidencePublisher -> real Redpanda
 -> KafkaEvidenceConsumer
 -> EvidencePersistenceConsumer
 -> EvidenceBatchPersistenceService -> real PostgreSQL
```

Only the external Internet endpoint is faked; ATI's acquisition, conversion,
message, publisher, durable log, consumer, batch persistence, PostgreSQL,
and lifecycle architecture are all real.

Coverage (H28H-01..21):
- temporal semantics: fresh A, later A-equivalent (UNCHANGED, not replay),
  A->B, A->B->C, A->B->A (distinct message appends v3), one atomic
  multi-Evidence batch;
- replay/idempotency: exact-message replay is a receipt no-op; same semantic
  state with a new datasource execution is a new receipt with unchanged EO
  history;
- failure/recovery: failure before PG commit, PG-commit-then-Kafka-commit-
  absent, poll-then-stop, atomic multi-record rollback, committed restart;
- producer lifecycle: COMPLETED without a consumer, publication failure,
  post-terminal append rejection;
- provenance: exact EvidenceObservationEntity and RelationshipObservation
  references;
- Investigation reproducibility: explicit, observation-exact admission.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.datasource_evidence_producer import (
    DatasourceEvidenceProducer,
    DatasourceProducerOutcome,
)
from agentic_threat_investigator.app.evidence_batch_persistence import (
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_consumer import (
    EvidenceConsumerRunResult,
    EvidencePersistenceConsumer,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceBatch,
    EvidenceCommitError,
    EvidenceConsumer,
    EvidenceConsumerId,
    EvidencePublisher,
    EvidencePublishError,
    EvidencePublishResult,
)
from agentic_threat_investigator.app.evidence_message import EvidenceMessage
from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceLogAppendAfterTerminalError,
    EvidenceBatchPersistenceResult,
    PreparedEvidenceBatch,
    SoftDeletedIdentityError,
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
from agentic_threat_investigator.domain.evidence import (
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox import (
    ThreatFoxDatasource,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    build_threatfox_conversion_registry,
)
from agentic_threat_investigator.infrastructure.kafka.evidence_log import (
    KafkaEvidenceConsumer,
    KafkaEvidencePublisher,
    build_kafka_consumer,
    build_kafka_publisher,
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
_POLL_TIME_MS = 2000
_PUB_CLIENT = "h28-publisher"
_CON_CLIENT = "h28-consumer"

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)
_DOMAIN_ENTITY = Entity(type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN)

_RECORD_ID = "864201"
"""Stable upstream source record identity of the canonical fixture scenario."""

_MALWARE_A = "win.asyncrat"
_MALWARE_B = "agent.tesla"
_MALWARE_C = "redline.stealer"


def _state(malware: str = _MALWARE_A) -> dict[str, Any]:
    """Build the canonical ThreatFox fixture state of one stable record.

    One stable source record (``_RECORD_ID``) whose only material variation
    is the machine malware identifier (inside normalized facts); timestamps,
    IOC, source, and identity stay fixed so the material-state comparison
    isolates exactly the intended change.
    """
    return threatfox_search_response(
        asyncrat_domain_record(id=_RECORD_ID, malware=malware)
    )


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


def _publisher(bootstrap: str, topic: str) -> KafkaEvidencePublisher:
    """Build a production KafkaEvidencePublisher over the real broker."""
    return build_kafka_publisher(
        bootstrap_servers=(bootstrap,),
        topic=topic,
        client_id=_PUB_CLIENT,
    )


def _consumer(bootstrap: str, topic: str, group: str) -> KafkaEvidenceConsumer:
    """Build a production KafkaEvidenceConsumer with an isolated group."""
    return build_kafka_consumer(
        bootstrap_servers=(bootstrap,),
        topic=topic,
        consumer_id=EvidenceConsumerId(group),
        client_id=f"{_CON_CLIENT}-{uuid4().hex[:6]}",
        poll_timeout_ms=_POLL_TIME_MS,
    )


def _new_group() -> str:
    """Return a fresh deterministic consumer group identity for this test."""
    return f"h28-{uuid4().hex[:12]}"


async def _produce_once(
    bootstrap: str,
    topic: str,
    uow_factory: Callable[[], PostgresUnitOfWork],
    payload: dict[str, Any],
) -> tuple[DatasourceProducerOutcome, UUID | None, int]:
    """Run one full real producer execution (acquire..publish..complete)."""
    publisher = _publisher(bootstrap, topic)
    await publisher.start()
    try:
        async with _client(lambda _: _json_response(payload)) as client:
            producer = DatasourceEvidenceProducer(
                definition=_DEFINITION,
                acquirer=_datasource(client),
                registry=build_threatfox_conversion_registry(),
                publisher=publisher,
                uow_factory=uow_factory,
                clock=lambda: _OCCURRED_AT,
            )
            result = await producer.produce(_DOMAIN_ENTITY)
    finally:
        await publisher.stop()
    return result.outcome, result.execution_id, result.published_count


async def _produce_lifecycle(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
    *,
    bootstrap: str,
    topic: str,
    malware: str = _MALWARE_A,
) -> tuple[UUID, int]:
    """Run one real producer execution and assert its full lifecycle.

    Returns ``(execution_id, published_count)`` after asserting the exact
    ``STARTED, ACQUIRED, DECODED, CONVERTED, PUBLISHED, COMPLETED`` durable
    lifecycle recorded through the real PostgreSQL ``datasource_log`` API.
    """
    outcome, execution_id, published = await _produce_once(
        bootstrap, topic, uow_factory, _state(malware)
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert execution_id is not None
    assert published == 1
    assert await _lifecycle(integration_engine, execution_id) == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    return execution_id, published


class _CommitFailingConsumer(EvidenceConsumer):
    """Narrow seam: delegates real poll, fails the configured commits.

    ``fail_calls`` commit failures are raised as :class:`EvidenceCommitError`
    before any delegate commit; later commits pass through. Used to prove
    the PG-commit-before-Kafka-commit window without production chaos hooks.
    """

    def __init__(self, inner: EvidenceConsumer, *, fail_calls: int = 1) -> None:
        """Bind the seam to the real consumer and the failure count."""
        self._inner = inner
        self._fail_calls = fail_calls

    async def poll(self, max_messages: int) -> EvidenceBatch:
        """Delegate the poll to the real consumer."""
        return await self._inner.poll(max_messages)

    async def commit(self, batch: EvidenceBatch) -> None:
        """Fail the next ``fail_calls`` commits, then delegate."""
        if self._fail_calls > 0:
            self._fail_calls -= 1
            raise EvidenceCommitError("injected broker commit failure")
        await self._inner.commit(batch)


class _FailBeforeCommitPersistence(EvidenceBatchPersistenceService):
    """Narrow seam: one persistence call fails before the transaction opens.

    The first ``persist`` call raises a deterministic runtime failure
    without touching PostgreSQL; later calls delegate to the real service,
    so a retry exercises genuine PR 28E PostgreSQL persistence.
    """

    def __init__(self, uow_factory: Callable[[], PostgresUnitOfWork]) -> None:
        """Initialize one inner real service instance with the armed fault."""
        super().__init__(uow_factory)
        self._inner = EvidenceBatchPersistenceService(uow_factory)
        self._arm_next = True

    async def persist(
        self, prepared: PreparedEvidenceBatch
    ) -> EvidenceBatchPersistenceResult:
        """Fail the first call, then delegate to the real service."""
        if self._arm_next:
            self._arm_next = False
            raise RuntimeError("injected failure before PostgreSQL commit")
        return await self._inner.persist(prepared)


async def _consume_until_processed(
    bootstrap: str,
    topic: str,
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    group: str,
    batch_size: int = 10,
    attempts: int = 8,
    consumer_wrapper: Callable[[EvidenceConsumer], EvidenceConsumer] | None = None,
) -> EvidenceConsumerRunResult:
    """Run one real consumer until a batch is processed and committed.

    A fresh consumer group needs a bounded amount of course time for
    assignment; the adapter's own poll already blocks up to its configured
    timeout, so a few retries suffice on a healthy local broker. Empty polls
    open no transaction and commit nothing (documented empty-run result).
    """
    consumer = _consumer(bootstrap, topic, group)
    await consumer.start()
    bound: EvidenceConsumer = (
        consumer_wrapper(consumer) if consumer_wrapper is not None else consumer
    )
    service = EvidenceBatchPersistenceService(uow_factory)
    persistence = EvidencePersistenceConsumer(
        consumer=bound, persistence=service, batch_size=batch_size
    )
    result: EvidenceConsumerRunResult = EvidenceConsumerRunResult(
        polled_count=0,
        persisted_count=0,
        created_count=0,
        unchanged_count=0,
        appended_count=0,
        committed=False,
    )
    try:
        for _ in range(attempts):
            result = await persistence.process_next_batch()
            if result.committed:
                return result
        return result
    finally:
        await consumer.stop()


async def _count(engine: AsyncEngine, table: str) -> int:
    """Return the row count of one ati table."""
    async with engine.connect() as connection:
        count = await connection.scalar(text(f"SELECT count(*) FROM ati.{table}"))
    return int(count or 0)


async def _observations(
    engine: AsyncEngine,
) -> list[tuple[int, str, UUID, bool]]:
    """Return bounded (version, id, evidence_id, diff-present) observation rows."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT o.version, o.id::text, o.evidence_id, "
                "o.diff IS NOT NULL AS has_diff "
                "FROM ati.evidence_observation o ORDER BY o.version"
            )
        )
        return [
            (row[0], row[1], UUID(str(row[2])), bool(row[3]))
            for row in result.fetchall()
        ]


async def _evidence_ids(engine: AsyncEngine) -> set[UUID]:
    """Return the distinct global Evidence ids."""
    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT id::text FROM ati.evidence"))
    return {UUID(str(row[0])) for row in result.fetchall()}


async def _receipt_ids(engine: AsyncEngine) -> set[UUID]:
    """Return every receipt message_id."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text("SELECT message_id FROM ati.evidence_message_receipt")
        )
    return {row[0] for row in result.fetchall()}


async def _ro_rows(engine: AsyncEngine) -> list[tuple[UUID, UUID]]:
    """Return ordered (relationship_id, evidence_observation_id) RO rows."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT relationship_id, evidence_observation_id "
                "FROM ati.relationship_observation ORDER BY evidence_observation_id"
            )
        )
    return [(row[0], row[1]) for row in result.fetchall()]


async def _eoe_observation_entities(
    engine: AsyncEngine,
) -> dict[UUID, set[str]]:
    """Return map observation_id -> associated entity values."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT e.evidence_observation_id, ent.canonical_value "
                "FROM ati.evidence_observation_entity e "
                "JOIN ati.entity ent ON ent.id = e.entity_id"
            )
        )
    grouped: dict[UUID, set[str]] = {}
    for observation_id, value in result.fetchall():
        grouped.setdefault(observation_id, set()).add(value)
    return grouped


async def _lifecycle(engine: AsyncEngine, execution_id: UUID) -> list[str]:
    """Return the durable lifecycle event types of one execution, in order."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT event_type FROM ati.datasource_log "
                "WHERE execution_id = :execution_id ORDER BY id ASC"
            ),
            {"execution_id": execution_id},
        )
    return [str(row[0]) for row in result.fetchall()]


async def _decode_published(bootstrap: str, topic: str) -> EvidenceMessage:
    """Decode one real broker record with a disposable no-commit reader."""
    reader = _consumer(bootstrap, topic, _new_group())
    await reader.start()
    try:
        for _ in range(8):
            batch = await reader.poll(10)
            if batch.records:
                assert len(batch.records) == 1
                return batch.records[0].message
    finally:
        await reader.stop()
    raise AssertionError("no published record could be decoded")


async def _append_lifecycle_event(
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    execution_id: UUID,
    event_type: DatasourceExecutionEventType,
) -> None:
    """Append one lifecycle event in a short committed transaction."""
    async with uow_factory() as uow:
        await uow.datasource_logs.append(
            DatasourceLogEvent(
                execution_id=execution_id,
                datasource_id=_DEFINITION.datasource_id,
                event_type=event_type,
                occurred_at=_OCCURRED_AT,
                item_count=1,
            )
        )


async def _seed_investigation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> UUID:
    """Create one visible Investigation and return its id."""
    investigation_id = uuid4()
    async with uow_factory() as uow:
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[uuid4()],
                objective="Reproducibility probe.",
                budget=default_investigation_budget(),
                started_at=_OCCURRED_AT,
            )
        )
    return investigation_id


async def _admit_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    investigation_id: UUID,
    observation_id: UUID,
) -> None:
    """Admit one exact observation into the Investigation (existing API)."""
    async with uow_factory() as uow:
        await uow.investigation_evidence.admit(
            InvestigationEvidence(
                investigation_id=investigation_id,
                evidence_observation_id=observation_id,
                inclusion_reason=InvestigationEvidenceReason.INITIAL,
                added_at=_OCCURRED_AT,
                added_by=InvestigationEvidenceActor.SYSTEM,
            )
        )


async def _admission_pairs(engine: AsyncEngine, investigation_id: UUID) -> set[UUID]:
    """Return the admitted evidence_observation ids of one Investigation."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT evidence_observation_id FROM ati.investigation_evidence "
                "WHERE investigation_id = :investigation_id"
            ),
            {"investigation_id": investigation_id},
        )
    return {row[0] for row in result.fetchall()}


# ---------------------------------------------------------------------------
# H28H-01..06: happy path and temporal matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_h28h_01_fresh_a_creates_evidence_and_v1(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-01: one fresh state A creates one Evidence, EO v1, receipt, graph.

    Producer PUBLISHED/COMPLETED through the real broker; the real consumer
    persists atomically and commits the Kafka offsets only after the
    PostgreSQL commit; the authoritative graph references the committed EO.
    """
    execution_id, _ = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    result = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert result.persisted_count == 1
    assert result.created_count == 1
    assert result.committed is True

    assert await _count(integration_engine, "evidence") == 1
    observations = await _observations(integration_engine)
    assert [(v, diff) for v, _, _, diff in observations] == [(1, False)]
    assert await _count(integration_engine, "evidence_message_receipt") == 1
    assert len(await _eoe_observation_entities(integration_engine)) == 1
    assert len(await _ro_rows(integration_engine)) == 1
    assert await _count(integration_engine, "investigation_evidence") == 0
    assert await _lifecycle(integration_engine, execution_id) == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]


@pytest.mark.asyncio
async def test_h28h_02_later_a_equivalent_is_unchanged_not_replay(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-02: E1 X/A then E2 X/A-equivalent persists UNCHANGED with no EO v2.

    Two distinct datasource executions (different execution IDs, therefore
    different message IDs) carry the same semantic state; the second is not
    an exact replay and must not append an observation.
    """
    execution_id_1, _ = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    execution_id_2, _ = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    assert execution_id_1 != execution_id_2

    first = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert first.created_count == 1
    second = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert second.unchanged_count == 1
    assert second.committed is True

    assert await _count(integration_engine, "evidence") == 1
    observations = await _observations(integration_engine)
    assert [(v, diff) for v, _, _, diff in observations] == [(1, False)]
    assert len(await _receipt_ids(integration_engine)) == 2
    assert len(await _eoe_observation_entities(integration_engine)) == 1
    assert len(await _ro_rows(integration_engine)) == 1


@pytest.mark.asyncio
async def test_h28h_03_a_to_b_appends_monotonic_v2(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-03: a material change appends v2 with a diff and B provenance."""
    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        malware=_MALWARE_B,
    )
    first = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert first.created_count == 1
    second = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert second.appended_count == 1

    observations = await _observations(integration_engine)
    assert [(v, diff) for v, _, _, diff in observations] == [
        (1, False),
        (2, True),
    ]
    assert len(await _evidence_ids(integration_engine)) == 1
    ro = await _ro_rows(integration_engine)
    assert sorted(row[1] for row in ro) == sorted(UUID(row[1]) for row in observations)
    assert len(await _receipt_ids(integration_engine)) == 2


@pytest.mark.asyncio
async def test_h28h_04_a_to_b_to_c_versions_1_2_3(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-04: A->B->C yields exactly v1/v2/v3 with exact provenance."""
    for malware in (_MALWARE_A, _MALWARE_B, _MALWARE_C):
        await _produce_lifecycle(
            uow_factory,
            integration_engine,
            bootstrap=kafka_bootstrap,
            topic=evidence_topic,
            malware=malware,
        )
    for _ in range(3):
        await _consume_until_processed(
            kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
        )
    observations = await _observations(integration_engine)
    assert [(v, diff) for v, _, _, diff in observations] == [
        (1, False),
        (2, True),
        (3, True),
    ]
    assert len(await _evidence_ids(integration_engine)) == 1
    assert len(await _receipt_ids(integration_engine)) == 3
    ro = await _ro_rows(integration_engine)
    assert sorted(row[1] for row in ro) == sorted(UUID(row[1]) for row in observations)


@pytest.mark.asyncio
async def test_h28h_05_a_to_b_to_a_appends_v3_recurrence(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-05: a NEW message returning to state A appends v3, never replay.

    Receipts are keyed by message identity: the third message is distinct
    (fresh execution), so it runs the authoritative transition against the
    latest material state (B) and appends v3 with state A.
    """
    for malware in (_MALWARE_A, _MALWARE_B, _MALWARE_A):
        await _produce_lifecycle(
            uow_factory,
            integration_engine,
            bootstrap=kafka_bootstrap,
            topic=evidence_topic,
            malware=malware,
        )
    for _ in range(3):
        await _consume_until_processed(
            kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
        )
    observations = await _observations(integration_engine)
    assert [(v, diff) for v, _, _, diff in observations] == [
        (1, False),
        (2, True),
        (3, True),
    ]
    assert len(await _evidence_ids(integration_engine)) == 1
    assert len(await _receipt_ids(integration_engine)) == 3


@pytest.mark.asyncio
async def test_h28h_06_multi_evidence_atomic_batch(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-06: several Evidence records persist as one atomic batch.

    One consumer iteration handles a multi-Evidence batch: every record is
    reported committed, PostgreSQL holds all observations, and the broker
    commit happened only after the database transaction succeeded.
    """
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(
                    asyncrat_domain_record(id=_RECORD_ID, malware=_MALWARE_A),
                    asyncrat_domain_record(id="864299", malware=_MALWARE_B),
                )
            )
        ) as client:
            producer = DatasourceEvidenceProducer(
                definition=_DEFINITION,
                acquirer=_datasource(client),
                registry=build_threatfox_conversion_registry(),
                publisher=publisher,
                uow_factory=uow_factory,
                clock=lambda: _OCCURRED_AT,
            )
            result = await producer.produce(_DOMAIN_ENTITY)
    finally:
        await publisher.stop()
    assert result.outcome is DatasourceProducerOutcome.COMPLETED
    assert result.published_count == 2

    consumed = await _consume_until_processed(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        group=_new_group(),
        batch_size=10,
    )
    assert consumed.persisted_count == 2
    assert consumed.committed is True
    assert len(await _evidence_ids(integration_engine)) == 2
    assert await _count(integration_engine, "evidence_observation") == 2
    assert len(await _receipt_ids(integration_engine)) == 2


# ---------------------------------------------------------------------------
# H28H-07..08: replay/idempotency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_h28h_07_exact_message_replay_is_harmless(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-07: republishing exact producer bytes adds no semantic state.

    A real producer message is decoded through the real consumer, then the
    exact same identity/bytes are republished to the real broker and
    consumed again: the receipt table makes the replay a no-op (no duplicate
    Evidence, EO, EOEntity, or RelationshipObservation).
    """
    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    message = await _decode_published(kafka_bootstrap, evidence_topic)

    first = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert first.persisted_count == 1

    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await publisher.publish((message,))
    finally:
        await publisher.stop()

    # A fresh group reads the immutable topic from the beginning: the batch
    # carries both the original record and the republished record. Both are
    # receipt hits (echoing the established authoritative result), so the
    # diagnostic idempotency lives in the database, not in the poll count.
    replay = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert replay.persisted_count == 2
    assert replay.committed is True

    assert len(await _evidence_ids(integration_engine)) == 1
    observations = await _observations(integration_engine)
    assert [(v, diff) for v, _, _, diff in observations] == [(1, False)]
    assert len(await _receipt_ids(integration_engine)) == 1
    assert len(await _eoe_observation_entities(integration_engine)) == 1
    assert len(await _ro_rows(integration_engine)) == 1


@pytest.mark.asyncio
async def test_h28h_08_same_semantic_state_new_message_new_receipt(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-08: same state with a new datasource execution is a new receipt.

    Distinct producer executions create distinct messages (hence distinct
    message IDs), so the receipt table records both; the EO history stays
    at one observation because the material state is unchanged.
    """
    for _ in range(2):
        await _produce_lifecycle(
            uow_factory,
            integration_engine,
            bootstrap=kafka_bootstrap,
            topic=evidence_topic,
        )
    for _ in range(2):
        await _consume_until_processed(
            kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
        )
    assert len(await _receipt_ids(integration_engine)) == 2
    observations = await _observations(integration_engine)
    assert [(v, diff) for v, _, _, diff in observations] == [(1, False)]


# ---------------------------------------------------------------------------
# H28H-09..13: failure/recovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_h28h_09_failure_before_pg_commit_redelivers_and_recovers(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-09: a pre-commit persistence failure leaves Kafka uncommitted.

    The first persistence attempt fails before the PostgreSQL transaction
    opens (injected deterministic boundary failure, no production chaos
    API). No authoritative state is written, the broker cursor is not
    advanced, the same group redelivers, and the retry succeeds once.
    """
    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    group = _new_group()

    consumer = _consumer(kafka_bootstrap, evidence_topic, group)
    await consumer.start()
    service = _FailBeforeCommitPersistence(uow_factory)
    persistence = EvidencePersistenceConsumer(
        consumer=consumer, persistence=service, batch_size=10
    )
    try:
        with pytest.raises(RuntimeError, match="before PostgreSQL commit"):
            await persistence.process_next_batch()
    finally:
        await consumer.stop()

    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 0

    recovered = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=group
    )
    assert recovered.created_count == 1
    assert recovered.committed is True
    assert await _count(integration_engine, "evidence") == 1
    observations = await _observations(integration_engine)
    assert [(v, diff) for v, _, _, diff in observations] == [(1, False)]


@pytest.mark.asyncio
async def test_h28h_10_pg_commit_then_kafka_commit_absent_is_replay_safe(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-10: the at-least-once window is replay-safe.

    Poll -> real PostgreSQL COMMIT -> injected Kafka commit failure ->
    recreate the same group -> redelivery -> receipt-idempotent replay ->
    final Kafka commit -> no further redelivery.
    """
    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    group = _new_group()

    with pytest.raises(EvidenceCommitError, match="commit failure"):
        await _consume_until_processed(
            kafka_bootstrap,
            evidence_topic,
            uow_factory,
            group=group,
            consumer_wrapper=lambda inner: _CommitFailingConsumer(inner, fail_calls=1),
        )
    # PostgreSQL committed durably before the Kafka commit failed.
    assert await _count(integration_engine, "evidence") == 1
    observations = await _observations(integration_engine)
    assert [(v, diff) for v, _, _, diff in observations] == [(1, False)]
    assert len(await _receipt_ids(integration_engine)) == 1

    replay = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=group
    )
    assert replay.persisted_count == 1
    assert replay.committed is True
    assert await _count(integration_engine, "evidence") == 1
    assert await _count(integration_engine, "evidence_observation") == 1
    assert len(await _receipt_ids(integration_engine)) == 1

    after = _consumer(kafka_bootstrap, evidence_topic, group)
    await after.start()
    try:
        batch = await after.poll(10)
        assert not batch.records
    finally:
        await after.stop()


@pytest.mark.asyncio
async def test_h28h_11_poll_then_stop_before_persistence_redelivers(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-11: polling without persistence leaves no DB state and redelivers."""
    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    group = _new_group()

    first = _consumer(kafka_bootstrap, evidence_topic, group)
    await first.start()
    try:
        batch = await first.poll(10)
        assert len(batch.records) == 1
        # No persistence, no commit: simulate a process stop.
    finally:
        await first.stop()

    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 0

    redelivered = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=group
    )
    assert redelivered.persisted_count == 1
    assert redelivered.committed is True
    assert await _count(integration_engine, "evidence") == 1


@pytest.mark.asyncio
async def test_h28h_12_atomic_multi_record_rollback_and_uncommitted_broker(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-12: one failing record rolls the whole batch back atomically.

    Two Evidence records are published; a deterministic in-batch failure
    (soft-deleted canonical domain entity rediscovery, the established
    real-PostgreSQL seam) aborts the transaction. No earlier record or
    receipt from that batch remains and the broker batch stays uncommitted.
    """
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(
                    asyncrat_domain_record(id=_RECORD_ID, malware=_MALWARE_A),
                    asyncrat_domain_record(id="864299", malware=_MALWARE_B),
                )
            )
        ) as client:
            producer = DatasourceEvidenceProducer(
                definition=_DEFINITION,
                acquirer=_datasource(client),
                registry=build_threatfox_conversion_registry(),
                publisher=publisher,
                uow_factory=uow_factory,
                clock=lambda: _OCCURRED_AT,
            )
            result = await producer.produce(_DOMAIN_ENTITY)
    finally:
        await publisher.stop()
    assert result.outcome is DatasourceProducerOutcome.COMPLETED
    assert result.published_count == 2

    # Deterministic U18C2 seam: the batch depends on the canonical domain
    # entity, which is soft-deleted up front (mirrors the V28E-02 seam).
    async with uow_factory() as uow:
        entity = await uow.entities.upsert(
            Entity(id=uuid4(), type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN)
        )
        assert entity.id is not None
        await uow.entities.soft_delete(entity.id)

    group = _new_group()
    consumer = _consumer(kafka_bootstrap, evidence_topic, group)
    await consumer.start()
    service = EvidenceBatchPersistenceService(uow_factory)
    persistence = EvidencePersistenceConsumer(
        consumer=consumer, persistence=service, batch_size=10
    )
    try:
        with pytest.raises(SoftDeletedIdentityError):
            await persistence.process_next_batch()
    finally:
        await consumer.stop()

    async with uow_factory() as uow:
        assert uow.session is not None
        assert await _count(integration_engine, "evidence") == 0
        assert await _count(integration_engine, "evidence_observation") == 0
        assert await _count(integration_engine, "evidence_observation_entity") == 0
        assert await _count(integration_engine, "relationship_observation") == 0
        assert await _count(integration_engine, "evidence_message_receipt") == 0

    # Broker progress uncommitted: a same-group reader still sees the batch.
    reader = _consumer(kafka_bootstrap, evidence_topic, group)
    await reader.start()
    try:
        batch = await reader.poll(10)
        assert len(batch.records) == 2
    finally:
        await reader.stop()


@pytest.mark.asyncio
async def test_h28h_13_successful_commit_then_restart_no_redelivery(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-13: after a real PG + Kafka commit, restart sees no records."""
    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    group = _new_group()
    processed = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=group
    )
    assert processed.committed is True
    assert await _count(integration_engine, "evidence") == 1

    restarted = _consumer(kafka_bootstrap, evidence_topic, group)
    await restarted.start()
    try:
        batch = await restarted.poll(10)
        assert not batch.records
    finally:
        await restarted.stop()


# ---------------------------------------------------------------------------
# H28H-14..16: producer lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_h28h_14_producer_completes_without_consumer(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-14: COMPLETED means published, never consumed.

    The producer completes its full lifecycle through the real broker with
    no consumer running; no global Evidence exists yet; a consumer started
    afterwards persists the retained record.
    """
    outcome, execution_id, published = await _produce_once(
        kafka_bootstrap, evidence_topic, uow_factory, _state()
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 1
    assert execution_id is not None
    assert await _lifecycle(integration_engine, execution_id) == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    assert await _count(integration_engine, "evidence") == 0

    processed = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert processed.persisted_count == 1
    assert await _count(integration_engine, "evidence") == 1


@pytest.mark.asyncio
async def test_h28h_15_publication_failure_records_publication_failed(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-15: a publish failure never records PUBLISHED/COMPLETED.

    The real producer path with a not-started real publisher fails closed
    with ``publication_failed`` in the durable lifecycle and persists no
    Evidence. No application-level republish loop is added.
    """

    class UnstartedPublisher(EvidencePublisher):
        """A real adapter-shaped publisher that is never started."""

        async def publish(
            self, messages: Sequence[EvidenceMessage]
        ) -> EvidencePublishResult:
            """Fail closed exactly like the not-started Kafka adapter."""
            raise EvidencePublishError("evidence publisher is not started")

    async with _client(lambda _: _json_response(_state())) as client:
        producer = DatasourceEvidenceProducer(
            definition=_DEFINITION,
            acquirer=_datasource(client),
            registry=build_threatfox_conversion_registry(),
            publisher=UnstartedPublisher(),
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )
        with pytest.raises(EvidencePublishError):
            await producer.produce(_DOMAIN_ENTITY)

    async with uow_factory() as uow:
        assert uow.session is not None
        row = (
            await uow.session.execute(
                text(
                    "SELECT execution_id, event_type, error_code "
                    "FROM ati.datasource_log ORDER BY id DESC LIMIT 1"
                )
            )
        ).first()
    assert row is not None
    assert str(row[1]) == "failed"
    assert str(row[2]) == "publication_failed"
    assert await _count(integration_engine, "evidence") == 0


@pytest.mark.asyncio
async def test_h28h_16_lifecycle_append_failure_after_successful_publish(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-16: a PUBLISHED append after terminal completion is rejected.

    After the real producer completes (PUBLISHED/COMPLETED), a later
    PUBLISHED append fails atomically with the typed append-after-terminal
    error — publication and the durable lifecycle are separate boundaries
    and nothing is automatically republished.
    """
    outcome, execution_id, published = await _produce_once(
        kafka_bootstrap, evidence_topic, uow_factory, _state()
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 1
    assert execution_id is not None
    with pytest.raises(
        DatasourceLogAppendAfterTerminalError,
        match="cannot append datasource log event after terminal outcome",
    ):
        await _append_lifecycle_event(
            uow_factory,
            execution_id=execution_id,
            event_type=DatasourceExecutionEventType.PUBLISHED,
        )
    lifecycle = await _lifecycle(integration_engine, execution_id)
    assert lifecycle == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]


# ---------------------------------------------------------------------------
# H28H-17..18: provenance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_h28h_17_eoe_references_exact_authoritative_observation(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-17: every EOEntity association references its exact committed EO.

    A->B keeps both authoritative observation identities: v1 associates the
    A malware, v2 the B malware; associations are never rebound to latest.
    """
    for malware in (_MALWARE_A, _MALWARE_B):
        await _produce_lifecycle(
            uow_factory,
            integration_engine,
            bootstrap=kafka_bootstrap,
            topic=evidence_topic,
            malware=malware,
        )
    for _ in range(2):
        await _consume_until_processed(
            kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
        )
    observations = await _observations(integration_engine)
    by_version = {v: UUID(obs_id) for v, obs_id, _, _ in observations}
    assert set(by_version) == {1, 2}
    associated = await _eoe_observation_entities(integration_engine)
    v1_entities = associated[by_version[1]]
    v2_entities = associated[by_version[2]]
    assert {"malicious-domain.test", _MALWARE_A} == v1_entities
    assert {"malicious-domain.test", _MALWARE_B} == v2_entities


@pytest.mark.asyncio
async def test_h28h_18_ro_references_exact_committed_observation(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-18: each RelationshipObservation references its exact EO.

    The deterministic ThreatFox extraction asserts the subject ASSOCIATED_WITH
    the malware of its own observation; per-state ROs keep per-state EO
    provenance and are never rebound to the latest observation.
    """
    for malware in (_MALWARE_A, _MALWARE_B):
        await _produce_lifecycle(
            uow_factory,
            integration_engine,
            bootstrap=kafka_bootstrap,
            topic=evidence_topic,
            malware=malware,
        )
    for _ in range(2):
        await _consume_until_processed(
            kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
        )
    observations = await _observations(integration_engine)
    ro = await _ro_rows(integration_engine)
    assert len(ro) == 2
    assert sorted(row[1] for row in ro) == sorted(
        UUID(obs_id) for _, obs_id, _, _ in observations
    )
    # Each RO records its exact observation; no observation has two ROs.
    seen: set[UUID] = set()
    for _, observation_id in ro:
        assert observation_id not in seen
        seen.add(observation_id)


# ---------------------------------------------------------------------------
# H28H-19..21: Investigation reproducibility
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_h28h_19_two_investigations_admit_same_observation(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-19: one global EO admitted by two independent Investigations.

    Ingestion never admits; admission stays an explicit investigation
    operation referencing the exact authoritative observation.
    """
    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    observation_id = UUID((await _observations(integration_engine))[0][1])

    investigation_a = await _seed_investigation(uow_factory)
    investigation_b = await _seed_investigation(uow_factory)
    await _admit_observation(
        uow_factory, investigation_id=investigation_a, observation_id=observation_id
    )
    await _admit_observation(
        uow_factory, investigation_id=investigation_b, observation_id=observation_id
    )
    assert await _admission_pairs(integration_engine, investigation_a) == {
        observation_id
    }
    assert await _admission_pairs(integration_engine, investigation_b) == {
        observation_id
    }
    assert await _count(integration_engine, "investigation_evidence") == 2


@pytest.mark.asyncio
async def test_h28h_20_one_investigation_admits_v1_and_v2(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-20: one Investigation admits v1 and v2 exactly and independently."""
    for malware in (_MALWARE_A, _MALWARE_B):
        await _produce_lifecycle(
            uow_factory,
            integration_engine,
            bootstrap=kafka_bootstrap,
            topic=evidence_topic,
            malware=malware,
        )
    for _ in range(2):
        await _consume_until_processed(
            kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
        )
    observations = await _observations(integration_engine)
    version_ids = {v: UUID(obs_id) for v, obs_id, _, _ in observations}
    assert set(version_ids) == {1, 2}

    investigation_id = await _seed_investigation(uow_factory)
    await _admit_observation(
        uow_factory,
        investigation_id=investigation_id,
        observation_id=version_ids[1],
    )
    await _admit_observation(
        uow_factory,
        investigation_id=investigation_id,
        observation_id=version_ids[2],
    )
    assert await _admission_pairs(integration_engine, investigation_id) == {
        version_ids[1],
        version_ids[2],
    }


@pytest.mark.asyncio
async def test_h28h_21_later_global_observation_does_not_mutate_admission(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """H28H-21: a later global EO never silently mutates prior admissions.

    Admit v1, then ingest v2 globally: the Investigation still references
    only v1 until v2 is explicitly admitted.
    """
    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
    )
    await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    v1 = UUID((await _observations(integration_engine))[0][1])

    investigation_id = await _seed_investigation(uow_factory)
    await _admit_observation(
        uow_factory, investigation_id=investigation_id, observation_id=v1
    )

    await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        malware=_MALWARE_B,
    )
    await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    v2 = next(
        UUID(obs_id)
        for v, obs_id, _, _ in (await _observations(integration_engine))
        if v == 2
    )
    assert v2 != v1
    # Ingestion did not extend the admission; v2 remains invisible until
    # explicitly admitted.
    assert await _admission_pairs(integration_engine, investigation_id) == {v1}
    await _admit_observation(
        uow_factory, investigation_id=investigation_id, observation_id=v2
    )
    assert await _admission_pairs(integration_engine, investigation_id) == {
        v1,
        v2,
    }
