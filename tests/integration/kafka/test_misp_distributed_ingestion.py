# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 32D MISP real-stack distributed Evidence closure (M32D-K01..K06).

The mandatory feature-acceptance topology runs every layer through its
production implementation and reuses the PR 28H real topology:

```text
deterministic MISP fixture
 -> real ProviderHttpClient boundary (httpx.MockTransport only, no Internet)
 -> real MispDatasource (bounded sequential events/restSearch)
 -> real parse_misp_event
 -> real MispToEvidenceConverter (build_misp_conversion_registry)
 -> CollectionDatasourceEvidenceProducer
 -> KafkaEvidencePublisher -> real Redpanda
 -> KafkaEvidenceConsumer
 -> EvidencePersistenceConsumer
 -> EvidenceBatchPersistenceService -> real PostgreSQL
```

Only external MISP HTTPS is faked; the broker and database are real. The
matrix proves the complete domain pipeline (K01), multi-message identities
without cross-partition order claims (K02), replay/idempotency through the
PostgreSQL-commit/Kafka-commit-failure seam (K03), unchanged material state
(K04), changed material state under PostgreSQL version/diff authority
(K05), and consumer failure before commit with redelivery (K06).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.datasource_evidence_producer import (
    CollectionDatasourceEvidenceProducer,
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
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceBatchPersistenceResult,
    PreparedEvidenceBatch,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.evidence import (
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.misp import MispDatasource
from agentic_threat_investigator.infrastructure.datasources.misp_evidence import (
    build_misp_conversion_registry,
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
from tests.support.misp_fixtures import (
    ATTRIBUTE_UUID,
    DOMAIN_VALUE,
    FIXED_KEY,
    IPV4_VALUE,
    MISP_BASE_URL,
)
from tests.support.provider_http import no_op_sleep, zero_jitter

pytestmark = pytest.mark.integration

_OCCURRED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)
_POLL_TIME_MS = 2000
_PUB_CLIENT = "m32d-publisher"
_CON_CLIENT = "m32d-consumer"

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("misp-live"),
    source_id=SourceId.MISP,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.MISP,
)

_FIRST_ATTRIBUTE_UUID = ATTRIBUTE_UUID
_SECOND_ATTRIBUTE_UUID = "77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b42"


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


def _datasource(client: httpx.AsyncClient) -> MispDatasource:
    """Build the real acquirer over the real bounded HTTP client."""
    return MispDatasource(
        ProviderHttpClient(
            client=client,
            policy=ProviderHttpPolicy(max_retries=0, base_delay_seconds=0.01),
            sleep=no_op_sleep,
            jitter_fn=zero_jitter,
        ),
        api_key=FIXED_KEY,
        base_url=MISP_BASE_URL,
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
    return f"m32d-{uuid4().hex[:12]}"


def _event(
    *,
    attributes: tuple[dict[str, Any], ...],
    info: str = "MISP K-series event",
) -> dict[str, Any]:
    """Build one deterministic MISP REST search payload."""
    event = {
        "id": "1",
        "uuid": "10f8c2a0-5e54-4a0a-8b5c-2f9cc2ff3b01",
        "info": info,
        "date": "2023-11-01",
        "timestamp": "1700000000",
        "published": True,
        "distribution": "0",
        "sharing_group_id": "0",
        "threat_level_id": "1",
        "analysis": "2",
        "Attribute": list(attributes),
    }
    return {"response": [{"Event": event}]}


def _attribute(
    *,
    type_: str = "domain",
    value: str = DOMAIN_VALUE,
    uuid: str = _FIRST_ATTRIBUTE_UUID,
    comment: str = "",
) -> dict[str, Any]:
    """Build one synthetic MISP Attribute member."""
    return {
        "id": "21",
        "uuid": uuid,
        "type": type_,
        "category": "Network activity",
        "value": value,
        "timestamp": "1700000100",
        "to_ids": True,
        "distribution": "1",
        "sharing_group_id": "0",
        "deleted": False,
        "comment": comment,
    }


async def _produce_once(
    bootstrap: str,
    topic: str,
    uow_factory: Callable[[], PostgresUnitOfWork],
    payload: dict[str, Any],
) -> tuple[DatasourceProducerOutcome, UUID | None, int]:
    """Run one full real collection producer execution (acquire..publish)."""
    publisher = _publisher(bootstrap, topic)
    await publisher.start()
    try:
        async with _client(lambda _request: _json_response(payload)) as client:
            producer = CollectionDatasourceEvidenceProducer(
                definition=_DEFINITION,
                acquirer=_datasource(client),
                registry=build_misp_conversion_registry(),
                publisher=publisher,
                uow_factory=uow_factory,
                clock=lambda: _OCCURRED_AT,
            )
            result = await producer.produce()
    finally:
        await publisher.stop()
    return result.outcome, result.execution_id, result.published_count


async def _produce_lifecycle(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
    *,
    bootstrap: str,
    topic: str,
    payload: dict[str, Any],
) -> tuple[UUID, int]:
    """Run one real producer execution and assert its full lifecycle."""
    outcome, execution_id, published = await _produce_once(
        bootstrap, topic, uow_factory, payload
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert execution_id is not None
    assert published >= 0
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
    """Narrow seam: delegates real poll, fails the configured commits."""

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
    """Narrow seam: one persistence call fails before the transaction opens."""

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
    """Run one real consumer until a batch is processed and committed."""
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


async def _source_record_ids(engine: AsyncEngine) -> set[str]:
    """Return the distinct Evidence source_record_ids."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text("SELECT source_record_id FROM ati.evidence")
        )
    return {row[0] for row in result.fetchall()}


async def _observations(
    engine: AsyncEngine,
) -> list[tuple[int, UUID, UUID, bool]]:
    """Return (version, id, evidence_id, has_diff) observation rows."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT o.version, o.id, o.evidence_id, o.diff IS NOT NULL "
                "FROM ati.evidence_observation o ORDER BY o.version"
            )
        )
    return [(row[0], row[1], row[2], bool(row[3])) for row in result.fetchall()]


async def _observation_entities(engine: AsyncEngine) -> dict[UUID, set[str]]:
    """Return observation_id -> associated entity canonical values."""
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


# ---------------------------------------------------------------------------
# K01..K06 feature acceptance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_k01_complete_domain_pipeline(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """K01: one domain Attribute closes real Redpanda + PostgreSQL."""
    payload = _event(attributes=(_attribute(),))
    execution_id, published = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        payload=payload,
    )
    assert published == 1
    run = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert run.committed is True
    assert run.created_count == 1
    expected_evidence_id = evidence_id_for_source_record(
        SemanticFormatId.MISP, SourceId.MISP, _FIRST_ATTRIBUTE_UUID
    )
    assert await _count(integration_engine, "evidence") == 1
    assert await _source_record_ids(integration_engine) == {_FIRST_ATTRIBUTE_UUID}
    observations = await _observations(integration_engine)
    assert len(observations) == 1
    assert observations[0][0] == 1
    assert observations[0][2] == expected_evidence_id
    assert await _count(integration_engine, "evidence_observation") == 1
    assert await _observation_entities(integration_engine) == {
        observations[0][1]: {DOMAIN_VALUE}
    }
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0
    assert await _count(integration_engine, "investigation_evidence") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 1
    assert (await _lifecycle(integration_engine, execution_id))[-1] == "completed"


@pytest.mark.asyncio
async def test_k02_multi_message_distinct_identities(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """K02: multiple supported Attributes keep distinct Evidence identities.

    Ordering is asserted only where the transport guarantees it: each
    Evidence identity routes to one partition, and the producer's zero-based
    sequence and distinct Attribute UUID identities are asserted at the
    producer boundary; no cross-partition order claim is made.
    """
    payload = _event(
        attributes=(
            _attribute(uuid=_FIRST_ATTRIBUTE_UUID, value=DOMAIN_VALUE),
            _attribute(
                uuid=_SECOND_ATTRIBUTE_UUID,
                type_="ip-src",
                value=IPV4_VALUE,
            ),
        )
    )
    _, published = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        payload=payload,
    )
    assert published == 2
    run = await _consume_until_processed(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        group=_new_group(),
        batch_size=10,
    )
    assert run.committed is True
    assert run.persisted_count == 2
    assert await _source_record_ids(integration_engine) == {
        _FIRST_ATTRIBUTE_UUID,
        _SECOND_ATTRIBUTE_UUID,
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 2
    expected_domain = evidence_id_for_source_record(
        SemanticFormatId.MISP, SourceId.MISP, _FIRST_ATTRIBUTE_UUID
    )
    expected_ip = evidence_id_for_source_record(
        SemanticFormatId.MISP, SourceId.MISP, _SECOND_ATTRIBUTE_UUID
    )
    assert await _count(integration_engine, "relationship") == 0
    assert expected_domain != expected_ip


@pytest.mark.asyncio
async def test_k03_replay_idempotent_with_commit_failure_seam(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """K03: PostgreSQL commit then Kafka-commit failure redelivers no dupes."""
    payload = _event(attributes=(_attribute(),))
    _, published = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        payload=payload,
    )
    assert published == 1
    group = _new_group()
    with pytest.raises(EvidenceCommitError, match="commit failure"):
        await _consume_until_processed(
            kafka_bootstrap,
            evidence_topic,
            uow_factory,
            group=group,
            consumer_wrapper=lambda consumer: _CommitFailingConsumer(
                consumer, fail_calls=1
            ),
        )
    # PostgreSQL committed durably before the failed broker commit.
    assert await _count(integration_engine, "evidence") == 1
    assert await _count(integration_engine, "evidence_message_receipt") == 1
    replay = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=group
    )
    assert replay.persisted_count == 1
    assert replay.committed is True
    # Redelivery created no duplicate Evidence, Observation, Entity
    # association, or receipt.
    assert await _count(integration_engine, "evidence") == 1
    assert await _count(integration_engine, "evidence_observation") == 1
    assert await _count(integration_engine, "evidence_observation_entity") == 1
    assert await _count(integration_engine, "entity") == 1
    assert await _count(integration_engine, "evidence_message_receipt") == 1
    after = _consumer(kafka_bootstrap, evidence_topic, group)
    await after.start()
    try:
        batch = await after.poll(10)
        assert not batch.records
    finally:
        await after.stop()


@pytest.mark.asyncio
async def test_k04_unchanged_material_state(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """K04: same Attribute UUID + state yields UNCHANGED, no new Observation."""
    payload = _event(attributes=(_attribute(),))
    _, _ = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        payload=payload,
    )
    first = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert first.created_count == 1

    # A fresh acquisition execution with identical material state.
    _, published = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        payload=payload,
    )
    assert published == 1
    second = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert second.unchanged_count == 1
    assert second.appended_count == 0
    # New message identity is allowed; no extra Observation is created.
    assert await _count(integration_engine, "evidence_observation") == 1
    assert await _count(integration_engine, "evidence_message_receipt") == 2


@pytest.mark.asyncio
async def test_k05_changed_material_state_appends_through_postgresql(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """K05: a material change appends v2 under PostgreSQL version/diff authority."""
    payload_a = _event(attributes=(_attribute(comment=""),))
    _, _ = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        payload=payload_a,
    )
    first = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert first.created_count == 1

    # Same Evidence identity, one material change (Attribute comment).
    payload_b = _event(attributes=(_attribute(comment="updated by analyst"),))
    _, published = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        payload=payload_b,
    )
    assert published == 1
    second = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert second.appended_count == 1
    assert second.unchanged_count == 0
    # Same Evidence row; v1 and v2 observations; v2 carries the DB diff.
    assert await _count(integration_engine, "evidence") == 1
    observations = await _observations(integration_engine)
    assert [(version, has_diff) for version, _id, _eid, has_diff in observations] == [
        (1, False),
        (2, True),
    ]
    # Both observations reference the exact authoritative observation rows
    # through the Entity association join.
    entities_by_observation = await _observation_entities(integration_engine)
    assert {observations[0][1], observations[1][1]} == set(entities_by_observation)
    assert all(values == {DOMAIN_VALUE} for values in entities_by_observation.values())
    assert await _count(integration_engine, "relationship") == 0


@pytest.mark.asyncio
async def test_k06_consumer_failure_before_commit_redelivers(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """K06: pre-commit persistence failure redelivers; retry commits cleanly."""
    payload = _event(attributes=(_attribute(),))
    _, published = await _produce_lifecycle(
        uow_factory,
        integration_engine,
        bootstrap=kafka_bootstrap,
        topic=evidence_topic,
        payload=payload,
    )
    assert published == 1
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
    # No authoritative state was written and the broker cursor was not
    # advanced: the same group redelivers.
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 0

    recovered = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=group
    )
    assert recovered.created_count == 1
    assert recovered.committed is True
    assert await _count(integration_engine, "evidence") == 1
    assert await _count(integration_engine, "evidence_observation") == 1
    assert await _count(integration_engine, "evidence_observation_entity") == 1
    assert await _count(integration_engine, "evidence_message_receipt") == 1
