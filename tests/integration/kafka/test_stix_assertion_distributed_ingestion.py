# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33D real-stack distributed STIX assertion ingestion (K01..K03).

The canonical PR 33D distributed durable-ingestion slices run every layer
through its production implementation:

```text
synthetic STIX Relationship/Sighting object
 -> real parse_stix21_object (PR 33A)
 -> real Stix21ToEvidenceConverter (PR 33B/33C/33D)
 -> EvidenceMessage V1 (PR 28C codec)
 -> KafkaEvidencePublisher -> real Redpanda
 -> KafkaEvidenceConsumer -> EvidencePersistenceConsumer
 -> EvidenceBatchPersistenceService -> real PostgreSQL
```

Only the upstream STIX object input is synthetic; conversion, message
codec, publisher, durable log, consumer, batch persistence, PostgreSQL,
and the broker commit-after-PostgreSQL-commit ordering are all real.

Matrix IDs M33D-K01..K03: a Relationship through the real broker with the
V01 persistence result, a Sighting through the real broker with zero
relationship rows, and a tampered assertion whose processing fails so the
broker position stays uncommitted and the message remains redeliverable.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_batch_persistence import (
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_consumer import (
    EvidenceConsumerRunResult,
    EvidencePersistenceConsumer,
)
from agentic_threat_investigator.app.evidence_conversion import (
    EvidenceConversionContext,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceConsumer,
    EvidenceConsumerId,
    EvidencePublishResult,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    evidence_message_from_converted,
)
from agentic_threat_investigator.app.extraction.models import EvidenceExtractionError
from agentic_threat_investigator.domain.datasource import DatasourceId
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
from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
    Stix21ToEvidenceConverter,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    parse_stix21_object,
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
from tests.support import stix21_fixtures as fixtures

pytestmark = pytest.mark.integration

_OCCURRED_AT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_SOURCE_REFERENCE = "https://taxii.example.test/collections/1/objects/"
_POLL_TIME_MS = 2000
_PUB_CLIENT = "pr-33d-publisher"

_CONVERTER = Stix21ToEvidenceConverter()


def _context(source_id: SourceId = SourceId.CISA_KEV) -> EvidenceConversionContext:
    """Build one deterministic STIX conversion context."""
    return EvidenceConversionContext(
        semantic_source=SemanticSourceContext(
            datasource_id=DatasourceId("stix-future"),
            source_id=source_id,
            semantic_format=SemanticFormatId.STIX_21,
            retrieved_at=_OCCURRED_AT,
            source_reference=_SOURCE_REFERENCE,
        )
    )


def _message(
    decoded: dict[str, Any], source_id: SourceId = SourceId.CISA_KEV
) -> EvidenceMessage:
    """Convert one object and build its V1 message through production code."""
    context = _context(source_id)
    converted = _CONVERTER.convert(parse_stix21_object(decoded), context)[0]
    return evidence_message_from_converted(
        converted,
        datasource_execution_id=uuid4(),
        semantic_source=context.semantic_source,
        sequence=0,
    )


def _tampered_message() -> EvidenceMessage:
    """Build a valid V1 message whose durable assertion facts are tampered.

    The STIX relationship string and the ATI relationship URN disagree
    (``uses`` paired with the ``targets`` URN), which the deterministic
    extractor must reject during consumer preflight.
    """
    evidence_id = evidence_id_for_source_record(
        SemanticFormatId.STIX_21, SourceId.CISA_KEV, fixtures.RELATIONSHIP_ID
    )
    converted = ConvertedEvidence(
        evidence=Evidence(
            id=evidence_id,
            type=EvidenceType.THREAT_INTELLIGENCE,
            source=SourceId.CISA_KEV.value,
            source_record_id=fixtures.RELATIONSHIP_ID,
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=evidence_id,
            source_url=_SOURCE_REFERENCE,
            observed_at=None,
            retrieved_at=_OCCURRED_AT,
            facts={
                "stix": {"id": fixtures.RELATIONSHIP_ID, "type": "relationship"},
                "indicator": None,
                "iocs": [],
                "cti_entity": None,
                "source_assertion": {
                    "kind": "relationship",
                    "relationship": {
                        "type": "uses",
                        "ati_type": "urn:ati:relationship:threat:targets",
                        "source": {
                            "type": "threat_actor",
                            "value": fixtures.THREAT_ACTOR_ID,
                        },
                        "target": {"type": "tool", "value": fixtures.TOOL_ID},
                        "start_time": None,
                        "stop_time": None,
                    },
                    "sighting": None,
                },
            },
            raw_payload=None,
        ),
    )
    return evidence_message_from_converted(
        converted,
        datasource_execution_id=uuid4(),
        semantic_source=_context().semantic_source,
        sequence=0,
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
        client_id=f"pr-33d-{uuid4().hex[:6]}",
        poll_timeout_ms=_POLL_TIME_MS,
    )


def _new_group() -> str:
    """Return a fresh deterministic consumer group identity for this test."""
    return f"pr-33d-{uuid4().hex[:12]}"


async def _publish_many(
    publisher: KafkaEvidencePublisher, messages: list[EvidenceMessage]
) -> EvidencePublishResult:
    """Publish a message run and assert unchanged result metadata."""
    result = await publisher.publish(messages)
    assert len(result.records) == len(messages)
    return result


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
    """Run the real consumer until a batch is processed and committed."""
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


async def _evidence_ids(engine: AsyncEngine) -> set[UUID]:
    """Return the distinct global Evidence ids."""
    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT id FROM ati.evidence"))
    return {row[0] for row in result.fetchall()}


async def _observation_entities(engine: AsyncEngine) -> dict[UUID, set[str]]:
    """Return map observation_id -> associated entity canonical values."""
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


async def _relationship_rows(engine: AsyncEngine) -> list[tuple[str, str, str]]:
    """Return ordered (type, source value, target value) relationship rows."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT r.relationship_type_urn, se.canonical_value, te.canonical_value "
                "FROM ati.relationship r "
                "JOIN ati.entity se ON se.id = r.source_entity_id "
                "JOIN ati.entity te ON te.id = r.target_entity_id "
                "ORDER BY r.relationship_type_urn"
            )
        )
    return [(row[0], row[1], row[2]) for row in result.fetchall()]


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


def _expected_evidence_id(
    stix_id: str, source_id: SourceId = SourceId.CISA_KEV
) -> UUID:
    """Return the exact deterministic Evidence identity of one STIX object."""
    return evidence_id_for_source_record(SemanticFormatId.STIX_21, source_id, stix_id)


@pytest.mark.asyncio
async def test_m33d_k01_relationship_through_real_broker(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """M33D-K01: a Relationship persists end-to-end through real Redpanda."""
    message = _message(
        fixtures.stix_relationship(
            relationship_type="uses",
            source_ref=fixtures.THREAT_ACTOR_ID,
            target_ref=fixtures.TOOL_ID,
        )
    )
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, [message])
    finally:
        await publisher.stop()

    result = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert result.persisted_count == 1
    assert result.created_count == 1
    assert result.committed is True

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.RELATIONSHIP_ID)
    }
    assert await _count(integration_engine, "evidence_observation") == 1
    assert await _count(integration_engine, "evidence_message_receipt") == 1
    eoe = await _observation_entities(integration_engine)
    assert len(eoe) == 1
    (associated,) = eoe.values()
    assert associated == {fixtures.THREAT_ACTOR_ID, fixtures.TOOL_ID}
    assert await _relationship_rows(integration_engine) == [
        ("urn:ati:relationship:threat:uses", fixtures.THREAT_ACTOR_ID, fixtures.TOOL_ID)
    ]
    ro = await _ro_rows(integration_engine)
    assert len(ro) == 1
    # Provenance points at the real committed EvidenceObservation (not a
    # transport position or a candidate id).
    observation_id = next(iter(eoe))
    assert ro[0][1] == observation_id


@pytest.mark.asyncio
async def test_m33d_k02_sighting_through_real_broker(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """M33D-K02: a Sighting persists facts with zero relationship rows."""
    message = _message(
        fixtures.stix_sighting(
            sighting_of_ref=fixtures.CAMPAIGN_ID,
            first_seen="2026-01-10T00:00:00Z",
            last_seen="2026-01-20T00:00:00Z",
            count=4,
            summary=True,
        )
    )
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, [message])
    finally:
        await publisher.stop()

    result = await _consume_until_processed(
        kafka_bootstrap, evidence_topic, uow_factory, group=_new_group()
    )
    assert result.committed is True

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.SIGHTING_ID)
    }
    assert await _count(integration_engine, "evidence_observation") == 1
    eoe = await _observation_entities(integration_engine)
    assert len(eoe) == 1
    (associated,) = eoe.values()
    assert associated == {fixtures.CAMPAIGN_ID}
    assert await _relationship_rows(integration_engine) == []
    assert await _count(integration_engine, "relationship_observation") == 0
    # first_seen/last_seen/count stayed normalized source facts, never an
    # ATI observation time.
    async with integration_engine.connect() as connection:
        observed_at = await connection.scalar(
            text("SELECT observed_at FROM ati.evidence_observation LIMIT 1")
        )
        sighting = await connection.scalar(
            text(
                "SELECT facts->'source_assertion'->'sighting' FROM ati.evidence_observation LIMIT 1"
            )
        )
    assert observed_at is None
    assert sighting["count"] == 4
    assert sighting["first_seen"] == "2026-01-10T00:00:00Z"


@pytest.mark.asyncio
async def test_m33d_k03_tampered_assertion_leaves_broker_uncommitted(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
    kafka_bootstrap: str,
    evidence_topic: str,
) -> None:
    """M33D-K03: a tampered assertion is not acknowledged by the consumer.

    Processing fails during deterministic preflight before any PostgreSQL
    write; the broker position stays uncommitted and the same-group reader
    still sees the message for redelivery.
    """
    message = _tampered_message()
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, [message])
    finally:
        await publisher.stop()

    group = _new_group()
    consumer = _consumer(kafka_bootstrap, evidence_topic, group)
    await consumer.start()
    service = EvidenceBatchPersistenceService(uow_factory)
    persistence = EvidencePersistenceConsumer(
        consumer=consumer, persistence=service, batch_size=10
    )
    try:
        with pytest.raises(EvidenceExtractionError):
            await persistence.process_next_batch()
    finally:
        await consumer.stop()

    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "evidence_observation") == 0
    assert await _count(integration_engine, "entity") == 0
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 0

    # Broker progress uncommitted: a same-group reader still sees the batch.
    reader = _consumer(kafka_bootstrap, evidence_topic, group)
    await reader.start()
    try:
        batch = await reader.poll(10)
        assert len(batch.records) == 1
    finally:
        await reader.stop()
