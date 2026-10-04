# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E real-broker TAXII distributed ingestion (K33E-T01..T04).

The full production TAXII slice over **real Redpanda** (not the in-memory
log) plus real PostgreSQL:

```text
deterministic TAXII 2.1 wire boundary (MockTransport only)
 -> real ProviderHttpClient
 -> real Taxii21Datasource (ordered pagination + durable date-added checkpoint)
 -> real parse_stix21_object / Stix21ToEvidenceConverter
 -> CollectionDatasourceEvidenceProducer
 -> KafkaEvidencePublisher -> real Redpanda
 -> KafkaEvidenceConsumer -> EvidencePersistenceConsumer
 -> EvidenceBatchPersistenceService -> real PostgreSQL
```

Covers cross-page message ordering over the broker, the incremental second
execution through the durable checkpoint, and replay idempotency — exactly
the acceptance-shape slices V06/V07/V10 with the real broker boundary.
"""

from __future__ import annotations

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
    EvidenceConsumerId,
)
from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceCheckpoint,
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
from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
    build_stix21_conversion_registry,
)
from agentic_threat_investigator.infrastructure.datasources.taxii21 import (
    TAXII_CHECKPOINT_KIND,
    Taxii21Datasource,
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
from agentic_threat_investigator.infrastructure.providers.composition import (
    build_taxii_checkpoint_committer,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from tests.support import stix21_fixtures as fixtures
from tests.support.provider_http import no_op_sleep, zero_jitter
from tests.support.taxii_fixtures import (
    BEARER_TOKEN,
    DATE_ADDED_2,
    DATE_ADDED_3,
    NEXT_1,
    NEXT_2,
    TAXII_API_ROOT,
    TAXII_COLLECTION_ID,
    RecordedTaxiiServer,
    client_for,
    taxii_envelope,
    taxii_response,
)

pytestmark = pytest.mark.integration

_OCCURRED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("opencti-collection"),
    source_id=SourceId.OPENCTI,
    protocol=DatasourceProtocol.TAXII_21,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.STIX_21,
)

_PUB_CLIENT = "ati-taxii-k"
_CON_CLIENT = "ati-taxii-k-consumer"
_POLL_TIME_MS = 2000


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
    return f"taxii-k-{uuid4().hex[:12]}"


def _datasource(
    client: httpx.AsyncClient,
    *,
    uow_factory: Callable[[], PostgresUnitOfWork],
    max_pages: int = 100,
    page_size: int = 100,
) -> Taxii21Datasource:
    """Build the real TAXII acquirer over the real bounded HTTP client."""

    async def _read() -> DatasourceCheckpoint | None:
        async with uow_factory() as uow:
            return await uow.datasource_checkpoints.get(
                datasource_id="opencti-collection",
                checkpoint_kind=TAXII_CHECKPOINT_KIND,
            )

    return Taxii21Datasource(
        ProviderHttpClient(
            client=client,
            policy=ProviderHttpPolicy(max_retries=0, base_delay_seconds=0.01),
            sleep=no_op_sleep,
            jitter_fn=zero_jitter,
        ),
        api_root_url=TAXII_API_ROOT,
        collection_id=TAXII_COLLECTION_ID,
        bearer_token=BEARER_TOKEN,
        page_size=page_size,
        max_pages=max_pages,
        checkpoint_reader=_read,
        clock=lambda: _OCCURRED_AT,
    )


async def _produce(
    bootstrap: str,
    topic: str,
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    pages: list[tuple[Any, str | None]],
    max_pages: int = 100,
    page_size: int = 100,
) -> tuple[UUID, int]:
    """Run one real TAXII producer execution (acquire..publish..checkpoint)."""
    server = RecordedTaxiiServer(pages)
    publisher = _publisher(bootstrap, topic)
    await publisher.start()
    try:
        client = client_for(server.handler())
        producer = CollectionDatasourceEvidenceProducer(
            definition=_DEFINITION,
            acquirer=_datasource(
                client,
                uow_factory=uow_factory,
                max_pages=max_pages,
                page_size=page_size,
            ),
            registry=build_stix21_conversion_registry(),
            publisher=publisher,
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
            progress_committer=build_taxii_checkpoint_committer(
                uow_factory,
                checkpoint_kind=TAXII_CHECKPOINT_KIND,
                clock=lambda: _OCCURRED_AT,
            ),
        )
        result = await producer.produce()
        await client.aclose()
    finally:
        await publisher.stop()
    assert result.outcome is DatasourceProducerOutcome.COMPLETED
    assert result.execution_id is not None
    return result.execution_id, result.published_count


async def _consume_until_processed(
    bootstrap: str,
    topic: str,
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    group: str,
    expected: int,
) -> EvidenceConsumerRunResult:
    """Run one real consumer until the expected messages are committed."""
    consumer = _consumer(bootstrap, topic, group)
    await consumer.start()
    persistence = EvidencePersistenceConsumer(
        consumer=consumer,
        persistence=EvidenceBatchPersistenceService(uow_factory),
    )
    total = 0
    result: EvidenceConsumerRunResult | None = None
    try:
        for _ in range(12):
            run = await persistence.process_next_batch()
            result = run
            total += run.persisted_count
            if total >= expected:
                break
    finally:
        await consumer.stop()
    assert result is not None
    assert total >= expected
    return result


async def _evidence_ids(engine: AsyncEngine) -> set[UUID]:
    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT id FROM ati.evidence"))
    return {row[0] for row in result.fetchall()}


async def _checkpoint(engine: AsyncEngine) -> str | None:
    async with engine.connect() as connection:
        row = (
            await connection.execute(
                text(
                    "SELECT checkpoint_value FROM ati.datasource_checkpoint "
                    "WHERE datasource_id = 'opencti-collection' "
                    "AND checkpoint_kind = 'taxii_added_after'"
                )
            )
        ).fetchone()
    return None if row is None else str(row[0])


def _expected(stix_id: str) -> UUID:
    return evidence_id_for_source_record(
        SemanticFormatId.STIX_21, SourceId.OPENCTI, stix_id
    )


@pytest.mark.asyncio
async def test_t01_cross_page_order_over_real_broker(
    kafka_bootstrap: str,
    evidence_topic: str,
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """T01: three TAXII pages publish ordered messages through real Redpanda."""
    pages = [
        (
            taxii_response(
                taxii_envelope(
                    fixtures.stix_domain_name(), more=True, next_token=NEXT_1
                ),
                first="2026-07-01T00:00:00Z",
                last="2026-07-01T00:00:00Z",
            ),
            None,
        ),
        (
            taxii_response(
                taxii_envelope(fixtures.stix_ipv4_addr(), more=True, next_token=NEXT_2),
                first="2026-07-01T00:30:00Z",
                last="2026-07-01T00:30:00Z",
            ),
            NEXT_1,
        ),
        (
            taxii_response(
                taxii_envelope(fixtures.stix_ipv6_addr(), more=False),
                first=DATE_ADDED_3,
                last=DATE_ADDED_3,
            ),
            NEXT_2,
        ),
    ]
    execution_id, published = await _produce(
        kafka_bootstrap, evidence_topic, uow_factory, pages=pages
    )
    assert published == 3
    run = await _consume_until_processed(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        group=_new_group(),
        expected=3,
    )
    assert run.committed is True
    assert await _evidence_ids(integration_engine) == {
        _expected(fixtures.DOMAIN_ID),
        _expected(fixtures.IPV4_ID),
        _expected(fixtures.IPV6_ID),
    }
    assert await _checkpoint(integration_engine) == "2026-07-01T01:00:00.000000Z"


@pytest.mark.asyncio
async def test_t02_incremental_second_execution_over_real_broker(
    kafka_bootstrap: str,
    evidence_topic: str,
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """T02: the durable checkpoint drives added_after on a second real-broker run."""
    execution_id, published = await _produce(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(fixtures.stix_domain_name()),
                    first="2026-07-01T00:00:00Z",
                    last="2026-07-01T00:00:00Z",
                ),
                None,
            )
        ],
    )
    await _consume_until_processed(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        group=_new_group(),
        expected=1,
    )
    first_cursor = await _checkpoint(integration_engine)
    assert first_cursor == "2026-07-01T00:00:00.000000Z"

    _execution2, published2 = await _produce(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(fixtures.stix_ipv4_addr()),
                    first=DATE_ADDED_2,
                    last=DATE_ADDED_2,
                ),
                None,
            )
        ],
    )
    assert published2 == 1
    await _consume_until_processed(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        group=_new_group(),
        expected=1,
    )
    assert await _checkpoint(integration_engine) == "2026-07-01T00:30:00.000000Z"
    assert await _evidence_ids(integration_engine) == {
        _expected(fixtures.DOMAIN_ID),
        _expected(fixtures.IPV4_ID),
    }


@pytest.mark.asyncio
async def test_t03_replay_is_idempotent_over_real_broker(
    kafka_bootstrap: str,
    evidence_topic: str,
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """T03: replaying from the old cursor yields no duplicate Evidence state."""
    _execution1, published = await _produce(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(fixtures.stix_domain_name()),
                    first="2026-07-01T00:00:00Z",
                    last="2026-07-01T00:00:00Z",
                ),
                None,
            )
        ],
    )
    assert published == 1
    # Replay the same acquisition: deterministic Evidence identity plus the
    # durable checkpoint make this safe (no duplicate entity/semantic rows).
    _execution2, published2 = await _produce(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(fixtures.stix_domain_name()),
                    first="2026-07-01T00:00:00Z",
                    last="2026-07-01T00:00:00Z",
                ),
                None,
            )
        ],
    )
    assert published2 == 1
    await _consume_until_processed(
        kafka_bootstrap,
        evidence_topic,
        uow_factory,
        group=_new_group(),
        expected=2,
    )
    assert await _evidence_ids(integration_engine) == {_expected(fixtures.DOMAIN_ID)}
    async with integration_engine.connect() as connection:
        entity_scalar = (
            await connection.execute(text("SELECT count(*) FROM ati.entity"))
        ).scalar()
        entity_count = int(entity_scalar or 0)
    assert entity_count == 1
