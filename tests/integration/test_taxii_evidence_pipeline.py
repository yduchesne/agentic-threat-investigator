# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E TAXII Evidence-pipeline vertical slices over real PostgreSQL (V01..V14).

The canonical v0.2 TAXII/STIX collection slice runs every layer through its
production implementation:

```text
deterministic TAXII 2.1 wire boundary (httpx.MockTransport only, no Internet)
 -> real ProviderHttpClient boundary (bounded retry/content-type/headers)
 -> real Taxii21Datasource (ordered bounded pagination + date-added checkpoints)
 -> real parse_stix21_object (PR 33A single-object seam, never a Bundle wrap)
 -> real Stix21ToEvidenceConverter (build_stix21_conversion_registry)
 -> CollectionDatasourceEvidenceProducer (post-publication progress committer)
 -> EvidenceMessage V1 (PR 28C codec)
 -> InMemoryEvidenceLog
 -> real EvidencePersistenceConsumer
 -> real EvidenceBatchPersistenceService -> real PostgreSQL
```

Only the external TAXII server is faked; ATI's acquisition, parsing,
conversion, message, publication, durable lifecycle, durable checkpoint
(stored functions), consumer, batch persistence, and PostgreSQL are all
real. Assertions cover IOC/CTI Entity/Relationship/Sighting evidence with
exact identity/provenance, pagination order, the incremental second
execution through the durable checkpoint, the publication-safe failure
ordering, replay idempotency, bounded max-pages windows, atomic later-page
failures, source-namespace separation, and unresolved-reference safety.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

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
    EvidencePersistenceConsumer,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceConsumerId,
    EvidencePublisher,
    InMemoryEvidenceLog,
)
from agentic_threat_investigator.app.evidence_message import EvidenceMessage
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
    format_taxii_timestamp,
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
    DATE_ADDED_1,
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


def _json_response(payload: object, *, status: int = 200) -> httpx.Response:
    """Build one deterministic TAXII JSON response with an explicit body length."""
    return httpx.Response(
        status,
        content=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/taxii+json"},
    )


def _make_reader(
    uow_factory: Callable[[], PostgresUnitOfWork],
    datasource_id: str = "opencti-collection",
) -> Callable[[], Awaitable[DatasourceCheckpoint | None]]:
    """Build the real durable-checkpoint reader over one short committed UoW."""

    async def _read() -> DatasourceCheckpoint | None:
        async with uow_factory() as uow:
            return await uow.datasource_checkpoints.get(
                datasource_id=datasource_id, checkpoint_kind=TAXII_CHECKPOINT_KIND
            )

    return _read


def _datasource(
    client: httpx.AsyncClient,
    *,
    uow_factory: Callable[[], PostgresUnitOfWork],
    datasource_id: str = "opencti-collection",
    max_pages: int = 100,
    page_size: int = 100,
    initial_added_after: str | None = None,
) -> Taxii21Datasource:
    """Build the real TAXII acquirer over the real bounded HTTP client."""
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
        initial_added_after=initial_added_after,
        checkpoint_reader=_make_reader(uow_factory, datasource_id),
        clock=lambda: _OCCURRED_AT,
    )


async def _produce_and_consume(
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    pages: list[tuple[Any, str | None]],
    max_pages: int = 100,
    page_size: int = 100,
    initial_added_after: str | None = None,
    definition: DatasourceDefinition = _DEFINITION,
    checkpoint_committer: Callable[..., Awaitable[None]] | None = None,
    publisher: EvidencePublisher | None = None,
    log: InMemoryEvidenceLog | None = None,
) -> tuple[
    DatasourceProducerOutcome,
    int,
    RecordedTaxiiServer,
    UUID | None,
    tuple[EvidenceMessage, ...],
]:
    """Run one real TAXII collection execution through to real PostgreSQL.

    Returns ``(outcome, published_count, server, execution_id)`` after the
    real ``EvidencePersistenceConsumer`` processed and committed one batch
    (when publication succeeded); ``messages`` is the ordered published tuple.
    Raises when the producer does (publication
    failure, checkpoint-commit failure, lifecycle failure).
    """
    server = RecordedTaxiiServer(pages)
    client = client_for(server.handler())
    datasource = _datasource(
        client,
        uow_factory=uow_factory,
        max_pages=max_pages,
        page_size=page_size,
        initial_added_after=initial_added_after,
    )
    committer = checkpoint_committer or build_taxii_checkpoint_committer(
        uow_factory, checkpoint_kind=TAXII_CHECKPOINT_KIND
    )
    log = log or InMemoryEvidenceLog()
    producer = CollectionDatasourceEvidenceProducer(
        definition=definition,
        acquirer=datasource,
        registry=build_stix21_conversion_registry(),
        publisher=publisher or log.publisher(),
        uow_factory=uow_factory,
        clock=lambda: _OCCURRED_AT,
        progress_committer=committer,
    )
    result = await producer.produce()
    await client.aclose()
    if result.outcome is DatasourceProducerOutcome.COMPLETED:
        service = EvidenceBatchPersistenceService(uow_factory)
        consumer = EvidencePersistenceConsumer(
            consumer=log.consumer(EvidenceConsumerId(f"taxii-v-{result.execution_id}")),
            persistence=service,
        )
        run = await consumer.process_next_batch()
        assert run.committed is (result.published_count > 0)
    messages = await _poll_messages(log)
    return result.outcome, result.published_count, server, result.execution_id, messages


async def _poll_messages(log: InMemoryEvidenceLog) -> tuple[EvidenceMessage, ...]:
    """Return every published message of one log in position order."""
    consumer = log.consumer(EvidenceConsumerId("taxii-v-poller"))
    batch = await consumer.poll(400)
    return tuple(record.message for record in batch.records)


async def _count(engine: AsyncEngine, table: str) -> int:
    """Return the row count of one ati table."""
    async with engine.connect() as connection:
        count = await connection.scalar(text(f"SELECT count(*) FROM ati.{table}"))
    return int(count or 0)


def _expected_evidence_id(stix_id: str, source_id: SourceId = SourceId.OPENCTI) -> UUID:
    """Return the exact deterministic Evidence identity of one STIX object."""
    return evidence_id_for_source_record(SemanticFormatId.STIX_21, source_id, stix_id)


async def _checkpoint_value(
    engine: AsyncEngine, datasource_id: str = "opencti-collection"
) -> str | None:
    """Read the durable TAXII checkpoint value directly from PostgreSQL."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT checkpoint_value FROM ati.datasource_checkpoint "
                "WHERE datasource_id = :ds AND checkpoint_kind = :kind"
            ),
            {"ds": datasource_id, "kind": TAXII_CHECKPOINT_KIND},
        )
        row = result.fetchone()
    return None if row is None else str(row[0])


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


async def _evidence_ids(engine: AsyncEngine) -> set[UUID]:
    """Return the distinct global Evidence ids."""
    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT id FROM ati.evidence"))
    return {row[0] for row in result.fetchall()}


async def _entity_counts(engine: AsyncEngine) -> dict[str, set[str]]:
    """Return entity type -> set of canonical values persisted by the slice."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT ent.entity_type, ent.canonical_value "
                "FROM ati.entity ent ORDER BY ent.canonical_value"
            )
        )
    grouped: dict[str, set[str]] = {}
    for entity_type, value in result.fetchall():
        grouped.setdefault(entity_type, set()).add(value)
    return grouped


async def _relationships(engine: AsyncEngine) -> list[dict[str, Any]]:
    """Return relationship rows of the slice with their canonical endpoints."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT r.relationship_type_urn, s.canonical_value AS src, "
                "t.canonical_value AS dst "
                "FROM ati.relationship r "
                "JOIN ati.entity s ON s.id = r.source_entity_id "
                "JOIN ati.entity t ON t.id = r.target_entity_id "
                "ORDER BY r.relationship_type_urn, s.canonical_value, t.canonical_value"
            )
        )
    return [
        {"type": row[0], "source": row[1], "target": row[2]}
        for row in result.fetchall()
    ]


async def _relationship_observations(engine: AsyncEngine) -> int:
    """Return the number of relationship-observation rows."""
    return await _count(engine, "relationship_observation")


@pytest.mark.asyncio
async def test_v01_ioc_ingestion(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V01: supported domain/IP STIX objects persist IOC Evidence + Entities."""
    outcome, published, server, execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_domain_name(), fixtures.stix_ipv4_addr()
                    ),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            )
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 2
    assert execution_id is not None
    assert await _lifecycle(integration_engine, execution_id) == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.DOMAIN_ID),
        _expected_evidence_id(fixtures.IPV4_ID),
    }
    typed = await _entity_counts(integration_engine)
    assert typed.get("domain") == {fixtures.DOMAIN_VALUE}
    assert typed.get("ip_address") == {fixtures.IPV4_VALUE}
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0
    assert await _checkpoint_value(integration_engine) == format_taxii_timestamp(
        datetime(2026, 7, 1, tzinfo=UTC)
    )


@pytest.mark.asyncio
async def test_v02_cti_entity_ingestion(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V02: the five supported CTI SDO types persist canonical Entities."""
    outcome, published, _server, _execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_threat_actor(),
                        fixtures.stix_campaign(),
                        fixtures.stix_intrusion_set(),
                        fixtures.stix_tool(),
                        fixtures.stix_infrastructure(),
                    ),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            )
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 5
    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(identifier)
        for identifier in (
            fixtures.THREAT_ACTOR_ID,
            fixtures.CAMPAIGN_ID,
            fixtures.INTRUSION_SET_ID,
            fixtures.TOOL_ID,
            fixtures.INFRASTRUCTURE_ID,
        )
    }
    typed = await _entity_counts(integration_engine)
    assert typed.get("threat_actor") == {fixtures.THREAT_ACTOR_ID}
    assert typed.get("campaign") == {fixtures.CAMPAIGN_ID}
    assert typed.get("intrusion_set") == {fixtures.INTRUSION_SET_ID}
    assert typed.get("tool") == {fixtures.TOOL_ID}
    assert typed.get("infrastructure") == {fixtures.INFRASTRUCTURE_ID}


@pytest.mark.asyncio
async def test_v03_relationship_ingestion(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V03: a supported 33D Relationship persists with exact provenance."""
    outcome, published, _server, execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_threat_actor(),
                        fixtures.stix_tool(),
                        fixtures.stix_relationship(
                            relationship_type="uses",
                            source_ref=fixtures.THREAT_ACTOR_ID,
                            target_ref=fixtures.TOOL_ID,
                        ),
                    ),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            )
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 3
    relationships = await _relationships(integration_engine)
    assert relationships == [
        {
            "type": "urn:ati:relationship:threat:uses",
            "source": fixtures.THREAT_ACTOR_ID,
            "target": fixtures.TOOL_ID,
        }
    ]
    # The relationship observation carries the Evidence observation provenance.
    assert await _relationship_observations(integration_engine) == 1
    async with integration_engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT ro.evidence_observation_id FROM ati.relationship_observation ro"
            )
        )
        provenance_observation_ids = {row[0] for row in result.fetchall()}
    assert provenance_observation_ids
    async with integration_engine.connect() as connection:
        result = await connection.execute(
            text("SELECT o.id FROM ati.evidence_observation o")
        )
        observation_ids = {row[0] for row in result.fetchall()}
    assert provenance_observation_ids.issubset(observation_ids)


@pytest.mark.asyncio
async def test_v04_sighting_ingestion(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V04: a Sighting stays Evidence + entity association, zero edges."""
    outcome, published, _server, _execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_threat_actor(),
                        fixtures.stix_sighting(
                            sighting_of_ref=fixtures.THREAT_ACTOR_ID
                        ),
                    ),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            )
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 2
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0
    typed = await _entity_counts(integration_engine)
    assert typed.get("threat_actor") == {fixtures.THREAT_ACTOR_ID}


@pytest.mark.asyncio
async def test_v05_mixed_supported_unsupported(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V05: valid unsupported STIX produces zero Evidence while IOC persists."""
    outcome, published, _server, _execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_domain_name(),
                        fixtures.stix_custom(),
                    ),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            )
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 1
    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.DOMAIN_ID)
    }


@pytest.mark.asyncio
async def test_v06_multi_page_order(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V06: cross-page request order and message sequence preserve source order."""
    outcome, published, server, _execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_domain_name(), more=True, next_token=NEXT_1
                    ),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            ),
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_ipv4_addr(), more=True, next_token=NEXT_2
                    ),
                    first=DATE_ADDED_2,
                    last=DATE_ADDED_2,
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
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 3
    assert [r.query.get("next") for r in server.requests] == [None, NEXT_1, NEXT_2]
    assert [message.source_record_id for message in _messages] == [
        fixtures.DOMAIN_ID,
        fixtures.IPV4_ID,
        fixtures.IPV6_ID,
    ]
    assert [message.sequence for message in _messages] == [0, 1, 2]


@pytest.mark.asyncio
async def test_v07_incremental_second_execution(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V07: the second execution sends added_after and ingests only additions."""
    outcome, published, server, _execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(fixtures.stix_domain_name()),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            )
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 1
    first_cursor = await _checkpoint_value(integration_engine)
    assert first_cursor == format_taxii_timestamp(datetime(2026, 7, 1, tzinfo=UTC))

    (
        outcome2,
        published2,
        server2,
        _execution_id2,
        _messages2,
    ) = await _produce_and_consume(
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
    assert outcome2 is DatasourceProducerOutcome.COMPLETED
    assert published2 == 1
    assert server2.requests[0].query["added_after"] == first_cursor
    assert await _checkpoint_value(integration_engine) == format_taxii_timestamp(
        datetime(2026, 7, 1, 0, 30, 0, tzinfo=UTC)
    )
    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.DOMAIN_ID),
        _expected_evidence_id(fixtures.IPV4_ID),
    }


@pytest.mark.asyncio
async def test_v08_publication_failure_does_not_advance(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V08: a publisher failure leaves the checkpoint and terminal state intact."""

    class _FailingPublisher(EvidencePublisher):
        async def publish(self, messages: Sequence[EvidenceMessage]) -> Any:
            raise RuntimeError("injected publication failure")

    with pytest.raises(RuntimeError):
        await _produce_and_consume(
            uow_factory,
            pages=[
                (
                    taxii_response(
                        taxii_envelope(fixtures.stix_domain_name()),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ],
            publisher=_FailingPublisher(),
        )
    # The durable checkpoint was never created.
    assert await _checkpoint_value(integration_engine) is None
    assert await _count(integration_engine, "evidence") == 0


@pytest.mark.asyncio
async def test_v09_checkpoint_commit_failure_after_publication(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V09: checkpoint failure after publish keeps old state; replay is legal."""

    async def _failing_committer(datasource_id: DatasourceId, progress: object) -> None:
        raise RuntimeError("injected checkpoint commit failure")

    log = InMemoryEvidenceLog()
    with pytest.raises(RuntimeError):
        await _produce_and_consume(
            uow_factory,
            pages=[
                (
                    taxii_response(
                        taxii_envelope(fixtures.stix_domain_name()),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ],
            checkpoint_committer=_failing_committer,
            log=log,
        )
    assert await _checkpoint_value(integration_engine) is None
    # Broker data was not rolled back: the message was published exactly once.
    assert len(await _poll_messages(log)) == 1


@pytest.mark.asyncio
async def test_v10_replay_idempotency(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V10: a rerun from the old checkpoint replays safely with stable identity."""

    async def _failing_committer(datasource_id: DatasourceId, progress: object) -> None:
        raise RuntimeError("injected checkpoint commit failure")

    log = InMemoryEvidenceLog()
    with pytest.raises(RuntimeError):
        await _produce_and_consume(
            uow_factory,
            pages=[
                (
                    taxii_response(
                        taxii_envelope(fixtures.stix_domain_name()),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ],
            checkpoint_committer=_failing_committer,
            log=log,
        )
    # The failed commit never advanced: exactly one message reached the broker
    # and the durable checkpoint still reads None.
    assert len(await _poll_messages(log)) == 1
    assert await _checkpoint_value(integration_engine) is None

    # Rerun with the REAL committer: the durable checkpoint advances and the
    # deterministic Evidence identity prevents semantic duplication.
    outcome, published, _server, _execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(fixtures.stix_domain_name()),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            )
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 1
    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.DOMAIN_ID)
    }
    assert await _count(integration_engine, "entity") == 1
    assert await _checkpoint_value(integration_engine) == format_taxii_timestamp(
        datetime(2026, 7, 1, tzinfo=UTC)
    )


@pytest.mark.asyncio
async def test_v11_max_pages_bounded_window(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V11: max-pages stops bounded and advances only through admitted pages."""
    outcome, published, server, _execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_domain_name(), more=True, next_token=NEXT_1
                    ),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            ),
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_ipv4_addr(), more=True, next_token=NEXT_2
                    ),
                    first=DATE_ADDED_2,
                    last=DATE_ADDED_2,
                ),
                NEXT_1,
            ),
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_ipv6_addr(), more=True, next_token="more"
                    ),
                    first=DATE_ADDED_3,
                    last=DATE_ADDED_3,
                ),
                NEXT_2,
            ),
        ],
        max_pages=2,
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 2
    assert len(server.requests) == 2
    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.DOMAIN_ID),
        _expected_evidence_id(fixtures.IPV4_ID),
    }
    assert await _checkpoint_value(integration_engine) == format_taxii_timestamp(
        datetime(2026, 7, 1, 0, 30, 0, tzinfo=UTC)
    )


@pytest.mark.asyncio
async def test_v12_malformed_later_page_atomic(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V12: a malformed later page publishes zero messages, checkpoint unchanged."""
    outcome, published, server, execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_domain_name(), more=True, next_token=NEXT_1
                    ),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            ),
            (_json_response({"objects": "nope"}), NEXT_1),
        ],
    )
    assert outcome is DatasourceProducerOutcome.FAILED
    assert published == 0
    assert execution_id is not None
    lifecycle = await _lifecycle(integration_engine, execution_id)
    assert lifecycle[-1] == "failed"
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 0
    assert await _checkpoint_value(integration_engine) is None


@pytest.mark.asyncio
async def test_v13_source_namespace_separation(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V13: same STIX object ID in two sources: separate Evidence, shared Entity."""
    second_definition = DatasourceDefinition(
        datasource_id=DatasourceId("commercial-tip"),
        source_id=SourceId.CISA_KEV,
        protocol=DatasourceProtocol.TAXII_21,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.STIX_21,
    )
    outcome, published, _server, _execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(fixtures.stix_domain_name()),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            )
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    (
        outcome2,
        published2,
        _server2,
        _execution_id2,
        _messages2,
    ) = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(fixtures.stix_domain_name()),
                    first=DATE_ADDED_2,
                    last=DATE_ADDED_2,
                ),
                None,
            )
        ],
        definition=second_definition,
    )
    assert outcome2 is DatasourceProducerOutcome.COMPLETED
    assert published2 == 1
    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.DOMAIN_ID, SourceId.OPENCTI),
        _expected_evidence_id(fixtures.DOMAIN_ID, SourceId.CISA_KEV),
    }
    typed = await _entity_counts(integration_engine)
    assert typed.get("domain") == {fixtures.DOMAIN_VALUE}
    assert await _count(integration_engine, "entity") == 1


@pytest.mark.asyncio
async def test_v14_unresolved_reference_safety(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V14: an unresolved reference creates no placeholder Entity or edge."""
    outcome, published, _server, _execution_id, _messages = await _produce_and_consume(
        uow_factory,
        pages=[
            (
                taxii_response(
                    taxii_envelope(
                        fixtures.stix_threat_actor(),
                        # Valid STIX relationship whose target (malware) is
                        # outside the 33D reconstructible-endpoint profile.
                        fixtures.stix_relationship(
                            relationship_type="uses",
                            source_ref=fixtures.THREAT_ACTOR_ID,
                            target_ref=fixtures.MALWARE_ID,
                        ),
                    ),
                    first=DATE_ADDED_1,
                    last=DATE_ADDED_1,
                ),
                None,
            )
        ],
    )
    assert outcome is DatasourceProducerOutcome.COMPLETED
    assert published == 1  # only the threat actor produced Evidence
    typed = await _entity_counts(integration_engine)
    assert typed.get("threat_actor") == {fixtures.THREAT_ACTOR_ID}
    assert set(typed.keys()) == {"threat_actor"}
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0
