# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 32D MISP Evidence-pipeline vertical slices over real PostgreSQL (M32D-V01..V05).

The canonical v0.2 MISP collection slice runs every layer through its
production implementation:

```text
deterministic MISP fixture
 -> real ProviderHttpClient boundary (httpx.MockTransport only, no Internet)
 -> real MispDatasource (bounded sequential events/restSearch)
 -> real parse_misp_event
 -> real MispToEvidenceConverter (build_misp_conversion_registry)
 -> CollectionDatasourceEvidenceProducer
 -> EvidenceMessage V1 (PR 28C codec)
 -> InMemoryEvidenceLog
 -> real EvidencePersistenceConsumer
 -> real EvidenceBatchPersistenceService -> real PostgreSQL
```

Only external MISP HTTPS is faked; ATI's acquisition, conversion, message,
publication, durable-log, consumer, batch persistence, PostgreSQL, and
lifecycle architecture are all real. Assertions cover exact lifecycle,
stable Attribute-UUID Evidence identity, exact source/retrieval
provenance, normalized facts with ``raw_payload IS NULL``, canonical
DOMAIN/IP association, the ``domain|ip`` two-Entity observation with zero
invented relationships, unsupported/Object zero-Evidence behavior, and the
complete absence of Investigation admission.
"""

from __future__ import annotations

import json
from collections.abc import Callable
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
    InMemoryEvidenceLog,
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
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from tests.support.misp_fixtures import (
    ATTRIBUTE_UUID,
    COMPOUND_DOMAIN_IP_VALUE,
    DOMAIN_VALUE,
    FIXED_KEY,
    IPV4_VALUE,
    IPV6_VALUE,
    MISP_BASE_URL,
    MISP_REST_SEARCH_ENDPOINT,
    OBJECT_UUID,
    UNSUPPORTED_ATTRIBUTE_TYPE,
    misp_attribute,
    misp_object,
    misp_object_attribute,
    misp_rest_search,
)
from tests.support.provider_http import no_op_sleep, zero_jitter

pytestmark = pytest.mark.integration

_OCCURRED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)
_ATTRIBUTE_OBSERVED_AT = datetime(2023, 11, 14, 22, 15, 0, tzinfo=UTC)

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("misp-live"),
    source_id=SourceId.MISP,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.MISP,
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


async def _produce_and_consume(
    uow_factory: Callable[[], PostgresUnitOfWork],
    payload: dict[str, Any],
) -> tuple[UUID, int]:
    """Run one real MISP collection execution through to real PostgreSQL.

    Returns ``(execution_id, published_count)`` after the real
    ``EvidencePersistenceConsumer`` processed and committed one batch.
    """
    log = InMemoryEvidenceLog()
    async with _client(lambda _request: _json_response(payload)) as client:
        producer = CollectionDatasourceEvidenceProducer(
            definition=_DEFINITION,
            acquirer=_datasource(client),
            registry=build_misp_conversion_registry(),
            publisher=log.publisher(),
            uow_factory=uow_factory,
            clock=lambda: _OCCURRED_AT,
        )
        result = await producer.produce()
    assert result.outcome is DatasourceProducerOutcome.COMPLETED
    assert result.execution_id is not None

    service = EvidenceBatchPersistenceService(uow_factory)
    consumer = EvidencePersistenceConsumer(
        consumer=log.consumer(EvidenceConsumerId("misp-v-slice")),
        persistence=service,
    )
    run = await consumer.process_next_batch()
    # Zero-output publication leaves no durable records, so the consumer's
    # empty poll commits nothing (documented empty-run result); a non-empty
    # publication must commit.
    assert run.committed is (result.published_count > 0)
    return result.execution_id, result.published_count


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


async def _observations(engine: AsyncEngine) -> list[dict[str, Any]]:
    """Return bounded observation rows of the slice."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT o.id, o.evidence_id, o.version, o.source_url, "
                "o.observed_at, o.retrieved_at, o.facts, o.raw_payload "
                "FROM ati.evidence_observation o ORDER BY o.version"
            )
        )
        return [
            {
                "id": row[0],
                "evidence_id": row[1],
                "version": row[2],
                "source_url": row[3],
                "observed_at": row[4],
                "retrieved_at": row[5],
                "facts": row[6],
                "raw_payload": row[7],
            }
            for row in result.fetchall()
        ]


async def _observation_entities(engine: AsyncEngine) -> dict[UUID, set[str]]:
    """Return observation_id -> set of associated entity canonical values."""
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


def _domain_event() -> dict[str, Any]:
    """Build one Event with one supported domain Attribute."""
    return misp_rest_search(
        {
            "Event": {
                "id": "1",
                "uuid": "10f8c2a0-5e54-4a0a-8b5c-2f9cc2ff3b01",
                "info": "MISP domain slice",
                "date": "2023-11-01",
                "timestamp": "1700000000",
                "published": True,
                "distribution": "0",
                "sharing_group_id": "0",
                "threat_level_id": "1",
                "analysis": "2",
                "Attribute": [
                    {
                        "id": "21",
                        "uuid": ATTRIBUTE_UUID,
                        "type": "domain",
                        "category": "Network activity",
                        "value": DOMAIN_VALUE,
                        "timestamp": "1700000100",
                        "to_ids": True,
                        "distribution": "1",
                        "sharing_group_id": "0",
                        "deleted": False,
                        "comment": "",
                    }
                ],
            }
        }
    )


@pytest.mark.asyncio
async def test_v01_domain_attribute_full_pipeline(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V01: one domain Attribute closes the full MISP -> Evidence pipeline."""
    execution_id, published = await _produce_and_consume(uow_factory, _domain_event())
    assert published == 1
    # Exact lifecycle through the real recorder + real PostgreSQL.
    assert await _lifecycle(integration_engine, execution_id) == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    # One global Evidence with the exact Attribute-UUID identity.
    expected_evidence_id = evidence_id_for_source_record(
        SemanticFormatId.MISP, SourceId.MISP, ATTRIBUTE_UUID
    )
    assert await _evidence_ids(integration_engine) == {expected_evidence_id}
    observations = await _observations(integration_engine)
    assert len(observations) == 1
    observation = observations[0]
    assert observation["evidence_id"] == expected_evidence_id
    assert observation["version"] == 1
    # Credential-free provenance and exact source timestamps.
    assert observation["source_url"] == MISP_REST_SEARCH_ENDPOINT
    assert observation["observed_at"] == _ATTRIBUTE_OBSERVED_AT
    assert observation["retrieved_at"] == _OCCURRED_AT
    assert observation["raw_payload"] is None
    # Normalized facts with the canonical IOC and preserved source metadata.
    assert observation["facts"]["iocs"] == [{"type": "domain", "value": DOMAIN_VALUE}]
    assert observation["facts"]["attribute"]["uuid"] == ATTRIBUTE_UUID
    assert observation["facts"]["attribute"]["value"] == DOMAIN_VALUE
    assert observation["facts"]["attribute"]["to_ids"] is True
    assert observation["facts"]["event"]["info"] == "MISP domain slice"
    # Canonical DOMAIN association; zero fabricated relationships.
    entities = await _observation_entities(integration_engine)
    assert entities[observation["id"]] == {DOMAIN_VALUE}
    typed = await _entity_counts(integration_engine)
    assert typed.get("domain") == {DOMAIN_VALUE}
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0
    assert await _count(integration_engine, "investigation_evidence") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 1


@pytest.mark.asyncio
async def test_v02_ipv6_attribute(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V02: an IPv6 ip-src Attribute persists canonical IPv6 provenance."""
    event = _domain_event()
    attribute = event["response"][0]["Event"]["Attribute"][0]
    attribute["type"] = "ip-src"
    attribute["value"] = IPV6_VALUE
    execution_id, published = await _produce_and_consume(uow_factory, event)
    assert published == 1
    assert (await _lifecycle(integration_engine, execution_id))[-1] == "completed"
    observations = await _observations(integration_engine)
    assert len(observations) == 1
    observation = observations[0]
    assert observation["observed_at"] == _ATTRIBUTE_OBSERVED_AT
    assert observation["retrieved_at"] == _OCCURRED_AT
    assert observation["raw_payload"] is None
    assert observation["facts"]["iocs"] == [{"type": "ip_address", "value": IPV6_VALUE}]
    entities = await _observation_entities(integration_engine)
    assert entities[observation["id"]] == {IPV6_VALUE}
    typed = await _entity_counts(integration_engine)
    assert typed.get("ip_address") == {IPV6_VALUE}
    assert await _count(integration_engine, "relationship") == 0


@pytest.mark.asyncio
async def test_v03_domain_ip_compound_preserves_both_entities(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V03: one domain|ip Evidence associates both canonical Entities."""
    event = _domain_event()
    attribute = event["response"][0]["Event"]["Attribute"][0]
    attribute["type"] = "domain|ip"
    attribute["value"] = COMPOUND_DOMAIN_IP_VALUE
    execution_id, published = await _produce_and_consume(uow_factory, event)
    assert published == 1
    assert (await _lifecycle(integration_engine, execution_id))[-1] == "completed"
    observations = await _observations(integration_engine)
    assert len(observations) == 1
    observation = observations[0]
    assert observation["facts"]["iocs"] == [
        {"type": "domain", "value": "example.test"},
        {"type": "ip_address", "value": IPV4_VALUE},
    ]
    entities = await _observation_entities(integration_engine)
    assert entities[observation["id"]] == {"example.test", IPV4_VALUE}
    typed = await _entity_counts(integration_engine)
    assert typed.get("domain") == {"example.test"}
    assert typed.get("ip_address") == {IPV4_VALUE}
    # Co-occurrence never fabricates a DOMAIN<->IP relationship.
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0


@pytest.mark.asyncio
async def test_v04_supported_unsupported_and_object_coexist(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V04: supported Attributes persist; unsupported/Object produce nothing.

    A mixed Event (one supported domain, one unsupported sha256 Attribute,
    one MISP Object with an Object-owned Attribute) must not fail the
    execution and must persist exactly the supported Event-level Evidence.
    """
    payload = misp_rest_search(
        {
            "Event": {
                "id": "1",
                "uuid": "10f8c2a0-5e54-4a0a-8b5c-2f9cc2ff3b01",
                "info": "MISP mixed slice",
                "date": "2023-11-01",
                "timestamp": "1700000000",
                "published": True,
                "distribution": "0",
                "sharing_group_id": "0",
                "threat_level_id": "1",
                "analysis": "2",
                "Attribute": [
                    misp_attribute(type_="domain", value=DOMAIN_VALUE)["Attribute"],
                    misp_attribute(
                        type_=UNSUPPORTED_ATTRIBUTE_TYPE,
                        value="a" * 64,
                        uuid="77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b42",
                    )["Attribute"],
                ],
                "Object": [
                    misp_object(
                        uuid="32fac2a0-7e54-4a0a-ac7d-4f9cc2ff3b03",
                        attributes=(
                            misp_object_attribute(
                                type_="domain",
                                value=DOMAIN_VALUE,
                                uuid="43fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b04",
                            ),
                        ),
                    )["Object"]
                ],
            }
        }
    )
    execution_id, published = await _produce_and_consume(uow_factory, payload)
    assert published == 1
    events = await _lifecycle(integration_engine, execution_id)
    assert events == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    assert await _evidence_ids(integration_engine) == {
        evidence_id_for_source_record(
            SemanticFormatId.MISP, SourceId.MISP, ATTRIBUTE_UUID
        )
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 1
    assert observations[0]["facts"]["iocs"] == [
        {"type": "domain", "value": DOMAIN_VALUE}
    ]
    # The Object and Object-owned Attribute never became Evidence or identity.
    typed = await _entity_counts(integration_engine)
    assert typed == {"domain": {DOMAIN_VALUE}}


@pytest.mark.asyncio
async def test_v05_zero_conversion_unsupported_only(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V05: unsupported-only/Object-only input yields CONVERTED(0)/PUBLISHED(0).

    The execution still completes and no Evidence, Observation, Entity,
    Relationship, or receipt is committed.
    """
    payload = misp_rest_search(
        {
            "Event": {
                "id": "1",
                "uuid": "10f8c2a0-5e54-4a0a-8b5c-2f9cc2ff3b01",
                "info": "MISP zero slice",
                "date": "2023-11-01",
                "timestamp": "1700000000",
                "published": True,
                "distribution": "0",
                "sharing_group_id": "0",
                "threat_level_id": "1",
                "analysis": "2",
                "Attribute": [
                    misp_attribute(
                        type_=UNSUPPORTED_ATTRIBUTE_TYPE,
                        value="a" * 64,
                        uuid="77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b42",
                    )["Attribute"]
                ],
                "Object": [
                    misp_object(
                        uuid=OBJECT_UUID,
                        attributes=(misp_object_attribute(type_="filename"),),
                    )["Object"]
                ],
            }
        }
    )
    execution_id, published = await _produce_and_consume(uow_factory, payload)
    assert published == 0
    assert await _lifecycle(integration_engine, execution_id) == [
        "started",
        "acquired",
        "decoded",
        "converted",
        "published",
        "completed",
    ]
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "evidence_observation") == 0
    assert await _count(integration_engine, "evidence_observation_entity") == 0
    assert await _count(integration_engine, "entity") == 0
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 0
