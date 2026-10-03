# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33C STIX CTI Evidence -> Entity persistence vertical slices (M33C-V01..V07).

The canonical v0.2 STIX collection slice runs every layer through its
production implementation over real PostgreSQL:

```text
synthetic STIX CTI object
 -> real parse_stix21_object (PR 33A)
 -> real Stix21ToEvidenceConverter (PR 33B/33C)
 -> real evidence_message_from_converted/EvidenceMessage V1 codec (PR 28C)
 -> InMemoryEvidenceLog (PR 28D failure-injectable log)
 -> real EvidencePersistenceConsumer (PR 28E)
 -> real evidence_message reconstruction -> real STIX durable extraction
 -> real EvidenceBatchPersistenceService -> real PostgreSQL
```

No TAXII acquisition exists yet (PR 33E); the semantic object enters the
pipeline at the already-parsed/converted message boundary exactly as the
plan's V01 topology states. Only the durable log is in-memory; message
codec, reconstruction, extraction, batch persistence, PostgreSQL, and the
Entity/EvidenceObservationEntity associations are all real.

Matrix IDs M33C-V01..V07: one threat actor Evidence -> Entity persistence,
all five CTI types, same-name/different-ID anti-merge, version continuity /
display-name change, source-namespace separation versus Entity identity,
the multi-leaf Indicator association regression, and generic graph/API
projection with test-only relationship fixtures (never produced by STIX
extraction). Every slice asserts zero Relationships and zero
RelationshipObservations.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
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
    EvidenceConsumerId,
    InMemoryEvidenceLog,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    evidence_message_from_converted,
)
from agentic_threat_investigator.domain.datasource import DatasourceId
from agentic_threat_investigator.domain.evidence import (
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
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support import stix21_fixtures as fixtures

pytestmark = pytest.mark.integration

_OCCURRED_AT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_SOURCE_REFERENCE = "https://taxii.example.test/collections/1/objects/"

_CONVERTER = Stix21ToEvidenceConverter()
"""The one real STIX converter; stateless and shared across the slice."""


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


def _messages(
    *decoded_objects: dict[str, Any],
    source_id: SourceId = SourceId.CISA_KEV,
) -> tuple[EvidenceMessage, ...]:
    """Convert and encode one order of STIX objects into EvidenceMessages."""
    context = _context(source_id)
    converted = tuple(
        item
        for decoded in decoded_objects
        for item in _CONVERTER.convert(parse_stix21_object(decoded), context)
    )
    return tuple(
        evidence_message_from_converted(
            item,
            datasource_execution_id=uuid4(),
            semantic_source=context.semantic_source,
            sequence=sequence,
        )
        for sequence, item in enumerate(converted)
    )


async def _consume(
    uow_factory: Callable[[], PostgresUnitOfWork],
    messages: Sequence[EvidenceMessage],
) -> EvidenceConsumerRunResult:
    """Publish and consume one bounded batch through the real consumer."""
    log = InMemoryEvidenceLog()
    await log.publisher().publish(tuple(messages))
    consumer = EvidencePersistenceConsumer(
        consumer=log.consumer(EvidenceConsumerId("stix-v-slice")),
        persistence=EvidenceBatchPersistenceService(uow_factory),
    )
    run = await consumer.process_next_batch()
    assert run.persisted_count == len(messages)
    assert run.committed is True
    return run


async def _count(engine: AsyncEngine, table: str) -> int:
    """Return the row count of one ati table."""
    async with engine.connect() as connection:
        count = await connection.scalar(text(f"SELECT count(*) FROM ati.{table}"))
    return int(count or 0)


async def _observations(engine: AsyncEngine) -> list[dict[str, Any]]:
    """Return bounded observation rows of the slice, ordered by version."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT o.id, o.evidence_id, o.version, o.facts "
                "FROM ati.evidence_observation o ORDER BY o.version"
            )
        )
        return [
            {
                "id": row[0],
                "evidence_id": row[1],
                "version": row[2],
                "facts": row[3],
            }
            for row in result.fetchall()
        ]


async def _observation_entities(engine: AsyncEngine) -> dict[UUID, list[str]]:
    """Return observation_id -> ordered list of associated canonical values."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT e.evidence_observation_id, ent.canonical_value, ent.entity_type "
                "FROM ati.evidence_observation_entity e "
                "JOIN ati.entity ent ON ent.id = e.entity_id "
                "ORDER BY ent.entity_type, ent.canonical_value"
            )
        )
    grouped: dict[UUID, list[str]] = {}
    for observation_id, value, _entity_type in result.fetchall():
        grouped.setdefault(observation_id, []).append(value)
    return grouped


async def _entities(engine: AsyncEngine) -> list[dict[str, Any]]:
    """Return entity rows of the slice with their display metadata."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT entity_type, canonical_value, display_name "
                "FROM ati.entity ORDER BY entity_type, canonical_value"
            )
        )
    return [
        {
            "type": row[0],
            "value": row[1],
            "display_name": row[2],
        }
        for row in result.fetchall()
    ]


async def _evidence_ids(engine: AsyncEngine) -> set[UUID]:
    """Return the distinct global Evidence ids."""
    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT id FROM ati.evidence"))
    return {row[0] for row in result.fetchall()}


def _expected_evidence_id(
    stix_id: str, source_id: SourceId = SourceId.CISA_KEV
) -> UUID:
    """Return the exact deterministic Evidence identity of one STIX object."""
    return evidence_id_for_source_record(SemanticFormatId.STIX_21, source_id, stix_id)


def _threat_actor_content(
    *, name: str = fixtures.THREAT_ACTOR_NAME, modified: str = "2026-01-02T00:00:00Z"
) -> dict[str, Any]:
    """Build one synthetic threat-actor object with deterministic facts."""
    return fixtures.stix_threat_actor(name=name, modified=modified)


@pytest.mark.asyncio
async def test_v01_threat_actor_evidence_to_entity_persistence(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V01: one threat actor closes the full STIX -> Entity pipeline."""
    message = _messages(_threat_actor_content())[0]
    await _consume(uow_factory, (message,))

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.THREAT_ACTOR_ID)
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 1
    observation = observations[0]
    assert observation["evidence_id"] == _expected_evidence_id(fixtures.THREAT_ACTOR_ID)
    assert observation["version"] == 1
    assert observation["facts"]["cti_entity"] == {
        "type": "threat_actor",
        "value": fixtures.THREAT_ACTOR_ID,
        "display_name": fixtures.THREAT_ACTOR_NAME,
    }
    assert observation["facts"]["iocs"] == []
    entities = await _entities(integration_engine)
    assert entities == [
        {
            "type": "threat_actor",
            "value": fixtures.THREAT_ACTOR_ID,
            "display_name": fixtures.THREAT_ACTOR_NAME,
        }
    ]
    associated = await _observation_entities(integration_engine)
    assert associated == {observation["id"]: [fixtures.THREAT_ACTOR_ID]}
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0


@pytest.mark.asyncio
async def test_v02_all_five_cti_types(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V02: one object of each type persists five typed Entities, zero edges."""
    messages = _messages(
        fixtures.stix_threat_actor(),
        fixtures.stix_campaign(),
        fixtures.stix_intrusion_set(),
        fixtures.stix_tool(),
        fixtures.stix_infrastructure(),
    )
    await _consume(uow_factory, messages)

    entities = await _entities(integration_engine)
    assert len(entities) == 5
    by_type = {entry["type"]: entry for entry in entities}
    assert set(by_type) == {
        "threat_actor",
        "campaign",
        "intrusion_set",
        "tool",
        "infrastructure",
    }
    assert by_type["threat_actor"]["value"] == fixtures.THREAT_ACTOR_ID
    assert by_type["threat_actor"]["display_name"] == fixtures.THREAT_ACTOR_NAME
    assert by_type["campaign"]["value"] == fixtures.CAMPAIGN_ID
    assert by_type["campaign"]["display_name"] == fixtures.CAMPAIGN_NAME
    assert by_type["intrusion_set"]["value"] == fixtures.INTRUSION_SET_ID
    assert by_type["tool"]["value"] == fixtures.TOOL_ID
    assert by_type["infrastructure"]["value"] == fixtures.INFRASTRUCTURE_ID
    observations = await _observations(integration_engine)
    assert len(observations) == 5
    associated = await _observation_entities(integration_engine)
    assert len(associated) == 5
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0


@pytest.mark.asyncio
async def test_v03_same_name_different_identities(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V03: same-name threat actors with different STIX IDs stay distinct."""
    messages = _messages(
        fixtures.stix_threat_actor(),
        fixtures.stix_threat_actor(
            id=fixtures.THREAT_ACTOR_2_ID, name=fixtures.THREAT_ACTOR_NAME
        ),
    )
    await _consume(uow_factory, messages)

    entities = await _entities(integration_engine)
    assert len(entities) == 2
    assert {entry["value"] for entry in entities} == {
        fixtures.THREAT_ACTOR_ID,
        fixtures.THREAT_ACTOR_2_ID,
    }
    assert all(
        entry["display_name"] == fixtures.THREAT_ACTOR_NAME for entry in entities
    )
    assert await _count(integration_engine, "relationship") == 0


@pytest.mark.asyncio
async def test_v04_version_continuity_and_display_name_change(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V04: changed modified/name keeps identity, appends, updates display."""
    first = _messages(_threat_actor_content())[0]
    second = _messages(
        _threat_actor_content(
            name="Renamed Adversary Group", modified="2026-03-01T00:00:00Z"
        )
    )[0]
    await _consume(uow_factory, (first, second))

    # Same Evidence identity; two material versions appended.
    evidence_ids = await _evidence_ids(integration_engine)
    assert evidence_ids == {_expected_evidence_id(fixtures.THREAT_ACTOR_ID)}
    observations = await _observations(integration_engine)
    assert len(observations) == 2
    assert {observation["version"] for observation in observations} == {1, 2}
    # One canonical Entity whose display metadata follows upsert semantics.
    entities = await _entities(integration_engine)
    assert len(entities) == 1
    assert entities[0]["value"] == fixtures.THREAT_ACTOR_ID
    assert entities[0]["display_name"] == "Renamed Adversary Group"
    # Both observations associate to the same canonical Entity.
    associated = await _observation_entities(integration_engine)
    assert set(associated) == {observations[0]["id"], observations[1]["id"]}
    assert all(values == [fixtures.THREAT_ACTOR_ID] for values in associated.values())
    assert await _count(integration_engine, "relationship") == 0


@pytest.mark.asyncio
async def test_v05_source_namespace_separation_vs_entity_identity(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V05: two source namespaces, two Evidences, one shared Entity."""
    cisa = _messages(_threat_actor_content(), source_id=SourceId.CISA_KEV)[0]
    misp_source = _messages(_threat_actor_content(), source_id=SourceId.MISP)[0]
    await _consume(uow_factory, (cisa, misp_source))

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.THREAT_ACTOR_ID, SourceId.CISA_KEV),
        _expected_evidence_id(fixtures.THREAT_ACTOR_ID, SourceId.MISP),
    }
    entities = await _entities(integration_engine)
    assert len(entities) == 1
    assert entities[0]["value"] == fixtures.THREAT_ACTOR_ID
    observations = await _observations(integration_engine)
    assert len(observations) == 2
    associated = await _observation_entities(integration_engine)
    assert set(associated) == {observations[0]["id"], observations[1]["id"]}
    # No inferred cross-source equivalence Relationship was created.
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0


@pytest.mark.asyncio
async def test_v06_multileaf_indicator_entity_association(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """V06: a multi-leaf Indicator associates all represented Entities."""
    pattern = (
        "[domain-name:value = 'a.test' AND ipv4-addr:value = '203.0.113.42' "
        "AND ipv6-addr:value = '2001:db8::42']"
    )
    message = _messages(fixtures.stix_indicator(pattern=pattern))[0]
    await _consume(uow_factory, (message,))

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.INDICATOR_ID)
    }
    entities = await _entities(integration_engine)
    assert {entry["type"] for entry in entities} == {"domain", "ip_address"}
    assert {entry["value"] for entry in entities} == {
        "a.test",
        "203.0.113.42",
        "2001:db8::42",
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 1
    associated = await _observation_entities(integration_engine)
    assert set(associated[observations[0]["id"]]) == {
        "a.test",
        "203.0.113.42",
        "2001:db8::42",
    }
    assert await _count(integration_engine, "relationship") == 0


@pytest.mark.asyncio
async def test_v07_generic_graph_projection_of_cti_types(
    session_factory: Any,
) -> None:
    """V07: CTI Entity types project and filter through the generic graph API.

    The fixture relationship is test setup only, created through the
    existing authoritative persistence APIs; production STIX extraction in
    PR 33C never produces edges.
    """
    from agentic_threat_investigator.domain.entities import EntityType
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )
    from tests.integration.api_helpers import api_client, api_settings, seed_user
    from tests.support.query_fixtures import (
        seed_entity,
        seed_evidence_observation,
        seed_investigation,
        seed_observation,
        seed_relationship,
    )

    await seed_user(session_factory)
    actor_a = fixtures.THREAT_ACTOR_ID
    tool_b = fixtures.TOOL_ID
    actor_c = fixtures.THREAT_ACTOR_2_ID
    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(
            uow,
            entity_type=EntityType.THREAT_ACTOR,
            value=actor_a,
        )
        tool = await seed_entity(uow, entity_type=EntityType.TOOL, value=tool_b)
        other_actor = await seed_entity(
            uow, entity_type=EntityType.THREAT_ACTOR, value=actor_c
        )
        edge_tool = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=tool
        )
        edge_actor = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=other_actor
        )
        for edge in (edge_tool, edge_actor):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )

    base = f"/api/v1/investigations/{investigation_id}/graph/entities/{focal}"
    with api_client(api_settings()) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        assert login.status_code == 200

        # Unfiltered neighborhood projects both new CTI types generically.
        response = client.get(f"{base}/neighborhood")
        assert response.status_code == 200
        body = response.json()
        node_types = {node["entity_type"] for node in body["nodes"]}
        assert node_types == {"threat_actor", "tool"}
        nodes_by_id = {node["entity_id"]: node for node in body["nodes"]}
        assert nodes_by_id[str(tool)]["entity_type"] == "tool"
        assert nodes_by_id[str(tool)]["value"] == tool_b
        assert nodes_by_id[str(other_actor)]["entity_type"] == "threat_actor"
        assert nodes_by_id[str(other_actor)]["value"] == actor_c
        assert len(body["edges"]) == 2
        assert body["truncated"] is False

        # The generic entity-type filter serializes a new wire value and
        # selects only counterparties of that type.
        filtered = client.get(f"{base}/neighborhood?entity_type=threat_actor")
        assert filtered.status_code == 200
        filtered_body = filtered.json()
        filtered_types = {node["entity_type"] for node in filtered_body["nodes"]}
        assert filtered_types == {"threat_actor"}
        assert len(filtered_body["edges"]) == 1
