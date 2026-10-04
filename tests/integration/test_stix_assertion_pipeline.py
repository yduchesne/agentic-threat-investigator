# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33D STIX source-assertion vertical slices (M33D-V01..V10).

The canonical v0.2 STIX Relationship/Sighting slice runs every layer through
its production implementation over real PostgreSQL:

```text
synthetic STIX Relationship/Sighting object
 -> real parse_stix21_object (PR 33A)
 -> real Stix21ToEvidenceConverter (PR 33B/33C/33D)
 -> real evidence_message_from_converted/EvidenceMessage V1 codec (PR 28C)
 -> InMemoryEvidenceLog (PR 28D failure-injectable log)
 -> real EvidencePersistenceConsumer (PR 28E)
 -> real durable message reconstruction -> real STIX assertion extraction
 -> real EvidenceBatchPersistenceService -> real PostgreSQL
```

Only the upstream STIX object input is synthetic (ATI-authored fixtures); the
converter, message codec, reconstruction, extractor, consumer, UnitOfWork,
repositories, stored functions, and PostgreSQL are all real.

Matrix IDs M33D-V01..V10: the Relationship complete slice with exact
``RelationshipObservation.evidence_observation_id`` provenance, all four
source-neutral relationship URNs, repeated same-semantic-edge provenance
without collapse, material source-fact updates, semantic-edge mutation under
one stable Evidence identity with historical preservation, the Sighting
complete slice, Sighting version continuity, unsupported-assertion
isolation, source-namespace separation, and atomic batch failure.
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
from agentic_threat_investigator.app.extraction.models import EvidenceExtractionError
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

_RELATIONSHIP_START = "2026-01-05T00:00:00Z"
_RELATIONSHIP_STOP = "2026-02-05T00:00:00Z"


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
        consumer=log.consumer(EvidenceConsumerId("stix-assertion-v-slice")),
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
                "SELECT o.id, o.evidence_id, o.version, o.observed_at, o.facts "
                "FROM ati.evidence_observation o ORDER BY o.version"
            )
        )
    return [
        {
            "id": row[0],
            "evidence_id": row[1],
            "version": row[2],
            "observed_at": row[3],
            "facts": row[4],
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


async def _relationships(engine: AsyncEngine) -> list[dict[str, Any]]:
    """Return relationship rows with resolved source/target canonical values."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT r.relationship_type_urn, se.canonical_value, te.canonical_value "
                "FROM ati.relationship r "
                "JOIN ati.entity se ON se.id = r.source_entity_id "
                "JOIN ati.entity te ON te.id = r.target_entity_id "
                "ORDER BY r.relationship_type_urn, se.canonical_value"
            )
        )
    return [
        {"type": row[0], "source": row[1], "target": row[2]}
        for row in result.fetchall()
    ]


async def _relationship_observations(engine: AsyncEngine) -> list[dict[str, Any]]:
    """Return relationship observation rows with exact provenance."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT o.relationship_id, o.evidence_observation_id, "
                "o.observed_at, o.retrieved_at, o.source "
                "FROM ati.relationship_observation o "
                "ORDER BY o.evidence_observation_id"
            )
        )
    return [
        {
            "relationship_id": row[0],
            "evidence_observation_id": row[1],
            "observed_at": row[2],
            "retrieved_at": row[3],
            "source": row[4],
        }
        for row in result.fetchall()
    ]


def _expected_evidence_id(
    stix_id: str, source_id: SourceId = SourceId.CISA_KEV
) -> UUID:
    """Return the exact deterministic Evidence identity of one STIX object."""
    return evidence_id_for_source_record(SemanticFormatId.STIX_21, source_id, stix_id)


_OTHER_RELATIONSHIP_ID = "relationship--88888888-8888-4888-8888-888888888888"
"""A second stable STIX Relationship object identity (M33D-V03)."""


def _uses(
    *,
    source_ref: str = fixtures.THREAT_ACTOR_ID,
    target_ref: str = fixtures.TOOL_ID,
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic supported ``uses`` Relationship object."""
    return fixtures.stix_relationship(
        relationship_type="uses",
        source_ref=source_ref,
        target_ref=target_ref,
        **overrides,
    )


def _sighting(
    *,
    sighting_of_ref: str = fixtures.THREAT_ACTOR_ID,
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic supported Sighting object."""
    return fixtures.stix_sighting(sighting_of_ref=sighting_of_ref, **overrides)


@pytest.mark.asyncio
async def test_m33d_v01_relationship_complete_slice(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V01: threat actor USES tool closes the full assertion pipeline."""
    message = _messages(_uses())[0]
    await _consume(uow_factory, (message,))

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.RELATIONSHIP_ID)
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 1
    observation = observations[0]
    assert observation["evidence_id"] == _expected_evidence_id(fixtures.RELATIONSHIP_ID)
    assert observation["version"] == 1
    assert observation["observed_at"] is None
    assertion = observation["facts"]["source_assertion"]
    assert assertion["kind"] == "relationship"
    assert assertion["relationship"]["ati_type"] == "urn:ati:relationship:threat:uses"
    assert assertion["relationship"]["source"] == {
        "type": "threat_actor",
        "value": fixtures.THREAT_ACTOR_ID,
    }
    assert assertion["relationship"]["target"] == {
        "type": "tool",
        "value": fixtures.TOOL_ID,
    }

    entities = await _entities(integration_engine)
    assert {entry["value"] for entry in entities} == {
        fixtures.THREAT_ACTOR_ID,
        fixtures.TOOL_ID,
    }
    associated = await _observation_entities(integration_engine)
    assert set(associated[observation["id"]]) == {
        fixtures.THREAT_ACTOR_ID,
        fixtures.TOOL_ID,
    }

    relationships = await _relationships(integration_engine)
    assert relationships == [
        {
            "type": "urn:ati:relationship:threat:uses",
            "source": fixtures.THREAT_ACTOR_ID,
            "target": fixtures.TOOL_ID,
        }
    ]
    ro_rows = await _relationship_observations(integration_engine)
    assert len(ro_rows) == 1
    ro = ro_rows[0]
    # Exact immutable EvidenceObservation provenance, not a transport id.
    assert ro["evidence_observation_id"] == observation["id"]
    assert ro["source"] == SourceId.CISA_KEV.value
    assert ro["observed_at"] is None
    assert ro["retrieved_at"] == _OCCURRED_AT


@pytest.mark.asyncio
async def test_m33d_v02_all_four_relationship_types(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V02: one supported assertion of each of the four URNs persists."""
    messages = _messages(
        _uses(),
        fixtures.stix_relationship(
            relationship_type="targets",
            source_ref=fixtures.CAMPAIGN_ID,
            target_ref=fixtures.INFRASTRUCTURE_ID,
        ),
        fixtures.stix_relationship(
            relationship_type="attributed-to",
            source_ref=fixtures.INTRUSION_SET_ID,
            target_ref=fixtures.THREAT_ACTOR_2_ID,
        ),
        fixtures.stix_relationship(
            relationship_type="controls",
            source_ref=fixtures.THREAT_ACTOR_ID,
            target_ref=fixtures.INFRASTRUCTURE_ID,
        ),
    )
    await _consume(uow_factory, messages)

    relationships = await _relationships(integration_engine)
    assert {row["type"] for row in relationships} == {
        "urn:ati:relationship:threat:uses",
        "urn:ati:relationship:threat:targets",
        "urn:ati:relationship:threat:attributed_to",
        "urn:ati:relationship:threat:controls",
    }
    by_type = {row["type"]: row for row in relationships}
    assert (
        by_type["urn:ati:relationship:threat:uses"]["source"]
        == fixtures.THREAT_ACTOR_ID
    )
    assert by_type["urn:ati:relationship:threat:uses"]["target"] == fixtures.TOOL_ID
    assert (
        by_type["urn:ati:relationship:threat:targets"]["source"] == fixtures.CAMPAIGN_ID
    )
    assert (
        by_type["urn:ati:relationship:threat:targets"]["target"]
        == fixtures.INFRASTRUCTURE_ID
    )
    assert (
        by_type["urn:ati:relationship:threat:attributed_to"]["source"]
        == fixtures.INTRUSION_SET_ID
    )
    assert (
        by_type["urn:ati:relationship:threat:attributed_to"]["target"]
        == fixtures.THREAT_ACTOR_2_ID
    )
    assert (
        by_type["urn:ati:relationship:threat:controls"]["source"]
        == fixtures.THREAT_ACTOR_ID
    )
    assert (
        by_type["urn:ati:relationship:threat:controls"]["target"]
        == fixtures.INFRASTRUCTURE_ID
    )
    observations = await _observations(integration_engine)
    assert len(observations) == 4
    assert await _count(integration_engine, "relationship_observation") == 4


@pytest.mark.asyncio
async def test_m33d_v03_same_edge_two_assertion_objects(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V03: same semantic edge under two Relationship IDs keeps provenance.

    Two distinct STIX Relationship IDs assert the same A USES B edge: two
    Evidence identities, two EvidenceObservations, one stable Relationship,
    and two RelationshipObservations — each pointing at its own supporting
    EvidenceObservation.
    """
    messages = _messages(
        _uses(),
        _uses(id=_OTHER_RELATIONSHIP_ID),  # distinct relationship object id
    )
    await _consume(uow_factory, messages)

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.RELATIONSHIP_ID),
        _expected_evidence_id(_OTHER_RELATIONSHIP_ID),
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 2
    relationships = await _relationships(integration_engine)
    assert len(relationships) == 1
    ro_rows = await _relationship_observations(integration_engine)
    assert len(ro_rows) == 2
    assert {ro["evidence_observation_id"] for ro in ro_rows} == {
        observations[0]["id"],
        observations[1]["id"],
    }
    # Both immutable observations reference the one stable Relationship.
    assert len({ro["relationship_id"] for ro in ro_rows}) == 1


@pytest.mark.asyncio
async def test_m33d_v04_same_id_material_source_fact_update(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V04: same Relationship ID + same edge appends observations."""
    first = _messages(_uses())[0]
    second = _messages(
        _uses(
            modified="2026-03-01T00:00:00Z",
            start_time=_RELATIONSHIP_START,
            stop_time=_RELATIONSHIP_STOP,
        )
    )[0]
    await _consume(uow_factory, (first, second))

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.RELATIONSHIP_ID)
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 2
    assert {observation["version"] for observation in observations} == {1, 2}
    relationships = await _relationships(integration_engine)
    assert len(relationships) == 1
    ro_rows = await _relationship_observations(integration_engine)
    assert len(ro_rows) == 2
    assert {ro["evidence_observation_id"] for ro in ro_rows} == {
        observations[0]["id"],
        observations[1]["id"],
    }


@pytest.mark.asyncio
async def test_m33d_v05_same_id_changed_semantic_edge_preserves_history(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V05: a semantic-edge change under one Evidence identity preserves history.

    Version 1 asserts threat_actor A USES tool B; version 2 (same STIX
    Relationship ID, same Evidence identity) asserts threat_actor A USES
    infrastructure C. PR 33D preserves history: the old Relationship and its
    observation remain queryable, the new edge exists, and nothing is
    deleted or inferred as ended.
    """
    first = _messages(_uses())[0]
    second = _messages(
        _uses(target_ref=fixtures.INFRASTRUCTURE_ID, modified="2026-03-01T00:00:00Z")
    )[0]
    await _consume(uow_factory, (first, second))

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.RELATIONSHIP_ID)
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 2
    relationships = await _relationships(integration_engine)
    assert len(relationships) == 2
    by_target = {row["target"]: row["type"] for row in relationships}
    assert by_target == {
        fixtures.TOOL_ID: "urn:ati:relationship:threat:uses",
        fixtures.INFRASTRUCTURE_ID: "urn:ati:relationship:threat:uses",
    }
    ro_rows = await _relationship_observations(integration_engine)
    assert len(ro_rows) == 2
    # Exact per-observation provenance to distinct historical relationships.
    assert {ro["evidence_observation_id"] for ro in ro_rows} == {
        observations[0]["id"],
        observations[1]["id"],
    }
    assert len({ro["relationship_id"] for ro in ro_rows}) == 2
    # No relationship was soft-deleted or rewritten.
    async with integration_engine.connect() as connection:
        deleted = await connection.scalar(
            text("SELECT count(*) FROM ati.relationship WHERE deleted_at IS NOT NULL")
        )
    assert int(deleted or 0) == 0


@pytest.mark.asyncio
async def test_m33d_v06_sighting_complete_slice(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V06: a supported Sighting persists facts and zero graph edges."""
    message = _messages(
        _sighting(
            first_seen="2026-01-10T00:00:00Z",
            last_seen="2026-01-20T00:00:00Z",
            count=4,
            summary=True,
            where_sighted_refs=["identity--11111111-1111-1111-1111-111111111111"],
            observed_data_refs=["observed-data--11111111-1111-1111-1111-111111111111"],
        )
    )[0]
    await _consume(uow_factory, (message,))

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.SIGHTING_ID)
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 1
    observation = observations[0]
    assert observation["observed_at"] is None
    assertion = observation["facts"]["source_assertion"]
    assert assertion["kind"] == "sighting"
    assert assertion["relationship"] is None
    sighting = assertion["sighting"]
    assert sighting["sighting_of"] == {
        "type": "threat_actor",
        "value": fixtures.THREAT_ACTOR_ID,
    }
    assert sighting["first_seen"] == "2026-01-10T00:00:00Z"
    assert sighting["last_seen"] == "2026-01-20T00:00:00Z"
    assert sighting["count"] == 4
    assert sighting["summary"] is True
    assert sighting["where_sighted_refs"] == [
        "identity--11111111-1111-1111-1111-111111111111"
    ]
    assert sighting["observed_data_refs"] == [
        "observed-data--11111111-1111-1111-1111-111111111111"
    ]

    entities = await _entities(integration_engine)
    assert entities == [
        {
            "type": "threat_actor",
            "value": fixtures.THREAT_ACTOR_ID,
            "display_name": None,
        }
    ]
    associated = await _observation_entities(integration_engine)
    assert associated == {observation["id"]: [fixtures.THREAT_ACTOR_ID]}
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0


@pytest.mark.asyncio
async def test_m33d_v07_sighting_version_continuity(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V07: a later Sighting version appends observations, no edges."""
    first = _messages(_sighting(count=2))[0]
    second = _messages(
        _sighting(
            last_seen="2026-02-01T00:00:00Z", count=9, modified="2026-03-01T00:00:00Z"
        )
    )[0]
    await _consume(uow_factory, (first, second))

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.SIGHTING_ID)
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 2
    assert {observation["version"] for observation in observations} == {1, 2}
    entities = await _entities(integration_engine)
    assert len(entities) == 1
    assert entities[0]["value"] == fixtures.THREAT_ACTOR_ID
    associated = await _observation_entities(integration_engine)
    assert set(associated) == {observations[0]["id"], observations[1]["id"]}
    assert all(values == [fixtures.THREAT_ACTOR_ID] for values in associated.values())
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0


@pytest.mark.asyncio
async def test_m33d_v08_unsupported_assertion_isolation(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V08: only supported objects in a mixed batch produce Evidence."""
    messages = _messages(
        _uses(),
        fixtures.stix_relationship(),  # valid ``indicates`` -> zero
        _sighting(),
        fixtures.stix_sighting(),  # malware Sighting -> zero
    )
    assert len(messages) == 2
    await _consume(uow_factory, messages)

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.RELATIONSHIP_ID),
        _expected_evidence_id(fixtures.SIGHTING_ID),
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 2
    relationships = await _relationships(integration_engine)
    assert len(relationships) == 1
    assert await _count(integration_engine, "relationship_observation") == 1
    # The supported Relationship contributes threat_actor + tool; the
    # supported Sighting sightings the same canonical threat_actor.
    assert await _count(integration_engine, "entity") == 2


@pytest.mark.asyncio
async def test_m33d_v09_source_namespace_separation(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V09: one Relationship ID + edge under two namespaces stays distinct.

    Two Evidence identities and two RelationshipObservations share the one
    canonical Relationship; no cross-source Evidence merge occurs.
    """
    cisa = _messages(_uses(), source_id=SourceId.CISA_KEV)[0]
    misp_source = _messages(_uses(), source_id=SourceId.MISP)[0]
    await _consume(uow_factory, (cisa, misp_source))

    assert await _evidence_ids(integration_engine) == {
        _expected_evidence_id(fixtures.RELATIONSHIP_ID, SourceId.CISA_KEV),
        _expected_evidence_id(fixtures.RELATIONSHIP_ID, SourceId.MISP),
    }
    observations = await _observations(integration_engine)
    assert len(observations) == 2
    relationships = await _relationships(integration_engine)
    assert len(relationships) == 1
    ro_rows = await _relationship_observations(integration_engine)
    assert len(ro_rows) == 2
    assert {ro["source"] for ro in ro_rows} == {
        SourceId.CISA_KEV.value,
        SourceId.MISP.value,
    }
    assert {ro["evidence_observation_id"] for ro in ro_rows} == {
        observations[0]["id"],
        observations[1]["id"],
    }


@pytest.mark.asyncio
async def test_m33d_v10_atomic_failure_no_partial_write(
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """M33D-V10: a tampered assertion in a batch fails atomically with no write.

    The whole prepared batch fails during consumer-side preflight
    (reconstruction/extraction) before the UnitOfWork opens, so zero
    PostgreSQL rows are written.
    """
    valid = _messages(_uses())[0]
    tampered_facts: dict[str, Any] = {
        "stix": {"id": fixtures.RELATIONSHIP_ID, "type": "relationship"},
        "indicator": None,
        "iocs": [],
        "cti_entity": None,
        "source_assertion": {
            "kind": "relationship",
            "relationship": {
                "type": "uses",
                "ati_type": "urn:ati:relationship:threat:targets",  # tampered
                "source": {"type": "threat_actor", "value": fixtures.THREAT_ACTOR_ID},
                "target": {"type": "tool", "value": fixtures.TOOL_ID},
                "start_time": None,
                "stop_time": None,
            },
            "sighting": None,
        },
    }
    tampered_evidence_id = _expected_evidence_id(fixtures.RELATIONSHIP_ID)
    from agentic_threat_investigator.domain.evidence import (
        ConvertedEvidence,
        Evidence,
        EvidenceObservationCandidate,
        EvidenceType,
    )

    tampered_converted = ConvertedEvidence(
        evidence=Evidence(
            id=tampered_evidence_id,
            type=EvidenceType.THREAT_INTELLIGENCE,
            source=SourceId.CISA_KEV.value,
            source_record_id=fixtures.RELATIONSHIP_ID,
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=tampered_evidence_id,
            source_url=_SOURCE_REFERENCE,
            observed_at=None,
            retrieved_at=_OCCURRED_AT,
            facts=tampered_facts,
            raw_payload=None,
        ),
    )
    tampered_message = evidence_message_from_converted(
        tampered_converted,
        datasource_execution_id=uuid4(),
        semantic_source=_context().semantic_source,
        sequence=1,
    )

    log = InMemoryEvidenceLog()
    await log.publisher().publish((valid, tampered_message))
    consumer = EvidencePersistenceConsumer(
        consumer=log.consumer(EvidenceConsumerId("stix-assertion-atomic")),
        persistence=EvidenceBatchPersistenceService(uow_factory),
    )
    # The tampered durable assertion is rejected by deterministic
    # extraction during consumer preflight; nothing reaches PostgreSQL.
    with pytest.raises(EvidenceExtractionError):
        await consumer.process_next_batch()

    # Zero partial PostgreSQL writes: no evidence, entity, relationship, or
    # observation was persisted and no consumer commit could occur.
    assert await _count(integration_engine, "evidence") == 0
    assert await _count(integration_engine, "evidence_observation") == 0
    assert await _count(integration_engine, "entity") == 0
    assert await _count(integration_engine, "relationship") == 0
    assert await _count(integration_engine, "relationship_observation") == 0
    assert await _count(integration_engine, "evidence_message_receipt") == 0
