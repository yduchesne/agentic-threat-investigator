# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL integration regression for PR 22E observation history semantics.

RelationshipObservation is itself the historical record: appending one
observation must create exactly one immutable ``relationship_observation``
row and never a ``domain_object_history`` row for that observation. The
stable Relationship resource and the Evidence resource keep their existing
historization contracts. Covers the PR 22E regression tests I01..I07.
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.models import (
    RelationshipRow,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


async def seed_graph(
    uow: PostgresUnitOfWork,
) -> tuple[UUID, UUID, UUID]:
    """Create one investigation, one evidence row, and one resolved edge.

    Returns the investigation, evidence, and relationship identifiers.
    """
    investigation_id = uuid4()
    await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[uuid4()],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
        )
    )
    source = await uow.entities.upsert(
        Entity(type=EntityType.DOMAIN, value=f"source-{uuid4().hex[:8]}.com")
    )
    target = await uow.entities.upsert(
        Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
    )
    assert source.id is not None and target.id is not None
    evidence = Evidence(
        investigation_id=investigation_id,
        type=EvidenceType.DNS,
        subject=EntityRef(id=source.id, type=EntityType.DOMAIN, value=source.value),
        source="urn:ati:source:google_public_dns",
        retrieved_at=_RETRIEVED_AT,
    )
    evidence = await uow.evidence.insert(evidence)
    assert evidence.id is not None
    relationship = await uow.relationships.upsert(
        Relationship(
            id=uuid4(),
            source_entity_id=source.id,
            target_entity_id=target.id,
            type=RelationshipType.RESOLVES_TO,
        )
    )
    return investigation_id, evidence.id, relationship.id


def observation_factory(
    *,
    relationship_id: UUID,
    evidence_id: UUID,
    investigation_id: UUID | None = None,
    retrieved_at: datetime | None = None,
) -> tuple[RelationshipObservation, UUID]:
    """Build an observation and its deterministic identity for append."""
    observation_id = uuid4()
    return (
        RelationshipObservation(
            id=observation_id,
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            retrieved_at=retrieved_at or _RETRIEVED_AT,
            source="urn:ati:source:google_public_dns",
            confidence=0.9,
        ),
        observation_id,
    )


async def table_count(uow: PostgresUnitOfWork, table: str) -> int:
    """Count every row of one application table in the active UoW."""
    assert uow.session is not None
    result = await uow.session.execute(text(f"SELECT count(*) FROM ati.{table}"))
    return int(result.scalar_one())


async def history_count(
    uow: PostgresUnitOfWork,
    object_type: str,
    object_id: UUID | None = None,
) -> int:
    """Count domain history rows for one object type and optional identity."""
    assert uow.session is not None
    if object_id is None:
        result = await uow.session.execute(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = :object_type"
            ),
            {"object_type": object_type},
        )
    else:
        result = await uow.session.execute(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = :object_type AND object_id = :object_id"
            ),
            {"object_type": object_type, "object_id": object_id},
        )
    return int(result.scalar_one())


@pytest.mark.asyncio
@pytest.mark.integration
async def test_observation_append_creates_no_domain_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """22E-I01: one observation creates exactly one row and no history."""
    async with uow_factory() as uow:
        investigation_id, evidence_id, relationship_id = await seed_graph(uow)
        observation, observation_id = observation_factory(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
        )
        observation_history_before = await history_count(
            uow, "relationship_observation"
        )
        total_history_before = await table_count(uow, "domain_object_history")

        await uow.relationship_observations.append(observation)

        row = await uow.relationship_observations.get_by_id(observation_id)
        assert uow.session is not None
        version = await uow.session.scalar(
            text(
                "SELECT version FROM ati.relationship_observation "
                "WHERE id = :observation_id"
            ),
            {"observation_id": observation_id},
        )
        observation_history_after = await history_count(uow, "relationship_observation")
        total_history_after = await table_count(uow, "domain_object_history")
        observation_history_for_id = await history_count(
            uow, "relationship_observation", observation_id
        )

    assert row is not None and row.id == observation_id
    assert version is not None and version > 0
    # The append added an observation row but no history row: the observation
    # table is the history.
    assert observation_history_before == 0
    assert observation_history_after == 0
    assert total_history_after == total_history_before
    assert observation_history_for_id == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_create_still_writes_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """22E-I02: a new stable Relationship still gets exactly one CREATE history row."""
    async with uow_factory() as uow:
        _investigation_id, _evidence_id, relationship_id = await seed_graph(uow)
        created = await history_count(uow, "relationship", relationship_id)
        assert uow.session is not None
        operation = await uow.session.scalar(
            text(
                "SELECT operation FROM ati.domain_object_history "
                "WHERE object_type = 'relationship' AND object_id = :relationship_id"
            ),
            {"relationship_id": relationship_id},
        )

    assert created == 1
    assert operation == "CREATE"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_reuse_remains_history_noop(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """22E-I03: upserting the same canonical edge reuses id/version and no history."""
    async with uow_factory() as uow:
        _investigation_id, _evidence_id, relationship_id = await seed_graph(uow)
        assert uow.session is not None
        first = await uow.session.get(RelationshipRow, relationship_id)
        assert first is not None

        await uow.relationships.upsert(
            Relationship(
                id=uuid4(),
                source_entity_id=first.source_entity_id,
                target_entity_id=first.target_entity_id,
                type=RelationshipType(first.relationship_type_urn),
            )
        )
        second = await uow.session.get(RelationshipRow, relationship_id)
        assert second is not None
        created_rows = await history_count(uow, "relationship", relationship_id)

    assert second.id == relationship_id
    assert second.version == first.version
    assert created_rows == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_multiple_observations_create_rows_but_no_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """22E-I04: repeated observations append rows; zero observation history rows."""
    async with uow_factory() as uow:
        investigation_id, evidence_id, relationship_id = await seed_graph(uow)
        first, first_id = observation_factory(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            retrieved_at=_RETRIEVED_AT,
        )
        second, second_id = observation_factory(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            retrieved_at=_RETRIEVED_AT + timedelta(minutes=1),
        )
        assert first_id != second_id
        await uow.relationship_observations.append(first)
        await uow.relationship_observations.append(second)
        rows = await uow.relationship_observations.list_for_investigation(
            investigation_id
        )
        assert uow.session is not None
        versions = (
            (
                await uow.session.execute(
                    text(
                        "SELECT version FROM ati.relationship_observation "
                        "WHERE id IN (:first, :second) ORDER BY retrieved_at"
                    ),
                    {"first": first_id, "second": second_id},
                )
            )
            .scalars()
            .all()
        )
        history_for_first = await history_count(
            uow, "relationship_observation", first_id
        )
        history_for_second = await history_count(
            uow, "relationship_observation", second_id
        )

    # Newest retrieval timestamp first, matching the documented ordering.
    assert [row.id for row in rows] == [second_id, first_id]
    assert all(version is not None and version > 0 for version in versions)
    assert len(versions) == 2
    assert history_for_first == 0
    assert history_for_second == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_invalid_observation_append_rolls_back_atomically(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """22E-I05: a dangling-Evidence append aborts with no row and no history."""
    async with uow_factory() as uow:
        investigation_id, evidence_id, relationship_id = await seed_graph(uow)
        valid, _valid_id = observation_factory(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
        )
        await uow.relationship_observations.append(valid)

    async with uow_factory() as uow:
        observations_before = await table_count(uow, "relationship_observation")
        total_history_before = await table_count(uow, "domain_object_history")

        dangling = RelationshipObservation(
            id=uuid4(),
            relationship_id=relationship_id,
            evidence_id=uuid4(),  # no such Evidence row exists
            investigation_id=investigation_id,
            observed_at=None,
            retrieved_at=_RETRIEVED_AT,
            source="urn:ati:source:google_public_dns",
            confidence=0.9,
        )
        with pytest.raises(IntegrityError):
            await uow.relationship_observations.append(dangling)

    async with uow_factory() as uow:
        observations_after = await table_count(uow, "relationship_observation")
        total_history_after = await table_count(uow, "domain_object_history")
        dangling_history = await history_count(
            uow, "relationship_observation", dangling.id
        )
        dangling_row = await uow.relationship_observations.get_by_id(dangling.id)

    # Atomicity is unchanged: the rejected observation left no observation
    # row and no history row behind.
    assert observations_after == observations_before
    assert total_history_after == total_history_before
    assert dangling_history == 0
    assert dangling_row is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_still_writes_create_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """22E-I06: Evidence retains its approved immutable CREATE history contract."""
    async with uow_factory() as uow:
        _investigation_id, evidence_id, _relationship_id = await seed_graph(uow)
        created = await history_count(uow, "evidence", evidence_id)
        assert uow.session is not None
        operation = await uow.session.scalar(
            text(
                "SELECT operation FROM ati.domain_object_history "
                "WHERE object_type = 'evidence' AND object_id = :evidence_id"
            ),
            {"evidence_id": evidence_id},
        )

    assert created == 1
    assert operation == "CREATE"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_migration_preserves_legacy_observation_history_rows(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """22E-I07: upgrading from 0020 keeps legacy rows and stops producing them."""
    alembic_cfg = Config("alembic.ini")
    try:
        command.downgrade(alembic_cfg, "0020_research_execution")

        # Seed the legacy graph with the pre-22E write path (SQL API v0008),
        # which still wrote redundant observation history rows.
        async with uow_factory() as uow:
            investigation_id, evidence_id, relationship_id = await seed_graph(uow)
            legacy, legacy_id = observation_factory(
                relationship_id=relationship_id,
                evidence_id=evidence_id,
                investigation_id=investigation_id,
                retrieved_at=_RETRIEVED_AT,
            )
            await uow.relationship_observations.append(legacy)
            assert await history_count(uow, "relationship_observation", legacy_id) == 1

        command.upgrade(alembic_cfg, "head")

        # The migration is non-destructive: the legacy duplicate history row
        # remains, while a fresh append produces no observation history row.
        async with uow_factory() as uow:
            legacy_history = await history_count(
                uow, "relationship_observation", legacy_id
            )
            _investigation_id, _evidence_id, relationship_id = await seed_graph(uow)
            fresh, fresh_id = observation_factory(
                relationship_id=relationship_id,
                evidence_id=_evidence_id,
                investigation_id=_investigation_id,
                retrieved_at=_RETRIEVED_AT,
            )
            await uow.relationship_observations.append(fresh)
            fresh_history = await history_count(
                uow, "relationship_observation", fresh_id
            )
            observation_rows = await table_count(uow, "relationship_observation")

        assert legacy_history == 1
        assert fresh_id != legacy_id
        assert fresh_history == 0
        assert observation_rows == 2
    finally:
        command.upgrade(alembic_cfg, "head")
