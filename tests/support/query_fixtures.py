# SPDX-License-Identifier: AGPL-3.0-only
"""Shared synthetic seeding helpers for the PR 23A query integration tests.

Every helper writes through the normal application repositories/UnitOfWork
seam on the disposable isolated integration database. Direct SQL is used only
to stamp database-assigned timestamps with deterministic values so
pagination tie-break tests are exact.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import text

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

FIXED_TIME = datetime(2026, 1, 1, tzinfo=UTC)
"""Fixed deterministic test epoch shared by PR 23A seeding helpers."""


async def seed_investigation(
    uow: PostgresUnitOfWork,
    *,
    status: InvestigationStatus = InvestigationStatus.RUNNING,
    created_at: datetime = FIXED_TIME,
    root_entity_ids: tuple[UUID, ...] = (),
) -> UUID:
    """Create one investigation and stamp its deterministic created_at."""
    investigation_id = uuid4()
    await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=status,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=list(root_entity_ids) or [uuid4()],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=created_at,
        )
    )
    assert uow.session is not None
    await uow.session.execute(
        text("UPDATE ati.investigation SET created_at = :created_at WHERE id = :id"),
        {"created_at": created_at, "id": investigation_id},
    )
    return investigation_id


async def seed_entity(
    uow: PostgresUnitOfWork,
    *,
    entity_type: EntityType = EntityType.DOMAIN,
    value: str = "example.com",
) -> UUID:
    """Create one canonical entity and return its database identity."""
    entity = await uow.entities.upsert(Entity(type=entity_type, value=value))
    assert entity.id is not None
    return entity.id


def evidence_factory(
    investigation_id: UUID,
    entity_id: UUID,
    *,
    retrieved_at: datetime = FIXED_TIME,
    source: str = "urn:ati:source:google_public_dns",
    evidence_type: EvidenceType = EvidenceType.DNS,
) -> Evidence:
    """Build one deterministic immutable evidence observation."""
    return Evidence(
        investigation_id=investigation_id,
        type=evidence_type,
        subject=EntityRef(id=entity_id, type=EntityType.DOMAIN, value="example.com"),
        source=source,
        retrieved_at=retrieved_at,
        facts={"answers": ["192.0.2.1"]},
    )


async def seed_relationship(
    uow: PostgresUnitOfWork,
    *,
    source_entity_id: UUID,
    target_entity_id: UUID,
    relationship_type: RelationshipType = RelationshipType.RESOLVES_TO,
) -> Relationship:
    """Create or reuse one stable relationship edge."""
    return await uow.relationships.upsert(
        Relationship(
            id=uuid4(),
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            type=relationship_type,
        )
    )


async def seed_observation(
    uow: PostgresUnitOfWork,
    *,
    investigation_id: UUID,
    relationship: Relationship,
    evidence: Evidence,
    retrieved_at: datetime = FIXED_TIME,
    observed_at: datetime | None = None,
) -> RelationshipObservation:
    """Append one immutable relationship observation.

    ``evidence`` must be the recorded observation returned by the Evidence
    repository insert, so its database identity is authoritative.
    """
    if evidence.id is None:
        raise ValueError("evidence must be recorded before appending observations")
    observation = RelationshipObservation(
        id=uuid4(),
        relationship_id=relationship.id,
        evidence_id=evidence.id,
        investigation_id=investigation_id,
        observed_at=observed_at,
        retrieved_at=retrieved_at,
        source=evidence.source,
    )
    return await uow.relationship_observations.append(observation)
