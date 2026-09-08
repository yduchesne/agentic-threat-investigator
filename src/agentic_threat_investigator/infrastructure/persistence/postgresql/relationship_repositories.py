"""PostgreSQL adapters for relationships, observations, and evidence."""

import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceDuplicateIdentityError,
    EvidenceRepository,
    RelationshipObservationRepository,
    RelationshipRepository,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)

from .errors import SQLSTATE_EVIDENCE_DUPLICATE, sqlstate
from .models import EntityRow, EvidenceRow, RelationshipObservationRow, RelationshipRow


def _relationship(row: RelationshipRow) -> Relationship:
    """Map a relationship row to its domain model."""
    return Relationship(
        id=row.id,
        source_entity_id=row.source_entity_id,
        target_entity_id=row.target_entity_id,
        type=RelationshipType(row.relationship_type_urn),
    )


class PostgresRelationshipRepository(RelationshipRepository):
    """Persist stable relationship identities in the active transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_identity(
        self,
        source_entity_id: UUID,
        relationship_type: str,
        target_entity_id: UUID,
        *,
        include_deleted: bool = False,
    ) -> Relationship | None:
        """Find an edge by its three-part identity."""
        query = select(RelationshipRow).where(
            RelationshipRow.source_entity_id == source_entity_id,
            RelationshipRow.target_entity_id == target_entity_id,
            RelationshipRow.relationship_type_urn == relationship_type,
        )
        if not include_deleted:
            query = query.where(RelationshipRow.deleted_at.is_(None))
        row = (await self.session.execute(query)).scalar_one_or_none()
        return None if row is None else _relationship(row)

    async def upsert(
        self, relationship: Relationship, *, expected_version: int | None = None
    ) -> Relationship:
        """Insert an edge, or return its existing immutable identity."""
        existing = await self.get_by_identity(
            relationship.source_entity_id,
            relationship.type.value,
            relationship.target_entity_id,
            include_deleted=True,
        )
        if existing is not None:
            row = await self.session.get(RelationshipRow, existing.id)
            if (
                expected_version is not None
                and row is not None
                and row.version != expected_version
            ):
                raise ValueError("stale expected_version")
            return existing
        version = int(
            await self.session.scalar(
                text("SELECT nextval('ati.relationship_version_seq')")
            )
        )
        row = RelationshipRow(
            id=relationship.id,
            source_entity_id=relationship.source_entity_id,
            target_entity_id=relationship.target_entity_id,
            relationship_type_urn=relationship.type.value,
            version=version,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        self.session.add(row)
        await self.session.flush()
        return _relationship(row)

    async def soft_delete(
        self,
        relationship_id: UUID,
        *,
        actor_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Relationship:
        """Soft-delete an edge with optimistic version checking."""
        row = await self.session.get(RelationshipRow, relationship_id)
        if row is None or row.deleted_at is not None:
            raise LookupError("relationship not found")
        if expected_version is not None and row.version != expected_version:
            raise ValueError("stale expected_version")
        row.deleted_at, row.deleted_by_actor_id, row.updated_at, row.version = (
            datetime.now(timezone.utc),
            actor_id,
            datetime.now(timezone.utc),
            row.version + 1,
        )
        await self.session.flush()
        return _relationship(row)


class PostgresRelationshipObservationRepository(
    RelationshipObservationRepository
):  # pylint: disable=too-few-public-methods
    """Append immutable relationship observations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        """Insert an observation with immutable version one."""
        self.session.add(
            RelationshipObservationRow(**observation.model_dump(), version=1)
        )
        await self.session.flush()
        return observation


class PostgresEvidenceRepository(
    EvidenceRepository
):  # pylint: disable=too-few-public-methods
    """Append and read immutable evidence rows in the caller's transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _to_domain(row: EvidenceRow, subject: EntityRow) -> Evidence:
        """Map an evidence row and its subject entity to the domain model."""
        return Evidence(
            id=row.id,
            investigation_id=row.investigation_id,
            type=EvidenceType(row.evidence_type),
            subject=EntityRef(
                id=subject.id,
                type=EntityType(subject.entity_type),
                value=subject.canonical_value,
            ),
            source=row.source,
            source_record_id=row.source_record_id,
            source_url=row.source_url,
            observed_at=row.observed_at,
            retrieved_at=row.retrieved_at,
            facts=row.facts,
            raw_payload=row.raw_payload,
        )

    async def insert(
        self,
        evidence: Evidence,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Evidence:
        """Append evidence through the authoritative database write function.

        The caller resolves the subject entity first; a duplicate evidence
        identity is a typed conflict and never mutates a prior observation.
        """
        if evidence.subject.id is None:
            raise ValueError("evidence subject id is required")
        evidence_id = evidence.id or uuid4()
        try:
            await self.session.execute(
                text("""
                    SELECT id, version FROM ati.append_evidence(
                        :id, :investigation_id, :evidence_type, :subject_entity_id,
                        :source, :source_record_id, :source_url, :observed_at,
                        :retrieved_at, CAST(:facts AS jsonb),
                        CAST(:raw_payload AS jsonb), :actor_id, :request_id)
                """),
                {
                    "id": evidence_id,
                    "investigation_id": evidence.investigation_id,
                    "evidence_type": evidence.type.value,
                    "subject_entity_id": evidence.subject.id,
                    "source": evidence.source,
                    "source_record_id": evidence.source_record_id,
                    "source_url": evidence.source_url,
                    "observed_at": evidence.observed_at,
                    "retrieved_at": evidence.retrieved_at,
                    "facts": json.dumps(thaw_json(evidence.facts)),
                    "raw_payload": (
                        None
                        if evidence.raw_payload is None
                        else json.dumps(thaw_json(evidence.raw_payload))
                    ),
                    "actor_id": actor_id,
                    "request_id": request_id,
                },
            )
        except DBAPIError as error:
            if sqlstate(error) == SQLSTATE_EVIDENCE_DUPLICATE:
                raise EvidenceDuplicateIdentityError(evidence_id) from error
            raise
        return evidence.model_copy(update={"id": evidence_id})

    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        """Return an evidence observation by its immutable identity."""
        result = await self.session.execute(
            select(EvidenceRow, EntityRow)
            .join(EntityRow, EntityRow.id == EvidenceRow.subject_entity_id)
            .where(EvidenceRow.id == evidence_id)
        )
        row = result.first()
        return None if row is None else self._to_domain(row[0], row[1])

    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Evidence]:
        """Return bounded observations in deterministic newest-first order."""
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        limit = min(limit, 1000)
        result = await self.session.execute(
            select(EvidenceRow, EntityRow)
            .join(EntityRow, EntityRow.id == EvidenceRow.subject_entity_id)
            .where(EvidenceRow.investigation_id == investigation_id)
            .order_by(EvidenceRow.retrieved_at.desc(), EvidenceRow.id.asc())
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(row[0], row[1]) for row in result.fetchall()]
