"""PostgreSQL adapters for relationships, observations, and evidence."""

from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    RelationshipObservationProvenanceError,
    RelationshipObservationRepository,
    RelationshipRepository,
    SoftDeletedIdentityError,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)

from .errors import (
    SQLSTATE_RELATIONSHIP_NOT_FOUND,
    SQLSTATE_RELATIONSHIP_OBSERVATION_PROVENANCE_INVALID,
    SQLSTATE_RELATIONSHIP_SOFT_DELETED,
    SQLSTATE_VERSION_CONFLICT,
    sqlstate,
)
from .evidence_repositories import (
    PostgresEvidenceRepository,  # noqa: F401  (compat re-export)
)
from .models import (
    InvestigationEvidenceRow,
    RelationshipObservationRow,
    RelationshipRow,
)

# One above the Evidence Analyst's accepted observation maximum (1000), so the
# loader's overflow probe (max + 1) is never silently clamped by the
# repository. Exactly this sentinel width is required by the bound contract.
_PROBE_LIMIT_CEILING = 1001


def _relationship(row: RelationshipRow) -> Relationship:
    """Map a relationship row to its domain model."""
    return Relationship(
        id=row.id,
        source_entity_id=row.source_entity_id,
        target_entity_id=row.target_entity_id,
        type=RelationshipType(row.relationship_type_urn),
    )


def _observation(row: RelationshipObservationRow) -> RelationshipObservation:
    """Map an observation row to its immutable domain model."""
    return RelationshipObservation(
        id=row.id,
        relationship_id=row.relationship_id,
        evidence_observation_id=row.evidence_observation_id,
        observed_at=row.observed_at,
        retrieved_at=row.retrieved_at,
        source=row.source,
        confidence=row.confidence,
    )


class PostgresRelationshipRepository(RelationshipRepository):
    """Persist stable relationship identities in the active transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(
        self, relationship_id: UUID, *, include_deleted: bool = False
    ) -> Relationship | None:
        """Return the visible relationship with the given identifier, if any."""
        query = select(RelationshipRow).where(RelationshipRow.id == relationship_id)
        if not include_deleted:
            query = query.where(RelationshipRow.deleted_at.is_(None))
        row = (await self.session.execute(query)).scalar_one_or_none()
        return None if row is None else _relationship(row)

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
        """Create or reuse the edge through the authoritative SQL function.

        The database owns identity resolution, race-safe creation, version
        allocation, and history; this adapter never self-commits and never
        allocates versions in Python. A soft-deleted identity raises the
        approved typed error instead of being silently reused.
        """
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, created FROM ati.upsert_relationship(
                        :source, :target, :type)
                """),
                {
                    "source": relationship.source_entity_id,
                    "target": relationship.target_entity_id,
                    "type": relationship.type.value,
                },
            )
        except DBAPIError as error:
            if sqlstate(error) == SQLSTATE_RELATIONSHIP_SOFT_DELETED:
                raise SoftDeletedIdentityError(
                    "relationship", relationship.id
                ) from error
            raise
        written_id, _version, created = result.one()
        row = await self.session.get(RelationshipRow, written_id)
        if row is None:  # pragma: no cover - the function and transaction are atomic
            raise RuntimeError("relationship write returned no row")
        if (
            expected_version is not None
            and not created
            and row.version != expected_version
        ):
            raise ValueError("stale expected_version")
        return _relationship(row)

    async def soft_delete(
        self,
        relationship_id: UUID,
        *,
        actor_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Relationship:
        """Soft-delete through the authoritative SQL function.

        PostgreSQL owns the version allocation and the immutable DELETE
        history; a missing or already-deleted edge and a stale expected
        version surface as the established typed errors without any extra
        mutation.
        """
        try:
            result = await self.session.execute(
                text(
                    "SELECT id, version FROM ati.soft_delete_relationship("
                    ":id, :actor, :expected)"
                ),
                {
                    "id": relationship_id,
                    "actor": actor_id,
                    "expected": expected_version,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_RELATIONSHIP_NOT_FOUND:
                raise LookupError("relationship not found") from error
            if state == SQLSTATE_VERSION_CONFLICT:
                raise ValueError("stale expected_version") from error
            raise
        written_id, _version = result.one()
        row = (
            await self.session.execute(
                select(RelationshipRow).where(RelationshipRow.id == written_id)
            )
        ).scalar_one()
        return _relationship(row)


class PostgresRelationshipObservationRepository(RelationshipObservationRepository):
    """Append immutable relationship observations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, observation_id: UUID) -> RelationshipObservation | None:
        """Return an immutable observation by its identity."""
        row = await self.session.get(RelationshipObservationRow, observation_id)
        return None if row is None else _observation(row)

    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RelationshipObservation]:
        """Return bounded observations backed by admitted EvidenceObservations.

        The query traverses
        ``relationship_observation.evidence_observation_id ->
        investigation_evidence.evidence_observation_id -> investigation_id``,
        so an observation is returned only when its backing observation is
        exactly admitted to the supplied Investigation. Ordering is
        deterministic: ``retrieved_at``/``observed_at`` descending with a
        stable UUID tie-breaker, matching the documented analyst input order.

        ``limit`` may reach ``_PROBE_LIMIT_CEILING`` (one above the analyst's
        accepted maximum of 1000) so the Evidence Analyst overflow probe never
        silently clamps; a larger limit is rejected rather than reduced.
        """
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        if limit > _PROBE_LIMIT_CEILING:
            raise ValueError(f"limit must not exceed {_PROBE_LIMIT_CEILING}")
        result = await self.session.execute(
            select(RelationshipObservationRow)
            .join(
                InvestigationEvidenceRow,
                InvestigationEvidenceRow.evidence_observation_id
                == RelationshipObservationRow.evidence_observation_id,
            )
            .where(InvestigationEvidenceRow.investigation_id == investigation_id)
            .order_by(
                RelationshipObservationRow.retrieved_at.desc(),
                RelationshipObservationRow.observed_at.desc().nulls_last(),
                RelationshipObservationRow.id.asc(),
            )
            .limit(limit)
            .offset(offset)
        )
        return [_observation(row) for row in result.scalars().all()]

    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        """Append one immutable observation with exact EvidenceObservation provenance.

        The database allocates the version and rejects a missing backing
        observation or relationship; this adapter performs no Python-side
        version allocation and exposes no update or delete path.
        """
        try:
            await self.session.execute(
                text("""
                    SELECT id, version FROM ati.append_relationship_observation(
                        :id, :relationship_id, :evidence_observation_id,
                        :observed_at, :retrieved_at, :source, :confidence)
                """),
                {
                    "id": observation.id,
                    "relationship_id": observation.relationship_id,
                    "evidence_observation_id": observation.evidence_observation_id,
                    "observed_at": observation.observed_at,
                    "retrieved_at": observation.retrieved_at,
                    "source": observation.source,
                    "confidence": observation.confidence,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_RELATIONSHIP_OBSERVATION_PROVENANCE_INVALID:
                raise RelationshipObservationProvenanceError(
                    observation.evidence_observation_id
                ) from error
            if state == SQLSTATE_RELATIONSHIP_NOT_FOUND:
                raise LookupError(
                    f"relationship not found: {observation.relationship_id}"
                ) from error
            raise
        return observation
