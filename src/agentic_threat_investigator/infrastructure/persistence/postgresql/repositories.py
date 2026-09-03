# SPDX-License-Identifier: AGPL-3.0-only
"""Thin PostgreSQL repository adapters for stable identity resources."""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import EntityRepository
from agentic_threat_investigator.domain.entities import Entity, EntityType, canonicalize

from .models import EntityRow


class PostgresEntityRepository(EntityRepository):
    """Persist entities through the PostgreSQL transaction supplied by a UoW."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _to_domain(row: EntityRow) -> Entity:
        """Convert an ORM row without exposing persistence types."""
        return Entity(
            id=row.id,
            type=EntityType(row.entity_type),
            value=row.canonical_value,
            display_name=row.display_name,
            attributes=row.attributes,
        )

    async def get_by_identity(
        self, entity_type: str, canonical_value: str, *, include_deleted: bool = False
    ) -> Entity | None:
        """Find an entity by its canonical identity."""
        statement = select(EntityRow).where(
            EntityRow.entity_type == entity_type,
            EntityRow.canonical_value == canonical_value,
        )
        if not include_deleted:
            statement = statement.where(EntityRow.deleted_at.is_(None))
        row = (await self._session.execute(statement)).scalar_one_or_none()
        return None if row is None else self._to_domain(row)

    async def upsert(
        self, entity: Entity, *, expected_version: int | None = None
    ) -> Entity:
        """Insert or update an entity in the active transaction."""
        canonical_value = canonicalize(entity.type, entity.value)
        row = (
            await self._session.execute(
                select(EntityRow)
                .where(
                    EntityRow.entity_type == entity.type.value,
                    EntityRow.canonical_value == canonical_value,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if row is None:
            row = EntityRow(
                entity_type=entity.type.value,
                canonical_value=canonical_value,
                display_name=entity.display_name,
                attributes=entity.attributes,
                version=1,
            )
            self._session.add(row)
        else:
            if expected_version is not None and row.version != expected_version:
                raise ValueError("optimistic version conflict")
            row.display_name, row.attributes, row.version = (
                entity.display_name,
                entity.attributes,
                row.version + 1,
            )
        await self._session.flush()
        return self._to_domain(row)

    async def soft_delete(
        self,
        entity_id: UUID,
        *,
        actor_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Entity:
        """Soft-delete an entity while retaining its historical row."""
        row = await self._session.get(EntityRow, entity_id, with_for_update=True)
        if row is None or row.deleted_at is not None:
            raise ValueError("entity not found")
        if expected_version is not None and row.version != expected_version:
            raise ValueError("optimistic version conflict")
        row.deleted_at, row.deleted_by_actor_id, row.version = (
            datetime.now(timezone.utc),
            actor_id,
            row.version + 1,
        )
        await self._session.flush()
        return self._to_domain(row)
