# SPDX-License-Identifier: AGPL-3.0-only
"""Thin PostgreSQL repository adapters for stable identity resources."""

import json
from collections.abc import Sequence
from uuid import UUID

from psycopg.types.json import Jsonb
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    BatchSizeLimitExceededError,
    EntityBatchItem,
    EntityBatchResult,
    EntityRepository,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType, canonicalize

from .models import EntityRow


class PostgresEntityRepository(EntityRepository):
    """Persist entities through the PostgreSQL transaction supplied by a UoW."""

    def __init__(self, session: AsyncSession, batch_size: int = 100) -> None:
        self._session = session
        self._batch_size = batch_size

    @staticmethod
    def _to_domain(row: EntityRow) -> Entity:
        """Convert an ORM row without exposing persistence types."""
        return Entity(
            id=row.id,
            type=EntityType(row.entity_type),
            value=row.canonical_value,
            display_name=row.display_name,
            attributes=row.attributes,
            content_hash=row.content_hash,
            version=row.version,
            deleted_at=row.deleted_at,
            deleted_by_actor_id=row.deleted_by_actor_id,
        )

    async def get_by_identity(
        self, entity_type: str, canonical_value: str, *, include_deleted: bool = False
    ) -> Entity | None:
        """Find an entity by canonicalizing the supplied identity first."""
        entity_kind = EntityType(entity_type)
        normalized_value = canonicalize(entity_kind, canonical_value)
        statement = select(EntityRow).where(
            EntityRow.entity_type == entity_kind.value,
            EntityRow.canonical_value == normalized_value,
        )
        if not include_deleted:
            statement = statement.where(EntityRow.deleted_at.is_(None))
        row = (await self._session.execute(statement)).scalar_one_or_none()
        return None if row is None else self._to_domain(row)

    async def upsert(
        self, entity: Entity, *, expected_version: int | None = None
    ) -> Entity:
        """Invoke the authoritative PostgreSQL entity write function."""
        canonical_value = canonicalize(entity.type, entity.value)
        result = await self._session.execute(
            text(
                """
                SELECT id, version, created FROM ati.upsert_entity(
                    :id, :entity_type, :canonical_value, :display_name,
                    CAST(:attributes AS jsonb), :content_hash, :expected_version
                )
            """
            ),
            {
                "id": entity.id,
                "entity_type": entity.type.value,
                "canonical_value": canonical_value,
                "display_name": entity.display_name,
                "attributes": json.dumps(entity.attributes),
                "content_hash": entity.content_hash,
                "expected_version": expected_version,
            },
        )
        written_id, _version, _created = result.one()
        row = await self._session.get(EntityRow, written_id)
        if row is None:  # pragma: no cover - the function and transaction are atomic
            raise RuntimeError("entity write returned no row")
        return self._to_domain(row)

    async def upsert_batch(
        self, items: Sequence[EntityBatchItem]
    ) -> list[EntityBatchResult]:
        """Serialize and submit a bounded batch to the canonical SQL function."""
        if len(items) > self._batch_size:
            raise BatchSizeLimitExceededError(
                f"entity batch contains {len(items)} items; limit is {self._batch_size}"
            )
        composite_items = []
        for item_number, item in enumerate(items, start=1):
            entity = item.entity
            composite_items.append(
                (
                    item_number,
                    entity.id,
                    entity.type.value,
                    canonicalize(entity.type, entity.value),
                    entity.display_name,
                    Jsonb(entity.attributes),
                    entity.content_hash,
                    item.expected_version,
                )
            )
        result = await self._session.execute(
            text(
                "SELECT ordinal, id, version, outcome FROM ati.upsert_entities(:items)"
            ),
            {"items": composite_items},
        )
        return [
            EntityBatchResult(
                ordinal=row[0],
                entity_id=row[1],
                version=row[2],
                outcome=BatchOutcome(row[3]),
            )
            for row in result.fetchall()
        ]

    async def soft_delete(
        self,
        entity_id: UUID,
        *,
        actor_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Entity:
        """Invoke the authoritative PostgreSQL soft-delete function."""
        result = await self._session.execute(
            text(
                "SELECT id, version FROM ati.soft_delete_entity(:id, :actor, :expected)"
            ),
            {"id": entity_id, "actor": actor_id, "expected": expected_version},
        )
        written_id, _version = result.one()
        row = await self._session.get(EntityRow, written_id)
        if row is None:  # pragma: no cover
            raise RuntimeError("entity delete returned no row")
        return self._to_domain(row)
