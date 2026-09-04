# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL integration coverage for canonical entity persistence."""

from collections.abc import Callable
from uuid import uuid4

import pytest
from sqlalchemy import text

from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_entity_upsert_canonicalizes_and_records_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Create/update/no-op/delete use database revisions and immutable history."""
    entity_id = uuid4()
    async with uow_factory() as uow:
        created = await uow.entities.upsert(
            Entity(id=entity_id, type=EntityType.DOMAIN, value=" Example.COM. ")
        )
        assert created.id == entity_id
        assert created.value == "example.com"
        assert created.version is not None
        first_version = created.version
        updated = await uow.entities.upsert(
            Entity(
                id=entity_id,
                type=EntityType.DOMAIN,
                value="example.com",
                display_name="Example",
            ),
            expected_version=first_version,
        )
        assert updated.version is not None and updated.version > first_version
        unchanged = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="EXAMPLE.COM", display_name="Example"),
            expected_version=updated.version,
        )
        assert unchanged.version == updated.version
        deleted = await uow.entities.soft_delete(
            entity_id, actor_id=uuid4(), expected_version=updated.version
        )
        assert deleted.deleted_at is not None
        assert await uow.entities.get_by_identity("domain", "example.com") is None
        assert (
            await uow.entities.get_by_identity(
                "domain", "example.com", include_deleted=True
            )
            is not None
        )
        assert uow.session is not None
        history = await uow.session.execute(
            text(
                """SELECT operation FROM ati.domain_object_history
                    WHERE object_type = 'entity' AND object_id = :id
                    ORDER BY version"""
            ),
            {"id": entity_id},
        )
        assert [row[0] for row in history] == ["CREATE", "UPDATE", "DELETE"]
