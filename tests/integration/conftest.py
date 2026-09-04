# SPDX-License-Identifier: AGPL-3.0-only
"""Shared isolated PostgreSQL fixtures for repository integration tests.

Fixture arguments intentionally reuse fixture names; pytest resolves them by
name, while Pylint otherwise treats them as shadowed module-level functions.
"""

# pylint: disable=redefined-outer-name

import os
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentic_threat_investigator.config import ensure_test_database_safe
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.identity import User, UserRole
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)


def _database_url() -> str:
    """Return the guarded URL supplied by the integration harness."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.fail("DATABASE_URL must point at the isolated integration database")
    ensure_test_database_safe(url)
    return url.replace("postgresql+psycopg://", "postgresql+psycopg_async://", 1)


@pytest_asyncio.fixture(scope="session")
async def integration_engine() -> AsyncIterator[AsyncEngine]:
    """Create one async engine for the isolated migrated database."""
    engine = create_async_engine(_database_url())
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture(scope="session")
def session_factory(
    integration_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Return sessions that are never shared between tests or UoWs."""
    return async_sessionmaker(integration_engine, expire_on_commit=False)


@pytest_asyncio.fixture(autouse=True)
async def reset_application_data(
    integration_engine: AsyncEngine,
) -> AsyncIterator[None]:
    """Clear all mutable application rows while retaining the migrated schema."""
    tables = (
        "ingestion_checkpoint",
        "source_record",
        "session",
        "credential",
        '"user"',
        "assessment",
        "investigation",
        "evidence",
        "relationship_observation",
        "relationship",
        "entity",
        "domain_object_history",
    )
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "TRUNCATE " + ", ".join(f"ati.{table}" for table in tables) + " CASCADE"
            )
        )
    yield


@pytest.fixture
def uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
) -> Iterator[Callable[[], PostgresUnitOfWork]]:
    """Build a fresh transaction boundary for each test operation."""

    def factory() -> PostgresUnitOfWork:
        return PostgresUnitOfWork(session_factory)

    yield factory


def entity_factory(
    *, entity_type: EntityType = EntityType.DOMAIN, value: str = "example.com"
) -> Entity:
    """Build a deterministic valid entity fixture."""
    return Entity(id=uuid4(), type=entity_type, value=value)


def user_factory(
    *, role: UserRole = UserRole.ANALYST, user_id: UUID | None = None
) -> User:
    """Build a user with timezone-aware deterministic test timestamps."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return User(
        id=user_id or uuid4(),
        username=f"user-{uuid4().hex[:8]}",
        role=role,
        created_at=now,
        updated_at=now,
    )
