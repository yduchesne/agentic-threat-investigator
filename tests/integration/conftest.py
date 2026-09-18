# SPDX-License-Identifier: AGPL-3.0-only
"""Shared isolated PostgreSQL fixtures for repository integration tests.

Fixture arguments intentionally reuse fixture names; pytest resolves them by
name, so the intentional shadowing is not flagged by the enabled Ruff rules.
"""

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
    """Return the guarded URL supplied by the integration harness.

    The isolated database is provisioned by Alembic, whose env.py prepares
    ``SET search_path TO ati, public`` on every migration connection (see
    ``migrations/env.py``). The migrated objects (including the PostGIS
    extension functions) live under the ``ati`` schema, so every test
    connection carries the identical per-connection search path via the DSN
    ``options`` parameter; otherwise unqualified function/type resolution
    (e.g. ``ST_AsEWKT``/``ST_Y`` over ``ati.geometry``) would fail against
    an otherwise correctly migrated database.
    """
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.fail("DATABASE_URL must point at the isolated integration database")
    ensure_test_database_safe(url)
    url = url.replace("postgresql+psycopg://", "postgresql+psycopg_async://", 1)
    separator = "&" if "?" in url else "?"
    if "search_path" not in url:
        url = f"{url}{separator}options=-csearch_path=ati,public"
    return url


@pytest_asyncio.fixture(scope="session")
async def integration_engine() -> AsyncIterator[AsyncEngine]:
    """Create one async engine for the isolated migrated database.

    The isolated database is provisioned by Alembic, whose env.py prepares
    ``SET search_path TO ati, public`` on every migration connection (see
    ``migrations/env.py``). The migrated objects (including the PostGIS
    extension schema) live under ``ati``, so every test session mirrors the
    same per-connection search path contract; otherwise unqualified
    schema-qualified object resolutions (e.g. ``ati.geometry`` reads)
    would fail against an otherwise correctly migrated database.
    """
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
        "assessment_finding_support",
        "assessment_finding",
        "assessment",
        "investigation_report",
        "investigation",
        "investigation_job",
        "api_idempotency",
        "evidence",
        "evidence_observation",
        "evidence_observation_entity",
        "investigation_evidence",
        "relationship_observation",
        "relationship",
        "entity",
        "domain_object_history",
        "investigation_timeline_event",
        "research_result",
        "entity_location",
        "entity_location_observation",
        "geo_resolution",
        "location",
        "datasource_log",
    )
    async with integration_engine.begin() as connection:
        # Migration round-trip tests (test_migration) downgrade the schema
        # mid-suite, so the reset must only truncate tables that currently
        # exist; never fail setup over a deliberately downgraded revision.
        present = {
            row[0]
            for row in await connection.execute(
                text(
                    "SELECT tablename FROM pg_catalog.pg_tables "
                    "WHERE schemaname = 'ati'"
                )
            )
        }
        tables = (
            "ingestion_checkpoint",
            "source_record",
            "session",
            "credential",
            '"user"',
            "assessment_finding_support",
            "assessment_finding",
            "assessment",
            "investigation_report",
            "investigation",
            "investigation_job",
            "api_idempotency",
            "evidence",
            "evidence_observation",
            "evidence_observation_entity",
            "investigation_evidence",
            "relationship_observation",
            "relationship",
            "entity",
            "domain_object_history",
            "investigation_timeline_event",
            "research_result",
            "entity_location",
            "entity_location_observation",
            "geo_resolution",
            "location",
            "datasource_log",
        )
        existing = tuple(name for name in tables if name.strip('"') in present)
        if existing:
            await connection.execute(
                text(
                    "TRUNCATE "
                    + ", ".join(f"ati.{name}" for name in existing)
                    + " CASCADE"
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
