# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""OpenCTI interoperability assertion-suite fixtures (PR 33E section 10.9).

The harness (scripts/opencti-integration.sh) starts the isolated interop
topology, seeds the deterministic fake world into real OpenCTI, runs the
real ATI acquisition (TAXII -> converter -> Redpanda -> consumer ->
PostgreSQL), waits on the ingestion-completion barrier
(READY_FOR_ASSERTIONS), and only then runs the tests in this directory
against the durable ATI PostgreSQL of that isolated topology.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable, Iterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentic_threat_investigator.config.settings import ensure_test_database_safe
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)


def _database_url() -> str:
    """Return the guarded ATI PostgreSQL URL of the harness topology."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.fail("DATABASE_URL must point at the isolated interop database")
    if "ati-interop" not in url and "ati-test" not in url and "ati_interop" not in url:
        pytest.fail("interop assertions require an isolated interop database URL")
    ensure_test_database_safe(url)
    return url


@pytest_asyncio.fixture(scope="session")
async def interop_engine() -> AsyncIterator[AsyncEngine]:
    """Create one async engine for the harness-run migrated database."""
    url = _database_url().replace(
        "postgresql+psycopg://", "postgresql+psycopg_async://", 1
    )
    separator = "&" if "?" in url else "?"
    if "search_path" not in url:
        url = f"{url}{separator}options=-csearch_path=ati,public"
    engine = create_async_engine(url)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture(scope="session")
def session_factory(
    interop_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Return sessions that are never shared between tests or UoWs."""
    return async_sessionmaker(interop_engine, expire_on_commit=False)


@pytest.fixture
def uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
) -> Iterator[Callable[[], PostgresUnitOfWork]]:
    """Build a fresh transaction boundary for each test operation."""

    def factory() -> PostgresUnitOfWork:
        return PostgresUnitOfWork(session_factory)

    yield factory
