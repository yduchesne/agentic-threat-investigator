# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests run against the isolated PostgreSQL container."""

import os
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from agentic_threat_investigator.config import ensure_test_database_safe

EXPECTED_TABLES = {
    "domain_object_history",
    "entity",
    "relationship",
    "relationship_observation",
    "evidence",
    "investigation",
    "assessment",
    "alembic_version",
}

EXPECTED_SEQUENCES = {
    "entity_version_seq",
    "relationship_version_seq",
    "relationship_observation_version_seq",
    "evidence_version_seq",
    "investigation_version_seq",
    "assessment_version_seq",
}

EXPECTED_FUNCTIONS = {"ati_jsonb_diff", "upsert_entity"}


def _test_engine() -> AsyncEngine:
    """Create an engine for the guarded integration test database URL."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.fail("DATABASE_URL must point at the isolated integration test database")
    ensure_test_database_safe(url)
    return create_async_engine(
        url.replace("postgresql+psycopg://", "postgresql+psycopg_async://", 1)
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_upgrade_head_installs_expected_schema() -> None:
    """Alembic head installs the PR 3 tables, sequences, functions, and extension."""
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            tables = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'ati'"
                    )
                )
            }
            sequences = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT sequence_name FROM information_schema.sequences "
                        "WHERE sequence_schema = 'ati'"
                    )
                )
            }
            functions = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT routine_name FROM information_schema.routines "
                        "WHERE routine_schema = 'ati'"
                    )
                )
            }
            extensions = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT e.extname FROM pg_extension e"
                        " JOIN pg_namespace n ON n.oid = e.extnamespace"
                        " WHERE n.nspname = 'ati'"
                    )
                )
            }
    finally:
        await engine.dispose()
    assert EXPECTED_TABLES <= tables
    assert EXPECTED_SEQUENCES <= sequences
    assert EXPECTED_FUNCTIONS <= functions
    # The migration search path installs extensions into the ati schema so all
    # database objects, including pgvector support, live there.
    assert {"vector", "pgcrypto"} <= extensions


@pytest.mark.asyncio
@pytest.mark.integration
async def test_jsonb_diff_semantics() -> None:
    """The shallow diff covers changes, additions, removals, and missing-vs-null."""
    engine = _test_engine()
    try:

        async def diff(old: str, new: str) -> Any:
            """Compute the versioned diff helper result for two JSON states."""
            async with engine.connect() as connection:
                result = await connection.execute(
                    text(
                        "SELECT ati.ati_jsonb_diff(CAST(:old AS jsonb), CAST(:new AS jsonb))"
                    ),
                    {"old": old, "new": new},
                )
                return result.scalar_one()

        assert await diff('{"a": 1}', '{"a": 1}') == {}
        assert await diff('{"a": 1}', '{"a": 2}') == {"a": {"old": 1, "new": 2}}
        assert await diff('{"a": 1}', '{"a": 1, "b": 2}') == {
            "b": {"old": None, "new": 2}
        }
        assert await diff('{"a": 1, "b": 2}', '{"a": 1}') == {
            "b": {"old": 2, "new": None}
        }
        # A missing key and an explicit JSON null remain distinguishable inputs
        # but both surface as JSON null in the old/new slots.
        assert await diff('{"a": 1}', '{"a": 1, "b": null}') == {
            "b": {"old": None, "new": None}
        }
        assert await diff('{"a": null}', '{"a": 1}') == {"a": {"old": None, "new": 1}}
        # Nested values are atomic at the top level.
        assert await diff('{"n": {"x": 1}}', '{"n": {"x": 2}}') == {
            "n": {"old": {"x": 1}, "new": {"x": 2}}
        }
    finally:
        await engine.dispose()
