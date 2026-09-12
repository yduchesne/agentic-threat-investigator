# SPDX-License-Identifier: AGPL-3.0-only
"""Shared helpers for the /api/v1 PostgreSQL integration tests.

These tests exercise the production FastAPI application over real
PostgreSQL. The application lifespan creates its own engine and session
factory (independent of the conftest fixture engine); both point at the same
isolated integration database.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from agentic_threat_investigator.api.app import create_app
from agentic_threat_investigator.app.identity import (
    Argon2idPasswordHasher,
    normalize_username,
)
from agentic_threat_investigator.config import (
    Settings,
    ensure_test_database_safe,
)
from agentic_threat_investigator.domain.identity import User, UserRole
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)


def api_settings() -> Settings:
    """Build the settings the API process uses against the test database."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.fail("DATABASE_URL must point at the isolated integration database")
    ensure_test_database_safe(url)
    return Settings(
        database_url=url,
        public_base_url="http://testserver",
        session_cookie_secure=False,
    )


def api_client(settings: Settings | None = None) -> TestClient:
    """Return a TestClient whose lifespan composes the real API services."""
    return TestClient(create_app(settings or api_settings()))


async def seed_user(
    session_factory: Any,
    *,
    username: str = "alice",
    password: str = "correct horse battery staple",
    role: UserRole = UserRole.ANALYST,
) -> UUID:
    """Seed one user with an Argon2id credential in a short transaction."""
    hasher = Argon2idPasswordHasher()
    now = datetime.now(UTC)
    async with PostgresUnitOfWork(session_factory) as uow:
        user = User(
            id=uuid4(),
            username=normalize_username(username),
            role=role,
            created_at=now,
            updated_at=now,
        )
        await uow.users.create(user)
        await uow.credentials.create(user.id, hasher.hash(password), now)
        return user.id


def csrf_headers(client: TestClient) -> dict[str, str]:
    """Return the CSRF header pair derived from the client's CSRF cookie."""
    token = client.cookies.get("ati_csrf")
    return {"X-CSRF-Token": token, "Origin": "http://testserver"}


def create_payload() -> dict[str, object]:
    """Return the canonical create-Investigation payload used by the tests."""
    return {
        "indicators": [{"type": "domain", "value": "example.com"}],
        "objective": "assess the example domain",
    }
