# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL API authentication/session integration test (23C-I01).

Seeds a real Argon2id user, logs in over HTTP, calls /auth/me, logs out, and
proves the raw session token is never persisted: only its SHA-256 digest is
stored.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from sqlalchemy import text

from agentic_threat_investigator.domain.identity import UserRole
from tests.integration.api_helpers import (
    api_client,
    api_settings,
    csrf_headers,
    seed_user,
)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i01_login_session_round_trip(session_factory: Any) -> None:
    """Login -> me -> logout proves the full session lifecycle over HTTP."""
    user_id = await seed_user(session_factory, role=UserRole.ANALYST)

    with api_client(api_settings()) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )

        assert login.status_code == 200
        body = login.json()
        assert body["id"] == str(user_id)
        assert body["alias"] == "alice"
        assert body["role"] == "analyst"
        set_cookie = login.headers.get("set-cookie", "")
        assert "HttpOnly" in set_cookie

        me = client.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert me.json()["id"] == str(user_id)

        logout = client.post("/api/v1/auth/logout", headers=csrf_headers(client))
        assert logout.status_code == 204

        me_after = client.get("/api/v1/auth/me")
        assert me_after.status_code == 401
        assert me_after.json()["error"]["code"] == "authentication_required"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i01_only_token_digest_is_persisted(
    session_factory: Any, integration_engine: Any
) -> None:
    """The database stores only the SHA-256 digest of the session token."""
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        assert login.status_code == 200
        token = client.cookies.get("ati_session")

    assert token
    async with integration_engine.begin() as connection:
        stored = (
            await connection.execute(text("SELECT token_hash FROM ati.session"))
        ).scalar_one()
    assert stored == hashlib.sha256(token.encode("utf-8")).digest()
    assert stored != token.encode("utf-8")
