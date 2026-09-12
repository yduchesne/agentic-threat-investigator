# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23C authentication route tests (R01-R04, U23-U30)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentic_threat_investigator.api.auth_constants import (
    COOKIE_NAME,
)
from agentic_threat_investigator.api.routes.auth import router as auth_router
from agentic_threat_investigator.domain.identity import User, UserRole

from .conftest import (
    FakeAuthenticationService,
    build_test_app,
    csrf_headers,
    login_client,
    make_user,
)


def _auth_app(service: FakeAuthenticationService) -> TestClient:
    """Build an app exposing only the auth router with the fixture service."""
    return build_test_app(authentication=service, routers=(auth_router,))


def test_r01_login_success_sets_cookies_and_returns_public_dto() -> None:
    """A successful login returns 200, HttpOnly cookies, and the public DTO."""
    service = FakeAuthenticationService(
        user=make_user(role=UserRole.ANALYST, username="alice")
    )
    with _auth_app(service) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": " ALICE ", "password": "secret"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(service.user.id)
    assert body["alias"] == "alice"
    assert body["role"] == "analyst"
    set_cookie = response.headers.get("set-cookie", "")
    assert COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie
    assert response.headers.get("x-request-id")


def test_r02_bad_login_returns_stable_401_without_enumeration() -> None:
    """Wrong passwords and unknown users share one stable 401 envelope."""
    service = FakeAuthenticationService()
    with _auth_app(service) as client:
        wrong = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        unknown = client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "anything"},
        )

    for response in (wrong, unknown):
        assert response.status_code == 401
        body = response.json()
        assert body["error"]["code"] == "invalid_credentials"
        assert "alice" not in body["error"]["message"]
    # Unknown-user and wrong-password responses share the identical stable
    # code and message (no username enumeration, no credential echo); only
    # the per-request request ID legitimately differs.
    wrong_error, unknown_error = wrong.json()["error"], unknown.json()["error"]
    assert wrong_error["code"] == unknown_error["code"] == "invalid_credentials"
    assert wrong_error["message"] == unknown_error["message"]


def test_r03_unauthenticated_analytical_route_returns_401() -> None:
    """An analytical route without a session returns 401 authentication_required."""
    with build_test_app() as client:
        response = client.get("/api/v1/investigations")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


def test_r04_unsupported_role_returns_403() -> None:
    """An actor without ANALYST/ADMIN role is forbidden by the dependency."""
    from typing import Any, cast

    from agentic_threat_investigator.api.dependencies import require_analyst
    from agentic_threat_investigator.api.errors import ApiError

    class UnsupportedActor:
        """Actor stub carrying an unsupported role value."""

        role = "observer"

    with pytest.raises(ApiError) as error:
        require_analyst(cast(User, cast(Any, UnsupportedActor())))

    assert error.value.status_code == 403
    assert error.value.code == "forbidden"


def test_u23_valid_password_creates_session() -> None:
    """Login verifies through the service and issues the session cookie."""
    service = FakeAuthenticationService()
    with _auth_app(service) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "secret"},
        )

    assert response.status_code == 200
    assert service.login_calls == [("alice", "secret")]


def test_u24_wrong_password_same_public_failure_as_unknown_user() -> None:
    """Wrong password and unknown user are indistinguishable at the API."""
    service = FakeAuthenticationService()
    with _auth_app(service) as client:
        wrong = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        unknown = client.post(
            "/api/v1/auth/login",
            json={"username": "ghost", "password": "wrong"},
        )

    wrong_error, unknown_error = wrong.json()["error"], unknown.json()["error"]
    assert wrong_error["code"] == unknown_error["code"] == "invalid_credentials"
    assert wrong_error["message"] == unknown_error["message"]


def test_u25_deleted_user_returns_invalid_credentials() -> None:
    """A session for a deleted user validates to None and yields 401."""
    from datetime import UTC, datetime

    service = FakeAuthenticationService()
    service.user = service.user.model_copy(
        update={"deleted_at": datetime(2026, 2, 1, tzinfo=UTC)}
    )
    with _auth_app(service) as client:
        login_client(client)
        response = client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_u26_expired_session_returns_401() -> None:
    """An unknown/expired session token yields 401 authentication_required."""
    service = FakeAuthenticationService()
    with _auth_app(service) as client:
        client.cookies.set(COOKIE_NAME, "expired-token")
        response = client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


def test_u27_analyst_allowed() -> None:
    """ANALYST actors may use investigation endpoints."""
    service = FakeAuthenticationService(user=make_user(role=UserRole.ANALYST))
    with build_test_app(authentication=service) as client:
        login_client(client)
        response = client.get("/api/v1/investigations")

    assert response.status_code == 200


def test_u28_admin_allowed() -> None:
    """ADMIN actors may use investigation endpoints."""
    service = FakeAuthenticationService(user=make_user(role=UserRole.ADMIN))
    with build_test_app(authentication=service) as client:
        login_client(client)
        response = client.get("/api/v1/investigations")

    assert response.status_code == 200


def test_u30_logout_revokes_session_and_expires_cookies() -> None:
    """Logout revokes the session, expires cookies, and returns 204."""
    service = FakeAuthenticationService()
    with _auth_app(service) as client:
        login_client(client)
        response = client.post("/api/v1/auth/logout", headers=csrf_headers())

    assert response.status_code == 204
    assert service.logged_out == ["session-token"]
    assert COOKIE_NAME not in response.cookies


def test_logout_rejects_missing_csrf() -> None:
    """A state-changing logout without CSRF proof fails closed with 403."""
    service = FakeAuthenticationService()
    with _auth_app(service) as client:
        login_client(client, csrf="cookie-token")
        response = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "other"})

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"
    assert service.logged_out == []


def test_me_returns_public_dto() -> None:
    """/auth/me resolves the session to the public user DTO."""
    service = FakeAuthenticationService(
        user=make_user(role=UserRole.ANALYST, username="alice")
    )
    with _auth_app(service) as client:
        login_client(client)
        response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(service.user.id)
    assert body["alias"] == "alice"
    assert body["role"] == "analyst"
    assert "password" not in body
    assert "credential" not in body


def test_login_validation_uses_ati_envelope() -> None:
    """Empty login fields return the stable 422 envelope."""
    with _auth_app(FakeAuthenticationService()) as client:
        response = client.post(
            "/api/v1/auth/login", json={"username": "", "password": ""}
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_cookie_flags_match_settings() -> None:
    """Secure flag follows the profile; HttpOnly and SameSite stay explicit."""
    from agentic_threat_investigator.config import Settings

    insecure = build_test_app(
        authentication=FakeAuthenticationService(),
        settings=Settings(
            public_base_url="http://testserver", session_cookie_secure=False
        ),
        routers=(auth_router,),
    )
    with insecure as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "secret"},
        )
    cookie = response.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "Secure" not in cookie

    secure = build_test_app(
        authentication=FakeAuthenticationService(),
        settings=Settings(
            public_base_url="http://testserver", session_cookie_secure=True
        ),
        routers=(auth_router,),
    )
    with secure as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "secret"},
        )
    assert "Secure" in response.headers.get("set-cookie", "")
