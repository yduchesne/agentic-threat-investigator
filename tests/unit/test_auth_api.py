# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the contract-pinned authentication endpoints."""

# Test doubles intentionally expose narrow async seams; recorded empty
# sequences are asserted explicitly against the observed values.
# pylint: disable=too-few-public-methods,unused-argument,use-implicit-booleaness-not-comparison

from datetime import datetime, timezone
from typing import Any, cast
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentic_threat_investigator.api.auth import (
    COOKIE_NAME,
    CSRF_COOKIE,
    UserResponse,
    install_authentication,
    router,
)
from agentic_threat_investigator.app.audit import InMemoryAuditEmitter
from agentic_threat_investigator.app.identity import (
    AuthenticationError,
    AuthenticationService,
    RateLimitedError,
)
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.domain.audit import AuditAction, AuditOutcome
from agentic_threat_investigator.domain.identity import User, UserRole


def _user(username: str = "alice") -> User:
    """Build one authenticated domain user fixture."""
    now = datetime.now(timezone.utc)
    return User(
        username=username,
        role=UserRole.ADMIN,
        created_at=now,
        updated_at=now,
    )


class FakeAuthenticationService:
    """Deterministic authentication service double for the API contract."""

    def __init__(self, user: User | None = None, *, rate_limited: bool = False) -> None:
        self.user = user or _user()
        self.rate_limited = rate_limited
        self.logged_out: list[str] = []
        self.audit = InMemoryAuditEmitter()

    async def login(
        self, _username: str, password: str, *, client_address: str | None = None
    ) -> tuple[User, str]:
        """Issue the fixture user unless failure modes are armed."""
        if self.rate_limited:
            raise RateLimitedError("too many attempts")
        if password == "wrong":
            raise AuthenticationError("Invalid username or password.")
        return self.user, "session-token"

    async def logout(self, token: str) -> None:
        """Record the revoked token."""
        self.logged_out.append(token)

    async def validate_session(self, token: str) -> User | None:
        """Accept only the fixture session token."""
        return self.user if token == "session-token" else None


class BrokenAuditEmitter(InMemoryAuditEmitter):
    """Audit double whose emit path fails like a broken sink."""

    async def emit(
        self,
        action: Any,
        outcome: Any,
        actor: Any = None,
        **kwargs: Any,
    ) -> None:
        """Raise so the endpoint must swallow the audit failure."""
        raise RuntimeError("audit sink unavailable")


def _app(service: Any = None, *, with_service: bool = True) -> TestClient:
    """Build the API application with an installed or missing service."""
    application = FastAPI()
    application.include_router(router)
    application.state.settings = Settings()
    if with_service:
        install_authentication(application, cast(AuthenticationService, service))
    return TestClient(application)


def test_login_returns_user_and_sets_cookies() -> None:
    """A successful login issues HttpOnly session and CSRF cookies."""
    with _app(FakeAuthenticationService()) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": " ALICE ", "password": "secret"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["username"] == "alice"
    assert body["user"]["role"] == "admin"
    cookies = response.cookies
    assert cookies.get(COOKIE_NAME) == "session-token"
    assert CSRF_COOKIE in cookies


def test_login_rejects_invalid_credentials() -> None:
    """Credential failures surface the generic 401 message."""
    with _app(FakeAuthenticationService()) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "wrong"},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


def test_login_reports_rate_limiting() -> None:
    """A rate-limited login is reported as HTTP 429."""
    with _app(FakeAuthenticationService(rate_limited=True)) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "secret"},
        )

    assert response.status_code == 429
    assert response.json()["detail"] == "Too many login attempts."


def test_login_rejects_empty_request_fields() -> None:
    """The request DTO requires non-empty username and password."""
    with _app(FakeAuthenticationService()) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "", "password": ""},
        )

    assert response.status_code == 422


def test_endpoints_report_503_without_installed_service() -> None:
    """Requests fail fast when bootstrap never installed a service."""
    with _app(with_service=False) as client:
        login = client.post(
            "/api/v1/auth/login", json={"username": "a", "password": "b"}
        )
        me = client.get("/api/v1/auth/me")

    assert login.status_code == 503
    assert me.status_code == 503


def test_logout_with_valid_csrf_revokes_session() -> None:
    """A same-origin double-submit CSRF proof authorizes logout."""

    service = FakeAuthenticationService()
    with _app(service) as client:
        client.cookies.set(COOKIE_NAME, "session-token")
        client.cookies.set(CSRF_COOKIE, "csrf-token")
        response = client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": "csrf-token", "Origin": "http://localhost:8000"},
        )

    assert response.status_code == 204
    assert service.logged_out == ["session-token"]


def test_logout_without_cookie_is_a_no_op() -> None:
    """Logout without a session cookie still clears cookies."""

    service = FakeAuthenticationService()
    with _app(service) as client:
        response = client.post("/api/v1/auth/logout")

    assert response.status_code == 204
    assert service.logged_out == []


def test_logout_rejects_mismatched_csrf_token() -> None:
    """A forged CSRF proof yields 403 without revoking the session."""

    service = FakeAuthenticationService()
    with _app(service) as client:
        client.cookies.set(COOKIE_NAME, "session-token")
        client.cookies.set(CSRF_COOKIE, "csrf-token")
        response = client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": "forged", "Origin": "http://localhost:8000"},
        )

    assert response.status_code == 403
    assert service.logged_out == []
    assert len(service.audit.events) == 1
    assert service.audit.events[0].action == AuditAction.AUTH_CSRF_REJECTED
    assert service.audit.events[0].outcome == AuditOutcome.DENIED


def test_logout_rejects_cross_site_origin() -> None:
    """An off-site origin is rejected even with matching CSRF tokens."""

    service = FakeAuthenticationService()
    with _app(service) as client:
        client.cookies.set(COOKIE_NAME, "session-token")
        client.cookies.set(CSRF_COOKIE, "csrf-token")
        response = client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": "csrf-token", "Origin": "https://evil.example"},
        )

    assert response.status_code == 403
    assert service.logged_out == []


def test_logout_swallows_audit_sink_failure() -> None:
    """A broken audit sink never changes the security response."""

    service = FakeAuthenticationService()
    service.audit = BrokenAuditEmitter()
    with _app(service) as client:
        client.cookies.set(COOKIE_NAME, "session-token")
        client.cookies.set(CSRF_COOKIE, "csrf-token")
        response = client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": "forged", "Origin": "http://localhost:8000"},
        )

    assert response.status_code == 403


def test_me_returns_the_session_user() -> None:
    """A valid session cookie resolves the authenticated user."""
    with _app(FakeAuthenticationService()) as client:
        client.cookies.set(COOKIE_NAME, "session-token")
        response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert response.json()["username"] == "alice"


def test_me_requires_a_session_cookie() -> None:
    """Missing and invalid session cookies both yield 401."""
    with _app(FakeAuthenticationService()) as client:
        missing = client.get("/api/v1/auth/me")
        client.cookies.set(COOKIE_NAME, "unknown-token")
        invalid = client.get("/api/v1/auth/me")

    assert missing.status_code == 401
    assert invalid.status_code == 401


def test_user_response_hides_internal_fields() -> None:
    """The public DTO exposes only identity-safe fields."""
    user = _user()

    dto = UserResponse.from_domain(user)

    assert set(dto.model_dump()) == {"id", "username", "display_name", "role"}
    assert dto.id == str(user.id)


@pytest.mark.parametrize("role", list(UserRole))
def test_user_response_renders_every_role(role: UserRole) -> None:
    """All roles render without exposing enum internals."""
    now = datetime.now(timezone.utc)
    user = User(username=str(uuid4()), role=role, created_at=now, updated_at=now)
    assert UserResponse.from_domain(user).role == role.value
