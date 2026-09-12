# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the FastAPI application factory and its lifespan wiring."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

import agentic_threat_investigator.api.app as app_module
from agentic_threat_investigator.config import Settings

from .api.conftest import (
    FakeAuthenticationService,
    FakeQueryBundle,
    FakeSubmissionService,
)


def _fake_composition(disposed: list[bool]) -> Any:
    """Build an ApiComposition double that installs fakes and records disposal."""

    class FakeBootstrap:
        """Bootstrap-admin double with a no-op ensure."""

        async def ensure(self, username: str | None, password: str | None) -> None:
            """Do nothing."""

    class FakeComposition:
        """Composition double replacing the real engine/session wiring."""

        def __init__(self, settings: Settings) -> None:
            """Record nothing; all services come from fakes."""

        def install_services(self, application: Any) -> None:
            """Install the deterministic fakes on the application state."""
            application.state.settings = Settings(public_base_url="http://testserver")
            application.state.authentication = FakeAuthenticationService()
            application.state.submission_service = FakeSubmissionService()
            application.state.query_services_factory = lambda: (
                FakeQueryBundle().as_bundle()
            )

        def bootstrap_admin(self) -> FakeBootstrap:
            """Return the no-op bootstrap double."""
            return FakeBootstrap()

        async def dispose(self) -> None:
            """Record the disposal."""
            disposed.append(True)

    return FakeComposition


def test_factory_app_runs_lifespan_and_health_endpoints(monkeypatch: Any) -> None:
    """The factory app disposes its composition and serves health endpoints."""
    disposed: list[bool] = []
    monkeypatch.setattr(app_module, "ApiComposition", _fake_composition(disposed))
    application = app_module.create_app(Settings())

    with TestClient(application) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").json() == {"status": "ready"}

    assert disposed == [True]


def test_factory_app_installs_the_auth_router(monkeypatch: Any) -> None:
    """The factory app exposes authentication without a database."""
    disposed: list[bool] = []
    monkeypatch.setattr(app_module, "ApiComposition", _fake_composition(disposed))
    application = app_module.create_app(Settings())

    with TestClient(application) as client:
        # The auth router is mounted: /me answers its contract 401 without
        # touching any database because no session cookie is present.
        response = client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


def test_factory_app_requires_csrf_for_creation(monkeypatch: Any) -> None:
    """The factory app mounts the investigations router with CSRF protection."""
    disposed: list[bool] = []
    monkeypatch.setattr(app_module, "ApiComposition", _fake_composition(disposed))
    application = app_module.create_app(Settings())

    with TestClient(application) as client:
        # Authenticate first so the CSRF dependency is reached.
        client.cookies.set("ati_session", "session-token")
        response = client.post(
            "/api/v1/investigations",
            json={
                "indicators": [{"type": "domain", "value": "example.com"}],
                "objective": "assess",
            },
            headers={"Idempotency-Key": "k1"},
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"
