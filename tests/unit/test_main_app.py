# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the FastAPI application factory and its lifespan wiring."""

# Engine doubles intentionally expose only the disposal seam.
# pylint: disable=too-few-public-methods,unused-argument

from typing import Any

from fastapi.testclient import TestClient

import agentic_threat_investigator.main as main_module
from agentic_threat_investigator.config import Settings


def test_factory_app_runs_lifespan_and_health_endpoints(monkeypatch: Any) -> None:
    """The factory app disposes its engine and serves factory health."""
    disposed: list[bool] = []

    class FakeEngine:
        """Engine double recording disposal."""

        async def dispose(self) -> None:
            """Record the disposal."""
            disposed.append(True)

    def fake_factory(settings: Settings) -> Any:
        """Replace the PostgreSQL engine factory for the test."""
        return FakeEngine(), None

    monkeypatch.setattr(main_module, "create_engine_and_session_factory", fake_factory)
    application = main_module.create_app(Settings())

    with TestClient(application) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").json() == {"status": "ready"}

    assert disposed == [True]


def test_factory_app_installs_the_auth_router(monkeypatch: Any) -> None:
    """The factory app exposes the authentication endpoints without a database."""

    class FakeEngine:
        """Engine double with a no-op disposal."""

        async def dispose(self) -> None:
            """Do nothing."""

    monkeypatch.setattr(
        main_module,
        "create_engine_and_session_factory",
        lambda settings: (FakeEngine(), None),
    )
    application = main_module.create_app(Settings())

    with TestClient(application) as client:
        # The auth router is mounted: /me answers its contract 401 without
        # touching the (fake) database because no session cookie is present.
        response = client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_module_app_serves_health_endpoints() -> None:
    """The importable module-level app serves its health endpoints."""
    with TestClient(main_module.app) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").json() == {"status": "ready"}
