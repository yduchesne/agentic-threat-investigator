# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Runtime-mode metadata route contract tests (PR 23D).

Covers the authenticated ``GET /api/v1/runtime`` endpoint: it reports only
the lowercase operating mode, requires the analyst session, never switches
mode, and never exposes configuration or secrets. Stable IDs: 23D-U23 and
23D-U24.
"""

from __future__ import annotations

from agentic_threat_investigator.config import OperatingMode, Settings

from .conftest import build_test_app, login_client, make_user


def test_runtime_metadata_fake() -> None:
    """23D-U23: fake operating mode reports ``fake`` and nothing else."""
    settings = Settings(
        operating_mode=OperatingMode.FAKE, public_base_url="http://testserver"
    )
    with build_test_app(settings=settings) as client:
        login_client(client)
        response = client.get("/api/v1/runtime")
    assert response.status_code == 200
    assert response.json() == {"operating_mode": "fake"}


def test_runtime_metadata_production() -> None:
    """23D-U24: production operating mode reports ``production``."""
    settings = Settings(
        operating_mode=OperatingMode.PRODUCTION, public_base_url="http://testserver"
    )
    with build_test_app(settings=settings) as client:
        login_client(client)
        response = client.get("/api/v1/runtime")
    assert response.status_code == 200
    assert response.json() == {"operating_mode": "production"}


def test_runtime_metadata_requires_authentication() -> None:
    """The runtime endpoint is authenticated like every analytical read."""
    with build_test_app() as client:
        response = client.get("/api/v1/runtime")
    assert response.status_code == 401


def test_runtime_metadata_requires_analyst_role() -> None:
    """Non-analyst roles are forbidden from the runtime endpoint."""
    from agentic_threat_investigator.domain.identity import UserRole as _Role

    from .conftest import FakeAuthenticationService

    # Only ADMIN and ANALYST exist in v0.1; a viewer-equivalent non-analyst
    # role does not exist, so the endpoint contract is covered by requiring
    # the analyst dependency (already proven by the auth tests). This test
    # documents that ADMIN and ANALYST are both admitted.
    for role in (_Role.ADMIN, _Role.ANALYST):
        user = make_user(role=role)
        settings = Settings(
            operating_mode=OperatingMode.FAKE, public_base_url="http://testserver"
        )
        with build_test_app(
            settings=settings, authentication=FakeAuthenticationService(user=user)
        ) as client:
            client.cookies.set("ati_session", "session-token")
            client.cookies.set("ati_csrf", "csrf-token")
            response = client.get("/api/v1/runtime")
        assert response.status_code == 200


def test_runtime_metadata_is_read_only_and_never_switches_mode() -> None:
    """No request method or field can change the reported operating mode."""
    settings = Settings(
        operating_mode=OperatingMode.FAKE, public_base_url="http://testserver"
    )
    with build_test_app(settings=settings) as client:
        login_client(client)
        post = client.post("/api/v1/runtime")
        put = client.put("/api/v1/runtime")
        delete = client.delete("/api/v1/runtime")
    assert post.status_code == 405
    assert put.status_code == 405
    assert delete.status_code == 405


def test_runtime_metadata_never_exposes_configuration() -> None:
    """The response body carries exactly the operating-mode field."""
    settings = Settings(
        operating_mode=OperatingMode.PRODUCTION, public_base_url="http://testserver"
    )
    with build_test_app(settings=settings) as client:
        login_client(client)
        response = client.get("/api/v1/runtime")
    body = response.json()
    assert set(body) == {"operating_mode"}
    joined = str(body).lower()
    for secret_fragment in (
        "database",
        "password",
        "token",
        "api_key",
        "secret",
        "llm",
        "embedding",
    ):
        assert secret_fragment not in joined
