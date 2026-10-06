# SPDX-License-Identifier: AGPL-3.0-only
"""Shared fakes and app builders for the web presentation contract tests.

Web route tests exercise pure HTML/HTTP contracts with injected application
fakes: no database, no real authentication, no LLM. The fakes are the same
presentation-neutral doubles the API route tests use, proving both adapters
consume one application surface.
"""

from __future__ import annotations

from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response

from agentic_threat_investigator.api.app import (
    API_ROUTERS,
    install_cookie_security_scheme,
    install_cors,
)
from agentic_threat_investigator.api.errors import install_error_handlers
from agentic_threat_investigator.api.middleware import RequestContextMiddleware
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.web.composition import install_web
from tests.unit.api.conftest import (
    FakeAuthenticationService,
    FakeQueryBundle,
    FakeSubmissionService,
)

TEST_ORIGIN = "http://testserver"
"""The single exact origin used by the bare web test app."""

SESSION_TOKEN = "session-token"
"""The fixed session token used by :class:`FakeAuthenticationService`."""


def web_settings(
    *,
    public_base_url: str = TEST_ORIGIN,
    web_base_url: str = TEST_ORIGIN,
    session_cookie_secure: bool = False,
) -> Settings:
    """Build settings with explicit exact origins and cookie security."""
    return Settings(
        public_base_url=public_base_url,
        web_base_url=web_base_url,
        session_cookie_secure=session_cookie_secure,
    )


def build_web_app(
    *,
    authentication: FakeAuthenticationService | None = None,
    settings: Settings | None = None,
    include_api: bool = True,
) -> TestClient:
    """Build a bare FastAPI with the web adapter (and optionally the API)."""
    application = FastAPI()
    application.add_middleware(RequestContextMiddleware)
    install_error_handlers(application)
    if include_api:
        for route in API_ROUTERS:
            application.include_router(route)
    configured = settings or web_settings()
    application.state.settings = configured
    application.state.authentication = authentication or FakeAuthenticationService()
    application.state.submission_service = FakeSubmissionService()
    application.state.query_services_factory = lambda: FakeQueryBundle().as_bundle()
    install_cors(application, configured)
    install_cookie_security_scheme(application)
    install_web(application, configured)
    return TestClient(
        application, raise_server_exceptions=False, follow_redirects=False
    )


def prime_login_csrf(client: TestClient) -> str:
    """Fetch the login page so the double-submit cookie is armed."""
    client.get("/login")
    return cast(str, client.cookies.get("ati_csrf", ""))


def web_login(
    client: TestClient,
    *,
    username: str = "alice",
    password: str = "secret",
    csrf: str | None = None,
    origin: str = TEST_ORIGIN,
) -> Response:
    """POST the web login form and return the raw response."""
    token = csrf if csrf is not None else prime_login_csrf(client)
    return cast(
        Response,
        client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": token,
                "next": "/",
            },
            headers={"Origin": origin},
        ),
    )
