# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application factory for the /api/v1 HTTP boundary (PR 23C).

``create_app`` builds a testable FastAPI application: CORS, the request-ID /
security-header middleware, the stable error envelope, all /api/v1 routers,
and health probes. Heavy infrastructure (engine, session factory, services)
is composed lazily inside the lifespan through
:class:`~agentic_threat_investigator.infrastructure.api_composition.ApiComposition`;
nothing heavy happens at import time and the FastAPI process never launches
the investigation worker, LangGraph, provider polling, or job execution.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentic_threat_investigator.api.errors import install_error_handlers
from agentic_threat_investigator.api.middleware import RequestContextMiddleware
from agentic_threat_investigator.api.routes import (
    assessments,
    auth,
    evidence,
    history,
    investigations,
    relationships,
    reports,
    research,
    runtime,
    timeline,
)
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.infrastructure.api_composition import ApiComposition

LOGGER = logging.getLogger(__name__)


def log_operating_mode(settings: Settings) -> None:
    """Emit the safe startup observability event for the API process.

    Only the selected operating mode and its intelligence-source label are
    logged; resolved secrets and configuration internals are never included.
    """
    LOGGER.info(
        "operating_mode=%s intelligence_source_mode=%s",
        settings.operating_mode.value,
        settings.operating_mode.value,
    )
    if settings.operating_mode.value == "fake":
        LOGGER.info(
            "ATI operating mode: FAKE; external threat-intelligence sources: "
            "deterministic local fakes; LLM: configured runtime implementation "
            "(not selected by operating mode)"
        )


API_ROUTERS = (
    auth.router,
    investigations.router,
    evidence.router,
    relationships.relationships_router,
    relationships.observations_router,
    research.router,
    assessments.router,
    reports.router,
    timeline.router,
    history.router,
    runtime.router,
)
"""Every /api/v1 router in a stable registration order."""


def install_cors(application: FastAPI, settings: Settings) -> None:
    """Install credentialed CORS with explicit configured origins only.

    ``allow_credentials`` is never combined with a wildcard origin (the
    settings validator rejects it); methods and headers stay bounded.
    """
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.api_cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "X-Request-ID",
            "X-CSRF-Token",
            "Idempotency-Key",
            "Content-Type",
            "Accept",
        ],
        expose_headers=["X-Request-ID", "Location"],
        max_age=600,
    )


def install_cookie_security_scheme(application: FastAPI) -> None:
    """Declare the cookie-session security scheme accurately in OpenAPI.

    The stable ``cookieSession`` scheme (an apiKey in the ``ati_session``
    cookie) is registered and required by every operation except the public
    probes and ``POST /auth/login``. JWT/Bearer is never documented because
    the implementation is cookie sessions.
    """
    from agentic_threat_investigator.api.auth_constants import COOKIE_NAME

    PUBLIC_OPERATIONS = {
        ("/health/live", "get"),
        ("/health/ready", "get"),
        ("/api/v1/auth/login", "post"),
    }

    original_openapi = application.openapi

    def patched_openapi() -> dict[str, object]:
        """Return the OpenAPI schema with the accurate cookie scheme."""
        schema = original_openapi()
        components = schema.setdefault("components", {})
        schemes = components.setdefault("securitySchemes", {})
        schemes["cookieSession"] = {
            "type": "apiKey",
            "in": "cookie",
            "name": COOKIE_NAME,
        }
        error_ref = {
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                }
            }
        }
        documented_errors = {
            "400": {**error_ref, "description": "Invalid request."},
            "401": {**error_ref, "description": "Authentication required."},
            "403": {**error_ref, "description": "Access forbidden."},
            "404": {**error_ref, "description": "Resource not found."},
            "409": {**error_ref, "description": "Conflict."},
            "422": {**error_ref, "description": "Request validation failed."},
        }
        for path, path_item in schema.get("paths", {}).items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                if (path, method) in PUBLIC_OPERATIONS:
                    continue
                operation["security"] = [{"cookieSession": []}]
                responses = operation.setdefault("responses", {})
                for code, detail in documented_errors.items():
                    responses.setdefault(code, detail)
        return schema

    application.openapi = patched_openapi  # type: ignore[method-assign]


def create_app(settings: Settings) -> FastAPI:
    """Build the FastAPI application wired for the supplied settings.

    The returned application is not usable until its lifespan runs (the
    TestClient context manager or the ASGI server starts it); services are
    installed on ``application.state`` during startup.
    """

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        """Compose the real API services and seed the bootstrap admin."""
        log_operating_mode(settings)
        composition = ApiComposition(settings)
        composition.install_services(application)
        await composition.bootstrap_admin().ensure(
            settings.bootstrap_admin_username, settings.bootstrap_admin_password
        )
        try:
            yield
        finally:
            await composition.dispose()

    application = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
    # CORS wraps the middleware stack outermost so preflight responses also
    # carry the credential policy; the request-ID middleware is registered
    # after it so it runs inside (after) CORS handling.
    install_cors(application, settings)
    install_cookie_security_scheme(application)
    application.add_middleware(RequestContextMiddleware)
    install_error_handlers(application)
    for route in API_ROUTERS:
        application.include_router(route)

    async def live() -> dict[str, str]:
        """Report that the API process is alive."""
        return {"status": "ok"}

    async def ready() -> dict[str, str]:
        """Report application readiness."""
        return {"status": "ready"}

    application.add_api_route("/health/live", live, methods=["GET"], tags=["health"])
    application.add_api_route("/health/ready", ready, methods=["GET"], tags=["health"])
    return application
