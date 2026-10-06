# SPDX-License-Identifier: AGPL-3.0-only
"""Composition seam for the server-rendered web presentation adapter.

The web adapter is composed into ATI's existing FastAPI process alongside
``/api/v1`` so both presentation adapters share one lifespan, one
authentication/session authority, and one database. No second Python
backend, database, or worker is introduced.
"""

from __future__ import annotations

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.web.errors import install_web_error_handlers
from agentic_threat_investigator.web.rendering import (
    STATIC_DIR,
    STATIC_URL_PREFIX,
    WebTemplates,
)
from agentic_threat_investigator.web.routes import web_router


def install_web(application: FastAPI, settings: Settings) -> None:
    """Compose the HTML presentation adapter into a FastAPI application.

    ``settings`` is accepted for symmetry with the API composition and so
    any future web-only typed setting is resolved at this one seam; the
    routes themselves resolve settings from ``request.app.state`` installed
    by the shared API composition.
    """
    del settings  # The shared API composition installs settings on app.state.
    application.state.web_templates = WebTemplates()
    # ATI-owned static path: cannot be confused with React/Nginx assets.
    application.mount(
        STATIC_URL_PREFIX,
        StaticFiles(directory=str(STATIC_DIR)),
        name="web-static",
    )
    application.include_router(web_router)
    install_web_error_handlers(application)
