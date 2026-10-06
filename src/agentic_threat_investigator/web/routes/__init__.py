# SPDX-License-Identifier: AGPL-3.0-only
"""HTML routes for the server-rendered web presentation adapter."""

from __future__ import annotations

from fastapi import APIRouter

from agentic_threat_investigator.web.routes import auth, home

web_router = APIRouter()
"""The composed web router: authentication and the protected proof shell."""

web_router.include_router(home.router)
web_router.include_router(auth.router)

__all__ = ["web_router"]
