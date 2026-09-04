# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application bootstrap."""

from fastapi import FastAPI

from agentic_threat_investigator.api.auth import router as auth_router
from agentic_threat_investigator.config import get_settings

app = FastAPI(title=get_settings().app_name, version="0.1.0")
app.include_router(auth_router)


@app.get("/health/live", tags=["health"])
async def live() -> dict[str, str]:
    """Report that the API process is alive."""

    return {"status": "ok"}


@app.get("/health/ready", tags=["health"])
async def ready() -> dict[str, str]:
    """Report local application readiness.

    Database connectivity will be added with the persistence PR; optional remote
    providers must never be required for this endpoint.
    """

    return {"status": "ready"}
