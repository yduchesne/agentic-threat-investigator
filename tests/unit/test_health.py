# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Bootstrap API health probes."""

import pytest
from fastapi.routing import APIRoute

from agentic_threat_investigator.api.app import create_app
from agentic_threat_investigator.config import Settings


@pytest.mark.asyncio
async def test_health_endpoints() -> None:
    """Health probes return their bootstrap statuses through the app route."""
    app = create_app(Settings())

    live_handler = next(
        route.endpoint
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == "/health/live"
    )
    ready_handler = next(
        route.endpoint
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == "/health/ready"
    )

    assert await live_handler() == {"status": "ok"}
    assert await ready_handler() == {"status": "ready"}
