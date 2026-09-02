# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Bootstrap API tests."""

import pytest

from agentic_threat_investigator.main import live, ready


@pytest.mark.asyncio
async def test_health_endpoints() -> None:
    """Health endpoint handlers return their bootstrap statuses."""

    assert await live() == {"status": "ok"}
    assert await ready() == {"status": "ready"}
