# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared provider HTTP-client request-body contract tests.

Covers the PR 17 mutually-exclusive request-body contract added for the
URLhaus form-encoded endpoints.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


@pytest.mark.asyncio
async def test_request_json_rejects_combined_json_and_form_bodies() -> None:
    """Supplying both json_body and form_body fails before any I/O."""
    transport = MockTransport(
        lambda _: pytest.fail("no transport I/O may occur for a bad request shape")
    )
    async with httpx.AsyncClient(transport=transport) as client:
        http = ProviderHttpClient(client=client, max_retries=0)
        with pytest.raises(ValueError, match="mutually exclusive"):
            await http.request_json(
                "POST",
                "https://test.example.com/api",
                json_body={"a": 1},
                form_body={"b": "2"},
            )
