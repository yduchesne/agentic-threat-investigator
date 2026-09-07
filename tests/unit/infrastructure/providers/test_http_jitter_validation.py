# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Request-loop tests for invalid injected jitter samples."""

from __future__ import annotations

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient


@pytest.mark.asyncio
async def test_invalid_jitter_propagates_before_sleep_or_second_attempt() -> None:
    """Invalid retry jitter is a programming error, not a provider outcome."""
    attempt_count = 0
    sleep_calls: list[float] = []

    def _handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempt_count
        attempt_count += 1
        return httpx.Response(503, json={})

    async def _recording_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    transport = MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        http = ProviderHttpClient(
            client=client,
            max_retries=2,
            sleep=_recording_sleep,
            jitter_fn=lambda: -0.1,
        )
        with pytest.raises(ValueError, match="jitter sample must be finite"):
            await http.request_json("GET", "https://jitter-validation.test/api")

    assert attempt_count == 1
    assert not sleep_calls
