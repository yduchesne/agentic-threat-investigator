# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Injected clock validation for the RDAP bootstrap cache."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from agentic_threat_investigator.infrastructure.providers.rdap import RdapBootstrapCache


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapBootstrapClockValidation:
    """Bootstrap expiry calculations require valid monotonic samples."""

    @pytest.mark.parametrize(
        "bad_clock", [float("nan"), float("inf"), float("-inf"), True, "0"]
    )
    async def test_cache_rejects_invalid_monotonic_sample(self, bad_clock: Any) -> None:
        """Invalid monotonic samples cannot enter cache expiry calculations."""
        requests = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal requests
            requests += 1
            return httpx.Response(500, json={})

        async with httpx.AsyncClient(transport=MockTransport(_handler)) as client:
            cache = RdapBootstrapCache(
                ProviderHttpClient(client=client),
                cache_seconds=3600,
                clock=lambda: bad_clock,
            )
            with pytest.raises(ValueError, match="monotonic clock"):
                await cache.get_services("dns")
        assert requests == 0

    async def test_cache_clock_exception_propagates_unchanged(self) -> None:
        """A cache clock programming failure is not converted to provider error."""
        failure = RuntimeError("clock failed")

        def _raise() -> float:
            raise failure

        async with httpx.AsyncClient(
            transport=MockTransport(lambda _: httpx.Response(500, json={}))
        ) as client:
            cache = RdapBootstrapCache(
                ProviderHttpClient(client=client), cache_seconds=3600, clock=_raise
            )
            with pytest.raises(RuntimeError) as caught:
                await cache.get_services("dns")
        assert caught.value is failure
