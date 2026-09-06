# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Data-minimization regression tests for provider URL validation failures.

Provider URL and path validation exceptions must never echo the raw input:
malformed syntax can embed credentials, query values, or other sensitive
material that the category checks would otherwise reject before any text is
raised. These tests pin the fixed, generic error messages.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpClient,
    RateLimiterSettings,
    validate_entity_url_path,
    validate_provider_url,
)

_USERNAME_SENTINEL = "TOPSECRET"
_QUERY_SENTINEL = "QUERYSECRET"


@pytest.mark.unit
@pytest.mark.provider_contract
class TestUrlDataMinimization:
    """Validation failures never expose raw URLs, paths, or embedded values."""

    def test_malformed_url_parser_failure_does_not_leak_input(self) -> None:
        """A URL that fails parsing raises a generic ValueError without echoing input."""
        url = f"https://user:{_USERNAME_SENTINEL}@[bad/path?token={_QUERY_SENTINEL}"
        with pytest.raises(ValueError, match="malformed provider URL") as excinfo:
            validate_provider_url(url)
        message = str(excinfo.value)
        assert _USERNAME_SENTINEL not in message
        assert _QUERY_SENTINEL not in message
        assert url not in message

    def test_malformed_path_parser_failure_does_not_leak_input(self) -> None:
        """A path that fails parsing raises a generic ValueError without echoing input."""
        path = f"//user:{_USERNAME_SENTINEL}@[bad/path?token={_QUERY_SENTINEL}"
        with pytest.raises(ValueError, match="malformed resource path") as excinfo:
            validate_entity_url_path("https://rdap.example.test/", path)
        message = str(excinfo.value)
        assert _USERNAME_SENTINEL not in message
        assert _QUERY_SENTINEL not in message
        assert path not in message

    def test_credential_url_message_does_not_contain_password(self) -> None:
        """A credential-bearing URL is rejected without exposing the password."""
        with pytest.raises(ValueError, match="credentials") as excinfo:
            validate_provider_url(f"https://user:{_USERNAME_SENTINEL}@dns.google/x")
        assert _USERNAME_SENTINEL not in str(excinfo.value)

    def test_base_query_message_does_not_contain_query_value(self) -> None:
        """A base URL with a query is rejected without exposing the query value."""
        with pytest.raises(ValueError, match="query") as excinfo:
            validate_entity_url_path(
                f"https://rdap.example.test/base?token={_QUERY_SENTINEL}",
                "domain/test",
            )
        assert _QUERY_SENTINEL not in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_malformed_url_raises_before_limiter_or_http(self) -> None:
        """The ValueError precedes limiter acquisition and transport use."""

        class _RecordingLimiter(BoundedLimiter):
            """Limiter that records every attempted acquisition."""

            def __init__(self) -> None:
                super().__init__(RateLimiterSettings(max_concurrency=2))
                self.acquire_attempts = 0

            async def acquire(self) -> None:
                self.acquire_attempts += 1
                await super().acquire()

        io_issued = False

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal io_issued
            io_issued = True
            return httpx.Response(200, json={})

        limiter = _RecordingLimiter()
        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client, limiter=limiter)
            with pytest.raises(ValueError, match="malformed provider URL") as excinfo:
                await http.request_json(
                    "GET",
                    f"https://user:{_USERNAME_SENTINEL}@[bad/path"
                    f"?token={_QUERY_SENTINEL}",
                )
        assert limiter.acquire_attempts == 0
        assert io_issued is False
        message = str(excinfo.value)
        assert _USERNAME_SENTINEL not in message
        assert _QUERY_SENTINEL not in message
