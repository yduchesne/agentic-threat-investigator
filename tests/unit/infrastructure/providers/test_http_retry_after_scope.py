# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests proving Retry-After parsing is authorized only for HTTP 429."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.infrastructure.providers.http import (
    HttpOutcome,
    ProviderHttpClient,
)

_TEST_URL = "https://retry-scope.test.example.com/api"


def _zero_jitter() -> float:
    """Neutral jitter value (0.5 maps to zero offset)."""
    return 0.5


class _RecordingSleep:  # pylint: disable=too-few-public-methods
    """Records sleep calls for assertion."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


async def _request_outcome(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    utc_clock: Callable[[], datetime] | None = None,
    max_retries: int = 2,
) -> HttpOutcome:
    """Run one bounded request against a mock transport and return the outcome."""
    transport = MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        kwargs: dict[str, object] = {
            "client": client,
            "max_retries": max_retries,
            "base_delay_seconds": 0.01,
            "max_delay_seconds": 0.1,
            "sleep": _RecordingSleep(),
            "jitter_fn": _zero_jitter,
        }
        if utc_clock is not None:
            kwargs["utc_clock"] = utc_clock
        http = ProviderHttpClient(**kwargs)  # type: ignore[arg-type]
        return await http.request_json("GET", _TEST_URL)


@pytest.mark.asyncio
class TestRetryAfterScope:
    """Retry-After parsing is authorized only for HTTP 429 outcomes."""

    async def test_5xx_ignores_retry_after_header(self) -> None:
        """A 503 Retry-After value never overrides local backoff or the outcome."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(503, headers={"Retry-After": "9999"}, json={})

        outcome = await _request_outcome(_handler)
        assert outcome.final_error_code == ProviderErrorCode.PROVIDER_UNAVAILABLE
        assert outcome.final_status == 503
        assert outcome.attempt_count == 3
        assert outcome.retry_count == 2
        assert outcome.retry_after_seconds is None

    async def test_permanent_status_ignores_retry_after_header(self) -> None:
        """A 401 with Retry-After is terminal with no retry-after value."""
        request_count = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return httpx.Response(
                401,
                headers={"Retry-After": "Thu, 15 Jan 2026 12:30:00 GMT"},
                json={},
            )

        outcome = await _request_outcome(_handler)
        assert outcome.final_error_code == ProviderErrorCode.AUTHENTICATION_FAILED
        assert outcome.final_status == 401
        assert outcome.attempt_count == 1
        assert outcome.retry_count == 0
        assert outcome.retry_after_seconds is None
        assert request_count == 1

    async def test_non_429_does_not_evaluate_retry_after_clock(self) -> None:
        """The Retry-After UTC clock is never called for non-429 statuses."""

        def _failing_clock() -> datetime:
            pytest.fail("Retry-After clock evaluated for a non-429 status")

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                503,
                headers={"Retry-After": "Thu, 15 Jan 2026 12:30:00 GMT"},
                json={},
            )

        outcome = await _request_outcome(
            _handler, utc_clock=_failing_clock, max_retries=1
        )
        assert outcome.final_error_code == ProviderErrorCode.PROVIDER_UNAVAILABLE
        assert outcome.retry_after_seconds is None
