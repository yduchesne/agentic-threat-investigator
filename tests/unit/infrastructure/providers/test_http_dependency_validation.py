# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Construction and injected-dependency validation for provider HTTP policy."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx
import pytest

from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpPolicy,
    RateLimiterSettings,
    parse_retry_after_header,
    read_monotonic_clock,
)


@pytest.mark.unit
class TestPolicyScalarValidation:
    """Directly constructible policies enforce their declared scalar types."""

    @pytest.mark.parametrize("bad_value", [True, False, 1.0, 1.5, "1", None])
    @pytest.mark.parametrize("field_name", ["max_retries", "max_response_bytes"])
    def test_policy_integer_fields_reject_coercion(
        self, field_name: str, bad_value: Any
    ) -> None:
        """Integer policy fields reject booleans and coercible non-integers."""
        with pytest.raises(ValueError, match="integer"):
            ProviderHttpPolicy(**{field_name: bad_value})

    @pytest.mark.parametrize("bad_value", [True, False, 1.0, 1.5, "1", None])
    def test_limiter_concurrency_rejects_coercion(self, bad_value: Any) -> None:
        """Semaphore capacity is always a genuine integer."""
        with pytest.raises(ValueError, match="integer"):
            RateLimiterSettings(max_concurrency=bad_value)

    @pytest.mark.parametrize(
        "field_name",
        [
            "timeout_seconds",
            "base_delay_seconds",
            "max_delay_seconds",
            "jitter_ratio",
        ],
    )
    def test_policy_real_fields_reject_booleans(self, field_name: str) -> None:
        """Booleans are not valid timing or jitter values."""
        with pytest.raises(ValueError, match="real number"):
            ProviderHttpPolicy(**{field_name: True})

    def test_limiter_rate_rejects_boolean(self) -> None:
        """A boolean request rate is not a valid real rate."""
        with pytest.raises(ValueError, match="real number"):
            RateLimiterSettings(requests_per_second=True)


@pytest.mark.unit
class TestInjectedClockValidation:
    """Injected timing dependencies fail fast on invalid return values."""

    @pytest.mark.parametrize(
        "bad_value", [float("nan"), float("inf"), float("-inf"), True, "0"]
    )
    def test_monotonic_clock_requires_finite_real(self, bad_value: Any) -> None:
        """Non-finite and non-real monotonic samples are programming errors."""
        with pytest.raises(ValueError, match="monotonic clock"):
            read_monotonic_clock(lambda: bad_value)

    @pytest.mark.asyncio
    async def test_limiter_releases_permit_after_invalid_clock(self) -> None:
        """Invalid rate-clock output propagates without leaking concurrency."""
        samples: list[Any] = [float("nan"), 0.0]
        limiter = BoundedLimiter(
            RateLimiterSettings(max_concurrency=1, requests_per_second=1.0),
            clock=lambda: samples.pop(0),
        )
        with pytest.raises(ValueError, match="monotonic clock"):
            await limiter.acquire()
        await limiter.acquire()
        limiter.release()

    def test_monotonic_clock_exception_propagates(self) -> None:
        """An exception raised by an injected monotonic clock is unchanged."""
        failure = RuntimeError("clock failed")

        def _raise() -> float:
            raise failure

        with pytest.raises(RuntimeError) as caught:
            read_monotonic_clock(_raise)
        assert caught.value is failure

    @pytest.mark.parametrize("bad_value", ["not-a-date", None, 0])
    def test_retry_after_utc_clock_requires_datetime(self, bad_value: Any) -> None:
        """HTTP-date parsing does not repair a non-datetime UTC clock."""
        response = httpx.Response(
            429, headers={"Retry-After": "Thu, 15 Jan 2026 12:00:10 GMT"}
        )
        with pytest.raises(ValueError, match="UTC clock"):
            parse_retry_after_header(response, lambda: bad_value)

    def test_retry_after_utc_clock_requires_aware_datetime(self) -> None:
        """A naive injected datetime is rejected rather than assumed to be UTC."""
        response = httpx.Response(
            429, headers={"Retry-After": "Thu, 15 Jan 2026 12:00:10 GMT"}
        )
        with pytest.raises(ValueError, match="timezone-aware"):
            parse_retry_after_header(response, lambda: datetime(2026, 1, 15, 12, 0, 0))

    def test_retry_after_accepts_aware_non_utc_clock(self) -> None:
        """An aware clock is normalized before HTTP-date comparison."""
        response = httpx.Response(
            429, headers={"Retry-After": "Thu, 15 Jan 2026 12:00:10 GMT"}
        )
        non_utc = datetime.fromisoformat("2026-01-15T07:00:00-05:00")
        assert parse_retry_after_header(response, lambda: non_utc) == 10
