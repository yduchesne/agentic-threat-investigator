# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Retry timing and Retry-After parsing tests for the HTTP infrastructure.

Covers deterministic ``compute_backoff_delay`` semantics (exponential delay,
bounded symmetric jitter, Retry-After minimum, hard cap) and
``parse_retry_after_header`` semantics for integer-seconds and HTTP-date
forms, including the round-up rule that keeps fractional HTTP-date delays
from ever expiring before the provider-directed deadline.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import httpx
import pytest

from agentic_threat_investigator.infrastructure.providers.http import (
    JitterFn,
    ProviderHttpClient,
    parse_retry_after_header,
)

from .test_http import _FakeUtcClock, _fixed_jitter, _zero_jitter


class TestComputeBackoffDelay:
    """Retry backoff delay computation: jitter, Retry-After, and capping."""

    def test_backoff_delay_never_exceeds_max_cap(self) -> None:
        """Jittered backoff is clamped to max_delay_seconds as the final step."""
        http = ProviderHttpClient(
            base_delay_seconds=30.0,
            max_delay_seconds=30.0,
            jitter_ratio=1.0,
            jitter_fn=lambda: 1.0,  # Max positive jitter
        )
        delay = http.compute_backoff_delay(retry_number=0)
        assert delay == 30.0  # Clamped, not 60.0

    def test_negative_jitter_never_goes_below_retry_after(self) -> None:
        """Negative jitter cannot schedule a retry before an in-cap Retry-After."""
        http = ProviderHttpClient(
            base_delay_seconds=10.0,
            max_delay_seconds=30.0,
            jitter_ratio=1.0,
            jitter_fn=lambda: 0.0,  # Max negative jitter
        )
        # Exponential 10s with full negative jitter clamps to 0s, but the
        # provider-directed Retry-After minimum is preserved.
        delay = http.compute_backoff_delay(retry_number=0, retry_after_seconds=20)
        assert delay == 20.0

    def test_positive_jitter_may_exceed_retry_after(self) -> None:
        """A jittered exponential delay larger than Retry-After is used."""
        http = ProviderHttpClient(
            base_delay_seconds=10.0,
            max_delay_seconds=50.0,
            jitter_ratio=1.0,
            jitter_fn=lambda: 1.0,  # Max positive jitter
        )
        # Exponential 20s + full positive jitter = 40s > Retry-After 30s.
        delay = http.compute_backoff_delay(retry_number=1, retry_after_seconds=30)
        assert delay == 40.0

    def test_retry_after_above_cap_is_clamped_to_cap(self) -> None:
        """A provider Retry-After above the local cap sleeps no longer than the cap."""
        http = ProviderHttpClient(
            base_delay_seconds=1.0,
            max_delay_seconds=30.0,
            jitter_ratio=1.0,
            jitter_fn=lambda: 1.0,  # Max positive jitter
        )
        delay = http.compute_backoff_delay(retry_number=3, retry_after_seconds=1000)
        assert delay == 30.0

    def test_zero_base_delay_with_retry_after_uses_retry_after(self) -> None:
        """A zero base delay still honors a valid Retry-After minimum."""
        http = ProviderHttpClient(
            base_delay_seconds=0.0,
            max_delay_seconds=30.0,
            jitter_ratio=1.0,
            jitter_fn=lambda: 0.0,
        )
        delay = http.compute_backoff_delay(retry_number=2, retry_after_seconds=7)
        assert delay == 7.0

    def test_no_retry_after_preserves_symmetric_jitter_range(self) -> None:
        """Without Retry-After, symmetric jitter spans the exponential delay."""
        for jitter_value, expected in ((0.0, 0.0), (0.5, 10.0), (1.0, 20.0)):
            http = ProviderHttpClient(
                base_delay_seconds=10.0,
                max_delay_seconds=30.0,
                jitter_ratio=1.0,
                jitter_fn=_fixed_jitter(jitter_value),
            )
            assert http.compute_backoff_delay(retry_number=0) == expected

    def test_huge_retry_after_saturates_without_overflow(self) -> None:
        """A hundreds-of-digits Retry-After saturates at the cap, never raising."""
        http = ProviderHttpClient(
            base_delay_seconds=1.0,
            max_delay_seconds=30.0,
            jitter_ratio=1.0,
            jitter_fn=_zero_jitter,
        )
        delay = http.compute_backoff_delay(retry_number=0, retry_after_seconds=10**400)
        assert delay == 30.0

    def test_huge_retry_number_saturates_without_overflow(self) -> None:
        """A huge retry index saturates at the cap before any overflow."""
        http = ProviderHttpClient(
            base_delay_seconds=1.0,
            max_delay_seconds=30.0,
            jitter_ratio=1.0,
            jitter_fn=_zero_jitter,
        )
        assert http.compute_backoff_delay(retry_number=1024) == 30.0
        assert http.compute_backoff_delay(retry_number=10**400) == 30.0

    def test_zero_base_delay_with_huge_retry_number_is_zero(self) -> None:
        """Zero base delay stays exactly zero even for a huge retry index."""
        http = ProviderHttpClient(
            base_delay_seconds=0.0,
            max_delay_seconds=30.0,
            jitter_ratio=1.0,
            jitter_fn=_fixed_jitter(1.0),
        )
        assert http.compute_backoff_delay(retry_number=10**400) == 0.0

    def test_zero_jitter_factor_with_huge_retry_number_is_zero(self) -> None:
        """Full negative jitter stays exactly zero for a huge retry index."""
        http = ProviderHttpClient(
            base_delay_seconds=1.0,
            max_delay_seconds=30.0,
            jitter_ratio=1.0,
            jitter_fn=_fixed_jitter(0.0),
        )
        assert http.compute_backoff_delay(retry_number=10**400) == 0.0

    def test_negative_retry_number_rejected(self) -> None:
        """A negative retry index is a programming error, not a provider failure."""
        http = ProviderHttpClient(
            base_delay_seconds=1.0,
            max_delay_seconds=30.0,
            jitter_ratio=1.0,
            jitter_fn=_zero_jitter,
        )
        with pytest.raises(ValueError, match="nonnegative"):
            http.compute_backoff_delay(retry_number=-1)

    @pytest.mark.parametrize(
        "sample",
        [-0.0001, 1.0001, float("nan"), float("inf"), float("-inf")],
    )
    def test_invalid_numeric_jitter_sample_rejected(self, sample: float) -> None:
        """Out-of-range and non-finite jitter samples are programming errors."""
        http = ProviderHttpClient(jitter_fn=_fixed_jitter(sample))
        with pytest.raises(ValueError, match="jitter sample must be finite"):
            http.compute_backoff_delay(retry_number=0)

    def test_wrong_type_jitter_sample_rejected(self) -> None:
        """A non-numeric jitter sample produces a stable ValueError."""
        invalid_jitter = cast(JitterFn, lambda: "not-a-number")
        http = ProviderHttpClient(jitter_fn=invalid_jitter)
        with pytest.raises(ValueError, match="jitter sample must be finite"):
            http.compute_backoff_delay(retry_number=0)

    def test_jitter_sample_evaluated_exactly_once(self) -> None:
        """One backoff computation requests exactly one jitter sample."""
        call_count = 0

        def _counting_jitter() -> float:
            nonlocal call_count
            call_count += 1
            return 0.5

        http = ProviderHttpClient(jitter_fn=_counting_jitter)
        assert http.compute_backoff_delay(retry_number=0) == 1.0
        assert call_count == 1

    def test_jitter_callable_exception_propagates(self) -> None:
        """An exception raised by the jitter callable is never normalized."""

        class JitterSentinelError(Exception):
            """Sentinel exception proving callable failures propagate unchanged."""

        def _failing_jitter() -> float:
            raise JitterSentinelError("sentinel")

        http = ProviderHttpClient(jitter_fn=_failing_jitter)
        with pytest.raises(JitterSentinelError, match="sentinel"):
            http.compute_backoff_delay(retry_number=0)


class TestRetryAfter:
    """Retry-After header parsing (sync, deterministic)."""

    def test_integer_retry_after(self) -> None:
        """A positive integer Retry-After is parsed directly."""
        response = httpx.Response(429, headers={"Retry-After": "30"})
        result = parse_retry_after_header(response, _FakeUtcClock())
        assert result == 30

    def test_negative_integer_returns_none(self) -> None:
        """A negative Retry-After integer returns None."""
        response = httpx.Response(429, headers={"Retry-After": "-5"})
        result = parse_retry_after_header(response, _FakeUtcClock())
        assert result is None

    def test_http_date_retry_after(self) -> None:
        """An HTTP-date Retry-After is resolved against the injected clock."""
        clock = _FakeUtcClock(datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC))
        response = httpx.Response(
            429,
            headers={"Retry-After": "Thu, 15 Jan 2026 12:30:00 GMT"},
        )
        result = parse_retry_after_header(response, clock)
        assert result == 1800

    def test_http_date_fractional_delay_rounds_up(self) -> None:
        """A fractional HTTP-date delay rounds up, never truncates."""
        # Deadline is 29.2 seconds ahead: truncation would yield 29 and
        # schedule the retry before the provider-directed deadline.
        clock = _FakeUtcClock(datetime(2026, 1, 15, 12, 29, 30, 800000, tzinfo=UTC))
        response = httpx.Response(
            429,
            headers={"Retry-After": "Thu, 15 Jan 2026 12:30:00 GMT"},
        )
        result = parse_retry_after_header(response, clock)
        assert result == 30

    def test_http_date_under_one_second_ahead_rounds_to_one(self) -> None:
        """An HTTP-date less than a second ahead returns 1, not 0."""
        clock = _FakeUtcClock(datetime(2026, 1, 15, 12, 0, 0, 500000, tzinfo=UTC))
        response = httpx.Response(
            429,
            headers={"Retry-After": "Thu, 15 Jan 2026 12:00:01 GMT"},
        )
        result = parse_retry_after_header(response, clock)
        assert result == 1

    def test_http_date_exactly_now_returns_zero(self) -> None:
        """An HTTP-date exactly equal to the clock returns 0."""
        clock = _FakeUtcClock(datetime(2026, 1, 15, 12, 0, 0, 0, tzinfo=UTC))
        response = httpx.Response(
            429,
            headers={"Retry-After": "Thu, 15 Jan 2026 12:00:00 GMT"},
        )
        result = parse_retry_after_header(response, clock)
        assert result == 0

    def test_http_date_delay_capped_by_compute_backoff(self) -> None:
        """A rounded-up HTTP-date delay is capped by max_delay_seconds."""
        http = ProviderHttpClient(
            base_delay_seconds=0.01,
            max_delay_seconds=10.0,
            jitter_fn=_zero_jitter,
        )
        # An HTTP-date 29.2 seconds ahead parses to 30; the configured
        # maximum delay stays the hard upper bound even then.
        clock = _FakeUtcClock(datetime(2026, 1, 15, 12, 29, 30, 800000, tzinfo=UTC))
        response = httpx.Response(
            429,
            headers={"Retry-After": "Thu, 15 Jan 2026 12:30:00 GMT"},
        )
        retry_after = parse_retry_after_header(response, clock)
        assert retry_after == 30
        delay = http.compute_backoff_delay(
            retry_number=0, retry_after_seconds=retry_after
        )
        assert delay == 10.0

    def test_past_date_returns_none(self) -> None:
        """A past HTTP-date Retry-After returns None."""
        clock = _FakeUtcClock(datetime(2026, 1, 15, 12, 30, 0, tzinfo=UTC))
        response = httpx.Response(
            429,
            headers={"Retry-After": "Thu, 15 Jan 2026 12:00:00 GMT"},
        )
        result = parse_retry_after_header(response, clock)
        assert result is None

    def test_missing_header_returns_none(self) -> None:
        """No Retry-After header returns None."""
        response = httpx.Response(200, json={})
        result = parse_retry_after_header(response, _FakeUtcClock())
        assert result is None

    def test_unparseable_returns_none(self) -> None:
        """An unparseable Retry-After returns None."""
        response = httpx.Response(429, headers={"Retry-After": "garbage"})
        result = parse_retry_after_header(response, _FakeUtcClock())
        assert result is None
