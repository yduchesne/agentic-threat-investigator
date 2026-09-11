# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the HTTP infrastructure layer."""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    JitterFn,
    ProviderHttpClient,
    ProviderHttpPolicy,
    RateLimiterSettings,
    check_content_type,
    classify_http_status,
    status_error_message,
    validate_entity_url_path,
    validate_provider_url,
)

from .limiter_fakes import FakeRateClock, GatedSleep


class TestValidateUrl:
    """URL validation and safety checks."""

    def test_valid_https_url(self) -> None:
        """A valid HTTPS URL is accepted."""
        url = validate_provider_url("https://dns.google/resolve")
        assert url == "https://dns.google/resolve"

    def test_http_url_rejected(self) -> None:
        """An HTTP URL is rejected."""
        with pytest.raises(ValueError, match="https"):
            validate_provider_url("http://dns.google/resolve")

    def test_credentials_in_url_rejected(self) -> None:
        """A URL containing credentials is rejected."""
        with pytest.raises(ValueError, match="credentials"):
            validate_provider_url("https://user:pass@dns.google/resolve")

    def test_no_hostname_rejected(self) -> None:
        """A URL without a hostname is rejected."""
        with pytest.raises(ValueError, match="hostname"):
            validate_provider_url("https:///path")

    def test_invalid_port_rejected(self) -> None:
        """A URL with an invalid port is rejected."""
        with pytest.raises(ValueError, match="invalid port"):
            validate_provider_url("https://example.com:999999/path")

    @pytest.mark.parametrize("host", ["bad host", "exa_mple.com"])
    def test_malformed_hostname_rejected(self, host: str) -> None:
        """Malformed DNS hostnames are rejected before I/O."""
        with pytest.raises(ValueError, match="invalid hostname"):
            validate_provider_url(f"https://{host}/path")

    def test_fragment_rejected(self) -> None:
        """A URL with a fragment is rejected."""
        with pytest.raises(ValueError, match="fragment"):
            validate_provider_url("https://example.com/path#section")

    def test_uppercase_host_canonicalized_to_lowercase(self) -> None:
        """Uppercase and lowercase host spellings yield one canonical URL."""
        assert (
            validate_provider_url("https://RDAP.EXAMPLE.TEST/base")
            == "https://rdap.example.test/base"
        )

    def test_terminal_dns_root_dot_removed(self) -> None:
        """A terminal DNS root dot is removed from the canonical host."""
        assert (
            validate_provider_url("https://rdap.example.test./base")
            == "https://rdap.example.test/base"
        )

    def test_unicode_host_idna_normalized(self) -> None:
        """Unicode and equivalent IDNA host spellings yield one canonical URL."""
        unicode_url = validate_provider_url("https://café.test/")
        ascii_url = validate_provider_url("https://xn--caf-dma.test/")
        assert unicode_url == ascii_url == "https://xn--caf-dma.test/"

    def test_explicit_default_https_port_removed(self) -> None:
        """An explicit default HTTPS port is normalized away."""
        assert (
            validate_provider_url("https://rdap.example.test:443/base")
            == "https://rdap.example.test/base"
        )

    def test_non_default_port_preserved(self) -> None:
        """A non-default explicit port is preserved in the canonical URL."""
        assert (
            validate_provider_url("https://rdap.example.test:8443/base")
            == "https://rdap.example.test:8443/base"
        )

    def test_ipv6_literal_reconstructed_with_brackets(self) -> None:
        """IPv6 literals are canonicalized, lowercased, and bracketed."""
        assert (
            validate_provider_url("https://[2001:DB8::0001]:443/ip/")
            == "https://[2001:db8::1]/ip/"
        )

    def test_ipv6_literal_non_default_port_preserved(self) -> None:
        """A non-default port on an IPv6 literal is preserved."""
        assert (
            validate_provider_url("https://[2001:DB8::1]:8443/ip/")
            == "https://[2001:db8::1]:8443/ip/"
        )

    def test_valid_entity_path(self) -> None:
        """A path joined to a valid base URL works correctly."""
        url = validate_entity_url_path(
            "https://rdap.example.com/", "domain/example.com"
        )
        assert url == "https://rdap.example.com/domain/example.com"

    def test_entity_path_with_scheme_rejected(self) -> None:
        """A path containing a scheme is rejected."""
        with pytest.raises(ValueError, match="scheme or authority"):
            validate_entity_url_path(
                "https://rdap.example.com/", "https://evil.test/path"
            )

    def test_entity_path_with_fragment_rejected(self) -> None:
        """A path containing a fragment is rejected."""
        with pytest.raises(ValueError, match="fragment"):
            validate_entity_url_path("https://rdap.example.com/", "domain/test#frag")

    def test_entity_base_query_rejected(self) -> None:
        """A base URL containing a query is rejected before path joining."""
        with pytest.raises(ValueError, match="query"):
            validate_entity_url_path(
                "https://rdap.example.com/base?secret=value", "domain/test"
            )

    def test_entity_path_http_base_rejected(self) -> None:
        """An HTTP base URL for entity paths is rejected."""
        with pytest.raises(ValueError, match="https"):
            validate_entity_url_path("http://rdap.example.com/", "domain/test")

    def test_entity_path_credentials_rejected(self) -> None:
        """A base URL with credentials is rejected."""
        with pytest.raises(ValueError, match="credentials"):
            validate_entity_url_path("https://u:p@rdap.example.com/", "domain/test")


class TestContentTypeAndStatusClassification:
    """Content-Type checking and HTTP status classification helpers."""

    def test_check_content_type_valid(self) -> None:
        """Standard and +json content types are accepted."""
        types = ("application/json", "application/rdap+json")
        assert check_content_type("application/json", types) is True
        assert check_content_type("application/json; charset=utf-8", types) is True
        assert check_content_type("application/rdap+json", types) is True
        assert check_content_type("application/problem+json", types) is False

    def test_check_content_type_invalid(self) -> None:
        """Non-JSON content types are rejected."""
        types = ("application/json",)
        assert check_content_type("text/plain", types) is False
        assert check_content_type("text/html; charset=utf-8", types) is False
        assert check_content_type(None, types) is False
        assert check_content_type("", types) is False

    def test_classify_http_status_codes(self) -> None:
        """Statuses map correctly to ProviderErrorCode values."""
        accepted = {200}
        assert classify_http_status(200, accepted) is None
        assert (
            classify_http_status(401, accepted)
            == ProviderErrorCode.AUTHENTICATION_FAILED
        )
        assert classify_http_status(403, accepted) == ProviderErrorCode.FORBIDDEN
        assert classify_http_status(404, accepted) == ProviderErrorCode.NOT_FOUND
        assert classify_http_status(429, accepted) == ProviderErrorCode.RATE_LIMITED
        assert (
            classify_http_status(500, accepted)
            == ProviderErrorCode.PROVIDER_UNAVAILABLE
        )
        assert (
            classify_http_status(503, accepted)
            == ProviderErrorCode.PROVIDER_UNAVAILABLE
        )
        assert (
            classify_http_status(599, accepted)
            == ProviderErrorCode.PROVIDER_UNAVAILABLE
        )
        assert classify_http_status(600, accepted) == ProviderErrorCode.INVALID_RESPONSE
        assert classify_http_status(400, accepted) == ProviderErrorCode.INVALID_RESPONSE
        assert classify_http_status(301, accepted) == ProviderErrorCode.INVALID_RESPONSE

    def test_status_error_messages(self) -> None:
        """Status error messages are generic and safe."""
        assert "authentication" in status_error_message(
            401, ProviderErrorCode.AUTHENTICATION_FAILED
        )
        assert "forbidden" in status_error_message(403, ProviderErrorCode.FORBIDDEN)
        assert "not found" in status_error_message(404, ProviderErrorCode.NOT_FOUND)
        assert "rate limited" in status_error_message(
            429, ProviderErrorCode.RATE_LIMITED
        )
        assert "503" in status_error_message(
            503, ProviderErrorCode.PROVIDER_UNAVAILABLE
        )
        assert "400" in status_error_message(400, ProviderErrorCode.INVALID_RESPONSE)


class TestPolicyValidation:
    """Construction validation for policy and limiter settings."""

    def test_rate_limiter_settings_bounds(self) -> None:
        """RateLimiterSettings validates concurrency and rate bounds."""
        with pytest.raises(ValueError, match="max_concurrency"):
            RateLimiterSettings(max_concurrency=0)
        with pytest.raises(ValueError, match="requests_per_second"):
            RateLimiterSettings(requests_per_second=0)
        with pytest.raises(ValueError, match="requests_per_second"):
            RateLimiterSettings(requests_per_second=-1.0)
        valid = RateLimiterSettings(max_concurrency=5, requests_per_second=10.0)
        assert valid.max_concurrency == 5
        assert valid.requests_per_second == 10.0

    @pytest.mark.parametrize("bad_rate", [float("inf"), float("-inf"), float("nan")])
    def test_rate_limiter_non_finite_rate_rejected(self, bad_rate: float) -> None:
        """A non-finite request rate is not a bounded limiter setting."""
        with pytest.raises(ValueError, match="finite"):
            RateLimiterSettings(max_concurrency=5, requests_per_second=bad_rate)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"timeout_seconds": float("inf")},
            {"timeout_seconds": float("-inf")},
            {"timeout_seconds": float("nan")},
            {"base_delay_seconds": float("inf"), "max_delay_seconds": float("inf")},
            {"base_delay_seconds": float("nan")},
            {"max_delay_seconds": float("inf")},
            {"max_delay_seconds": float("nan")},
            {"jitter_ratio": float("inf")},
            {"jitter_ratio": float("nan")},
        ],
    )
    def test_provider_http_policy_non_finite_rejected(
        self, kwargs: dict[str, Any]
    ) -> None:
        """Non-finite timing/jitter values violate the bounded policy contract."""
        with pytest.raises(ValueError, match="finite"):
            ProviderHttpPolicy(**kwargs)

    def test_finite_policy_and_rate_construct(self) -> None:
        """Ordinary finite policy and rate settings still construct."""
        policy = ProviderHttpPolicy(
            timeout_seconds=15.0,
            base_delay_seconds=0.0,
            max_delay_seconds=0.0,
            jitter_ratio=1.0,
        )
        assert policy.timeout_seconds == 15.0
        limiter_settings = RateLimiterSettings(
            max_concurrency=1, requests_per_second=0.001
        )
        assert limiter_settings.requests_per_second == 0.001

    def test_provider_http_policy_bounds(self) -> None:
        """ProviderHttpPolicy validates timing, retry, and byte bounds."""
        with pytest.raises(ValueError, match="timeout_seconds"):
            ProviderHttpPolicy(timeout_seconds=0)
        with pytest.raises(ValueError, match="max_retries"):
            ProviderHttpPolicy(max_retries=-1)
        with pytest.raises(ValueError, match="base_delay_seconds"):
            ProviderHttpPolicy(base_delay_seconds=-1)
        with pytest.raises(ValueError, match="max_delay_seconds"):
            ProviderHttpPolicy(base_delay_seconds=10, max_delay_seconds=5)
        with pytest.raises(ValueError, match="jitter_ratio"):
            ProviderHttpPolicy(jitter_ratio=1.5)
        with pytest.raises(ValueError, match="max_response_bytes"):
            ProviderHttpPolicy(max_response_bytes=0)
        with pytest.raises(ValueError, match="max_response_bytes"):
            ProviderHttpPolicy(max_response_bytes=200_000_000)

    def test_provider_client_validates_direct_construction(self) -> None:
        """ProviderHttpClient rejects invalid constructor arguments."""
        with pytest.raises(ValueError, match="timeout_seconds"):
            ProviderHttpClient(timeout_seconds=-1.0)


# -- Fake clock/sleep/jitter helpers --------------------------------------


class _FakeClock:
    """Deterministic monotonic clock for retry/limiter tests."""

    def __init__(self, ticks: list[float] | None = None) -> None:
        self._ticks = ticks or [0.0]
        self._index = 0

    def __call__(self) -> float:
        val = self._ticks[self._index % len(self._ticks)]
        self._index += 1
        return val


class _FakeUtcClock:
    """Deterministic UTC clock for Retry-After header tests."""

    def __init__(self, fixed_time: datetime | None = None) -> None:
        self._fixed = fixed_time or datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self._fixed


class _RecordingSleep:
    """Records sleep calls for assertion."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _zero_jitter() -> float:
    return 0.5  # neutral jitter (0.5 * 2 - 1 = 0.0)


def _fixed_jitter(value: float) -> JitterFn:
    """Return a deterministic jitter callable returning ``value``."""
    return lambda: value


def _ok_json_handler(_: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        json={"status": "ok"},
    )


# -- Main HTTP client test suite -----------------------------------------


@pytest.mark.asyncio
class TestProviderHttpClient:
    """ProviderHttpClient retry, timeout, headers, and status handling."""

    async def test_request_200_returns_success(self) -> None:
        """A 200 response is accepted immediately with no retry."""
        transport = MockTransport(_ok_json_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_status == 200
            assert outcome.final_error_code is None
            assert outcome.attempt_count == 1
            assert outcome.response_json == {"status": "ok"}

    async def test_unsafe_url_raises_before_io(self) -> None:
        """Unsafe URLs raise ValueError immediately without issuing I/O."""
        io_issued = False

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal io_issued
            io_issued = True
            return httpx.Response(200, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            with pytest.raises(ValueError, match="https"):
                await http.request_json(
                    "GET", "http://user:pass@test.example.com/path#frag"
                )
            assert io_issued is False

    async def test_supplied_client_timeout_and_headers_applied(self) -> None:
        """Supplied clients receive User-Agent, Accept, and configured timeout."""
        captured_request: httpx.Request | None = None

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_request
            captured_request = request
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"status": "ok"},
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(
            transport=transport, timeout=httpx.Timeout(99.0)
        ) as client:
            http = ProviderHttpClient(client=client, timeout_seconds=1.5)
            await http.request_json("GET", "https://test.example.com/api")
            assert captured_request is not None
            assert "AgenticThreatInvestigator" in captured_request.headers["User-Agent"]
            assert "application/json" in captured_request.headers["Accept"]
            timeout_ext = captured_request.extensions.get("timeout")
            assert timeout_ext is not None
            assert timeout_ext.get("connect") == 1.5

    async def test_redirect_not_followed(self) -> None:
        """A 302 redirect response is not followed and returns INVALID_RESPONSE."""
        call_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if request.url.path == "/start":
                return httpx.Response(
                    302, headers={"Location": "https://evil.test/end"}
                )
            return httpx.Response(200, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(
            transport=transport, follow_redirects=True
        ) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json("GET", "https://test.example.com/start")
            assert outcome.final_status == 302
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert call_count == 1  # Never contacted Location host

    async def test_wrong_content_type_rejected(self) -> None:
        """A response with text/plain Content-Type returns INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                content=b'{"status": "ok"}',
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert "content type" in (outcome.final_error_message or "")

    async def test_request_404_not_retried(self) -> None:
        """A 404 is not retried and returns NOT_FOUND."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "not found"})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_status == 404
            assert outcome.final_error_code == ProviderErrorCode.NOT_FOUND
            assert outcome.attempt_count == 1

    async def test_request_401_not_retried(self) -> None:
        """A 401 is not retried and returns AUTHENTICATION_FAILED."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "unauthorized"})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.AUTHENTICATION_FAILED
            assert outcome.attempt_count == 1

    async def test_request_403_not_retried(self) -> None:
        """A 403 is not retried and returns FORBIDDEN."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json={"error": "forbidden"})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.FORBIDDEN
            assert outcome.attempt_count == 1

    async def test_request_503_exhausts_retries(self) -> None:
        """A persistent 503 exhausts retries and returns PROVIDER_UNAVAILABLE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={"error": "unavailable"})

        transport = MockTransport(_handler)
        sleep = _RecordingSleep()
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client,
                max_retries=2,
                base_delay_seconds=0.01,
                max_delay_seconds=0.1,
                sleep=sleep,
                jitter_fn=_zero_jitter,
            )
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.PROVIDER_UNAVAILABLE
            assert outcome.attempt_count == 3
            assert len(sleep.calls) == 2

    async def test_429_then_success(self) -> None:
        """A 429 is retried; a subsequent 200 succeeds."""
        call_count = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(429, headers={"Retry-After": "0"}, json={})
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"status": "ok"},
            )

        transport = MockTransport(_handler)
        sleep = _RecordingSleep()
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client,
                max_retries=2,
                base_delay_seconds=0.01,
                sleep=sleep,
                jitter_fn=_zero_jitter,
            )
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_status == 200
            assert outcome.retry_count == 1
            assert call_count == 2
            assert len(sleep.calls) == 1

    async def test_429_exhausted(self) -> None:
        """Persistent 429 returns RATE_LIMITED after retry exhaustion."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(429, headers={"Retry-After": "30"}, json={})

        transport = MockTransport(_handler)
        sleep = _RecordingSleep()
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client,
                max_retries=1,
                base_delay_seconds=0.01,
                sleep=sleep,
                jitter_fn=_zero_jitter,
            )
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.RATE_LIMITED
            assert outcome.attempt_count == 2
            assert len(sleep.calls) == 1
            assert sleep.calls[0] == 30.0

    async def test_timeout_exhausts_retries(self) -> None:
        """A persistent timeout exhausts retries and returns TIMEOUT."""

        def _handler(_: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("connection timed out")

        transport = MockTransport(_handler)
        sleep = _RecordingSleep()
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client,
                max_retries=1,
                base_delay_seconds=0.01,
                sleep=sleep,
                jitter_fn=_zero_jitter,
            )
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.TIMEOUT
            assert outcome.attempt_count == 2

    async def test_timeout_then_success(self) -> None:
        """A timeout is retried; a subsequent 200 succeeds."""
        call_count = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.TimeoutException("timed out")
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"status": "ok"},
            )

        transport = MockTransport(_handler)
        sleep = _RecordingSleep()
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client,
                max_retries=2,
                base_delay_seconds=0.01,
                sleep=sleep,
                jitter_fn=_zero_jitter,
            )
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_status == 200
            assert outcome.retry_count == 1
            assert len(sleep.calls) == 1

    async def test_response_too_large(self) -> None:
        """An oversized response returns INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=b"x" * 1000,
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client, max_response_bytes=100)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert "too large" in (outcome.final_error_message or "")

    async def test_content_length_preflight_rejection(self) -> None:
        """A Content-Length header exceeding max bytes is rejected immediately."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": "10000",
                },
                content=b"short",
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client, max_response_bytes=100)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert "too large" in (outcome.final_error_message or "")

    async def test_malformed_json(self) -> None:
        """A malformed JSON response returns INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=b"not json",
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert outcome.response_json is None

    async def test_client_close_owned(self) -> None:
        """The HTTP client closes its owned client without error."""
        http = ProviderHttpClient(jitter_fn=_zero_jitter)
        await http.aclose()

    async def test_client_does_not_close_supplied(self) -> None:
        """The HTTP client does not close a caller-supplied client."""
        transport = MockTransport(_ok_json_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            await http.aclose()
            resp = await client.get("https://test.example.com/api")
            assert resp.status_code == 200

    async def test_transport_error_safe_message(self) -> None:
        """Transport errors return a generic message, not the exception string."""

        def _handler(_: httpx.Request) -> httpx.Response:
            raise httpx.TransportError(
                "connection to https://secret.internal/api failed"
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, max_retries=0, jitter_fn=_zero_jitter
            )
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.PROVIDER_UNAVAILABLE
            assert "secret.internal" not in (outcome.final_error_message or "")
            assert outcome.final_error_message == "provider transport unavailable"


@pytest.mark.asyncio
class TestFiveXxRetryBoundary:
    """Exact retry behavior across the upper 5xx status boundary."""

    @pytest.mark.asyncio
    async def test_request_599_exhausts_retries(self) -> None:
        """The last true 5xx status (599) remains retryable through exhaustion."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(599, json={"error": "unavailable"})

        transport = MockTransport(_handler)
        sleep = _RecordingSleep()
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client,
                max_retries=2,
                base_delay_seconds=0.01,
                max_delay_seconds=0.1,
                sleep=sleep,
                jitter_fn=_zero_jitter,
            )
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.PROVIDER_UNAVAILABLE
            assert outcome.final_status == 599
            assert outcome.attempt_count == 3
            assert outcome.retry_count == 2
            assert len(sleep.calls) == 2

    @pytest.mark.asyncio
    async def test_request_600_is_terminal_invalid_response(self) -> None:
        """A nonstandard status above 599 is not a retryable server error."""
        request_count = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return httpx.Response(600, json={})

        transport = MockTransport(_handler)
        sleep = _RecordingSleep()
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client,
                max_retries=2,
                base_delay_seconds=0.01,
                sleep=sleep,
                jitter_fn=_zero_jitter,
            )
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert outcome.final_status == 600
            assert outcome.attempt_count == 1
            assert outcome.retry_count == 0
            assert request_count == 1
            assert not sleep.calls


@pytest.mark.asyncio
class TestBoundedLimiter:
    """BoundedLimiter concurrency, rate limiting, and cancellation safety."""

    async def test_basic_concurrency(self) -> None:
        """The semaphore limits concurrent access."""
        limiter = BoundedLimiter(RateLimiterSettings(max_concurrency=2))
        async with limiter:
            pass
        async with limiter:
            pass

    async def test_retry_attempts_consume_actual_rate_slots(self) -> None:
        """Every attempt, including retries, is admitted through a real slot."""
        attempts = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(503, json={})
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json={}
            )

        clock = FakeRateClock()
        limiter_sleep = GatedSleep(clock)
        limiter = BoundedLimiter(
            RateLimiterSettings(max_concurrency=1, requests_per_second=1.0),
            sleep=limiter_sleep,
            clock=clock,
        )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client,
                limiter=limiter,
                max_retries=1,
                base_delay_seconds=0.0,
                sleep=_RecordingSleep(),
                jitter_fn=_zero_jitter,
            )
            task = asyncio.create_task(
                http.request_json("GET", "https://test.example.com/api")
            )
            for _ in range(8):
                await asyncio.sleep(0)

            # Attempt 1 was admitted immediately (first slot) and failed with
            # 503; the retry attempt reserved the next real start slot, one
            # full interval later, proving retries go through the limiter.
            assert attempts == 1
            assert limiter_sleep.calls == pytest.approx([1.0])

            limiter_sleep.gate(0).set()
            outcome = await asyncio.wait_for(task, timeout=1.0)

        assert outcome.final_error_code is None
        assert outcome.attempt_count == 2
        assert attempts == 2

    async def test_cancellation_during_rate_limit_sleep_releases_permit(self) -> None:
        """Cancelling during the rate-limit wait releases the semaphore permit."""
        sleep_started = asyncio.Event()
        sleep_blocker = asyncio.Event()

        async def _blocking_sleep(_: float) -> None:
            sleep_started.set()
            await sleep_blocker.wait()

        limiter = BoundedLimiter(
            RateLimiterSettings(max_concurrency=1, requests_per_second=1.0),
            sleep=_blocking_sleep,
            clock=_FakeClock([0.0, 0.5]),
        )

        # The first acquisition reserves its slot immediately without sleeping.
        await limiter.acquire()
        limiter.release()

        # The second acquisition must wait for the interval; sleep blocks.
        task = asyncio.create_task(limiter.acquire())
        await sleep_started.wait()
        task.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            await task

        # Unblock sleep so subsequent acquire can complete without blocking
        sleep_blocker.set()

        # The permit must be available again immediately
        try:
            await asyncio.wait_for(limiter.acquire(), timeout=0.1)
            limiter.release()
        except TimeoutError:
            pytest.fail("limiter permit was leaked after cancellation")

    async def test_max_concurrency_enforcement(self) -> None:
        """Only max_concurrency tasks can hold permits simultaneously."""
        limiter = BoundedLimiter(RateLimiterSettings(max_concurrency=2))
        current_concurrency = 0
        peak_concurrency = 0
        peak_reached = asyncio.Event()
        gate = asyncio.Event()

        async def _worker() -> None:
            nonlocal current_concurrency, peak_concurrency
            async with limiter:
                current_concurrency += 1
                peak_concurrency = max(peak_concurrency, current_concurrency)
                if peak_concurrency == 2:
                    peak_reached.set()
                await gate.wait()
                current_concurrency -= 1

        tasks = [asyncio.create_task(_worker()) for _ in range(4)]
        await asyncio.wait_for(peak_reached.wait(), timeout=1.0)
        assert peak_concurrency == 2

        gate.set()
        await asyncio.gather(*tasks)
        assert current_concurrency == 0

    async def test_first_acquisition_does_not_sleep(self) -> None:
        """The first acquisition starts immediately, even at clock value 0.0."""
        delays: list[float] = []

        async def _sleep(secs: float) -> None:
            delays.append(secs)

        limiter = BoundedLimiter(
            RateLimiterSettings(max_concurrency=5, requests_per_second=10.0),
            sleep=_sleep,
            clock=lambda: 0.0,
        )

        await limiter.acquire()
        limiter.release()

        assert not delays

    async def test_subsequent_acquisitions_spaced_by_interval(self) -> None:
        """Later acquisitions are spaced by ``1 / requests_per_second``."""
        delays: list[float] = []
        clock_now = 0.0

        async def _sleep(secs: float) -> None:
            nonlocal clock_now
            delays.append(secs)
            clock_now += secs  # The monotonic clock advances while asleep.

        limiter = BoundedLimiter(
            RateLimiterSettings(max_concurrency=5, requests_per_second=10.0),
            sleep=_sleep,
            clock=lambda: clock_now,
        )

        for _ in range(4):
            await limiter.acquire()
            limiter.release()

        assert delays == pytest.approx([0.1, 0.1, 0.1])

    async def test_rate_limit_wait_reserved_under_lock_slept_outside(self) -> None:
        """Wait is reserved under the lock and slept outside it.

        While one task sleeps for its reserved future slot, other tasks must
        still be able to enter the lock and reserve their own slots, proving
        the lock is not held while sleeping. Reserved slots stay ordered and
        spaced by one request interval.
        """
        reserved: list[float] = []
        later_reservations_done = asyncio.Event()
        first_sleep_blocker = asyncio.Event()

        async def _sleep(secs: float) -> None:
            reserved.append(secs)
            if len(reserved) == 1:
                await first_sleep_blocker.wait()
            if len(reserved) == 3:
                later_reservations_done.set()

        limiter = BoundedLimiter(
            RateLimiterSettings(max_concurrency=5, requests_per_second=1.0),
            sleep=_sleep,
            clock=lambda: 0.0,
        )

        # The first acquisition reserves the initial slot without sleeping.
        await limiter.acquire()
        limiter.release()

        tasks = [asyncio.create_task(limiter.acquire()) for _ in range(3)]

        # The first sleeper blocks on its reserved wait, yet the other two
        # tasks must still complete their own reservations and sleeps.
        await asyncio.wait_for(later_reservations_done.wait(), timeout=1.0)
        assert sorted(reserved) == pytest.approx([1.0, 2.0, 3.0])

        first_sleep_blocker.set()
        await asyncio.gather(*tasks)
        assert sorted(reserved) == pytest.approx([1.0, 2.0, 3.0])
        for _ in tasks:
            limiter.release()


@pytest.mark.asyncio
async def test_huge_retry_after_exhaustion_is_bounded_and_reported() -> None:
    """A 400-digit Retry-After sleeps at the cap but is reported unchanged."""
    huge = 10**400

    def _handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": str(huge)}, json={})

    transport = MockTransport(_handler)
    sleep = _RecordingSleep()
    async with httpx.AsyncClient(transport=transport) as client:
        http = ProviderHttpClient(
            client=client,
            max_retries=1,
            base_delay_seconds=0.005,
            max_delay_seconds=0.25,
            sleep=sleep,
            jitter_fn=_zero_jitter,
        )
        outcome = await http.request_json("GET", "https://test.example.com/api")

    assert outcome.final_error_code == ProviderErrorCode.RATE_LIMITED
    assert outcome.attempt_count == 2
    assert len(sleep.calls) == 1
    assert sleep.calls[0] == pytest.approx(0.25)
    assert outcome.retry_after_seconds == huge
