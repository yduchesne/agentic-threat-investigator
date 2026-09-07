# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Malformed HTTP content-encoding contract tests for live providers.

A successful response advertising a content encoding it does not actually
use must become one non-retryable typed ``INVALID_RESPONSE`` and never
escape as an HTTPX exception, must not be retried, and must keep the
response context closed and limiter permits released.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from uuid import UUID

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpClient,
    RateLimiterSettings,
)

from .test_google_dns import _dns_response, _record

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")


class _MalformedGzipStream(httpx.AsyncByteStream):
    """A response body stream that fails content decoding during iteration."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"not gzip"


def _malformed_gzip_handler(
    stream: _MalformedGzipStream,
) -> Callable[[httpx.Request], httpx.Response]:
    """Build a handler serving a 200 JSON response with a malformed gzip body."""

    def _handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
            content=stream,
        )

    return _handler


class _RecordingTransport(httpx.AsyncBaseTransport):
    """Wraps a mock transport and records every returned response."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.responses: list[httpx.Response] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response: httpx.Response = await self.inner.handle_async_request(request)
        self.responses.append(response)
        return response


@pytest.mark.asyncio
class TestMalformedContentEncoding:
    """Malformed advertised content encoding is a typed INVALID_RESPONSE."""

    async def test_malformed_gzip_returns_invalid_response(self) -> None:
        """A non-gzip body with a gzip Content-Encoding never raises."""
        transport = MockTransport(_malformed_gzip_handler(_MalformedGzipStream()))
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert outcome.final_error_code.retryable is False
            assert outcome.final_error_message == "invalid response content encoding"
            assert outcome.response_json is None

    async def test_malformed_content_encoding_not_retried(self) -> None:
        """A decoding failure makes exactly one request even with retries enabled."""
        request_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return _malformed_gzip_handler(_MalformedGzipStream())(request)

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client, max_retries=3)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert request_count == 1
            assert outcome.attempt_count == 1
            assert outcome.retry_count == 0
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE

    async def test_safe_message_hides_decoder_details(self) -> None:
        """The error message never exposes decoder, body, URL, or query values."""
        transport = MockTransport(_malformed_gzip_handler(_MalformedGzipStream()))
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json(
                "GET",
                "https://test.example.com/api",
                params={"name": "example.com", "secret": "hidden"},
            )
            message = outcome.final_error_message or ""
            assert message == "invalid response content encoding"
            assert "incorrect header check" not in message
            assert "not gzip" not in message
            assert "example.com" not in message
            assert "hidden" not in message

    async def test_response_closed_after_decoding_failure(self) -> None:
        """The streamed response context is closed when decoding fails."""
        recorder = _RecordingTransport(
            MockTransport(_malformed_gzip_handler(_MalformedGzipStream()))
        )
        async with httpx.AsyncClient(transport=recorder) as client:
            http = ProviderHttpClient(client=client)
            await http.request_json("GET", "https://test.example.com/api")
            assert len(recorder.responses) == 1
            assert recorder.responses[0].is_closed is True

    async def test_limiter_permit_released_after_decoding_failure(self) -> None:
        """The concurrency permit is released after a decoding failure."""
        limiter = BoundedLimiter(RateLimiterSettings(max_concurrency=1))
        transport = MockTransport(_malformed_gzip_handler(_MalformedGzipStream()))
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client, limiter=limiter)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE

            # A leaked permit would make this acquisition time out.
            try:
                await asyncio.wait_for(limiter.acquire(), timeout=0.1)
                limiter.release()
            except TimeoutError:
                pytest.fail("limiter permit was leaked after decoding failure")

    async def test_timeout_and_transport_distinctions_preserved(self) -> None:
        """Timeouts stay TIMEOUT and transport errors stay PROVIDER_UNAVAILABLE."""

        def _timeout_handler(_: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("timed out")

        transport = MockTransport(_timeout_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client, max_retries=0)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.TIMEOUT

        def _transport_handler(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        transport = MockTransport(_transport_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client, max_retries=0)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code == ProviderErrorCode.PROVIDER_UNAVAILABLE


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestGoogleDnsMalformedContentEncoding:  # pylint: disable=too-few-public-methods
    """Provider-contract behavior of Google DNS with malformed content encoding."""

    async def test_partial_evidence_plus_typed_error(self) -> None:
        """A later malformed-encoding DNS query yields typed error plus partial evidence."""

        async def _gzip_stream() -> AsyncIterator[bytes]:
            yield b"not gzip"

        def _handler(request: httpx.Request) -> httpx.Response:
            rr_type = request.url.params.get("type")
            if rr_type == "AAAA":
                return httpx.Response(
                    200,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Encoding": "gzip",
                    },
                    content=_gzip_stream(),
                )
            if rr_type == "A":
                json_payload = _dns_response(
                    answers=[_record("example.com.", 1, "203.0.113.9")]
                )
            else:
                json_payload = _dns_response()
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json=json_payload
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            investigation = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )

        assert len(investigation.evidence) == 1
        assert investigation.evidence[0].facts["query_type"] == "A"
        assert len(investigation.errors) == 1
        assert investigation.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert investigation.errors[0].retryable is False
        assert investigation.errors[0].message == "invalid response content encoding"
        assert "not gzip" not in investigation.errors[0].message
