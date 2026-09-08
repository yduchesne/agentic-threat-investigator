# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""URLhaus provider HTTP contract tests.

# The provider/test modules deliberately mirror the established
# provider-family shapes (see ThreatFox/AbuseIPDB); per-block R0801
# suppression is not supported by Pylint, so duplicate-code is
# disabled at module scope for the deliberately accepted duplication.
# pylint: disable=duplicate-code

Covers the exact POST form-body and header contract, typed failure
mapping for HTTP statuses and body-encoded statuses, retry behavior, and
cancellation propagation — all against ATI-authored synthetic responses
carried by an in-process transport. No test contacts the real URLhaus
service.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs

import httpx
import pytest

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpPolicy
from tests.support.provider_http import handler_client
from tests.support.urlhaus_fixtures import (
    CANONICAL_URLHAUS_DOMAIN,
    CANONICAL_URLHAUS_URL,
    FIXED_KEY,
    FIXED_TS,
    FIXED_UUID,
    urlhaus_no_results_response,
    urlhaus_provider,
    urlhaus_url_response,
)

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]

_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

_DOMAIN_ENTITY = Entity(
    type=EntityType.DOMAIN,
    value=CANONICAL_URLHAUS_DOMAIN,
)
_URL_ENTITY = Entity(
    type=EntityType.URL,
    value=CANONICAL_URLHAUS_URL,
)


class _CapturingHandler:  # pylint: disable=too-few-public-methods
    """Captures requests and serves one canned response per dispatch."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._response


def _form_fields(request: httpx.Request) -> dict[str, list[str]]:
    """Decode an ``application/x-www-form-urlencoded`` request body."""
    return parse_qs(request.content.decode("utf-8"))


def _assert_invalid(result: object) -> None:
    """Assert one non-retryable INVALID_RESPONSE error and no evidence."""
    (error,) = result.errors  # type: ignore[attr-defined]
    assert not result.evidence  # type: ignore[attr-defined]
    assert error.code is ProviderErrorCode.INVALID_RESPONSE
    assert error.retryable is False


# -- HTTP request contract ------------------------------------------------------


@pytest.mark.unit
class TestHttpRequestContract:
    """Exact POST endpoint, form body, and header contract tests."""

    async def test_exact_url_lookup_post_form_and_headers(self) -> None:
        """A URL query sends the exact documented form POST request."""
        handler = _CapturingHandler(httpx.Response(200, json=urlhaus_url_response()))
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client, clock=lambda: FIXED_TS)
            await provider.investigate(FIXED_UUID, _URL_ENTITY)

        assert len(handler.requests) == 1
        request = handler.requests[0]
        assert request.method == "POST"
        assert str(request.url) == _URL_ENDPOINT
        assert request.headers["Auth-Key"] == FIXED_KEY
        assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert request.headers["Accept"] == "application/json"
        assert _form_fields(request) == {"url": [CANONICAL_URLHAUS_URL]}
        # The query value is the canonical identity, not raw entity input.
        assert "MALICIOUS" not in request.content.decode("utf-8")

    async def test_exact_host_lookup_post_form_and_headers(self) -> None:
        """A domain query sends the exact documented host form POST request."""
        handler = _CapturingHandler(
            httpx.Response(
                200,
                json=urlhaus_url_response(),  # content unused; contract only
            )
        )
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client, clock=lambda: FIXED_TS)
            await provider.investigate(FIXED_UUID, _DOMAIN_ENTITY)

        request = handler.requests[0]
        assert str(request.url) == _HOST_ENDPOINT
        assert _form_fields(request) == {"host": [CANONICAL_URLHAUS_DOMAIN]}

    async def test_auth_key_never_in_url_or_body(self) -> None:
        """The Auth-Key travels only in its header, never in URL or body."""
        handler = _CapturingHandler(httpx.Response(200, json=urlhaus_url_response()))
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client)
            result = await provider.investigate(FIXED_UUID, _URL_ENTITY)

        request = handler.requests[0]
        assert not result.errors
        body = request.content.decode("utf-8")
        assert FIXED_KEY not in body
        assert FIXED_KEY not in str(request.url)
        assert "auth" not in str(request.url).lower()

    async def test_search_value_is_canonical(self) -> None:
        """The form value is the canonicalized entity value, not raw input."""
        handler = _CapturingHandler(
            httpx.Response(200, json=urlhaus_no_results_response())
        )
        entity = Entity(type=EntityType.URL, value="HTTP://Example.COM/a")
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client)
            result = await provider.investigate(FIXED_UUID, entity)

        assert result.evidence == ()
        assert result.errors == ()
        assert _form_fields(handler.requests[0]) == {"url": ["http://example.com/a"]}

    async def test_redirects_are_disabled(self) -> None:
        """The shared client never follows redirects."""

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(301, headers={"Location": "https://elsewhere.test/"})

        async with handler_client(handler) as client:
            provider = urlhaus_provider(client)
            result = await provider.investigate(FIXED_UUID, _URL_ENTITY)

        assert result.evidence == ()
        assert result.errors[0].code in (
            ProviderErrorCode.PROVIDER_UNAVAILABLE,
            ProviderErrorCode.INVALID_RESPONSE,
        )


# -- Status, envelope, and transport failure handling ----------------------------


@pytest.mark.unit
class TestStatusAndTransportFailures:
    """Typed failure mapping for HTTP statuses."""

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (401, ProviderErrorCode.AUTHENTICATION_FAILED),
            (403, ProviderErrorCode.FORBIDDEN),
            (404, ProviderErrorCode.NOT_FOUND),
        ],
    )
    async def test_permanent_statuses_single_attempt(
        self, status: int, expected: ProviderErrorCode
    ) -> None:
        """401/403/404 yield non-retryable typed errors on exactly one attempt."""
        handler = _CapturingHandler(httpx.Response(status, json={}))
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client)
            result = await provider.investigate(FIXED_UUID, _URL_ENTITY)

        assert len(handler.requests) == 1
        assert result.evidence == ()
        assert len(result.errors) == 1
        assert result.errors[0].code == expected
        assert result.errors[0].retryable is False
        assert FIXED_KEY not in result.errors[0].message

    async def test_429_retries_then_reports_retry_after(self) -> None:
        """A 429 with Retry-After schedules exactly that delay and retries once."""
        retry_response = httpx.Response(429, headers={"Retry-After": "30"}, json={})
        handler = _CapturingHandler(retry_response)
        scheduled: list[float] = []

        async def _spy_sleep(seconds: float) -> None:
            scheduled.append(seconds)

        policy = ProviderHttpPolicy(max_retries=1, base_delay_seconds=0.01)
        http_kwargs: dict[str, object] = {"policy": policy, "sleep": _spy_sleep}
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client, http_kwargs=http_kwargs)
            result = await provider.investigate(FIXED_UUID, _URL_ENTITY)

        (error,) = result.errors
        assert len(handler.requests) == 2
        assert not result.evidence
        assert scheduled == [30.0]
        assert error.code is ProviderErrorCode.RATE_LIMITED
        assert error.retry_after_seconds == 30

    async def test_503_then_success_succeeds(self) -> None:
        """A transient 503 retries once and succeeds on the second attempt."""
        responses = [
            httpx.Response(503, json={}),
            httpx.Response(200, json=urlhaus_url_response()),
        ]

        def handler(_: httpx.Request) -> httpx.Response:
            return responses.pop(0)

        policy = ProviderHttpPolicy(max_retries=2, base_delay_seconds=0.01)
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client, http_kwargs={"policy": policy})
            result = await provider.investigate(FIXED_UUID, _URL_ENTITY)

        assert result.errors == ()
        assert len(result.evidence) == 1

    async def test_persistent_5xx_exhausts_retries(self) -> None:
        """A persistent 5xx exhausts retries and ends PROVIDER_UNAVAILABLE."""
        handler = _CapturingHandler(httpx.Response(503, json={}))
        policy = ProviderHttpPolicy(max_retries=2, base_delay_seconds=0.01)
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client, http_kwargs={"policy": policy})
            result = await provider.investigate(FIXED_UUID, _URL_ENTITY)

        (error,) = result.errors
        assert len(handler.requests) == 3
        assert not result.evidence
        assert error.code is ProviderErrorCode.PROVIDER_UNAVAILABLE
        assert error.retryable is True

    async def test_malformed_json_is_invalid_response(self) -> None:
        """A malformed JSON body is a non-retryable INVALID_RESPONSE."""
        handler = _CapturingHandler(
            httpx.Response(
                200, content=b"{not json", headers={"Content-Type": "application/json"}
            )
        )
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client)
            result = await provider.investigate(FIXED_UUID, _URL_ENTITY)

        _assert_invalid(result)

    async def test_wrong_content_type_is_invalid_response(self) -> None:
        """A non-JSON content type is a non-retryable INVALID_RESPONSE."""
        handler = _CapturingHandler(
            httpx.Response(
                200, content=b"<html/>", headers={"Content-Type": "text/html"}
            )
        )
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client)
            result = await provider.investigate(FIXED_UUID, _URL_ENTITY)

        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_cancellation_propagates(self) -> None:
        """A cancelled request propagates ``CancelledError`` unchanged."""

        def handler(_: httpx.Request) -> httpx.Response:
            raise asyncio.CancelledError()

        async with handler_client(handler) as client:
            provider = urlhaus_provider(client)
            with pytest.raises(asyncio.CancelledError):
                await provider.investigate(FIXED_UUID, _URL_ENTITY)

    async def test_response_body_never_leaks_into_errors(self) -> None:
        """Error messages never carry the response body or queried URL."""
        handler = _CapturingHandler(
            httpx.Response(
                200,
                json={"query_status": "ok", "url": CANONICAL_URLHAUS_URL},
            )
        )
        async with handler_client(handler) as client:
            provider = urlhaus_provider(client)
            result = await provider.investigate(FIXED_UUID, _URL_ENTITY)

        (error,) = result.errors
        assert not result.evidence
        assert CANONICAL_URLHAUS_URL not in error.message
        assert json.dumps(urlhaus_no_results_response()) not in error.message
