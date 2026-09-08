# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""URLhaus documented collection-limit and validation-ordering unit tests.

The official contract caps direct-response payload lists and host-response
``urls[]`` collections at 100 entries; these tests pin both boundaries and
prove invalid/unsupported input evaluates neither the retrieval clock nor
the HTTP transport.
"""

# The URLhaus test modules deliberately mirror the established
# provider-family test shapes (see ThreatFox/AbuseIPDB); per-block R0801
# suppression is not supported by Pylint, so duplicate-code is disabled at
# module scope for the deliberately accepted duplication.
# pylint: disable=duplicate-code

from __future__ import annotations

from typing import Any

import httpx
import pytest

from agentic_threat_investigator.app.providers import ProviderResult
from agentic_threat_investigator.domain.entities import Entity, EntityType
from tests.support.provider_http import failing_io_client
from tests.support.urlhaus_fixtures import (
    FIXED_UUID,
    investigate,
    urlhaus_host_response,
    urlhaus_host_url_record,
    urlhaus_payload,
    urlhaus_provider,
    urlhaus_url_record,
)
from tests.unit.infrastructure.providers.test_urlhaus import (
    _DOMAIN_ENTITY,
    _URL_ENTITY,
    _assert_invalid_response,
    _assert_unsupported_no_io,
)

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


def _synthetic_payload(index: int) -> dict[str, Any]:
    """Build one distinct synthetic payload entry."""
    return urlhaus_payload(
        firstseen="2026-08-20",
        filename=f"payload-{index}.bin",
    )


def _synthetic_host_record(index: int) -> dict[str, Any]:
    """Build one distinct synthetic host nested record."""
    return urlhaus_host_url_record(
        id=str(600000 + index),
        url=f"http://malicious-domain.test/download/file-{index}.bin",
    )


def _raising_clock() -> Any:
    """Build a clock callable that fails the test if it is ever evaluated."""

    def _clock() -> Any:
        raise AssertionError("clock must not be evaluated before validation")

    return _clock


@pytest.mark.unit
class TestDocumentedCollectionLimits:
    """The documented 100-entry maximums on both endpoints."""

    async def test_url_lookup_accepts_exactly_100_payloads(self) -> None:
        """100 payload entries are within the documented limit."""
        record = urlhaus_url_record(
            payloads=[_synthetic_payload(i) for i in range(100)]
        )
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        assert result.errors == ()
        assert len(result.evidence[0].facts["matches"][0]["payloads"]) == 100

    async def test_url_lookup_rejects_101_payloads(self) -> None:
        """101 payload entries exceed the documented limit."""
        record = urlhaus_url_record(
            payloads=[_synthetic_payload(i) for i in range(101)]
        )
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        _assert_invalid_response(result)

    async def test_host_response_accepts_exactly_100_urls(self) -> None:
        """100 raw urls[] entries are within the documented limit."""
        payload = urlhaus_host_response(
            *(_synthetic_host_record(i) for i in range(100)),
            url_count="250",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.errors == ()
        assert len(result.evidence[0].facts["matches"]) == 100
        assert result.evidence[0].facts["url_count"] == 250

    async def test_host_response_rejects_101_urls(self) -> None:
        """101 raw urls[] entries exceed the documented limit."""
        payload = urlhaus_host_response(
            *(_synthetic_host_record(i) for i in range(101)),
            url_count="250",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_invalid_response(result)

    async def test_url_count_need_not_equal_urls_length(self) -> None:
        """url_count is the host total; the returned list is capped at 100."""
        payload = urlhaus_host_response(
            *(_synthetic_host_record(i) for i in range(100)),
            url_count="1000",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.errors == ()
        assert result.evidence[0].facts["url_count"] == 1000
        assert len(result.evidence[0].facts["matches"]) == 100


@pytest.mark.unit
class TestValidationAvoidsClockAndHttp:
    """Invalid/unsupported input evaluates neither the clock nor HTTP."""

    @staticmethod
    async def _investigate_with_strict_clock(entity: Entity) -> ProviderResult:
        """Investigate with a raising clock and a failing-I/O client."""
        async with failing_io_client() as client:
            provider = urlhaus_provider(client, clock=_raising_clock())
            return await provider.investigate(FIXED_UUID, entity)

    async def test_unsupported_entity_avoids_clock_and_http(self) -> None:
        """An unsupported entity type never reaches the clock or transport."""
        result = await self._investigate_with_strict_clock(
            Entity(type=EntityType.MALWARE, value="win.asyncrat")
        )
        _assert_unsupported_no_io(result)

    async def test_invalid_supported_entity_avoids_clock_and_http(self) -> None:
        """An uncanonicalizable supported value never reaches clock or HTTP."""
        result = await self._investigate_with_strict_clock(
            Entity(type=EntityType.DOMAIN, value="under_score.example.com")
        )
        _assert_unsupported_no_io(result)

    async def test_invalid_url_avoids_clock_and_http(self) -> None:
        """A URL outside the identity contract never reaches clock or HTTP."""
        result = await self._investigate_with_strict_clock(
            Entity(type=EntityType.URL, value="ftp://example.com/payload.bin")
        )
        _assert_unsupported_no_io(result)

    async def test_unsupported_ipv6_avoids_clock_and_http(self) -> None:
        """IPv6 hosts are rejected before clock evaluation and HTTP."""
        result = await self._investigate_with_strict_clock(
            Entity(type=EntityType.IP_ADDRESS, value="2001:db8::1")
        )
        _assert_unsupported_no_io(result)
