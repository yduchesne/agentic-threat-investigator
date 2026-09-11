# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Provider contract tests for strict DNS-name boundaries in GooglePublicDnsProvider.

Provider responses carry untrusted names. A DNS presentation name may carry
exactly one terminal root dot; names with multiple terminal dots contain an
empty label and must yield one non-retryable ``INVALID_RESPONSE`` with no
evidence instead of silently canonicalizing into normalized evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable
from uuid import UUID

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode, ProviderResult
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")

_RR_TYPE_BY_NUMBER: dict[int, str] = {5: "CNAME", 2: "NS", 12: "PTR"}


def _json_response(body: dict[str, Any]) -> httpx.Response:
    """Build a successful Google DNS JSON response."""
    return httpx.Response(200, headers={"Content-Type": "application/json"}, json=body)


def _record(name: str, rr_type: int, data: str) -> dict[str, Any]:
    """Build one strictly typed answer record."""
    return {"name": name, "type": rr_type, "TTL": 300, "data": data}


def _ptr_entity() -> Entity:
    """An IP address entity resolved through its reverse-pointer name."""
    return Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")


async def _investigate(
    handler: Callable[[httpx.Request], httpx.Response], entity: Entity
) -> ProviderResult:
    """Run one investigation against a mock transport handler."""
    transport = MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
        return await provider.investigate(_FIXED_UUID, entity)


async def _assert_invalid_response(result: ProviderResult) -> None:
    """Assert one non-retryable INVALID_RESPONSE and no evidence."""
    [error] = result.errors
    assert error.code == ProviderErrorCode.INVALID_RESPONSE
    assert error.retryable is False
    assert not result.evidence


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestGoogleDnsStrictNameBoundaries:
    """Malformed provider DNS names cannot become evidence."""

    async def test_question_name_with_multiple_terminal_dots_rejected(self) -> None:
        """A Question.name with multiple terminal dots is INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return _json_response(
                {
                    "Status": 0,
                    "Question": [{"name": "1.2.0.192.in-addr.arpa..", "type": 12}],
                    "Answer": [_record("1.2.0.192.in-addr.arpa.", 12, "host.example.")],
                }
            )

        result = await _investigate(_handler, _ptr_entity())
        await _assert_invalid_response(result)

    async def test_answer_name_with_multiple_terminal_dots_rejected(self) -> None:
        """An answer name with multiple terminal dots is INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return _json_response(
                {
                    "Status": 0,
                    "Answer": [
                        _record("1.2.0.192.in-addr.arpa..", 12, "host.example.")
                    ],
                }
            )

        result = await _investigate(_handler, _ptr_entity())
        await _assert_invalid_response(result)

    @pytest.mark.parametrize(
        ("rr_type", "entity"),
        [
            (5, Entity(type=EntityType.DOMAIN, value="example.com")),
            (2, Entity(type=EntityType.DOMAIN, value="example.com")),
            (12, _ptr_entity()),
        ],
    )
    async def test_name_target_with_multiple_terminal_dots_rejected(
        self, rr_type: int, entity: Entity
    ) -> None:
        """CNAME, NS, and PTR targets with multiple terminal dots are rejected."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.params.get("type") != _RR_TYPE_BY_NUMBER[rr_type]:
                return _json_response({"Status": 0})
            return _json_response(
                {
                    "Status": 0,
                    "Answer": [_record("example.com.", rr_type, "host.example..")],
                }
            )

        result = await _investigate(_handler, entity)
        await _assert_invalid_response(result)

    async def test_reverse_pointer_name_with_multiple_terminal_dots_rejected(
        self,
    ) -> None:
        """A PTR target with multiple terminal dots is INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return _json_response(
                {
                    "Status": 0,
                    "Answer": [
                        _record("1.2.0.192.in-addr.arpa..", 12, "host.example..")
                    ],
                }
            )

        result = await _investigate(_handler, _ptr_entity())
        await _assert_invalid_response(result)


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestGoogleDnsInputValidationOrdering:
    """Malformed queried domain names are rejected before any HTTP I/O.

    The shared validation helper must strictly validate the original entity
    value before lossy canonicalization: repeated terminal dots such as
    ``example.com..`` must yield exactly one non-retryable
    ``UNSUPPORTED_INDICATOR`` with no evidence and zero HTTP requests,
    never a silently repaired DNS lookup.
    """

    @pytest.mark.parametrize(
        "value",
        ["example.com..", "example.com...", "bücher.example.."],
    )
    async def test_repeated_terminal_dots_rejected_without_io(self, value: str) -> None:
        """Repeated terminal dots never reach the Google DNS endpoint."""

        def _handler(_: httpx.Request) -> httpx.Response:
            raise AssertionError("HTTP request issued for an invalid domain")

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(
                ProviderHttpClient(client=client),
                clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value=value)
            )

        assert result.provider == SourceId.GOOGLE_PUBLIC_DNS.value
        assert result.evidence == ()
        [error] = result.errors
        assert error.provider == SourceId.GOOGLE_PUBLIC_DNS.value
        assert error.code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert error.retryable is False
        assert error.message == "invalid entity value"
