# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared synthetic transport and assertion helpers for RDAP provider tests.

This module is test-only support for the RDAP provider contract suites; it
carries no test cases of its own. It keeps the deterministic mock-transport
plumbing in one place so each contract module stays focused on its own
behavior.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

import httpx
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from agentic_threat_investigator.infrastructure.providers.rdap import RdapProvider

from .rdap_payloads import _bootstrap_registry

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
"""A fixed investigation UUID shared by the RDAP contract tests."""


def _iana_then_authority_handler(
    authority_payload: dict[str, Any] | None = None,
    *,
    bootstrap_payload: dict[str, Any] | None = None,
    authority_host: str = "rdap.test",
    authority_content: bytes | None = None,
    bootstrap_content: bytes | None = None,
) -> Any:
    """Build a handler serving an IANA bootstrap registry and an authority."""

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "data.iana.org":
            if bootstrap_content is not None:
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    content=bootstrap_content,
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=(
                    bootstrap_payload
                    if bootstrap_payload is not None
                    else _bootstrap_registry(
                        [[["com"], [f"https://{authority_host}/"]]]
                    )
                ),
            )
        if authority_content is not None:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                content=authority_content,
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "application/rdap+json"},
            json=authority_payload if authority_payload is not None else {},
        )

    return _handler


async def _investigate(
    handler: Any,
    entity: Entity,
    **client_kwargs: Any,
) -> Any:
    """Run one investigation against a mock transport handler."""
    transport = MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = RdapProvider(ProviderHttpClient(client=client, **client_kwargs))
        return await provider.investigate(_FIXED_UUID, entity)


async def _assert_invalid(payload: dict[str, Any], entity: Entity) -> None:
    """Assert a payload yields exactly one non-retryable INVALID_RESPONSE."""
    result = await _investigate(_iana_then_authority_handler(payload), entity)
    assert len(result.errors) == 1
    assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
    assert result.errors[0].retryable is False
    assert len(result.evidence) == 0


async def _request_count(
    handler: Callable[[httpx.Request], httpx.Response], entity: Entity
) -> tuple[Any, int]:
    """Investigate while counting HTTP requests issued by the provider."""
    requests: list[httpx.Request] = []

    def _counting(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    transport = MockTransport(_counting)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = RdapProvider(ProviderHttpClient(client=client, max_retries=0))
        result = await provider.investigate(_FIXED_UUID, entity)
    return result, len(requests)


async def _assert_invalid_with_request_budget(
    payload: dict[str, Any], entity: Entity, *, max_requests: int = 2
) -> None:
    """Assert one INVALID_RESPONSE, no evidence, and a bounded request count.

    The default budget of two requests covers exactly the IANA bootstrap
    lookup plus the single authoritative lookup; anything more would mean
    the provider issued additional lookups after the invalid response.
    """
    result, requests = await _request_count(
        _iana_then_authority_handler(payload), entity
    )
    assert len(result.errors) == 1
    assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
    assert result.errors[0].retryable is False
    assert len(result.evidence) == 0
    assert requests <= max_requests


async def _domain_result(payload: dict[str, Any], value: str = "example.com") -> Any:
    """Investigate a synthetic domain payload against a domain entity."""
    return await _investigate(
        _iana_then_authority_handler(payload),
        Entity(type=EntityType.DOMAIN, value=value),
    )
