# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-authored synthetic fixtures for AbuseIPDB provider tests.

Test-only support; no production package may import from it. Every value
here is clearly synthetic: the IPv4 address is an RFC 5737 documentation
address, operator/report values are invented, and timestamps follow ATI's
fixed test date convention. No value is copied from a real AbuseIPDB
record or the public documentation example.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

from agentic_threat_investigator.app.providers import ProviderResult
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.providers.abuseipdb import (
    AbuseIpdbProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from tests.support.provider_http import no_op_sleep, static_client, zero_jitter

SYNTHETIC_IPV4 = "192.0.2.39"
"""Synthetic RFC 5737 documentation address used by every AbuseIPDB fixture."""

SYNTHETIC_IPV6 = "2001:db8::1"
"""Synthetic RFC 3849 documentation address used by AbuseIPDB fixtures."""

FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
FIXED_KEY = "test-abuseipdb-key"

SYNTHETIC_IPV4_ENTITY = Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
"""Reusable immutable entity for the synthetic IPv4 address."""


class _Removed:  # pylint: disable=too-few-public-methods
    """Sentinel marking a member as absent from the synthetic response."""


REMOVED = _Removed()

REPORT_ENTRY: dict[str, Any] = {
    "reportedAt": "2026-01-15T12:00:00+00:00",
    "comment": "synthetic ignored report comment",
    "categories": [18, 22],
    "reporterId": 1,
    "reporterCountryCode": "US",
    "reporterCountryName": "United States",
}


def check_data(**overrides: Any) -> dict[str, Any]:
    """Build a fully populated synthetic check ``data`` object."""
    data: dict[str, Any] = {
        "ipAddress": SYNTHETIC_IPV4,
        "isPublic": False,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 100,
        "countryCode": "US",
        "usageType": "Documentation Network",
        "isp": "Example Network Operator",
        "domain": "example.invalid",
        "hostnames": [],
        "isTor": False,
        "totalReports": 1,
        "numDistinctUsers": 1,
        "lastReportedAt": "2026-01-15T12:00:00+00:00",
        "reports": [dict(REPORT_ENTRY)],
    }
    for key, value in overrides.items():
        if value is REMOVED:
            data.pop(key, None)
        else:
            data[key] = value
    return data


def check_response(data: Any = None, **extra: Any) -> dict[str, Any]:
    """Wrap a ``data`` payload into the top-level response object."""
    body: dict[str, Any] = {"data": check_data() if data is None else data}
    body.update(extra)
    return body


def provider(
    client: httpx.AsyncClient,
    *,
    clock: Any = None,
    http_kwargs: dict[str, Any] | None = None,
    max_age_in_days: int = 30,
) -> AbuseIpdbProvider:
    """Build the provider under test with the deterministic test key.

    ``http_kwargs`` apply to the shared HTTP client (sleep, jitter, policy);
    ``clock`` is the provider's UTC retrieval clock.
    """
    client_kwargs: dict[str, Any] = {
        "sleep": no_op_sleep,
        "jitter_fn": zero_jitter,
    }
    if http_kwargs:
        client_kwargs.update(http_kwargs)
    provider_kwargs: dict[str, Any] = {"clock": clock} if clock is not None else {}
    return AbuseIpdbProvider(
        ProviderHttpClient(client=client, **client_kwargs),
        api_key=FIXED_KEY,
        max_age_in_days=max_age_in_days,
        **provider_kwargs,
    )


async def investigate_static(
    response: httpx.Response,
    *,
    clock: Any = None,
    http_kwargs: dict[str, Any] | None = None,
    entity: Entity | None = None,
    max_age_in_days: int = 30,
) -> ProviderResult:
    """Investigate the synthetic IPv4 entity against one static response.

    ``AbuseIpdbProvider.investigate`` returns a ``ProviderResult``; the
    return type is kept loose so tests never need a production import for
    assertions on plain attributes.
    """
    async with static_client(response) as client:
        abuse_provider = provider(
            client,
            clock=clock,
            http_kwargs=http_kwargs,
            max_age_in_days=max_age_in_days,
        )
        return await abuse_provider.investigate(
            FIXED_UUID, entity if entity is not None else SYNTHETIC_IPV4_ENTITY
        )


def assert_no_key_leak(value: str) -> None:
    """Prove a provider-facing string carries no credential material."""
    assert FIXED_KEY not in value, "credential material must never leak"
