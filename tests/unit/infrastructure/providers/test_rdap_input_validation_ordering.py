# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Public-path input-validation ordering tests for the RDAP provider.

The shared validation helper must strictly validate the original entity
value before lossy canonicalization: repeated terminal dots such as
``example.com..`` must yield exactly one non-retryable
``UNSUPPORTED_INDICATOR`` with no evidence and zero HTTP requests, so
neither the IANA bootstrap registry nor an authoritative RDAP service is
contacted for a silently repaired name.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from agentic_threat_investigator.infrastructure.providers.rdap import RdapProvider

from .rdap_contract_helpers import _FIXED_UUID


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapInputValidationOrdering:
    """Malformed queried domain names are rejected before any HTTP I/O."""

    @pytest.mark.parametrize(
        "value",
        ["example.com..", "example.com...", "bücher.example.."],
    )
    async def test_repeated_terminal_dots_rejected_without_io(self, value: str) -> None:
        """Repeated terminal dots never reach the bootstrap or authority."""

        def _handler(_: httpx.Request) -> httpx.Response:
            raise AssertionError("HTTP request issued for an invalid domain")

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(
                ProviderHttpClient(client=client),
                clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value=value)
            )

        assert result.provider == SourceId.RDAP.value
        assert result.evidence == ()
        [error] = result.errors
        assert error.provider == SourceId.RDAP.value
        assert error.code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert error.retryable is False
        assert error.message == "invalid entity value"
