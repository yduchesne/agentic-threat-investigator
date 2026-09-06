# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Autnum range-endpoint bounds contract tests for the RDAP provider.

Authoritative ``startAutnum``/``endAutnum`` values are constrained to the
legal 32-bit ASN domain (``1..4294967295``), the same bounds ATI canonical
ASN values and IANA bootstrap ASN ranges must satisfy.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType

from .rdap_contract_helpers import _iana_then_authority_handler, _investigate
from .rdap_payloads import _bootstrap_registry, _rdap_autnum


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapAutnumRangeBounds:
    """Authoritative autnum range endpoints are bounded to the legal ASN domain."""

    @staticmethod
    def _asn_bootstrap() -> dict[str, Any]:
        """A valid ASN bootstrap registry serving the queried range."""
        return _bootstrap_registry([[["100-200"], ["https://rdap.test/"]]])

    async def _assert_autnum_invalid(self, payload: dict[str, Any]) -> None:
        """Assert an autnum payload yields one non-retryable INVALID_RESPONSE."""
        result = await _investigate(
            _iana_then_authority_handler(
                payload,
                bootstrap_payload=self._asn_bootstrap(),
            ),
            Entity(type=EntityType.ASN, value="AS150"),
        )
        assert len(result.errors) == 1
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False
        assert len(result.evidence) == 0

    async def test_zero_start_autnum_rejected(self) -> None:
        """startAutnum 0 is outside the legal ASN domain and is INVALID_RESPONSE."""
        await self._assert_autnum_invalid(_rdap_autnum(0, 200))

    async def test_zero_end_autnum_rejected(self) -> None:
        """endAutnum 0 is outside the legal ASN domain and is INVALID_RESPONSE."""
        await self._assert_autnum_invalid(_rdap_autnum(100, 0))

    @pytest.mark.parametrize(
        ("start", "end"),
        [
            (4294967296, 4294967296),
            (999999999999, 999999999999),
            (100, 4294967296),
            (100, 999999999999),
        ],
    )
    async def test_autnum_endpoint_above_32_bit_bound_rejected(
        self, start: int, end: int
    ) -> None:
        """Range endpoints above the 32-bit ASN maximum are INVALID_RESPONSE."""
        await self._assert_autnum_invalid(_rdap_autnum(start, end))

    async def test_reversed_autnum_range_rejected(self) -> None:
        """A reversed autnum range remains INVALID_RESPONSE."""
        await self._assert_autnum_invalid(_rdap_autnum(200, 100))

    async def test_non_containing_autnum_range_rejected(self) -> None:
        """An in-bounds range that excludes the queried ASN is INVALID_RESPONSE."""
        await self._assert_autnum_invalid(_rdap_autnum(1, 99))

    async def test_maximum_asn_boundary_accepted(self) -> None:
        """The inclusive 32-bit ASN maximum 4294967295 remains valid evidence."""
        result = await _investigate(
            _iana_then_authority_handler(
                _rdap_autnum(4294967295, 4294967295, "AS4294967295"),
                bootstrap_payload=_bootstrap_registry(
                    [[["4294967295"], ["https://rdap.test/"]]]
                ),
            ),
            Entity(type=EntityType.ASN, value="AS4294967295"),
        )
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["start_autnum"] == 4294967295
        assert result.evidence[0].facts["end_autnum"] == 4294967295
        assert result.evidence[0].source_record_id == "AS4294967295"
