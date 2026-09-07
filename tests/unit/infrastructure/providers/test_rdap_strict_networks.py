# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Provider contract tests for strict network-prefix boundaries in the RDAP provider.

Bootstrap registry keys and CIDR0 prefixes with host bits set assert a
different network than they render. They invalidate the registry or response
as ``INVALID_RESPONSE`` instead of being silently masked to a broader
network address, and they can never influence authority selection.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType

from .rdap_contract_helpers import (
    _assert_invalid,
    _iana_then_authority_handler,
    _investigate,
)
from .rdap_payloads import _bootstrap_registry, _rdap_network
from .test_rdap_strict_models import _network_payload


def _host_bit_registry(keys: list[str]) -> dict[str, Any]:
    """Build an IANA registry payload around the given IPv4/IPv6 keys."""
    return _bootstrap_registry([[keys, ["https://rdap.test/"]]])


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapStrictNetworkBoundaries:
    """Host-bit-set network prefixes cannot produce evidence or authority."""

    async def test_cidr0_host_bit_set_prefix_rejected(self) -> None:
        """Host-bit-set CIDR0 prefixes must not be masked to a broader network."""
        for cidr in [
            {"v4prefix": "198.51.100.42", "length": 24},
            {"v6prefix": "2001:db8::1", "length": 32},
        ]:
            await _assert_invalid(
                _network_payload(cidr0_cidrs=[cidr]),
                Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
            )

    async def test_ipv4_host_bit_set_bootstrap_key_rejected(self) -> None:
        """An IPv4 key with host bits set invalidates the registry."""
        handler = _iana_then_authority_handler(
            bootstrap_payload=_host_bit_registry(["198.51.100.42/24"])
        )
        result = await _investigate(
            handler, Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1")
        )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert len(result.evidence) == 0

    async def test_ipv6_host_bit_set_bootstrap_key_rejected(self) -> None:
        """An IPv6 key with nonzero host bits invalidates the registry."""
        handler = _iana_then_authority_handler(
            bootstrap_payload=_host_bit_registry(["2001:db8::1/32"])
        )
        result = await _investigate(
            handler, Entity(type=EntityType.IP_ADDRESS, value="2001:db8::1")
        )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert len(result.evidence) == 0

    async def test_host_bit_set_key_cannot_influence_selection(self) -> None:
        """Host-bit-set keys invalidate the registry instead of matching."""
        handler = _iana_then_authority_handler(
            bootstrap_payload=_host_bit_registry(
                [
                    "198.51.100.0/24",
                    "198.51.100.42/24",
                ]
            )
        )
        result = await _investigate(
            handler, Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1")
        )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert len(result.evidence) == 0

    async def test_canonical_network_keys_still_select(self) -> None:
        """Canonical network-address keys keep selecting the longest prefix."""
        handler = _iana_then_authority_handler(
            authority_payload=_rdap_network("198.51.100.0", "198.51.100.255"),
            bootstrap_payload=_bootstrap_registry(
                [
                    [["198.51.0.0/16"], ["https://broad.rir.test/"]],
                    [["198.51.100.0/24"], ["https://specific.rir.test/"]],
                ]
            ),
        )
        result = await _investigate(
            handler,
            Entity(type=EntityType.IP_ADDRESS, value="198.51.100.42"),
        )
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["cidr0_cidrs"] == (
            {"prefix": "198.51.100.0", "length": 24},
        )
