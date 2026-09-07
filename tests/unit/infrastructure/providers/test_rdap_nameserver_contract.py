# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Optional RDAP nameserver name members and normalized-name precedence tests."""

from __future__ import annotations

import pytest

from agentic_threat_investigator.domain.entities import Entity, EntityType

from .rdap_contract_helpers import (
    _assert_invalid,
    _iana_then_authority_handler,
    _investigate,
)
from .test_rdap_strict_models import _domain_payload


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapNameserverContract:
    """Optional RDAP nameserver name members and normalized-name precedence."""

    async def test_nameserver_ldh_name_only(self) -> None:
        """A nameserver with only ldhName contributes its canonical name."""
        payload = _domain_payload(nameservers=[{"ldhName": "NS1.Example.com"}])
        result = await _investigate(
            _iana_then_authority_handler(payload),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert len(result.evidence) == 1
        assert list(result.evidence[0].facts["nameservers"]) == ["ns1.example.com"]

    async def test_nameserver_unicode_name_only(self) -> None:
        """A Unicode-only nameserver canonicalizes to IDNA in facts."""
        payload = _domain_payload(nameservers=[{"unicodeName": "münchen.example"}])
        result = await _investigate(
            _iana_then_authority_handler(payload),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert len(result.evidence) == 1
        assert list(result.evidence[0].facts["nameservers"]) == [
            "xn--mnchen-3ya.example"
        ]

    async def test_nameserver_equivalent_ldh_and_unicode_forms(self) -> None:
        """Equivalent LDH and Unicode forms canonicalize to one identity."""
        payload = _domain_payload(
            nameservers=[
                {
                    "ldhName": "xn--mnchen-3ya.example",
                    "unicodeName": "münchen.example",
                }
            ]
        )
        result = await _investigate(
            _iana_then_authority_handler(payload),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert len(result.evidence) == 1
        assert list(result.evidence[0].facts["nameservers"]) == [
            "xn--mnchen-3ya.example"
        ]

    async def test_nameserver_without_any_name_is_omitted(self) -> None:
        """A nameserver with neither name never fails the lookup nor yields a fact."""
        payload = _domain_payload(
            nameservers=[{"handle": "NS1"}, {"ldhName": "ns2.example.com"}]
        )
        result = await _investigate(
            _iana_then_authority_handler(payload),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert len(result.evidence) == 1
        assert list(result.evidence[0].facts["nameservers"]) == ["ns2.example.com"]

    async def test_nameserver_source_order_preserved(self) -> None:
        """Normalized nameserver names preserve upstream order."""
        payload = _domain_payload(
            nameservers=[
                {"ldhName": "ns2.example.com"},
                {"unicodeName": "münchen.example"},
                {"ldhName": "ns1.example.com"},
            ]
        )
        result = await _investigate(
            _iana_then_authority_handler(payload),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert len(result.evidence) == 1
        assert list(result.evidence[0].facts["nameservers"]) == [
            "ns2.example.com",
            "xn--mnchen-3ya.example",
            "ns1.example.com",
        ]

    async def test_nameserver_unicode_only_malformed_name_rejected(self) -> None:
        """A malformed supplied unicodeName stays INVALID_RESPONSE."""
        await _assert_invalid(
            _domain_payload(nameservers=[{"unicodeName": "bad_label.example"}]),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
