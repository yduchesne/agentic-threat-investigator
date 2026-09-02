# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for entity canonicalization contracts."""

import pytest

from agentic_threat_investigator.domain.entities import EntityType, canonicalize


def test_domain_normalizes_case_trailing_dot_and_whitespace() -> None:
    """Domains lowercase, trim, and lose trailing dots."""

    assert canonicalize(EntityType.DOMAIN, "  EXAMPLE.COM. ") == "example.com"


def test_domain_idn_encodes_to_punycode() -> None:
    """Internationalized domains canonicalize to their punycode form."""

    assert canonicalize(EntityType.DOMAIN, "MÜNCHEN.de") == "xn--mnchen-3ya.de"


def test_domain_punycode_passes_through() -> None:
    """Already-punycode domains remain unchanged."""

    result = canonicalize(EntityType.DOMAIN, "xn--mnchen-3ya.de")

    assert result == "xn--mnchen-3ya.de"


def test_domain_empty_raises() -> None:
    """Empty domains are rejected."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.DOMAIN, "  . ")


@pytest.mark.parametrize(
    "raw",
    [
        "2001:0DB8:0000:0000:0000:0000:0000:0001",
        " 2001:db8::1 ",
    ],
)
def test_ip_address_compresses(raw: str) -> None:
    """IP addresses canonicalize to their compressed representation."""

    assert canonicalize(EntityType.IP_ADDRESS, raw) == "2001:db8::1"


@pytest.mark.parametrize("raw", ["192.168.001.1", "999.1.1.1", "example.com"])
def test_ip_address_invalid_raises(raw: str) -> None:
    """Malformed IP addresses are rejected."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.IP_ADDRESS, raw)


def test_network_prefix_zeros_host_bits() -> None:
    """Prefixes canonicalize to their network boundary."""

    result = canonicalize(EntityType.NETWORK_PREFIX, "192.168.1.5/24")

    assert result == "192.168.1.0/24"


def test_network_prefix_ipv6_compresses() -> None:
    """IPv6 prefixes canonicalize to compressed boundary form."""

    result = canonicalize(EntityType.NETWORK_PREFIX, "2001:0DB8:0:0:0:0:0:0/64")

    assert result == "2001:db8::/64"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AS65001", "AS65001"),
        ("as65001", "AS65001"),
        ("65001", "AS65001"),
        ("AS000123", "AS123"),
    ],
)
def test_asn_normalizes_prefix_and_leading_zeros(raw: str, expected: str) -> None:
    """ASNs canonicalize to AS<number>."""

    assert canonicalize(EntityType.ASN, raw) == expected


@pytest.mark.parametrize("raw", ["AS", "not-a-number", "AS0", "AS4294967296"])
def test_asn_invalid_raises(raw: str) -> None:
    """Malformed or out-of-range ASNs are rejected."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.ASN, raw)


def test_cve_uppercases() -> None:
    """CVE identifiers canonicalize to uppercase."""

    assert canonicalize(EntityType.VULNERABILITY, " cve-2024-1234 ") == "CVE-2024-1234"


def test_attack_technique_uppercases() -> None:
    """ATT&CK identifiers canonicalize to uppercase."""

    result = canonicalize(EntityType.ATTACK_TECHNIQUE, " t1059.001 ")

    assert result == "T1059.001"


def test_cve_empty_raises() -> None:
    """Empty CVE identifiers are rejected."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.VULNERABILITY, "   ")


def test_attack_technique_empty_raises() -> None:
    """Empty ATT&CK identifiers are rejected."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.ATTACK_TECHNIQUE, "   ")


@pytest.mark.parametrize(
    "entity_type",
    [EntityType.URL, EntityType.ORGANIZATION, EntityType.MALWARE],
)
def test_uncontracted_types_raise(entity_type: EntityType) -> None:
    """Types without a confirmed canonicalization contract are rejected."""

    with pytest.raises(ValueError):
        canonicalize(entity_type, "example")
