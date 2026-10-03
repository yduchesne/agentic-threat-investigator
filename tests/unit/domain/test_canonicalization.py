# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for entity canonicalization contracts."""

import pytest

from agentic_threat_investigator.domain.entities import (
    EntityType,
    canonicalize,
    validate_dns_name,
)


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
    [EntityType.ORGANIZATION],
)
def test_uncontracted_types_raise(entity_type: EntityType) -> None:
    """Types without a confirmed canonicalization contract are rejected.

    ORGANIZATION deliberately has no canonicalizer: no source semantics in
    v0.1 authorize organization entity discovery. MALWARE has the narrow
    ThreatFox machine-identifier contract.
    """

    with pytest.raises(ValueError):
        canonicalize(entity_type, "example")


def test_validate_dns_name_canonicalizes() -> None:
    """Strict validation canonicalizes case, trailing dots, whitespace, and IDNA."""

    assert validate_dns_name("  EXAMPLE.COM. ") == "example.com"
    assert validate_dns_name("Bücher.Example.") == "xn--bcher-kva.example"
    assert validate_dns_name("xn--bcher-kva.example") == "xn--bcher-kva.example"
    assert validate_dns_name("1.0.0.127.in-addr.arpa") == "1.0.0.127.in-addr.arpa"
    assert validate_dns_name("  1.0.0.127.in-addr.arpa. ") == "1.0.0.127.in-addr.arpa"


@pytest.mark.parametrize(
    "bad_name",
    [
        "example.com..",
        "example.com...",
        "  example.com..  ",
        "Bücher.Example..",
        "xn--bcher-kva.example..",
        "1.0.0.127.in-addr.arpa..",
        "1.0.0.127.in-addr.arpa...",
    ],
)
def test_validate_dns_name_rejects_multiple_terminal_dots(bad_name: str) -> None:
    """More than one terminal root dot introduces an empty label and is rejected."""

    with pytest.raises(ValueError):
        validate_dns_name(bad_name)


@pytest.mark.parametrize(
    "bad_name",
    [
        "bad label.com",
        "bad_label.com",
        "a..b.com",
        ".leadingdot.com",
        "-leadinghyphen.com",
        "trailinghyphen-.com",
        "x" * 64 + ".com",
        ("ab." * 100),  # > 253 octets overall
        "",
        "   ",
        ".",
    ],
)
def test_validate_dns_name_rejects_malformed(bad_name: str) -> None:
    """Spaces, underscores, empty labels, and overlong values are rejected."""

    with pytest.raises(ValueError):
        validate_dns_name(bad_name)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("win.asyncrat", "win.asyncrat"),
        ("win-treeview_qakbot-47", "win-treeview_qakbot-47"),
        ("x", "x"),
        ("a" * 128, "a" * 128),
    ],
)
def test_malware_machine_ids_canonicalize_idempotently(raw: str, expected: str) -> None:
    """Strict lowercase machine identifiers pass through unchanged."""

    assert canonicalize(EntityType.MALWARE, raw) == expected
    assert canonicalize(EntityType.MALWARE, expected) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "",
        " ",
        "AsyncRAT",
        "WIN.ASYNCRAT",
        "win asyncrat",
        "win/asyncrat",
        "win:asyncrat",
        "win;asyncrat",
        "win+asyncrat",
        "программа",
        "-leadingpunctuation",
        ".leadingdot",
        "_leadingunderscore",
        "a" * 129,
    ],
)
def test_malware_identity_rejects_non_machine_forms(bad: str) -> None:
    """Uppercase, whitespace, disallowed punctuation, and overlong IDs are rejected."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.MALWARE, bad)


def test_malware_printable_name_is_never_an_identity() -> None:
    """Printable names never canonicalize: identity is the machine ID only."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.MALWARE, "AsyncRAT (aka Win32.AsyncRAT)")


# --- PR 33C source-neutral CTI Entity identity contract (M33C-D01..D25) ---

_TA_ID = "threat-actor--11111111-1111-1111-1111-111111111111"
_CAMPAIGN_ID = "campaign--22222222-2222-2222-2222-222222222222"
_INTRUSION_SET_ID = "intrusion-set--33333333-3333-3333-3333-333333333333"
_TOOL_ID = "tool--44444444-4444-4444-4444-444444444444"
_INFRASTRUCTURE_ID = "infrastructure--55555555-5555-5555-5555-555555555555"


@pytest.mark.parametrize(
    ("entity_type", "value"),
    [
        (EntityType.THREAT_ACTOR, _TA_ID),
        (EntityType.CAMPAIGN, _CAMPAIGN_ID),
        (EntityType.INTRUSION_SET, _INTRUSION_SET_ID),
        (EntityType.TOOL, _TOOL_ID),
        (EntityType.INFRASTRUCTURE, _INFRASTRUCTURE_ID),
    ],
)
def test_m33c_d01_d05_exact_machine_ids_unchanged(
    entity_type: EntityType, value: str
) -> None:
    """D01..D05: exact STIX machine IDs pass through byte-for-byte unchanged."""

    assert canonicalize(entity_type, value) == value


def test_m33c_d06_wrong_stix_prefix_rejected() -> None:
    """D06: a threat-actor carrying a campaign prefix fails closed."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.THREAT_ACTOR, _CAMPAIGN_ID)


def test_m33c_d07_campaign_wrong_prefix_rejected() -> None:
    """D07: a campaign carrying a tool prefix fails closed."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.CAMPAIGN, _TOOL_ID)


@pytest.mark.parametrize(
    "bad",
    [
        "threat-actor--not-a-uuid",
        "threat-actor--11111111-1111-1111-1111-11111111111x",
        "threat-actor--11111111111111111111111111111111",
    ],
)
def test_m33c_d08_malformed_uuid_rejected(bad: str) -> None:
    """D08: a non-canonical or malformed UUID suffix fails closed."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.THREAT_ACTOR, bad)


def test_m33c_d09_missing_delimiter_rejected() -> None:
    """D09: a missing ``--`` delimiter fails closed."""

    with pytest.raises(ValueError):
        canonicalize(
            EntityType.THREAT_ACTOR, "threat-actor11111111-1111-1111-1111-111111111111"
        )


@pytest.mark.parametrize(
    "bad", [f" {_TA_ID}", _TA_ID.upper(), _TA_ID.replace("-", "_")]
)
def test_m33c_d10_d11_padded_or_mutated_identifier_rejected(bad: str) -> None:
    """D10/D11: leading/trailing whitespace and mutated prefixes fail closed."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.THREAT_ACTOR, bad)


def test_m33c_d12_human_name_never_identity() -> None:
    """D12: a printable human/alias name is never a machine identity."""

    with pytest.raises(ValueError):
        canonicalize(EntityType.THREAT_ACTOR, "APT 29")
    with pytest.raises(ValueError):
        canonicalize(EntityType.TOOL, "Synthetic Scanner")


def test_m33c_d13_blank_rejected() -> None:
    """D13: blank values fail closed."""

    for entity_type in (
        EntityType.THREAT_ACTOR,
        EntityType.CAMPAIGN,
        EntityType.INTRUSION_SET,
        EntityType.TOOL,
        EntityType.INFRASTRUCTURE,
    ):
        with pytest.raises(ValueError):
            canonicalize(entity_type, "")
        with pytest.raises(ValueError):
            canonicalize(entity_type, "   ")


def test_m33c_d14_canonicalization_idempotent() -> None:
    """D14: canonicalization is idempotent for accepted machine IDs."""

    for entity_type, value in (
        (EntityType.THREAT_ACTOR, _TA_ID),
        (EntityType.CAMPAIGN, _CAMPAIGN_ID),
        (EntityType.INTRUSION_SET, _INTRUSION_SET_ID),
        (EntityType.TOOL, _TOOL_ID),
        (EntityType.INFRASTRUCTURE, _INFRASTRUCTURE_ID),
    ):
        assert canonicalize(entity_type, canonicalize(entity_type, value)) == value


def test_m33c_d15_same_display_name_never_merges_identity() -> None:
    """D15: different machine IDs stay distinct even under one display name.

    Names are display metadata only; canonical identity is the exact machine
    value, so two same-name STIX objects remain two distinct identities.
    """

    first = canonicalize(EntityType.THREAT_ACTOR, _TA_ID)
    second = canonicalize(EntityType.THREAT_ACTOR, _TA_ID.replace("1111", "9999", 1))
    assert first != second


@pytest.mark.parametrize(
    ("entity_type", "stix_prefix"),
    [
        (EntityType.THREAT_ACTOR, "threat-actor"),
        (EntityType.CAMPAIGN, "campaign"),
        (EntityType.INTRUSION_SET, "intrusion-set"),
        (EntityType.TOOL, "tool"),
        (EntityType.INFRASTRUCTURE, "infrastructure"),
    ],
)
def test_m33c_d16_d20_every_new_enum_has_canonicalizer(
    entity_type: EntityType, stix_prefix: str
) -> None:
    """D16..D20: each new enum member is registered in ``_CANONICALIZERS``."""

    value = f"{stix_prefix}--99999999-9999-9999-9999-999999999999"
    assert canonicalize(entity_type, value) == value


def test_m33c_d21_malware_contract_unchanged() -> None:
    """D21: the existing MALWARE machine-ID contract is unchanged."""

    assert canonicalize(EntityType.MALWARE, "win.asyncrat") == "win.asyncrat"
    with pytest.raises(ValueError):
        canonicalize(EntityType.MALWARE, "AsyncRAT")


def test_m33c_d22_vulnerability_contract_unchanged() -> None:
    """D22: the existing CVE contract is unchanged."""

    assert canonicalize(EntityType.VULNERABILITY, "cve-2024-1234") == "CVE-2024-1234"


def test_m33c_d23_attack_technique_contract_unchanged() -> None:
    """D23: the existing ATT&CK technique contract is unchanged."""

    assert canonicalize(EntityType.ATTACK_TECHNIQUE, "t1059") == "T1059"
    with pytest.raises(ValueError):
        canonicalize(EntityType.ATTACK_TECHNIQUE, "")


def test_m33c_d24_ioc_canonicalizers_unchanged() -> None:
    """D24: existing domain/IP/URL/ASN/prefix IOC contracts are unchanged."""

    assert canonicalize(EntityType.DOMAIN, "  EXAMPLE.COM ") == "example.com"
    assert canonicalize(EntityType.IP_ADDRESS, "2001:0DB8::1") == "2001:db8::1"
    assert canonicalize(EntityType.ASN, "as65001") == "AS65001"
    assert canonicalize(EntityType.NETWORK_PREFIX, "192.168.1.5/24") == "192.168.1.0/24"
    assert (
        canonicalize(EntityType.URL, "HTTPS://Example.COM/A") == "https://example.com/A"
    )


def test_m33c_d25_enum_wire_values_exact() -> None:
    """D25: every EntityType serializes to its exact approved wire value."""

    assert {member.value for member in EntityType} >= {
        "threat_actor",
        "campaign",
        "intrusion_set",
        "tool",
        "infrastructure",
    }
    assert EntityType.THREAT_ACTOR.value == "threat_actor"
    assert EntityType.CAMPAIGN.value == "campaign"
    assert EntityType.INTRUSION_SET.value == "intrusion_set"
    assert EntityType.TOOL.value == "tool"
    assert EntityType.INFRASTRUCTURE.value == "infrastructure"
