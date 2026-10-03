# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-authored synthetic STIX 2.1 semantic fixtures (PR 33B).

Every payload in this module is synthetic documentation-safe test data
authored for ATI (RFC 5737 addresses, RFC 3849 ``2001:db8::`` addresses,
RFC 2606 ``.test`` domains, and fixed synthetic UUID-shaped IDs). No
payload is a copied community STIX object and no helper contacts a live
TAXII/MITRE/OASIS service. Builders construct plain JSON-compatible STIX
2.1 object dictionaries and accept ``**overrides`` so malformed shapes can
be authored per test.

The builders never import the production parser or converter; they only
construct plain dictionaries the production seams are then tested against.
"""

from __future__ import annotations

from typing import Any

# Fixed synthetic STIX object IDs (RFC 4122 v4-shaped, documentation-safe).
DOMAIN_ID = "domain-name--11111111-1111-1111-1111-111111111111"
IPV4_ID = "ipv4-addr--22222222-2222-2222-2222-222222222222"
IPV6_ID = "ipv6-addr--33333333-3333-3333-3333-333333333333"
INDICATOR_ID = "indicator--44444444-4444-4444-4444-444444444444"
MALWARE_ID = "malware--55555555-5555-5555-5555-555555555555"
RELATIONSHIP_ID = "relationship--66666666-6666-6666-6666-666666666666"
SIGHTING_ID = "sighting--77777777-7777-7777-7777-777777777777"
ATTACK_PATTERN_ID = "attack-pattern--88888888-8888-8888-8888-888888888888"
CUSTOM_ID = "x-ati-sample--99999999-9999-9999-9999-999999999999"

# Synthetic documentation-safe IOC values (RFC 5737 / RFC 2606 / RFC 3849).
DOMAIN_VALUE = "malicious-domain.test"
MIXED_CASE_DOMAIN_VALUE = "Example.TEST."
UNICODE_DOMAIN_VALUE = "b\u00fccher.example"
IPV4_VALUE = "203.0.113.42"
EXPANDED_IPV4_VALUE = "203.0.113.42"
IPV6_VALUE = "2001:db8::42"
EXPANDED_IPV6_VALUE = "2001:0db8:0000:0000:0000:0000:0000:0042"

# Synthetic documentation-safe timestamps (UTC).
CREATED_TS = "2026-01-01T00:00:00Z"
MODIFIED_TS = "2026-01-02T00:00:00+00:00"
VALID_FROM_TS = "2026-01-03T00:00:00.000000Z"

# One approved equality-only Indicator pattern over the whitelist subset.
SINGLE_DOMAIN_PATTERN = "[domain-name:value = 'malicious-domain.test']"
SINGLE_IPV4_PATTERN = "[ipv4-addr:value = '203.0.113.42']"
SINGLE_IPV6_PATTERN = "[ipv6-addr:value = '2001:db8::42']"


def stix_domain_name(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic valid STIX 2.1 ``domain-name`` SCO."""
    value: dict[str, Any] = {
        "type": "domain-name",
        "id": DOMAIN_ID,
        "spec_version": "2.1",
        "value": DOMAIN_VALUE,
    }
    value.update(overrides)
    return value


def stix_ipv4_addr(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic valid STIX 2.1 ``ipv4-addr`` SCO."""
    value: dict[str, Any] = {
        "type": "ipv4-addr",
        "id": IPV4_ID,
        "spec_version": "2.1",
        "value": IPV4_VALUE,
    }
    value.update(overrides)
    return value


def stix_ipv6_addr(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic valid STIX 2.1 ``ipv6-addr`` SCO."""
    value: dict[str, Any] = {
        "type": "ipv6-addr",
        "id": IPV6_ID,
        "spec_version": "2.1",
        "value": IPV6_VALUE,
    }
    value.update(overrides)
    return value


def stix_indicator(
    *,
    pattern: str = SINGLE_DOMAIN_PATTERN,
    pattern_type: str = "stix",
    pattern_version: str | None = "2.1",
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic valid STIX 2.1 ``indicator`` SDO."""
    value: dict[str, Any] = {
        "type": "indicator",
        "id": INDICATOR_ID,
        "spec_version": "2.1",
        "pattern": pattern,
        "pattern_type": pattern_type,
        "pattern_version": pattern_version,
        "created": CREATED_TS,
        "modified": MODIFIED_TS,
        "revoked": False,
        "valid_from": VALID_FROM_TS,
        "valid_until": None,
        "indicator_types": ["malicious-activity"],
        "object_marking_refs": [
            "marking-definition--1c9b3a0a-7f1b-4b1e-8f2b-2b2b2b2b2b2b"
        ],
    }
    value.update(overrides)
    return value


def stix_malware(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic valid (unsupported) STIX 2.1 ``malware`` SDO."""
    value: dict[str, Any] = {
        "type": "malware",
        "id": MALWARE_ID,
        "spec_version": "2.1",
        "name": "Synthetic Sample Malware",
        "is_family": False,
    }
    value.update(overrides)
    return value


def stix_relationship(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic valid (unsupported) STIX 2.1 ``relationship`` SDO."""
    value: dict[str, Any] = {
        "type": "relationship",
        "id": RELATIONSHIP_ID,
        "spec_version": "2.1",
        "relationship_type": "indicates",
        "source_ref": INDICATOR_ID,
        "target_ref": MALWARE_ID,
    }
    value.update(overrides)
    return value


def stix_sighting(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic valid (unsupported) STIX 2.1 ``sighting`` SDO."""
    value: dict[str, Any] = {
        "type": "sighting",
        "id": SIGHTING_ID,
        "spec_version": "2.1",
        "sighting_of_ref": MALWARE_ID,
    }
    value.update(overrides)
    return value


def stix_attack_pattern(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic valid (unsupported) STIX 2.1 ``attack-pattern`` SDO."""
    value: dict[str, Any] = {
        "type": "attack-pattern",
        "id": ATTACK_PATTERN_ID,
        "spec_version": "2.1",
        "name": "Synthetic Technique",
    }
    value.update(overrides)
    return value


def stix_custom(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic valid custom STIX 2.1 object type."""
    value: dict[str, Any] = {
        "type": "x-ati-sample",
        "id": CUSTOM_ID,
        "spec_version": "2.1",
        "name": "synthetic",
    }
    value.update(overrides)
    return value
