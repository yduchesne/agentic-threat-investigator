# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-authored deterministic OpenCTI fake-world dataset (PR 33E section 10.3).

This module is the single source of truth for the OpenCTI interoperability
fake-world: fixed STIX 2.1 object IDs and timestamps, the exact STIX bundle
that the harness seeds into real OpenCTI, and the expected-state manifest
that the readiness barrier and the final assertion suite both consume (so
readiness criteria and test expectations cannot silently diverge).

The dataset contains the supported IOC objects, the five supported CTI SDO
types, the admitted Relationship profiles (``uses``/``targets``/
``attributed-to``/``controls``), a Sighting, a valid-unsupported STIX object,
an unresolved-reference relationship case, and a version-update case. IDs
and timestamps are fixed; no real threat actor, customer, or private data is
present.
"""

from __future__ import annotations

from typing import Any

FIXTURE_NAME = "opencti-fake-world-v1"

DOMAIN_ID = "domain-name--11111111-1111-1111-1111-111111111111"
IPV4_ID = "ipv4-addr--22222222-2222-2222-2222-222222222222"
IPV6_ID = "ipv6-addr--33333333-3333-3333-3333-333333333333"
INDICATOR_ID = "indicator--44444444-4444-4444-4444-444444444444"
THREAT_ACTOR_ID = "threat-actor--aaaaaaaa-1111-1111-1111-111111111111"
CAMPAIGN_ID = "campaign--bbbbbbbb-2222-2222-2222-222222222222"
INTRUSION_SET_ID = "intrusion-set--cccccccc-3333-3333-3333-333333333333"
TOOL_ID = "tool--dddddddd-4444-4444-4444-444444444444"
INFRASTRUCTURE_ID = "infrastructure--eeeeeeee-5555-5555-5555-555555555555"
SIGHTING_ID = "sighting--ffffffff-6666-6666-6666-666666666666"
UNSUPPORTED_ATTACK_PATTERN_ID = "attack-pattern--99999999-7777-7777-7777-777777777777"
REL_UNRESOLVED_ID = "relationship--aaaaaaaa-7777-7777-7777-777777777777"

DOMAIN_VALUE = "malicious-domain.test"
IPV4_VALUE = "203.0.113.42"
IPV6_VALUE = "2001:db8::42"
INDICATOR_PATTERN = "[domain-name:value = 'malicious-domain.test']"
THREAT_ACTOR_NAME = "Interop Simulation Group"
CAMPAIGN_NAME = "Operation Deterministic Dawn"
INTRUSION_SET_NAME = "Interop Intrusion Set"
TOOL_NAME = "Interop Scanner v2"
INFRASTRUCTURE_NAME = "Interop MitM Infrastructure"

TS_CREATED = "2026-01-01T00:00:00Z"
TS_MODIFIED_V1 = "2026-01-02T00:00:00Z"
TS_MODIFIED_V2 = "2026-01-03T00:00:00Z"
TS_DESC = "Automated-fixed interop fixture; no real data."


def _common(o_type: str, o_id: str, **extra: Any) -> dict[str, Any]:
    """Build one fixed STIX 2.1 object with the shared identity contract."""
    value: dict[str, Any] = {
        "type": o_type,
        "id": o_id,
        "spec_version": "2.1",
        "created": TS_CREATED,
        "modified": TS_MODIFIED_V1,
        "description": TS_DESC,
    }
    value.update(extra)
    return value


def fake_world_objects_v1() -> list[dict[str, Any]]:
    """Return the ordered first-version fake-world STIX objects."""
    return [
        _common("domain-name", DOMAIN_ID, value=DOMAIN_VALUE),
        _common("ipv4-addr", IPV4_ID, value=IPV4_VALUE),
        _common("ipv6-addr", IPV6_ID, value=IPV6_VALUE),
        _common(
            "indicator",
            INDICATOR_ID,
            name="Interop domain indicator",
            pattern=INDICATOR_PATTERN,
            pattern_type="stix",
            valid_from=TS_CREATED,
        ),
        _common("threat-actor", THREAT_ACTOR_ID, name=THREAT_ACTOR_NAME),
        _common("campaign", CAMPAIGN_ID, name=CAMPAIGN_NAME),
        _common("intrusion-set", INTRUSION_SET_ID, name=INTRUSION_SET_NAME),
        _common("tool", TOOL_ID, name=TOOL_NAME),
        _common("infrastructure", INFRASTRUCTURE_ID, name=INFRASTRUCTURE_NAME),
        _relationship(
            "uses",
            "relationship--11111111-8888-8888-8888-888888888888",
            THREAT_ACTOR_ID,
            TOOL_ID,
        ),
        _relationship(
            "targets",
            "relationship--22222222-8888-8888-8888-888888888888",
            THREAT_ACTOR_ID,
            INFRASTRUCTURE_ID,
        ),
        _relationship(
            "attributed-to",
            "relationship--33333333-8888-8888-8888-888888888888",
            CAMPAIGN_ID,
            THREAT_ACTOR_ID,
        ),
        _relationship(
            "controls",
            "relationship--44444444-8888-8888-8888-888888888888",
            INTRUSION_SET_ID,
            INFRASTRUCTURE_ID,
        ),
        _common(
            "sighting",
            SIGHTING_ID,
            sighting_of_ref=THREAT_ACTOR_ID,
            first_seen="2026-01-04T00:00:00Z",
            last_seen="2026-01-05T00:00:00Z",
            count=3,
            _report_id="",
        ),
        # Valid unsupported STIX (generic attack-pattern: never Evidence).
        _common(
            "attack-pattern", UNSUPPORTED_ATTACK_PATTERN_ID, name="Generic pattern"
        ),
        # OpenCTI-realistic unresolved dependency: a relationship whose target
        # is NOT in the collection and is outside the 33D endpoint profile.
        _common(
            "relationship",
            REL_UNRESOLVED_ID,
            relationship_type="uses",
            source_ref=THREAT_ACTOR_ID,
            target_ref="malware--00000000-0000-4000-8000-0000000000ab",
        ),
    ]


def fake_world_update_v2() -> list[dict[str, Any]]:
    """Return the incremental second-version STIX objects.

    ``added after`` the first seed: one brand-new supported object plus a
    version-update of the existing domain-name SCO (same ID, newer
    ``modified``, new ``x_interop_version`` marker). The durable TAXII
    checkpoint must make a second ATI acquisition ingest only these.
    """
    updated_domain = fake_world_objects_v1()[0]
    updated_domain["modified"] = TS_MODIFIED_V2
    updated_domain["x_interop_version"] = 2
    fresh = _common(
        "campaign",
        "campaign--bbbbbbbb-9999-9999-9999-999999999999",
        name="Interop Follow-up Campaign",
        modified=TS_MODIFIED_V2,
    )
    return [updated_domain, fresh]


def _relationship(
    relationship_type: str, r_id: str, source_ref: str, target_ref: str
) -> dict[str, Any]:
    """Build one fixed Relationship with fixed timestamps."""
    return _common(
        "relationship",
        r_id,
        relationship_type=relationship_type,
        source_ref=source_ref,
        target_ref=target_ref,
        start_time="2026-01-01T00:00:00Z",
        stop_time="2026-01-06T00:00:00Z",
    )


def fake_world_bundle_v1() -> dict[str, Any]:
    """Return the exact STIX 2.1 Bundle the harness seeds into OpenCTI."""
    return {
        "type": "bundle",
        "id": "bundle--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "objects": fake_world_objects_v1(),
    }


def expected_manifest_v1() -> dict[str, Any]:
    """Return the deterministic expected-state manifest for the first seed.

    Both the readiness barrier and the final assertion suite consume this
    manifest; expected identities are exact, never row counts alone.
    """
    return {
        "fixture": FIXTURE_NAME,
        "source_id": "urn:ati:source:opencti",
        "datasource_id": "opencti-collection",
        "stix_ids": [obj["id"] for obj in fake_world_objects_v1()],
        "expected_evidence_ids": [
            DOMAIN_ID,
            IPV4_ID,
            IPV6_ID,
            INDICATOR_ID,
            THREAT_ACTOR_ID,
            CAMPAIGN_ID,
            INTRUSION_SET_ID,
            TOOL_ID,
            INFRASTRUCTURE_ID,
            SIGHTING_ID,
            "relationship--11111111-8888-8888-8888-888888888888",
            "relationship--22222222-8888-8888-8888-888888888888",
            "relationship--33333333-8888-8888-8888-888888888888",
            "relationship--44444444-8888-8888-8888-888888888888",
        ],
        "expected_evidence_count": 14,
        "expected_entities": {
            "domain": [DOMAIN_VALUE],
            "ip": [IPV4_VALUE, IPV6_VALUE],
            "indicator": [DOMAIN_VALUE],
            "threat-actor": [THREAT_ACTOR_ID],
            "campaign": [CAMPAIGN_ID],
            "intrusion-set": [INTRUSION_SET_ID],
            "tool": [TOOL_ID],
            "infrastructure": [INFRASTRUCTURE_ID],
        },
        "expected_relationships": [
            {"type": "uses", "source": THREAT_ACTOR_ID, "target": TOOL_ID},
            {"type": "targets", "source": THREAT_ACTOR_ID, "target": INFRASTRUCTURE_ID},
            {"type": "attributed-to", "source": CAMPAIGN_ID, "target": THREAT_ACTOR_ID},
            {
                "type": "controls",
                "source": INTRUSION_SET_ID,
                "target": INFRASTRUCTURE_ID,
            },
        ],
        "unsupported_stix_ids": [UNSUPPORTED_ATTACK_PATTERN_ID, REL_UNRESOLVED_ID],
        "checkpoint": {
            "kind": "taxii_added_after",
            "advance": True,
            "datasource_id": "opencti-collection",
        },
    }


def expected_manifest_v2() -> dict[str, Any]:
    """Return the expected-state manifest of the incremental second seed."""
    manifest = expected_manifest_v1()
    manifest["fixture"] = "opencti-fake-world-v2"
    manifest["stix_ids"] = [obj["id"] for obj in fake_world_update_v2()]
    manifest["expected_evidence_ids"] = [
        "campaign--bbbbbbbb-9999-9999-9999-999999999999"
    ]
    manifest["expected_evidence_count"] = 1
    manifest["expected_entities"] = {
        "campaign": ["Interop Follow-up Campaign"],
    }
    manifest["expected_relationships"] = []
    return manifest
