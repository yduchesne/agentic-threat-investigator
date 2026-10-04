# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-authored deterministic OpenCTI fake-world dataset (PR 33E section 10.3).

This module is the single source of truth for the OpenCTI interoperability
fake-world: fixed STIX 2.1 object IDs and timestamps, the exact STIX bundle
that the harness seeds into real OpenCTI, and the expected-state manifest
that the readiness barrier and the final assertion suite both consume (so
readiness criteria and test expectations cannot silently diverge).

The dataset contains the supported IOC objects, the five supported CTI SDO
types, the admitted Relationship instances that real OpenCTI 6.9 can
actually materialize and that ATI supports (``uses`` and ``attributed-to``,
PR 33E-1 re-scope), a STIX-valid Sighting (``sighting_of_ref`` +
``where_sighted_refs`` referencing a deterministic Identity), a valid
unsupported object reaching ATI through TAXII (generic ``attack-pattern``),
an ATI-unsupported Identity that the Sighting references, and explicit
objects that real OpenCTI 6.9 rejects (``targets``/``controls`` profile
mismatches and an unresolved-reference relationship). IDs and timestamps
are fixed; no real threat actor, customer, or private data is present.

Object lifecycle categories (PR 33E-1 Option C):

- ``MATERIALIZABLE_AND_ATI_SUPPORTED``: materializes in real OpenCTI, is
  exported by TAXII, and becomes ATI Evidence/Entity/Relationship.
- ``MATERIALIZABLE_BUT_ATI_UNSUPPORTED``: materializes and reaches ATI
  through TAXII but produces zero ATI persistence semantics (never
  Evidence/Entity/Relationship).
- ``REJECTED_BY_OPENCTI_PROFILE``: real OpenCTI rejects the object at import
  (relationship-schema matrix or unresolvable reference); the object is
  deliberately **not** counted as ATI unsupported-object coverage.
"""

from __future__ import annotations

from typing import Any

FIXTURE_NAME = "opencti-fake-world-v1"

# --- Lifecycle categories (PR 33E-1 Option C) ------------------------------
CATEGORY_SUPPORTED = "MATERIALIZABLE_AND_ATI_SUPPORTED"
CATEGORY_UNSUPPORTED = "MATERIALIZABLE_BUT_ATI_UNSUPPORTED"
CATEGORY_REJECTED = "REJECTED_BY_OPENCTI_PROFILE"

# --- Deterministic object identities (valid UUIDv4 form) -------------------
# Every fixture STIX id is a valid RFC 4122 UUIDv4 (version nibble ``4``,
# variant nibble in ``8/9/a/b``); the platform validates every incoming id with
# ``uuidValidate`` (src/graphql/schema.js) and rejects non-conformant spellings.
# The readable per-object digit patterns survive; OpenCTI regenerates its own
# canonical ``standard_id`` on export (harness maps seed -> canonical, PR 33E-1
# Option C), so these precise IDs are never expected back from the TAXII feed.
DOMAIN_ID = "domain-name--11111111-1111-4111-8111-111111111111"
IPV4_ID = "ipv4-addr--22222222-2222-4222-8222-222222222222"
IPV6_ID = "ipv6-addr--33333333-3333-4333-8333-333333333333"
INDICATOR_ID = "indicator--44444444-4444-4444-8444-444444444444"
THREAT_ACTOR_ID = "threat-actor--aaaaaaaa-1111-4111-8111-111111111111"
CAMPAIGN_ID = "campaign--bbbbbbbb-2222-4222-8222-222222222222"
INTRUSION_SET_ID = "intrusion-set--cccccccc-3333-4333-8333-333333333333"
TOOL_ID = "tool--dddddddd-4444-4444-8444-444444444444"
INFRASTRUCTURE_ID = "infrastructure--eeeeeeee-5555-4555-8555-555555555555"
SIGHTING_ID = "sighting--ffffffff-6666-4666-8666-666666666666"
IDENTITY_ID = "identity--77777777-7777-4777-8777-777777777777"
UNSUPPORTED_ATTACK_PATTERN_ID = "attack-pattern--99999999-7777-4777-8777-777777777777"

# Real-OpenCTI-materializable Relationship instances (uses + attributed-to).
REL_USES_TOOL_ID = "relationship--11111111-8888-4888-8888-888888888888"
REL_USES_INFRA_ID = "relationship--22222222-8888-4888-8888-888888888888"
REL_ATTRIBUTED_TO_CAMPAIGN_ID = "relationship--33333333-8888-4888-8888-888888888888"
REL_ATTRIBUTED_TO_INTRUSION_SET_ID = (
    "relationship--44444444-8888-4888-8888-888888888888"
)

# Explicitly REJECTED_BY_OPENCTI_PROFILE Relationship instances (kept in the
# fixture to document platform behavior; real OpenCTI 6.9 rejects them).
REL_TARGETS_REJECTED_ID = "relationship--55555555-8888-4888-8888-888888888888"
REL_CONTROLS_REJECTED_ID = "relationship--66666666-8888-4888-8888-888888888888"
REL_UNRESOLVED_ID = "relationship--aaaaaaaa-7777-4777-8777-777777777777"

# The deliberately unresolved dependency target stays outside the collection
# (never seeded as an object); already in valid UUIDv4 form.
UNRESOLVED_MALWARE_ID = "malware--00000000-0000-4000-8000-0000000000ab"

# Incremental-v2 object identities.
V2_CAMPAIGN_ID = "campaign--bbbbbbbb-9999-4999-8999-999999999999"

DOMAIN_VALUE = "malicious-domain.test"
IPV4_VALUE = "203.0.113.42"
IPV6_VALUE = "2001:db8::42"
INDICATOR_PATTERN = "[domain-name:value = 'malicious-domain.test']"
THREAT_ACTOR_NAME = "Interop Simulation Group"
CAMPAIGN_NAME = "Operation Deterministic Dawn"
INTRUSION_SET_NAME = "Interop Intrusion Set"
TOOL_NAME = "Interop Scanner v2"
INFRASTRUCTURE_NAME = "Interop MitM Infrastructure"
IDENTITY_NAME = "Interop Sighting Organization"
ATTACK_PATTERN_NAME = "Generic pattern"

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
        # Legal relationship instances real OpenCTI 6.9 can materialize and
        # ATI supports (PR 33E-1 re-scope: uses + attributed-to only).
        _relationship("uses", REL_USES_TOOL_ID, THREAT_ACTOR_ID, TOOL_ID),
        _relationship("uses", REL_USES_INFRA_ID, THREAT_ACTOR_ID, INFRASTRUCTURE_ID),
        _relationship(
            "attributed-to", REL_ATTRIBUTED_TO_CAMPAIGN_ID, CAMPAIGN_ID, THREAT_ACTOR_ID
        ),
        _relationship(
            "attributed-to",
            REL_ATTRIBUTED_TO_INTRUSION_SET_ID,
            INTRUSION_SET_ID,
            THREAT_ACTOR_ID,
        ),
        # STIX 2.1-valid Sighting: sighting_of_ref is the supported CTI SDO and
        # where_sighted_refs (required by the format) references the Identity.
        _common(
            "sighting",
            SIGHTING_ID,
            sighting_of_ref=THREAT_ACTOR_ID,
            where_sighted_refs=[IDENTITY_ID],
            first_seen="2026-01-04T00:00:00Z",
            last_seen="2026-01-05T00:00:00Z",
            count=3,
        ),
        # ATI-unsupported Identity: materializes (required by the Sighting) but
        # must produce zero ATI Entity/Evidence/Relationship semantics.
        _common(
            "identity",
            IDENTITY_ID,
            name=IDENTITY_NAME,
            identity_class="organization",
        ),
        # Valid unsupported STIX (generic attack-pattern): reaches ATI through
        # TAXII, never Evidence.
        _common(
            "attack-pattern", UNSUPPORTED_ATTACK_PATTERN_ID, name=ATTACK_PATTERN_NAME
        ),
        # OpenCTI relationship-schema rejection: ``targets`` is not admitted
        # toward Infrastructure for the supported CTI types (PR 33E-1 Option C).
        _relationship(
            "targets", REL_TARGETS_REJECTED_ID, THREAT_ACTOR_ID, INFRASTRUCTURE_ID
        ),
        # OpenCTI relationship-schema rejection: ``controls`` is not admitted
        # from Intrusion-Set toward Infrastructure.
        _relationship(
            "controls", REL_CONTROLS_REJECTED_ID, INTRUSION_SET_ID, INFRASTRUCTURE_ID
        ),
        # OpenCTI missing-reference rejection: target is NOT in the collection
        # and outside the 33D endpoint profile.
        _common(
            "relationship",
            REL_UNRESOLVED_ID,
            relationship_type="uses",
            source_ref=THREAT_ACTOR_ID,
            target_ref=UNRESOLVED_MALWARE_ID,
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
        V2_CAMPAIGN_ID,
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


def object_category_seed_ids_v1() -> dict[str, list[str]]:
    """Return the exact v1 seed-id partition by lifecycle category."""
    supported = [
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
        REL_USES_TOOL_ID,
        REL_USES_INFRA_ID,
        REL_ATTRIBUTED_TO_CAMPAIGN_ID,
        REL_ATTRIBUTED_TO_INTRUSION_SET_ID,
    ]
    unsupported = [IDENTITY_ID, UNSUPPORTED_ATTACK_PATTERN_ID]
    rejected = [REL_TARGETS_REJECTED_ID, REL_CONTROLS_REJECTED_ID, REL_UNRESOLVED_ID]
    return {
        CATEGORY_SUPPORTED: supported,
        CATEGORY_UNSUPPORTED: unsupported,
        CATEGORY_REJECTED: rejected,
    }


def expected_manifest_v1() -> dict[str, Any]:
    """Return the deterministic expected-state manifest for the first seed.

    Both the readiness barrier and the final assertion suite consume this
    manifest; expected identities are exact, never row counts alone. The
    seed-level manifest expresses every identity in fixture seed IDs and
    carries deterministic feed type-counts for the pre-mapping convergence
    gate; the harness translates it into the canonical manifest (canonical
    OpenCTI ``standard_id`` identities) once OpenCTI materialization state is
    resolved (PR 33E-1 Option C).
    """
    supported, unsupported, rejected = tuple(
        object_category_seed_ids_v1()[key]
        for key in (CATEGORY_SUPPORTED, CATEGORY_UNSUPPORTED, CATEGORY_REJECTED)
    )
    return {
        "fixture": FIXTURE_NAME,
        "source_id": "urn:ati:source:opencti",
        "datasource_id": "opencti-collection",
        "object_categories": {
            CATEGORY_SUPPORTED: supported,
            CATEGORY_UNSUPPORTED: unsupported,
            CATEGORY_REJECTED: rejected,
        },
        "rejected_by_opencti_profile_reasons": {
            REL_TARGETS_REJECTED_ID: (
                "opencti_relationship_schema: targets not allowed "
                "Threat-Actor-Group -> Infrastructure"
            ),
            REL_CONTROLS_REJECTED_ID: (
                "opencti_relationship_schema: controls not allowed "
                "Intrusion-Set -> Infrastructure"
            ),
            REL_UNRESOLVED_ID: (
                "opencti_missing_reference: target malware--00000000-0000-4000-"
                "8000-0000000000ab is not present"
            ),
        },
        "stix_ids": [obj["id"] for obj in fake_world_objects_v1()],
        # Deterministic materializable feed composition (the pre-mapping
        # convergence gate); rejected objects never reach the feed so they
        # carry no type-count expectation.
        "expected_feed_type_counts": {
            "domain-name": 1,
            "ipv4-addr": 1,
            "ipv6-addr": 1,
            "indicator": 1,
            "threat-actor": 1,
            "campaign": 1,
            "intrusion-set": 1,
            "tool": 1,
            "infrastructure": 1,
            "relationship": 4,
            "sighting": 1,
            "identity": 1,
            "attack-pattern": 1,
        },
        "expected_evidence_ids": supported,
        "expected_evidence_count": len(supported),
        "expected_entities": {
            # ATI wire entity types and canonical values exactly as the
            # pipeline persists them: ``domain``/``ip_address`` canonicalize
            # to their value, the five CTI Entity types canonicalize to the
            # STIX id byte-for-byte. ``indicator`` is not an ATI Entity
            # (Evidence only), so it has no expected entity row.
            "domain": [DOMAIN_VALUE],
            "ip_address": [IPV4_VALUE, IPV6_VALUE],
            "threat_actor": [THREAT_ACTOR_ID],
            "campaign": [CAMPAIGN_ID],
            "intrusion_set": [INTRUSION_SET_ID],
            "tool": [TOOL_ID],
            "infrastructure": [INFRASTRUCTURE_ID],
        },
        "expected_relationships": [
            {"type": "uses", "source": THREAT_ACTOR_ID, "target": TOOL_ID},
            {"type": "uses", "source": THREAT_ACTOR_ID, "target": INFRASTRUCTURE_ID},
            {"type": "attributed-to", "source": CAMPAIGN_ID, "target": THREAT_ACTOR_ID},
            {
                "type": "attributed-to",
                "source": INTRUSION_SET_ID,
                "target": THREAT_ACTOR_ID,
            },
        ],
        "expected_sighting_evidence": {
            "seed_id": SIGHTING_ID,
            "sighting_of": THREAT_ACTOR_ID,
        },
        "unsupported_stix_ids": unsupported,
        "checkpoint": {
            "kind": "taxii_added_after",
            "advance": True,
            "datasource_id": "opencti-collection",
        },
    }


def expected_manifest_v2() -> dict[str, Any]:
    """Return the expected-state manifest of the incremental second seed."""
    return {
        "fixture": "opencti-fake-world-v2",
        "source_id": "urn:ati:source:opencti",
        "datasource_id": "opencti-collection",
        "object_categories": {
            CATEGORY_SUPPORTED: [V2_CAMPAIGN_ID],
            CATEGORY_UNSUPPORTED: [],
            CATEGORY_REJECTED: [],
        },
        "rejected_by_opencti_profile_reasons": {},
        "stix_ids": [obj["id"] for obj in fake_world_update_v2()],
        # After v2 the collection holds two campaigns (v1 + the new one); the
        # v2 convergence gate waits for the new campaign object to be visible.
        "expected_feed_type_counts": {"campaign": 2},
        "expected_evidence_ids": [V2_CAMPAIGN_ID],
        "expected_evidence_count": 1,
        "expected_entities": {
            # ATI campaign Entity canonicalizes to the STIX id; the canonical
            # manifest translation rewrites the seed id to the canonical one.
            "campaign": [V2_CAMPAIGN_ID],
        },
        "expected_relationships": [],
        "expected_sighting_evidence": {},
        "unsupported_stix_ids": [],
        "checkpoint": {
            "kind": "taxii_added_after",
            "advance": False,
            "datasource_id": "opencti-collection",
        },
    }
