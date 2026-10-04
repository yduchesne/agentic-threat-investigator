# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E-1 Option C unit coverage (fixture conformance + canonical identity).

Guards the Option C contracts without any live network or OpenCTI stack:

- fixture STIX IDs are valid RFC 4122 UUIDv4 (the platform's import gate);
- the lifecycle categories partition the exact seeded bundle and rejected
  objects are never counted as ATI unsupported-object coverage;
- the seed -> canonical manifest translation rewrites every identity-bearing
  field (evidence, entities, relationships, sighting, unsupported) and never
  leaks rejected objects into expectations;
- verification fails loudly on missing canonical objects, unrewritten
  relationship/Sighting references, or rejected objects visible in a feed;
- the pre-mapping type-count convergence gate and the canonical id gate stay
  deterministic.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from tests.interop.opencti.canonical_identity import (
    IdentityResolutionError,
    build_canonical_manifest,
    verify_feed_canonical,
)
from tests.interop.opencti.fixtures.opencti_fake_world import (
    CATEGORY_REJECTED,
    CATEGORY_SUPPORTED,
    CATEGORY_UNSUPPORTED,
    IDENTITY_ID,
    REL_UNRESOLVED_ID,
    SIGHTING_ID,
    THREAT_ACTOR_ID,
    UNRESOLVED_MALWARE_ID,
    expected_manifest_v1,
    expected_manifest_v2,
    fake_world_objects_v1,
    fake_world_update_v2,
    object_category_seed_ids_v1,
)
from tests.interop.opencti.status import _feed_type_counts, _feed_type_counts_cover


def _uuid_part(stix_id: str) -> str:
    assert "--" in stix_id
    return stix_id.split("--", 1)[1]


class TestFixtureStixIdConformance:
    """PR 33E-1 Option C: fixture IDs must pass OpenCTI's RFC 4122 gate."""

    @pytest.mark.parametrize("stage", ["v1", "v2"])
    def test_all_seed_ids_are_valid_uuidv4(self, stage: str) -> None:
        objects = fake_world_objects_v1() if stage == "v1" else fake_world_update_v2()
        assert objects, stage
        for obj in objects:
            parsed = uuid.UUID(_uuid_part(obj["id"]))
            assert parsed.version == 4, obj["id"]
            assert parsed.variant == uuid.RFC_4122, obj["id"]
            prefix = obj["id"].split("--", 1)[0]
            assert prefix == obj["type"], obj["id"]

    def test_dangling_malware_target_stays_valid_v4(self) -> None:
        parsed = uuid.UUID(_uuid_part(UNRESOLVED_MALWARE_ID))
        assert parsed.version == 4
        assert parsed.variant == uuid.RFC_4122

    def test_categories_partition_exact_bundle(self) -> None:
        categories = object_category_seed_ids_v1()
        object_ids = {obj["id"] for obj in fake_world_objects_v1()}
        partitioned: set[str] = set()
        for seed_ids in categories.values():
            assert not (partitioned & set(seed_ids)), "category overlap"
            partitioned |= set(seed_ids)
        assert partitioned == object_ids
        assert len(object_ids) == 19

    def test_rejected_never_in_unsupported_coverage(self) -> None:
        """REJECTED_BY_OPENCTI_PROFILE objects are not ATI-unsupported objects."""
        seed_manifest = expected_manifest_v1()
        rejected = seed_manifest["object_categories"][CATEGORY_REJECTED]
        unsupported = seed_manifest["object_categories"][CATEGORY_UNSUPPORTED]
        assert not (set(rejected) & set(unsupported))
        assert not (set(rejected) & set(seed_manifest["expected_evidence_ids"]))
        assert REL_UNRESOLVED_ID in rejected

    def test_rejected_reasons_exact_and_required(self) -> None:
        seed_manifest = expected_manifest_v1()
        rejected = set(seed_manifest["object_categories"][CATEGORY_REJECTED])
        assert set(seed_manifest["rejected_by_opencti_profile_reasons"]) == rejected

    def test_reference_contract_is_internal_and_stix_valid(self) -> None:
        ids = {obj["id"] for obj in fake_world_objects_v1()}
        references: list[str] = []
        relationships = 0
        sightings = 0
        for obj in fake_world_objects_v1():
            if obj["type"] == "relationship":
                relationships += 1
                references.extend([obj["source_ref"], obj["target_ref"]])
            if obj["type"] == "sighting":
                sightings += 1
                references.append(obj["sighting_of_ref"])
                references.extend(obj.get("where_sighted_refs") or [])
        assert relationships == 7  # 4 legal + targets + controls + unresolved
        assert sightings == 1
        # Every reference is either a seeded object or the deliberate
        # dangling malware endpoint (never materialized by design).
        assert all(ref in ids or ref == UNRESOLVED_MALWARE_ID for ref in references)
        sighting = next(
            obj for obj in fake_world_objects_v1() if obj["type"] == "sighting"
        )
        assert sighting["where_sighted_refs"] == [IDENTITY_ID]
        assert sighting["sighting_of_ref"] == THREAT_ACTOR_ID

    def test_legal_relationship_types_are_real_opencti_materializable(self) -> None:
        """Only uses/attributed-to are asserted as supported evidence rows."""
        manifest = expected_manifest_v1()
        types = {rel["type"] for rel in manifest["expected_relationships"]}
        assert types == {"uses", "attributed-to"}
        assert len(manifest["expected_relationships"]) == 4

    def test_feed_type_counts_match_materializable_composition(self) -> None:
        manifest = expected_manifest_v1()
        counts = manifest["expected_feed_type_counts"]
        assert sum(counts.values()) == len(
            manifest["object_categories"][CATEGORY_SUPPORTED]
        ) + len(manifest["object_categories"][CATEGORY_UNSUPPORTED])
        assert counts == {
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
        }


class TestCanonicalManifestTranslation:
    """Seed IDs -> canonical OpenCTI identities everywhere identities matter."""

    def _mapping(self) -> dict[str, str]:
        seed_manifest = expected_manifest_v1()
        mapping: dict[str, str] = {}
        for category, seed_ids in seed_manifest["object_categories"].items():
            if category == CATEGORY_REJECTED:
                continue
            for index, seed_id in enumerate(seed_ids):
                o_type = seed_id.split("--", 1)[0]
                mapping[seed_id] = f"{o_type}--canonical-{index:03d}"
        return mapping

    def test_translation_covers_every_identity_field(self) -> None:
        seed_manifest = expected_manifest_v1()
        mapping = self._mapping()
        canonical = build_canonical_manifest(seed_manifest, mapping)
        assert canonical["canonical"] is True
        assert "expected_feed_type_counts" not in canonical
        assert set(canonical["expected_evidence_ids"]) == {
            mapping[seed]
            for seed in seed_manifest["object_categories"][CATEGORY_SUPPORTED]
        }
        # stix_ids carry only materializable canonical identities.
        assert len(canonical["stix_ids"]) == len(mapping)
        assert not (
            set(canonical["stix_ids"])
            & set(seed_manifest["object_categories"][CATEGORY_REJECTED])
        )
        # Unsupported canonical identities survive for the zero-semantics proof.
        assert set(canonical["unsupported_stix_ids"]) == {
            mapping[seed]
            for seed in seed_manifest["object_categories"][CATEGORY_UNSUPPORTED]
        }

    def test_entities_and_relationships_use_canonical_ids(self) -> None:
        seed_manifest = expected_manifest_v1()
        mapping = self._mapping()
        canonical = build_canonical_manifest(seed_manifest, mapping)
        for entity_type, values in seed_manifest["expected_entities"].items():
            expected = [mapping.get(v, v) for v in values]
            assert canonical["expected_entities"][entity_type] == expected
        expected_relationships = []
        for rel in seed_manifest["expected_relationships"]:
            expected_relationships.append(
                {
                    "type": rel["type"],
                    "source": mapping[rel["source"]],
                    "target": mapping[rel["target"]],
                }
            )
        assert canonical["expected_relationships"] == expected_relationships

    def test_sighting_translated_with_canonical_endpoints(self) -> None:
        seed_manifest = expected_manifest_v1()
        mapping = self._mapping()
        canonical = build_canonical_manifest(seed_manifest, mapping)
        sighting = canonical["expected_sighting_evidence"]
        assert sighting["seed_id"] == SIGHTING_ID
        assert sighting["evidence_id"] == mapping[SIGHTING_ID]
        assert sighting["sighting_of"] == mapping[THREAT_ACTOR_ID]

    def test_v2_manifest_translates_without_rejected_noise(self) -> None:
        seed_manifest = expected_manifest_v2()
        mapping = {
            seed_id: seed_id.replace("campaign", "campaign-canon")
            for seed_id in seed_manifest["object_categories"][CATEGORY_SUPPORTED]
        }
        canonical = build_canonical_manifest(seed_manifest, mapping)
        assert canonical["expected_evidence_ids"] == [
            mapping[seed_manifest["object_categories"][CATEGORY_SUPPORTED][0]]
        ]
        assert canonical["unsupported_stix_ids"] == []
        assert canonical["expected_relationships"] == []


class TestFeedVerification:
    """Canonical identity verification against a (bounded) real feed shape."""

    @staticmethod
    def _seed_manifest() -> dict[str, Any]:
        return expected_manifest_v1()

    @staticmethod
    def _mapping() -> dict[str, str]:
        seed_manifest = expected_manifest_v1()
        mapping: dict[str, str] = {}
        for category, seed_ids in seed_manifest["object_categories"].items():
            if category == CATEGORY_REJECTED:
                continue
            for index, seed_id in enumerate(seed_ids):
                o_type = seed_id.split("--", 1)[0]
                mapping[seed_id] = f"{o_type}--canon-{index:02d}"
        return mapping

    def _feed(self, mapping: dict[str, str]) -> list[dict[str, Any]]:
        by_seed = {obj["id"]: obj for obj in fake_world_objects_v1()}
        feed: list[dict[str, Any]] = []
        for seed_id, canonical in mapping.items():
            obj = by_seed[seed_id]
            feed_obj: dict[str, Any] = {"type": obj["type"], "id": canonical}
            if obj["type"] == "relationship":
                feed_obj["relationship_type"] = obj["relationship_type"]
                feed_obj["source_ref"] = mapping[obj["source_ref"]]
                feed_obj["target_ref"] = mapping[obj["target_ref"]]
            if obj["type"] == "sighting":
                feed_obj["sighting_of_ref"] = mapping[obj["sighting_of_ref"]]
                feed_obj["where_sighted_refs"] = [
                    mapping[ref] for ref in obj["where_sighted_refs"]
                ]
            feed.append(feed_obj)
        return feed

    def test_complete_feed_verifies(self) -> None:
        mapping = self._mapping()
        result = verify_feed_canonical(
            self._seed_manifest(), mapping, self._feed(mapping), exact_feed=True
        )
        assert result["ok"] is True
        assert result["relationship_refs_canonicalized"] is True
        assert result["sighting_refs_canonicalized"] is True
        assert result["rejected_absent"] is True

    def test_missing_canonical_identity_raises(self) -> None:
        mapping = self._mapping()
        feed = self._feed(mapping)
        feed.pop()
        with pytest.raises(IdentityResolutionError):
            verify_feed_canonical(
                self._seed_manifest(), mapping, feed, exact_feed=False
            )

    def test_unrewritten_relationship_ref_raises(self) -> None:
        mapping = self._mapping()
        feed = self._feed(mapping)
        rel = next(o for o in feed if o["type"] == "relationship")
        rel["source_ref"] = "threat-actor--seed-leak"
        with pytest.raises(IdentityResolutionError, match="not canonicalized"):
            verify_feed_canonical(
                self._seed_manifest(), mapping, feed, exact_feed=False
            )

    def test_unrewritten_sighting_ref_raises(self) -> None:
        mapping = self._mapping()
        feed = self._feed(mapping)
        sighting = next(o for o in feed if o["type"] == "sighting")
        sighting["sighting_of_ref"] = "threat-actor--seed-leak"
        with pytest.raises(IdentityResolutionError, match="sighting_of_ref"):
            verify_feed_canonical(
                self._seed_manifest(), mapping, feed, exact_feed=False
            )

    def test_rejected_object_visible_in_feed_raises(self) -> None:
        mapping = self._mapping()
        feed = self._feed(mapping)
        feed.append(
            {
                "type": "relationship",
                "id": "relationship--55555555-8888-4888-8888-888888888888",
            }
        )
        with pytest.raises(
            IdentityResolutionError, match="REJECTED_BY_OPENCTI_PROFILE"
        ):
            verify_feed_canonical(
                self._seed_manifest(), mapping, feed, exact_feed=False
            )

    def test_foreign_object_fails_exact_feed_only(self) -> None:
        mapping = self._mapping()
        feed = self._feed(mapping)
        feed.append({"type": "domain-name", "id": "domain-name--foreign"})
        with pytest.raises(IdentityResolutionError, match="outside the materialized"):
            verify_feed_canonical(self._seed_manifest(), mapping, feed, exact_feed=True)
        result = verify_feed_canonical(
            self._seed_manifest(), mapping, feed, exact_feed=False
        )
        assert result["ok"] is True

    def test_colliding_canonical_identity_raises(self) -> None:
        mapping = self._mapping()
        values = list(mapping.values())
        mapping[next(iter(mapping))] = values[-1]
        feed = self._feed(mapping)
        with pytest.raises(IdentityResolutionError, match="not bijective"):
            verify_feed_canonical(
                self._seed_manifest(), mapping, feed, exact_feed=False
            )


class TestTypeCountConvergenceGate:
    """The pre-mapping seed-manifest gate stays deterministic."""

    def test_counts_cover(self) -> None:
        expected = {"campaign": 2, "domain-name": 1}
        assert _feed_type_counts_cover(expected, {"campaign": 2, "domain-name": 1})
        assert _feed_type_counts_cover(expected, {"campaign": 3, "domain-name": 2})
        assert not _feed_type_counts_cover(expected, {"campaign": 1, "domain-name": 1})
        assert not _feed_type_counts_cover(expected, {"domain-name": 1})

    def test_feed_type_counts_derivation(self) -> None:
        objects = [
            {"type": "campaign", "id": "a"},
            {"type": "campaign", "id": "b"},
            {"type": "domain-name", "id": "c"},
        ]
        assert _feed_type_counts(objects) == {"campaign": 2, "domain-name": 1}

    def test_v2_manifest_counts(self) -> None:
        manifest = expected_manifest_v2()
        assert manifest["expected_feed_type_counts"] == {"campaign": 2}
        assert set(manifest["stix_ids"]) == {
            obj["id"] for obj in fake_world_update_v2()
        }

    def test_v1_manifest_is_deterministic_json(self) -> None:
        # The manifest must be JSON-serializable (harness writes it to disk).
        payload = json.dumps(expected_manifest_v1())
        parsed = json.loads(payload)
        assert parsed["fixture"] == "opencti-fake-world-v1"
