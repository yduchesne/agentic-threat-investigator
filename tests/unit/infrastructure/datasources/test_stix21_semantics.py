# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27C STIX 2.1 semantic-format parser tests (D27C-S01..S12) and PR 33A.

Matrix IDs D27C-S01..S12 pin the decoded-value bundle parser: typed object
output in source order, fail-closed envelope/object validation, extension
field preservation (``x_mitre_*``), retention of unknown valid object
types, deep snapshot isolation from caller mutation, and the serialization
boundary (JSON bytes must be decoded before the semantic parser).

PR 33A adds matrix IDs M33A-01..30 for the reusable single-object seam
``parse_stix21_object()``: direct-object validation, Bundle rejection,
lossless nested preservation, bounded errors that never echo source
values, deterministic re-parse equality, Bundle-adapter delegation with
member-index error context, and module isolation from Evidence/provider/
HTTP/persistence/TAXII implementations. All payloads are synthetic
ATI-authored STIX; no parser test contacts the Internet, MITRE, or any
live source.
"""

from __future__ import annotations

import inspect
import json
import re
from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.infrastructure.datasources import (
    stix21_semantics,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    Stix21Object,
    Stix21SemanticError,
    parse_stix21_bundle,
    parse_stix21_object,
)


def _object(
    object_type: str = "attack-pattern",
    object_id: str = "attack-pattern--a934d7f9-1f15-4d3f-b7a1-2a7f0a1b1c01",
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic valid STIX 2.1 object with ATT&CK extensions."""
    value: dict[str, Any] = {
        "type": object_type,
        "id": object_id,
        "spec_version": "2.1",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2024-06-01T00:00:00.000Z",
        "name": "Phishing",
        "revoked": False,
        "x_mitre_deprecated": False,
        "x_mitre_is_subtechnique": False,
        "x_mitre_attack_id": "T1566",
        "x_mitre_platforms": ["Linux", "Windows"],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
        ],
    }
    value.update(overrides)
    return value


def _bundle(*objects: Any) -> dict[str, Any]:
    """Build one synthetic valid STIX 2.1 bundle."""
    return {"type": "bundle", "id": "bundle--sample", "objects": list(objects)}


class TestValidBundles:
    """D27C-S01/S02/S09/S10: typed output, order, and field preservation."""

    def test_s01_valid_bundle_yields_typed_objects(self) -> None:
        """D27C-S01: a valid bundle parses into typed immutable objects."""
        parsed = parse_stix21_bundle(_bundle(_object()))
        assert len(parsed) == 1
        obj = parsed[0]
        assert isinstance(obj, Stix21Object)
        assert obj.type == "attack-pattern"
        assert obj.id == "attack-pattern--a934d7f9-1f15-4d3f-b7a1-2a7f0a1b1c01"
        assert obj.spec_version == "2.1"
        # The frozen model rejects mutation.
        with pytest.raises(ValidationError):
            obj.type = "malware"

    def test_s02_several_objects_preserve_source_order(self) -> None:
        """D27C-S02: multiple objects are returned in source order."""
        parsed = parse_stix21_bundle(
            _bundle(
                _object(object_id="attack-pattern--one"),
                _object(object_type="malware", object_id="malware--two"),
                _object(object_type="relationship", object_id="relationship--three"),
            )
        )
        assert [obj.id for obj in parsed] == [
            "attack-pattern--one",
            "malware--two",
            "relationship--three",
        ]

    def test_s09_x_mitre_extension_fields_preserved(self) -> None:
        """D27C-S09: ``x_mitre_*`` fields survive validation verbatim."""
        obj = parse_stix21_bundle(
            _bundle(
                _object(
                    x_mitre_attack_id="T1566.001",
                    x_mitre_deprecated=True,
                    x_mitre_is_subtechnique=True,
                    x_mitre_platforms=["Windows"],
                )
            )
        )[0]
        source = obj.source_value()
        assert source["x_mitre_attack_id"] == "T1566.001"
        assert source["x_mitre_deprecated"] is True
        assert source["x_mitre_is_subtechnique"] is True
        assert source["x_mitre_platforms"] == ["Windows"]
        assert deepcopy(source["kill_chain_phases"]) == [
            {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
        ]

    def test_s10_unknown_valid_object_type_retained(self) -> None:
        """D27C-S10: unknown valid types are retained for downstream policy."""
        parsed = parse_stix21_bundle(
            _bundle(
                _object(object_type="campaign", object_id="campaign--future"),
            )
        )
        assert len(parsed) == 1
        assert parsed[0].type == "campaign"
        assert parsed[0].id == "campaign--future"


class TestMalformedBundles:
    """D27C-S03..S08: envelope and object identity validation fails closed."""

    @pytest.mark.parametrize(
        "decoded",
        [
            [],
            ["bundle"],
            None,
            b"{}",
            "bundle",
        ],
    )
    def test_s03_non_object_top_level_fails(self, decoded: Any) -> None:
        """D27C-S03: a non-object decoded value fails closed."""
        with pytest.raises(Stix21SemanticError, match="decoded JSON object"):
            parse_stix21_bundle(decoded)

    @pytest.mark.parametrize(
        "decoded",
        [
            {},
            {"type": "not-a-bundle", "objects": []},
        ],
    )
    def test_s04_top_level_type_not_bundle_fails(self, decoded: dict[str, Any]) -> None:
        """D27C-S04: a top-level type other than ``bundle`` fails closed."""
        with pytest.raises(Stix21SemanticError, match="must be 'bundle'"):
            parse_stix21_bundle(decoded)

    @pytest.mark.parametrize(
        "decoded",
        [
            {"type": "bundle"},
            {"type": "bundle", "objects": None},
            {"type": "bundle", "objects": {}},
            {"type": "bundle", "objects": "records"},
        ],
    )
    def test_s05_objects_missing_or_non_array_fails(
        self, decoded: dict[str, Any]
    ) -> None:
        """D27C-S05: missing/non-array ``objects`` fails closed."""
        with pytest.raises(Stix21SemanticError, match="must be a list"):
            parse_stix21_bundle(decoded)

    def test_s06_non_mapping_object_entry_fails(self) -> None:
        """D27C-S06: a non-mapping object entry fails closed."""
        with pytest.raises(Stix21SemanticError, match="must be an object"):
            parse_stix21_bundle(_bundle("not-an-object"))

    @pytest.mark.parametrize(
        "entry",
        [
            {"type": "attack-pattern"},
            {"type": "attack-pattern", "id": ""},
            {"type": "attack-pattern", "id": "   "},
            {"type": "attack-pattern", "id": 42},
        ],
    )
    def test_s07_missing_or_blank_id_fails(self, entry: dict[str, Any]) -> None:
        """D27C-S07: a missing/blank/non-string id fails closed."""
        with pytest.raises(Stix21SemanticError, match="invalid STIX bundle object"):
            parse_stix21_bundle(_bundle(entry))

    @pytest.mark.parametrize(
        "entry",
        [
            {"id": "attack-pattern--one"},
            {"id": "attack-pattern--one", "type": ""},
            {"id": "attack-pattern--one", "type": 7},
        ],
    )
    def test_s08_missing_or_blank_type_fails(self, entry: dict[str, Any]) -> None:
        """D27C-S08: a missing/blank/non-string type fails closed."""
        with pytest.raises(Stix21SemanticError, match="invalid STIX bundle object"):
            parse_stix21_bundle(_bundle(entry))


class TestSnapshotIsolation:
    """D27C-S11: the semantic object is a deep snapshot, not shared state."""

    def test_s11_caller_mutation_does_not_reach_parsed_object(self) -> None:
        """D27C-S11: mutating the original dict never changes the parsed model."""
        source = _object()
        parsed = parse_stix21_bundle(_bundle(source))[0]
        original = parsed.source_value()
        # Deeply mutate the caller's original mapping after parsing.
        source["name"] = "Mutated"
        source["x_mitre_platforms"].append("MutatedPlatform")
        source["kill_chain_phases"][0]["phase_name"] = "mutated-phase"
        # The parsed object and its thawed copy are unchanged.
        assert parsed.source_value() == original
        assert parsed.source_value()["name"] == "Phishing"
        assert parsed.source_value()["x_mitre_platforms"] == ["Linux", "Windows"]
        assert parsed.source_value()["kill_chain_phases"][0]["phase_name"] == (
            "initial-access"
        )

    def test_s11b_source_value_returns_mutable_deep_copy(self) -> None:
        """The thawed view is a mutable copy; mutating it leaves the model fixed."""
        parsed = parse_stix21_bundle(_bundle(_object()))[0]
        view = parsed.source_value()
        view["name"] = "Mutated"
        view["x_mitre_platforms"].append("Windows")
        assert parsed.source_value()["name"] == "Phishing"
        assert parsed.source_value()["x_mitre_platforms"] == ["Linux", "Windows"]


class TestSerializationBoundary:
    """D27C-S12: raw bytes must be decoded before the semantic parser."""

    def test_s12_malformed_json_bytes_fail_before_parser(self) -> None:
        """D27C-S12: malformed JSON bytes are rejected at the decode boundary.

        The parser accepts decoded values only; passing raw bytes fails
        without attempting JSON interpretation, and byte-level UTF-8/JSON
        errors are rejected by the caller's decoder before the parser runs
        (proven by the MITRE source path).
        """
        with pytest.raises(Stix21SemanticError, match="decoded JSON object"):
            parse_stix21_bundle(b"{not json")
        with pytest.raises(json.JSONDecodeError):
            json.loads(b"{not json")  # skeleton: decode happens first
        with pytest.raises(UnicodeDecodeError):
            b"\xff\xfe{{\x00}}\x00".decode("utf-8")


class TestDirectObjectSeam:
    """M33A-01..20: one reusable single-object validation boundary."""

    def test_m33a_01_minimal_type_and_id_object(self) -> None:
        """M33A-01: a minimal object parses to an immutable Stix21Object."""
        obj = parse_stix21_object(
            {"type": "attack-pattern", "id": "attack-pattern--one"}
        )
        assert isinstance(obj, Stix21Object)
        assert obj.type == "attack-pattern"
        assert obj.id == "attack-pattern--one"
        assert obj.spec_version is None

    def test_m33a_02_spec_version_2_1_preserved(self) -> None:
        """M33A-02: an explicit spec_version 2.1 is preserved."""
        obj = parse_stix21_object(_object())
        assert obj.spec_version == "2.1"

    def test_m33a_03_absent_spec_version_accepted(self) -> None:
        """M33A-03: spec_version is optional and never tightened to 2.1."""
        obj = parse_stix21_object(
            {"type": "attack-pattern", "id": "attack-pattern--one"}
        )
        assert obj.spec_version is None

    def test_m33a_04_unknown_custom_type_accepted(self) -> None:
        """M33A-04: unknown/custom object types remain valid identity data."""
        obj = parse_stix21_object(
            {"type": "x-custom-widget", "id": "x-custom-widget--abc123"}
        )
        assert obj.type == "x-custom-widget"
        assert obj.id == "x-custom-widget--abc123"

    def test_m33a_05_x_mitre_fields_preserved(self) -> None:
        """M33A-05: x_mitre_* extension fields survive verbatim."""
        obj = parse_stix21_object(
            _object(x_mitre_attack_id="T1566.001", x_mitre_deprecated=True)
        )
        source = obj.source_value()
        assert source["x_mitre_attack_id"] == "T1566.001"
        assert source["x_mitre_deprecated"] is True

    def test_m33a_06_nested_extensions_deeply_preserved(self) -> None:
        """M33A-06: nested extensions/custom data are deeply preserved."""
        nested = {
            "visibility": "private",
            "tlp_level": "amber",
            "scores": [1, 2, 3],
            "meta": {"source": "synthetic", "tags": ["a", "b"]},
        }
        obj = parse_stix21_object(
            _object(
                custom_field={"deep": {"list": [1, {"x": 2}]}},
                extensions={"extension-definition--abc": nested},
            )
        )
        source = obj.source_value()
        assert source["custom_field"] == {"deep": {"list": [1, {"x": 2}]}}
        assert source["extensions"] == {"extension-definition--abc": nested}

    def test_m33a_07_mutate_original_after_parse(self) -> None:
        """M33A-07: mutating the caller's mapping never reaches the object."""
        source = _object()
        obj = parse_stix21_object(source)
        original = obj.source_value()
        source["name"] = "Mutated"
        source["x_mitre_platforms"].append("MutatedPlatform")
        source["kill_chain_phases"][0]["phase_name"] = "mutated-phase"
        assert obj.source_value() == original
        assert obj.source_value()["name"] == "Phishing"
        assert obj.source_value()["x_mitre_platforms"] == ["Linux", "Windows"]

    def test_m33a_08_mutate_source_value_copy(self) -> None:
        """M33A-08: mutating source_value() leaves the parsed object fixed."""
        obj = parse_stix21_object(_object())
        view = obj.source_value()
        view["name"] = "Mutated"
        view["x_mitre_platforms"].append("Windows")
        assert obj.source_value()["name"] == "Phishing"
        assert obj.source_value()["x_mitre_platforms"] == ["Linux", "Windows"]

    @pytest.mark.parametrize(
        "decoded",
        [
            [],
            ["attack-pattern"],
            None,
            "attack-pattern",
            7,
            True,
        ],
    )
    def test_m33a_09_non_mapping_fails(self, decoded: Any) -> None:
        """M33A-09: a non-Mapping value fails closed with a bounded error."""
        with pytest.raises(Stix21SemanticError, match="decoded JSON object"):
            parse_stix21_object(decoded)

    def test_m33a_10_raw_bytes_fail(self) -> None:
        """M33A-10: raw bytes are rejected, never JSON-decoded here."""
        with pytest.raises(Stix21SemanticError, match="decoded JSON object"):
            parse_stix21_object(b'{"type": "attack-pattern"}')

    def test_m33a_11_missing_type_fails(self) -> None:
        """M33A-11: a missing type fails closed."""
        with pytest.raises(Stix21SemanticError, match="invalid STIX object"):
            parse_stix21_object({"id": "attack-pattern--one"})

    def test_m33a_12_blank_type_fails(self) -> None:
        """M33A-12: a blank type fails closed."""
        with pytest.raises(Stix21SemanticError, match="invalid STIX object"):
            parse_stix21_object({"type": "   ", "id": "attack-pattern--one"})

    def test_m33a_13_non_string_type_fails(self) -> None:
        """M33A-13: a non-string type fails closed."""
        with pytest.raises(Stix21SemanticError, match="invalid STIX object"):
            parse_stix21_object({"type": 7, "id": "attack-pattern--one"})

    def test_m33a_14_missing_id_fails(self) -> None:
        """M33A-14: a missing id fails closed."""
        with pytest.raises(Stix21SemanticError, match="invalid STIX object"):
            parse_stix21_object({"type": "attack-pattern"})

    def test_m33a_15_blank_id_fails(self) -> None:
        """M33A-15: a blank id fails closed."""
        with pytest.raises(Stix21SemanticError, match="invalid STIX object"):
            parse_stix21_object({"type": "attack-pattern", "id": ""})

    def test_m33a_16_non_string_id_fails(self) -> None:
        """M33A-16: a non-string id fails closed."""
        with pytest.raises(Stix21SemanticError, match="invalid STIX object"):
            parse_stix21_object({"type": "attack-pattern", "id": 42})

    def test_m33a_17_non_string_spec_version_fails(self) -> None:
        """M33A-17: present spec_version must be a string under the contract."""
        with pytest.raises(Stix21SemanticError, match="invalid STIX object"):
            parse_stix21_object(
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--one",
                    "spec_version": 2.1,
                }
            )

    def test_m33a_18_bundle_rejected_by_object_parser(self) -> None:
        """M33A-18: a Bundle is not a STIX object and is rejected."""
        with pytest.raises(Stix21SemanticError, match="not a STIX object"):
            parse_stix21_object({"type": "bundle", "id": "bundle--x", "objects": []})

    def test_m33a_19_source_value_never_echoed_in_error(self) -> None:
        """M33A-19: invalid object values never leak into the error text."""
        secret = "TOP-SECRET-SOURCE-VALUE-9c8f"
        with pytest.raises(Stix21SemanticError) as exc_info:
            parse_stix21_object(
                {
                    "type": "",
                    "id": "attack-pattern--secret",
                    "name": secret,
                    "description": secret,
                }
            )
        message = str(exc_info.value)
        assert secret not in message
        assert "attack-pattern--secret" not in message

    def test_m33a_20_equal_input_parses_deterministically(self) -> None:
        """M33A-20: identical input yields identical semantic output."""
        first = parse_stix21_object(_object())
        second = parse_stix21_object(_object())
        assert first.model_dump() == second.model_dump()
        assert first.source_value() == second.source_value()


class TestBundleAdapter:
    """M33A-21..30: the Bundle stays an envelope adapter over the seam."""

    def test_m33a_21_valid_multi_object_bundle_preserves_order(self) -> None:
        """M33A-21: a valid multi-object Bundle returns exact source order."""
        parsed = parse_stix21_bundle(
            _bundle(
                _object(object_id="attack-pattern--one"),
                _object(object_type="malware", object_id="malware--two"),
                _object(object_type="relationship", object_id="relationship--three"),
            )
        )
        assert [obj.id for obj in parsed] == [
            "attack-pattern--one",
            "malware--two",
            "relationship--three",
        ]

    def test_m33a_22_bundle_retains_unknown_custom_object(self) -> None:
        """M33A-22: unknown/custom object types inside a Bundle are retained."""
        parsed = parse_stix21_bundle(
            _bundle(
                _object(
                    object_type="x-custom-widget",
                    object_id="x-custom-widget--abc123",
                )
            )
        )
        assert parsed[0].type == "x-custom-widget"
        assert parsed[0].id == "x-custom-widget--abc123"

    def test_m33a_23_invalid_member_identifies_index(self) -> None:
        """M33A-23: a failing member N raises a bounded error naming index N."""
        with pytest.raises(Stix21SemanticError, match=r"invalid STIX bundle object 1"):
            parse_stix21_bundle(
                _bundle(_object(), {"type": "attack-pattern"})  # missing id
            )

    def test_m33a_24_malformed_bundle_envelope_existing_behavior(self) -> None:
        """M33A-24: envelope shape failures keep the pre-refactor behavior."""
        decoded: object
        for decoded in ([], None, "bundle", b"{}"):
            with pytest.raises(Stix21SemanticError, match="decoded JSON object"):
                parse_stix21_bundle(decoded)
        with pytest.raises(Stix21SemanticError, match="must be 'bundle'"):
            parse_stix21_bundle({"type": "attack-pattern", "objects": []})

    def test_m33a_25_non_list_objects_existing_behavior(self) -> None:
        """M33A-25: missing/non-list ``objects`` keeps the existing behavior."""
        decoded: dict[str, Any]
        for decoded in (
            {"type": "bundle"},
            {"type": "bundle", "objects": None},
            {"type": "bundle", "objects": {}},
            {"type": "bundle", "objects": "records"},
        ):
            with pytest.raises(Stix21SemanticError, match="must be a list"):
                parse_stix21_bundle(decoded)

    def test_m33a_26_raw_bundle_bytes_existing_behavior(self) -> None:
        """M33A-26: raw Bundle bytes fail at the decoded-value boundary."""
        with pytest.raises(Stix21SemanticError, match="decoded JSON object"):
            parse_stix21_bundle(b'{"type": "bundle", "objects": []}')

    def test_m33a_27_bundle_member_snapshot_isolation(self) -> None:
        """M33A-27: Bundle members are deep snapshots, not shared state."""
        source = _object()
        obj = parse_stix21_bundle(_bundle(source))[0]
        original = obj.source_value()
        source["name"] = "Mutated"
        source["x_mitre_platforms"].append("MutatedPlatform")
        source["kill_chain_phases"][0]["phase_name"] = "mutated-phase"
        assert obj.source_value() == original
        assert obj.source_value()["name"] == "Phishing"
        assert obj.source_value()["x_mitre_platforms"] == ["Linux", "Windows"]

    def test_m33a_28_direct_parse_matches_bundle_member(self) -> None:
        """M33A-28: the direct seam and a Bundle member yield one model."""
        member = _object()
        direct = parse_stix21_object(member)
        via_bundle = parse_stix21_bundle(_bundle(member))[0]
        assert direct == via_bundle
        assert direct.source_value() == via_bundle.source_value()

    def test_m33a_29_bundle_delegates_to_object_seam(self) -> None:
        """M33A-29: the Bundle parser structurally delegates to the seam."""
        source = inspect.getsource(parse_stix21_bundle)
        assert "parse_stix21_object(" in source
        assert "Stix21Object.model_validate" not in source

    def test_m33a_30_relationship_members_have_no_side_effect(self) -> None:
        """M33A-30: Relationship/referenced members stay plain data objects."""
        parsed = parse_stix21_bundle(
            _bundle(
                _object(
                    object_type="relationship",
                    object_id="relationship--r1",
                    relationship_type="uses",
                    source_ref="attack-pattern--a",
                    target_ref="attack-pattern--b",
                ),
                _object(),
            )
        )
        assert len(parsed) == 2
        source = parsed[0].source_value()
        assert source["relationship_type"] == "uses"
        assert source["source_ref"] == "attack-pattern--a"
        assert source["target_ref"] == "attack-pattern--b"
        # No Evidence, Entity, or graph side effect: plain objects only.
        assert isinstance(parsed[0], Stix21Object)
        assert isinstance(parsed[1], Stix21Object)


class TestModuleIsolation:
    """M33A: the semantic module stays free of downstream/runtime layers."""

    def test_no_evidence_provider_http_or_persistence_imports(self) -> None:
        """stix21_semantics imports no Evidence/provider/HTTP/persistence."""
        source = inspect.getsource(stix21_semantics)
        forbidden = re.compile(
            r"^\s*(?:from|import)\s+\S*"
            r"(evidence|providers|persistence|sqlalchemy|httpx|kafka|redpanda|taxii|asyncio)",
            re.M,
        )
        assert forbidden.search(source) is None
        for name in (
            "Evidence",
            "ConvertedEvidence",
            "EvidenceMessage",
            "ToEvidenceConverter",
            "EvidenceProvider",
            "ProviderHttpClient",
            "UnitOfWork",
        ):
            assert not hasattr(stix21_semantics, name)
        import_lines = [
            line.strip()
            for line in source.splitlines()
            if line.lstrip().startswith(("import ", "from "))
        ]
        assert all(
            "httpx" not in line
            and "sqlalchemy" not in line
            and "asyncio" not in line
            and "kafka" not in line
            and "taxii" not in line
            for line in import_lines
        )

    def test_no_source_content_logging(self) -> None:
        """The parser defines no logger and must never log source objects."""
        source = inspect.getsource(stix21_semantics)
        assert "logger" not in source.lower()
        assert "logging" not in source
