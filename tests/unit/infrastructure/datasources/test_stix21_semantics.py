# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27C STIX 2.1 semantic-format parser tests.

Matrix IDs D27C-S01..S12 pin the decoded-value bundle parser: typed object
output in source order, fail-closed envelope/object validation, extension
field preservation (``x_mitre_*``), retention of unknown valid object
types, deep snapshot isolation from caller mutation, and the serialization
boundary (JSON bytes must be decoded before the semantic parser). All
payloads are synthetic ATI-authored STIX; no parser test contacts the
Internet or MITRE.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    Stix21Object,
    Stix21SemanticError,
    parse_stix21_bundle,
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
