# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Scenario loader tests: strict validation, malformed fail-closed, deterministic order."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentic_threat_investigator.evaluation.analyst.loader import (
    AnalystScenarioLoadError,
    load_scenario_file,
    load_scenarios_directory,
)
from tests.support.evaluation_fixtures import unit_scenario

CORPUS_DIRECTORY = Path("evals/scenarios/analyst")
EXPECTED_CORPUS_IDS = (
    "cloud_asn_context",
    "conflicting_reputation",
    "geolocation_context",
    "graph_backed_malware_association",
    "malicious_ioc_direct_evidence",
    "no_reputation_hit",
    "shared_asn",
    "stale_evidence",
)


def _dump_scenario(*, extra: dict[str, Any] | None = None) -> str:
    """Serialize the unit scenario, optionally injecting extra top-level fields."""
    raw = json.loads(unit_scenario().model_dump_json())
    if extra:
        raw.update(extra)
    return json.dumps(raw)


def test_committed_corpus_is_versioned_complete_and_valid(tmp_path: Path) -> None:
    """The committed corpus loads: 8 core deterministic scenarios in order."""
    scenarios = load_scenarios_directory(CORPUS_DIRECTORY)
    assert [scenario.id for scenario in scenarios] == list(EXPECTED_CORPUS_IDS)
    assert all(scenario.version == 1 for scenario in scenarios)
    assert all(scenario.description.strip() for scenario in scenarios)
    # Deterministic discovery: filenames sort exactly to the ids above.
    assert [path.name for path in sorted(CORPUS_DIRECTORY.glob("*.json"))] == [
        f"{scenario_id}.json" for scenario_id in EXPECTED_CORPUS_IDS
    ]


def test_committed_corpus_covers_required_regressions() -> None:
    """The corpus covers every mandatory contextual/contradiction regression."""
    scenarios = load_scenarios_directory(CORPUS_DIRECTORY)
    by_id = {scenario.id: scenario for scenario in scenarios}
    assert "geolocation_context" in by_id
    assert "no_reputation_hit" in by_id
    assert "cloud_asn_context" in by_id
    assert "shared_asn" in by_id
    assert "conflicting_reputation" in by_id
    assert "stale_evidence" in by_id

    # Direct Evidence support and RelationshipObservation support both exist.
    assert any(
        finding.required_evidence_support
        for scenario in scenarios
        for finding in scenario.expected.required_findings
    )
    assert any(
        finding.required_relationship_support
        for scenario in scenarios
        for finding in scenario.expected.required_findings
    )


def test_valid_scenario_file_loads(tmp_path: Path) -> None:
    """A valid scenario file loads and round-trips through JSON."""
    path = tmp_path / "valid.json"
    path.write_text(_dump_scenario(), encoding="utf-8")
    loaded = load_scenario_file(path)
    assert loaded == unit_scenario()


def test_unknown_field_rejected_fail_closed(tmp_path: Path) -> None:
    """An unknown scenario field fails closed with the load error."""
    path = tmp_path / "unknown.json"
    path.write_text(_dump_scenario(extra={"mystery": 1}), encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_blank_id_rejected(tmp_path: Path) -> None:
    """A missing/blank scenario id fails closed."""
    path = tmp_path / "blank.json"
    path.write_text(_dump_scenario(extra={"id": ""}), encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_non_positive_version_rejected(tmp_path: Path) -> None:
    """A zero or negative scenario version fails closed."""
    path = tmp_path / "version.json"
    path.write_text(_dump_scenario(extra={"version": 0}), encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_unsupported_enum_value_rejected(tmp_path: Path) -> None:
    """An unsupported verdict enum value fails closed."""
    raw = json.loads(unit_scenario().model_dump_json())
    raw["expected"]["allowed_verdicts"] = ["definitely_evil"]
    path = tmp_path / "enum.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_malformed_json_fails_closed(tmp_path: Path) -> None:
    """Invalid JSON fails closed with the load error."""
    path = tmp_path / "broken.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_missing_file_fails_closed(tmp_path: Path) -> None:
    """A missing scenario file fails closed."""
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(tmp_path / "missing.json")


def test_duplicate_scenario_id_rejected(tmp_path: Path) -> None:
    """Two files declaring the same id at the same version are rejected."""
    (tmp_path / "a.json").write_text(_dump_scenario(), encoding="utf-8")
    (tmp_path / "b.json").write_text(_dump_scenario(), encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError, match="unit_scenario@1"):
        load_scenarios_directory(tmp_path)


def test_same_id_different_versions_allowed(tmp_path: Path) -> None:
    """Two files with the same stable id at different versions coexist."""
    (tmp_path / "a.json").write_text(
        _dump_scenario(extra={"version": 1}), encoding="utf-8"
    )
    (tmp_path / "b.json").write_text(
        _dump_scenario(extra={"version": 2}), encoding="utf-8"
    )
    scenarios = load_scenarios_directory(tmp_path)
    assert [(s.id, s.version) for s in scenarios] == [
        ("unit_scenario", 1),
        ("unit_scenario", 2),
    ]


def test_duplicate_identity_error_ordering_deterministic(tmp_path: Path) -> None:
    """Multiple duplicated identity pairs sort deterministically in the error."""
    raw_one = json.loads(unit_scenario().model_dump_json())
    raw_two = json.loads(unit_scenario().model_dump_json())
    raw_two["id"] = "other_scenario"
    (tmp_path / "a.json").write_text(json.dumps(raw_one), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(raw_two), encoding="utf-8")
    (tmp_path / "c.json").write_text(json.dumps(raw_one), encoding="utf-8")
    (tmp_path / "d.json").write_text(json.dumps(raw_two), encoding="utf-8")
    with pytest.raises(
        AnalystScenarioLoadError, match="other_scenario@1, unit_scenario@1"
    ):
        load_scenarios_directory(tmp_path)


def test_duplicate_top_level_json_key_rejected(tmp_path: Path) -> None:
    """A duplicated top-level JSON object key fails closed."""
    path = tmp_path / "dup-key.json"
    path.write_text('{"id": "a", "id": "b"}', encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_duplicate_nested_json_key_rejected(tmp_path: Path) -> None:
    """A duplicated key inside a nested object fails closed."""
    path = tmp_path / "dup-nested.json"
    path.write_text(
        '{"expected": {"allowed_verdicts": ["malicious"], '
        '"allowed_verdicts": ["benign"]}}',
        encoding="utf-8",
    )
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_invalid_utf8_fails_closed(tmp_path: Path) -> None:
    """Invalid UTF-8 bytes fail through the loader error seam."""
    path = tmp_path / "bad-utf8.json"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_invalid_utf8_never_leaks_unicode_error(tmp_path: Path) -> None:
    """UnicodeDecodeError is never surfaced to the caller."""
    path = tmp_path / "bad-utf8-2.json"
    path.write_bytes(b'{"id": "\xff"}')
    try:
        load_scenario_file(path)
    except AnalystScenarioLoadError:
        pass
    else:
        raise AssertionError("expected AnalystScenarioLoadError")


def test_unhashable_collection_member_fails_through_loader(
    tmp_path: Path,
) -> None:
    """A malformed nested collection member fails with the typed loader seam."""
    raw = json.loads(unit_scenario().model_dump_json())
    raw["expected"]["allowed_verdicts"] = ["malicious", ["malicious"]]
    path = tmp_path / "unhashable.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError) as exc_info:
        load_scenario_file(path)
    assert exc_info.value.path == path


def test_loader_error_type_is_not_the_raw_validation_exception(
    tmp_path: Path,
) -> None:
    """Callers see AnalystScenarioLoadError, never the chained raw exception."""
    raw = json.loads(unit_scenario().model_dump_json())
    raw["tags"] = ["tag-a", ["tag-b"]]
    path = tmp_path / "malformed-tags.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_corpus_discovery_order_deterministic(tmp_path: Path) -> None:
    """Discovery order is sorted by file name, independent of creation order."""
    (tmp_path / "zebra.json").write_text(
        _dump_scenario(extra={"id": "unit_scenario_b"}), encoding="utf-8"
    )
    (tmp_path / "alpha.json").write_text(_dump_scenario(), encoding="utf-8")
    ids = [scenario.id for scenario in load_scenarios_directory(tmp_path)]
    assert ids == ["unit_scenario", "unit_scenario_b"]


def test_corpus_loads_deterministically_twice(tmp_path: Path) -> None:
    """Loading the same directory twice yields identical scenario tuples."""
    (tmp_path / "only.json").write_text(_dump_scenario(), encoding="utf-8")
    first = load_scenarios_directory(tmp_path)
    second = load_scenarios_directory(tmp_path)
    assert first == second
