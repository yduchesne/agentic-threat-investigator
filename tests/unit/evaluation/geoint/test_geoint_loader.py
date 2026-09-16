# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Strict GEOINT scenario corpus loading (PR 26G).

The committed corpus under ``evals/scenarios/geoint/`` loads deterministically
and fail-closed: malformed files, duplicate scenario identities, and
duplicate JSON object keys are typed load errors.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_threat_investigator.evaluation.geoint.loader import (
    DuplicateJsonKeyError,
    GeointScenarioLoadError,
    load_geoint_scenario_file,
    load_geoint_scenarios_directory,
)

CORPUS = Path("evals/scenarios/geoint")


def test_committed_corpus_loads_deterministically() -> None:
    """The committed corpus has 16 scenarios and is order-stable."""
    scenarios = load_geoint_scenarios_directory(CORPUS)
    assert len(scenarios) == 16
    ids = [scenario.id for scenario in scenarios]
    assert ids == sorted(ids)
    for scenario in scenarios:
        assert scenario.version >= 1
        assert scenario.expected.resolutions


def test_missing_directory_fails_closed() -> None:
    """A nonexistent corpus directory is a typed load error."""
    with pytest.raises(GeointScenarioLoadError):
        load_geoint_scenarios_directory(Path("evals/scenarios/does-not-exist"))


def test_empty_directory_fails_closed(tmp_path: Path) -> None:
    """An empty corpus directory is a typed load error."""
    with pytest.raises(GeointScenarioLoadError):
        load_geoint_scenarios_directory(tmp_path)


def test_malformed_json_fails_closed(tmp_path: Path) -> None:
    """Malformed JSON never yields a partial scenario."""
    path = tmp_path / "bad.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(GeointScenarioLoadError):
        load_geoint_scenario_file(path)


def test_unknown_scenario_field_fails_closed(tmp_path: Path) -> None:
    """Unknown scenario fields are rejected (fail-closed authoring)."""
    path = tmp_path / "unknown.json"
    path.write_text(
        json.dumps(
            {
                "id": "unknown_field_scenario",
                "version": 1,
                "description": "Unknown field scenario.",
                "unexpected": True,
                "fixture": {
                    "objective": "Objective.",
                    "root_entity": "x",
                    "geography": [
                        {
                            "label": "us",
                            "location_type": "country",
                            "name": "United States",
                            "country_code": "US",
                        }
                    ],
                    "entities": [],
                    "evidence": [],
                    "resolutions": [],
                },
                "expected": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(GeointScenarioLoadError):
        load_geoint_scenario_file(path)


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    """Duplicate JSON object keys at any depth are rejected."""
    path = tmp_path / "dup.json"
    path.write_text(
        '{"id": "dup", "id": "dup2", "version": 1, "description": "d", '
        '"fixture": {"objective": "o", "root_entity": "e", "geography": [{"label": "us", "location_type": "country", "name": "United States", "country_code": "US"}], '
        '"entities": [], "evidence": [], "resolutions": []}, "expected": {}}',
        encoding="utf-8",
    )
    with pytest.raises(GeointScenarioLoadError) as error:
        load_geoint_scenario_file(path)
    assert isinstance(error.value.__cause__, DuplicateJsonKeyError)


def test_duplicate_scenario_identity_fails_closed(tmp_path: Path) -> None:
    """Repeated scenario id at the same version is rejected."""
    body = {
        "id": "same_scenario",
        "version": 1,
        "description": "Duplicate identity scenario.",
        "fixture": {
            "objective": "Objective.",
            "root_entity": "target_ip",
            "geography": [
                {
                    "label": "us",
                    "location_type": "country",
                    "name": "United States",
                    "country_code": "US",
                }
            ],
            "entities": [
                {"label": "target_ip", "type": "ip_address", "value": "203.0.113.1"}
            ],
            "evidence": [
                {
                    "label": "geo_evidence",
                    "subject": "target_ip",
                    "source": "urn:ati:source:test",
                    "facts": {"country_code": "US", "precision": "country"},
                }
            ],
            "resolutions": [
                {"label": "geo_obs", "entity": "target_ip", "evidence": "geo_evidence"}
            ],
        },
        "expected": {
            "resolutions": [{"label": "geo_obs", "status": "unresolvable"}],
            "agent_output": {
                "expected_validation": "accepted",
                "allowed_verdicts": ["inconclusive"],
            },
        },
    }
    (tmp_path / "a.json").write_text(json.dumps(body), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(body), encoding="utf-8")
    with pytest.raises(GeointScenarioLoadError):
        load_geoint_scenarios_directory(tmp_path)


def test_same_id_different_version_is_allowed(tmp_path: Path) -> None:
    """The same stable id at different positive versions is legal."""
    body = {
        "id": "versioned_scenario",
        "version": 1,
        "description": "Version 1.",
        "fixture": {
            "objective": "Objective.",
            "root_entity": "target_ip",
            "geography": [
                {
                    "label": "us",
                    "location_type": "country",
                    "name": "United States",
                    "country_code": "US",
                }
            ],
            "entities": [
                {"label": "target_ip", "type": "ip_address", "value": "203.0.113.1"}
            ],
            "evidence": [
                {
                    "label": "geo_evidence",
                    "subject": "target_ip",
                    "source": "urn:ati:source:test",
                    "facts": {"country_code": "US", "precision": "country"},
                }
            ],
            "resolutions": [
                {"label": "geo_obs", "entity": "target_ip", "evidence": "geo_evidence"}
            ],
        },
        "expected": {
            "resolutions": [{"label": "geo_obs", "status": "unresolvable"}],
            "agent_output": {
                "expected_validation": "accepted",
                "allowed_verdicts": ["inconclusive"],
            },
        },
    }
    body_v2 = json.loads(json.dumps(body))
    body_v2["version"] = 2
    (tmp_path / "a.json").write_text(json.dumps(body), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(body_v2), encoding="utf-8")
    scenarios = load_geoint_scenarios_directory(tmp_path)
    assert len(scenarios) == 2
