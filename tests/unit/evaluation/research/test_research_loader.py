# SPDX-License-Identifier: AGPL-3.0-only
"""Research scenario loader unit tests (PR 22D, matrix 22D-U13..U15)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentic_threat_investigator.evaluation.research import (
    ExpectedResearchResult,
    ResearchScenarioLoadError,
    load_retrieval_scenarios_directory,
    load_synthesis_scenarios_directory,
)

_RETRIEVAL_CORPUS = Path(__file__).parents[4] / "evals/scenarios/research/retrieval"
_SYNTHESIS_CORPUS = Path(__file__).parents[4] / "evals/scenarios/research/synthesis"


def _retrieval_payload(**overrides: Any) -> dict[str, Any]:
    """Build one minimal valid retrieval scenario payload."""
    payload: dict[str, Any] = {
        "id": "unit.scenario",
        "version": 1,
        "query": "obfuscate command and control traffic",
        "max_results": 3,
        "expected_relevant_source_records": ["record-a"],
        "expected_source_ids": ["urn:ati:source:mitre_attack"],
    }
    payload.update(overrides)
    return payload


def test_repository_retrieval_corpus_loads_strictly() -> None:
    """Every repository retrieval scenario loads with unique identities."""
    scenarios = load_retrieval_scenarios_directory(_RETRIEVAL_CORPUS)
    assert len(scenarios) == 5
    ids = [scenario.id for scenario in scenarios]
    assert len(ids) == len(set(ids))


def test_repository_synthesis_corpus_loads_strictly() -> None:
    """Every repository synthesis scenario loads with unique identities."""
    scenarios = load_synthesis_scenarios_directory(_SYNTHESIS_CORPUS)
    assert len(scenarios) == 6
    by_id = {scenario.id: scenario for scenario in scenarios}
    for required in (
        "rag-s01-relevant-context",
        "rag-s02-no-retrieval-result",
        "rag-s03-irrelevant-context",
        "rag-s04-contradictory-context",
        "rag-s05-unsupported-citation",
        "rag-s06-hostile-corpus-content",
    ):
        assert required in by_id


def test_u13_malformed_json_fails_closed(tmp_path: Path) -> None:
    """U13: malformed scenario JSON is a typed load failure."""
    (tmp_path / "broken.json").write_text("{not json")
    with pytest.raises(ResearchScenarioLoadError):
        load_retrieval_scenarios_directory(tmp_path)


def test_unknown_field_fails_closed(tmp_path: Path) -> None:
    """Unknown fields are rejected by the extra=forbid models."""
    payload = _retrieval_payload(extra_unknown="leak")
    (tmp_path / "scenario.json").write_text(json.dumps(payload))
    with pytest.raises(ResearchScenarioLoadError):
        load_retrieval_scenarios_directory(tmp_path)


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    """A repeated JSON object key at any depth fails loading."""
    raw = (
        '{"id": "dup-key", "id": "dup-key", "version": 1,'
        ' "query": "q", "max_results": 3}'
    )
    (tmp_path / "scenario.json").write_text(raw)
    with pytest.raises(ResearchScenarioLoadError):
        load_retrieval_scenarios_directory(tmp_path)


def test_u14_duplicate_scenario_identity_fails(tmp_path: Path) -> None:
    """U14: duplicate (id, version) identities across files fail loading."""
    payload = _retrieval_payload(id="dup-scenario")
    (tmp_path / "a.json").write_text(json.dumps(payload))
    (tmp_path / "b.json").write_text(json.dumps(payload))
    with pytest.raises(ResearchScenarioLoadError):
        load_retrieval_scenarios_directory(tmp_path)


def test_duplicate_identity_at_different_version_coexists(tmp_path: Path) -> None:
    """Two versions of one stable id may coexist under corpus identity rules."""
    first = _retrieval_payload(id="versioned-scenario", version=1)
    second = _retrieval_payload(id="versioned-scenario", version=2)
    (tmp_path / "a.json").write_text(json.dumps(first))
    (tmp_path / "b.json").write_text(json.dumps(second))
    loaded = load_retrieval_scenarios_directory(tmp_path)
    assert [scenario.version for scenario in loaded] == [1, 2]


def test_u15_duplicate_expectation_label_fails(tmp_path: Path) -> None:
    """U15: duplicate expectation labels fail before tuple conversion."""
    payload = _retrieval_payload(
        expected_relevant_source_records=["record-a", "record-a"]
    )
    (tmp_path / "scenario.json").write_text(json.dumps(payload))
    with pytest.raises(ResearchScenarioLoadError):
        load_retrieval_scenarios_directory(tmp_path)


def test_gap_with_expected_material_fails_closed(tmp_path: Path) -> None:
    """A declared gap that also declares expected material is an authoring error."""
    payload = _retrieval_payload(expected_retrieval_gap=True)
    (tmp_path / "scenario.json").write_text(json.dumps(payload))
    with pytest.raises(ResearchScenarioLoadError):
        load_retrieval_scenarios_directory(tmp_path)


def test_invalid_scenario_id_fails_closed(tmp_path: Path) -> None:
    """Non-conforming scenario identifiers fail loading."""
    payload = _retrieval_payload(id="Not A Valid ID!")
    (tmp_path / "scenario.json").write_text(json.dumps(payload))
    with pytest.raises(ResearchScenarioLoadError):
        load_retrieval_scenarios_directory(tmp_path)


def test_missing_directory_fails_closed(tmp_path: Path) -> None:
    """A missing scenario directory fails loading."""
    with pytest.raises(ResearchScenarioLoadError):
        load_synthesis_scenarios_directory(tmp_path / "absent")


def test_empty_directory_fails_closed(tmp_path: Path) -> None:
    """A scenario directory without JSON files fails loading."""
    with pytest.raises(ResearchScenarioLoadError):
        load_retrieval_scenarios_directory(tmp_path)


def _synthesis_payload(**overrides: Any) -> dict[str, Any]:
    """Build one minimal valid synthesis scenario payload."""
    payload: dict[str, Any] = {
        "id": "unit.synthesis",
        "version": 1,
        "fixture": {"name": "mitre-attack-small"},
        "query": "obfuscate command and control traffic",
        "max_results": 2,
        "expected": ExpectedResearchResult().model_dump(mode="json"),
    }
    payload.update(overrides)
    return payload


def test_blank_query_and_duplicate_synthesis_filters_fail(tmp_path: Path) -> None:
    """Blank queries and duplicate synthesis filters fail loading."""
    from agentic_threat_investigator.evaluation.research import (
        ResearchFixtureReference,
    )

    (tmp_path / "blank.json").write_text(json.dumps(_synthesis_payload(query=" ")))
    with pytest.raises(ResearchScenarioLoadError):
        load_synthesis_scenarios_directory(tmp_path)
    (tmp_path / "blank.json").write_text(
        json.dumps(
            _synthesis_payload(source_ids=["urn:ati:source:a", "urn:ati:source:a"])
        )
    )
    with pytest.raises(ResearchScenarioLoadError):
        load_synthesis_scenarios_directory(tmp_path)
    (tmp_path / "blank.json").write_text(json.dumps(_synthesis_payload()))
    loaded = load_synthesis_scenarios_directory(tmp_path)
    assert loaded[0].fixture == ResearchFixtureReference(name="mitre-attack-small")
