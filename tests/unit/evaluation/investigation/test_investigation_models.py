# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for Investigation scenario model contracts (PR 30F)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.evaluation.investigation.loader import (
    InvestigationScenarioLoadError,
    load_investigation_scenario_file,
    load_investigation_scenarios_directory,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    ExpectedInvestigationOutcome,
    InvestigationScenario,
)
from tests.unit.evaluation.investigation.helpers import scenario

_CORPUS = Path(__file__).parents[4] / "evals/scenarios/investigation"


def test_corpus_loads_all_six_scenarios() -> None:
    """The canonical corpus carries the six required scenarios (L01)."""
    scenarios = load_investigation_scenarios_directory(_CORPUS)
    assert {s.id for s in scenarios} == {
        "inv-s01-malicious-multi-source",
        "inv-s02-benign",
        "inv-s03-inconclusive-sparse",
        "inv-s04-conflicting-evidence",
        "inv-s05-research-required",
        "inv-s06-cycle-duplicate-bounded",
    }


def test_corpus_file_order_deterministic() -> None:
    """Sorted-by-filename loading yields a stable corpus order (L09)."""
    first = load_investigation_scenarios_directory(_CORPUS)
    second = load_investigation_scenarios_directory(_CORPUS)
    assert [s.id for s in first] == [s.id for s in second]


def test_corpus_versions_positive() -> None:
    """Every scenario carries a positive version."""
    for item in load_investigation_scenarios_directory(_CORPUS):
        assert item.version >= 1


def test_unknown_field_rejected() -> None:
    """Unknown scenario fields fail closed (L02)."""
    with pytest.raises(ValidationError):
        InvestigationScenario.model_validate(
            scenario().model_dump(mode="python") | {"sneaky_field": True}
        )


def test_wrong_target_rejected(tmp_path: Path) -> None:
    """A non-investigation target fails dataset-level validation (L03)."""
    import json

    from agentic_threat_investigator.evaluation.common import DatasetLoadError
    from agentic_threat_investigator.evaluation.common.models import (
        EvaluationDatasetId,
        EvaluationTarget,
    )
    from agentic_threat_investigator.evaluation.datasets import (
        load_evaluation_dataset,
    )

    payload = scenario().model_dump(mode="json")
    payload["specification"]["target"] = EvaluationTarget.COORDINATOR.value
    directory = tmp_path / "scenarios" / "investigation"
    directory.mkdir(parents=True)
    (directory / "wrong.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DatasetLoadError, match="target"):
        load_evaluation_dataset(
            EvaluationDatasetId(target=EvaluationTarget.INVESTIGATION, version=1),
            corpus_root=tmp_path / "scenarios",
        )


def test_negative_version_rejected() -> None:
    """A non-positive version is rejected (L04)."""
    with pytest.raises(ValidationError):
        InvestigationScenario.model_validate(
            scenario().model_dump(mode="python") | {"version": 0}
        )


def test_duplicate_case_rejected(tmp_path: Path) -> None:
    """Duplicate scenario identities fail closed at load time (L05)."""
    payload = scenario(scenario_id="dup-case").model_dump(mode="json")
    import json

    for name in ("a.json", "b.json"):
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(InvestigationScenarioLoadError, match="duplicate"):
        load_investigation_scenarios_directory(tmp_path)


def test_invalid_semantic_label_rejected() -> None:
    """An invalid semantic label is rejected (L06)."""
    payload = scenario().model_dump(mode="python")
    payload["expected"]["evidence"]["required_entity_labels"] = ["Bad Label!"]
    with pytest.raises(ValidationError):
        InvestigationScenario.model_validate(payload)


def test_negative_envelope_rejected() -> None:
    """A negative efficiency envelope is rejected (L07)."""
    payload = scenario().model_dump(mode="python")
    payload["expected"]["efficiency"]["max_provider_calls"] = -1
    with pytest.raises(ValidationError):
        InvestigationScenario.model_validate(payload)


def test_report_verdict_must_match_assessment() -> None:
    """The report envelope cannot contradict the Assessment verdict."""
    payload = scenario().model_dump(mode="python")
    payload["expected"]["report"]["verdict"] = "benign"
    with pytest.raises(ValidationError):
        ExpectedInvestigationOutcome.model_validate(payload["expected"])


def test_disjoint_expectations_enforced() -> None:
    """A finding/relationship/action cannot be both required and forbidden."""
    payload = scenario().model_dump(mode="python")
    payload["expected"]["relationships"]["required"] = [
        "urn:ati:relationship:dns:resolves_to"
    ]
    payload["expected"]["relationships"]["forbidden"] = [
        "urn:ati:relationship:dns:resolves_to"
    ]
    with pytest.raises(ValidationError):
        InvestigationScenario.model_validate(payload)


def test_duplicate_json_key_rejected(tmp_path: Path) -> None:
    """Duplicate JSON object keys fail closed at load time."""
    payload = (
        '{"id": "dup", "version": 1, "fixture": "x", "id": "dup", '
        '"expected": {"terminal": {"status": "completed"}}}'
    )
    path = tmp_path / "dup.json"
    path.write_text(payload)
    with pytest.raises(InvestigationScenarioLoadError):
        load_investigation_scenarios_directory(tmp_path)


def test_strict_single_file_load(tmp_path: Path) -> None:
    """One valid scenario file loads through the strict file seam."""
    payload = scenario(scenario_id="inv-single").model_dump(mode="json")
    path = tmp_path / "single.json"
    path.write_text(
        __import__("json").dumps(payload),
        encoding="utf-8",
    )
    loaded = load_investigation_scenario_file(path)
    assert loaded.id == "inv-single"
