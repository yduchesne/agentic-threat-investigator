# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator scenario loader tests (PR 21)."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.investigation import StopReason
from agentic_threat_investigator.evaluation.coordinator import (
    CoordinatorScenarioLoadError,
    load_coordinator_scenarios_directory,
)

_CORPUS = Path(__file__).parents[3] / "evals/scenarios/coordinator"


def test_corpus_loads_strictly_and_deterministically() -> None:
    """The repository corpus loads in sorted file order with valid models."""
    scenarios = load_coordinator_scenarios_directory(_CORPUS)
    assert len(scenarios) >= 12
    ids = [scenario.id for scenario in scenarios]
    assert len(ids) == len(set(ids)), "scenario ids must be unique"
    for scenario in scenarios:
        assert scenario.version >= 1
        assert scenario.fixture.name.strip()
        assert scenario.expected.expected_stop_reason in StopReason


def test_every_repository_scenario_resolves_all_semantic_labels() -> None:
    """Every checked-in scenario has a registered, complete fixture contract."""
    from agentic_threat_investigator.evaluation.scenario_fixtures import (
        CoordinatorScenarioMaterializer,
        resolve_coordinator_scenario,
    )

    materializer = CoordinatorScenarioMaterializer()
    for scenario in load_coordinator_scenarios_directory(_CORPUS):
        declared = resolve_coordinator_scenario(scenario)
        resolution = materializer.resolve_runtime(scenario, declared.entities)
        assert resolution.entities


def test_loading_is_deterministic() -> None:
    """Two loads of the corpus produce the same ordered scenarios."""
    first = load_coordinator_scenarios_directory(_CORPUS)
    second = load_coordinator_scenarios_directory(_CORPUS)
    assert [s.id for s in first] == [s.id for s in second]


def test_required_corpus_scenarios_present() -> None:
    """The required corpus scenarios all exist and load."""
    scenarios = load_coordinator_scenarios_directory(_CORPUS)
    by_id = {s.id: s for s in scenarios}
    for expected_id in (
        "domain-discovers-ip",
        "duplicate-ip-discovery",
        "already-investigated-ip",
        "non-pivotable-discovery",
        "depth-limit",
        "provider-budget",
        "entity-budget",
        "sufficient-evidence-stop",
        "no-eligible-pivots",
        "one-justified-replan",
        "replan-limit",
        "cycle-suppression",
        "malware-research-marker",
    ):
        assert expected_id in by_id, f"missing required scenario {expected_id}"


def test_malformed_json_fails_closed(tmp_path: Path) -> None:
    """Malformed JSON is a typed load error."""
    (tmp_path / "broken.json").write_text("{not json")
    with pytest.raises(CoordinatorScenarioLoadError):
        load_coordinator_scenarios_directory(tmp_path)


def test_unknown_fields_fail_closed(tmp_path: Path) -> None:
    """Unknown JSON fields are rejected (strict contract)."""
    from agentic_threat_investigator.evaluation.coordinator import (
        _ScenarioValidator,
    )

    with pytest.raises(ValidationError):
        _ScenarioValidator.model_validate(
            {
                "id": "x",
                "version": 1,
                "fixture": {"name": "f"},
                "expected": {
                    "expected_stop_reason": "sufficient_evidence",
                    "surprise_field": True,
                },
            }
        )


def test_duplicate_scenario_ids_fail_closed(tmp_path: Path) -> None:
    """Duplicate scenario IDs across files are rejected."""
    base = {
        "id": "dup",
        "version": 1,
        "fixture": {"name": "f"},
        "expected": {"expected_stop_reason": "sufficient_evidence"},
    }
    (tmp_path / "a.json").write_text(json.dumps(base))
    (tmp_path / "b.json").write_text(json.dumps(base))
    with pytest.raises(CoordinatorScenarioLoadError):
        load_coordinator_scenarios_directory(tmp_path)


def test_zero_and_negative_versions_fail_closed(tmp_path: Path) -> None:
    """Versions below one are rejected at load time."""
    (tmp_path / "v.json").write_text(
        json.dumps(
            {
                "id": "v",
                "version": 0,
                "fixture": {"name": "f"},
                "expected": {"expected_stop_reason": "sufficient_evidence"},
            }
        )
    )
    with pytest.raises(CoordinatorScenarioLoadError):
        load_coordinator_scenarios_directory(tmp_path)


def test_duplicate_labels_fail_closed(tmp_path: Path) -> None:
    """Duplicate expectation labels are rejected by the strict envelope."""
    (tmp_path / "dup.json").write_text(
        json.dumps(
            {
                "id": "dup-labels",
                "version": 1,
                "fixture": {"name": "f"},
                "expected": {
                    "expected_stop_reason": "sufficient_evidence",
                    "required_pivots": ["a", "a"],
                },
            }
        )
    )
    with pytest.raises(CoordinatorScenarioLoadError):
        load_coordinator_scenarios_directory(tmp_path)


def test_fixture_resolution_resolves_semantic_labels() -> None:
    """A known fixture resolves entity and provider-work labels deterministically."""
    from agentic_threat_investigator.evaluation.scenario_fixtures import (
        resolve_coordinator_scenario,
    )

    scenarios = list(load_coordinator_scenarios_directory(_CORPUS))
    canonical = next(s for s in scenarios if s.id == "domain-discovers-ip")
    resolution = resolve_coordinator_scenario(canonical)
    assert resolution.entities["root_domain"] != resolution.entities["resolved_ip"]
    provider, entity_id, depth = resolution.provider_work["dns_root_domain"]
    assert provider == "urn:ati:source:google_public_dns"
    assert entity_id == resolution.entities["root_domain"]
    assert depth == 0
    # Deterministic: resolving twice yields identical UUIDs.
    assert resolve_coordinator_scenario(canonical) == resolution


def test_fixture_resolution_fails_closed_on_unknown_fixture() -> None:
    """An unknown fixture name is a deterministic resolution error."""
    from agentic_threat_investigator.domain.investigation import StopReason
    from agentic_threat_investigator.evaluation.coordinator import (
        CoordinatorFixtureReference,
        CoordinatorScenario,
        ExpectedCoordinatorTrajectory,
    )
    from agentic_threat_investigator.evaluation.scenario_fixtures import (
        CoordinatorFixtureError,
        resolve_coordinator_scenario,
    )

    bogus = CoordinatorScenario(
        id="bogus",
        version=1,
        fixture=CoordinatorFixtureReference(name="no-such-fixture"),
        expected=ExpectedCoordinatorTrajectory(
            expected_stop_reason=StopReason.NO_ELIGIBLE_PIVOTS
        ),
    )
    with pytest.raises(CoordinatorFixtureError):
        resolve_coordinator_scenario(bogus)


def test_fixture_resolution_fails_closed_on_unresolved_label() -> None:
    """A required label absent from the fixture universe is a resolution error."""
    from agentic_threat_investigator.domain.investigation import StopReason
    from agentic_threat_investigator.evaluation.coordinator import (
        CoordinatorFixtureReference,
        CoordinatorScenario,
        ExpectedCoordinatorTrajectory,
    )
    from agentic_threat_investigator.evaluation.scenario_fixtures import (
        CoordinatorFixtureError,
        resolve_coordinator_scenario,
    )

    missing = CoordinatorScenario(
        id="missing-label",
        version=1,
        fixture=CoordinatorFixtureReference(name="canonical-domain-ip"),
        expected=ExpectedCoordinatorTrajectory(
            required_pivots=("does_not_exist",),
            expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        ),
    )
    with pytest.raises(CoordinatorFixtureError):
        resolve_coordinator_scenario(missing)


def test_fixture_resolution_rejects_required_forbidden_overlap() -> None:
    """A label declared both required and forbidden pivot fails closed."""
    from agentic_threat_investigator.domain.investigation import StopReason
    from agentic_threat_investigator.evaluation.coordinator import (
        CoordinatorFixtureReference,
        CoordinatorScenario,
        ExpectedCoordinatorTrajectory,
    )
    from agentic_threat_investigator.evaluation.scenario_fixtures import (
        CoordinatorFixtureError,
        resolve_coordinator_scenario,
    )

    overlap = CoordinatorScenario(
        id="overlap",
        version=1,
        fixture=CoordinatorFixtureReference(name="canonical-domain-ip"),
        expected=ExpectedCoordinatorTrajectory(
            required_pivots=("resolved_ip",),
            forbidden_pivots=("resolved_ip",),
            expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        ),
    )
    with pytest.raises(CoordinatorFixtureError):
        resolve_coordinator_scenario(overlap)


def test_empty_corpus_directory_fails_closed(tmp_path: Path) -> None:
    """Loading an empty scenario directory is a deterministic load error."""
    with pytest.raises(CoordinatorScenarioLoadError):
        load_coordinator_scenarios_directory(tmp_path)
