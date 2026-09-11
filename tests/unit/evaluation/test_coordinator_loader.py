# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator scenario loader tests (PR 21)."""

import json
from pathlib import Path
from uuid import UUID

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


def _valid_scenario_json(*, allowed_pivots: object = ()) -> dict[str, object]:
    """Build a strict-loading-valid scenario envelope with explicit pivots."""
    expected: dict[str, object] = {
        "allowed_pivots": allowed_pivots,
        "expected_stop_reason": "no_eligible_pivots",
        "max_transitions": 40,
    }
    return {
        "id": "s-oracle",
        "version": 1,
        "fixture": {"name": "f"},
        "expected": expected,
    }


# --- PR 21D scenario oracle authoring matrix (S1-S9) ------------------------


def test_s1_allowed_pivots_omitted_fails_closed(tmp_path: Path) -> None:
    """S1: omission must never silently mean 'no pivot is legal'."""
    expected: dict[str, object] = {
        "expected_stop_reason": "no_eligible_pivots",
        "max_transitions": 40,
    }
    raw: dict[str, object] = {
        "id": "s-omitted",
        "version": 1,
        "fixture": {"name": "f"},
        "expected": expected,
    }
    (tmp_path / "missing.json").write_text(json.dumps(raw))
    with pytest.raises(CoordinatorScenarioLoadError, match="allowed_pivots"):
        load_coordinator_scenarios_directory(tmp_path)


def test_s2_blank_allowed_entity_label_fails_closed(tmp_path: Path) -> None:
    """S2: a blank allowed-pivot entity label is rejected at load."""
    (tmp_path / "blank.json").write_text(
        json.dumps(_valid_scenario_json(allowed_pivots=[{"entity": "  ", "depth": 1}]))
    )
    with pytest.raises(CoordinatorScenarioLoadError):
        load_coordinator_scenarios_directory(tmp_path)


def test_s3_negative_allowed_depth_fails_closed(tmp_path: Path) -> None:
    """S3: a negative allowed-pivot depth is rejected at load."""
    (tmp_path / "negative.json").write_text(
        json.dumps(_valid_scenario_json(allowed_pivots=[{"entity": "ip", "depth": -1}]))
    )
    with pytest.raises(CoordinatorScenarioLoadError):
        load_coordinator_scenarios_directory(tmp_path)


def test_s4_duplicate_allowed_identity_fails_closed(tmp_path: Path) -> None:
    """S4: duplicate (entity label, depth) allowed identities are rejected."""
    duplicate = [
        {"entity": "resolved_ip", "depth": 1},
        {"entity": "resolved_ip", "depth": 1},
    ]
    (tmp_path / "dup.json").write_text(
        json.dumps(_valid_scenario_json(allowed_pivots=duplicate))
    )
    with pytest.raises(CoordinatorScenarioLoadError, match="duplicate"):
        load_coordinator_scenarios_directory(tmp_path)


def test_s5_unknown_allowed_entity_label_fails_resolution() -> None:
    """S5: an allowed label outside the fixture universe is a typed error."""
    from agentic_threat_investigator.domain.investigation import StopReason
    from agentic_threat_investigator.evaluation.coordinator import (
        CoordinatorFixtureReference,
        CoordinatorScenario,
        ExpectedCoordinatorTrajectory,
        ExpectedPivot,
    )
    from agentic_threat_investigator.evaluation.scenario_fixtures import (
        CoordinatorFixtureError,
        resolve_coordinator_scenario,
    )

    bogus = CoordinatorScenario(
        id="unknown-allowed",
        version=1,
        fixture=CoordinatorFixtureReference(name="canonical-domain-ip"),
        expected=ExpectedCoordinatorTrajectory(
            allowed_pivots=(ExpectedPivot(entity="does_not_exist", depth=1),),
            expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        ),
    )
    with pytest.raises(CoordinatorFixtureError, match="does_not_exist"):
        resolve_coordinator_scenario(bogus)


def test_s6_required_pivot_not_in_allowed_set_fails_closed(tmp_path: Path) -> None:
    """S6: every required pivot label must be represented in allowed_pivots."""
    expected: dict[str, object] = {
        "allowed_pivots": [{"entity": "other", "depth": 1}],
        "required_pivots": ["resolved_ip"],
        "expected_stop_reason": "no_eligible_pivots",
        "max_transitions": 40,
    }
    raw: dict[str, object] = {
        "id": "s-uncovered",
        "version": 1,
        "fixture": {"name": "f"},
        "expected": expected,
    }
    (tmp_path / "uncovered.json").write_text(json.dumps(raw))
    with pytest.raises(CoordinatorScenarioLoadError, match="required_pivots"):
        load_coordinator_scenarios_directory(tmp_path)


def test_s7_forbidden_pivot_in_allowed_set_fails_closed(tmp_path: Path) -> None:
    """S7: a forbidden pivot label may never appear in allowed_pivots."""
    expected: dict[str, object] = {
        "allowed_pivots": [{"entity": "resolved_ip", "depth": 1}],
        "forbidden_pivots": ["resolved_ip"],
        "expected_stop_reason": "no_eligible_pivots",
        "max_transitions": 40,
    }
    raw: dict[str, object] = {
        "id": "s-conflict",
        "version": 1,
        "fixture": {"name": "f"},
        "expected": expected,
    }
    (tmp_path / "conflict.json").write_text(json.dumps(raw))
    with pytest.raises(CoordinatorScenarioLoadError, match="forbidden_pivots"):
        load_coordinator_scenarios_directory(tmp_path)


def test_s8_valid_empty_allowed_set_is_accepted(tmp_path: Path) -> None:
    """S8: an explicitly empty allowed set is a valid scenario oracle."""
    (tmp_path / "empty.json").write_text(
        json.dumps(_valid_scenario_json(allowed_pivots=[]))
    )
    scenarios = load_coordinator_scenarios_directory(tmp_path)
    assert len(scenarios) == 1
    assert scenarios[0].expected.allowed_pivots == ()


def test_s9_valid_allowed_pivot_resolves_to_expected_identity() -> None:
    """S9: a valid allowed pivot label resolves deterministically via the fixture."""
    from agentic_threat_investigator.domain.investigation import StopReason
    from agentic_threat_investigator.evaluation.coordinator import (
        CoordinatorFixtureReference,
        CoordinatorScenario,
        ExpectedCoordinatorTrajectory,
        ExpectedPivot,
    )
    from agentic_threat_investigator.evaluation.scenario_fixtures import (
        resolve_coordinator_scenario,
    )

    scenario = CoordinatorScenario(
        id="valid-allowed",
        version=1,
        fixture=CoordinatorFixtureReference(name="canonical-domain-ip"),
        expected=ExpectedCoordinatorTrajectory(
            allowed_pivots=(ExpectedPivot(entity="resolved_ip", depth=1),),
            expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        ),
    )
    resolution = resolve_coordinator_scenario(scenario)
    pivot = scenario.expected.allowed_pivots[0]
    target = resolution.entities[pivot.entity]
    assert isinstance(target, UUID)
    assert target != resolution.entities["root_domain"]
    # Deterministic: resolving twice yields the same resolved identity.
    assert resolve_coordinator_scenario(scenario).entities[pivot.entity] == target
