# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Exhaustive validation tests for the PR 20C evaluation DTOs."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.evaluation.analyst.loader import (
    AnalystScenarioLoadError,
    load_scenario_file,
)
from agentic_threat_investigator.evaluation.analyst.models import (
    AnalystEvaluationFailureCode,
    AnalystEvaluationMetrics,
    AnalystEvaluationResult,
    AnalystScenario,
    ExpectedAssessment,
    ExpectedFinding,
    ForbiddenFinding,
    RequiredContradiction,
)
from tests.support.evaluation_fixtures import (
    EVIDENCE_A,
    EVIDENCE_B,
    OBSERVATION,
    unit_scenario,
)


def _default_expected() -> ExpectedAssessment:
    """Build the canonical passing envelope for the unit scenario."""
    return ExpectedAssessment(
        allowed_verdicts=frozenset({Verdict.MALICIOUS}),
        allowed_confidence=frozenset(
            {AssessmentConfidence.MEDIUM, AssessmentConfidence.HIGH}
        ),
    )


def _scenario_with_findings() -> dict[str, Any]:
    """Return the unit-scenario JSON with one required and one forbidden Finding."""
    raw: dict[str, Any] = json.loads(unit_scenario().model_dump_json())
    raw["expected"]["required_findings"] = [
        {
            "category": "reputation",
            "disposition": "supporting",
            "allowed_confidence": ["medium"],
            "required_evidence_support": [EVIDENCE_A],
            "required_relationship_support": [OBSERVATION],
            "forbidden_evidence_support": [EVIDENCE_B],
            "forbidden_relationship_support": [OBSERVATION],
        }
    ]
    raw["expected"]["forbidden_findings"] = [
        {
            "disposition": "supporting",
            "evidence_support": [EVIDENCE_B],
            "relationship_support": [OBSERVATION],
        }
    ]
    # Populate every optional assessment-level collection with one valid entry
    # so duplicate-entry tests can reach and duplicate each member.
    raw["expected"]["forbidden_evidence_support"] = [EVIDENCE_B]
    raw["expected"]["forbidden_relationship_support"] = [OBSERVATION]
    raw["expected"]["required_limitations"] = ["Evidence is approximate."]
    raw["expected"]["required_unresolved_questions"] = ["Is the host active?"]
    raw["expected"]["required_next_steps"] = ["Revalidate the indicator."]
    return raw


def test_minimal_scenario_round_trip() -> None:
    """A valid scenario loads from a plain dict preserving every field."""
    scenario = unit_scenario()
    raw = scenario.model_dump()
    loaded = AnalystScenario.model_validate(raw)
    assert loaded == scenario
    assert loaded.version == 1
    assert loaded.id == "unit_scenario"


def test_unknown_field_rejected() -> None:
    """Scenario JSON with an undeclared field fails closed."""
    raw = unit_scenario().model_dump()
    raw["surprise"] = True
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


@pytest.mark.parametrize(
    "mutation",
    [
        {"id": ""},
        {"id": "Upper Case"},
        {"version": 0},
        {"version": -1},
        {"description": "   "},
    ],
)
def test_invalid_scalar_fields_rejected(mutation: dict[str, Any]) -> None:
    """Blank/malformed ids, non-positive versions, and blank descriptions fail."""
    raw = unit_scenario().model_dump()
    raw.update(mutation)
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_blank_tag_rejected() -> None:
    """Blank tags are rejected."""
    raw = unit_scenario().model_dump()
    raw["tags"] = ["  "]
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_too_many_tags_rejected() -> None:
    """More than the bounded tag count is rejected."""
    raw = unit_scenario().model_dump()
    raw["tags"] = [f"tag-{index}" for index in range(11)]
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_duplicate_tags_rejected_from_raw_list() -> None:
    """Repeated identical tags fail closed before frozenset conversion."""
    raw = json.loads(unit_scenario().model_dump_json())
    raw["tags"] = ["tag-a", "tag-a"]
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_eleven_repeated_tags_fail_raw_count_bound() -> None:
    """Eleven repeated identical tags cannot evade the ten-tag bound."""
    raw = json.loads(unit_scenario().model_dump_json())
    raw["tags"] = ["tag-a"] * 11
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


@pytest.mark.parametrize(
    "field_path",
    [
        ("expected", "required_findings", 0, "required_evidence_support"),
        ("expected", "required_findings", 0, "required_relationship_support"),
        ("expected", "required_findings", 0, "forbidden_evidence_support"),
        ("expected", "required_findings", 0, "forbidden_relationship_support"),
        ("expected", "forbidden_findings", 0, "evidence_support"),
        ("expected", "forbidden_findings", 0, "relationship_support"),
        (
            "expected",
            "forbidden_evidence_support",
        ),  # assessment-level
        (
            "expected",
            "forbidden_relationship_support",
        ),
        (
            "expected",
            "required_limitations",
        ),
        (
            "expected",
            "required_unresolved_questions",
        ),
        (
            "expected",
            "required_next_steps",
        ),
    ],
)
def test_duplicate_support_or_phrase_entries_rejected(
    field_path: tuple[str, ...],
) -> None:
    """Duplicate labels/phrases in raw JSON lists fail closed."""
    raw = _scenario_with_findings()
    node: Any = raw
    for member in field_path:
        node = node[member]
    node.append(node[0])
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


@pytest.mark.parametrize(
    "field_path",
    [
        ("expected", "allowed_verdicts"),
        ("expected", "allowed_confidence"),
        ("expected", "required_findings", 0, "allowed_confidence"),
    ],
)
def test_duplicate_envelope_entries_rejected(field_path: tuple[str, ...]) -> None:
    """Duplicate allowed-verdict/confidence entries fail closed before set conversion."""
    raw = (
        _scenario_with_findings()
        if field_path[0:2] == ("expected", "required_findings")
        else json.loads(unit_scenario().model_dump_json())
    )
    node: Any = raw
    for member in field_path:
        node = node[member]
    node.append(node[0])
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_duplicate_expected_finding_rejected_through_loader(
    tmp_path: Path,
) -> None:
    """Duplicate support in a scenario file fails through the loader seam."""
    raw = _scenario_with_findings()
    raw["expected"]["required_findings"][0]["required_evidence_support"] = [
        EVIDENCE_A,
        EVIDENCE_A,
    ]
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(AnalystScenarioLoadError):
        load_scenario_file(path)


def test_committed_fixture_labels_are_stable_forms() -> None:
    """Every committed fixture label matches the stable semantic-label contract."""
    scenario = unit_scenario()
    for entity in scenario.fixture.entities:
        assert re.fullmatch(r"[a-z0-9][a-z0-9._-]*", entity.label)
        assert len(entity.label) <= 64
    for evidence in scenario.fixture.evidence:
        assert re.fullmatch(r"[a-z0-9][a-z0-9._-]*", evidence.label)
        assert re.fullmatch(r"[a-z0-9][a-z0-9._-]*", evidence.subject)
    assert re.fullmatch(r"[a-z0-9][a-z0-9._-]*", scenario.fixture.root_entity)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw["expected"]["allowed_verdicts"].append(["malicious"]),
        lambda raw: raw["expected"]["allowed_confidence"].append(["medium"]),
        lambda raw: raw["expected"]["required_findings"][0][
            "required_evidence_support"
        ].append({"provider_a": 1}),
        lambda raw: raw["tags"].append(["tag-a"]),
    ],
)
def test_unhashable_collection_members_fail_via_pydantic(
    mutate: Any,
) -> None:
    """Malformed unhashable members never raise raw TypeError from validation."""
    raw = _scenario_with_findings()
    mutate(raw)
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_duplicate_unhashable_collection_members_fail_cleanly() -> None:
    """Two identical nested-list members fail validation without raw TypeError."""
    raw = _scenario_with_findings()
    raw["expected"]["allowed_verdicts"].extend([["malicious"], ["malicious"]])
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw["fixture"]["entities"][0].__setitem__("label", ""),
        lambda raw: raw["fixture"]["entities"][0].__setitem__(
            "label", "Contains Space"
        ),
        lambda raw: raw["fixture"]["entities"][0].__setitem__("label", "Upper-Case"),
        lambda raw: raw["fixture"]["entities"][0].__setitem__("label", "x" * 65),
        lambda raw: raw["fixture"]["evidence"][0].__setitem__("subject", "Bad Subject"),
        lambda raw: raw["fixture"]["relationships"][0].__setitem__(
            "source", "BAD-SOURCE"
        ),
        lambda raw: raw["fixture"]["observations"][0].__setitem__(
            "relationship", "bad relationship"
        ),
        lambda raw: raw["fixture"].__setitem__("root_entity", "Missing"),
    ],
)
def test_invalid_semantic_labels_rejected(mutate: Any) -> None:
    """Blank, whitespace, uppercase, and over-length fixture labels fail."""
    raw = json.loads(unit_scenario().model_dump_json())
    mutate(raw)
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_invalid_support_reference_label_rejected() -> None:
    """Malformed support-reference labels inside expectations fail."""
    with pytest.raises(ValidationError):
        ExpectedFinding(
            category=None,
            disposition=FindingDisposition.SUPPORTING,
            required_evidence_support=frozenset({"Not A Label"}),
        )
    with pytest.raises(ValidationError):
        ForbiddenFinding(
            disposition=FindingDisposition.SUPPORTING,
            evidence_support=frozenset({"Not A Label"}),
        )
    with pytest.raises(ValidationError):
        ExpectedAssessment(
            allowed_verdicts=frozenset({Verdict.MALICIOUS}),
            allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
            forbidden_evidence_support=frozenset({"Not A Label"}),
        )


def test_expected_finding_without_constraint_rejected() -> None:
    """An expectation constraining nothing is rejected."""
    with pytest.raises(ValidationError):
        _ = ExpectedFinding()


def test_expected_finding_required_and_forbidden_overlap_rejected() -> None:
    """A label cannot be both required and forbidden for one expectation."""
    with pytest.raises(ValidationError):
        ExpectedFinding(
            category=None,
            disposition=None,
            required_evidence_support=frozenset({EVIDENCE_A}),
            forbidden_evidence_support=frozenset({EVIDENCE_A}),
        )


def test_forbidden_finding_without_constraint_rejected() -> None:
    """A ForbiddenFinding pattern constraining nothing is rejected."""
    with pytest.raises(ValidationError):
        _ = ForbiddenFinding()


def test_contradiction_dispositions_validated() -> None:
    """Contradiction sides must carry the exact opposing dispositions."""
    with pytest.raises(ValidationError):
        RequiredContradiction(
            supporting_finding=ExpectedFinding(
                disposition=FindingDisposition.CONTRADICTING,
                required_evidence_support=frozenset({EVIDENCE_A}),
            ),
            contradicting_finding=ExpectedFinding(
                disposition=FindingDisposition.CONTRADICTING,
                required_evidence_support=frozenset({EVIDENCE_B}),
            ),
        )


def test_contradiction_contradicting_side_wrong() -> None:
    """The contradicting side must be CONTRADICTING as well."""
    with pytest.raises(ValidationError):
        RequiredContradiction(
            supporting_finding=ExpectedFinding(
                disposition=FindingDisposition.SUPPORTING,
                required_evidence_support=frozenset({EVIDENCE_A}),
            ),
            contradicting_finding=ExpectedFinding(
                disposition=FindingDisposition.SUPPORTING,
                required_evidence_support=frozenset({EVIDENCE_B}),
            ),
        )


def test_duplicate_contradictions_rejected() -> None:
    """Identical required contradiction pairs are rejected."""
    contradiction = RequiredContradiction(
        supporting_finding=ExpectedFinding(
            disposition=FindingDisposition.SUPPORTING,
            required_evidence_support=frozenset({EVIDENCE_A}),
        ),
        contradicting_finding=ExpectedFinding(
            disposition=FindingDisposition.CONTRADICTING,
            required_evidence_support=frozenset({EVIDENCE_B}),
        ),
    )
    with pytest.raises(ValidationError):
        ExpectedAssessment(
            allowed_verdicts=frozenset({Verdict.MALICIOUS}),
            allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
            required_contradictions=(contradiction, contradiction),
        )


def test_contradiction_round_trip() -> None:
    """A well-formed contradiction pair validates."""
    contradiction = RequiredContradiction(
        supporting_finding=ExpectedFinding(
            category=None,
            disposition=FindingDisposition.SUPPORTING,
            required_evidence_support=frozenset({EVIDENCE_A}),
        ),
        contradicting_finding=ExpectedFinding(
            category=None,
            disposition=FindingDisposition.CONTRADICTING,
            required_evidence_support=frozenset({EVIDENCE_B}),
        ),
    )
    assert contradiction.supporting_finding.disposition is FindingDisposition.SUPPORTING


def test_empty_envelopes_rejected() -> None:
    """Empty verdict or confidence envelopes are rejected."""
    with pytest.raises(ValidationError):
        ExpectedAssessment(
            allowed_verdicts=frozenset(),
            allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
        )
    with pytest.raises(ValidationError):
        ExpectedAssessment(
            allowed_verdicts=frozenset({Verdict.MALICIOUS}),
            allowed_confidence=frozenset(),
        )


def test_duplicate_expected_findings_rejected() -> None:
    """Identical required Finding expectations are duplicate labels."""
    expectation = ExpectedFinding(
        category=None,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({EVIDENCE_A}),
    )
    with pytest.raises(ValidationError):
        ExpectedAssessment(
            allowed_verdicts=frozenset({Verdict.MALICIOUS}),
            allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
            required_findings=(expectation, expectation),
        )


def test_duplicate_forbidden_findings_rejected() -> None:
    """Identical ForbiddenFinding patterns are rejected."""
    pattern = ForbiddenFinding(
        disposition=FindingDisposition.SUPPORTING,
        evidence_support=frozenset({EVIDENCE_A}),
    )
    with pytest.raises(ValidationError):
        ExpectedAssessment(
            allowed_verdicts=frozenset({Verdict.MALICIOUS}),
            allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
            forbidden_findings=(pattern, pattern),
        )


def test_blank_canonical_phrase_rejected() -> None:
    """Blank canonical limitation phrases are rejected."""
    with pytest.raises(ValidationError):
        ExpectedAssessment(
            allowed_verdicts=frozenset({Verdict.MALICIOUS}),
            allowed_confidence=frozenset({AssessmentConfidence.MEDIUM}),
            required_limitations=frozenset({"  "}),
        )


def test_unknown_evidence_label_in_expectation_rejected() -> None:
    """Expectations referencing a fixture label that does not exist fail closed."""
    expectation = ExpectedFinding(
        category=None,
        disposition=FindingDisposition.SUPPORTING,
        required_evidence_support=frozenset({"no_such_evidence"}),
    )
    envelope = _default_expected().model_copy(
        update={"required_findings": (expectation,)}
    )
    with pytest.raises(ValidationError):
        unit_scenario(expected=envelope)


def test_unknown_observation_label_rejected() -> None:
    """Expectations referencing an unknown observation label fail closed."""
    expectation = ExpectedFinding(
        category=None,
        disposition=FindingDisposition.SUPPORTING,
        required_relationship_support=frozenset({"no_such_observation"}),
    )
    envelope = _default_expected().model_copy(
        update={"required_findings": (expectation,)}
    )
    with pytest.raises(ValidationError):
        unit_scenario(expected=envelope)


def test_unknown_contextual_label_rejected() -> None:
    """Assessment-level contextual-only labels must exist in the fixture."""
    envelope = _default_expected().model_copy(
        update={"forbidden_evidence_support": frozenset({"no_such_evidence"})}
    )
    with pytest.raises(ValidationError):
        unit_scenario(expected=envelope)


def test_duplicate_fixture_labels_rejected() -> None:
    """Fixture labels must be unique across every fixture kind."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["entities"][1]["label"] = raw["fixture"]["entities"][0]["label"]
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_references_unknown_entity_rejected() -> None:
    """Fixture evidence must reference a declared subject entity."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["evidence"][0]["subject"] = "no_such_entity"
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_root_entity_must_exist() -> None:
    """The fixture root entity must be declared."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["root_entity"] = "no_such_entity"
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_blank_objective_rejected() -> None:
    """Blank fixture objectives are rejected."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["objective"] = "   "
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_entity_label_collides_with_evidence_label_rejected() -> None:
    """A label shared between an entity and an evidence row is rejected."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["entities"][1]["label"] = "provider_a"
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_relationship_unknown_source_rejected() -> None:
    """A relationship referencing an unknown source entity is rejected."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["relationships"][0]["source"] = "no_such_entity"
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_relationship_unknown_target_rejected() -> None:
    """A relationship referencing an unknown target entity is rejected."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["relationships"][0]["target"] = "no_such_entity"
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_observation_unknown_relationship_rejected() -> None:
    """An observation referencing an unknown relationship is rejected."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["observations"][0]["relationship"] = "no_such_relationship"
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_observation_references_must_exist() -> None:
    """Fixture observations must reference declared relationships and evidence."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["observations"][0]["evidence"] = "no_such_evidence"
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_evidence_timestamps_must_be_aware() -> None:
    """Naive fixture timestamps are rejected."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["evidence"][0]["observed_at"] = datetime(2026, 1, 1)
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_requires_an_entity() -> None:
    """A fixture without entities cannot exist."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["entities"] = []
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_failure_code_values_stable() -> None:
    """The bounded failure codes carry stable machine-readable values."""
    assert AnalystEvaluationFailureCode.REQUIRED_CONTRADICTION_MISSING.value == (
        "required_contradiction_missing"
    )
    assert AnalystEvaluationFailureCode.CONTEXTUAL_EVIDENCE_MISUSED.value == (
        "contextual_evidence_misused"
    )


def test_metrics_satisfied_cannot_exceed_total() -> None:
    """Satisfied counts beyond their totals are rejected."""
    with pytest.raises(ValidationError):
        AnalystEvaluationMetrics(
            verdict_acceptable=True,
            confidence_acceptable=True,
            required_findings_total=1,
            required_findings_satisfied=2,
            required_support_total=0,
            required_support_satisfied=0,
            forbidden_support_violations=0,
            required_contradictions_total=0,
            required_contradictions_satisfied=0,
            required_limitations_total=0,
            required_limitations_satisfied=0,
            required_unresolved_questions_total=0,
            required_unresolved_questions_satisfied=0,
            required_next_steps_total=0,
            required_next_steps_satisfied=0,
        )


def test_metrics_derived_ratios_denominator_safe() -> None:
    """Empty denominators produce 1.0 with no division by zero."""
    metrics = AnalystEvaluationMetrics(
        verdict_acceptable=True,
        confidence_acceptable=True,
        required_findings_total=0,
        required_findings_satisfied=0,
        required_support_total=0,
        required_support_satisfied=0,
        forbidden_support_violations=0,
        required_contradictions_total=0,
        required_contradictions_satisfied=0,
        required_limitations_total=2,
        required_limitations_satisfied=1,
        required_unresolved_questions_total=0,
        required_unresolved_questions_satisfied=0,
        required_next_steps_total=0,
        required_next_steps_satisfied=0,
    )
    assert metrics.required_finding_recall == 1.0
    assert metrics.required_support_recall == 1.0
    assert metrics.contradiction_coverage == 1.0
    assert metrics.required_limitations_total == 2
    assert metrics.required_limitations_satisfied == 1


def test_metrics_nonempty_denominator_ratios() -> None:
    """Non-empty denominators produce the documented deterministic ratios."""
    metrics = AnalystEvaluationMetrics(
        verdict_acceptable=True,
        confidence_acceptable=True,
        required_findings_total=2,
        required_findings_satisfied=1,
        required_support_total=4,
        required_support_satisfied=2,
        forbidden_support_violations=0,
        required_contradictions_total=2,
        required_contradictions_satisfied=1,
        required_limitations_total=0,
        required_limitations_satisfied=0,
        required_unresolved_questions_total=0,
        required_unresolved_questions_satisfied=0,
        required_next_steps_total=0,
        required_next_steps_satisfied=0,
    )
    assert metrics.required_finding_recall == 0.5
    assert metrics.required_support_recall == 0.5
    assert metrics.contradiction_coverage == 0.5


def test_result_rejects_passed_failure_mismatch() -> None:
    """A result whose passed flag contradicts its failures is rejected."""
    metrics = AnalystEvaluationMetrics(
        verdict_acceptable=True,
        confidence_acceptable=True,
        required_findings_total=0,
        required_findings_satisfied=0,
        required_support_total=0,
        required_support_satisfied=0,
        forbidden_support_violations=0,
        required_contradictions_total=0,
        required_contradictions_satisfied=0,
        required_limitations_total=0,
        required_limitations_satisfied=0,
        required_unresolved_questions_total=0,
        required_unresolved_questions_satisfied=0,
        required_next_steps_total=0,
        required_next_steps_satisfied=0,
    )
    with pytest.raises(ValidationError):
        AnalystEvaluationResult(
            scenario_id="unit_scenario",
            scenario_version=1,
            passed=False,
            failures=(),
            metrics=metrics,
        )


def test_scenario_rejects_non_string_id() -> None:
    """Scenario identifiers must be strings, not bare JSON numbers."""
    raw = unit_scenario().model_dump()
    raw["id"] = 42
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)


def test_fixture_rejects_naive_retrieved_timestamp() -> None:
    """Naive retrieved timestamps are rejected just like observed_at."""
    raw = unit_scenario().model_dump()
    raw["fixture"]["evidence"][1]["retrieved_at"] = "2026-01-02T00:00:00"
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)
