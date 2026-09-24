# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A common model tests (EVAL-A01..A12).

These tests freeze the binary eval contract: completed verdicts are PASS or
FAIL only, ERROR is distinct from FAIL, invalid status/verdict combinations
are rejected, and evaluator/case/dataset aggregation follows exactly the
frozen rules.
"""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.evaluation.common import (
    EvaluationCaseResult,
    EvaluationDatasetId,
    EvaluationResult,
    EvaluationRunResult,
    EvaluationTarget,
    ExpectedBehavior,
    ScenarioSpecification,
)
from agentic_threat_investigator.evaluation.common.models import (
    case_aggregate,
    dataset_aggregate,
)
from tests.support.evaluation_common import (
    COMPLETED,
    ERROR,
    FAIL,
    PASS,
    unit_case_result,
    unit_dataset,
    unit_error,
    unit_fail,
    unit_pass,
    unit_result,
    unit_specification,
)

TARGET = EvaluationTarget.EVIDENCE_ANALYST


# EVAL-A01..A03 valid combinations.


def test_a01_completed_pass_valid() -> None:
    """COMPLETED + PASS is a valid evaluator result."""
    result = unit_pass()
    assert result.execution_status is COMPLETED
    assert result.verdict is PASS


def test_a02_completed_fail_valid() -> None:
    """COMPLETED + FAIL is a valid evaluator result."""
    result = unit_fail()
    assert result.execution_status is COMPLETED
    assert result.verdict is FAIL


def test_a03_error_without_verdict_valid() -> None:
    """ERROR + no verdict is a valid evaluator result."""
    result = unit_error()
    assert result.execution_status is ERROR
    assert result.verdict is None


# EVAL-A04..A08 invalid combinations and contracts.


def test_a04_error_cannot_carry_verdict() -> None:
    """ERROR must never carry PASS or FAIL."""
    with pytest.raises(ValidationError):
        unit_result(status=ERROR, verdict=PASS)
    with pytest.raises(ValidationError):
        unit_result(status=ERROR, verdict=FAIL)


def test_a05_completed_requires_verdict() -> None:
    """COMPLETED must carry exactly one verdict."""
    with pytest.raises(ValidationError):
        unit_result(status=COMPLETED, verdict=None)


def test_a06_no_numeric_score_field() -> None:
    """The canonical result exposes no numeric score field."""
    result = unit_pass()
    model_dump = result.model_dump()
    assert "score" not in model_dump
    assert "pass_rate" not in model_dump
    assert all(not isinstance(value, float) for value in model_dump.values())


def test_a07_explanation_required_nonblank() -> None:
    """PASS, FAIL, and ERROR all require a nonblank explanation."""
    for status, verdict in ((COMPLETED, PASS), (COMPLETED, FAIL), (ERROR, None)):
        with pytest.raises(ValidationError):
            unit_result(status=status, verdict=verdict, explanation="   ")


def test_a08_evaluator_id_required_stable() -> None:
    """The evaluator id must be stable and nonblank."""
    with pytest.raises(ValidationError):
        EvaluationResult(
            evaluator_id="   ",
            execution_status=COMPLETED,
            verdict=PASS,
            explanation="x",
        )
    assert unit_pass().evaluator_id == "unit-evaluator"


def test_case_and_run_ids_nonblank() -> None:
    """Case/run results reject blank case identifiers."""
    with pytest.raises(ValidationError):
        EvaluationCaseResult(
            case_id="   ", execution_status=ERROR, evaluator_results=()
        )


def test_diagnostics_json_safe_enforced() -> None:
    """NaN/infinite floats and non-string keys are rejected as diagnostics."""
    with pytest.raises(ValidationError):
        EvaluationResult(
            evaluator_id="e",
            execution_status=COMPLETED,
            verdict=PASS,
            explanation="x",
            diagnostics={"bad": math.nan},
        )
    with pytest.raises(ValidationError):
        EvaluationResult(
            evaluator_id="e",
            execution_status=COMPLETED,
            verdict=PASS,
            explanation="x",
            diagnostics={1: "numeric-key"},  # type: ignore[dict-item]
        )


def test_diagnostics_never_change_aggregation() -> None:
    """Diagnostics are measurements; they never alter the verdict."""
    noisy = EvaluationResult(
        evaluator_id="e",
        execution_status=COMPLETED,
        verdict=PASS,
        explanation="x",
        diagnostics={"measurement": 7, "detail": {"nested": ["a", "b"]}},
    )
    assert case_aggregate([noisy]) == (COMPLETED, PASS)


def test_dataset_id_canonical_round_trip() -> None:
    """Dataset identity round-trips through canonical form."""
    dataset = unit_dataset()
    assert dataset.canonical == "evidence-analyst/v1"
    parsed = EvaluationDatasetId.from_canonical(dataset.canonical)
    assert parsed == dataset


def test_dataset_id_rejects_malformed_canonical() -> None:
    """Malformed dataset identity strings fail closed."""
    for malformed in ("", "v1", "evidence-analyst", "evidence-analyst/1", "nope/v1"):
        with pytest.raises(ValueError):
            EvaluationDatasetId.from_canonical(malformed)


# EVAL-A09..A11 case aggregation rules.


def test_a09_all_pass_aggregates_case_pass() -> None:
    """All evaluator PASS results aggregate to a COMPLETED/PASS case."""
    results = (unit_pass(), unit_pass())
    assert case_aggregate(results) == (COMPLETED, PASS)
    case = unit_case_result(results=results)
    assert case.verdict is PASS


def test_a10_any_fail_no_error_aggregates_case_fail() -> None:
    """Any COMPLETED/FAIL with no ERROR aggregates to COMPLETED/FAIL."""
    results = (unit_pass(), unit_fail())
    assert case_aggregate(results) == (COMPLETED, FAIL)
    case = unit_case_result(verdict=FAIL, results=results)
    assert case.verdict is FAIL


def test_a11_any_error_aggregates_case_error() -> None:
    """One or more ERROR evaluator results aggregate to ERROR/no verdict."""
    results = (unit_pass(), unit_error(), unit_fail())
    assert case_aggregate(results) == (ERROR, None)
    case = unit_case_result(status=ERROR, verdict=None, results=results)
    assert case.execution_status is ERROR
    assert case.verdict is None


def test_case_aggregate_requires_consistent_declaration() -> None:
    """A case result whose declaration contradicts aggregation is rejected."""
    with pytest.raises(ValidationError):
        unit_case_result(verdict=FAIL, results=(unit_pass(),))
    with pytest.raises(ValidationError):
        unit_case_result(results=(unit_fail(),))


# EVAL-A12 dataset aggregation rules.


def _run(cases: tuple[EvaluationCaseResult, ...]) -> EvaluationRunResult:
    """Build one run from case results with the frozen aggregation."""
    return EvaluationRunResult(
        dataset_id=unit_dataset(),
        execution_status=dataset_aggregate(cases)[0],
        verdict=dataset_aggregate(cases)[1],
        cases=cases,
    )


def test_a12_dataset_aggregation_matches_frozen_rules() -> None:
    """Dataset aggregation follows exactly the frozen PASS/FAIL/ERROR rules."""
    pass_one = unit_case_result()
    run = _run((pass_one, pass_one))
    assert run.execution_status is COMPLETED
    assert run.verdict is PASS

    fail_case = unit_case_result(verdict=FAIL, results=(unit_fail(),))
    assert dataset_aggregate((pass_one, fail_case)) == (COMPLETED, FAIL)

    error_case = unit_case_result(status=ERROR, verdict=None, results=(unit_error(),))
    assert dataset_aggregate((pass_one, error_case)) == (ERROR, None)
    assert dataset_aggregate((fail_case, error_case)) == (ERROR, None)

    run = _run((pass_one, fail_case, error_case))
    assert run.execution_status is ERROR
    assert run.verdict is None


def test_dataset_aggregate_empty_is_error() -> None:
    """An empty case sequence aggregates to ERROR/no verdict (never run)."""
    assert dataset_aggregate(()) == (ERROR, None)


def test_run_requires_at_least_one_case() -> None:
    """An EvaluationRunResult with no cases is rejected."""
    with pytest.raises(ValidationError):
        EvaluationRunResult(
            dataset_id=unit_dataset(),
            execution_status=ERROR,
            cases=(),
        )


def test_run_aggregation_consistent_enforced() -> None:
    """A run whose declaration contradicts dataset aggregation is rejected."""
    fail_case = unit_case_result(verdict=FAIL, results=(unit_fail(),))
    with pytest.raises(ValidationError):
        EvaluationRunResult(
            dataset_id=unit_dataset(),
            execution_status=COMPLETED,
            verdict=PASS,
            cases=(fail_case,),
        )


def test_timestamps_absent_for_determinism() -> None:
    """Common result models carry no wall-clock timestamps."""
    run = _run((unit_case_result(),))
    payload = run.model_dump()
    assert "timestamp" not in payload
    assert "created_at" not in payload


def test_evaluation_case_projection_keeps_identity() -> None:
    """evaluation_case_from projects id/version/specification deterministically."""
    from agentic_threat_investigator.evaluation.common.models import (
        evaluation_case_from,
    )

    class FakeScenario:
        """Structural ScenarioLike stand-in for projection tests."""

        id: str = "fake-case"
        version: int = 1
        specification: ScenarioSpecification = unit_specification()

        def model_dump(self, *, mode: str = "python") -> dict[str, object]:
            """Satisfy the PR 30B canonical serialization seam on ScenarioLike."""
            return {
                "id": self.id,
                "version": self.version,
                "specification": self.specification.model_dump(mode=mode),
            }

    case = evaluation_case_from(FakeScenario())
    assert case.case_id == "fake-case"
    assert case.version == 1
    assert case.specification.title == "Unit scenario"


def test_expected_behavior_normalizes_whitespace() -> None:
    """Behavior statements are canonicalized and duplicates rejected."""
    behavior = ExpectedBehavior(
        required=("  The   Assessment is supported. ",),
        forbidden=("not supported",),
    )
    assert behavior.required == ("The Assessment is supported.",)
    with pytest.raises(ValidationError):
        ExpectedBehavior(required=("same", "  same "), forbidden=("x",))
    with pytest.raises(ValidationError):
        ExpectedBehavior(required=("overlap",), forbidden=("overlap",))
    with pytest.raises(ValidationError):
        ExpectedBehavior(required=("   ",), forbidden=("y",))


def test_architecture_refs_validated() -> None:
    """Architecture references are syntactically validated and unique."""
    refined = unit_specification(
        architecture_refs=("temporal-semantics", "evidence-admission")
    )
    assert refined.architecture_refs[0] == "temporal-semantics"
    with pytest.raises(ValidationError):
        unit_specification(architecture_refs=("Temporal Semantics!",))
    with pytest.raises(ValidationError):
        unit_specification(architecture_refs=("dup", "dup"))


def test_all_targets_in_vocabulary() -> None:
    """The frozen target vocabulary is complete for PR 30 benchmarks."""
    assert {target.value for target in EvaluationTarget} == {
        "evidence-analyst",
        "coordinator",
        "research-agent",
        "report-writer",
        "investigation",
        "geoint",
    }
