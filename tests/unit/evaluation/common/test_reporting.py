# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A deterministic reporting tests (EVAL-P01..P06).

Human-readable reporting identifies the failing case/evaluator and its
explanation while keeping ERROR visually distinct from FAIL; machine-readable
reporting round-trips to JSON with recursively sorted keys; neither emits an
aggregate numeric correctness score, and the human report never exposes
diagnostic material.
"""

from __future__ import annotations

import json

from agentic_threat_investigator.evaluation.common import (
    EvaluationCaseResult,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationRunResult,
    render_human_report,
    render_machine_report,
)
from agentic_threat_investigator.evaluation.common.models import (
    dataset_aggregate,
)
from tests.support.evaluation_common import (
    COMPLETED,
    FAIL,
    PASS,
    unit_case,
    unit_case_result,
    unit_dataset,
    unit_fail,
)


def _run_with_cases(cases: tuple[EvaluationCaseResult, ...]) -> EvaluationRunResult:
    """Build one run using the frozen dataset aggregation."""
    status, verdict = dataset_aggregate(cases)
    return EvaluationRunResult(
        dataset_id=unit_dataset(),
        execution_status=status,
        verdict=verdict,
        cases=cases,
    )


def test_p01_pass_summary_correct() -> None:
    """A fully passing run renders the correct summary counts."""
    run = _run_with_cases(
        (
            unit_case_result(unit_case("a")),
            unit_case_result(unit_case("b")),
        )
    )
    text = render_human_report(run)
    assert "ATI Evaluation" in text
    assert "Dataset: evidence-analyst/v1" in text
    assert "Cases: 2" in text
    assert "PASS: 2" in text
    assert "FAIL: 0" in text
    assert "ERROR: 0" in text
    assert "RESULT: PASS" in text
    assert "FAIL a" not in text
    assert "ERROR b" not in text


def test_p02_fail_summary_identifies_case_evaluator_explanation() -> None:
    """A FAIL run names the case, evaluator, and explanation."""
    failing = EvaluationResult(
        evaluator_id="temporal-reasoning",
        execution_status=COMPLETED,
        verdict=FAIL,
        explanation=(
            "Assessment treated observations from different observed_at "
            "values as simultaneous contradictory state."
        ),
    )
    case = unit_case_result(
        unit_case("conflicting-dns-observations"),
        verdict=FAIL,
        results=(failing,),
    )
    run = _run_with_cases((case,))
    text = render_human_report(run)
    assert "FAIL conflicting-dns-observations" in text
    assert "temporal-reasoning: FAIL" in text
    assert "simultaneous contradictory state" in text
    assert "RESULT: FAIL" in text


def test_p03_error_distinct_from_fail() -> None:
    """ERROR blocks are rendered distinctly from FAIL blocks."""
    error_case = unit_case_result(
        unit_case("research-context-004"),
        status=EvaluationExecutionStatus.ERROR,
        verdict=None,
        results=(
            EvaluationResult.error(
                evaluator_id="groundedness-judge",
                message="Judge invocation failed: provider unavailable",
            ),
        ),
    )
    run = _run_with_cases((error_case,))
    text = render_human_report(run)
    assert "ERROR research-context-004" in text
    assert "groundedness-judge: ERROR" in text
    assert "Judge invocation failed: provider unavailable" in text
    assert "RESULT: ERROR" in text
    assert "RESULT: FAIL" not in text


def test_p04_machine_report_round_trips() -> None:
    """Machine-readable output matches the frozen schema and round-trips."""
    machine = {
        "dataset_id": "evidence-analyst/v1",
        "execution_status": "completed",
        "verdict": "fail",
        "cases": [
            {
                "case_id": "a",
                "execution_status": "completed",
                "verdict": "pass",
                "evaluators": [
                    {
                        "evaluator_id": "unit-evaluator",
                        "execution_status": "completed",
                        "verdict": "pass",
                        "explanation": "deterministic unit explanation",
                        "diagnostics": {},
                    }
                ],
            },
            {
                "case_id": "b",
                "execution_status": "completed",
                "verdict": "fail",
                "evaluators": [
                    {
                        "evaluator_id": "unit-evaluator",
                        "execution_status": "completed",
                        "verdict": "fail",
                        "explanation": "deterministic unit explanation",
                        "diagnostics": {},
                    }
                ],
            },
        ],
    }
    run = _run_with_cases(
        (
            unit_case_result(unit_case("a")),
            unit_case_result(unit_case("b"), verdict=FAIL, results=(unit_fail(),)),
        )
    )
    rendered = render_machine_report(run)
    assert rendered == machine
    assert json.loads(json.dumps(rendered)) == rendered


def test_p04_machine_report_sorts_keys_deterministically() -> None:
    """Machine output is deterministic regardless of diagnostic key order."""
    run = _run_with_cases(
        (
            unit_case_result(
                unit_case("x"),
                results=(
                    EvaluationResult(
                        evaluator_id="odd",
                        execution_status=COMPLETED,
                        verdict=PASS,
                        explanation="deterministic",
                        diagnostics={"zebra": 1, "apple": 2},
                    ),
                ),
            ),
        )
    )
    rendered = render_machine_report(run)
    cases = rendered["cases"]
    assert isinstance(cases, list)
    assert isinstance(cases[0], dict)
    evaluators = cases[0]["evaluators"]
    assert isinstance(evaluators, list)
    assert isinstance(evaluators[0], dict)
    diagnostics = evaluators[0]["diagnostics"]
    assert isinstance(diagnostics, dict)
    assert list(diagnostics.keys()) == ["apple", "zebra"]


def test_p05_no_aggregate_numeric_score_emitted() -> None:
    """Neither report emits a numeric aggregate correctness score."""
    run = _run_with_cases(
        (
            unit_case_result(unit_case("a")),
            unit_case_result(unit_case("b"), verdict=FAIL, results=(unit_fail(),)),
        )
    )
    text = render_human_report(run)
    assert "score" not in text.lower()
    assert "%" not in text
    payload = json.dumps(render_machine_report(run))
    assert "score" not in payload
    assert "pass_rate" not in payload


def test_p06_human_report_hides_diagnostic_material() -> None:
    """The human report never exposes evaluator diagnostic material."""
    secret = "hidden-diagnostic-secret-value"
    run = _run_with_cases(
        (
            unit_case_result(
                unit_case("secret-case"),
                verdict=FAIL,
                results=(
                    EvaluationResult(
                        evaluator_id="leaky",
                        execution_status=COMPLETED,
                        verdict=FAIL,
                        explanation="behavior violated",
                        diagnostics={"secret": secret},
                    ),
                ),
            ),
        )
    )
    text = render_human_report(run)
    assert secret not in text
    assert "diagnostics" not in text

    # The machine report carries the evaluator's declared diagnostics but the
    # human report never relays them directly.
    machine = render_machine_report(run)
    assert secret in json.dumps(machine)


def test_human_report_error_with_sanitized_explanation() -> None:
    """Sanitized ERROR explanations contain no raw sensitive detail."""
    run = _run_with_cases(
        (
            unit_case_result(
                unit_case("infra"),
                status=EvaluationExecutionStatus.ERROR,
                verdict=None,
                results=(
                    EvaluationResult.error(
                        evaluator_id="connector",
                        message=(
                            "RuntimeError: postgresql://user:supersecret@db/ati "
                            "broke with a very long traceback\n" + ("x" * 500)
                        ),
                    ),
                ),
            ),
        )
    )
    text = render_human_report(run)
    assert "supersecret" not in text
    assert "user:supersecret" not in text
    assert "RESULT: ERROR" in text
    assert "connector: ERROR" in text


def test_human_report_counts_match_frozen_semantics() -> None:
    """Report counts always agree with the frozen dataset aggregation."""
    run = _run_with_cases(
        (
            unit_case_result(unit_case("a")),
            unit_case_result(unit_case("b"), verdict=FAIL, results=(unit_fail(),)),
        )
    )
    text = render_human_report(run)
    assert "PASS: 1" in text
    assert "FAIL: 1" in text
    assert "ERROR: 0" in text
