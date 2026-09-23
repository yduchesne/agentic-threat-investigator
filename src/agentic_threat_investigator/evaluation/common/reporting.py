# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A deterministic local evaluation reporting.

Human-readable reporting focuses a reviewer on failures and errors; ERROR
blocks are visually and textually distinct from FAIL blocks. Machine-readable
reporting dumps the typed run result to deterministic, JSON-safe data with
recursively sorted keys. Neither reporter emits an aggregate numeric
correctness score, pass rate, raw prompts, raw model responses, secrets, or
chain-of-thought; the human report never prints diagnostics at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCaseResult,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationRunResult,
    EvaluationVerdict,
    JsonValue,
)


def _json_sorted(value: JsonValue) -> JsonValue:
    """Recursively sort mapping keys for deterministic machine output."""
    if isinstance(value, dict):
        return {key: _json_sorted(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_json_sorted(item) for item in value]
    return value


def _case_summary_text(case: EvaluationCaseResult) -> str:
    """Render the detail block for one failed or errored case."""
    lines: list[str] = []
    for evaluator_result in case.evaluator_results:
        if (
            evaluator_result.execution_status is EvaluationExecutionStatus.ERROR
            or evaluator_result.verdict is EvaluationVerdict.FAIL
        ):
            lines.append(
                f"  {evaluator_result.evaluator_id}: {_verdict_text(evaluator_result)}"
            )
            lines.append(f"  {evaluator_result.explanation}")
    return "\n".join(lines)


def _verdict_text(result: EvaluationResult) -> str:
    """Render one evaluator result verdict text."""
    if result.execution_status is EvaluationExecutionStatus.ERROR:
        return "ERROR"
    assert result.verdict is not None
    return result.verdict.value.upper()


def render_human_report(run: EvaluationRunResult) -> str:
    """Render the deterministic human-readable run summary.

    PASS and FAIL details are shown for every failed or errored evaluator;
    passing evaluators are summarized only in the counts, and diagnostics
    are never printed.
    """
    cases = run.cases
    passed = sum(
        1
        for case in cases
        if case.execution_status is EvaluationExecutionStatus.COMPLETED
        and case.verdict is EvaluationVerdict.PASS
    )
    failed = sum(
        1
        for case in cases
        if case.execution_status is EvaluationExecutionStatus.COMPLETED
        and case.verdict is EvaluationVerdict.FAIL
    )
    errored = sum(
        1 for case in cases if case.execution_status is EvaluationExecutionStatus.ERROR
    )
    lines = [
        "ATI Evaluation",
        f"Dataset: {run.dataset_id.canonical}",
        "",
        f"Cases: {len(cases)}",
        f"PASS: {passed}",
        f"FAIL: {failed}",
        f"ERROR: {errored}",
        "",
    ]
    for case in cases:
        if case.execution_status is EvaluationExecutionStatus.COMPLETED and (
            case.verdict is not EvaluationVerdict.FAIL
        ):
            continue
        lines.append(
            f"FAIL {case.case_id}"
            if case.execution_status is EvaluationExecutionStatus.COMPLETED
            else f"ERROR {case.case_id}"
        )
        summary = _case_summary_text(case)
        if summary:
            lines.append(summary)
        lines.append("")
    if run.execution_status is EvaluationExecutionStatus.ERROR:
        lines.append("RESULT: ERROR")
    else:
        assert run.verdict is not None
        lines.append(f"RESULT: {run.verdict.value.upper()}")
    return "\n".join(lines).rstrip() + "\n"


def _render_evaluator(result: EvaluationResult) -> dict[str, JsonValue]:
    """Render one evaluator result as deterministic JSON-safe data."""
    return {
        "evaluator_id": result.evaluator_id,
        "execution_status": result.execution_status.value,
        "verdict": result.verdict.value if result.verdict is not None else None,
        "explanation": result.explanation,
        "diagnostics": _json_sorted(dict(result.diagnostics)),
    }


def render_machine_report(run: EvaluationRunResult) -> Mapping[str, JsonValue]:
    """Render one run as deterministic JSON-safe machine-readable data.

    The output contains no LangSmith identifiers and no aggregate numeric
    correctness score; PR 30B's adapter maps this structure to LangSmith.
    """
    return cast(
        Mapping[str, JsonValue],
        _json_sorted(
            {
                "dataset_id": run.dataset_id.canonical,
                "execution_status": run.execution_status.value,
                "verdict": run.verdict.value if run.verdict is not None else None,
                "cases": [
                    {
                        "case_id": case.case_id,
                        "execution_status": case.execution_status.value,
                        "verdict": (
                            case.verdict.value if case.verdict is not None else None
                        ),
                        "evaluators": [
                            _render_evaluator(result)
                            for result in case.evaluator_results
                        ],
                    }
                    for case in run.cases
                ],
            }
        ),
    )
