# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared deterministic builders for PR 30A common evaluation unit tests."""

from __future__ import annotations

from typing import Any

from agentic_threat_investigator.evaluation.common import (
    EvaluationCase,
    EvaluationCaseResult,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationTarget,
    EvaluationVerdict,
    ExpectedBehavior,
    ScenarioSpecification,
)

COMPLETED = EvaluationExecutionStatus.COMPLETED
ERROR = EvaluationExecutionStatus.ERROR
PASS = EvaluationVerdict.PASS
FAIL = EvaluationVerdict.FAIL


def unit_specification(**overrides: Any) -> ScenarioSpecification:
    """Build one fully descriptive canonical specification."""
    payload: dict[str, Any] = {
        "title": "Unit scenario",
        "description": "A fully described canonical unit scenario.",
        "target": EvaluationTarget.EVIDENCE_ANALYST,
        "purpose": "Exercises the unit contract.",
        "operational_relevance": "Relevant to unit evaluation coverage.",
        "regression_risk": "Protects against unit contract regressions.",
        "expected_behavior": ExpectedBehavior(
            required=("The Assessment is supported by direct evidence.",),
            forbidden=("The Assessment cites only contextual evidence.",),
        ),
        "tags": ("unit", "regression"),
        "architecture_refs": ("exact-investigation-evidence-admission",),
    }
    payload.update(overrides)
    return ScenarioSpecification.model_validate(payload)


def unit_case(case_id: str = "unit-case", version: int = 1) -> EvaluationCase:
    """Build one canonical common case."""
    return EvaluationCase.from_scenario(
        case_id=case_id, version=version, specification=unit_specification()
    )


def unit_result(
    *,
    status: EvaluationExecutionStatus = COMPLETED,
    verdict: EvaluationVerdict | None = PASS,
    explanation: str = "deterministic unit explanation",
) -> EvaluationResult:
    """Build one deterministic evaluator result."""
    return EvaluationResult(
        evaluator_id="unit-evaluator",
        execution_status=status,
        verdict=verdict,
        explanation=explanation,
    )


def unit_pass() -> EvaluationResult:
    """Build one COMPLETED/PASS result."""
    return unit_result(status=COMPLETED, verdict=PASS)


def unit_fail() -> EvaluationResult:
    """Build one COMPLETED/FAIL result."""
    return unit_result(status=COMPLETED, verdict=FAIL)


def unit_error() -> EvaluationResult:
    """Build one ERROR result with a sanitized explanation."""
    return EvaluationResult.error(evaluator_id="unit-evaluator", message="boom: oops")


def unit_case_result(
    case: EvaluationCase | None = None,
    *,
    status: EvaluationExecutionStatus = COMPLETED,
    verdict: EvaluationVerdict | None = PASS,
    results: tuple[EvaluationResult, ...] = (),
) -> EvaluationCaseResult:
    """Build one aggregated case result.

    ``results`` defaults to a single PASS result so the declared
    COMPLETED/PASS status stays aggregate-consistent by default.
    """
    evaluator_results = results or (unit_pass(),)
    return EvaluationCaseResult(
        case_id=(case or unit_case()).case_id,
        execution_status=status,
        verdict=verdict,
        evaluator_results=evaluator_results,
    )


def unit_dataset(version: int = 1) -> EvaluationDatasetId:
    """Build the canonical evidence-analyst/v<version> dataset identity."""
    return EvaluationDatasetId(
        target=EvaluationTarget.EVIDENCE_ANALYST, version=version
    )
