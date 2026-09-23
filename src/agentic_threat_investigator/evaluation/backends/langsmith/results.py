# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Categorical ATI result -> LangSmith feedback publication projection (PR 30B).

Pure functions map an immutable :class:`EvaluationRunResult` onto the
bounded :class:`LangSmithEvaluationPublication` without touching the common
models and without publishing diagnostics by default. The frozen categorical
mapping is:

.. code-block:: text

    COMPLETED + PASS   -> "pass"
    COMPLETED + FAIL   -> "fail"
    ERROR              -> "error"

There is no numeric correctness score, percentage, weight, threshold,
partial pass, confidence, or pairwise ranking anywhere in this boundary,
and an execution ERROR is never uploaded as a behavioral FAIL.
"""

from __future__ import annotations

from typing import Literal

from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithEvaluationPublication,
    LangSmithExperimentMetadata,
    LangSmithPublicationFeedback,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationRunResult,
    EvaluationVerdict,
    JsonValue,
    sanitize_explanation,
)

CategoricalVerdict = Literal["pass", "fail", "error"]
"""The three-value categorical LangSmith feedback vocabulary."""

_MAX_PUBLISHED_EXPLANATION = 500
"""Upper bound for one published evaluator explanation."""

_TRUNCATED_MARKER = "[truncated]"
"""Deterministic truncation marker for bounded published explanations."""

_RUN_STATUS_KEY = "ati.run.status"
"""Stable feedback key for the run-level categorical aggregate."""

_CASE_KEY_PREFIX = "ati.case."
"""Stable feedback-key prefix for case-level categorical aggregates."""

_EVALUATOR_KEY_PREFIX = "ati.evaluator."
"""Stable feedback-key prefix for evaluator-level categorical results."""


def categorical_status(
    status: EvaluationExecutionStatus,
    verdict: EvaluationVerdict | None,
) -> CategoricalVerdict:
    """Map one frozen ATI status/verdict combination onto the categorical vocabulary.

    ERROR (or any missing verdict) maps to ``error`` -- never to ``fail``.
    A COMPLETED status always carries a verdict, so only PASS/FAIL remain.
    """
    if status is EvaluationExecutionStatus.ERROR or verdict is None:
        return "error"
    if verdict is EvaluationVerdict.PASS:
        return "pass"
    return "fail"


def _bounded_comment(text: str, *, max_length: int = _MAX_PUBLISHED_EXPLANATION) -> str:
    """Collapse whitespace/control characters and bound one explanation.

    PASS/FAIL explanations are author-declared narrative; publishing still
    collapses whitespace and truncates deterministically so no unbounded
    text ever reaches LangSmith.
    """
    collapsed = "".join(character for character in text if character >= " ")
    collapsed = " ".join(collapsed.split())
    if len(collapsed) <= max_length:
        return collapsed
    return collapsed[:max_length].rstrip() + _TRUNCATED_MARKER


def _result_comment(result: EvaluationResult) -> str:
    """Return the bounded publication comment for one evaluator result.

    ERROR explanations are re-sanitized (control characters stripped, URL
    credentials redacted, bounded); PASS/FAIL explanations are author text
    that is only bounded.
    """
    if result.execution_status is EvaluationExecutionStatus.ERROR:
        return sanitize_explanation(
            result.explanation, max_length=_MAX_PUBLISHED_EXPLANATION
        )
    return _bounded_comment(result.explanation)


def build_publication(run: EvaluationRunResult) -> LangSmithEvaluationPublication:
    """Project one immutable run result onto categorical LangSmith feedback.

    Feedback items are deterministic and ordered: the run aggregate first,
    then each case in declared order (case aggregate, then each evaluator
    result in declared order). Diagnostics are never published by default.
    """
    run_status = categorical_status(run.execution_status, run.verdict)
    items: list[LangSmithPublicationFeedback] = [
        LangSmithPublicationFeedback(
            key=_RUN_STATUS_KEY,
            value=run_status,
            comment="",
        )
    ]
    for case in run.cases:
        items.append(
            LangSmithPublicationFeedback(
                key=f"{_CASE_KEY_PREFIX}{case.case_id}",
                value=categorical_status(case.execution_status, case.verdict),
                comment="",
            )
        )
        for result in case.evaluator_results:
            items.append(
                LangSmithPublicationFeedback(
                    key=f"{_EVALUATOR_KEY_PREFIX}{result.evaluator_id}",
                    value=categorical_status(result.execution_status, result.verdict),
                    comment=_result_comment(result),
                )
            )
    return LangSmithEvaluationPublication(
        dataset_id=run.dataset_id.canonical,
        run_status=run_status,
        feedback=tuple(items),
    )


def build_experiment_metadata(
    *,
    commit_sha: str | None = None,
    dataset_id: str | None = None,
    projection_schema_version: int | None = None,
    agent_implementation_version: str | None = None,
    prompt_version: str | None = None,
    model_provider: str | None = None,
    model_name: str | None = None,
    model_parameters: dict[str, JsonValue] | None = None,
    fixture_set_version: str | None = None,
    normalization_version: str | None = None,
    retriever_version: str | None = None,
    embedding_version: str | None = None,
    evaluator_version: str | None = None,
    judge_model: str | None = None,
    judge_prompt_version: str | None = None,
    timestamp: str | None = None,
) -> dict[str, JsonValue]:
    """Build optional, adapter-only experiment metadata for PR 30C+ runs.

    Unset values are omitted entirely; every value is bounded and JSON-safe.
    No secrets, raw prompts, model outputs, or chain-of-thought are accepted
    or emitted, and the caller controls the bounded model parameters.
    """
    model = LangSmithExperimentMetadata(
        commit_sha=commit_sha,
        dataset_id=dataset_id,
        projection_schema_version=projection_schema_version,
        agent_implementation_version=agent_implementation_version,
        prompt_version=prompt_version,
        model_provider=model_provider,
        model_name=model_name,
        model_parameters=model_parameters,
        fixture_set_version=fixture_set_version,
        normalization_version=normalization_version,
        retriever_version=retriever_version,
        embedding_version=embedding_version,
        evaluator_version=evaluator_version,
        judge_model=judge_model,
        judge_prompt_version=judge_prompt_version,
        timestamp=timestamp,
    )
    dumped = model.model_dump(mode="python")
    return {f"ati.{key}": value for key, value in dumped.items() if value is not None}
