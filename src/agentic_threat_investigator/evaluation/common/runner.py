# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A common deterministic evaluation runner.

Orchestration:

.. code-block:: text

    EvaluationRunner
     -> refuse to start on malformed datasets
     -> execute the target per case
     -> execute every case evaluator per case
     -> aggregate evaluator results
     -> aggregate case results
     -> return EvaluationRunResult

Failure taxonomy (frozen in docs/EVALUATION.md):

1. malformed scenario/dataset      -> refuse to start;
2. target execution exception      -> case ERROR (no evaluator ran);
3. evaluator exception             -> evaluator ERROR, case ERROR;
4. completed evaluator says FAIL   -> case FAIL;
5. every evaluator PASS            -> case/dataset PASS.

Ordinary exceptions are converted to ERROR results with sanitized
explanations. ``BaseException`` is never caught, so cancellation
(``CancelledError``) propagates. Cases are executed in the provided order
and independent cases continue after an ERROR so one run reports all
observed failures/errors.
"""

from __future__ import annotations

from collections.abc import Sequence

from agentic_threat_investigator.evaluation.common.evaluator import (
    EvaluationContext,
    Evaluator,
    TargetExecutor,
)
from agentic_threat_investigator.evaluation.common.loader import (
    DatasetLoadError,
    validate_dataset_cases,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCase,
    EvaluationCaseResult,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationRunResult,
    case_aggregate,
    dataset_aggregate,
)

TARGET_EXECUTION_EVALUATOR_ID = "target-execution"
"""Stable evaluator id for the synthetic target-execution ERROR result.

A case whose target execution raised an exception carries exactly one
synthetic ERROR result under this stable evaluator id; the case aggregates
as ERROR and the failure reason is preserved (sanitized) in the report.
"""


class EvaluationRunner:
    """Deterministic backend-neutral evaluation runner.

    The runner is state-free: every input arrives through :meth:`run`, so
    identical inputs produce identical results. It never performs network,
    database, LLM, or LangSmith access.
    """

    async def run(
        self,
        *,
        dataset_id: EvaluationDatasetId,
        cases: Sequence[EvaluationCase],
        target: TargetExecutor[object],
        evaluators: Sequence[Evaluator[object]],
    ) -> EvaluationRunResult:
        """Execute all cases and return the aggregated run result.

        Raises :class:`DatasetLoadError` before starting when the dataset
        is malformed (empty case/evaluator lists, duplicate case IDs, or
        target/version mismatches).
        """
        if not cases:
            raise DatasetLoadError("a run requires at least one case")
        if not evaluators:
            raise DatasetLoadError("a run requires at least one evaluator")
        validate_dataset_cases(cases, dataset_id=dataset_id)

        case_results: list[EvaluationCaseResult] = []
        for case in cases:
            context = EvaluationContext(
                dataset_id=dataset_id.canonical, case_id=case.case_id
            )
            case_results.append(
                await self._execute_case(
                    case=case,
                    context=context,
                    target=target,
                    evaluators=evaluators,
                )
            )
        status, verdict = dataset_aggregate(case_results)
        return EvaluationRunResult(
            dataset_id=dataset_id,
            execution_status=status,
            verdict=verdict,
            cases=tuple(case_results),
        )

    async def _execute_case(
        self,
        *,
        case: EvaluationCase,
        context: EvaluationContext,
        target: TargetExecutor[object],
        evaluators: Sequence[Evaluator[object]],
    ) -> EvaluationCaseResult:
        """Execute one case without raising for ordinary failures."""
        try:
            output = await target.execute(case=case, context=context)
        except Exception as exc:  # noqa: BLE001 - runner boundary converts failures to ERROR
            return EvaluationCaseResult(
                case_id=case.case_id,
                execution_status=EvaluationExecutionStatus.ERROR,
                evaluator_results=(
                    EvaluationResult.error(
                        evaluator_id=TARGET_EXECUTION_EVALUATOR_ID,
                        message=f"{type(exc).__name__}: {exc}",
                    ),
                ),
            )
        evaluator_results: list[EvaluationResult] = []
        for evaluator in evaluators:
            try:
                result = await evaluator.evaluate(
                    case=case, output=output, context=context
                )
            except Exception as exc:  # noqa: BLE001 - runner boundary converts failures to ERROR
                result = EvaluationResult.error(
                    evaluator_id=evaluator.evaluator_id,
                    message=f"{type(exc).__name__}: {exc}",
                )
            evaluator_results.append(result)
        status, verdict = case_aggregate(evaluator_results)
        return EvaluationCaseResult(
            case_id=case.case_id,
            execution_status=status,
            verdict=verdict,
            evaluator_results=tuple(evaluator_results),
        )
