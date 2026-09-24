# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30E thin evaluator adapter over the existing ReportWriterEvaluator.

The adapter maps the deterministic, synchronous
:class:`~agentic_threat_investigator.evaluation.report_writer.evaluator.ReportWriterEvaluator`
decision onto the common PR 30 contract:

.. code-block:: text

    existing evaluator passes  -> COMPLETED / PASS
    existing evaluator fails   -> COMPLETED / FAIL
    adapter exception          -> ERROR (through the common runner)

ATI owns correctness: the existing evaluator remains the semantic authority
and no numeric score, coverage threshold, or weight ever determines a
verdict. :class:`ReportWriterMetrics` values are exposed as JSON-safe,
purely descriptive diagnostics only; the coverage ratios are never uploaded
and never decide a verdict.
"""

from __future__ import annotations

from collections.abc import Mapping

from agentic_threat_investigator.evaluation.common.evaluator import (
    EvaluationContext,
    Evaluator,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCase,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationVerdict,
    JsonValue,
)
from agentic_threat_investigator.evaluation.report_writer.evaluator import (
    ReportWriterEvaluator,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ReportWriterEvaluationResult,
)
from agentic_threat_investigator.evaluation.report_writer.target import (
    ReportWriterEvaluationOutput,
    ReportWriterScenarioLookup,
)

REPORT_WRITER_CONTRACT_EVALUATOR_ID = "report-writer-contract"
"""Stable evaluator id for the PR 30E Report Writer contract adapter."""

_PASS_EXPLANATION = (  # nosec B105 - canonical PR 30 PASS explanation text, never a credential
    "the persisted report (or declared no-report outcome) satisfies the "
    "scenario's expected-report contract"
)
"""Deterministic nonblank PASS explanation of the PR 30E adapter."""

_MAX_FAILURE_MESSAGE_LENGTH = 2000
"""Bounded length of one concatenated FAIL explanation."""

_MAX_DIAGNOSTIC_CODES = 100
"""Bounded number of failure codes rendered into one FAIL explanation."""


def _contract_diagnostics(
    result: ReportWriterEvaluationResult,
) -> Mapping[str, JsonValue]:
    """Project deterministic descriptive counts onto JSON-safe diagnostics.

    Only the envelope measurements the same comparisons produced are exposed;
    they are diagnostics only and never decide a verdict.
    """
    metrics = result.metrics
    return {
        "narrative_statement_count": metrics.narrative_statement_count,
        "included_finding_ordinals": list(metrics.included_finding_ordinals),
        "included_research_claim_count": metrics.included_research_claim_count,
        "required_finding_coverage": metrics.required_finding_coverage,
        "required_research_coverage": metrics.required_research_coverage,
    }


def _failure_explanation(result: ReportWriterEvaluationResult) -> str:
    """Render the deterministic nonblank FAIL explanation from failure codes.

    Only bounded stable :class:`ReportWriterFailureCode` values are rendered;
    report prose, prompts, provider responses, and chain-of-thought never
    appear.
    """
    codes = [failure.value for failure in result.failures]
    if not codes:  # pragma: no cover - passed==(not failures) makes this unreachable
        return "the persisted report violates the scenario's expected-report contract"
    joined = ", ".join(codes[:_MAX_DIAGNOSTIC_CODES])
    if len(codes) > _MAX_DIAGNOSTIC_CODES:
        joined += f", +{len(codes) - _MAX_DIAGNOSTIC_CODES} more"
    if len(joined) > _MAX_FAILURE_MESSAGE_LENGTH:
        return joined[:_MAX_FAILURE_MESSAGE_LENGTH].rstrip() + "[truncated]"
    return joined


class ReportWriterContractEvaluator(Evaluator[ReportWriterEvaluationOutput]):
    """PR 30E adapter deciding PASS/FAIL from the existing evaluator result.

    Stateless: every input arrives through :meth:`evaluate`, the exact typed
    scenario comes from the run-scoped lookup, and the existing
    :class:`ReportWriterEvaluator` remains the semantic authority. No
    LangSmith, provider SDK, or LLM client is ever touched here.
    """

    def __init__(
        self,
        *,
        scenario_lookup: ReportWriterScenarioLookup,
        evaluator: ReportWriterEvaluator | None = None,
    ) -> None:
        """Bind the lookup and the existing deterministic evaluator."""
        self._scenario_lookup = scenario_lookup
        self._evaluator = evaluator or ReportWriterEvaluator()

    @property
    def evaluator_id(self) -> str:
        """Return the stable PR 30E evaluator identifier."""
        return REPORT_WRITER_CONTRACT_EVALUATOR_ID

    async def evaluate(
        self,
        *,
        case: EvaluationCase,
        output: ReportWriterEvaluationOutput,
        context: EvaluationContext,
    ) -> EvaluationResult:
        """Decide PASS/FAIL for one executed report (ERROR on exceptions).

        An exception raised here (unknown fixture label, malformed output
        payload, ...) is converted by the common runner into an ERROR result
        with a sanitized explanation; it is never reported as a behavioral
        FAIL.
        """
        del context
        scenario = self._scenario_lookup.require(case.case_id, case.version)
        result = self._evaluator.evaluate(
            scenario=scenario,
            resolution=output.resolution,
            evaluation_input=output.evaluation_input,
        )
        if result.passed:
            return EvaluationResult(
                evaluator_id=self.evaluator_id,
                execution_status=EvaluationExecutionStatus.COMPLETED,
                verdict=EvaluationVerdict.PASS,
                explanation=_PASS_EXPLANATION,
                diagnostics=_contract_diagnostics(result),
            )
        return EvaluationResult(
            evaluator_id=self.evaluator_id,
            execution_status=EvaluationExecutionStatus.COMPLETED,
            verdict=EvaluationVerdict.FAIL,
            explanation=_failure_explanation(result),
            diagnostics=_contract_diagnostics(result),
        )
