# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C thin evaluator adapter over the existing EvidenceAnalystEvaluator.

The adapter maps the deterministic, synchronous
:class:`~agentic_threat_investigator.evaluation.analyst.evaluator.EvidenceAnalystEvaluator`
decision onto the common PR 30 contract:

.. code-block:: text

    existing evaluator passes  -> COMPLETED / PASS
    existing evaluator fails   -> COMPLETED / FAIL
    adapter exception          -> ERROR (through the common runner)

ATI owns correctness: the existing evaluator remains the semantic authority
and no numeric score, recall/coverage threshold, or weight ever determines
a verdict. ``AnalystEvaluationMetrics`` counts are exposed as JSON-safe,
purely descriptive diagnostics; the ratio/recall properties are never
uploaded and never decide a verdict.
"""

from __future__ import annotations

from collections.abc import Mapping

from agentic_threat_investigator.evaluation.analyst.evaluator import (
    EvidenceAnalystEvaluator,
)
from agentic_threat_investigator.evaluation.analyst.models import (
    AnalystEvaluationResult,
)
from agentic_threat_investigator.evaluation.analyst.target import (
    AnalystScenarioLookup,
    EvidenceAnalystEvaluationOutput,
)
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

EVIDENCE_ANALYST_ASSESSMENT_CONTRACT_EVALUATOR_ID = (
    "evidence-analyst-assessment-contract"
)
"""Stable evaluator id for the Evidence Analyst assessment-contract adapter."""

_PASS_EXPLANATION = (  # nosec B105 - canonical PR 30 PASS explanation text, never a credential
    "the persisted Assessment satisfies the scenario's expected-assessment contract"
)
"""Deterministic nonblank PASS explanation of the PR 30C adapter."""

_MAX_FAILURE_MESSAGE_LENGTH = 2000
"""Bounded length of one concatenated FAIL explanation."""


def _contract_diagnostics(result: AnalystEvaluationResult) -> Mapping[str, JsonValue]:
    """Project deterministic descriptive counts onto JSON-safe diagnostics.

    Only the boolean envelope acceptances and the denominator-safe counts
    that the same comparisons produced are exposed; the derived
    recall/coverage ratio properties are never used and never decide a
    verdict.
    """
    metrics = result.metrics
    return {
        "verdict_acceptable": metrics.verdict_acceptable,
        "confidence_acceptable": metrics.confidence_acceptable,
        "required_findings_total": metrics.required_findings_total,
        "required_findings_satisfied": metrics.required_findings_satisfied,
        "required_support_total": metrics.required_support_total,
        "required_support_satisfied": metrics.required_support_satisfied,
        "forbidden_support_violations": metrics.forbidden_support_violations,
        "required_contradictions_total": metrics.required_contradictions_total,
        "required_contradictions_satisfied": metrics.required_contradictions_satisfied,
        "required_limitations_total": metrics.required_limitations_total,
        "required_limitations_satisfied": metrics.required_limitations_satisfied,
        "required_unresolved_questions_total": (
            metrics.required_unresolved_questions_total
        ),
        "required_unresolved_questions_satisfied": (
            metrics.required_unresolved_questions_satisfied
        ),
        "required_next_steps_total": metrics.required_next_steps_total,
        "required_next_steps_satisfied": metrics.required_next_steps_satisfied,
    }


def _failure_explanation(result: AnalystEvaluationResult) -> str:
    """Render the deterministic nonblank FAIL explanation from failures.

    Failure codes and messages are bounded adapter text derived from the
    existing evaluator's stable failure model; provider responses, prompts,
    and chain-of-thought never appear.
    """
    messages = [
        f"{failure.code.value}: {failure.message}" for failure in result.failures
    ]
    if not messages:  # pragma: no cover - passed==(not failures) makes this unreachable
        return "the persisted Assessment violates the scenario's expected-assessment contract"
    joined = "; ".join(messages)
    if len(joined) > _MAX_FAILURE_MESSAGE_LENGTH:
        return joined[:_MAX_FAILURE_MESSAGE_LENGTH].rstrip() + "[truncated]"
    return joined


class EvidenceAnalystContractEvaluator(Evaluator[EvidenceAnalystEvaluationOutput]):
    """PR 30 adapter deciding PASS/FAIL from the existing evaluator result.

    Stateless: every input arrives through :meth:`evaluate`, the exact typed
    scenario comes from the run-scoped lookup, and the existing
    :class:`EvidenceAnalystEvaluator` remains the semantic authority. No
    LangSmith, provider SDK, or LLM client is ever touched here.
    """

    def __init__(
        self,
        *,
        scenario_lookup: AnalystScenarioLookup,
        evaluator: EvidenceAnalystEvaluator | None = None,
    ) -> None:
        """Bind the lookup and the existing deterministic evaluator."""
        self._scenario_lookup = scenario_lookup
        self._evaluator = evaluator or EvidenceAnalystEvaluator()

    @property
    def evaluator_id(self) -> str:
        """Return the stable PR 30 evaluator identifier."""
        return EVIDENCE_ANALYST_ASSESSMENT_CONTRACT_EVALUATOR_ID

    async def evaluate(
        self,
        *,
        case: EvaluationCase,
        output: EvidenceAnalystEvaluationOutput,
        context: EvaluationContext,
    ) -> EvaluationResult:
        """Decide PASS/FAIL for one persisted Assessment (ERROR on exceptions).

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
            assessment=output.assessment,
        )
        if result.passed:
            return EvaluationResult(
                evaluator_id=self.evaluator_id,
                execution_status=EvaluationExecutionStatus.COMPLETED,
                verdict=EvaluationVerdict.PASS,
                explanation=_PASS_EXPLANATION,
                diagnostics={},
            )
        return EvaluationResult(
            evaluator_id=self.evaluator_id,
            execution_status=EvaluationExecutionStatus.COMPLETED,
            verdict=EvaluationVerdict.FAIL,
            explanation=_failure_explanation(result),
            diagnostics=_contract_diagnostics(result),
        )
