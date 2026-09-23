# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Research evaluator dispatcher (thin PR 30 adapter).

Maps the existing deterministic Research evaluators onto the common PR 30
contract without redesigning the common runner:

.. code-block:: text

    ResearchRetrievalScenario  -> ResearchRetrievalEvaluator  -> COMPLETED/PASS|FAIL
    ResearchSynthesisScenario  -> ResearchSynthesisEvaluator  -> COMPLETED/PASS|FAIL
    adapter exception          -> ERROR (through the common runner)

Per-kind stable evaluator ids are carried on each result
(``research-retrieval-contract`` / ``research-synthesis-contract``); the
exposed evaluator identity is the dispatcher's stable id. Existing metrics
(recall@k, precision@k, MRR, citation-validity rate, required-citation/
claim coverage) remain JSON-safe descriptive diagnostics and never decide a
verdict through any numeric threshold.
"""

from __future__ import annotations

from agentic_threat_investigator.evaluation.common import (
    EvaluationCase,
    EvaluationContext,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationVerdict,
)
from agentic_threat_investigator.evaluation.common.evaluator import Evaluator
from agentic_threat_investigator.evaluation.common.models import JsonValue
from agentic_threat_investigator.evaluation.research.models import (
    ResearchRetrievalEvaluationResult,
    ResearchRetrievalScenario,
    ResearchSynthesisEvaluationResult,
    ResearchSynthesisScenario,
)
from agentic_threat_investigator.evaluation.research.retrieval import (
    ResearchRetrievalEvaluator,
)
from agentic_threat_investigator.evaluation.research.synthesis import (
    ResearchSynthesisEvaluator,
)
from agentic_threat_investigator.evaluation.research.target import (
    ResearchEvaluationOutput,
    ResearchScenarioLookup,
)

RESEARCH_RETRIEVAL_CONTRACT_EVALUATOR_ID = "research-retrieval-contract"
"""Stable evaluator id for the retrieval contract adapter."""

RESEARCH_SYNTHESIS_CONTRACT_EVALUATOR_ID = "research-synthesis-contract"
"""Stable evaluator id for the synthesis contract adapter."""

RESEARCH_AGENT_DISPATCHER_EVALUATOR_ID = "research-agent-contract"
"""Stable dispatcher identity; per-kind ids appear on each result."""

_PASS_EXPLANATION = (  # nosec B105 - canonical PR 30 PASS explanation text, never a credential
    "the persisted/retrieved outcome satisfies the research scenario contract"
)
"""Deterministic nonblank PASS explanation of the PR 30D dispatch adapter."""

_MAX_FAILURE_MESSAGE_LENGTH = 1200
"""Bounded length of one concatenated FAIL explanation."""


def _failure_text(codes: tuple[object, ...]) -> str:
    """Render one deterministic code-tuple FAIL explanation."""
    joined = ", ".join(
        str(code.value) if hasattr(code, "value") else str(code) for code in codes
    )
    return joined if joined else "the research outcome violates the scenario contract"


def _bounded(text: str) -> str:
    """Bound a deterministic explanation."""
    if len(text) > _MAX_FAILURE_MESSAGE_LENGTH:
        return text[:_MAX_FAILURE_MESSAGE_LENGTH].rstrip() + "[truncated]"
    return text


def _retrieval_diagnostics(
    result: ResearchRetrievalEvaluationResult,
) -> dict[str, JsonValue]:
    """Project retrieval metrics onto JSON-safe descriptive diagnostics."""
    metrics = result.metrics
    return {
        "recall_at_k": metrics.recall_at_k,
        "precision_at_k": metrics.precision_at_k,
        "mrr": metrics.mrr,
        "expected_source_rank": metrics.expected_source_rank,
    }


def _synthesis_diagnostics(
    result: ResearchSynthesisEvaluationResult,
) -> dict[str, JsonValue]:
    """Project synthesis metrics onto JSON-safe descriptive diagnostics."""
    metrics = result.metrics
    return {
        "citation_validity_rate": metrics.citation_validity_rate,
        "required_citation_coverage": metrics.required_citation_coverage,
        "required_claim_coverage": metrics.required_claim_coverage,
        "epistemic_promotion_count": metrics.epistemic_promotion_count,
    }


def _to_common_result(
    *,
    evaluator_id: str,
    passed: bool,
    failures: tuple[object, ...],
    diagnostics: dict[str, JsonValue],
) -> EvaluationResult:
    """Map one existing evaluator decision onto the common PR 30 result."""
    if passed:
        return EvaluationResult(
            evaluator_id=evaluator_id,
            execution_status=EvaluationExecutionStatus.COMPLETED,
            verdict=EvaluationVerdict.PASS,
            explanation=_PASS_EXPLANATION,
            diagnostics=diagnostics,
        )
    return EvaluationResult(
        evaluator_id=evaluator_id,
        execution_status=EvaluationExecutionStatus.COMPLETED,
        verdict=EvaluationVerdict.FAIL,
        explanation=_bounded(_failure_text(failures)),
        diagnostics=diagnostics,
    )


class ResearchAgentEvaluatorDispatcher(Evaluator[ResearchEvaluationOutput]):
    """Dispatch one research case to its family's existing evaluator.

    Stateless: every input arrives through :meth:`evaluate`; the exact typed
    scenario comes from the run-scoped lookup; the existing retrieval and
    synthesis evaluators remain the semantic authorities. No LangSmith,
    provider SDK, or LLM client is ever touched here.
    """

    def __init__(
        self,
        *,
        scenario_lookup: ResearchScenarioLookup,
        retrieval_evaluator: ResearchRetrievalEvaluator | None = None,
        synthesis_evaluator: ResearchSynthesisEvaluator | None = None,
    ) -> None:
        """Bind the lookup and the existing deterministic evaluators."""
        self._scenario_lookup = scenario_lookup
        self._retrieval_evaluator = retrieval_evaluator or ResearchRetrievalEvaluator()
        self._synthesis_evaluator = synthesis_evaluator or ResearchSynthesisEvaluator()

    @property
    def evaluator_id(self) -> str:
        """Return the stable dispatcher identity."""
        return RESEARCH_AGENT_DISPATCHER_EVALUATOR_ID

    async def evaluate(
        self,
        *,
        case: EvaluationCase,
        output: ResearchEvaluationOutput,
        context: EvaluationContext,
    ) -> EvaluationResult:
        """Decide PASS/FAIL for one research outcome (ERROR on exceptions)."""
        del context
        scenario = self._scenario_lookup.require(case.case_id, case.version)
        if isinstance(scenario, ResearchRetrievalScenario):
            if output.retrieval is None:
                raise ValueError("retrieval scenario produced no retrieval output")
            result = self._retrieval_evaluator.evaluate(
                scenario=scenario, chunks=output.retrieval.chunks
            )
            return _to_common_result(
                evaluator_id=RESEARCH_RETRIEVAL_CONTRACT_EVALUATOR_ID,
                passed=result.passed,
                failures=result.failures,
                diagnostics=_retrieval_diagnostics(result),
            )
        if isinstance(scenario, ResearchSynthesisScenario):
            if output.synthesis is None:
                raise ValueError("synthesis scenario produced no synthesis output")
            synthesis = output.synthesis
            synthesis_result = self._synthesis_evaluator.evaluate(
                scenario=scenario,
                resolution=synthesis.resolution,
                result=synthesis.result,
                supplied_citation_ids=synthesis.supplied_citation_ids,
                before_snapshot=synthesis.before_snapshot,
                after_snapshot=synthesis.after_snapshot,
                expected_investigation_id=synthesis.investigation_id,
                expected_subject_entity_id=synthesis.subject_entity_id,
            )
            return _to_common_result(
                evaluator_id=RESEARCH_SYNTHESIS_CONTRACT_EVALUATOR_ID,
                passed=synthesis_result.passed,
                failures=synthesis_result.failures,
                diagnostics=_synthesis_diagnostics(synthesis_result),
            )
        raise ValueError(
            f"unsupported research scenario kind: {type(scenario).__name__}"
        )
