# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30F end-to-end Investigation evaluation orchestration service (outside the CLI).

One function composes the canonical end-to-end Investigation benchmark:

.. code-block:: text

    repository scenarios
     -> common EvaluationCase projection
     -> run-scoped scenario lookup
     -> InvestigationTargetExecutor + InvestigationContractEvaluator
     -> common EvaluationRunner
     -> canonical EvaluationRunResult

The service is LangSmith-free by construction: the caller (CLI/operator)
decides whether to associate the returned run with a LangSmith experiment.
Aggregation, ERROR conversion, and cancellation propagation are the common
runner's unchanged responsibilities and are never reimplemented here.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.llm import LlmClient
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.report import InvestigationReport
from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationDatasetId,
    EvaluationRunner,
    EvaluationRunResult,
    EvaluationTarget,
    evaluation_case_from,
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
)
from agentic_threat_investigator.evaluation.datasets import (
    SCENARIOS_ROOT,
    load_evaluation_scenarios,
)
from agentic_threat_investigator.evaluation.investigation.composition import (
    InvestigationWorld,
)
from agentic_threat_investigator.evaluation.investigation.evaluator import (
    InvestigationEvaluator,
)
from agentic_threat_investigator.evaluation.investigation.materialization import (
    InvestigationScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    InvestigationEvaluationOutput,
    InvestigationEvaluationResult,
    InvestigationScenario,
)
from agentic_threat_investigator.evaluation.investigation.target import (
    InvestigationScenarioLookup,
    InvestigationTargetExecutor,
)


async def run_investigation_evaluation(
    *,
    dataset_id: EvaluationDatasetId,
    llm: LlmClient,
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenarios: Sequence[InvestigationScenario] | None = None,
    corpus_root: Path = SCENARIOS_ROOT,
    batch_size: int = 100,
    max_structured_output_attempts: int = 2,
    clock: Callable[[], datetime] | None = None,
    recursion_limit: int = 120,
    materializer: InvestigationScenarioMaterializer | None = None,
    world_factory: (
        Callable[[Mapping[SourceId, EvidenceProvider]], Awaitable[InvestigationWorld]]
        | None
    ) = None,
    run_investigation: (
        Callable[[InvestigationWorld, UUID], Awaitable[InvestigationState]] | None
    ) = None,
    write_report: (
        Callable[[InvestigationWorld, UUID], Awaitable[InvestigationReport]] | None
    ) = None,
) -> EvaluationRunResult:
    """Run the end-to-end Investigation benchmark and return the canonical result.

    ``scenarios`` defaults to the repository corpus loaded for ``dataset_id``;
    supplying typed scenarios keeps the service usable from tests without
    file I/O. Only ``investigation`` datasets are accepted; any other target
    is rejected before model work. The production runner, Coordinator graph,
    providers/extractors, Evidence Analyst, Research Agent, and Report Writer
    execute with ``llm`` at the model boundary over the real persisted
    fixtures.

    ``world_factory``/``run_investigation``/``write_report`` are optional
    injection seams (tests bind deterministic doubles without changing run
    semantics); the defaults compose the production investigation world.
    """
    if dataset_id.target is not EvaluationTarget.INVESTIGATION:
        raise DatasetLoadError(
            f"PR 30F supports only investigation datasets, got {dataset_id.canonical}"
        )
    if scenarios is None:
        loaded = load_evaluation_scenarios(dataset_id, corpus_root=corpus_root)
        scenarios = tuple(
            item for item in loaded if isinstance(item, InvestigationScenario)
        )
    if not scenarios:
        raise DatasetLoadError(
            f"no typed investigation scenarios loaded for {dataset_id.canonical}"
        )

    lookup = InvestigationScenarioLookup(scenarios)
    target = InvestigationTargetExecutor(
        scenario_lookup=lookup,
        uow_factory=uow_factory,
        llm_client=llm,
        materializer=materializer,
        world_factory=world_factory,
        run_investigation=run_investigation,
        write_report=write_report,
        session_factory=session_factory,
        batch_size=batch_size,
        max_structured_output_attempts=max_structured_output_attempts,
        clock=clock,
        recursion_limit=recursion_limit,
    )
    evaluator = InvestigationContractEvaluator(scenario_lookup=lookup)
    runner = EvaluationRunner()
    cases = tuple(evaluation_case_from(scenario) for scenario in scenarios)
    return await runner.run(
        dataset_id=dataset_id,
        cases=cases,
        target=target,
        # PR 30A freezes the runner seam as Evaluator[object]; the concrete
        # typed evaluator is accepted at runtime through the contravariant
        # protocol boundary (see analyst/run.py).
        evaluators=(evaluator,),  # type: ignore[arg-type]
    )


INVESTIGATION_CONTRACT_EVALUATOR_ID = "investigation-contract"
"""Stable evaluator id for the PR 30F end-to-end contract adapter."""

_PASS_EXPLANATION = (  # nosec B105 - canonical PR 30 PASS explanation text, never a credential
    "the durable end-to-end state and trajectory satisfy the scenario's "
    "expected-investigation contract"
)
"""Deterministic nonblank PASS explanation of the PR 30F adapter."""

_MAX_FAILURE_MESSAGE_LENGTH = 2000
"""Bounded length of one concatenated FAIL explanation."""

_MAX_DIAGNOSTIC_CODES = 100
"""Bounded number of failure codes rendered into one FAIL explanation."""


def _metrics_diagnostics(
    result: InvestigationEvaluationResult,
) -> dict[str, int]:
    """Project deterministic execution metrics onto JSON-safe diagnostics.

    Metrics are descriptive envelope operands only; no aggregate score is
    ever derived from them.
    """
    metrics = result.metrics
    return {
        "provider_calls": metrics.provider_calls,
        "llm_calls": metrics.llm_calls,
        "analysis_calls": metrics.analysis_calls,
        "research_calls": metrics.research_calls,
        "report_calls": metrics.report_calls,
        "replans": metrics.replans,
        "pivot_count": metrics.pivot_count,
        "duplicate_provider_calls": metrics.duplicate_provider_calls,
        "duplicate_entity_investigations": metrics.duplicate_entity_investigations,
        "total_actions": metrics.total_actions,
        "maximum_depth_observed": metrics.maximum_depth_observed,
    }


def _failure_explanation(result: InvestigationEvaluationResult) -> str:
    """Render the deterministic nonblank FAIL explanation from failure codes.

    Only bounded stable :class:`InvestigationFailureCode` values are rendered;
    report prose, prompts, provider responses, and chain-of-thought never
    appear.
    """
    codes = [failure.value for failure in result.failures]
    if not codes:  # pragma: no cover - passed==(not failures) makes this unreachable
        return "the durable end-to-end state violates the scenario's expected contract"
    joined = ", ".join(codes[:_MAX_DIAGNOSTIC_CODES])
    if len(codes) > _MAX_DIAGNOSTIC_CODES:
        joined += f", +{len(codes) - _MAX_DIAGNOSTIC_CODES} more"
    if len(joined) > _MAX_FAILURE_MESSAGE_LENGTH:
        return joined[:_MAX_FAILURE_MESSAGE_LENGTH].rstrip() + "[truncated]"
    return joined


class InvestigationContractEvaluator(Evaluator[InvestigationEvaluationOutput]):
    """PR 30F adapter deciding PASS/FAIL from the existing evaluator result.

    Stateless: every input arrives through :meth:`evaluate`; the exact typed
    scenario comes from the run-scoped lookup; the existing
    :class:`InvestigationEvaluator` remains the semantic authority. No
    LangSmith, provider SDK, or LLM client is ever touched here.
    """

    def __init__(
        self,
        *,
        scenario_lookup: InvestigationScenarioLookup,
        evaluator: InvestigationEvaluator | None = None,
    ) -> None:
        """Bind the lookup and the existing deterministic evaluator."""
        self._scenario_lookup = scenario_lookup
        self._evaluator = evaluator or InvestigationEvaluator()

    @property
    def evaluator_id(self) -> str:
        """Return the stable PR 30F evaluator identifier."""
        return INVESTIGATION_CONTRACT_EVALUATOR_ID

    async def evaluate(
        self,
        *,
        case: EvaluationCase,
        output: InvestigationEvaluationOutput,
        context: EvaluationContext,
    ) -> EvaluationResult:
        """Decide PASS/FAIL for one executed investigation (ERROR on exceptions).

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
            output=output,
        )
        if result.passed:
            return EvaluationResult(
                evaluator_id=self.evaluator_id,
                execution_status=EvaluationExecutionStatus.COMPLETED,
                verdict=EvaluationVerdict.PASS,
                explanation=_PASS_EXPLANATION,
                diagnostics=_metrics_diagnostics(result),
            )
        return EvaluationResult(
            evaluator_id=self.evaluator_id,
            execution_status=EvaluationExecutionStatus.COMPLETED,
            verdict=EvaluationVerdict.FAIL,
            explanation=_failure_explanation(result),
            diagnostics=_metrics_diagnostics(result),
        )
