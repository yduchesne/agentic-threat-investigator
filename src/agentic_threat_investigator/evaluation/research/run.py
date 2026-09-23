# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Research Agent evaluation orchestration service (outside the CLI).

Composes one canonical ``research-agent/v1`` run over the common runner:

.. code-block:: text

    repository retrieval + synthesis scenarios
     -> common EvaluationCase projection
     -> run-scoped typed lookup
     -> ResearchAgentTargetExecutor (family dispatch)
     -> ResearchAgentEvaluatorDispatcher (family dispatch)
     -> common EvaluationRunner
     -> canonical EvaluationRunResult

The service is LangSmith-free by construction and never decides retrieval/
synthesis policy; the caller (CLI/operator/tests) supplies the composed
production research world and persistence seams.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationDatasetId,
    EvaluationRunner,
    EvaluationRunResult,
    EvaluationTarget,
    evaluation_case_from,
)
from agentic_threat_investigator.evaluation.research.composition import (
    ResearchWorld,
)
from agentic_threat_investigator.evaluation.research.loader import (
    load_retrieval_scenarios_directory,
    load_synthesis_scenarios_directory,
)
from agentic_threat_investigator.evaluation.research.models import (
    ResearchRetrievalScenario,
    ResearchSynthesisScenario,
)
from agentic_threat_investigator.evaluation.research.pr30 import (
    ResearchAgentEvaluatorDispatcher,
)
from agentic_threat_investigator.evaluation.research.target import (
    ResearchAgentTargetExecutor,
    ResearchScenarioLookup,
)

SCENARIOS_ROOT = Path("evals/scenarios/research")
"""Repository-relative root of the research scenario corpus."""


async def run_research_agent_evaluation(
    *,
    dataset_id: EvaluationDatasetId,
    world: ResearchWorld,
    uow_factory: Callable[[], UnitOfWork],
    scenarios: Sequence[ResearchRetrievalScenario | ResearchSynthesisScenario]
    | None = None,
    corpus_root: Path = SCENARIOS_ROOT,
) -> EvaluationRunResult:
    """Run the Research Agent benchmark and return the canonical result.

    Requires the Research Agent target; loads both scenario families (or
    accepts an explicit tuple), builds the exact typed lookup, binds the
    dispatch target and evaluator, and invokes the common runner. No
    LangSmith dependency.
    """
    if dataset_id.target is not EvaluationTarget.RESEARCH_AGENT:
        raise DatasetLoadError(
            f"PR 30D supports only research-agent datasets, got {dataset_id.canonical}"
        )
    if scenarios is None:
        retrieval = load_retrieval_scenarios_directory(corpus_root / "retrieval")
        synthesis = load_synthesis_scenarios_directory(corpus_root / "synthesis")
        scenarios = tuple(retrieval) + tuple(synthesis)
    if not scenarios:
        raise DatasetLoadError(
            f"no typed research scenarios loaded for {dataset_id.canonical}"
        )

    lookup = ResearchScenarioLookup(scenarios)
    target = ResearchAgentTargetExecutor(
        scenario_lookup=lookup,
        world=world,
        uow_factory=uow_factory,
    )
    evaluator = ResearchAgentEvaluatorDispatcher(scenario_lookup=lookup)
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
