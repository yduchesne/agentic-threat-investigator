# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C Evidence Analyst evaluation orchestration service (outside the CLI).

One function composes the canonical Evidence Analyst benchmark:

.. code-block:: text

    repository scenarios
     -> common EvaluationCase projection
     -> run-scoped scenario lookup
     -> EvidenceAnalystTargetExecutor + EvidenceAnalystContractEvaluator
     -> common EvaluationRunner
     -> canonical EvaluationRunResult

The service is LangSmith-free by construction: the caller (CLI/operator)
decides whether to associate the returned run with a LangSmith experiment.
Aggregation, ERROR conversion, and cancellation propagation are the common
runner's unchanged responsibilities and are never reimplemented here.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from uuid import UUID

from agentic_threat_investigator.app.evidence_analyst.analyst import EvidenceAnalyst
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.evaluation.analyst.materializer import (
    DEFAULT_SCENARIO_NAMESPACE,
    AnalystScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.analyst.models import AnalystScenario
from agentic_threat_investigator.evaluation.analyst.pr30 import (
    EvidenceAnalystContractEvaluator,
)
from agentic_threat_investigator.evaluation.analyst.target import (
    AnalystScenarioLookup,
    EvidenceAnalystTargetExecutor,
)
from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationDatasetId,
    EvaluationRunner,
    EvaluationRunResult,
    EvaluationTarget,
    evaluation_case_from,
)
from agentic_threat_investigator.evaluation.datasets import (
    SCENARIOS_ROOT,
    load_evaluation_scenarios,
)


async def run_evidence_analyst_evaluation(
    *,
    dataset_id: EvaluationDatasetId,
    analyst: EvidenceAnalyst,
    uow_factory: Callable[[], UnitOfWork],
    scenarios: Sequence[AnalystScenario] | None = None,
    corpus_root: Path = SCENARIOS_ROOT,
    namespace: UUID = DEFAULT_SCENARIO_NAMESPACE,
    materializer: AnalystScenarioMaterializer | None = None,
) -> EvaluationRunResult:
    """Run the Evidence Analyst benchmark and return the canonical result.

    ``scenarios`` defaults to the repository corpus loaded for
    ``dataset_id``; supplying typed scenarios keeps the service usable from
    tests without file I/O. Only ``evidence-analyst`` datasets are accepted
    in PR 30C; any other target is rejected before model work.

    The materializer namespace is bound once so the target executor and the
    deterministic scenario Investigation identities always agree. Tests may
    inject their own materializer double without changing run semantics.
    """
    if dataset_id.target is not EvaluationTarget.EVIDENCE_ANALYST:
        raise DatasetLoadError(
            f"PR 30C supports only evidence-analyst datasets, got {dataset_id.canonical}"
        )
    if scenarios is None:
        loaded = load_evaluation_scenarios(dataset_id, corpus_root=corpus_root)
        scenarios = tuple(item for item in loaded if isinstance(item, AnalystScenario))
    if not scenarios:
        raise DatasetLoadError(
            f"no typed evidence-analyst scenarios loaded for {dataset_id.canonical}"
        )

    lookup = AnalystScenarioLookup(scenarios)
    bound_materializer = materializer or AnalystScenarioMaterializer(
        namespace=namespace
    )
    target = EvidenceAnalystTargetExecutor(
        scenario_lookup=lookup,
        analyst=analyst,
        uow_factory=uow_factory,
        materializer=bound_materializer,
    )
    evaluator = EvidenceAnalystContractEvaluator(scenario_lookup=lookup)
    runner = EvaluationRunner()
    cases = tuple(evaluation_case_from(scenario) for scenario in scenarios)
    return await runner.run(
        dataset_id=dataset_id,
        cases=cases,
        target=target,
        # PR 30A freezes the runner seam as Evaluator[object]; the concrete
        # typed evaluator is accepted at runtime through the contravariant
        # protocol boundary and mypy's object-typed view of the seam cannot
        # express the narrower parameter type.
        evaluators=(evaluator,),  # type: ignore[arg-type]
    )
