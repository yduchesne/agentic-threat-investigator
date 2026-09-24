# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30E Report Writer evaluation orchestration service (outside the CLI).

One function composes the canonical Report Writer benchmark:

.. code-block:: text

    repository scenarios
     -> common EvaluationCase projection
     -> run-scoped scenario lookup
     -> ReportWriterTargetExecutor + ReportWriterContractEvaluator
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

from agentic_threat_investigator.app.llm import LlmClient
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
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
from agentic_threat_investigator.evaluation.report_writer.fixtures import (
    ReportWriterScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ReportWriterScenario,
)
from agentic_threat_investigator.evaluation.report_writer.pr30 import (
    ReportWriterContractEvaluator,
)
from agentic_threat_investigator.evaluation.report_writer.target import (
    ReportWriterScenarioLookup,
    ReportWriterTargetExecutor,
)


async def run_report_writer_evaluation(
    *,
    dataset_id: EvaluationDatasetId,
    llm: LlmClient,
    uow_factory: Callable[[], UnitOfWork],
    scenarios: Sequence[ReportWriterScenario] | None = None,
    corpus_root: Path = SCENARIOS_ROOT,
    batch_size: int = 100,
    max_structured_output_attempts: int = 2,
    materializer: ReportWriterScenarioMaterializer | None = None,
) -> EvaluationRunResult:
    """Run the Report Writer benchmark and return the canonical result.

    ``scenarios`` defaults to the repository corpus loaded for ``dataset_id``;
    supplying typed scenarios keeps the service usable from tests without
    file I/O. Only ``report-writer`` datasets are accepted; any other target
    is rejected before model work. The production writer runs over the real
    persisted fixtures with ``llm`` at the model boundary.

    ``materializer`` is an optional injection seam (tests bind a
    deterministic materializer double without changing run semantics); the
    default materializes through the real application seams.
    """
    if dataset_id.target is not EvaluationTarget.REPORT_WRITER:
        raise DatasetLoadError(
            f"PR 30E supports only report-writer datasets, got {dataset_id.canonical}"
        )
    if scenarios is None:
        loaded = load_evaluation_scenarios(dataset_id, corpus_root=corpus_root)
        scenarios = tuple(
            item for item in loaded if isinstance(item, ReportWriterScenario)
        )
    if not scenarios:
        raise DatasetLoadError(
            f"no typed report-writer scenarios loaded for {dataset_id.canonical}"
        )

    lookup = ReportWriterScenarioLookup(scenarios)
    target = ReportWriterTargetExecutor(
        scenario_lookup=lookup,
        uow_factory=uow_factory,
        llm_client=llm,
        materializer=materializer,
        batch_size=batch_size,
        max_structured_output_attempts=max_structured_output_attempts,
    )
    evaluator = ReportWriterContractEvaluator(scenario_lookup=lookup)
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
