# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30E Report Writer target execution adapter.

Executes repository-owned :class:`ReportWriterScenario` cases through the
**real production Report Writer path** and returns the typed payload the PR
30E evaluator consumes:

.. code-block:: text

    common EvaluationCase
     -> exact typed ReportWriterScenario lookup
     -> repository-owned fixture resolution (fail closed)
     -> run-scoped fixture materialization (execution identity)
     -> production ReportWriter.write(investigation_id)
     -> persisted InvestigationReport OR declared typed no-report outcome
     -> ReportWriterEvaluationOutput(resolution, evaluation_input)

Only allowlisted typed production failures may be converted into an
evaluation input (declared no-report scenarios); any other exception
propagates and becomes a case ERROR through the common runner. Cancellation
always propagates unchanged. The target never calls the LLM client directly
(the production :class:`ReportWriter` owns that), never evaluates before
persistence, never touches LangSmith, and never performs any aggregation.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.app.llm import LlmClient, LlmError, LlmErrorCode
from agentic_threat_investigator.app.persistence.repositories import (
    StaleReportInputError,
    UnitOfWork,
)
from agentic_threat_investigator.app.report_writer.errors import (
    ReportProvenanceError,
)
from agentic_threat_investigator.app.report_writer.writer import ReportWriter
from agentic_threat_investigator.evaluation.common.evaluator import (
    EvaluationContext,
    TargetExecutor,
)
from agentic_threat_investigator.evaluation.common.models import EvaluationCase
from agentic_threat_investigator.evaluation.report_writer.composition import (
    CountingLlmClient,
    default_writer_factory,
)
from agentic_threat_investigator.evaluation.report_writer.fixtures import (
    ReportWriterScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ReportWriterEvaluationInput,
    ReportWriterScenario,
    ReportWriterScenarioResolution,
)
from agentic_threat_investigator.evaluation.report_writer.scenarios import (
    report_writer_fixture,
)

ScenarioIdentity = tuple[str, int]
"""One exact scenario identity: ``(case_id, case_version)``."""

STABLE_REPORT_EXECUTION_ERROR_REPORT_PROVENANCE = "report_provenance_error"
"""Stable scenario code for the deterministic provenance-validation rejection."""

STABLE_REPORT_EXECUTION_ERROR_INVALID_STRUCTURED_OUTPUT = "invalid_structured_output"
"""Stable scenario code for bounded structured-output failure/repair exhaustion."""

STABLE_REPORT_EXECUTION_ERROR_STALE_INPUT = "stale_report_input"
"""Stable scenario code for the typed stale-Assessment persistence conflict."""


class ReportWriterScenarioLookupError(ValueError):
    """A common case cannot be resolved to exactly one typed scenario.

    The target fails closed on unknown cases, duplicate identities, and any
    identity that does not exactly match the loaded repository corpus. The
    repository is the executable source of scenarios; no identity is ever
    reconstructed from LangSmith or remote example metadata.
    """


class ReportWriterScenarioLookup:
    """Immutable run-scoped ``(case_id, version) -> ReportWriterScenario`` map.

    Built once per run from the fully typed repository scenarios; exact
    identity only. Duplicate identities are rejected at construction.
    """

    def __init__(self, scenarios: Sequence[ReportWriterScenario]) -> None:
        """Index every scenario by its exact ``(id, version)`` identity."""
        index: dict[ScenarioIdentity, ReportWriterScenario] = {}
        for scenario in scenarios:
            identity = (scenario.id, scenario.version)
            if identity in index:
                raise ReportWriterScenarioLookupError(
                    f"duplicate scenario identity {scenario.id}@v{scenario.version}"
                )
            index[identity] = scenario
        self._index = index

    def require(self, case_id: str, version: int) -> ReportWriterScenario:
        """Return the exact typed scenario or fail closed."""
        try:
            return self._index[(case_id, version)]
        except KeyError as exc:
            raise ReportWriterScenarioLookupError(
                f"no typed report-writer scenario resolves {case_id}@v{version}"
            ) from exc


def stable_report_execution_error(exc: BaseException) -> str | None:
    """Map one typed production failure to its stable scenario code, or None.

    The mapping is narrow and category-based: provenance validation,
    bounded structured-output failure, and the stale-Assessment conflict.
    Exception messages are never parsed; any other failure category returns
    ``None`` and is treated as an unexpected ERROR by the executor.
    """
    if isinstance(exc, ReportProvenanceError):
        return STABLE_REPORT_EXECUTION_ERROR_REPORT_PROVENANCE
    if isinstance(exc, StaleReportInputError):
        return STABLE_REPORT_EXECUTION_ERROR_STALE_INPUT
    if isinstance(exc, LlmError) and exc.code is LlmErrorCode.INVALID_STRUCTURED_OUTPUT:
        return STABLE_REPORT_EXECUTION_ERROR_INVALID_STRUCTURED_OUTPUT
    return None


class ReportWriterEvaluationOutput(BaseModel):
    """Typed payload one evaluator consumes for one executed Report Writer case.

    Carries the run-scoped label resolution and the evaluation envelope facts
    (the persisted report, or the declared typed no-report failure with the
    exact current-execution model-attempt count). No LangSmith IDs, prompts,
    provider responses, or raw model output ever appear here.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    resolution: ReportWriterScenarioResolution
    """The exact scenario label -> persisted identity resolution."""

    evaluation_input: ReportWriterEvaluationInput
    """Envelope facts: persisted report (or typed no-report) plus call count."""


class ReportWriterTargetExecutor(TargetExecutor[ReportWriterEvaluationOutput]):
    """Run one common Report Writer case through the production writer.

    Materialization runs in short UnitOfWork transactions and closes before
    the writer's own short transactions (input loading, accounting, and
    persistence), so no database transaction is ever held across LLM I/O.
    Each execution gets a fresh run-scoped identity (``execution_id``), so
    repeated runs of the same case never collide and never destructively
    reset history; canonical Entity/Relationship rows may be reused.
    """

    def __init__(
        self,
        *,
        scenario_lookup: ReportWriterScenarioLookup,
        uow_factory: Callable[[], UnitOfWork],
        llm_client: LlmClient,
        materializer: ReportWriterScenarioMaterializer | None = None,
        writer_factory: Callable[[LlmClient], ReportWriter] | None = None,
        batch_size: int = 100,
        max_structured_output_attempts: int = 2,
    ) -> None:
        """Bind the lookup, persistence, model, and writer composition seams.

        ``writer_factory`` consumes the counting-wrapped ``LlmClient`` and
        builds one fresh production :class:`ReportWriter` (defaults to the
        existing infrastructure composition); tests inject a recording double.
        ``batch_size`` and ``max_structured_output_attempts`` bound the
        production writer exactly as the application Settings do.
        """
        self._scenario_lookup = scenario_lookup
        self._uow_factory = uow_factory
        self._llm_client = llm_client
        self._materializer = materializer or ReportWriterScenarioMaterializer(
            uow_factory
        )
        self._writer_factory = writer_factory
        self._batch_size = batch_size
        self._max_structured_output_attempts = max_structured_output_attempts

    async def execute(
        self,
        *,
        case: EvaluationCase,
        context: EvaluationContext,
    ) -> ReportWriterEvaluationOutput:
        """Materialize the exact scenario and run the production writer once.

        ``context`` carries stable identity only and is validated by the
        runner before the case executes; the exact typed scenario comes from
        the run-scoped lookup, never from the context or remote metadata. A
        declared no-report scenario converts only allowlisted typed
        production failures into an evaluation input; anything else is ERROR
        through the common runner and cancellation propagates.
        """
        del context
        scenario = self._scenario_lookup.require(case.case_id, case.version)
        fixture = report_writer_fixture(scenario.fixture)
        execution_id = uuid4()
        resolution = await self._materializer.materialize(
            scenario, fixture, execution_id=execution_id
        )
        counting = CountingLlmClient(self._llm_client)
        writer = self._writer_factory(counting) if self._writer_factory else None
        if writer is None:
            writer = default_writer_factory(
                uow_factory=self._uow_factory,
                batch_size=self._batch_size,
                max_structured_output_attempts=self._max_structured_output_attempts,
            )(counting)
        try:
            report = await writer.write(resolution.investigation_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            code = stable_report_execution_error(exc)
            if code is not None and scenario.expected.expected_no_report:
                return ReportWriterEvaluationOutput(
                    resolution=resolution,
                    evaluation_input=ReportWriterEvaluationInput(
                        report=None,
                        execution_error_code=code,
                        llm_calls=counting.calls,
                    ),
                )
            raise
        return ReportWriterEvaluationOutput(
            resolution=resolution,
            evaluation_input=ReportWriterEvaluationInput(
                report=report, llm_calls=counting.calls
            ),
        )
