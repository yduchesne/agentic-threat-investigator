# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C Evidence Analyst target execution adapter.

The adapter executes repository-owned :class:`AnalystScenario` cases through
the **real production Evidence Analyst path** and returns the typed payload
the PR 30 evaluator consumes:

.. code-block:: text

    common EvaluationCase
     -> exact typed AnalystScenario lookup
     -> isolated scenario fixture (materialize_or_reuse)
     -> production EvidenceAnalyst execution
     -> persisted Assessment + AnalystScenarioResolution

The target never calls the LLM client directly (the production
:class:`EvidenceAnalyst` owns that), never evaluates before persistence
(the persisted :class:`Assessment` returned by the analyst is the payload),
never touches LangSmith, and never performs any aggregation. A raised
exception becomes a case ERROR through the common runner; cancellation
propagates unchanged.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.app.evidence_analyst.analyst import EvidenceAnalyst
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.assessment import Assessment
from agentic_threat_investigator.evaluation.analyst.materializer import (
    AnalystScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.analyst.models import (
    AnalystScenario,
    AnalystScenarioResolution,
)
from agentic_threat_investigator.evaluation.common.evaluator import (
    EvaluationContext,
    TargetExecutor,
)
from agentic_threat_investigator.evaluation.common.models import EvaluationCase

ScenarioIdentity = tuple[str, int]
"""One exact scenario identity: ``(case_id, case_version)``."""


class ScenarioLookupError(ValueError):
    """A common case cannot be resolved to exactly one typed scenario.

    The target fails closed on unknown cases, duplicate identities, and any
    identity that does not exactly match the loaded repository corpus. The
    repository is the executable source of scenarios; no identity is ever
    reconstructed from remote example metadata.
    """


class AnalystScenarioLookup:
    """Immutable run-scoped ``(case_id, version) -> AnalystScenario`` map.

    Built once per run from the fully typed repository scenarios; exact
    identity only. Duplicate identities are rejected at construction.
    """

    def __init__(self, scenarios: Sequence[AnalystScenario]) -> None:
        """Index every scenario by its exact ``(id, version)`` identity."""
        index: dict[ScenarioIdentity, AnalystScenario] = {}
        for scenario in scenarios:
            identity = (scenario.id, scenario.version)
            if identity in index:
                raise ScenarioLookupError(
                    f"duplicate scenario identity {scenario.id}@v{scenario.version}"
                )
            index[identity] = scenario
        self._index = index

    def require(self, case_id: str, version: int) -> AnalystScenario:
        """Return the exact typed scenario or fail closed."""
        try:
            return self._index[(case_id, version)]
        except KeyError as exc:
            raise ScenarioLookupError(
                f"no typed scenario resolves {case_id}@v{version}"
            ) from exc


class EvidenceAnalystEvaluationOutput(BaseModel):
    """Typed payload one evaluator consumes for one executed analyst case.

    Carries the **persisted** :class:`Assessment` returned by the production
    analyst plus the :class:`AnalystScenarioResolution` produced by fixture
    materialization. No LangSmith IDs, prompts, provider responses, or raw
    model output ever appear here.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment: Assessment
    """The persisted Assessment of this invocation."""

    resolution: AnalystScenarioResolution
    """The exact scenario label -> persisted identity resolution."""


class EvidenceAnalystTargetExecutor(TargetExecutor[EvidenceAnalystEvaluationOutput]):
    """Run one common Evidence Analyst case through the production analyst.

    Materialization runs in one short UnitOfWork and closes it before the
    analyst's own short transactions (input loading, accounting, and
    persistence), so no database transaction is ever held across LLM I/O.
    Repeated runs of the same case reuse the deterministic fixture through
    :meth:`AnalystScenarioMaterializer.materialize_or_reuse`.
    """

    def __init__(
        self,
        *,
        scenario_lookup: AnalystScenarioLookup,
        analyst: EvidenceAnalyst,
        uow_factory: Callable[[], UnitOfWork],
        materializer: AnalystScenarioMaterializer | None = None,
    ) -> None:
        """Bind the lookup, the production analyst, and the UnitOfWork factory."""
        self._scenario_lookup = scenario_lookup
        self._analyst = analyst
        self._uow_factory = uow_factory
        self._materializer = materializer or AnalystScenarioMaterializer()

    async def execute(
        self,
        *,
        case: EvaluationCase,
        context: EvaluationContext,
    ) -> EvidenceAnalystEvaluationOutput:
        """Materialize the exact scenario and run the production analyst once.

        ``context`` carries stable identity only and is validated by the
        runner before the case executes; the exact typed scenario comes from
        the run-scoped lookup, never from the context or remote metadata.
        """
        del context
        scenario = self._scenario_lookup.require(case.case_id, case.version)
        async with self._uow_factory() as uow:
            resolution = await self._materializer.materialize_or_reuse(uow, scenario)
        assessment = await self._analyst.analyze(
            self._materializer.investigation_id(scenario)
        )
        return EvidenceAnalystEvaluationOutput(
            assessment=assessment, resolution=resolution
        )
