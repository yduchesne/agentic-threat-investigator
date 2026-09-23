# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Research Agent target execution (retrieval/synthesis dispatch).

The common runner executes **one target per case**; ``research-agent/v1``
owns two distinct scenario families. This module dispatches by the exact
typed scenario without redesigning the common runner:

- :class:`ResearchRetrievalScenario` cases run the **production retriever**
  once and carry the ordered chunks (zero LLM calls);
- :class:`ResearchSynthesisScenario` cases run the **real Research Agent**
  once, persist the current :class:`ResearchResult`, and return the exact
  supplied citation sequence (observed at the model boundary, never a probe
  retrieval) plus before/after epistemic snapshots.

The output is a frozen tagged union; the evaluator dispatcher consumes one
branch per case.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.research import (
    ResearchResult,
    RetrievedChunk,
)
from agentic_threat_investigator.domain.research_agent import ResearchAgentRequest
from agentic_threat_investigator.evaluation.common import (
    EvaluationCase,
    EvaluationContext,
)
from agentic_threat_investigator.evaluation.common.evaluator import TargetExecutor
from agentic_threat_investigator.evaluation.research.composition import (
    ResearchWorld,
    load_epistemic_snapshot,
    research_query,
    scenario_anchor_ids,
    seed_research_anchors,
)
from agentic_threat_investigator.evaluation.research.models import (
    ResearchEpistemicSnapshot,
    ResearchRetrievalScenario,
    ResearchScenarioResolution,
    ResearchSynthesisScenario,
)

ScenarioIdentity = tuple[str, int]
"""One exact scenario identity: ``(case_id, case_version)``."""


class ResearchScenarioLookupError(ValueError):
    """A common case cannot be resolved to exactly one typed research scenario."""


class ResearchScenarioLookup:
    """Immutable run-scoped ``(case_id, version) -> typed scenario`` map.

    Retrieval and synthesis scenarios share one identity space; duplicate
    identities across both families are rejected.
    """

    def __init__(
        self,
        scenarios: Sequence[ResearchRetrievalScenario | ResearchSynthesisScenario],
    ) -> None:
        """Index every scenario by its exact ``(id, version)`` identity."""
        index: dict[
            ScenarioIdentity, ResearchRetrievalScenario | ResearchSynthesisScenario
        ] = {}
        for scenario in scenarios:
            identity = (scenario.id, scenario.version)
            if identity in index:
                raise ResearchScenarioLookupError(
                    f"duplicate research scenario identity {scenario.id}@v{scenario.version}"
                )
            index[identity] = scenario
        self._index = index

    def require(
        self, case_id: str, version: int
    ) -> ResearchRetrievalScenario | ResearchSynthesisScenario:
        """Return the exact typed scenario or fail closed."""
        try:
            return self._index[(case_id, version)]
        except KeyError as exc:
            raise ResearchScenarioLookupError(
                f"no typed research scenario resolves {case_id}@v{version}"
            ) from exc


class ResearchRetrievalEvaluationOutput(BaseModel):
    """Retrieval-branch output: the ordered production retrieval response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    chunks: tuple[RetrievedChunk, ...]


class ResearchSynthesisEvaluationOutput(BaseModel):
    """Synthesis-branch output: persisted result + exact execution facts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    result: ResearchResult
    """The persisted ResearchResult of the current invocation."""

    resolution: ResearchScenarioResolution
    """Semantic labels resolved against the exact supplied retrieval."""

    supplied_citation_ids: tuple[UUID, ...]
    """Exact citation IDs supplied to the agent's model invocation."""

    before_snapshot: ResearchEpistemicSnapshot
    """Promotion-sensitive identities captured before the research interval."""

    after_snapshot: ResearchEpistemicSnapshot
    """Promotion-sensitive identities captured after the research interval."""

    investigation_id: UUID
    """The run-scoped Investigation anchor of this execution."""

    subject_entity_id: UUID
    """The run-scoped subject Entity anchor of this execution."""


class ResearchEvaluationOutput(BaseModel):
    """Frozen tagged union one evaluator consumes for one research case."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    retrieval: ResearchRetrievalEvaluationOutput | None = None
    synthesis: ResearchSynthesisEvaluationOutput | None = None


class ResearchAgentTargetExecutor(TargetExecutor[ResearchEvaluationOutput]):
    """Execute one common Research case through the production runtime.

    Dispatch is by the exact typed scenario; the production retriever and
    the real Research Agent are the only execution paths, and neither
    LangSmith nor a second probe retrieval ever participates.
    """

    def __init__(
        self,
        *,
        scenario_lookup: ResearchScenarioLookup,
        world: ResearchWorld,
        uow_factory: Callable[[], UnitOfWork],
    ) -> None:
        """Bind the typed lookup, the composed research world, and persistence."""
        self._scenario_lookup = scenario_lookup
        self._world = world
        self._uow_factory = uow_factory

    async def execute(
        self,
        *,
        case: EvaluationCase,
        context: EvaluationContext,
    ) -> ResearchEvaluationOutput:
        """Dispatch one case to its family-specific production execution."""
        del context
        scenario = self._scenario_lookup.require(case.case_id, case.version)
        if isinstance(scenario, ResearchRetrievalScenario):
            return await self._execute_retrieval(scenario)
        if isinstance(scenario, ResearchSynthesisScenario):
            return await self._execute_synthesis(scenario)
        raise ResearchScenarioLookupError(
            f"unsupported research scenario kind: {type(scenario).__name__}"
        )

    async def _execute_retrieval(
        self, scenario: ResearchRetrievalScenario
    ) -> ResearchEvaluationOutput:
        """Run one production retrieval pass for one retrieval scenario."""
        investigation_id, _ = scenario_anchor_ids(
            case_id=scenario.id,
            version=scenario.version,
            execution_id=uuid4(),
        )
        query = research_query(
            investigation_id=investigation_id,
            query=scenario.query,
            source_ids=scenario.source_ids,
            document_types=scenario.document_types,
            max_results=scenario.max_results,
        )
        chunks = await self._world.retriever.retrieve(query)
        return ResearchEvaluationOutput(
            retrieval=ResearchRetrievalEvaluationOutput(
                chunks=tuple(chunks),
            )
        )

    async def _execute_synthesis(
        self, scenario: ResearchSynthesisScenario
    ) -> ResearchEvaluationOutput:
        """Run one real Research Agent execution and capture its facts."""
        execution_id = uuid4()
        investigation_id, subject_entity_id = scenario_anchor_ids(
            case_id=scenario.id,
            version=scenario.version,
            execution_id=execution_id,
        )
        await seed_research_anchors(
            self._uow_factory,
            investigation_id=investigation_id,
            subject_entity_id=subject_entity_id,
        )
        request = ResearchAgentRequest(
            investigation_id=investigation_id,
            subject_entity_id=subject_entity_id,
            query=scenario.query,
            source_ids=tuple(scenario.source_ids),
            document_types=tuple(scenario.document_types),
            max_results=scenario.max_results,
        )
        before = await load_epistemic_snapshot(self._uow_factory, investigation_id)
        result = await self._world.agent.research(request)
        after = await load_epistemic_snapshot(self._uow_factory, investigation_id)
        async with self._uow_factory() as uow:
            persisted = await uow.research_results.get_by_id(result.id)
        if persisted is None:
            raise RuntimeError("research result was not persisted")
        supplied_chunks = (
            tuple(self._world.retriever.calls[-1])
            if self._world.retriever.calls
            else ()
        )
        from agentic_threat_investigator.evaluation.research.materialization import (
            resolve_research_scenario,
        )

        resolution = resolve_research_scenario(scenario, supplied_chunks)
        supplied = tuple(self._world.retriever.supplied_citation_ids)
        return ResearchEvaluationOutput(
            synthesis=ResearchSynthesisEvaluationOutput(
                result=persisted,
                resolution=resolution,
                supplied_citation_ids=supplied,
                before_snapshot=before,
                after_snapshot=after,
                investigation_id=investigation_id,
                subject_entity_id=subject_entity_id,
            )
        )
