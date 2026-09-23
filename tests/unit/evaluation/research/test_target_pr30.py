# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Research target dispatch tests (R-T01..T16).

Exercises the family dispatch with the **real Research Agent** over a scripted
retriever and an in-memory UnitOfWork (FakeLlmClient only at the model
boundary), plus the exact typed lookup. Proves: retrieval cases make zero LLM
calls; synthesis cases run one agent execution; supplied citations come from
the exact actual retrieval (no probe); empty retrieval stays zero-model-call;
LLM/persistence/citation failures are runner ERROR; cancellation propagates;
before/after snapshots are captured; and the boundary never imports LangSmith.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID, uuid5

import pytest

from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.research import ResearchRetriever
from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
from agentic_threat_investigator.app.research_persistence import (
    ResearchResultPersistenceService,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
)
from agentic_threat_investigator.domain.research import (
    ResearchQuery,
    ResearchResult,
    RetrievedChunk,
)
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
)
from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationContext,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationRunner,
    EvaluationTarget,
    evaluation_case_from,
)
from agentic_threat_investigator.evaluation.research.composition import (
    RecordingResearchRetriever,
)
from agentic_threat_investigator.evaluation.research.models import (
    ExpectedResearchResult,
    ResearchFixtureReference,
    ResearchRetrievalScenario,
    ResearchSynthesisScenario,
)
from agentic_threat_investigator.evaluation.research.pr30 import (
    ResearchAgentEvaluatorDispatcher,
)
from agentic_threat_investigator.evaluation.research.run import (
    run_research_agent_evaluation,
)
from agentic_threat_investigator.evaluation.research.target import (
    ResearchAgentTargetExecutor,
    ResearchScenarioLookup,
    ResearchScenarioLookupError,
)
from tests.support.evaluation_common import unit_dataset
from tests.support.llm_fixtures import FakeLlmClient

_RECORD = "attack-pattern--11111111-2222-3333-4444-555555555555"
_NS = UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


def _chunk(*, source_record_id: str = _RECORD) -> RetrievedChunk:
    """Build one deterministic retrieved chunk."""
    citation = uuid5(_NS, source_record_id)
    return RetrievedChunk(
        chunk_id=citation,
        citation_id=citation,
        document_id=uuid5(_NS, f"doc:{source_record_id}"),
        source_id="urn:ati:source:mitre_attack",
        source_record_id=source_record_id,
        document_type="attack-pattern",
        chunk_sequence=1,
        text="The technique obfuscates command-and-control traffic.",
        title="Data Obfuscation",
    )


def _spec(target: EvaluationTarget) -> Any:
    """Build one common scenario specification."""
    from agentic_threat_investigator.evaluation.common import (
        ExpectedBehavior,
        ScenarioSpecification,
    )

    return ScenarioSpecification(
        title="Unit research scenario",
        description="A fully described research unit scenario.",
        target=target,
        purpose="Exercises the research dispatch contract.",
        operational_relevance="Relevant to research evaluation coverage.",
        regression_risk="Protects against research dispatch regressions.",
        expected_behavior=ExpectedBehavior(
            required=("Context does not invent Evidence.",),
            forbidden=("Research never promotes into Evidence.",),
        ),
    )


def _retrieval_scenario() -> ResearchRetrievalScenario:
    """Build one deterministic retrieval scenario."""
    return ResearchRetrievalScenario(
        id="retrieval.s1",
        version=1,
        specification=_spec(EvaluationTarget.RESEARCH_AGENT),
        query="obfuscate command-and-control traffic",
        max_results=4,
        expected_relevant_source_records=(_RECORD,),
    )


def _synthesis_scenario() -> ResearchSynthesisScenario:
    """Build one deterministic synthesis scenario."""
    return ResearchSynthesisScenario(
        id="synthesis.s1",
        version=1,
        specification=_spec(EvaluationTarget.RESEARCH_AGENT),
        fixture=ResearchFixtureReference(name="mitre-attack-small"),
        query="obfuscate command-and-control traffic",
        max_results=4,
        source_records={"technique": _RECORD},
        expected=ExpectedResearchResult(
            min_claims=1,
            max_claims=2,
            required_citation_labels=("technique",),
            required_claims=(),
        ),
    )


class _ScriptedRetriever(ResearchRetriever):
    """Retriever double returning a fixed ordered chunk sequence."""

    def __init__(
        self, chunks: list[RetrievedChunk], *, fail: BaseException | None = None
    ) -> None:
        """Bind the scripted chunks and optional failure."""
        self._chunks = chunks
        self._fail = fail
        self.calls: list[ResearchQuery] = []

    async def retrieve(self, query: ResearchQuery) -> list[RetrievedChunk]:
        """Record the query and return the scripted chunks (or raise)."""
        self.calls.append(query)
        if self._fail is not None:
            raise self._fail
        return list(self._chunks)


class _FakeStore:
    """Shared in-memory fake store for the FakeUoW."""

    def __init__(self) -> None:
        """Initialize the empty stores."""
        self.entities: dict[UUID, object] = {}
        self.investigations: dict[UUID, InvestigationState] = {}
        self.results: dict[UUID, ResearchResult] = {}
        self.evidence_rows: dict[UUID, object] = {}
        self.observation_rows: dict[UUID, object] = {}
        self.assessment_rows: dict[UUID, object] = {}


class _FakeUoW:
    """Async-context UnitOfWork double exposing the research-write surface."""

    def __init__(self, store: _FakeStore) -> None:
        """Bind the shared store."""
        self._store = store
        self.entities = _Repo(store, "entities")
        self.investigations = _Repo(store, "investigations")
        self.research_results = _Repo(store, "results")
        self.evidence = _Repo(store, "evidence_rows")
        self.relationship_observations = _Repo(store, "observation_rows")
        self.assessments = _Repo(store, "assessment_rows")

    async def __aenter__(self) -> "_FakeUoW":
        """Return the double as its own context."""
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Close the double."""
        return


class _WriteResult:
    """Minimal investigation write-result double."""

    def __init__(
        self, investigation_id: UUID, version: int = 1, outcome: str = "INSERTED"
    ) -> None:
        """Bind the identity and version."""
        self.id = investigation_id
        self.version = version
        self.outcome = outcome


class _Repo:
    """One in-memory repository view over the shared store."""

    def __init__(self, store: _FakeStore, kind: str) -> None:
        """Bind the shared store and the targeted collection kind."""
        self._store = store
        self._kind = kind

    def _rows(self) -> dict[UUID, object]:
        """Return the targeted row collection."""
        return getattr(self._store, self._kind)  # type: ignore[no-any-return]

    async def upsert(self, entity: object) -> object:
        """Persist/return one entity by its id attribute."""
        self._rows()[entity.id] = entity  # type: ignore[attr-defined]
        return entity

    async def get_by_id(self, identity: UUID) -> object | None:
        """Return one stored object by identity across all collections."""
        return self._rows().get(identity)

    async def create(self, state: InvestigationState, **_: object) -> _WriteResult:
        """Persist one investigation, returning a write result."""
        stored = state.model_copy(update={"version": 1})
        self._rows()[stored.investigation_id] = stored
        return _WriteResult(stored.investigation_id, 1)

    async def update_budget(
        self, investigation_id: UUID, budget: object, **_: object
    ) -> _WriteResult:
        """Record the reserved budget and return a bumped version."""
        rows = self._store.investigations
        state = rows.get(investigation_id)
        if state is None:
            raise LookupError("investigation not found")
        current = state.version or 1
        bumped = current + 1
        rows[investigation_id] = state.model_copy(
            update={"budget": budget, "version": bumped}
        )
        return _WriteResult(investigation_id, bumped)

    async def list_for_investigation(
        self, investigation_id: UUID, **_: object
    ) -> list[object]:
        """Return an empty list for every snapshot query."""
        del investigation_id
        return []

    async def add(self, result: ResearchResult) -> None:
        """Store one research result."""
        self._rows()[result.id] = result


@dataclass(frozen=True)
class _FakeWorld:
    """Research world double with the same surface as ResearchWorld."""

    agent: ResearchAgent
    retriever: RecordingResearchRetriever
    session_factory: object = None


def _world(
    chunks: list[RetrievedChunk],
    llm: FakeLlmClient,
    store: _FakeStore,
    *,
    retriever_fail: BaseException | None = None,
) -> tuple[_FakeWorld, RecordingResearchRetriever]:
    """Build the real Research Agent over scripted retrieval and a FakeUoW."""
    recording = RecordingResearchRetriever(
        _ScriptedRetriever(chunks, fail=retriever_fail)
    )
    agent = ResearchAgent(
        retriever=recording,
        llm_client=llm,
        result_persistence=ResearchResultPersistenceService(
            lambda: cast(UnitOfWork, _FakeUoW(store))
        ),
        llm_accounting=LlmAccountingService(lambda: cast(UnitOfWork, _FakeUoW(store))),
        max_structured_output_attempts=2,
    )
    return _FakeWorld(agent=agent, retriever=recording), recording


def _uow_factory(store: _FakeStore) -> Callable[[], UnitOfWork]:
    """Return a fake UnitOfWork factory through the service's type."""
    return lambda: cast(UnitOfWork, _FakeUoW(store))


def _context(case_id: str) -> EvaluationContext:
    """Build one minimal evaluation context."""
    return EvaluationContext(dataset_id="research-agent/v1", case_id=case_id)


class TestResearchScenarioLookup:
    """R-T01..T04 identity semantics."""

    def test_t01_retrieval_and_synthesis_resolve(self) -> None:
        """T01 exact identities resolve for both families."""
        lookup = ResearchScenarioLookup([_retrieval_scenario(), _synthesis_scenario()])
        assert lookup.require("retrieval.s1", 1) is not None
        assert lookup.require("synthesis.s1", 1) is not None

    def test_t03_duplicate_identity_across_kinds_rejected(self) -> None:
        """T03 duplicate identities across families are rejected."""
        retrieval = _retrieval_scenario().model_copy(update={"id": "dup"})
        synthesis = _synthesis_scenario().model_copy(update={"id": "dup"})
        with pytest.raises(ResearchScenarioLookupError):
            ResearchScenarioLookup([retrieval, synthesis])

    def test_t04_unknown_and_version_mismatch_fail_closed(self) -> None:
        """T04 unknown/version-mismatch identities fail closed."""
        lookup = ResearchScenarioLookup([_retrieval_scenario()])
        with pytest.raises(ResearchScenarioLookupError):
            lookup.require("unknown", 1)
        with pytest.raises(ResearchScenarioLookupError):
            lookup.require("retrieval.s1", 9)


class TestResearchTargetRetrieval:
    """R-T05/T16 retrieval-branch semantics."""

    @pytest.mark.asyncio
    async def test_t05_retrieval_branch_zero_llm(self) -> None:
        """T01/T05 a retrieval case executes the retriever and uses zero LLM calls."""
        store = _FakeStore()
        llm = FakeLlmClient()
        world, _recording = _world([_chunk()], llm, store)
        scenario = _retrieval_scenario()
        lookup = ResearchScenarioLookup([scenario])
        target = ResearchAgentTargetExecutor(
            scenario_lookup=lookup,
            world=world,  # type: ignore[arg-type]
            uow_factory=_uow_factory(store),
        )
        output = await target.execute(
            case=evaluation_case_from(scenario), context=_context(scenario.id)
        )
        assert output.retrieval is not None
        assert len(output.retrieval.chunks) == 1
        assert llm.calls == []


class TestResearchTargetSynthesis:
    """R-T06..T15 synthesis-branch semantics."""

    def _synthesis_executor(
        self,
        store: _FakeStore,
        llm: FakeLlmClient,
        chunks: list[RetrievedChunk],
    ) -> tuple[
        ResearchSynthesisScenario, ResearchAgentTargetExecutor, ResearchScenarioLookup
    ]:
        """Build one synthesis executor over the real agent."""
        scenario = _synthesis_scenario()
        lookup = ResearchScenarioLookup([scenario])
        world, _recording = _world(chunks, llm, store)
        target = ResearchAgentTargetExecutor(
            scenario_lookup=lookup,
            world=world,  # type: ignore[arg-type]
            uow_factory=_uow_factory(store),
        )
        return scenario, target, lookup

    @pytest.mark.asyncio
    async def test_t06_one_agent_execution_exact_chunks(self) -> None:
        """T06/T07/T08/T09 one agent execution with exact supplied citations."""
        store = _FakeStore()
        chunk = _chunk()
        llm = FakeLlmClient()
        llm.set_default(
            ResearchAgentDecision(
                claims=(
                    ResearchAgentClaim(
                        text="Context claim.", citation_ids=(chunk.citation_id,)
                    ),
                )
            )
        )
        scenario, target, _lookup = self._synthesis_executor(store, llm, [chunk])
        output = await target.execute(
            case=evaluation_case_from(scenario), context=_context(scenario.id)
        )
        assert output.synthesis is not None
        assert output.synthesis.supplied_citation_ids == (chunk.citation_id,)
        assert output.synthesis.result.id is not None
        assert output.synthesis.resolution.citations["technique"] == chunk.citation_id
        assert len(output.synthesis.before_snapshot.evidence_ids) == 0
        assert len(output.synthesis.after_snapshot.evidence_ids) == 0

    @pytest.mark.asyncio
    async def test_t10_empty_retrieval_zero_llm_empty_result(self) -> None:
        """T10 empty retrieval persists an empty result with zero LLM calls."""
        store = _FakeStore()
        llm = FakeLlmClient()
        empty_scenario = _synthesis_scenario().model_copy(update={"source_records": {}})
        lookup = ResearchScenarioLookup([empty_scenario])
        world, _recording = _world([], llm, store)
        target = ResearchAgentTargetExecutor(
            scenario_lookup=lookup,
            world=world,  # type: ignore[arg-type]
            uow_factory=_uow_factory(store),
        )
        output = await target.execute(
            case=evaluation_case_from(empty_scenario),
            context=_context(empty_scenario.id),
        )
        assert output.synthesis is not None
        assert output.synthesis.result.claims == ()
        assert output.synthesis.result.citations == ()
        assert output.synthesis.supplied_citation_ids == ()
        assert llm.calls == []

    @pytest.mark.asyncio
    async def test_t11_llm_failure_is_error_not_fail(self) -> None:
        """T11 an LLM failure surfaces as a runner ERROR, not FAIL."""
        store = _FakeStore()
        chunk = _chunk()
        llm = FakeLlmClient()
        llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False))
        scenario, target, lookup = self._synthesis_executor(store, llm, [chunk])
        result = await EvaluationRunner().run(
            dataset_id=EvaluationDatasetId(
                target=EvaluationTarget.RESEARCH_AGENT, version=1
            ),
            cases=[evaluation_case_from(scenario)],
            target=target,
            evaluators=(ResearchAgentEvaluatorDispatcher(scenario_lookup=lookup),),  # type: ignore[arg-type]
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None

    @pytest.mark.asyncio
    async def test_t12_unsupported_citation_is_error(self) -> None:
        """T12 a schema-valid but unsupported citation fails closed as ERROR."""
        store = _FakeStore()
        chunk = _chunk()
        llm = FakeLlmClient()
        foreign = uuid5(_NS, "foreign")
        llm.set_default(
            ResearchAgentDecision(
                claims=(ResearchAgentClaim(text="Claim.", citation_ids=(foreign,)),)
            )
        )
        scenario, target, lookup = self._synthesis_executor(store, llm, [chunk])
        result = await EvaluationRunner().run(
            dataset_id=EvaluationDatasetId(
                target=EvaluationTarget.RESEARCH_AGENT, version=1
            ),
            cases=[evaluation_case_from(scenario)],
            target=target,
            evaluators=(ResearchAgentEvaluatorDispatcher(scenario_lookup=lookup),),  # type: ignore[arg-type]
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None

    @pytest.mark.asyncio
    async def test_t13_persistence_failure_is_error(self) -> None:
        """T13 a persistence failure becomes a runner ERROR."""

        class FailingStore(_FakeStore):
            """Store whose research add raises."""

        store = FailingStore()
        chunk = _chunk()
        llm = FakeLlmClient()
        llm.set_default(
            ResearchAgentDecision(
                claims=(
                    ResearchAgentClaim(
                        text="Claim.", citation_ids=(chunk.citation_id,)
                    ),
                )
            )
        )

        class FailingPersistence(ResearchResultPersistenceService):
            """Persistence double raising from persist."""

            async def persist(self, result: ResearchResult) -> None:
                """Raise a persistence failure."""
                del result
                raise RuntimeError("persistence blew up")

        recording = RecordingResearchRetriever(_ScriptedRetriever([chunk]))
        agent = ResearchAgent(
            retriever=recording,
            llm_client=llm,
            result_persistence=FailingPersistence(
                lambda: cast(UnitOfWork, _FakeUoW(store))
            ),
            llm_accounting=LlmAccountingService(
                lambda: cast(UnitOfWork, _FakeUoW(store))
            ),
            max_structured_output_attempts=2,
        )
        world = _FakeWorld(agent=agent, retriever=recording)
        scenario = _synthesis_scenario()
        lookup = ResearchScenarioLookup([scenario])
        target = ResearchAgentTargetExecutor(
            scenario_lookup=lookup,
            world=world,  # type: ignore[arg-type]
            uow_factory=_uow_factory(store),
        )
        result = await EvaluationRunner().run(
            dataset_id=EvaluationDatasetId(
                target=EvaluationTarget.RESEARCH_AGENT, version=1
            ),
            cases=[evaluation_case_from(scenario)],
            target=target,
            evaluators=(ResearchAgentEvaluatorDispatcher(scenario_lookup=lookup),),  # type: ignore[arg-type]
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None

    @pytest.mark.asyncio
    async def test_t14_snapshots_captured_around_interval(self) -> None:
        """T14 before/after snapshots are captured around the research interval."""
        store = _FakeStore()
        chunk = _chunk()
        llm = FakeLlmClient()
        llm.set_default(
            ResearchAgentDecision(
                claims=(
                    ResearchAgentClaim(
                        text="Context claim.", citation_ids=(chunk.citation_id,)
                    ),
                )
            )
        )
        scenario, target, _lookup = self._synthesis_executor(store, llm, [chunk])
        output = await target.execute(
            case=evaluation_case_from(scenario), context=_context(scenario.id)
        )
        assert output.synthesis is not None
        assert (
            output.synthesis.before_snapshot.evidence_ids
            == output.synthesis.after_snapshot.evidence_ids
        )
        assert (
            output.synthesis.before_snapshot.assessment_identities
            == output.synthesis.after_snapshot.assessment_identities
        )

    @pytest.mark.asyncio
    async def test_t15_cancellation_propagates(self) -> None:
        """T15 asyncio.CancelledError propagates through the target."""
        store = _FakeStore()
        chunk = _chunk()
        llm = FakeLlmClient()
        llm.enqueue(asyncio.CancelledError("cancelled"))
        scenario, target, _lookup = self._synthesis_executor(store, llm, [chunk])
        with pytest.raises(asyncio.CancelledError):
            await target.execute(
                case=evaluation_case_from(scenario), context=_context(scenario.id)
            )


def test_t16_no_langsmith_dependency() -> None:
    """T16 the research target boundary never imports LangSmith."""
    from agentic_threat_investigator.evaluation.research import target as module

    source = inspect.getsource(module)
    assert "from langsmith" not in source
    assert "import langsmith" not in source
    assert "LangSmithEvaluationClient" not in source


@pytest.mark.asyncio
async def test_run_service_rejects_non_research() -> None:
    """The research run service rejects non-research targets before execution."""
    store = _FakeStore()
    llm = FakeLlmClient()
    world, _ = _world([_chunk()], llm, store)
    with pytest.raises(DatasetLoadError):
        await run_research_agent_evaluation(
            dataset_id=unit_dataset(),
            world=world,  # type: ignore[arg-type]
            uow_factory=_uow_factory(store),
        )
