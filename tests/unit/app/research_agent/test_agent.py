# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the standalone structured Research Agent (PR 22B).

The real ``ResearchResultPersistenceService`` and ``LlmAccountingService``
run against in-memory fakes; a scripted ``FakeLlmClient`` drives the model
boundary; and a scripted ``FakeResearchRetriever`` drives the retrieval
boundary. No real external model or database participates.
"""

# The fakes mirror the repository seam shape used by the PR 22A persistence
# and PR 20B accounting suites, and the agent service deliberately takes one
# explicit dependency per seam; duplication is test-only and accepted.

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from types import TracebackType
from typing import Self
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.evidence_analyst import LlmAccountingService
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    InvestigationRepository,
    InvestigationVersionConflictError,
    InvestigationWriteResult,
    ResearchResultDuplicateIdentityError,
    UnitOfWork,
)
from agentic_threat_investigator.app.research import (
    ResearchRetrievalError,
    ResearchRetriever,
)
from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
from agentic_threat_investigator.app.research_agent.errors import (
    ResearchAgentCitationError,
)
from agentic_threat_investigator.app.research_persistence import (
    ResearchResultPersistenceService,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationBudget,
    InvestigationBudgetExhaustedError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.research import (
    ResearchQuery,
    ResearchResult,
    RetrievedChunk,
)
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
    ResearchAgentRequest,
)
from tests.support.llm_fixtures import FakeLlmClient

_RETRIEVED_AT = datetime(2026, 1, 2, tzinfo=UTC)
_FIXED_CLOCK = datetime(2026, 1, 3, 4, 5, 6, tzinfo=UTC)


def _chunk(**overrides: object) -> RetrievedChunk:
    """Build one deterministic retrieved chunk."""
    values: dict[str, object] = {
        "chunk_id": uuid4(),
        "citation_id": uuid4(),
        "document_id": uuid4(),
        "source_id": "urn:ati:source:mitre_attack",
        "source_record_id": "attack-pattern--1001",
        "document_type": "attack_technique",
        "chunk_sequence": 1,
        "text": "Operators reuse PowerShell to run scripted payloads.",
        "title": "PowerShell",
        "source_url": "https://attack.mitre.org/techniques/T1059/003",
        "published_at": _RETRIEVED_AT,
        "similarity_score": 0.87,
        "metadata": {"document": {"label": "technique"}},
    }
    values.update(overrides)
    return RetrievedChunk.model_validate(values)


def _claim(text: str, *citation_ids: UUID) -> ResearchAgentClaim:
    """Build one semantic claim citing the supplied stable citation IDs."""
    return ResearchAgentClaim(text=text, citation_ids=citation_ids)


def _decision(*claims: ResearchAgentClaim) -> ResearchAgentDecision:
    """Build a semantic decision preserving claim order."""
    return ResearchAgentDecision(claims=claims)


class ResearchWorld:
    """One deterministic execution world with scripted retrieved chunks."""

    def __init__(self) -> None:
        self.investigation_id = uuid4()
        self.subject_entity_id = uuid4()
        self.chunk_a = _chunk(
            text="Chunk A supports statement X.", source_record_id="attack-pattern--a"
        )
        self.chunk_b = _chunk(
            text="Chunk B conflicts with statement X.",
            source_record_id="attack-pattern--b",
        )
        self.chunk_unused = _chunk(
            text="Retrieved but unused context.",
            source_record_id="attack-pattern--unused",
        )
        self.investigation = InvestigationState(
            investigation_id=self.investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[self.subject_entity_id],
            objective="Explain the contextual question.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
            version=1,
        )

    def request(self, **overrides: object) -> ResearchAgentRequest:
        """Build the world's bounded execution request."""
        values: dict[str, object] = {
            "investigation_id": self.investigation_id,
            "subject_entity_id": self.subject_entity_id,
            "query": "Which technique is described?",
        }
        values.update(overrides)
        return ResearchAgentRequest.model_validate(values)


class FakeResearchRetriever(ResearchRetriever):
    """Scripted retriever recording every bounded query."""

    def __init__(self, chunks: Sequence[RetrievedChunk] = ()) -> None:
        self._chunks = list(chunks)
        self.queries: list[ResearchQuery] = []
        self.fail: Exception | None = None

    async def retrieve(self, query: ResearchQuery) -> list[RetrievedChunk]:
        """Record the bounded query and return the scripted chunks."""
        self.queries.append(query)
        if self.fail is not None:
            raise self.fail
        return list(self._chunks)


class _ResearchResults:
    """Append-only fake repository with an injectable failure seam."""

    def __init__(self) -> None:
        self.stored: dict[UUID, ResearchResult] = {}
        self.fail: Exception | None = None

    async def add(self, result: ResearchResult) -> None:
        """Insert an immutable result or reject a duplicate identity."""
        if self.fail is not None:
            raise self.fail
        if result.id in self.stored:
            raise ResearchResultDuplicateIdentityError(result.id)
        self.stored[result.id] = result

    async def get_by_id(self, result_id: UUID) -> ResearchResult | None:
        """Return one stored result."""
        return self.stored.get(result_id)

    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> list[ResearchResult]:
        """Return stored results for one investigation."""
        return [
            result
            for result in self.stored.values()
            if result.investigation_id == investigation_id
        ]


class _Investigations:
    """Fake investigation repository with an injectable visibility map."""

    def __init__(self, visible: set[UUID]) -> None:
        self._visible = visible

    async def get_by_id(self, id: UUID) -> InvestigationState | None:
        """Return a placeholder state when the identity is visible."""
        if id not in self._visible:
            return None
        return InvestigationState.__new__(InvestigationState)


class _Entities:
    """Fake entity repository with an injectable visibility map."""

    def __init__(self, visible: set[UUID]) -> None:
        self._visible = visible

    async def get_by_id(self, entity_id: UUID) -> Entity | None:
        """Return a placeholder entity when the identity is visible."""
        if entity_id not in self._visible:
            return None
        return Entity(id=entity_id, type=EntityType.DOMAIN, value="example.test")


class _PersistenceUow(UnitOfWork):
    """In-memory transaction boundary for result persistence."""

    def __init__(
        self,
        research_results: _ResearchResults,
        visible_investigations: set[UUID],
        visible_entities: set[UUID],
    ) -> None:
        self.research_results = research_results  # type: ignore[assignment]
        self.investigations = _Investigations(visible_investigations)  # type: ignore[assignment]
        self.entities = _Entities(visible_entities)  # type: ignore[assignment]
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self) -> Self:
        """Open the fake transaction."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit on success; count the rollback otherwise."""
        if exc_type is None:
            self.commits += 1
        else:
            self.rollbacks += 1

    async def commit(self) -> None:
        """Record the commit."""
        self.commits += 1

    async def rollback(self) -> None:
        """Record the rollback."""
        self.rollbacks += 1


class _AccountingUow(UnitOfWork):
    """In-memory reservation boundary applying budget updates to the state."""

    def __init__(self, investigation: InvestigationState) -> None:
        self.investigation = investigation
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self) -> Self:
        """Open the fake transaction."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit on success; count the rollback otherwise."""
        if exc_type is None:
            self.commits += 1
        else:
            self.rollbacks += 1

    async def commit(self) -> None:
        """Record the commit."""
        self.commits += 1

    async def rollback(self) -> None:
        """Record the rollback."""
        self.rollbacks += 1


class _AccountingInvestigationRepository(InvestigationRepository):
    """Investigation repository applying budget writes to the in-memory state."""

    def __init__(self, state: InvestigationState) -> None:
        self.state = state
        self.budget_writes: list[InvestigationBudget] = []
        self.versions: list[int] = []

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        """Return the visible state."""
        return self.state

    async def update_budget(
        self,
        investigation_id: UUID,
        budget: InvestigationBudget,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Apply the budget write under version semantics."""
        if expected_version is not None and self.state.version != expected_version:
            raise InvestigationVersionConflictError(investigation_id, expected_version)
        self.budget_writes.append(budget.model_copy())
        self.state.budget = budget
        self.state.version = (self.state.version or 0) + 1
        self.versions.append(self.state.version)
        return InvestigationWriteResult(
            investigation_id, self.state.version, BatchOutcome.UPDATED
        )

    async def update_assessment_reference(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        **_: object,
    ) -> InvestigationWriteResult:
        """Unused by the Research Agent; rejected by the fake."""
        raise NotImplementedError

    async def create(self, *args: object, **_: object) -> InvestigationWriteResult:
        """Unused by the Research Agent; rejected by the fake."""
        raise NotImplementedError

    async def update_status(
        self, *args: object, **_: object
    ) -> InvestigationWriteResult:
        """Unused by the Research Agent; rejected by the fake."""
        raise NotImplementedError

    async def update_coordinator_state(
        self,
        investigation_id: UUID,
        transition_kind: object,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        consumes_replan: bool = False,
    ) -> InvestigationWriteResult:
        """Unused by the Research Agent; rejected by the fake."""
        raise NotImplementedError

    async def set_analysis_result(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        analyzed_evidence_ids: list[UUID],
        disposition: object,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationWriteResult:
        """Unused by the Research Agent; rejected by the fake."""
        raise NotImplementedError

    async def soft_delete(self, *args: object, **_: object) -> InvestigationWriteResult:
        """Unused by the Research Agent; rejected by the fake."""
        raise NotImplementedError


@dataclass
class Harness:
    """The fully-bound Research Agent plus every observable fake."""

    agent: ResearchAgent
    llm: FakeLlmClient
    retriever: FakeResearchRetriever
    store: _ResearchResults
    persistence_uow: _PersistenceUow
    accounting_repo: _AccountingInvestigationRepository


def make_harness(
    world: ResearchWorld,
    *,
    chunks: Sequence[RetrievedChunk],
    visible_investigations: set[UUID] | None = None,
    visible_entities: set[UUID] | None = None,
    id_factory: Callable[[], UUID] | None = None,
    clock: Callable[[], datetime] | None = None,
    attempt_counts: list[int] | None = None,
) -> Harness:
    """Build the fully-bound agent plus all observable fakes."""
    fake_llm = FakeLlmClient()
    retriever = FakeResearchRetriever(chunks)
    store = _ResearchResults()
    persistence_uow = _PersistenceUow(
        store,
        visible_investigations or {world.investigation_id},
        visible_entities or {world.subject_entity_id},
    )
    accounting_uow = _AccountingUow(world.investigation)
    accounting_repo = _AccountingInvestigationRepository(world.investigation)
    accounting_uow.investigations = accounting_repo
    accounting = LlmAccountingService(lambda: accounting_uow)
    persistence = ResearchResultPersistenceService(lambda: persistence_uow)
    agent = ResearchAgent(
        retriever=retriever,
        llm_client=fake_llm,
        result_persistence=persistence,
        llm_accounting=accounting,
        max_structured_output_attempts=2,
        clock=clock,
        id_factory=id_factory,
    )
    return Harness(agent, fake_llm, retriever, store, persistence_uow, accounting_repo)


@pytest.fixture
def world() -> ResearchWorld:
    """Return one deterministic research world per test."""
    return ResearchWorld()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relevant_context_persists_with_stamped_identity(
    world: ResearchWorld,
) -> None:
    """RA-U16: a valid decision persists one result with stamped IDs and one snapshot."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.set_default(
        _decision(_claim("Statement X is described.", world.chunk_a.citation_id))
    )

    result = await harness.agent.research(world.request())

    assert isinstance(result.id, UUID)
    assert result.investigation_id == world.investigation_id
    assert result.subject_entity_id == world.subject_entity_id
    assert result.query == "Which technique is described?"
    assert len(result.claims) == 1
    assert result.claims[0].citation_ids == (world.chunk_a.citation_id,)
    assert len(result.citations) == 1
    assert result.citations[0].citation_id == world.chunk_a.citation_id
    assert result.citations[0].chunk_id == world.chunk_a.chunk_id
    assert harness.store.stored[result.id] is result
    assert len(harness.llm.calls) == 1
    assert len(harness.accounting_repo.budget_writes) == 1


@pytest.mark.asyncio
async def test_retrieval_query_is_bounded_and_mapped(world: ResearchWorld) -> None:
    """The pure request-to-query mapping reaches the retriever exactly once."""
    entity_id = uuid4()
    harness = make_harness(
        world,
        chunks=[world.chunk_a],
        id_factory=lambda: uuid4(),
    )
    harness.llm.set_default(
        _decision(_claim("Statement X.", world.chunk_a.citation_id))
    )

    await harness.agent.research(
        world.request(
            entity_ids=[entity_id],
            source_ids=["urn:src:a"],
            document_types=["attack_technique"],
            max_results=3,
        )
    )

    assert len(harness.retriever.queries) == 1
    query = harness.retriever.queries[0]
    assert query.investigation_id == world.investigation_id
    assert query.query == "Which technique is described?"
    assert query.entity_ids == [entity_id]
    assert query.source_ids == ["urn:src:a"]
    assert query.document_types == ["attack_technique"]
    assert query.max_results == 3


@pytest.mark.asyncio
async def test_application_stamps_ids_and_clock(world: ResearchWorld) -> None:
    """The application, not the model, owns identity, clock, and anchors."""
    result_id = uuid4()
    claim_id = uuid4()
    ids = iter([claim_id, result_id])
    harness = make_harness(
        world,
        chunks=[world.chunk_a],
        id_factory=lambda: next(ids),
        clock=lambda: _FIXED_CLOCK,
    )
    harness.llm.set_default(
        _decision(_claim("Statement X.", world.chunk_a.citation_id))
    )

    result = await harness.agent.research(world.request())

    assert result.id == result_id
    assert result.claims[0].id == claim_id
    assert result.created_at == _FIXED_CLOCK


# ---------------------------------------------------------------------------
# Citation provenance rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unsupported_citation_fails_closed(world: ResearchWorld) -> None:
    """RA-U17: a schema-valid claim citing an unknown citation is rejected."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.set_default(_decision(_claim("Invented.", uuid4())))

    with pytest.raises(ResearchAgentCitationError):
        await harness.agent.research(world.request())

    assert harness.store.stored == {}
    assert len(harness.llm.calls) == 1
    assert len(harness.accounting_repo.budget_writes) == 1


@pytest.mark.asyncio
async def test_citation_in_corpus_but_not_supplied_is_rejected(
    world: ResearchWorld,
) -> None:
    """RA-U18: a real citation outside the supplied set is rejected identically."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.set_default(
        _decision(
            _claim("Cites a real but unsupplied chunk.", world.chunk_b.citation_id)
        )
    )

    with pytest.raises(ResearchAgentCitationError) as holder:
        await harness.agent.research(world.request())

    assert holder.value.citation_ids == (world.chunk_b.citation_id,)
    assert harness.store.stored == {}


@pytest.mark.asyncio
async def test_retrieved_but_unused_chunk_is_not_snapshotted(
    world: ResearchWorld,
) -> None:
    """RA-U19: only cited chunks become durable citation snapshots."""
    harness = make_harness(world, chunks=[world.chunk_a, world.chunk_b])
    harness.llm.set_default(
        _decision(_claim("Only A is relevant.", world.chunk_a.citation_id))
    )

    result = await harness.agent.research(world.request())

    assert [citation.citation_id for citation in result.citations] == [
        world.chunk_a.citation_id
    ]
    assert world.chunk_b.citation_id not in {
        citation.citation_id for citation in result.citations
    }
    assert result.citations[0].chunk_id == world.chunk_a.chunk_id


@pytest.mark.asyncio
async def test_reused_citation_yields_one_snapshot(world: ResearchWorld) -> None:
    """RA-U20: multiple claims citing the same chunk share one snapshot."""
    first_claim_id, second_claim_id, result_id = uuid4(), uuid4(), uuid4()
    ids = iter([first_claim_id, second_claim_id, result_id])
    harness = make_harness(world, chunks=[world.chunk_a], id_factory=lambda: next(ids))
    harness.llm.set_default(
        _decision(
            _claim("First statement.", world.chunk_a.citation_id),
            _claim("Second statement.", world.chunk_a.citation_id),
        )
    )

    result = await harness.agent.research(world.request())

    assert result.id == result_id
    assert [claim.id for claim in result.claims] == [first_claim_id, second_claim_id]
    assert len(result.citations) == 1
    assert result.citations[0].citation_id == world.chunk_a.citation_id


@pytest.mark.asyncio
async def test_citation_order_is_deterministic_first_use(world: ResearchWorld) -> None:
    """RA-U21: citations follow first use in claim order, never set order."""
    harness = make_harness(world, chunks=[world.chunk_a, world.chunk_b])
    harness.llm.set_default(
        _decision(
            _claim(
                "First claim.",
                world.chunk_b.citation_id,
                world.chunk_a.citation_id,
            ),
            _claim("Second claim.", world.chunk_a.citation_id),
        )
    )

    result = await harness.agent.research(world.request())

    assert [citation.citation_id for citation in result.citations] == [
        world.chunk_b.citation_id,
        world.chunk_a.citation_id,
    ]


@pytest.mark.asyncio
async def test_contradictory_claims_are_represented_not_resolved(
    world: ResearchWorld,
) -> None:
    """RA-U24: conflicting sides persist as separately cited claims."""
    harness = make_harness(world, chunks=[world.chunk_a, world.chunk_b])
    harness.llm.set_default(
        _decision(
            _claim("A supports statement X.", world.chunk_a.citation_id),
            _claim("B contradicts statement X.", world.chunk_b.citation_id),
        )
    )

    result = await harness.agent.research(world.request())

    assert [claim.citation_ids for claim in result.claims] == [
        (world.chunk_a.citation_id,),
        (world.chunk_b.citation_id,),
    ]
    assert [citation.citation_id for citation in result.citations] == [
        world.chunk_a.citation_id,
        world.chunk_b.citation_id,
    ]
    assert "verdict" not in ResearchResult.model_fields
    assert "confidence" not in ResearchResult.model_fields


# ---------------------------------------------------------------------------
# Deterministic empty/irrelevant outcomes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_retrieved_context_short_circuits_without_llm(
    world: ResearchWorld,
) -> None:
    """RA-U22: empty retrieval persists a zero-claim result with zero calls."""
    harness = make_harness(world, chunks=[])

    result = await harness.agent.research(world.request())

    assert result.claims == ()
    assert result.citations == ()
    assert result.investigation_id == world.investigation_id
    assert harness.llm.calls == []
    assert harness.accounting_repo.budget_writes == []
    assert harness.store.stored[result.id] is result
    assert harness.persistence_uow.commits == 1


@pytest.mark.asyncio
async def test_irrelevant_context_persists_empty_without_snapshots(
    world: ResearchWorld,
) -> None:
    """RA-U23: retrieved-but-irrelevant context yields claims=() persisted."""
    harness = make_harness(world, chunks=[world.chunk_a, world.chunk_b])
    harness.llm.set_default(_decision())

    result = await harness.agent.research(world.request())

    assert result.claims == ()
    assert result.citations == ()
    assert len(harness.llm.calls) == 1
    assert [
        write.llm_calls_used for write in harness.accounting_repo.budget_writes
    ] == [1]
    assert harness.store.stored[result.id] is result


@pytest.mark.asyncio
async def test_empty_context_result_passes_persistence_reference_validation(
    world: ResearchWorld,
) -> None:
    """Step 3.4: even the no-context path validates real persistence references."""
    from agentic_threat_investigator.app.persistence.repositories import (
        ResearchResultReferenceError,
    )

    harness = make_harness(
        world,
        chunks=[],
        visible_investigations={uuid4()},
        visible_entities={uuid4()},
    )

    with pytest.raises(ResearchResultReferenceError):
        await harness.agent.research(world.request())

    assert harness.store.stored == {}


# ---------------------------------------------------------------------------
# Bounded structured-output execution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retryable_invalid_output_triggers_one_repair_attempt(
    world: ResearchWorld,
) -> None:
    """RA-U25/U27: repair is attempted once and exhaustion fails closed."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.enqueue(
        LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True)
    )
    harness.llm.enqueue(
        LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True)
    )

    with pytest.raises(LlmError):
        await harness.agent.research(world.request())

    assert len(harness.llm.calls) == 2
    assert harness.store.stored == {}
    assert [
        write.llm_calls_used for write in harness.accounting_repo.budget_writes
    ] == [
        1,
        2,
    ]


@pytest.mark.asyncio
async def test_repair_succeeds_with_two_calls_and_chained_accounting(
    world: ResearchWorld,
) -> None:
    """RA-U26: a second attempt after repair persists exactly one result."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.enqueue(
        LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True)
    )
    harness.llm.set_default(
        _decision(_claim("Repaired statement.", world.chunk_a.citation_id))
    )

    result = await harness.agent.research(world.request())

    assert len(harness.llm.calls) == 2
    assert harness.store.stored[result.id] is result
    assert len(harness.store.stored) == 1
    assert [
        write.llm_calls_used for write in harness.accounting_repo.budget_writes
    ] == [
        1,
        2,
    ]
    assert harness.accounting_repo.state.budget.llm_calls_used == 2
    assert "failed structured-schema validation" in harness.llm.calls[1].user_prompt


@pytest.mark.asyncio
async def test_non_retryable_invalid_output_is_not_retried(
    world: ResearchWorld,
) -> None:
    """RA-U28: non-retryable invalid output fails after one attempt."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.enqueue(
        LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False)
    )

    with pytest.raises(LlmError) as holder:
        await harness.agent.research(world.request())

    assert holder.value.code is LlmErrorCode.INVALID_STRUCTURED_OUTPUT
    assert len(harness.llm.calls) == 1
    assert harness.store.stored == {}


@pytest.mark.asyncio
async def test_timeout_is_not_retried(world: ResearchWorld) -> None:
    """RA-U29: a mapped timeout fails with no retry and no persistence."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.enqueue(LlmError(LlmErrorCode.TIMEOUT))

    with pytest.raises(LlmError) as holder:
        await harness.agent.research(world.request())

    assert holder.value.code is LlmErrorCode.TIMEOUT
    assert len(harness.llm.calls) == 1
    assert harness.store.stored == {}


@pytest.mark.asyncio
async def test_configuration_error_is_not_retried(world: ResearchWorld) -> None:
    """RA-U30: a configuration error fails with no retry."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.enqueue(LlmError(LlmErrorCode.CONFIGURATION_ERROR))

    with pytest.raises(LlmError):
        await harness.agent.research(world.request())

    assert len(harness.llm.calls) == 1
    assert harness.store.stored == {}


@pytest.mark.asyncio
async def test_provider_failure_is_not_retried(world: ResearchWorld) -> None:
    """RA-U31: a non-retryable provider failure fails with no retry."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE))

    with pytest.raises(LlmError):
        await harness.agent.research(world.request())

    assert len(harness.llm.calls) == 1
    assert harness.store.stored == {}


@pytest.mark.asyncio
async def test_cancellation_propagates_and_counts_attempt(
    world: ResearchWorld,
) -> None:
    """RA-U32: asyncio.CancelledError propagates unchanged; the call stays reserved."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.enqueue(asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        await harness.agent.research(world.request())

    assert len(harness.accounting_repo.budget_writes) == 1
    assert harness.accounting_repo.budget_writes[0].llm_calls_used == 1
    assert harness.store.stored == {}


# ---------------------------------------------------------------------------
# Safe failure semantics
# ---------------------------------------------------------------------------


def test_constructor_rejects_attempt_counts_outside_one_to_two(
    world: ResearchWorld,
) -> None:
    """RA-U33: attempt counts are hard-limited to 1..2 even without Settings."""
    for invalid in (0, 3, -1):
        with pytest.raises(ValueError, match="1..2"):
            ResearchAgent(
                retriever=FakeResearchRetriever(),
                llm_client=FakeLlmClient(),
                result_persistence=ResearchResultPersistenceService(
                    lambda: _PersistenceUow(
                        _ResearchResults(),
                        {world.investigation_id},
                        {world.subject_entity_id},
                    )
                ),
                llm_accounting=LlmAccountingService(
                    lambda: _AccountingUow(world.investigation)
                ),
                max_structured_output_attempts=invalid,
            )


@pytest.mark.asyncio
async def test_persistence_failure_propagates_without_false_success(
    world: ResearchWorld,
) -> None:
    """RA-U34: a persistence failure raises and never returns the in-memory result."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.set_default(
        _decision(_claim("Statement X.", world.chunk_a.citation_id))
    )
    harness.store.fail = RuntimeError("disk full")

    with pytest.raises(RuntimeError, match="disk full"):
        await harness.agent.research(world.request())

    assert harness.store.stored == {}


@pytest.mark.asyncio
async def test_retrieval_failure_stops_before_llm_and_persistence(
    world: ResearchWorld,
) -> None:
    """RA-U35: a typed retrieval failure reaches the caller untouched."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.retriever.fail = ResearchRetrievalError("query failed")

    with pytest.raises(ResearchRetrievalError):
        await harness.agent.research(world.request())

    assert harness.llm.calls == []
    assert harness.accounting_repo.budget_writes == []
    assert harness.store.stored == {}


class _PromptConstructionError(RuntimeError):
    """A fixed generic local prompt-construction failure for accounting tests."""


@pytest.mark.asyncio
async def test_prompt_build_failure_consumes_no_budget(
    world: ResearchWorld,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RA-U36: a prompt-construction failure reserves nothing and calls nothing."""
    harness = make_harness(world, chunks=[world.chunk_a])
    prompt_calls: list[bool] = []

    def failing_prompts(
        request: object, chunks: object, *, repair: bool = False
    ) -> tuple[str, str]:
        """Record the call and raise a fixed local exception."""
        del request, chunks, repair
        prompt_calls.append(True)
        raise _PromptConstructionError("local prompt rendering failed")

    monkeypatch.setattr(
        "agentic_threat_investigator.app.research_agent.agent."
        "build_research_agent_prompts",
        failing_prompts,
    )

    with pytest.raises(_PromptConstructionError):
        await harness.agent.research(world.request())

    assert len(prompt_calls) == 1
    assert harness.llm.calls == []
    assert harness.accounting_repo.budget_writes == []
    assert harness.store.stored == {}


@pytest.mark.asyncio
async def test_duplicate_retrieved_citation_identities_fail_closed(
    world: ResearchWorld,
) -> None:
    """RA-U37: duplicate citation IDs in one response are an invariant violation."""
    duplicate = world.chunk_b.model_copy(
        update={"chunk_id": uuid4(), "citation_id": world.chunk_a.citation_id}
    )
    harness = make_harness(world, chunks=[world.chunk_a, duplicate])

    with pytest.raises(ResearchRetrievalError):
        await harness.agent.research(world.request())

    assert harness.llm.calls == []
    assert harness.accounting_repo.budget_writes == []
    assert harness.store.stored == {}


@pytest.mark.asyncio
async def test_budget_exhaustion_blocks_the_model_call(world: ResearchWorld) -> None:
    """RA-U45: an exhausted LLM budget fails before any model invocation."""
    world.investigation.budget = world.investigation.budget.model_copy(
        update={"llm_calls_used": world.investigation.budget.max_llm_calls}
    )
    harness = make_harness(world, chunks=[world.chunk_a])

    with pytest.raises(InvestigationBudgetExhaustedError):
        await harness.agent.research(world.request())

    assert harness.llm.calls == []
    assert harness.store.stored == {}


# ---------------------------------------------------------------------------
# Idempotency / append-only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_repeat_executions_are_append_only(world: ResearchWorld) -> None:
    """Two identical executions produce two immutable results."""
    harness = make_harness(world, chunks=[world.chunk_a])
    harness.llm.set_default(
        _decision(_claim("Statement X.", world.chunk_a.citation_id))
    )

    first = await harness.agent.research(world.request())
    second = await harness.agent.research(world.request())

    assert first.id != second.id
    assert harness.store.stored[first.id] is first
    assert harness.store.stored[second.id] is second
    assert first.claims[0].id != second.claims[0].id
    assert {citation.citation_id for citation in second.citations} == {
        world.chunk_a.citation_id
    }
