# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL + FakeLlmClient vertical slice for PR 20B.

Exercises the full application path against the isolated migrated database:
seed Investigation/Evidence/Relationship graph, assemble analyst input from
persisted rows only, run the scripted FakeLlmClient, validate/persist through
the PR 20A seam, advance the Investigation pointer, and verify accounting.
No real external model is required.

The graph/decision fixtures deliberately mirror the unit-suite shapes; the
duplication is test-only and accepted.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Self
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.assessment_provenance import (
    AssessmentEvidenceReferenceError,
    AssessmentInvestigationMismatchError,
    AssessmentProvenanceMismatchError,
    AssessmentRelationshipObservationReferenceError,
)
from agentic_threat_investigator.app.evidence_analyst import (
    EvidenceAnalyst,
    EvidenceAnalystInputLoader,
    LlmAccountingService,
)
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode, ResponseT
from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    RelationshipSupport,
    Verdict,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.llm_fixtures import FakeLlmClient

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class Graph:
    """One seeded investigation/evidence/relationship/observation graph."""

    def __init__(self, subject: str | None = None) -> None:
        self.subject = subject or f"example-{uuid4().hex[:10]}.com"
        self.investigation_id = uuid4()
        self.source_entity_id = uuid4()
        self.target_value = (
            f"192.0.{int(uuid4().hex[:4], 16) % 255}.{int(uuid4().hex[4:8], 16) % 255}"
        )
        self.target_entity_id = uuid4()
        self.evidence_id = uuid4()
        self.relationship_id = uuid4()
        self.observation_id = uuid4()

    async def seed(
        self, uow: PostgresUnitOfWork, *, with_observation: bool = True
    ) -> None:
        """Persist the investigation, entities, evidence, and optional edge."""
        state = InvestigationState(
            investigation_id=self.investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[self.source_entity_id],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
        )
        await uow.investigations.create(state)
        source = Entity(
            id=self.source_entity_id, type=EntityType.DOMAIN, value=self.subject
        )
        target = Entity(
            id=self.target_entity_id,
            type=EntityType.IP_ADDRESS,
            value=self.target_value,
        )
        await uow.entities.upsert(source)
        await uow.entities.upsert(target)
        evidence = Evidence(
            id=self.evidence_id,
            investigation_id=self.investigation_id,
            type=EvidenceType.DNS,
            subject=EntityRef(
                id=self.source_entity_id,
                type=EntityType.DOMAIN,
                value=self.subject,
            ),
            source="urn:ati:source:google_public_dns",
            retrieved_at=_RETRIEVED_AT,
            facts={"a_records": [self.target_value]},
            raw_payload={"http_headers": {"x-test-secret": "never-show"}},
        )
        await uow.evidence.insert(evidence)
        relationship = await uow.relationships.upsert(
            Relationship(
                id=self.relationship_id,
                source_entity_id=self.source_entity_id,
                target_entity_id=self.target_entity_id,
                type=RelationshipType.RESOLVES_TO,
            )
        )
        self.relationship_id = relationship.id or self.relationship_id
        if with_observation:
            observation = RelationshipObservation(
                id=self.observation_id,
                relationship_id=self.relationship_id,
                evidence_id=self.evidence_id,
                investigation_id=self.investigation_id,
                retrieved_at=_RETRIEVED_AT,
                source="urn:ati:source:google_public_dns",
                confidence=0.8,
            )
            await uow.relationship_observations.append(observation)

    def decision(
        self,
        *,
        evidence_support: bool = False,
        graph_support: bool = False,
        verdict: Verdict = Verdict.SUSPICIOUS,
        disposition: FindingDisposition = FindingDisposition.SUPPORTING,
        evidence_id: UUID | None = None,
        observation_id: UUID | None = None,
    ) -> EvidenceAnalystDecision:
        """Build a deterministic decision citing this graph when requested."""
        support: list[EvidenceSupport | RelationshipSupport] = []
        if evidence_support:
            support.append(
                EvidenceSupport(
                    kind="evidence", evidence_id=evidence_id or self.evidence_id
                )
            )
        if graph_support:
            support.append(
                RelationshipSupport(
                    kind="relationship_observation",
                    relationship_observation_id=observation_id or self.observation_id,
                )
            )
        return EvidenceAnalystDecision(
            verdict=verdict,
            confidence=AssessmentConfidence.MEDIUM,
            summary="Evidence supports the verdict.",
            findings=(
                (
                    AnalyticalFinding(
                        category=FindingCategory.NETWORK,
                        disposition=disposition,
                        statement="The domain resolves to the address.",
                        confidence=AssessmentConfidence.MEDIUM,
                        support=tuple(support),
                    ),
                )
                if support
                else ()
            ),
        )


class TransactionTracker:
    """Count active real UnitOfWork transactions with a chronological log.

    Every composed analyst UnitOfWork (loader, accounting, persistence)
    reports enter/exit through this tracker, and the fake LLM appends an
    ``llm`` marker, so tests can prove no transaction is ever open while the
    model boundary runs and that the phases are strictly ordered.
    """

    def __init__(self) -> None:
        """Initialize the counter and event log."""
        self.active = 0
        self.events: list[str] = []

    def enter(self, label: str) -> None:
        """Record one UnitOfWork entering the transaction."""
        self.active += 1
        self.events.append(f"enter:{label}")

    def exit(self, label: str) -> None:
        """Record one UnitOfWork leaving the transaction."""
        self.active -= 1
        self.events.append(f"exit:{label}")


class TrackingUnitOfWork(PostgresUnitOfWork):
    """A real PostgresUnitOfWork that reports its lifecycle to a tracker."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        tracker: TransactionTracker,
        *,
        label: str = "uow",
        batch_size: int = 100,
    ) -> None:
        """Bind the tracker and label while delegating to the base boundary."""
        super().__init__(session_factory, batch_size=batch_size)
        self._tracker = tracker
        self._label = label

    async def __aenter__(self) -> Self:
        """Enter the real transaction, then report the entry."""
        await super().__aenter__()
        self._tracker.enter(self._label)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the real transaction and always report the exit."""
        try:
            await super().__aexit__(exc_type, exc, traceback)
        finally:
            self._tracker.exit(self._label)


class TransactionGuardFakeLlmClient(FakeLlmClient):
    """Fake LLM that asserts the shared transaction counter is zero.

    The tracker accumulates every real UnitOfWork the composed analyst
    stack enters, so ``active == 0`` here proves no actual transaction is
    open across the model boundary.
    """

    def __init__(self, tracker: TransactionTracker) -> None:
        """Bind the shared transaction tracker."""
        super().__init__()
        self._tracker = tracker

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Assert transaction quiescence, mark the LLM moment, and delegate."""
        assert self._tracker.active == 0, (
            "a UnitOfWork remained open during the LLM call "
            f"(active transactions: {self._tracker.active})"
        )
        self._tracker.events.append("llm")
        return await super().generate_structured(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            operation_name=operation_name,
        )


async def assessment_rows(uow: PostgresUnitOfWork, investigation_id: UUID) -> int:
    """Count durable Assessment rows for one Investigation."""
    assert uow.session is not None
    result = await uow.session.execute(
        text("SELECT count(*) FROM ati.assessment WHERE investigation_id = :id"),
        {"id": investigation_id},
    )
    return int(result.scalar_one())


class _FailingInsertUnitOfWork(TrackingUnitOfWork):
    """Persistence UnitOfWork whose Assessment insert always fails."""

    async def __aenter__(self) -> Self:
        """Enter normally, then swap the insert for an injected failure."""
        await super().__aenter__()

        async def failing_insert(assessment: Assessment, **_: object) -> Assessment:
            del assessment
            raise RuntimeError("injected persistence failure")

        self.assessments.insert = failing_insert  # type: ignore[method-assign]
        return self


def analyst_for(
    session_factory: async_sessionmaker[AsyncSession],
    llm: FakeLlmClient,
    *,
    tracker: TransactionTracker | None = None,
    failing_persistence: bool = False,
) -> EvidenceAnalyst:
    """Compose the full analyst stack over the real PostgreSQL boundary.

    When ``tracker`` is provided every UnitOfWork the stack enters (loader,
    LLM accounting, Assessment persistence) reports through it, so the real
    transaction lifecycle is observable.
    """

    def uow_factory() -> PostgresUnitOfWork:
        if tracker is None:
            return PostgresUnitOfWork(session_factory)
        return TrackingUnitOfWork(session_factory, tracker, label="loader")

    def accounting_uow_factory() -> PostgresUnitOfWork:
        if tracker is None:
            return PostgresUnitOfWork(session_factory)
        return TrackingUnitOfWork(session_factory, tracker, label="accounting")

    def persistence_uow_factory() -> PostgresUnitOfWork:
        if tracker is None:
            if failing_persistence:
                return _FailingInsertUnitOfWork(
                    session_factory, TransactionTracker(), label="persistence"
                )
            return PostgresUnitOfWork(session_factory)
        if failing_persistence:
            return _FailingInsertUnitOfWork(
                session_factory, tracker, label="persistence"
            )
        return TrackingUnitOfWork(session_factory, tracker, label="persistence")

    return EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(uow_factory),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            persistence_uow_factory, batch_size=100
        ),
        llm_accounting=LlmAccountingService(accounting_uow_factory),
        max_structured_output_attempts=2,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_only_pipeline(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A direct Evidence finding persists an Assessment and moves the pointer."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=False)
    llm = FakeLlmClient()
    llm.set_default(graph.decision(evidence_support=True))

    analyst = analyst_for(session_factory, llm)
    persisted = await analyst.analyze(graph.investigation_id)

    assert persisted.investigation_id == graph.investigation_id
    assert persisted.analyzed_evidence_ids == (graph.evidence_id,)
    assert [
        s.evidence_id
        for s in persisted.findings[0].support
        if isinstance(s, EvidenceSupport)
    ] == [graph.evidence_id]
    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None and state.assessment_id == persisted.id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_graph_backed_pipeline(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A RelationshipObservation finding validates through the exact chain."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=True)
    llm = FakeLlmClient()
    llm.set_default(graph.decision(graph_support=True))

    persisted = await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    [finding] = persisted.findings
    support = finding.support[0]
    assert isinstance(support, RelationshipSupport)
    assert support.relationship_observation_id == graph.observation_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_mixed_support_pipeline(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Direct and graph support coexist in one persisted Finding."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=True)
    llm = FakeLlmClient()
    llm.set_default(graph.decision(evidence_support=True, graph_support=True))

    persisted = await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    kinds = {type(support).__name__ for support in persisted.findings[0].support}
    assert kinds == {"EvidenceSupport", "RelationshipSupport"}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_contradicting_finding_persists(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A explicitly contradicting Finding survives validation and persistence."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=False)
    llm = FakeLlmClient()
    llm.set_default(
        graph.decision(
            evidence_support=True,
            disposition=FindingDisposition.CONTRADICTING,
        )
    )

    persisted = await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    assert persisted.findings[0].disposition is FindingDisposition.CONTRADICTING


@pytest.mark.asyncio
@pytest.mark.integration
async def test_invalid_evidence_citation_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """An invented Evidence citation produces no Assessment and no pointer."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=False)
    llm = FakeLlmClient()
    llm.set_default(graph.decision(evidence_support=True, evidence_id=uuid4()))

    with pytest.raises(AssessmentEvidenceReferenceError):
        await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 0
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None and state.assessment_id is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_cross_investigation_evidence_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A Finding citing another Investigation's Evidence is rejected."""
    async with uow_factory() as uow:
        graph = Graph()
        other = Graph(subject=f"other-{uuid4().hex[:8]}.com")
        await graph.seed(uow, with_observation=False)
        await other.seed(uow, with_observation=False)
    llm = FakeLlmClient()
    llm.set_default(
        graph.decision(evidence_support=True, evidence_id=other.evidence_id)
    )

    with pytest.raises(AssessmentInvestigationMismatchError):
        await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_substitute_observation_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Another observation of the same Relationship cannot substitute."""
    async with uow_factory() as uow:
        graph = Graph()
        other = Graph(subject=f"other-{uuid4().hex[:8]}.com")
        await graph.seed(uow, with_observation=True)
        await other.seed(uow, with_observation=True)
        # The substitution target: the OTHER investigation's observation of
        # an identical relationship type and value shape.
    llm = FakeLlmClient()
    llm.set_default(
        graph.decision(graph_support=True, observation_id=other.observation_id)
    )

    with pytest.raises(AssessmentInvestigationMismatchError):
        await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_deleted_relationship_rejects_graph_citation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A soft-deleted Relationship makes its observation ineligible."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=True)
        await uow.relationships.soft_delete(graph.relationship_id)
    llm = FakeLlmClient()
    llm.set_default(graph.decision(graph_support=True))

    with pytest.raises(AssessmentProvenanceMismatchError):
        await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_no_evidence_inconclusive_short_circuit(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """No evidence persists a deterministic INCONCLUSIVE with no model call."""
    async with uow_factory() as uow:
        investigation_id = uuid4()
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[uuid4()],
                objective="Assess the root indicator.",
                budget=default_investigation_budget(),
                started_at=_RETRIEVED_AT,
            )
        )
    llm = FakeLlmClient()

    persisted = await analyst_for(session_factory, llm).analyze(investigation_id)

    assert persisted.verdict is Verdict.INCONCLUSIVE
    assert persisted.findings == ()
    assert llm.calls == []
    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(investigation_id)
        assert state is not None
        assert state.budget.llm_calls_used == 0
        assert state.assessment_id == persisted.id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_structured_output_failure_leaves_nothing(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Exhausted structured-output attempts persist no Assessment."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=False)
    llm = FakeLlmClient()
    llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))

    with pytest.raises(LlmError):
        await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 0
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None
        assert state.assessment_id is None
        assert state.budget.llm_calls_used == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_persistence_failure_moves_no_pointer(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A persistence failure prevents the pointer update entirely."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=False)
    llm = FakeLlmClient()
    llm.set_default(graph.decision(evidence_support=True))

    with pytest.raises(RuntimeError, match="injected persistence failure"):
        await analyst_for(session_factory, llm, failing_persistence=True).analyze(
            graph.investigation_id
        )

    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 0
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None and state.assessment_id is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_later_analysis_appends_version_and_keeps_old(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A later analysis creates a new Assessment; the old one is unchanged."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=True)
    first_llm = FakeLlmClient()
    first_llm.set_default(
        graph.decision(evidence_support=True, verdict=Verdict.SUSPICIOUS)
    )
    second_llm = FakeLlmClient()
    second_llm.set_default(
        graph.decision(graph_support=True, verdict=Verdict.MALICIOUS)
    )

    first = await analyst_for(session_factory, first_llm).analyze(
        graph.investigation_id
    )
    second = await analyst_for(session_factory, second_llm).analyze(
        graph.investigation_id
    )

    assert first.id != second.id
    assert first.verdict is Verdict.SUSPICIOUS
    assert second.verdict is Verdict.MALICIOUS
    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 2
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None and state.assessment_id == second.id
        assert first.id is not None
        old = await uow.assessments.get_by_id(first.id)
        assert old is not None and old.verdict is Verdict.SUSPICIOUS


@pytest.mark.asyncio
@pytest.mark.integration
async def test_llm_call_happens_outside_any_database_transaction(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Every actual analyst UnitOfWork is closed before the model runs.

    The shared tracker instruments the real UnitOfWork instances composed
    into the analyst stack (loader, accounting, persistence); the fake LLM
    asserts the active counter is exactly zero and marks the LLM moment, so
    the phase ordering below is authoritative evidence.
    """
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=False)
    tracker = TransactionTracker()
    llm = TransactionGuardFakeLlmClient(tracker)
    llm.set_default(graph.decision(evidence_support=True))

    await analyst_for(session_factory, llm, tracker=tracker).analyze(
        graph.investigation_id
    )

    events = tracker.events
    # The read loader UnitOfWork exits before accounting even starts.
    assert events.index("enter:loader") < events.index("exit:loader")
    assert events.index("exit:loader") < events.index("enter:accounting")
    # The reservation UnitOfWork exits before the model call happens.
    assert events.index("exit:accounting") < events.index("llm")
    # Assessment persistence starts only after a typed decision exists.
    assert events.index("llm") < events.index("enter:persistence")
    assert events.index("enter:persistence") < events.index("exit:persistence")
    # No transaction was ever concurrently open during the model boundary.
    assert tracker.active == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unknown_relationship_observation_citation_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A random RelationshipObservation UUID is rejected with no pointer."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=True)
    llm = FakeLlmClient()
    llm.set_default(graph.decision(graph_support=True, observation_id=uuid4()))

    with pytest.raises(AssessmentRelationshipObservationReferenceError):
        await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 0
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None
        assert state.assessment_id is None
        # The single model invocation was durably counted.
        assert state.budget.llm_calls_used == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_cross_investigation_observation_citation_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """An observation owned by another Investigation is rejected."""
    async with uow_factory() as uow:
        graph = Graph()
        other = Graph(subject=f"other-{uuid4().hex[:8]}.com")
        await graph.seed(uow, with_observation=True)
        await other.seed(uow, with_observation=True)
    llm = FakeLlmClient()
    llm.set_default(
        graph.decision(graph_support=True, observation_id=other.observation_id)
    )

    with pytest.raises(AssessmentInvestigationMismatchError):
        await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 0
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None
        assert state.assessment_id is None
        assert state.budget.llm_calls_used == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_deleted_endpoint_entity_rejects_graph_citation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A soft-deleted endpoint Entity makes the citation fail closed.

    The loader omits the observation whose endpoint Entity was soft-deleted;
    a model citation to that observation is still rejected by the PR 20A
    validator with no Assessment and no pointer update.
    """
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=True)
        await uow.entities.soft_delete(graph.target_entity_id)
    llm = FakeLlmClient()
    llm.set_default(graph.decision(graph_support=True))

    with pytest.raises(AssessmentProvenanceMismatchError):
        await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        assert await assessment_rows(uow, graph.investigation_id) == 0
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None
        assert state.assessment_id is None
        assert state.budget.llm_calls_used == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_failed_later_analysis_keeps_prior_assessment_unchanged(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A failed later analysis leaves the prior Assessment and pointer intact."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=True)
    first_llm = FakeLlmClient()
    first_llm.set_default(
        graph.decision(evidence_support=True, verdict=Verdict.SUSPICIOUS)
    )
    first = await analyst_for(session_factory, first_llm).analyze(
        graph.investigation_id
    )
    assert first.id is not None

    failing_llm = FakeLlmClient()
    failing_llm.set_default(graph.decision(graph_support=True, observation_id=uuid4()))
    with pytest.raises(AssessmentRelationshipObservationReferenceError):
        await analyst_for(session_factory, failing_llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        # The prior Assessment remains the only durable row, unchanged.
        assert await assessment_rows(uow, graph.investigation_id) == 1
        old = await uow.assessments.get_by_id(first.id)
        assert old is not None
        assert old.verdict is Verdict.SUSPICIOUS
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None
        assert state.assessment_id == first.id
        # The failed attempt was counted, the earlier success also counted.
        assert state.budget.llm_calls_used == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_input_loader_excludes_raw_payload(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Evidence raw_payload never reaches the model prompts."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=False)
    llm = FakeLlmClient()
    llm.set_default(graph.decision(evidence_support=True))

    await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    joined = "\n".join(call.user_prompt + call.system_prompt for call in llm.calls)
    assert "never-show" not in joined
    assert "raw_payload" not in joined
    assert graph.target_value in joined


@pytest.mark.asyncio
@pytest.mark.integration
async def test_llm_accounting_persists_across_attempts(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Actual invocations, including repairs, persist in the Investigation budget."""
    async with uow_factory() as uow:
        graph = Graph()
        await graph.seed(uow, with_observation=False)
        state_after_create = await uow.investigations.get_by_id(graph.investigation_id)
        assert state_after_create is not None and state_after_create.version is not None
        created = state_after_create.version
    llm = FakeLlmClient()
    llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    llm.enqueue(graph.decision(evidence_support=True))

    await analyst_for(session_factory, llm).analyze(graph.investigation_id)

    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None and state.budget.llm_calls_used == 2
        # create + two reservations + pointer update
        assert state.version == created + 3
