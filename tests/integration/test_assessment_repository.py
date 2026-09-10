# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL integration coverage for versioned Assessment persistence."""

# Fixture arguments intentionally reuse fixture names; the single-file
# coverage of the Assessment write path exceeds the default module length.
# The Graph fixture carries one terminal UUID per persisted identity, and
# the deterministic race tests deliberately capture broad exceptions and
# many locals to record outcomes while proving PostgreSQL lock state.
# pylint: disable=redefined-outer-name,too-many-lines,too-many-instance-attributes
# pylint: disable=too-many-locals,too-many-statements,broad-exception-caught

import asyncio
import time
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.assessment_provenance import (
    AssessmentEvidenceReferenceError,
    AssessmentInvestigationMismatchError,
    AssessmentProvenanceMismatchError,
    AssessmentRelationshipObservationReferenceError,
)
from agentic_threat_investigator.app.persistence.repositories import (
    AssessmentCurrentReferenceConflictError,
    InvestigationVersionConflictError,
    InvestigationWriteResult,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    FindingSupport,
    RelationshipSupport,
    Verdict,
)
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
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
from agentic_threat_investigator.infrastructure.persistence.postgresql import (
    assessment_repositories,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class Graph:  # pylint: disable=too-few-public-methods
    """A seeded evidence/relationship/observation graph for one investigation.

    The single public method seeds a complete, eligible provenance chain;
    the identity terminals are deliberately bound once per test.
    """

    def __init__(self, subject: str | None = None) -> None:
        self.subject = subject or f"example-{uuid4().hex[:10]}.com"
        self.investigation_id = uuid4()
        self.source_entity_id = uuid4()
        # The target IP must be unique per graph: entities deduplicate on
        # canonical value, so a shared value would reuse another graph's row.
        self.target_value = (
            f"192.0.{int(uuid4().hex[:4], 16) % 255}."
            f"{int(uuid4().hex[4:8], 16) % 255}"
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
        await uow.evidence.insert(
            Evidence(
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
            )
        )
        if with_observation:
            relationship = Relationship(
                id=self.relationship_id,
                source_entity_id=self.source_entity_id,
                target_entity_id=self.target_entity_id,
                type=RelationshipType.RESOLVES_TO,
            )
            persisted_relationship = await uow.relationships.upsert(relationship)
            await uow.relationship_observations.append(
                RelationshipObservation(
                    id=self.observation_id,
                    relationship_id=persisted_relationship.id,
                    evidence_id=self.evidence_id,
                    investigation_id=self.investigation_id,
                    retrieved_at=_RETRIEVED_AT,
                    source="urn:ati:source:google_public_dns",
                )
            )


def assessment_factory(
    graph: Graph,
    *,
    verdict: Verdict = Verdict.SUSPICIOUS,
    analyzed: tuple[UUID, ...] | None = None,
    findings: tuple[AnalyticalFinding, ...] | None = None,
) -> Assessment:
    """Build a candidate Assessment over the seeded graph."""
    return Assessment(
        investigation_id=graph.investigation_id,
        verdict=verdict,
        confidence=AssessmentConfidence.MEDIUM,
        summary="The evidence supports the verdict.",
        analyzed_evidence_ids=(graph.evidence_id,) if analyzed is None else analyzed,
        findings=(
            (
                AnalyticalFinding(
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="The domain resolves to the address.",
                    confidence=AssessmentConfidence.MEDIUM,
                    support=(
                        EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),
                    ),
                ),
            )
            if findings is None
            else findings
        ),
    )


def direct_finding(graph: Graph) -> AnalyticalFinding:
    """Build one direct Evidence-backed Finding."""
    return AnalyticalFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement="A reputation source flags the subject.",
        confidence=AssessmentConfidence.MEDIUM,
        support=(EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),),
    )


def graph_finding(graph: Graph) -> AnalyticalFinding:
    """Build one RelationshipObservation-backed Finding."""
    return AnalyticalFinding(
        category=FindingCategory.NETWORK,
        disposition=FindingDisposition.SUPPORTING,
        statement="The domain resolves to a suspicious address.",
        confidence=AssessmentConfidence.MEDIUM,
        support=(
            RelationshipSupport(
                kind="relationship_observation",
                relationship_observation_id=graph.observation_id,
            ),
        ),
    )


async def pointer_of(uow: PostgresUnitOfWork, investigation_id: UUID) -> UUID | None:
    """Read the investigation's current assessment pointer from state."""
    state = await uow.investigations.get_by_id(investigation_id)
    assert state is not None
    return state.assessment_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_persist_and_read_minimal_assessment_with_direct_support(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A direct-support Assessment round-trips with exact provenance."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)

    persisted = await service.persist_assessment(
        assessment_factory(graph), actor_id=uuid4(), request_id=uuid4()
    )

    assert persisted.id is not None
    async with uow_factory() as uow:
        loaded = await uow.assessments.get_by_id(persisted.id)
    assert loaded is not None
    assert loaded.id == persisted.id
    assert loaded.investigation_id == graph.investigation_id
    assert loaded.verdict is Verdict.SUSPICIOUS
    assert loaded.confidence is AssessmentConfidence.MEDIUM
    assert loaded.summary == "The evidence supports the verdict."
    assert loaded.analyzed_evidence_ids == (graph.evidence_id,)
    assert len(loaded.findings) == 1
    finding = loaded.findings[0]
    assert finding.category is FindingCategory.NETWORK
    assert finding.disposition is FindingDisposition.SUPPORTING
    assert finding.statement == "The domain resolves to the address."
    assert finding.support == (
        EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_support_round_trip(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A graph-backed Finding preserves its exact observation reference."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)

    persisted = await service.persist_assessment(
        assessment_factory(graph, findings=(graph_finding(graph),))
    )

    assert persisted.id is not None
    async with uow_factory() as uow:
        loaded = await uow.assessments.get_by_id(persisted.id)
    assert loaded is not None
    assert loaded.findings[0].support == (
        RelationshipSupport(
            kind="relationship_observation",
            relationship_observation_id=graph.observation_id,
        ),
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_with_zero_relationships_is_valid_direct_support(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Direct claims need no graph; Evidence with zero observations persists."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow, with_observation=False)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)

    persisted = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )

    assert persisted.id is not None
    async with uow_factory() as uow:
        loaded = await uow.assessments.get_by_id(persisted.id)
    assert loaded is not None
    assert loaded.findings[0].support == (
        EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_mixed_support_and_multiple_observations_round_trip(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Mixed Evidence + observation support and multiple observations persist."""
    graph = Graph()
    second_target_id = uuid4()
    async with uow_factory() as uow:
        await graph.seed(uow)
        await uow.entities.upsert(
            Entity(
                id=second_target_id,
                type=EntityType.IP_ADDRESS,
                value="198.51.100.7",
            )
        )
        second_relationship_id = uuid4()
        persisted_second = await uow.relationships.upsert(
            Relationship(
                id=second_relationship_id,
                source_entity_id=graph.source_entity_id,
                target_entity_id=second_target_id,
                type=RelationshipType.USES_NAME_SERVER,
            )
        )
        second_observation_id = uuid4()
        await uow.relationship_observations.append(
            RelationshipObservation(
                id=second_observation_id,
                relationship_id=persisted_second.id,
                evidence_id=graph.evidence_id,
                investigation_id=graph.investigation_id,
                retrieved_at=_RETRIEVED_AT,
                source="urn:ati:source:google_public_dns",
            )
        )
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    mixed = AnalyticalFinding(
        category=FindingCategory.NETWORK,
        disposition=FindingDisposition.SUPPORTING,
        statement="Direct and graph facts agree.",
        confidence=AssessmentConfidence.MEDIUM,
        support=(
            EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),
            RelationshipSupport(
                kind="relationship_observation",
                relationship_observation_id=graph.observation_id,
            ),
            RelationshipSupport(
                kind="relationship_observation",
                relationship_observation_id=second_observation_id,
            ),
        ),
    )
    persisted = await service.persist_assessment(
        assessment_factory(graph, findings=(mixed,))
    )
    assert persisted.id is not None
    async with uow_factory() as uow:
        loaded = await uow.assessments.get_by_id(persisted.id)
    assert loaded is not None
    assert loaded.findings[0].support == mixed.support


@pytest.mark.asyncio
@pytest.mark.integration
async def test_cross_investigation_evidence_is_rejected_and_rolls_back(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Cross-investigation support never persists."""
    graph = Graph()
    other_investigation_id = uuid4()
    other_investigation_state = InvestigationState(
        investigation_id=other_investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[],
        objective="Another investigation.",
        budget=default_investigation_budget(),
        started_at=_RETRIEVED_AT,
    )
    other_evidence_id = uuid4()
    other_entity_id = uuid4()
    async with uow_factory() as uow:
        await graph.seed(uow)
        await uow.investigations.create(other_investigation_state)
        await uow.entities.upsert(
            Entity(
                id=other_entity_id,
                type=EntityType.DOMAIN,
                value="elsewhere.example",
            )
        )
        await uow.evidence.insert(
            Evidence(
                id=other_evidence_id,
                investigation_id=other_investigation_id,
                type=EvidenceType.REPUTATION,
                subject=EntityRef(
                    id=other_entity_id,
                    type=EntityType.DOMAIN,
                    value="elsewhere.example",
                ),
                source="urn:ati:source:threatfox",
                retrieved_at=_RETRIEVED_AT,
            )
        )
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    candidate = Assessment(
        investigation_id=graph.investigation_id,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Cross investigation.",
        analyzed_evidence_ids=(other_evidence_id,),
        findings=(
            direct_finding(graph).model_copy(
                update={
                    "support": (
                        EvidenceSupport(kind="evidence", evidence_id=other_evidence_id),
                    )
                }
            ),
        ),
    )

    with pytest.raises(AssessmentInvestigationMismatchError):
        await service.persist_assessment(candidate)

    async with uow_factory() as uow:
        assert await pointer_of(uow, graph.investigation_id) is None
        listing = await uow.assessments.list_for_investigation(graph.investigation_id)
        assert listing == []


@pytest.mark.asyncio
@pytest.mark.integration
async def test_provenance_mismatch_support_is_rejected_by_database(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The stored function rejects a support the validator would skip."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    candidate = Assessment.model_construct(
        investigation_id=graph.investigation_id,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="mismatched",
        analyzed_evidence_ids=(graph.evidence_id,),
        findings=(
            AnalyticalFinding.model_construct(
                category=FindingCategory.NETWORK,
                disposition=FindingDisposition.SUPPORTING,
                statement="observing a wrong-edge observation.",
                confidence=AssessmentConfidence.MEDIUM,
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=uuid4(),
                    ),
                ),
            ),
        ),
    )
    async with uow_factory() as uow:
        with pytest.raises(AssessmentRelationshipObservationReferenceError):
            await uow.assessments.insert(candidate)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_duplicate_support_is_rejected_by_database(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The stored function rejects duplicate support inside one Finding."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    candidate = Assessment.model_construct(
        investigation_id=graph.investigation_id,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="dup",
        analyzed_evidence_ids=(graph.evidence_id,),
        findings=(
            AnalyticalFinding.model_construct(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="Duplicated citation.",
                confidence=AssessmentConfidence.MEDIUM,
                support=(
                    EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),
                    EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),
                ),
            ),
        ),
    )
    with pytest.raises(AssessmentProvenanceMismatchError):
        async with uow_factory() as insert_uow:
            await insert_uow.assessments.insert(candidate)
    async with uow_factory() as uow:
        # The failed insert rolled back; nothing durable remains.
        assert await pointer_of(uow, graph.investigation_id) is None
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_one_relationship_with_many_observations_round_trip(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Repeated observations of one stable edge persist and read back exactly."""
    graph = Graph()
    second_evidence_id = uuid4()
    second_observation_id = uuid4()
    async with uow_factory() as uow:
        await graph.seed(uow)
        # Resolve the DB-assigned relationship identity for the seeded edge.
        edge = await uow.relationships.get_by_identity(
            graph.source_entity_id,
            RelationshipType.RESOLVES_TO.value,
            graph.target_entity_id,
        )
        assert edge is not None
        # A second Evidence observes the same stable relationship.
        await uow.evidence.insert(
            Evidence(
                id=second_evidence_id,
                investigation_id=graph.investigation_id,
                type=EvidenceType.REPUTATION,
                subject=EntityRef(
                    id=graph.source_entity_id,
                    type=EntityType.DOMAIN,
                    value="example.com",
                ),
                source="urn:ati:source:urlhaus",
                retrieved_at=_RETRIEVED_AT,
            )
        )
        await uow.relationship_observations.append(
            RelationshipObservation(
                id=second_observation_id,
                relationship_id=edge.id,
                evidence_id=second_evidence_id,
                investigation_id=graph.investigation_id,
                retrieved_at=_RETRIEVED_AT,
                source="urn:ati:source:urlhaus",
            )
        )
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    second_observation_finding = AnalyticalFinding(
        category=FindingCategory.NETWORK,
        disposition=FindingDisposition.SUPPORTING,
        statement="A later observation repeats the same resolution.",
        confidence=AssessmentConfidence.MEDIUM,
        support=(
            RelationshipSupport(
                kind="relationship_observation",
                relationship_observation_id=second_observation_id,
            ),
        ),
    )
    persisted = await service.persist_assessment(
        assessment_factory(
            graph,
            analyzed=(graph.evidence_id, second_evidence_id),
            findings=(
                graph_finding(graph),
                second_observation_finding,
            ),
        )
    )
    assert persisted.id is not None
    async with uow_factory() as uow:
        loaded = await uow.assessments.get_by_id(persisted.id)
    assert loaded is not None
    assert len(loaded.findings) == 2
    assert loaded.findings[0].support == (
        RelationshipSupport(
            kind="relationship_observation",
            relationship_observation_id=graph.observation_id,
        ),
    )
    assert loaded.findings[1].support == (
        RelationshipSupport(
            kind="relationship_observation",
            relationship_observation_id=second_observation_id,
        ),
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_deleted_relationship_is_ineligible_support(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A soft-deleted Relationship cannot back a persisted Finding."""
    graph = Graph()
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    async with uow_factory() as uow:
        await graph.seed(uow)
        edge = await uow.relationships.get_by_identity(
            graph.source_entity_id,
            RelationshipType.RESOLVES_TO.value,
            graph.target_entity_id,
        )
        assert edge is not None
        await uow.relationships.soft_delete(edge.id)

    with pytest.raises(AssessmentProvenanceMismatchError):
        await service.persist_assessment(
            assessment_factory(graph, findings=(graph_finding(graph),))
        )
    async with uow_factory() as uow:
        assert await pointer_of(uow, graph.investigation_id) is None
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_second_version_does_not_mutate_first(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A later analysis creates a new version and leaves A1 untouched."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)

    first = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )
    second = await service.persist_assessment(
        assessment_factory(
            graph,
            verdict=Verdict.MALICIOUS,
            findings=(graph_finding(graph),),
        )
    )

    assert first.id != second.id
    assert first.id is not None and second.id is not None
    assert second.version is not None and first.version is not None
    assert second.version > first.version
    async with uow_factory() as uow:
        a1 = await uow.assessments.get_by_id(first.id)
        a2 = await uow.assessments.get_by_id(second.id)
        investigations = await uow.investigations.get_by_id(graph.investigation_id)
    assert a1 is not None and a2 is not None
    # A1 keeps its exact version, Findings, and support.
    assert a1.verdict is Verdict.SUSPICIOUS
    assert a1.findings[0].support == (
        EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),
    )
    assert a2.verdict is Verdict.MALICIOUS
    assert a2.findings[0].support == (
        RelationshipSupport(
            kind="relationship_observation",
            relationship_observation_id=graph.observation_id,
        ),
    )
    # The Investigation pointer advances to the latest durable output.
    assert investigations is not None
    assert investigations.assessment_id == second.id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_versioned_create_history_and_audit_are_written(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Each Assessment version writes immutable history plus its audit event."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    actor_id = uuid4()
    request_id = uuid4()

    first = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),)),
        actor_id=actor_id,
        request_id=request_id,
    )
    assert first.version is not None and first.version >= 1
    async with uow_factory() as uow:
        # domain_object_history carries the CREATE entry with correlation.
        assert uow.session is not None
        rows = (
            await uow.session.execute(
                text("""
                    SELECT version, operation, diff::text, actor_id, request_id
                    FROM ati.domain_object_history
                    WHERE object_type = 'assessment' AND object_id = :id
                """),
                {"id": first.id},
            )
        ).fetchall()
        assert [(row[0], row[1]) for row in rows] == [(first.version, "CREATE")]
        assert rows[0][2] == "{}"
        assert rows[0][3] == actor_id
        assert rows[0][4] == request_id
        # The audit event commits transactionally with the Assessment.
        events = await uow.audit_events.list_events(
            object_type="assessment",
            object_id=first.id,
            action=AuditAction.ASSESSMENT_CREATE.value,
        )
        assert len(events) == 1
        assert events[0].actor_id == actor_id
        assert events[0].request_id == request_id
        # The pointer update bumps the investigation version and writes history.
        state = await uow.investigations.get_by_id(graph.investigation_id)
        assert state is not None
        assert state.assessment_id == first.id
        assert state.version is not None and state.version > 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_pointer_changes_only_after_durable_success(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A failed later analysis leaves both the pointer and A1 unchanged."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)

    first = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )
    async with uow_factory() as uow:
        pointer_before = await pointer_of(uow, graph.investigation_id)
    assert pointer_before == first.id

    with pytest.raises(AssessmentProvenanceMismatchError):
        await service.persist_assessment(
            Assessment.model_construct(
                investigation_id=graph.investigation_id,
                verdict=Verdict.SUSPICIOUS,
                confidence=AssessmentConfidence.MEDIUM,
                summary="bad later analysis",
                analyzed_evidence_ids=(),
                findings=(direct_finding(graph),),
            )
        )
    async with uow_factory() as uow:
        assert await pointer_of(uow, graph.investigation_id) == first.id
        listing = await uow.assessments.list_for_investigation(graph.investigation_id)
        assert len(listing) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_stale_investigation_version_leaves_no_partial_assessment(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A stale expected version rolls back the whole second analysis."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)

    async with uow_factory() as baseline:
        base_state = await baseline.investigations.get_by_id(graph.investigation_id)
    assert base_state is not None
    assert base_state.version is not None
    first = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),)),
        expected_investigation_version=base_state.version,
    )
    with pytest.raises(InvestigationVersionConflictError):
        await service.persist_assessment(
            assessment_factory(graph, findings=(graph_finding(graph),)),
            expected_investigation_version=base_state.version,
        )
    async with uow_factory() as uow:
        assert await pointer_of(uow, graph.investigation_id) == first.id
        listing = await uow.assessments.list_for_investigation(graph.investigation_id)
        assert len(listing) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_soft_delete_semantics(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Deletion of the current Assessment is rejected; historical deletes work.

    Approved PR 20A deletion policy: a visible Investigation can never retain
    a pointer to a deleted/invisible Assessment. Deleting the pointed-at
    Assessment raises the typed current-reference conflict and mutates
    nothing; a superseded historical Assessment soft-deletes cleanly while
    preserving its exact Findings and supports.
    """
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    actor_id = uuid4()
    first = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )
    assert first.id is not None

    # Supersede the first Assessment so the pointer moves to the second.
    await service.persist_assessment(
        assessment_factory(
            graph,
            findings=(
                AnalyticalFinding(
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="Graph provenance supports the verdict.",
                    confidence=AssessmentConfidence.MEDIUM,
                    support=(
                        RelationshipSupport(
                            kind="relationship_observation",
                            relationship_observation_id=graph.observation_id,
                        ),
                    ),
                ),
            ),
        )
    )
    assert (
        await service.delete_assessment(
            first.id, actor_id=actor_id, expected_version=first.version
        )
        is not None
    )

    async with uow_factory() as uow:
        deleted = await uow.assessments.get_by_id(first.id, include_deleted=True)
        assert deleted is not None
        assert deleted.deleted_at is not None
        assert await uow.assessments.get_by_id(first.id) is None
        listing = await uow.assessments.list_for_investigation(graph.investigation_id)
        assert all(item.id != first.id for item in listing)
        # The pointer still references the visible current Assessment.
        assert await pointer_of(uow, graph.investigation_id) != first.id
        # Exact historical Finding/support retention.
        assert deleted.findings[0].support == (
            EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_deleting_current_assessment_is_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Deleting the pointed-at Assessment is a typed conflict with no mutation."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    persisted = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )
    assert persisted.id is not None

    with pytest.raises(AssessmentCurrentReferenceConflictError):
        await service.delete_assessment(
            persisted.id, actor_id=uuid4(), expected_version=persisted.version
        )

    async with uow_factory() as uow:
        visible = await uow.assessments.get_by_id(persisted.id)
        assert visible is not None
        assert visible.deleted_at is None
        assert await pointer_of(uow, graph.investigation_id) == persisted.id
        # The DELETE history row must not exist.
        assert uow.session is not None
        history = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.domain_object_history "
                    "WHERE object_type = 'assessment' AND object_id = :id "
                    "AND operation = 'DELETE'"
                ),
                {"id": persisted.id},
            )
        ).scalar_one()
        assert history == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_delete_assessment_emits_transactional_audit(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A committed deletion emits exactly one ASSESSMENT_DELETE audit event."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    first = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )
    await service.persist_assessment(
        assessment_factory(
            graph,
            findings=(
                AnalyticalFinding(
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="Graph provenance supports the verdict.",
                    confidence=AssessmentConfidence.MEDIUM,
                    support=(
                        RelationshipSupport(
                            kind="relationship_observation",
                            relationship_observation_id=graph.observation_id,
                        ),
                    ),
                ),
            ),
        )
    )
    assert first.id is not None
    request_id = uuid4()
    await service.delete_assessment(first.id, actor_id=uuid4(), request_id=request_id)

    async with uow_factory() as uow:
        assert uow.session is not None
        events = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.audit_event "
                    "WHERE action = :action AND object_id = :id "
                    "AND request_id = :request"
                ),
                {
                    "action": AuditAction.ASSESSMENT_DELETE.value,
                    "id": first.id,
                    "request": request_id,
                },
            )
        ).scalar_one()
        assert events == 1
        assert uow.session is not None
        history = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.domain_object_history "
                    "WHERE object_type = 'assessment' AND object_id = :id "
                    "AND operation = 'DELETE' AND request_id = :request"
                ),
                {"id": first.id, "request": request_id},
            )
        ).scalar_one()
        assert history == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_stale_version_delete_rolls_back_audit(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A stale expected version rolls back deletion and emits no audit event."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    first = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )
    await service.persist_assessment(
        assessment_factory(
            graph,
            findings=(
                AnalyticalFinding(
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="Graph provenance supports the verdict.",
                    confidence=AssessmentConfidence.MEDIUM,
                    support=(
                        RelationshipSupport(
                            kind="relationship_observation",
                            relationship_observation_id=graph.observation_id,
                        ),
                    ),
                ),
            ),
        )
    )
    assert first.id is not None
    with pytest.raises(ValueError, match="stale"):
        await service.delete_assessment(first.id, expected_version=1)

    async with uow_factory() as uow:
        assert uow.session is not None
        events = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.audit_event "
                    "WHERE action = :action AND object_id = :id"
                ),
                {"action": AuditAction.ASSESSMENT_DELETE.value, "id": first.id},
            )
        ).scalar_one()
        assert events == 0
        assert first.id is not None
        visible = await uow.assessments.get_by_id(first.id)
        assert visible is not None
        assert visible.deleted_at is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_analysis_keeps_exactly_one_winner(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """One concurrent writer succeeds; the stale writer rolls back entirely."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    version = 1
    async with uow_factory() as baseline:
        base_state = await baseline.investigations.get_by_id(graph.investigation_id)
    assert base_state is not None
    if base_state.version is not None:
        version = base_state.version
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    candidate_a = assessment_factory(graph, findings=(direct_finding(graph),))
    candidate_b = assessment_factory(graph, findings=(graph_finding(graph),))

    results = await asyncio.gather(
        service.persist_assessment(candidate_a, expected_investigation_version=version),
        service.persist_assessment(candidate_b, expected_investigation_version=version),
        return_exceptions=True,
    )
    ok = [item for item in results if not isinstance(item, Exception)]
    failed = [item for item in results if isinstance(item, Exception)]
    assert len(ok) == 1
    assert len(failed) == 1
    assert isinstance(failed[0], InvestigationVersionConflictError)

    async with uow_factory() as uow:
        listing = await uow.assessments.list_for_investigation(graph.investigation_id)
        investigation = await uow.investigations.get_by_id(graph.investigation_id)
    assert len(listing) == 1
    assert investigation is not None
    assert investigation.assessment_id == listing[0].id


def _finding_construct(
    graph: Graph,
    support: tuple[FindingSupport, ...] | None = None,
    *,
    statement: str = "Direct evidence supports the verdict.",
) -> AnalyticalFinding:
    """Build a Finding that bypasses domain validation for DB-boundary tests."""
    return AnalyticalFinding.model_construct(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement=statement,
        confidence=AssessmentConfidence.MEDIUM,
        support=(
            support
            if support is not None
            else (EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),)
        ),
    )


async def _insert_candidate(
    uow_factory: Callable[[], PostgresUnitOfWork], candidate: Assessment
) -> None:
    """Insert a bypassing candidate through the repository boundary."""
    async with uow_factory() as uow:
        await uow.assessments.insert(candidate)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_uncited_nonexistent_analyzed_evidence(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A nonexistent analyzed Evidence ID fails even when no Finding cites it."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    phantom = uuid4()
    candidate = _candidate_with_findings(
        graph,
        analyzed=(graph.evidence_id, phantom),
        findings=(direct_finding(graph),),
    )
    with pytest.raises(AssessmentEvidenceReferenceError):
        await _insert_candidate(uow_factory, candidate)
    async with uow_factory() as uow:
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_cross_investigation_uncited_analyzed_evidence(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A cross-Investigation analyzed Evidence ID fails even when uncited."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    foreign = await _foreign_evidence_id(uow_factory)
    candidate = _candidate_with_findings(
        graph,
        analyzed=(graph.evidence_id, foreign),
        findings=(direct_finding(graph),),
    )
    with pytest.raises(AssessmentInvestigationMismatchError):
        await _insert_candidate(uow_factory, candidate)
    async with uow_factory() as uow:
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_finding_without_support(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A Finding with no support is rejected by the database path."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    candidate = _candidate_with_findings(
        graph,
        analyzed=(graph.evidence_id,),
        findings=(_finding_construct(graph, support=()),),
    )
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _insert_candidate(uow_factory, candidate)
    async with uow_factory() as uow:
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_unknown_finding_ordinal_support(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A support citing an unknown finding ordinal is rejected, not dropped."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    candidate = _candidate_with_findings(
        graph, analyzed=(graph.evidence_id,), findings=(direct_finding(graph),)
    )
    # Corrupt the staged input directly: a support for finding ordinal 2.
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _call_append_assessment(
            uow_factory,
            candidate,
            findings=[(1, "network", "supporting", "s", "medium")],
            supports=[(2, 1, "evidence", graph.evidence_id, None)],
        )
    async with uow_factory() as uow:
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_duplicate_and_gapped_finding_ordinals(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Duplicate, nonpositive, and gapped Finding ordinals are rejected."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _call_append_assessment(
            uow_factory,
            assessment_factory(graph),
            findings=[
                (1, "network", "supporting", "first", "medium"),
                (1, "network", "supporting", "duplicate", "medium"),
            ],
            supports=[
                (1, 1, "evidence", graph.evidence_id, None),
                (1, 2, "evidence", graph.evidence_id, None),
            ],
        )
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _call_append_assessment(
            uow_factory,
            assessment_factory(graph),
            findings=[
                (1, "network", "supporting", "first", "medium"),
                (3, "network", "supporting", "gap", "medium"),
            ],
            supports=[
                (1, 1, "evidence", graph.evidence_id, None),
                (2, 3, "evidence", graph.evidence_id, None),
            ],
        )
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _call_append_assessment(
            uow_factory,
            assessment_factory(graph),
            findings=[(0, "network", "supporting", "zero", "medium")],
            supports=[(0, 0, "evidence", graph.evidence_id, None)],
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_duplicate_and_gapped_support_ordinals(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Duplicate, nonpositive, and gapped support ordinals are rejected."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    second_evidence = await _second_evidence_id(uow_factory, graph)
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _call_append_assessment(
            uow_factory,
            assessment_factory(graph, analyzed=(graph.evidence_id, second_evidence)),
            findings=[(1, "network", "supporting", "s", "medium")],
            supports=[
                (1, 1, "evidence", graph.evidence_id, None),
                (1, 1, "evidence", second_evidence, None),
            ],
        )
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _call_append_assessment(
            uow_factory,
            assessment_factory(graph, analyzed=(graph.evidence_id, second_evidence)),
            findings=[(1, "network", "supporting", "s", "medium")],
            supports=[
                (1, 1, "evidence", graph.evidence_id, None),
                (1, 3, "evidence", second_evidence, None),
            ],
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_invalid_support_kind_and_mismatch(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Invalid kinds and discriminator/ID mismatches surface as typed errors."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _call_append_assessment(
            uow_factory,
            assessment_factory(graph),
            findings=[(1, "network", "supporting", "s", "medium")],
            supports=[(1, 1, "relationship", graph.evidence_id, None)],
        )
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _call_append_assessment(
            uow_factory,
            assessment_factory(graph),
            findings=[(1, "network", "supporting", "s", "medium")],
            supports=[(1, 1, "evidence", None, graph.observation_id)],
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_deleted_endpoint_entities(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Deleted source or target entities make observation support ineligible."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
        await uow.entities.soft_delete(graph.source_entity_id, actor_id=uuid4())
    candidate = _candidate_with_findings(
        graph, analyzed=(graph.evidence_id,), findings=(graph_finding(graph),)
    )
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _insert_candidate(uow_factory, candidate)

    second = Graph()
    async with uow_factory() as uow:
        await second.seed(uow)
        await uow.entities.soft_delete(second.target_entity_id, actor_id=uuid4())
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _insert_candidate(
            uow_factory,
            _candidate_with_findings(
                second,
                analyzed=(second.evidence_id,),
                findings=(graph_finding(second),),
            ),
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_wrong_investigation_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An observation bound to another Investigation fails the DB path."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
        # Rebind the seeded observation to a different Investigation directly
        # (test-only raw SQL; the app never mutates observations).
        assert uow.session is not None
        await uow.session.execute(
            text("""
                UPDATE ati.relationship_observation
                SET investigation_id = :other
                WHERE id = :observation_id
            """),
            {"other": uuid4(), "observation_id": graph.observation_id},
        )
    candidate = _candidate_with_findings(
        graph, analyzed=(graph.evidence_id,), findings=(graph_finding(graph),)
    )
    with pytest.raises(AssessmentInvestigationMismatchError):
        await _insert_candidate(uow_factory, candidate)
    async with uow_factory() as uow:
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_substitute_observation_of_same_relationship(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Another observation of the same edge cannot substitute in the DB path."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
        edge = await uow.relationships.get_by_identity(
            graph.source_entity_id,
            RelationshipType.RESOLVES_TO.value,
            graph.target_entity_id,
        )
        assert edge is not None
        second_evidence_id = uuid4()
        second_observation_id = uuid4()
        await uow.evidence.insert(
            Evidence(
                id=second_evidence_id,
                investigation_id=graph.investigation_id,
                type=EvidenceType.REPUTATION,
                subject=EntityRef(
                    id=graph.source_entity_id,
                    type=EntityType.DOMAIN,
                    value="example.com",
                ),
                source="urn:ati:source:urlhaus",
                retrieved_at=_RETRIEVED_AT,
            )
        )
        await uow.relationship_observations.append(
            RelationshipObservation(
                id=second_observation_id,
                relationship_id=edge.id,
                evidence_id=second_evidence_id,
                investigation_id=graph.investigation_id,
                retrieved_at=_RETRIEVED_AT,
                source="urn:ati:source:urlhaus",
            )
        )
    # Citing the substitute observation while only the exact Evidence is
    # analyzed fails, because the observation's own Evidence must be analyzed.
    substitute = _candidate_with_findings(
        graph,
        analyzed=(graph.evidence_id,),
        findings=(
            _finding_construct(
                graph,
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=second_observation_id,
                    ),
                ),
            ),
        ),
    )
    with pytest.raises(AssessmentEvidenceReferenceError):
        await _insert_candidate(uow_factory, substitute)
    # The exact cited observation remains valid.
    await _insert_candidate(
        uow_factory,
        _candidate_with_findings(
            graph, analyzed=(graph.evidence_id,), findings=(graph_finding(graph),)
        ),
    )
    async with uow_factory() as uow:
        listing = await uow.assessments.list_for_investigation(graph.investigation_id)
        assert len(listing) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_empty_evidence_inconclusive_round_trips(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An empty-evidence, empty-Finding INCONCLUSIVE Assessment persists."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    candidate = Assessment(
        investigation_id=graph.investigation_id,
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="No provider produced material evidence.",
        analyzed_evidence_ids=(),
        findings=(),
    )

    persisted = await service.persist_assessment(candidate)

    assert persisted.id is not None
    async with uow_factory() as uow:
        loaded = await uow.assessments.get_by_id(persisted.id)
    assert loaded is not None
    assert loaded.verdict is Verdict.INCONCLUSIVE
    assert loaded.analyzed_evidence_ids == ()
    assert loaded.findings == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_rejects_non_inconclusive_empty_evidence(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """No-evidence SUSPICIOUS/BENIGN/MALICIOUS Assessments are rejected by the DB."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    for verdict in (
        Verdict.SUSPICIOUS,
        Verdict.BENIGN,
        Verdict.MALICIOUS,
    ):
        candidate = _candidate_with_findings(
            graph, analyzed=(), findings=(), verdict=verdict
        )
        with pytest.raises(AssessmentProvenanceMismatchError):
            await _call_append_assessment(
                uow_factory, candidate, findings=[], supports=[]
            )
    async with uow_factory() as uow:
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_ordered_collections_round_trip_exactly(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Findings, supports, and string collections round-trip in exact order."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    second_evidence = await _second_evidence_id(uow_factory, graph)
    first_finding = AnalyticalFinding(
        category=FindingCategory.NETWORK,
        disposition=FindingDisposition.SUPPORTING,
        statement="First finding with mixed support.",
        confidence=AssessmentConfidence.HIGH,
        support=(
            EvidenceSupport(kind="evidence", evidence_id=graph.evidence_id),
            RelationshipSupport(
                kind="relationship_observation",
                relationship_observation_id=graph.observation_id,
            ),
        ),
    )
    second_finding = AnalyticalFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.CONTRADICTING,
        statement="Second finding with direct support.",
        confidence=AssessmentConfidence.LOW,
        support=(EvidenceSupport(kind="evidence", evidence_id=second_evidence),),
    )
    candidate = Assessment(
        investigation_id=graph.investigation_id,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Ordered analytical output.",
        analyzed_evidence_ids=(graph.evidence_id, second_evidence),
        findings=(first_finding, second_finding),
        limitations=("first limitation", "second limitation"),
        unresolved_questions=("q1", "q2", "q3"),
        recommended_next_steps=("only next step",),
    )
    service = AssessmentPersistenceService(uow_factory, batch_size=100)

    persisted = await service.persist_assessment(candidate)

    assert persisted.id is not None
    async with uow_factory() as uow:
        loaded = await uow.assessments.get_by_id(persisted.id)
    assert loaded is not None
    assert loaded.analyzed_evidence_ids == (
        graph.evidence_id,
        second_evidence,
    )
    assert loaded.findings[0] == first_finding
    assert loaded.findings[1] == second_finding
    assert loaded.findings[0].support == first_finding.support
    assert loaded.limitations == ("first limitation", "second limitation")
    assert loaded.unresolved_questions == ("q1", "q2", "q3")
    assert loaded.recommended_next_steps == ("only next step",)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_failed_append_rolls_back_parent_history_audit_and_pointer(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A failed child/append write leaves no Assessment, history, audit, or pointer."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    first = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )
    assert first.id is not None

    attempted_id = uuid4()
    malformed = Assessment.model_construct(
        id=attempted_id,
        investigation_id=graph.investigation_id,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="failing boundary candidate",
        analyzed_evidence_ids=(graph.evidence_id,),
        findings=(_finding_construct(graph, support=()),),
    )
    with pytest.raises(AssessmentProvenanceMismatchError):
        await _insert_candidate(uow_factory, malformed)

    async with uow_factory() as uow:
        assert uow.session is not None
        assert await uow.assessments.get_by_id(attempted_id) is None
        history = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.domain_object_history "
                    "WHERE object_type = 'assessment' AND object_id = :id"
                ),
                {"id": attempted_id},
            )
        ).scalar_one()
        assert history == 0
        audit = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.audit_event "
                    "WHERE object_type = 'assessment' AND object_id = :id"
                ),
                {"id": attempted_id},
            )
        ).scalar_one()
        assert audit == 0
        assert await pointer_of(uow, graph.investigation_id) == first.id
        listing = await uow.assessments.list_for_investigation(graph.investigation_id)
        assert [item.id for item in listing] == [first.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_creation_race_with_relationship_soft_delete(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Creation serialized against a Relationship soft delete never persists stale support."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
        edge = await uow.relationships.get_by_identity(
            graph.source_entity_id,
            RelationshipType.RESOLVES_TO.value,
            graph.target_entity_id,
        )
        assert edge is not None
        edge_id = edge.id
    candidate = _candidate_with_findings(
        graph, analyzed=(graph.evidence_id,), findings=(graph_finding(graph),)
    )

    async def deleter() -> None:
        """Soft-delete the relationship and hold the row lock briefly."""
        async with uow_factory() as uow:
            await uow.relationships.soft_delete(edge_id, actor_id=uuid4())
            await asyncio.sleep(0.4)

    async def creator() -> None:
        """Start Assessment creation after the delete lock is held."""
        await asyncio.sleep(0.05)
        with pytest.raises(AssessmentProvenanceMismatchError):
            async with uow_factory() as uow:
                await uow.assessments.insert(candidate)

    await asyncio.gather(deleter(), creator())
    async with uow_factory() as uow:
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_creation_race_with_entity_soft_delete(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Creation serialized against an endpoint Entity soft delete never persists stale support."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    candidate = _candidate_with_findings(
        graph, analyzed=(graph.evidence_id,), findings=(graph_finding(graph),)
    )

    async def deleter() -> None:
        """Soft-delete the source Entity and hold the row lock briefly."""
        async with uow_factory() as uow:
            await uow.entities.soft_delete(graph.source_entity_id, actor_id=uuid4())
            await asyncio.sleep(0.4)

    async def creator() -> None:
        """Start Assessment creation after the delete lock is held."""
        await asyncio.sleep(0.05)
        with pytest.raises(AssessmentProvenanceMismatchError):
            async with uow_factory() as uow:
                await uow.assessments.insert(candidate)

    await asyncio.gather(deleter(), creator())
    async with uow_factory() as uow:
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )


def _candidate_with_findings(
    graph: Graph,
    *,
    analyzed: tuple[UUID, ...],
    findings: tuple[AnalyticalFinding, ...],
    verdict: Verdict = Verdict.SUSPICIOUS,
) -> Assessment:
    """Build a validation-bypassing candidate (DB boundary tests only)."""
    return Assessment.model_construct(
        investigation_id=graph.investigation_id,
        verdict=verdict,
        confidence=AssessmentConfidence.MEDIUM,
        summary="database boundary candidate",
        analyzed_evidence_ids=analyzed,
        findings=findings,
    )


async def _foreign_evidence_id(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> UUID:
    """Persist one Evidence row belonging to a different investigation."""
    other = Graph()
    async with uow_factory() as uow:
        await other.seed(uow, with_observation=False)
    return other.evidence_id


async def _second_evidence_id(
    uow_factory: Callable[[], PostgresUnitOfWork], graph: Graph
) -> UUID:
    """Persist one more Evidence row in the graph's investigation."""
    second = uuid4()
    async with uow_factory() as uow:
        await uow.evidence.insert(
            Evidence(
                id=second,
                investigation_id=graph.investigation_id,
                type=EvidenceType.DNS,
                subject=EntityRef(
                    id=graph.source_entity_id,
                    type=EntityType.DOMAIN,
                    value="example.com",
                ),
                source="urn:ati:source:google_public_dns",
                retrieved_at=_RETRIEVED_AT,
            )
        )
    return second


async def _call_append_assessment(
    uow_factory: Callable[[], PostgresUnitOfWork],
    candidate: Assessment,
    *,
    findings: list[tuple[object, ...]],
    supports: list[tuple[object, ...]],
    analyzed: list[UUID] | None = None,
) -> None:
    """Invoke the stored function directly with raw composite arrays.

    This exercises the database boundary for inputs the Python repository
    serialization cannot produce (malformed ordinals/kinds are impossible to
    emit through the domain model). Stored-function SQLSTATEs are mapped to
    the same typed errors the repository raises. ``analyzed`` overrides the
    candidate's analyzed set for direct-function boundary tests.
    """
    assessment_id = candidate.id or uuid4()
    async with uow_factory() as uow:
        assert uow.session is not None
        try:
            await uow.session.execute(
                text("""
                    SELECT ati.append_assessment(
                        :id, :investigation_id, :verdict, :confidence, :summary,
                        :analyzed, :limitations, :unresolved, :next_steps,
                        CAST(:findings AS ati.assessment_finding_item[]),
                        CAST(:supports AS ati.assessment_finding_support_item[]),
                        NULL, NULL)
                """),
                {
                    "id": assessment_id,
                    "investigation_id": candidate.investigation_id,
                    "verdict": candidate.verdict.value,
                    "confidence": candidate.confidence.value,
                    "summary": candidate.summary,
                    "analyzed": (
                        list(candidate.analyzed_evidence_ids)
                        if analyzed is None
                        else analyzed
                    ),
                    "limitations": [],
                    "unresolved": [],
                    "next_steps": [],
                    "findings": findings,
                    "supports": supports,
                },
            )
        except DBAPIError as error:
            assessment_repositories.raise_assessment_write_error(
                error, assessment_id, candidate.investigation_id
            )


def _wait_for_pid(pids: dict[str, int], name: str, *, timeout: float = 10.0) -> int:
    """Wait, bounded by timeout, until the named task recorded its backend PID."""
    deadline = time.monotonic() + timeout
    while name not in pids:
        if time.monotonic() >= deadline:
            raise AssertionError(f"task {name} never recorded its backend pid")
        time.sleep(0.005)
    return pids[name]


class _LockProbe:
    """Observe PostgreSQL lock state to coordinate concurrent transactions.

    Polls ``pg_stat_activity.wait_event_type`` (waiting) and ``pg_locks``
    (held row locks) on a dedicated connection instead of sleeping a fixed
    duration, so the racing tests prove the intended lock state is reached
    before the blocker is released.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def session_pid(self, uow: PostgresUnitOfWork) -> int:
        """Return the backend PID of the supplied unit of work."""
        assert uow.session is not None
        pid = (await uow.session.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        return int(pid)

    async def wait_for_waiting(self, pid: int, *, timeout: float = 15.0) -> None:
        """Wait until the session is waiting on a PostgreSQL lock."""
        deadline = time.monotonic() + timeout
        async with self._engine.connect() as connection:
            while True:
                row = (
                    await connection.execute(
                        text(
                            "SELECT wait_event_type FROM pg_stat_activity "
                            "WHERE pid = :pid"
                        ),
                        {"pid": pid},
                    )
                ).first()
                if row is not None and row[0] == "Lock":
                    return
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        f"backend {pid} never became lock-waiting "
                        f"(state={row[0] if row else 'gone'})"
                    )
                await asyncio.sleep(0.02)

    async def wait_for_holds(
        self, pid: int, relation: str, *, timeout: float = 15.0
    ) -> None:
        """Wait until the session holds a heavyweight lock on a table."""
        deadline = time.monotonic() + timeout
        async with self._engine.connect() as connection:
            while True:
                count = (
                    await connection.execute(
                        text("""
                            SELECT count(*) FROM pg_locks l
                            JOIN pg_class c ON c.oid = l.relation
                            JOIN pg_namespace n ON n.oid = c.relnamespace
                            WHERE l.pid = :pid AND n.nspname = 'ati'
                              AND c.relname = :relation
                        """),
                        {"pid": pid, "relation": relation},
                    )
                ).scalar_one()
                if int(count) > 0:
                    return
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        f"backend {pid} never acquired a lock on {relation}"
                    )
                await asyncio.sleep(0.02)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pointer_deletion_race_pointer_assignment_wins(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """Pointer assignment serialized first defeats concurrent A deletion.

    A blocker holds A's row lock; the pointer assignment locks the
    Investigation and waits on A; the deletion cannot pass the Investigation
    lock; after the blocker releases, the pointer commits and the deletion is
    rejected with the current-reference conflict.
    """
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    a = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )
    b = await service.persist_assessment(
        assessment_factory(graph, findings=(graph_finding(graph),))
    )
    assert a.id is not None and b.id is not None
    a_ref: UUID = a.id
    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(graph.investigation_id)
    assert state is not None and state.version is not None
    inv_version: int = state.version

    probe = _LockProbe(integration_engine)
    pids: dict[str, int] = {}
    outcomes: dict[str, object] = {}
    blocker_ready = asyncio.Event()
    blocker_release = asyncio.Event()

    async def blocker() -> None:
        async with uow_factory() as uow:
            assert uow.session is not None
            await uow.session.execute(
                text("SELECT id FROM ati.assessment WHERE id = :id FOR UPDATE"),
                {"id": a_ref},
            )
            blocker_ready.set()
            await blocker_release.wait()

    async def pointer() -> None:
        async with uow_factory() as uow:
            assert uow.session is not None
            pids["pointer"] = await probe.session_pid(uow)
            try:
                result = await uow.investigations.update_assessment_reference(
                    graph.investigation_id,
                    a_ref,
                    expected_version=inv_version,
                )
            except BaseException as exc:  # noqa: BLE001 - captured for assertion
                outcomes["pointer"] = exc
            else:
                outcomes["pointer"] = result

    async def deleter() -> None:
        async with uow_factory() as uow:
            assert uow.session is not None
            pids["deleter"] = await probe.session_pid(uow)
            try:
                result = await uow.assessments.soft_delete(a_ref)
            except BaseException as exc:  # noqa: BLE001 - captured for assertion
                outcomes["deleter"] = exc
            else:
                outcomes["deleter"] = result

    blocker_task = asyncio.create_task(blocker())
    await asyncio.wait_for(blocker_ready.wait(), 10)
    pointer_task = asyncio.create_task(pointer())
    await asyncio.wait_for(asyncio.to_thread(_wait_for_pid, pids, "pointer"), 10)
    await asyncio.wait_for(probe.wait_for_holds(pids["pointer"], "investigation"), 10)
    await asyncio.wait_for(probe.wait_for_waiting(pids["pointer"]), 10)

    deleter_task = asyncio.create_task(deleter())
    await asyncio.wait_for(asyncio.to_thread(_wait_for_pid, pids, "deleter"), 10)
    await asyncio.wait_for(probe.wait_for_waiting(pids["deleter"]), 10)

    blocker_release.set()
    await asyncio.wait_for(blocker_task, 10)
    await asyncio.wait_for(pointer_task, 15)
    await asyncio.wait_for(deleter_task, 15)

    assert isinstance(outcomes.get("pointer"), InvestigationWriteResult), outcomes
    assert isinstance(
        outcomes.get("deleter"), AssessmentCurrentReferenceConflictError
    ), outcomes

    async with uow_factory() as uow:
        assert await pointer_of(uow, graph.investigation_id) == a.id
        assert (await uow.assessments.get_by_id(a.id)) is not None
        assert uow.session is not None
        delete_history = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.domain_object_history "
                    "WHERE object_type = 'assessment' AND object_id = :id "
                    "AND operation = 'DELETE'"
                ),
                {"id": a_ref},
            )
        ).scalar_one()
        delete_audit = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.audit_event "
                    "WHERE action = :action AND object_id = :id"
                ),
                {"action": AuditAction.ASSESSMENT_DELETE.value, "id": a.id},
            )
        ).scalar_one()
        assert delete_history == 0
        assert delete_audit == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pointer_deletion_race_deletion_wins(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """Deletion queued first defeats a concurrent pointer assignment to A.

    The blocker holds the Investigation row lock; the deleter queues first,
    deletes the superseded A, and commits; the pointer assignment then locks
    the Investigation, obtains the authoritative (deleted) Assessment state,
    and is rejected — the pointer stays B and exactly one DELETE history row
    exists for A.
    """
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    service = AssessmentPersistenceService(uow_factory, batch_size=100)
    a = await service.persist_assessment(
        assessment_factory(graph, findings=(direct_finding(graph),))
    )
    b = await service.persist_assessment(
        assessment_factory(graph, findings=(graph_finding(graph),))
    )
    assert a.id is not None and b.id is not None
    a_ref: UUID = a.id
    b_ref: UUID = b.id

    probe = _LockProbe(integration_engine)
    pids: dict[str, int] = {}
    outcomes: dict[str, object] = {}
    blocker_ready = asyncio.Event()
    blocker_release = asyncio.Event()

    async def blocker() -> None:
        async with uow_factory() as uow:
            assert uow.session is not None
            await uow.session.execute(
                text("SELECT id FROM ati.investigation WHERE id = :id FOR UPDATE"),
                {"id": graph.investigation_id},
            )
            blocker_ready.set()
            await blocker_release.wait()

    async def deleter() -> None:
        async with uow_factory() as uow:
            assert uow.session is not None
            pids["deleter"] = await probe.session_pid(uow)
            try:
                request_id = uuid4()
                deleted = await uow.assessments.soft_delete(
                    a_ref, actor_id=uuid4(), request_id=request_id
                )
                # Emit the transactional ASSESSMENT_DELETE audit event exactly
                # as AssessmentPersistenceService does.
                if deleted.investigation_id is not None:
                    await uow.audit_events.append(
                        AuditEvent(
                            action=AuditAction.ASSESSMENT_DELETE,
                            outcome=AuditOutcome.SUCCESS,
                            object_type="assessment",
                            object_id=a_ref,
                            request_id=request_id,
                            metadata={
                                "investigation_id": str(deleted.investigation_id)
                            },
                        )
                    )
                outcomes["deleter"] = deleted
            except BaseException as exc:  # noqa: BLE001 - captured
                outcomes["deleter"] = exc

    async def pointer() -> None:
        async with uow_factory() as uow:
            assert uow.session is not None
            pids["pointer"] = await probe.session_pid(uow)
            try:
                result = await uow.investigations.update_assessment_reference(
                    graph.investigation_id, a_ref
                )
            except BaseException as exc:  # noqa: BLE001 - captured
                outcomes["pointer"] = exc
            else:
                outcomes["pointer"] = result

    blocker_task = asyncio.create_task(blocker())
    await asyncio.wait_for(blocker_ready.wait(), 10)
    deleter_task = asyncio.create_task(deleter())
    await asyncio.wait_for(asyncio.to_thread(_wait_for_pid, pids, "deleter"), 10)
    await asyncio.wait_for(probe.wait_for_waiting(pids["deleter"]), 10)
    pointer_task = asyncio.create_task(pointer())
    await asyncio.wait_for(asyncio.to_thread(_wait_for_pid, pids, "pointer"), 10)
    await asyncio.wait_for(probe.wait_for_waiting(pids["pointer"]), 10)

    blocker_release.set()
    await asyncio.wait_for(blocker_task, 10)
    await asyncio.wait_for(deleter_task, 15)
    await asyncio.wait_for(pointer_task, 15)

    assert isinstance(outcomes.get("deleter"), Assessment), outcomes
    assert isinstance(
        outcomes.get("pointer"), AssessmentProvenanceMismatchError
    ), outcomes

    async with uow_factory() as uow:
        assert await pointer_of(uow, graph.investigation_id) == b_ref
        assert await uow.assessments.get_by_id(a_ref) is None
        assert (
            await uow.assessments.get_by_id(a_ref, include_deleted=True)
        ) is not None
        assert uow.session is not None
        delete_history = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.domain_object_history "
                    "WHERE object_type = 'assessment' AND object_id = :id "
                    "AND operation = 'DELETE'"
                ),
                {"id": a_ref},
            )
        ).scalar_one()
        delete_audit = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.audit_event "
                    "WHERE action = :action AND object_id = :id"
                ),
                {
                    "action": AuditAction.ASSESSMENT_DELETE.value,
                    "id": a_ref,
                },
            )
        ).scalar_one()
        assert delete_history == 1
        assert delete_audit == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_defensive_hard_limit_rejects_oversized_inputs(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Direct SQL calls above the hard ceiling fail before staging/mutation."""
    graph = Graph()
    async with uow_factory() as uow:
        await graph.seed(uow)
    # The database defensive ceiling is 10,000; the application limit is the
    # configured db_batch_size (100). Build inputs above the database ceiling
    # by bypassing the Python repository bounds entirely.
    hard_plus_one = 10_001
    oversized_ids = [graph.evidence_id] * hard_plus_one
    oversized_findings = [
        (idx, "network", "supporting", f"finding {idx}", "medium")
        for idx in range(1, hard_plus_one + 1)
    ]
    oversized_supports = [
        (idx, 1, "evidence", graph.evidence_id, None)
        for idx in range(1, hard_plus_one + 1)
    ]

    cases: list[dict[str, object]] = [
        {"findings": oversized_findings, "supports": oversized_supports},
        {"findings": [], "supports": [], "analyzed": oversized_ids},
    ]
    for case in cases:
        candidate = _candidate_with_findings(
            graph,
            analyzed=tuple(case.get("analyzed", (graph.evidence_id,))),  # type: ignore[arg-type]
            findings=(direct_finding(graph),),
        )
        with pytest.raises(AssessmentProvenanceMismatchError, match="hard"):
            await _call_append_assessment(
                uow_factory,
                candidate,
                findings=case["findings"],  # type: ignore[arg-type]
                supports=case["supports"],  # type: ignore[arg-type]
                analyzed=case.get("analyzed", [graph.evidence_id]),  # type: ignore[arg-type]
            )
    async with uow_factory() as uow:
        assert (
            await uow.assessments.list_for_investigation(graph.investigation_id) == []
        )
