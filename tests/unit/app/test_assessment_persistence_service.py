# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the validated Assessment persistence service boundary.

Fakes replace every repository and the UnitOfWork, proving the service
performs no provider, network, dispatcher, or LLM work and that the
Investigation pointer is only advanced after the Assessment write itself
has succeeded.
"""

# Fixture arguments intentionally reuse fixture names and the fakes mirror
# the repository seam shape used by the other persistence-service suites.
# pylint: disable=redefined-outer-name,duplicate-code

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from typing import Self
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.assessment_provenance import (
    AssessmentEvidenceReferenceError,
)
from agentic_threat_investigator.app.persistence.repositories import (
    AssessmentCurrentReferenceConflictError,
    AssessmentRepository,
    AssessmentSizeLimitExceededError,
    AuditEventRepository,
    BatchOutcome,
    EntityBatchItem,
    EntityBatchResult,
    EntityRepository,
    EvidenceRepository,
    InvestigationRepository,
    InvestigationWriteResult,
    RelationshipObservationRepository,
    RelationshipRepository,
    UnitOfWork,
)
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

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def visible_investigation(investigation_id: UUID) -> InvestigationState:
    """Build the visible Investigation for the provenance context."""
    return InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[uuid4()],
        objective="Assess the root indicator.",
        budget=default_investigation_budget(),
        started_at=_RETRIEVED_AT,
    )


# The World exists only to assemble one deterministic fixture chain, and the
# fake UnitOfWork deliberately takes one explicit repository per seam.
# pylint: disable=too-few-public-methods,too-many-instance-attributes


class FakeInvestigationRepository(InvestigationRepository):
    """Investigation repository recording pointer updates."""

    def __init__(self, visible: InvestigationState | None) -> None:
        self.visible = visible
        self.pointer_calls: list[tuple[UUID, UUID, int | None]] = []
        self.pointer_error: Exception | None = None

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        return self.visible

    async def update_assessment_reference(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        # One explicit argument per correlation/concurrency dimension mirrors
        # the real repository contract.
        # pylint: disable=too-many-arguments
        self.pointer_calls.append((investigation_id, assessment_id, expected_version))
        if self.pointer_error is not None:
            raise self.pointer_error
        return InvestigationWriteResult(investigation_id, 2, BatchOutcome.UPDATED)

    async def create(
        self, state: InvestigationState, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_status(
        self, *args: object, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def soft_delete(self, *args: object, **_: object) -> InvestigationWriteResult:
        raise NotImplementedError


class FakeEvidenceRepository(EvidenceRepository):
    """Evidence repository serving the configured provenance rows."""

    def __init__(self, rows: dict[UUID, Evidence]) -> None:
        self.rows = rows

    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        return self.rows.get(evidence_id)

    async def insert(self, evidence: Evidence, **_: object) -> Evidence:
        raise NotImplementedError

    async def list_for_investigation(
        self, investigation_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[Evidence]:
        return [
            row
            for row in self.rows.values()
            if row.investigation_id == investigation_id
        ]


class FakeObservationRepository(RelationshipObservationRepository):
    """Observation repository serving the configured provenance rows."""

    def __init__(self, rows: dict[UUID, RelationshipObservation]) -> None:
        self.rows = rows

    async def get_by_id(self, observation_id: UUID) -> RelationshipObservation | None:
        return self.rows.get(observation_id)

    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        raise NotImplementedError


class FakeRelationshipRepository(RelationshipRepository):
    """Relationship repository serving the configured eligible rows."""

    def __init__(self, rows: dict[UUID, Relationship]) -> None:
        self.rows = rows

    async def get_by_id(
        self, relationship_id: UUID, *, include_deleted: bool = False
    ) -> Relationship | None:
        return self.rows.get(relationship_id)

    async def get_by_identity(
        self,
        source_entity_id: UUID,
        relationship_type: str,
        target_entity_id: UUID,
        *,
        include_deleted: bool = False,
    ) -> Relationship | None:
        raise NotImplementedError

    async def upsert(self, relationship: Relationship, **_: object) -> Relationship:
        raise NotImplementedError

    async def soft_delete(self, relationship_id: UUID, **_: object) -> Relationship:
        raise NotImplementedError


class FakeEntityRepository(EntityRepository):
    """Entity repository serving the configured eligible rows."""

    def __init__(self, rows: dict[UUID, Entity]) -> None:
        self.rows = rows

    async def get_by_id(
        self, entity_id: UUID, *, include_deleted: bool = False
    ) -> Entity | None:
        return self.rows.get(entity_id)

    async def get_by_identity(
        self, entity_type: str, canonical_value: str, *, include_deleted: bool = False
    ) -> Entity | None:
        raise NotImplementedError

    async def upsert(self, entity: Entity, **_: object) -> Entity:
        raise NotImplementedError

    async def upsert_batch(
        self, items: Sequence[EntityBatchItem]
    ) -> list[EntityBatchResult]:
        raise NotImplementedError

    async def soft_delete(self, entity_id: UUID, **_: object) -> Entity:
        raise NotImplementedError


class FakeAssessmentRepository(AssessmentRepository):
    """Insert/soft-delete assessment fake with identity and failure seams."""

    def __init__(self, assigned_id: UUID | None = None) -> None:
        self.inserted: list[Assessment] = []
        self.assigned_id = assigned_id or uuid4()
        self.fail: Exception | None = None
        self.delete_calls: list[tuple[UUID, UUID | None, int | None]] = []
        self.delete_error: Exception | None = None
        self.deleted: Assessment | None = None

    async def insert(
        self,
        assessment: Assessment,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Assessment:
        if self.fail is not None:
            raise self.fail
        self.inserted.append(assessment)
        return assessment.model_copy(
            update={
                "id": self.assigned_id,
                "version": 1,
                "created_at": _RETRIEVED_AT,
            }
        )

    async def get_by_id(
        self, assessment_id: UUID, *, include_deleted: bool = False
    ) -> Assessment | None:
        raise NotImplementedError

    async def list_for_investigation(
        self, investigation_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[Assessment]:
        raise NotImplementedError

    async def soft_delete(
        self,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Assessment:
        self.delete_calls.append((assessment_id, actor_id, expected_version))
        if self.delete_error is not None:
            raise self.delete_error
        deleted = self.deleted or Assessment.model_construct(
            id=assessment_id,
            investigation_id=uuid4(),
            verdict=Verdict.SUSPICIOUS,
            confidence=AssessmentConfidence.MEDIUM,
            summary="deleted",
            analyzed_evidence_ids=(),
            version=(expected_version or 1) + 1,
        )
        return deleted


class FakeAuditRepository(AuditEventRepository):
    """Append-only audit repository with a failure seam."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self.fail: Exception | None = None

    async def append(self, event: AuditEvent) -> AuditEvent:
        if self.fail is not None:
            raise self.fail
        self.events.append(event)
        return event

    async def list_events(self, **_filters: object) -> list[AuditEvent]:
        return self.events


class FakeUnitOfWork(UnitOfWork):  # pylint: disable=too-many-instance-attributes
    """In-memory transaction boundary with deterministic commit accounting.

    Every repository seam is exposed as one typed attribute; seven of the
    nine attributes are the mandatory repository boundary itself.
    """

    entities: FakeEntityRepository
    relationships: FakeRelationshipRepository
    relationship_observations: FakeObservationRepository
    evidence: FakeEvidenceRepository
    investigations: FakeInvestigationRepository
    assessments: FakeAssessmentRepository
    audit_events: FakeAuditRepository

    def __init__(
        self,
        *,
        investigations: FakeInvestigationRepository,
        evidence: FakeEvidenceRepository,
        observations: FakeObservationRepository,
        relationships: FakeRelationshipRepository,
        entities: FakeEntityRepository,
        assessments: FakeAssessmentRepository,
        audit_events: FakeAuditRepository,
    ) -> None:
        # One explicit argument per repository seam is the UnitOfWork
        # convention; the count is intrinsic to the boundary.
        # pylint: disable=too-many-arguments
        self.investigations = investigations
        self.evidence = evidence
        self.relationship_observations = observations
        self.relationships = relationships
        self.entities = entities
        self.assessments = assessments
        self.audit_events = audit_events
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        if exc_type is None:
            self.commits += 1
        else:
            self.rollbacks += 1

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


class World:
    """One complete, eligible provenance world served by the fakes."""

    def __init__(self) -> None:
        self.investigation_id = uuid4()
        self.source_id = uuid4()
        self.target_id = uuid4()
        self.evidence_id = uuid4()
        self.relationship_id = uuid4()
        self.observation_id = uuid4()
        self.investigation = visible_investigation(self.investigation_id)
        self.source = Entity(
            id=self.source_id, type=EntityType.DOMAIN, value="example.com"
        )
        self.target = Entity(
            id=self.target_id, type=EntityType.IP_ADDRESS, value="192.0.2.1"
        )
        self.evidence = Evidence(
            id=self.evidence_id,
            investigation_id=self.investigation_id,
            type=EvidenceType.DNS,
            subject=EntityRef(
                id=self.source_id, type=EntityType.DOMAIN, value="example.com"
            ),
            source="urn:ati:source:google_public_dns",
            retrieved_at=_RETRIEVED_AT,
        )
        self.relationship = Relationship(
            id=self.relationship_id,
            source_entity_id=self.source_id,
            target_entity_id=self.target_id,
            type=RelationshipType.RESOLVES_TO,
        )
        self.observation = RelationshipObservation(
            id=self.observation_id,
            relationship_id=self.relationship_id,
            evidence_id=self.evidence_id,
            investigation_id=self.investigation_id,
            retrieved_at=_RETRIEVED_AT,
            source="urn:ai:source:google_public_dns",
        )
        self.assessment = Assessment(
            investigation_id=self.investigation_id,
            verdict=Verdict.SUSPICIOUS,
            confidence=AssessmentConfidence.MEDIUM,
            summary="Evidence supports the verdict.",
            analyzed_evidence_ids=(self.evidence_id,),
            findings=(
                AnalyticalFinding(
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="The domain resolves to the address.",
                    confidence=AssessmentConfidence.MEDIUM,
                    support=(
                        EvidenceSupport(kind="evidence", evidence_id=self.evidence_id),
                        RelationshipSupport(
                            kind="relationship_observation",
                            relationship_observation_id=self.observation_id,
                        ),
                    ),
                ),
            ),
        )

    def unit(self) -> FakeUnitOfWork:
        """Build a UnitOfWork serving this world."""
        return FakeUnitOfWork(
            investigations=FakeInvestigationRepository(self.investigation),
            evidence=FakeEvidenceRepository({self.evidence_id: self.evidence}),
            observations=FakeObservationRepository(
                {self.observation_id: self.observation}
            ),
            relationships=FakeRelationshipRepository(
                {self.relationship_id: self.relationship}
            ),
            entities=FakeEntityRepository(
                {self.source_id: self.source, self.target_id: self.target}
            ),
            assessments=FakeAssessmentRepository(),
            audit_events=FakeAuditRepository(),
        )


@pytest.fixture
def bound() -> Iterator[tuple[AssessmentPersistenceService, FakeUnitOfWork, World]]:
    """Bind the service to one deterministic unit and world per test."""
    world = World()
    unit = world.unit()
    yield AssessmentPersistenceService(lambda: unit, batch_size=100), unit, world


@pytest.fixture
def limited() -> tuple[AssessmentPersistenceService, FakeUnitOfWork, World]:
    """Bind the service to a tiny batch limit for oversize-bound tests."""
    world = World()
    unit = world.unit()
    return AssessmentPersistenceService(lambda: unit, batch_size=2), unit, world


@pytest.mark.asyncio
async def test_persist_validates_writes_pointer_and_audits_once(
    bound: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
) -> None:
    """A valid Assessment is inserted, pointed, audited, and committed once."""
    service, unit, world = bound

    persisted = await service.persist_assessment(
        world.assessment, actor_id=uuid4(), request_id=uuid4()
    )

    assert persisted.id == unit.assessments.assigned_id
    assert unit.commits == 1
    assert unit.rollbacks == 0
    assert unit.investigations.pointer_calls == [
        (world.investigation_id, unit.assessments.assigned_id, None)
    ]
    assert len(unit.audit_events.events) == 1
    event = unit.audit_events.events[0]
    assert event.action == AuditAction.ASSESSMENT_CREATE
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.object_type == "assessment"
    assert event.object_id == unit.assessments.assigned_id


@pytest.mark.asyncio
async def test_validation_failure_writes_nothing_and_rolls_back(
    bound: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
) -> None:
    """A candidate with invalid provenance is rejected before any write."""
    service, unit, world = bound
    candidate = world.assessment.model_copy(
        update={"analyzed_evidence_ids": (uuid4(),)}
    )

    with pytest.raises(AssessmentEvidenceReferenceError):
        await service.persist_assessment(candidate)
    assert unit.commits == 0
    assert unit.rollbacks == 1
    assert unit.assessments.inserted == []
    assert unit.investigations.pointer_calls == []
    assert unit.audit_events.events == []


@pytest.mark.asyncio
async def test_pointer_update_failure_rolls_back_everything(
    bound: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
) -> None:
    """A pointer update failure leaves no side effects in the unit."""
    service, unit, world = bound
    unit.investigations.pointer_error = RuntimeError("injected pointer failure")

    with pytest.raises(RuntimeError, match="injected pointer failure"):
        await service.persist_assessment(world.assessment)
    assert unit.commits == 0
    assert unit.rollbacks == 1
    # The AuditEvent is appended only after the pointer update succeeds.
    assert unit.audit_events.events == []


@pytest.mark.asyncio
async def test_passes_expected_investigation_version(
    bound: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
) -> None:
    """The optimistic-concurrency expectation reaches the pointer write."""
    service, unit, world = bound

    await service.persist_assessment(world.assessment, expected_investigation_version=7)

    assert unit.investigations.pointer_calls == [
        (world.investigation_id, unit.assessments.assigned_id, 7)
    ]


@pytest.mark.asyncio
async def test_failed_assessment_write_never_advances_pointer(
    bound: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
) -> None:
    """A write failure propagates before the pointer is touched."""
    service, unit, world = bound
    unit.assessments.fail = RuntimeError("injected insert failure")

    with pytest.raises(RuntimeError, match="injected insert failure"):
        await service.persist_assessment(world.assessment)
    assert unit.investigations.pointer_calls == []
    assert unit.audit_events.events == []
    assert unit.rollbacks == 1


@pytest.mark.asyncio
async def test_delete_assessment_audits_and_commits_once(
    bound: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
) -> None:
    """Deletion emits one ASSESSMENT_DELETE audit event and commits once."""
    service, unit, _ = bound
    assessment_id = uuid4()
    actor_id = uuid4()
    request_id = uuid4()

    deleted = await service.delete_assessment(
        assessment_id, actor_id=actor_id, request_id=request_id, expected_version=4
    )

    assert unit.commits == 1
    assert unit.rollbacks == 0
    assert unit.assessments.delete_calls == [(assessment_id, actor_id, 4)]
    assert len(unit.audit_events.events) == 1
    event = unit.audit_events.events[0]
    assert event.action == AuditAction.ASSESSMENT_DELETE
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.object_type == "assessment"
    assert event.object_id == assessment_id
    assert event.actor_id == actor_id
    assert event.request_id == request_id
    assert deleted.id == assessment_id


@pytest.mark.asyncio
async def test_delete_assessment_audit_failure_rolls_back(
    bound: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
) -> None:
    """An audit failure after deletion rolls back the whole operation."""
    service, unit, _ = bound
    unit.audit_events.fail = RuntimeError("injected audit failure")

    with pytest.raises(RuntimeError, match="injected audit failure"):
        await service.delete_assessment(uuid4())

    assert unit.commits == 0
    assert unit.rollbacks == 1
    assert unit.audit_events.events == []


@pytest.mark.asyncio
async def test_delete_assessment_current_reference_conflict_propagates(
    bound: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
) -> None:
    """A current-reference conflict propagates with no audit and a rollback."""
    service, unit, _ = bound
    unit.assessments.delete_error = AssessmentCurrentReferenceConflictError(uuid4())

    with pytest.raises(AssessmentCurrentReferenceConflictError):
        await service.delete_assessment(uuid4())

    assert unit.commits == 0
    assert unit.rollbacks == 1
    assert unit.audit_events.events == []


def _oversized_candidate(world: World, *, collection: str) -> Assessment:
    """Build a candidate whose named collection exceeds limit 2."""
    base = world.assessment
    if collection == "analyzed_evidence_ids":
        return base.model_copy(
            update={"analyzed_evidence_ids": (world.evidence_id, uuid4(), uuid4())}
        )
    if collection == "findings":
        return base.model_copy(
            update={
                "findings": (
                    base.findings[0],
                    base.findings[0],
                    base.findings[0],
                )
            }
        )
    if collection == "finding_support":
        return base.model_copy(
            update={
                "findings": (
                    AnalyticalFinding(
                        category=FindingCategory.NETWORK,
                        disposition=FindingDisposition.SUPPORTING,
                        statement="Three supports exceed the limit.",
                        confidence=AssessmentConfidence.MEDIUM,
                        support=(
                            EvidenceSupport(
                                kind="evidence", evidence_id=world.evidence_id
                            ),
                            RelationshipSupport(
                                kind="relationship_observation",
                                relationship_observation_id=world.observation_id,
                            ),
                            EvidenceSupport(kind="evidence", evidence_id=uuid4()),
                        ),
                    ),
                )
            }
        )
    if collection == "limitations":
        return base.model_copy(update={"limitations": ("a", "b", "c")})
    if collection == "unresolved_questions":
        return base.model_copy(update={"unresolved_questions": ("a", "b", "c")})
    return base.model_copy(update={"recommended_next_steps": ("a", "b", "c")})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "collection",
    [
        "analyzed_evidence_ids",
        "findings",
        "finding_support",
        "limitations",
        "unresolved_questions",
        "recommended_next_steps",
    ],
)
async def test_oversized_collection_rejected_before_unit_of_work(
    limited: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
    collection: str,
) -> None:
    """An oversized collection is rejected before any unit-of-work entry."""
    service, unit, world = limited
    candidate = _oversized_candidate(world, collection=collection)

    with pytest.raises(AssessmentSizeLimitExceededError) as exc_info:
        await service.persist_assessment(candidate)

    assert exc_info.value.collection == collection
    assert exc_info.value.count == 3
    assert exc_info.value.limit == 2
    assert "summary" not in str(exc_info.value)
    assert unit.commits == 0
    assert unit.rollbacks == 0
    assert unit.assessments.inserted == []
    assert unit.investigations.pointer_calls == []
    assert unit.audit_events.events == []


@pytest.mark.asyncio
async def test_collection_at_limit_is_accepted(
    limited: tuple[AssessmentPersistenceService, FakeUnitOfWork, World],
) -> None:
    """A candidate exactly at the limit persists; limit-plus-one is rejected.

    The findings count of two is exactly the configured limit, exercising the
    boundary alongside the oversize-plus-one rejection tests.
    """
    service, unit, world = limited
    first = AnalyticalFinding(
        category=FindingCategory.NETWORK,
        disposition=FindingDisposition.SUPPORTING,
        statement="First finding at the limit.",
        confidence=AssessmentConfidence.MEDIUM,
        support=(EvidenceSupport(kind="evidence", evidence_id=world.evidence_id),),
    )
    second = AnalyticalFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement="Second finding at the limit.",
        confidence=AssessmentConfidence.LOW,
        support=(EvidenceSupport(kind="evidence", evidence_id=world.evidence_id),),
    )
    candidate = world.assessment.model_copy(update={"findings": (first, second)})

    persisted = await service.persist_assessment(candidate)

    assert persisted.id == unit.assessments.assigned_id
    assert unit.commits == 1
    assert unit.rollbacks == 0
