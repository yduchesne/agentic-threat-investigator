# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the investigation persistence service boundary.

Fakes replace every repository and the UnitOfWork, proving the service
requires no provider, HTTP, LLM, or database machinery and that repositories
never own the transaction lifecycle.
"""

# Fixture arguments intentionally reuse fixture names, and the fake
# repository interfaces deliberately carry one explicit argument per
# correlation/concurrency dimension.

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Self
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.investigation_persistence import (
    InvestigationPersistenceService,
)
from agentic_threat_investigator.app.persistence.repositories import (
    AuditEventRepository,
    BatchOutcome,
    EvidenceDuplicateIdentityError,
    EvidenceRepository,
    InvestigationDuplicateIdentityError,
    InvestigationNotFoundError,
    InvestigationRepository,
    InvestigationVersionConflictError,
    InvestigationWriteResult,
    UnitOfWork,
)
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
    InvalidInvestigationStatusTransitionError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_STARTED_AT = datetime(2026, 1, 1, tzinfo=UTC)


class FakeInvestigationRepository(InvestigationRepository):
    """Deterministic in-memory investigation repository."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.create_result = InvestigationWriteResult(uuid4(), 1, BatchOutcome.INSERTED)
        self.create_error: Exception | None = None
        self.update_result = InvestigationWriteResult(uuid4(), 2, BatchOutcome.UPDATED)
        self.update_error: Exception | None = None
        self.visible: InvestigationState | None = None

    def record(self, operation: str, *arguments: object) -> None:
        """Record one repository invocation."""
        self.calls.append((operation, arguments))

    def operations(self) -> list[str]:
        """Return the recorded operation names."""
        return [operation for operation, _ in self.calls]

    async def create(
        self,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> InvestigationWriteResult:
        """Return the configured result, raising when configured to fail."""
        self.record("create", state, actor_id, request_id)
        if self.create_error is not None:
            raise self.create_error
        return self.create_result

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        """Return the configured visible state."""
        self.record("get_by_id", investigation_id, include_deleted)
        return self.visible

    async def update_status(
        self,
        investigation_id: UUID,
        status: InvestigationStatus,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Return the configured result, raising when configured to fail."""
        self.record("update_status", investigation_id, status)
        if self.update_error is not None:
            raise self.update_error
        return self.update_result

    async def update_assessment_reference(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Record the pointer update and return the configured result."""
        self.record("update_assessment_reference", investigation_id, assessment_id)
        if self.update_error is not None:
            raise self.update_error
        return self.update_result

    async def update_budget(
        self,
        investigation_id: UUID,
        budget: object,
        **_: object,
    ) -> InvestigationWriteResult:
        """Record the budget update and return the configured result."""
        self.record("update_budget", investigation_id)
        if self.update_error is not None:
            raise self.update_error
        return self.update_result

    async def soft_delete(
        self,
        investigation_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Return a soft-deletion result."""
        self.record("soft_delete", investigation_id)
        return InvestigationWriteResult(investigation_id, 3, BatchOutcome.UPDATED)


class FakeEvidenceRepository(EvidenceRepository):
    """Deterministic in-memory evidence repository."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.insert_error: Exception | None = None

    async def insert(
        self,
        evidence: Evidence,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Evidence:
        """Return the evidence with an identity, or raise the configured error."""
        self.calls.append("insert")
        if self.insert_error is not None:
            raise self.insert_error
        return evidence.model_copy(update={"id": uuid4()})

    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        """Reads are unused in these tests."""
        self.calls.append("get_by_id")
        return None

    async def list_for_investigation(
        self, investigation_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[Evidence]:
        """Reads are unused in these tests."""
        self.calls.append("list_for_investigation")
        return []


class FakeAuditEventRepository(AuditEventRepository):
    """Deterministic in-memory audit repository."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self.append_error: Exception | None = None

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Record the event, or raise the configured error."""
        if self.append_error is not None:
            raise self.append_error
        self.events.append(event)
        return event

    async def list_events(self, **_filters: object) -> list[AuditEvent]:
        """Queries are unused in these tests."""
        return self.events


class FakeUnitOfWork(UnitOfWork):
    """In-memory transaction boundary with deterministic commit accounting."""

    investigations: FakeInvestigationRepository
    evidence: FakeEvidenceRepository
    audit_events: FakeAuditEventRepository

    def __init__(self) -> None:
        self.investigations = FakeInvestigationRepository()
        self.evidence = FakeEvidenceRepository()
        self.audit_events = FakeAuditEventRepository()
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
        """Count an explicit commit."""
        self.commits += 1

    async def rollback(self) -> None:
        """Count an explicit rollback."""
        self.rollbacks += 1


class FakeUnitOfWorkFactory:
    """Callable unit-of-work factory retaining the created units."""

    def __init__(self) -> None:
        self.units: list[FakeUnitOfWork] = []
        self.next_unit: FakeUnitOfWork | None = None

    def __call__(self) -> FakeUnitOfWork:
        unit = self.next_unit if self.next_unit is not None else FakeUnitOfWork()
        self.units.append(unit)
        self.next_unit = None
        return unit

    def configure(self, unit: FakeUnitOfWork) -> FakeUnitOfWork:
        """Stage a preconfigured unit for the next service operation."""
        self.next_unit = unit
        return unit


@pytest.fixture
def uow_factory() -> FakeUnitOfWorkFactory:
    """Provide a fake unit-of-work factory per test."""
    return FakeUnitOfWorkFactory()


@pytest.fixture
def service(
    uow_factory: FakeUnitOfWorkFactory,
) -> Iterator[tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory]]:
    """Build the persistence service over the fake factory."""
    yield InvestigationPersistenceService(uow_factory), uow_factory


def state_factory(
    *, status: InvestigationStatus = InvestigationStatus.PENDING
) -> InvestigationState:
    """Build a deterministic valid investigation state."""
    return InvestigationState(
        investigation_id=uuid4(),
        status=status,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[uuid4()],
        objective="Assess the root indicator.",
        budget=default_investigation_budget(),
        started_at=_STARTED_AT,
    )


def evidence_factory(investigation_id: UUID | None = None) -> Evidence:
    """Build a deterministic valid evidence observation."""
    return Evidence(
        investigation_id=investigation_id or uuid4(),
        type=EvidenceType.DNS,
        subject=EntityRef(type=EntityType.DOMAIN, value="example.com"),
        source="urn:ati:source:google_public_dns",
        retrieved_at=_RETRIEVED_AT,
    )


@pytest.mark.asyncio
async def test_create_investigation_commits_once_with_audit(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """Creation mutates through the repository, appends audit, and commits once."""
    investigation_service, factory = service
    state = state_factory()

    result = await investigation_service.create_investigation(
        state, actor_id=uuid4(), request_id=uuid4()
    )

    unit = factory.units[-1]
    assert result.outcome is BatchOutcome.INSERTED
    assert unit.commits == 1
    assert unit.rollbacks == 0
    assert len(unit.audit_events.events) == 1
    event = unit.audit_events.events[0]
    assert event.action == AuditAction.INVESTIGATION_CREATE
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.object_type == "investigation"
    assert event.object_id == state.investigation_id


@pytest.mark.asyncio
async def test_operations_commit_exactly_once(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """Each operation performs its repository mutations and commits once."""
    investigation_service, factory = service
    investigation_id = uuid4()
    unit = factory.configure(FakeUnitOfWork())
    unit.investigations.visible = state_factory()
    unit.investigations.visible.investigation_id = investigation_id

    await investigation_service.update_investigation_status(
        investigation_id, InvestigationStatus.RUNNING
    )
    evidence_unit = factory.configure(FakeUnitOfWork())
    evidence_unit.investigations.visible = state_factory()
    evidence_unit.investigations.visible.investigation_id = investigation_id
    await investigation_service.record_evidence(evidence_factory(investigation_id))

    assert evidence_unit.commits == 1
    # Repositories never own the transaction lifecycle: only the UnitOfWork
    # exit commits, so exactly one commit is recorded per operation.
    assert all(unit.commits == 1 for unit in factory.units)


@pytest.mark.asyncio
async def test_repository_failure_rolls_back_and_propagates(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """A repository failure propagates and rolls back the unit of work."""
    investigation_service, factory = service
    unit = factory.configure(FakeUnitOfWork())
    unit.investigations.create_error = RuntimeError("investigation write failed")

    with pytest.raises(RuntimeError, match="investigation write failed"):
        await investigation_service.create_investigation(state_factory())

    assert unit.commits == 0
    assert unit.rollbacks == 1
    assert unit.audit_events.events == []


@pytest.mark.asyncio
async def test_audit_failure_rolls_back_same_transaction(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """An audit dependency failure rolls back the same transaction."""
    investigation_service, factory = service
    unit = factory.configure(FakeUnitOfWork())
    unit.audit_events.append_error = RuntimeError("audit append failed")

    with pytest.raises(RuntimeError, match="audit append failed"):
        await investigation_service.create_investigation(state_factory())

    assert unit.commits == 0
    assert unit.rollbacks == 1
    assert len(unit.investigations.calls) == 1  # mutation was rolled back


@pytest.mark.asyncio
async def test_duplicate_investigation_identity_propagates_typed_error(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """A duplicate investigation identity surfaces the typed conflict."""
    investigation_service, factory = service
    duplicate_id = uuid4()
    unit = factory.configure(FakeUnitOfWork())
    unit.investigations.create_error = InvestigationDuplicateIdentityError(duplicate_id)

    with pytest.raises(InvestigationDuplicateIdentityError):
        await investigation_service.create_investigation(state_factory())

    assert unit.rollbacks == 1


@pytest.mark.asyncio
async def test_valid_status_transition_updates_and_audits(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """A confirmed transition returns the database version and audit event."""
    investigation_service, factory = service
    investigation_id = uuid4()
    unit = factory.configure(FakeUnitOfWork())
    unit.investigations.visible = state_factory()
    unit.investigations.visible.investigation_id = investigation_id
    unit.investigations.update_result = InvestigationWriteResult(
        investigation_id, 7, BatchOutcome.UPDATED
    )

    result = await investigation_service.update_investigation_status(
        investigation_id, InvestigationStatus.RUNNING, expected_version=6
    )

    assert result.investigation_id == investigation_id
    assert result.version == 7
    assert result.outcome is BatchOutcome.UPDATED
    assert unit.audit_events.events[0].action == (
        AuditAction.INVESTIGATION_UPDATE_STATUS
    )


@pytest.mark.asyncio
async def test_invalid_status_transition_rejected_before_mutation(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """An invalid transition is rejected before any database mutation."""
    investigation_service, factory = service
    investigation_id = uuid4()
    unit = factory.configure(FakeUnitOfWork())
    unit.investigations.visible = state_factory(status=InvestigationStatus.RUNNING)
    unit.investigations.visible.investigation_id = investigation_id

    with pytest.raises(InvalidInvestigationStatusTransitionError):
        await investigation_service.update_investigation_status(
            investigation_id, InvestigationStatus.PENDING
        )

    assert "update_status" not in unit.investigations.operations()
    assert unit.audit_events.events == []
    assert unit.commits == 0 and unit.rollbacks == 1


@pytest.mark.asyncio
async def test_status_update_of_unknown_investigation_raises_not_found(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """A missing investigation raises the typed not-found error."""
    investigation_service, factory = service
    unit = factory.configure(FakeUnitOfWork())

    with pytest.raises(InvestigationNotFoundError):
        await investigation_service.update_investigation_status(
            uuid4(), InvestigationStatus.RUNNING
        )

    assert "update_status" not in unit.investigations.operations()
    assert unit.rollbacks == 1


@pytest.mark.asyncio
async def test_stale_expected_version_conflict_rolls_back(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """A stale expected version propagates the typed conflict and rolls back."""
    investigation_service, factory = service
    investigation_id = uuid4()
    unit = factory.configure(FakeUnitOfWork())
    unit.investigations.visible = state_factory()
    unit.investigations.visible.investigation_id = investigation_id
    unit.investigations.update_error = InvestigationVersionConflictError(
        investigation_id, 4
    )

    with pytest.raises(InvestigationVersionConflictError):
        await investigation_service.update_investigation_status(
            investigation_id,
            InvestigationStatus.RUNNING,
            expected_version=4,
        )

    assert unit.commits == 0 and unit.rollbacks == 1


@pytest.mark.asyncio
async def test_record_evidence_appends_observation_and_audit(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """Evidence records for an existing investigation with its audit event."""
    investigation_service, factory = service
    investigation_id = uuid4()
    unit = factory.configure(FakeUnitOfWork())
    unit.investigations.visible = state_factory()
    unit.investigations.visible.investigation_id = investigation_id
    evidence = evidence_factory(investigation_id)

    recorded = await investigation_service.record_evidence(evidence, actor_id=uuid4())

    assert recorded.id is not None
    assert unit.commits == 1
    event = unit.audit_events.events[0]
    assert event.action == AuditAction.EVIDENCE_RECORD
    assert event.object_type == "evidence"
    assert event.object_id == recorded.id
    assert event.metadata == {"investigation_id": str(investigation_id)}


@pytest.mark.asyncio
async def test_record_evidence_requires_existing_investigation(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """Evidence for an unknown investigation is rejected without mutation."""
    investigation_service, factory = service
    unit = factory.configure(FakeUnitOfWork())
    evidence = evidence_factory()

    with pytest.raises(InvestigationNotFoundError):
        await investigation_service.record_evidence(evidence)

    assert unit.evidence.calls == []
    assert unit.rollbacks == 1


@pytest.mark.asyncio
async def test_duplicate_evidence_identity_propagates_typed_error(
    service: tuple[InvestigationPersistenceService, FakeUnitOfWorkFactory],
) -> None:
    """A duplicate evidence identity never becomes an update."""
    investigation_service, factory = service
    unit = factory.configure(FakeUnitOfWork())
    unit.investigations.visible = state_factory()
    unit.evidence.insert_error = EvidenceDuplicateIdentityError(uuid4())
    evidence = evidence_factory(unit.investigations.visible.investigation_id)

    with pytest.raises(EvidenceDuplicateIdentityError):
        await investigation_service.record_evidence(evidence)

    assert unit.commits == 0 and unit.rollbacks == 1


def test_malformed_evidence_rejected_before_repository_mutation() -> None:
    """Timezone-naive evidence timestamps are rejected at the domain boundary."""
    with pytest.raises(ValidationError, match="timezone-aware"):
        Evidence(
            investigation_id=uuid4(),
            type=EvidenceType.DNS,
            subject=EntityRef(type=EntityType.DOMAIN, value="example.com"),
            source="urn:ati:source:google_public_dns",
            retrieved_at=datetime(2026, 1, 2, 3, 4, 5),
        )


def test_service_boundary_requires_no_provider_or_agent_objects(
    uow_factory: FakeUnitOfWorkFactory,
) -> None:
    """Constructing the service requires only a unit-of-work factory."""
    service = InvestigationPersistenceService(uow_factory)
    assert service is not None
