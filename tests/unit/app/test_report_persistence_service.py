# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for InvestigationReportPersistenceService atomicity (PR 23B)."""

from __future__ import annotations

from typing import Self, cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.persistence.repositories import (
    AuditEventRepository,
    BatchOutcome,
    InvestigationReportRepository,
    InvestigationRepository,
    InvestigationWriteResult,
    ReportCollectionLimitExceededError,
    UnitOfWork,
)
from agentic_threat_investigator.app.report_writer.persistence import (
    InvestigationReportPersistenceService,
)
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.audit import AuditEvent
from agentic_threat_investigator.domain.report import (
    InvestigationReport,
    ReportFindingSnapshot,
    ReportNarrativeStatement,
)


def _report() -> InvestigationReport:
    """Build one canonical report candidate."""
    evidence_id = uuid4()
    return InvestigationReport(
        investigation_id=uuid4(),
        assessment_id=uuid4(),
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        title="Canonical report title",
        findings=(
            ReportFindingSnapshot(
                assessment_finding_ordinal=1,
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="Reputation evidence indicates malicious activity.",
                confidence=AssessmentConfidence.HIGH,
                support=(EvidenceSupport(kind="evidence", evidence_id=evidence_id),),
            ),
        ),
        limitations=("a limitation",),
        source_evidence_ids=(evidence_id,),
    )


class FakeReportRepository:
    """Records appends and serves the authoritative persisted report."""

    def __init__(self) -> None:
        self.appended: list[InvestigationReport] = []
        self.deleted: list[InvestigationReport] = []
        self.fail_append: Exception | None = None
        self.fail_delete: Exception | None = None

    async def append(
        self,
        report: InvestigationReport,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> InvestigationReport:
        """Record the append and return it with stamped metadata."""
        if self.fail_append is not None:
            raise self.fail_append
        self.appended.append(report)
        return report.model_copy(update={"id": uuid4(), "version": 3})

    async def get_by_id(
        self, report_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationReport | None:
        """Return the last appended report for the recorded identity."""
        if not self.appended:
            return None
        return self.appended[-1].model_copy(update={"id": report_id, "version": 3})

    async def soft_delete(
        self,
        report_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationReport:
        """Record the deletion and return the post-deletion state."""
        if self.fail_delete is not None:
            raise self.fail_delete
        deleted = self.appended[-1].model_copy(
            update={"id": report_id, "deleted_at": None}
        )
        self.deleted.append(deleted)
        return deleted


class FakeInvestigationRepository:
    """Records every report-pointer update."""

    def __init__(self) -> None:
        self.pointer_updates: list[tuple[UUID, UUID, int | None]] = []
        self.fail_pointer: Exception | None = None

    async def update_report_reference(
        self,
        investigation_id: UUID,
        report_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Record the pointer update."""
        if self.fail_pointer is not None:
            raise self.fail_pointer
        self.pointer_updates.append((investigation_id, report_id, expected_version))
        return InvestigationWriteResult(investigation_id, 11, BatchOutcome.UPDATED)


class FakeAuditRepository:
    """Records every appended audit event."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Record the event."""
        self.events.append(event)
        return event


class FakeUnitOfWork(UnitOfWork):
    """In-memory transaction boundary tracking commit/rollback."""

    def __init__(
        self,
        reports: FakeReportRepository,
        investigations: FakeInvestigationRepository,
        audit: FakeAuditRepository,
    ) -> None:
        self.investigation_reports = cast(InvestigationReportRepository, reports)
        self.investigations = cast(InvestigationRepository, investigations)
        self.audit_events = cast(AuditEventRepository, audit)
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


def _harness() -> tuple[
    InvestigationReportPersistenceService,
    FakeReportRepository,
    FakeInvestigationRepository,
    FakeAuditRepository,
    FakeUnitOfWork,
]:
    """Build the persistence service bound to observable fakes."""
    reports = FakeReportRepository()
    investigations = FakeInvestigationRepository()
    audit = FakeAuditRepository()
    uow = FakeUnitOfWork(reports, investigations, audit)
    service = InvestigationReportPersistenceService(lambda: uow)
    return service, reports, investigations, audit, uow


@pytest.mark.asyncio
async def test_persist_appends_pointer_and_audit_atomically() -> None:
    """Append + pointer update + audit event happen in one commit."""
    service, reports, investigations, audit, uow = _harness()
    report = _report()

    persisted = await service.persist(report)

    assert len(reports.appended) == 1
    assert len(investigations.pointer_updates) == 1
    assert investigations.pointer_updates[0][0] == report.investigation_id
    assert investigations.pointer_updates[0][1] == persisted.id
    assert len(audit.events) == 1
    assert audit.events[0].action == "urn:ati:action:report:create"
    assert uow.commits >= 1
    assert uow.rollbacks == 0
    assert persisted.version == 3


@pytest.mark.asyncio
async def test_append_failure_rolls_back_pointer() -> None:
    """A failed append rolls back with no pointer update committed."""
    service, reports, investigations, audit, uow = _harness()
    reports.fail_append = LookupError("stale report input")

    with pytest.raises(LookupError, match="stale report input"):
        await service.persist(_report())

    assert investigations.pointer_updates == []
    assert audit.events == []
    assert uow.rollbacks == 1


@pytest.mark.asyncio
async def test_pointer_failure_rolls_back_report() -> None:
    """A failed pointer update rolls back the report insert."""
    service, reports, investigations, audit, uow = _harness()
    investigations.fail_pointer = ValueError("version conflict")

    with pytest.raises(ValueError, match="version conflict"):
        await service.persist(_report())

    assert len(reports.appended) == 1
    assert audit.events == []
    assert uow.rollbacks == 1


@pytest.mark.asyncio
async def test_oversized_collection_rejected_before_uow() -> None:
    """Oversized candidate collections fail before any UnitOfWork entry."""
    service, reports, investigations, audit, uow = _harness()
    report = _report().model_copy(update={"executive_summary": _summary(101)})
    # Reject via the shared bound checker with a small configured limit.
    service = InvestigationReportPersistenceService(lambda: uow, batch_size=100)
    with pytest.raises(ReportCollectionLimitExceededError):
        await service.persist(report)
    assert reports.appended == []


def _summary(count: int) -> tuple[ReportNarrativeStatement, ...]:
    """Build many narrative statements for the bound test."""

    from agentic_threat_investigator.domain.report import AssessmentFindingRef

    ref = AssessmentFindingRef(
        kind="assessment_finding", assessment_id=uuid4(), finding_ordinal=1
    )
    return tuple(
        ReportNarrativeStatement(text=f"statement {i}", support=(ref,))
        for i in range(count)
    )
