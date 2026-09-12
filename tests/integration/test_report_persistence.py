# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23B report persistence PostgreSQL integration tests (23B-I01..I08)."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationReportDuplicateIdentityError,
    ReportCurrentReferenceConflictError,
    StaleReportInputError,
)
from agentic_threat_investigator.app.report_writer.persistence import (
    InvestigationReportPersistenceService,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.report import (
    InvestigationReport,
    ReportFindingSnapshot,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.query_fixtures import (
    evidence_factory,
    seed_entity,
    seed_investigation,
)

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

UOW_FACTORY = Callable[[], PostgresUnitOfWork]


async def seed_assessment(
    uow_factory: UOW_FACTORY,
    investigation_id: UUID,
    evidence_id: UUID,
    *,
    verdict: Verdict = Verdict.MALICIOUS,
    confidence: AssessmentConfidence = AssessmentConfidence.HIGH,
) -> Assessment:
    """Persist one Assessment for the investigation through the production seam."""
    assessment = Assessment(
        investigation_id=investigation_id,
        verdict=verdict,
        confidence=confidence,
        summary="Canonical assessment summary.",
        analyzed_evidence_ids=(evidence_id,),
        findings=(
            AnalyticalFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="Reputation evidence indicates malicious activity.",
                confidence=AssessmentConfidence.HIGH,
                support=(EvidenceSupport(kind="evidence", evidence_id=evidence_id),),
            ),
        ),
        limitations=("a limitation",),
    )
    persisted = await AssessmentPersistenceService(uow_factory).persist_assessment(
        assessment
    )
    if persisted.id is None:  # pragma: no cover - service assigns identity
        raise RuntimeError("assessment persistence returned no identity")
    return persisted


def report_candidate(
    investigation_id: UUID, assessment: Assessment, *, title: str = "Canonical report"
) -> InvestigationReport:
    """Build one authoritative report candidate from a seeded Assessment."""
    if assessment.id is None:  # pragma: no cover - persisted rows carry it
        raise RuntimeError("assessment has no identity")
    evidence_ids = list(assessment.analyzed_evidence_ids)
    return InvestigationReport(
        investigation_id=investigation_id,
        assessment_id=assessment.id,
        verdict=assessment.verdict,
        confidence=assessment.confidence,
        title=title,
        findings=tuple(
            ReportFindingSnapshot(
                assessment_finding_ordinal=ordinal,
                category=finding.category,
                disposition=finding.disposition,
                statement=finding.statement,
                confidence=finding.confidence,
                support=finding.support,
            )
            for ordinal, finding in enumerate(assessment.findings, start=1)
        ),
        limitations=assessment.limitations,
        unresolved_questions=assessment.unresolved_questions,
        recommended_next_steps=assessment.recommended_next_steps,
        source_evidence_ids=tuple(evidence_ids),
    )


async def seed_report_context(
    uow_factory: UOW_FACTORY,
) -> tuple[UUID, UUID, Assessment]:
    """Seed one investigation with evidence and a current Assessment."""
    async with uow_factory() as uow:
        entity_id = await seed_entity(uow)
        investigation_id = await seed_investigation(uow, root_entity_ids=(entity_id,))
        evidence: Evidence = await uow.evidence.insert(
            evidence_factory(investigation_id, entity_id)
        )
        if evidence.id is None:  # pragma: no cover - insert assigns identity
            raise RuntimeError("evidence insert returned no identity")
        evidence_id = evidence.id
    assessment = await seed_assessment(uow_factory, investigation_id, evidence_id)
    return investigation_id, evidence_id, assessment


async def _history_rows(
    uow: PostgresUnitOfWork, object_type: str, object_id: UUID
) -> list[dict[str, object]]:
    """Return the domain-history rows for one object."""
    assert uow.session is not None
    result = await uow.session.execute(
        text(
            "SELECT object_type, object_id, version, operation, "
            "investigation_id FROM ati.domain_object_history "
            "WHERE object_type = :object_type AND object_id = :object_id "
            "ORDER BY version"
        ),
        {"object_type": object_type, "object_id": object_id},
    )
    return [dict(row) for row in result.mappings()]


async def test_i01_append_report_row_version_and_history(
    uow_factory: UOW_FACTORY,
) -> None:
    """23B-I01: one append creates one row, DB version, and CREATE history."""
    investigation_id, evidence_id, assessment = await seed_report_context(uow_factory)
    candidate = report_candidate(investigation_id, assessment)
    service = InvestigationReportPersistenceService(uow_factory)

    persisted = await service.persist(candidate)

    assert persisted.id is not None
    assert persisted.version is not None and persisted.version >= 1
    assert persisted.created_at is not None
    assert persisted.investigation_id == investigation_id
    assert persisted.assessment_id == assessment.id
    assert persisted.verdict is assessment.verdict
    assert persisted.confidence is assessment.confidence
    assert persisted.title == "Canonical report"
    assert persisted.source_evidence_ids == (evidence_id,)

    async with uow_factory() as uow:
        history = await _history_rows(uow, "investigation_report", persisted.id)
    assert len(history) == 1
    assert history[0]["operation"] == "CREATE"
    assert history[0]["investigation_id"] == investigation_id
    assert history[0]["version"] == persisted.version

    # The authoritative row round-trips exactly.
    assert persisted.executive_summary == candidate.executive_summary
    assert persisted.findings == candidate.findings
    assert persisted.research_context == candidate.research_context


async def test_i02_pointer_update_atomicity(uow_factory: UOW_FACTORY) -> None:
    """23B-I02: append and pointer update commit atomically with versions."""
    investigation_id, _evidence_id, assessment = await seed_report_context(uow_factory)
    service = InvestigationReportPersistenceService(uow_factory)

    async with uow_factory() as uow:
        before = await uow.investigations.get_by_id(investigation_id)
        assert before is not None
        version_before = before.version

    persisted = await service.persist(report_candidate(investigation_id, assessment))

    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(investigation_id)
        assert state is not None
        assert state.report_id == persisted.id
        assert state.version == (version_before or 0) + 1
        inv_history = await _history_rows(uow, "investigation", investigation_id)
        assert any(row["operation"] == "UPDATE" for row in inv_history)


async def test_i03_second_report_creates_new_version(uow_factory: UOW_FACTORY) -> None:
    """23B-I03: a second generation appends a higher version and moves pointer."""
    investigation_id, _evidence_id, assessment = await seed_report_context(uow_factory)
    service = InvestigationReportPersistenceService(uow_factory)

    first = await service.persist(report_candidate(investigation_id, assessment))
    second = await service.persist(
        report_candidate(investigation_id, assessment, title="Second report")
    )
    assert first.id is not None

    assert second.version is not None and first.version is not None
    assert second.version > first.version
    assert second.title == "Second report"
    # The first row is unchanged.
    async with uow_factory() as uow:
        first_reloaded = await uow.investigation_reports.get_by_id(first.id)
        assert first_reloaded is not None
        assert first_reloaded.title == "Canonical report"
        assert first_reloaded.version == first.version
        state = await uow.investigations.get_by_id(investigation_id)
        assert state is not None
        assert state.report_id == second.id


async def test_i04_stale_assessment_rejection(uow_factory: UOW_FACTORY) -> None:
    """23B-I04: appending against a superseded Assessment fails typed."""
    investigation_id, evidence_id, assessment_a = await seed_report_context(uow_factory)
    # Advance the Investigation to Assessment B.
    await seed_assessment(
        uow_factory,
        investigation_id,
        evidence_id,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
    )
    service = InvestigationReportPersistenceService(uow_factory)

    with pytest.raises(StaleReportInputError):
        await service.persist(report_candidate(investigation_id, assessment_a))

    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(investigation_id)
        assert state is not None
        assert state.report_id is None
        assert uow.session is not None
        assert assessment_a.id is not None
        rows = await uow.session.execute(
            text(
                "SELECT count(*) AS n FROM ati.investigation_report "
                "WHERE assessment_id = :assessment_id"
            ),
            {"assessment_id": assessment_a.id},
        )
        assert rows.scalar_one() == 0
        assert assessment_a.id is not None
        history = await _history_rows(uow, "investigation_report", assessment_a.id)
        assert history == []


async def test_i05_cross_investigation_assessment_rejected(
    uow_factory: UOW_FACTORY,
) -> None:
    """23B-I05: a report referencing another Investigation's Assessment fails."""
    investigation_a, _evidence_a, _assessment_a = await seed_report_context(uow_factory)
    _investigation_b, _evidence_b, assessment_b = await seed_report_context(uow_factory)
    service = InvestigationReportPersistenceService(uow_factory)

    candidate = report_candidate(investigation_a, assessment_b)
    with pytest.raises(ValueError):
        await service.persist(candidate)


async def test_i06_report_history_shape(uow_factory: UOW_FACTORY) -> None:
    """23B-I06: the CREATE history row carries exact identities."""
    investigation_id, _evidence_id, assessment = await seed_report_context(uow_factory)
    service = InvestigationReportPersistenceService(uow_factory)

    persisted = await service.persist(report_candidate(investigation_id, assessment))
    assert persisted.id is not None

    async with uow_factory() as uow:
        history = await _history_rows(uow, "investigation_report", persisted.id)
    assert len(history) == 1
    row = history[0]
    assert row["object_type"] == "investigation_report"
    assert row["object_id"] == persisted.id
    assert row["version"] == persisted.version
    assert row["operation"] == "CREATE"
    assert row["investigation_id"] == investigation_id


async def test_i07_superseded_report_soft_delete(uow_factory: UOW_FACTORY) -> None:
    """23B-I07: a superseded report may be soft-deleted with DELETE history."""
    investigation_id, _evidence_id, assessment = await seed_report_context(uow_factory)
    service = InvestigationReportPersistenceService(uow_factory)

    first = await service.persist(report_candidate(investigation_id, assessment))
    second = await service.persist(
        report_candidate(investigation_id, assessment, title="Second report")
    )
    assert first.id is not None and second.id is not None

    deleted = await service.soft_delete(first.id)
    assert deleted.deleted_at is not None

    async with uow_factory() as uow:
        hidden = await uow.investigation_reports.get_by_id(first.id)
        assert hidden is None
        visible = await uow.investigation_reports.get_by_id(
            first.id, include_deleted=True
        )
        assert visible is not None
        state = await uow.investigations.get_by_id(investigation_id)
        assert state is not None
        assert state.report_id == second.id
        history = await _history_rows(uow, "investigation_report", first.id)
        operations = [row["operation"] for row in history]
        assert operations == ["CREATE", "DELETE"]


async def test_i08_current_report_delete_rejected(uow_factory: UOW_FACTORY) -> None:
    """23B-I08: deleting the current report is rejected with no mutation."""
    investigation_id, _evidence_id, assessment = await seed_report_context(uow_factory)
    service = InvestigationReportPersistenceService(uow_factory)

    persisted = await service.persist(report_candidate(investigation_id, assessment))
    assert persisted.id is not None

    with pytest.raises(ReportCurrentReferenceConflictError):
        await service.soft_delete(persisted.id)

    async with uow_factory() as uow:
        visible = await uow.investigation_reports.get_by_id(persisted.id)
        assert visible is not None
        assert visible.deleted_at is None
        history = await _history_rows(uow, "investigation_report", persisted.id)
        assert [row["operation"] for row in history] == ["CREATE"]


async def test_duplicate_report_identity_rejected(uow_factory: UOW_FACTORY) -> None:
    """A duplicate report identity is a typed conflict, never an update."""
    investigation_id, _evidence_id, assessment = await seed_report_context(uow_factory)
    async with uow_factory() as uow:
        candidate = report_candidate(investigation_id, assessment)
        first = await uow.investigation_reports.append(candidate)
        dup = candidate.model_copy(update={"id": first.id})
        with pytest.raises(InvestigationReportDuplicateIdentityError):
            await uow.investigation_reports.append(dup)
