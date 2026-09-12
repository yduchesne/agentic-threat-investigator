# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapter for versioned, insert-only InvestigationReport outputs.

The database owns identity conflict detection, version allocation, immutable
CREATE history, the current-Assessment revalidation under the parent
Investigation row lock, and the external root FK provenance integrity. This
adapter serializes the domain model into the resource-specific flat composite
input arrays, invokes the versioned stored functions, and deserializes the
authoritative rows without ever mutating tables directly.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    InvestigationReportDuplicateIdentityError,
    InvestigationReportRepository,
    ReportCurrentReferenceConflictError,
    ReportReferenceInvalidError,
    StaleReportInputError,
    enforce_report_collection_bounds,
)
from agentic_threat_investigator.domain.assessment import (
    EvidenceSupport,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
)

from .errors import (
    SQLSTATE_INVESTIGATION_NOT_FOUND,
    SQLSTATE_REPORT_ASSESSMENT_INVALID,
    SQLSTATE_REPORT_CURRENT_CONFLICT,
    SQLSTATE_REPORT_DUPLICATE,
    SQLSTATE_REPORT_HARD_LIMIT,
    SQLSTATE_REPORT_NOT_FOUND,
    SQLSTATE_REPORT_REFERENCE_INVALID,
    SQLSTATE_REPORT_STALE_INPUT,
    SQLSTATE_REPORT_STRUCTURE_INVALID,
    SQLSTATE_VERSION_CONFLICT,
    sqlstate,
)
from .models import InvestigationReportRow


def raise_report_write_error(
    error: DBAPIError, report_id: UUID, investigation_id: UUID
) -> None:
    """Map a stored-function SQLSTATE to the typed application error, or re-raise.

    Used by the repository adapter and by the integration helper that invokes
    the stored function directly, so both paths surface the same typed
    taxonomy instead of raw DBAPI errors.
    """
    state = sqlstate(error)
    if state == SQLSTATE_REPORT_DUPLICATE:
        raise InvestigationReportDuplicateIdentityError(report_id) from error
    if state == SQLSTATE_INVESTIGATION_NOT_FOUND:
        raise InvestigationNotFoundError(str(investigation_id)) from error
    if state == SQLSTATE_REPORT_STALE_INPUT:
        raise StaleReportInputError(investigation_id, report_id) from error
    if state in (
        SQLSTATE_REPORT_STRUCTURE_INVALID,
        SQLSTATE_REPORT_ASSESSMENT_INVALID,
        SQLSTATE_REPORT_HARD_LIMIT,
    ):
        raise ValueError(
            f"report {report_id} structure or assessment is invalid for "
            f"investigation {investigation_id}"
        ) from error
    if state == SQLSTATE_REPORT_REFERENCE_INVALID:
        raise ReportReferenceInvalidError(investigation_id, report_id) from error
    # Re-raise the active DBAPI exception when no SQLSTATE matched. This
    # helper is only ever invoked from inside an except DBAPIError handler.
    raise error


def _narrative_rows(
    report: InvestigationReport,
) -> tuple[
    list[tuple[int, str]],
    list[tuple[int, int, str, UUID | None, int | None, UUID | None, UUID | None]],
]:
    """Serialize executive-summary statements and their flat support rows."""
    narrative: list[tuple[int, str]] = []
    support: list[
        tuple[int, int, str, UUID | None, int | None, UUID | None, UUID | None]
    ] = []
    for ordinal, statement in enumerate(report.executive_summary, start=1):
        narrative.append((ordinal, statement.text))
        for support_ordinal, ref in enumerate(statement.support, start=1):
            if isinstance(ref, AssessmentFindingRef):
                support.append(
                    (
                        ordinal,
                        support_ordinal,
                        ref.kind,
                        ref.assessment_id,
                        ref.finding_ordinal,
                        None,
                        None,
                    )
                )
            else:
                support.append(
                    (
                        ordinal,
                        support_ordinal,
                        ref.kind,
                        None,
                        None,
                        ref.research_result_id,
                        ref.research_claim_id,
                    )
                )
    return narrative, support


def _finding_rows(
    report: InvestigationReport,
) -> tuple[
    list[tuple[int, str, str, str, str]],
    list[tuple[int, int, str, UUID | None, UUID | None]],
]:
    """Serialize finding snapshots and their flat support rows."""
    findings: list[tuple[int, str, str, str, str]] = []
    support: list[tuple[int, int, str, UUID | None, UUID | None]] = []
    for finding in report.findings:
        findings.append(
            (
                finding.assessment_finding_ordinal,
                finding.category.value,
                finding.disposition.value,
                finding.statement,
                finding.confidence.value,
            )
        )
        for support_ordinal, item in enumerate(finding.support, start=1):
            if isinstance(item, EvidenceSupport):
                support.append(
                    (
                        finding.assessment_finding_ordinal,
                        support_ordinal,
                        item.kind,
                        item.evidence_id,
                        None,
                    )
                )
            else:
                support.append(
                    (
                        finding.assessment_finding_ordinal,
                        support_ordinal,
                        item.kind,
                        None,
                        item.relationship_observation_id,
                    )
                )
    return findings, support


def _research_rows(
    report: InvestigationReport,
) -> list[tuple[UUID, UUID, UUID, str, list[UUID], Jsonb]]:
    """Serialize research snapshots with their persisted citation JSONB."""
    rows: list[tuple[UUID, UUID, UUID, str, list[UUID], Jsonb]] = []
    for snapshot in report.research_context:
        rows.append(
            (
                snapshot.research_result_id,
                snapshot.research_claim_id,
                snapshot.subject_entity_id,
                snapshot.claim_text,
                list(snapshot.citation_ids),
                Jsonb(
                    [
                        citation.model_dump(mode="json")
                        for citation in snapshot.citations
                    ]
                ),
            )
        )
    return rows


def _report_from_row(row: InvestigationReportRow) -> InvestigationReport:
    """Rebuild the domain report from its authoritative persisted row."""
    return InvestigationReport.model_validate(
        {
            "id": row.id,
            "investigation_id": row.investigation_id,
            "assessment_id": row.assessment_id,
            "verdict": row.verdict,
            "confidence": row.confidence,
            "title": row.title,
            "executive_summary": thaw_json(row.executive_summary),
            "findings": thaw_json(row.findings),
            "research_context": thaw_json(row.research_context),
            "limitations": tuple(row.limitations),
            "unresolved_questions": tuple(row.unresolved_questions),
            "recommended_next_steps": tuple(row.recommended_next_steps),
            "source_evidence_ids": tuple(row.source_evidence_ids),
            "source_relationship_observation_ids": tuple(
                row.source_relationship_observation_ids
            ),
            "source_research_result_ids": tuple(row.source_research_result_ids),
            "version": row.version,
            "created_at": row.created_at,
            "deleted_at": row.deleted_at,
            "deleted_by_actor_id": row.deleted_by_actor_id,
        }
    )


report_from_row = _report_from_row
"""Public read mapping shared with the PR 23B report query layer."""


class PostgresInvestigationReportRepository(InvestigationReportRepository):
    """Persist reports through the caller's transaction."""

    def __init__(self, session: AsyncSession, batch_size: int = 100) -> None:
        """Bind the session and the configured report batch limit."""
        if batch_size < 1:
            raise ValueError("report batch size must be positive")
        self.session = session
        self._batch_size = batch_size

    async def append(
        self,
        report: InvestigationReport,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> InvestigationReport:
        """Append a new report version through the authoritative function.

        A duplicate identity, a stale Assessment, an oversized candidate, or
        any malformed or cross-investigation reference surfaces as a typed
        error and mutates nothing; the surrounding UnitOfWork rolls back.
        """
        # Defense in depth for callers that reach the repository without the
        # application service: enforce the bounds before SQL serialization
        # and execution.
        enforce_report_collection_bounds(report, self._batch_size)
        report_id = report.id or uuid4()
        narrative, narrative_support = _narrative_rows(report)
        findings, finding_support = _finding_rows(report)
        research = _research_rows(report)
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, created_at
                    FROM ati.append_investigation_report(
                        :id, :investigation_id, :assessment_id,
                        :verdict, :confidence, :title,
                        :executive_summary, :narrative_support,
                        :findings, :finding_support, :research_context,
                        :limitations, :unresolved, :next_steps,
                        :source_evidence_ids, :source_observation_ids,
                        :source_research_ids, :actor_id, :request_id)
                """),
                {
                    "id": report_id,
                    "investigation_id": report.investigation_id,
                    "assessment_id": report.assessment_id,
                    "verdict": report.verdict.value,
                    "confidence": report.confidence.value,
                    "title": report.title,
                    "executive_summary": narrative,
                    "narrative_support": narrative_support,
                    "findings": findings,
                    "finding_support": finding_support,
                    "research_context": research,
                    "limitations": list(report.limitations),
                    "unresolved": list(report.unresolved_questions),
                    "next_steps": list(report.recommended_next_steps),
                    "source_evidence_ids": list(report.source_evidence_ids),
                    "source_observation_ids": list(
                        report.source_relationship_observation_ids
                    ),
                    "source_research_ids": list(report.source_research_result_ids),
                    "actor_id": actor_id,
                    "request_id": request_id,
                },
            )
        except DBAPIError as error:
            raise_report_write_error(error, report_id, report.investigation_id)
        written_id, version, created_at = result.one()
        return report.model_copy(
            update={
                "id": written_id,
                "version": int(version),
                "created_at": created_at,
            }
        )

    async def get_by_id(
        self, report_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationReport | None:
        """Return the visible report with its exact nested snapshots."""
        query = select(InvestigationReportRow).where(
            InvestigationReportRow.id == report_id
        )
        if not include_deleted:
            query = query.where(InvestigationReportRow.deleted_at.is_(None))
        row = (await self.session.execute(query)).scalar_one_or_none()
        return None if row is None else _report_from_row(row)

    async def soft_delete(
        self,
        report_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationReport:
        """Soft-delete the report through the authoritative function.

        Deletion is rejected with the typed current-reference conflict while
        any visible Investigation still points at the report.
        """
        try:
            result = await self.session.execute(
                text(
                    "SELECT id, version FROM ati.soft_delete_investigation_report("
                    ":id, :actor, :expected, :request_id)"
                ),
                {
                    "id": report_id,
                    "actor": actor_id,
                    "expected": expected_version,
                    "request_id": request_id,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_REPORT_NOT_FOUND:
                raise LookupError("report not found") from error
            if state == SQLSTATE_VERSION_CONFLICT:
                raise ValueError("stale expected_version") from error
            if state == SQLSTATE_REPORT_CURRENT_CONFLICT:
                raise ReportCurrentReferenceConflictError(report_id) from error
            raise
        written_id, _version = result.one()
        row = await self.session.get(InvestigationReportRow, written_id)
        if row is None:  # pragma: no cover - function and transaction are atomic
            raise RuntimeError("report delete returned no row")
        return _report_from_row(row)
