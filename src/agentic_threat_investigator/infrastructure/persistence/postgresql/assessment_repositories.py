# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapter for versioned, insert-only Assessment persistence.

The database owns identity conflict detection, version allocation, immutable
CREATE history, cross-investigation support validation under the parent
Investigation row lock, and the external FK provenance integrity. This
adapter serializes the domain model into the resource-specific composite
input arrays, invokes the versioned stored functions, and deserializes the
authoritative rows without ever mutating tables directly.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.assessment_provenance import (
    AssessmentEvidenceReferenceError,
    AssessmentInvestigationMismatchError,
    AssessmentProvenanceMismatchError,
    AssessmentRelationshipObservationReferenceError,
)
from agentic_threat_investigator.app.persistence.repositories import (
    AssessmentCurrentReferenceConflictError,
    AssessmentDuplicateIdentityError,
    AssessmentRepository,
    InvestigationNotFoundError,
    enforce_assessment_collection_bounds,
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

from .errors import (
    SQLSTATE_ASSESSMENT_CURRENT_CONFLICT,
    SQLSTATE_ASSESSMENT_DUPLICATE,
    SQLSTATE_ASSESSMENT_DUPLICATE_EVIDENCE,
    SQLSTATE_ASSESSMENT_DUPLICATE_SUPPORT,
    SQLSTATE_ASSESSMENT_EVIDENCE_INVALID,
    SQLSTATE_ASSESSMENT_GRAPH_CONCURRENT,
    SQLSTATE_ASSESSMENT_HARD_LIMIT,
    SQLSTATE_ASSESSMENT_INVESTIGATION_MISMATCH,
    SQLSTATE_ASSESSMENT_NOT_FOUND,
    SQLSTATE_ASSESSMENT_OBSERVATION_INVALID,
    SQLSTATE_ASSESSMENT_REFERENCE_INVALID,
    SQLSTATE_ASSESSMENT_STRUCTURE_INVALID,
    SQLSTATE_INVESTIGATION_NOT_FOUND,
    SQLSTATE_VERSION_CONFLICT,
    sqlstate,
)
from .models import AssessmentFindingRow, AssessmentFindingSupportRow, AssessmentRow


def raise_assessment_write_error(
    error: DBAPIError, assessment_id: UUID, investigation_id: UUID
) -> None:
    """Map a stored-function SQLSTATE to the typed application error, or re-raise.

    Used by the repository adapter and by the integration helper that invokes
    the stored function directly with raw composite arrays, so both paths
    surface the same typed taxonomy instead of raw DBAPI errors.
    """
    state = sqlstate(error)
    if state == SQLSTATE_ASSESSMENT_DUPLICATE:
        raise AssessmentDuplicateIdentityError(assessment_id) from error
    if state == SQLSTATE_INVESTIGATION_NOT_FOUND:
        raise InvestigationNotFoundError(str(investigation_id)) from error
    if state in (
        SQLSTATE_ASSESSMENT_DUPLICATE_EVIDENCE,
        SQLSTATE_ASSESSMENT_EVIDENCE_INVALID,
    ):
        raise AssessmentEvidenceReferenceError(
            f"assessment evidence reference is invalid: {assessment_id}"
        ) from error
    if state == SQLSTATE_ASSESSMENT_DUPLICATE_SUPPORT:
        raise AssessmentProvenanceMismatchError(
            f"assessment finding support is duplicated: {assessment_id}"
        ) from error
    if state == SQLSTATE_ASSESSMENT_OBSERVATION_INVALID:
        raise AssessmentRelationshipObservationReferenceError(
            f"assessment observation reference is invalid: {assessment_id}"
        ) from error
    if state == SQLSTATE_ASSESSMENT_REFERENCE_INVALID:
        raise AssessmentProvenanceMismatchError(
            f"assessment reference is invalid for its investigation: {assessment_id}"
        ) from error
    if state == SQLSTATE_ASSESSMENT_STRUCTURE_INVALID:
        raise AssessmentProvenanceMismatchError(
            f"assessment finding/support structure is invalid: {assessment_id}"
        ) from error
    if state == SQLSTATE_ASSESSMENT_GRAPH_CONCURRENT:
        raise AssessmentProvenanceMismatchError(
            f"referenced graph resource is missing, ineligible, or was "
            f"concurrently deleted: {assessment_id}"
        ) from error
    if state == SQLSTATE_ASSESSMENT_INVESTIGATION_MISMATCH:
        raise AssessmentInvestigationMismatchError(
            f"assessment references evidence/observation from another "
            f"investigation: {assessment_id}"
        ) from error
    if state == SQLSTATE_ASSESSMENT_HARD_LIMIT:
        # The database rejected an oversized direct input; only the limit is
        # reported, never array contents.
        raise AssessmentProvenanceMismatchError(
            "assessment input exceeds the database defensive hard limit"
        ) from error
    # Re-raise the active DBAPI exception when no SQLSTATE matched. This
    # helper is only ever invoked from inside an except DBAPIError handler.
    raise error


def _serialized_supports(
    findings: tuple[AnalyticalFinding, ...],
) -> list[tuple[int, int, str, UUID | None, UUID | None]]:
    """Serialize Finding support references into the composite input rows."""
    rows: list[tuple[int, int, str, UUID | None, UUID | None]] = []
    for finding_ordinal, finding in enumerate(findings, start=1):
        for support_ordinal, support in enumerate(finding.support, start=1):
            if isinstance(support, EvidenceSupport):
                rows.append(
                    (
                        finding_ordinal,
                        support_ordinal,
                        support.kind,
                        support.evidence_id,
                        None,
                    )
                )
            else:
                rows.append(
                    (
                        finding_ordinal,
                        support_ordinal,
                        support.kind,
                        None,
                        support.relationship_observation_id,
                    )
                )
    return rows


def _support_from_row(row: AssessmentFindingSupportRow) -> FindingSupport:
    """Map one support row to its typed domain reference."""
    if row.kind == "evidence":
        if row.evidence_id is None:  # pragma: no cover - DB complement check
            raise AssertionError("evidence support row has no evidence id")
        return EvidenceSupport(kind="evidence", evidence_id=row.evidence_id)
    if row.relationship_observation_id is None:  # pragma: no cover
        raise AssertionError("observation support row has no observation id")
    return RelationshipSupport(
        kind="relationship_observation",
        relationship_observation_id=row.relationship_observation_id,
    )


def _finding_from_row(
    row: AssessmentFindingRow, supports: tuple[FindingSupport, ...]
) -> AnalyticalFinding:
    """Map one finding row (with its ordered supports) to the domain model."""
    return AnalyticalFinding(
        category=FindingCategory(row.category),
        disposition=FindingDisposition(row.disposition),
        statement=row.statement,
        confidence=AssessmentConfidence(row.confidence),
        support=supports,
    )


def _assessment_from_row(
    row: AssessmentRow, findings: tuple[AnalyticalFinding, ...]
) -> Assessment:
    """Rebuild the domain Assessment without recursive provenance expansion."""
    return Assessment(
        id=row.id,
        investigation_id=row.investigation_id,
        verdict=Verdict(row.verdict),
        confidence=AssessmentConfidence(row.confidence),
        summary=row.summary,
        analyzed_evidence_ids=tuple(row.analyzed_evidence_ids),
        findings=findings,
        limitations=tuple(row.limitations),
        unresolved_questions=tuple(row.unresolved_questions),
        recommended_next_steps=tuple(row.recommended_next_steps),
        version=row.version,
        created_at=row.created_at,
        deleted_at=row.deleted_at,
        deleted_by_actor_id=row.deleted_by_actor_id,
    )


class PostgresAssessmentRepository(AssessmentRepository):
    """Persist Assessments through the caller's transaction."""

    def __init__(self, session: AsyncSession, batch_size: int = 100) -> None:
        """Bind the session and the configured Assessment batch limit."""
        if batch_size < 1:
            raise ValueError("assessment batch size must be positive")
        self.session = session
        self._batch_size = batch_size

    async def insert(
        self,
        assessment: Assessment,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Assessment:
        """Append a new Assessment version through the authoritative function.

        A duplicate identity, a stale parent, an oversized candidate, or any
        malformed or cross-investigation support reference surfaces as a
        typed error and mutates nothing; the surrounding UnitOfWork rolls
        back.
        """
        # Defense in depth for callers that reach the repository without the
        # application service: enforce the bounds before SQL serialization
        # and execution, so no oversized composite or UUID array reaches
        # PostgreSQL.
        enforce_assessment_collection_bounds(assessment, self._batch_size)
        assessment_id = assessment.id or uuid4()
        analyzed = list(assessment.analyzed_evidence_ids)
        findings = [
            (
                ordinal,
                finding.category.value,
                finding.disposition.value,
                finding.statement,
                finding.confidence.value,
            )
            for ordinal, finding in enumerate(assessment.findings, start=1)
        ]
        supports = _serialized_supports(assessment.findings)
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, created_at FROM ati.append_assessment(
                        :id, :investigation_id, :verdict, :confidence, :summary,
                        :analyzed, :limitations, :unresolved, :next_steps,
                        :findings, :supports, :actor_id, :request_id)
                """),
                {
                    "id": assessment_id,
                    "investigation_id": assessment.investigation_id,
                    "verdict": assessment.verdict.value,
                    "confidence": assessment.confidence.value,
                    "summary": assessment.summary,
                    "analyzed": analyzed,
                    "limitations": list(assessment.limitations),
                    "unresolved": list(assessment.unresolved_questions),
                    "next_steps": list(assessment.recommended_next_steps),
                    "findings": findings,
                    "supports": supports,
                    "actor_id": actor_id,
                    "request_id": request_id,
                },
            )
        except DBAPIError as error:
            raise_assessment_write_error(
                error, assessment_id, assessment.investigation_id
            )
        written_id, version, created_at = result.one()
        return assessment.model_copy(
            update={
                "id": written_id,
                "version": int(version),
                "created_at": created_at,
            }
        )

    async def get_by_id(
        self, assessment_id: UUID, *, include_deleted: bool = False
    ) -> Assessment | None:
        """Return the visible Assessment with its exact Findings and supports."""
        row = await self._row_by_id(assessment_id, include_deleted=include_deleted)
        return None if row is None else await self._with_findings(row)

    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Assessment]:
        """Return bounded Assessments in deterministic newest-first order."""
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        limit = min(limit, 1000)
        rows = (
            (
                await self.session.execute(
                    select(AssessmentRow)
                    .where(
                        AssessmentRow.investigation_id == investigation_id,
                        AssessmentRow.deleted_at.is_(None),
                    )
                    .order_by(AssessmentRow.created_at.desc(), AssessmentRow.id.asc())
                    .limit(limit)
                    .offset(offset)
                )
            )
            .scalars()
            .all()
        )
        assessments: list[Assessment] = []
        for row in rows:
            assessments.append(await self._with_findings(row))
        return assessments

    async def soft_delete(
        self,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Assessment:
        """Soft-delete the Assessment through the authoritative function.

        Deletion is rejected with the typed current-reference conflict while
        any visible Investigation still points at the Assessment.
        """
        try:
            result = await self.session.execute(
                text(
                    "SELECT id, version FROM ati.soft_delete_assessment("
                    ":id, :actor, :expected, :request_id)"
                ),
                {
                    "id": assessment_id,
                    "actor": actor_id,
                    "expected": expected_version,
                    "request_id": request_id,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_ASSESSMENT_NOT_FOUND:
                raise LookupError("assessment not found") from error
            if state == SQLSTATE_VERSION_CONFLICT:
                raise ValueError("stale expected_version") from error
            if state == SQLSTATE_ASSESSMENT_CURRENT_CONFLICT:
                raise AssessmentCurrentReferenceConflictError(assessment_id) from error
            raise
        written_id, _version = result.one()
        row = await self.session.get(AssessmentRow, written_id)
        if row is None:  # pragma: no cover - function and transaction are atomic
            raise RuntimeError("assessment delete returned no row")
        return await self._with_findings(row)

    async def _row_by_id(
        self, assessment_id: UUID, *, include_deleted: bool
    ) -> AssessmentRow | None:
        """Return the assessment row, hiding soft-deleted rows by default."""
        query = select(AssessmentRow).where(AssessmentRow.id == assessment_id)
        if not include_deleted:
            query = query.where(AssessmentRow.deleted_at.is_(None))
        return (await self.session.execute(query)).scalar_one_or_none()

    async def _with_findings(self, row: AssessmentRow) -> Assessment:
        """Attach the ordered Findings and typed support references."""
        finding_rows = (
            (
                await self.session.execute(
                    select(AssessmentFindingRow)
                    .where(AssessmentFindingRow.assessment_id == row.id)
                    .order_by(AssessmentFindingRow.ordinal)
                )
            )
            .scalars()
            .all()
        )
        findings: list[AnalyticalFinding] = []
        for finding_row in finding_rows:
            support_rows = (
                (
                    await self.session.execute(
                        select(AssessmentFindingSupportRow)
                        .where(AssessmentFindingSupportRow.finding_id == finding_row.id)
                        .order_by(AssessmentFindingSupportRow.ordinal)
                    )
                )
                .scalars()
                .all()
            )
            findings.append(
                _finding_from_row(
                    finding_row,
                    tuple(_support_from_row(item) for item in support_rows),
                )
            )
        return _assessment_from_row(row, tuple(findings))
