# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL Assessment read queries (PR 23A).

Version listing is ordered ``version DESC, id ASC`` backed by the
``assessment_investigation_version_idx`` partial index. Findings and support
references are reconstructed with bounded batched reads — never one query
per row. The current Assessment is resolved through the Investigation's
durable ``assessment_id`` pointer, never ``MAX(version)``.
"""

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.assessments import (
    AssessmentListQuery,
    AssessmentQueryService,
    assessment_sort_values,
    parse_assessment_cursor,
)
from agentic_threat_investigator.app.query.models import QueryLimits, QueryPage
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    QueryKind,
    encode_cursor,
    require_cursor_for_query,
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

from ..postgresql.models import (
    AssessmentFindingRow,
    AssessmentFindingSupportRow,
    AssessmentRow,
    InvestigationRow,
)


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


def _with_findings(
    rows: Sequence[AssessmentRow],
    finding_rows: Sequence[AssessmentFindingRow],
    support_rows: Sequence[AssessmentFindingSupportRow],
) -> tuple[Assessment, ...]:
    """Attach Findings and supports to a page of Assessments without N+1.

    All finding/support rows for the page arrive in two bounded batched
    queries and are grouped in Python by their parent identities.
    """
    findings_by_assessment: dict[UUID, list[AssessmentFindingRow]] = {}
    for finding_row in finding_rows:
        findings_by_assessment.setdefault(finding_row.assessment_id, []).append(
            finding_row
        )
    supports_by_finding: dict[UUID, list[AssessmentFindingSupportRow]] = {}
    for support_row in support_rows:
        supports_by_finding.setdefault(support_row.finding_id, []).append(support_row)

    assessments: list[Assessment] = []
    for row in rows:
        findings: list[AnalyticalFinding] = []
        for finding_row in findings_by_assessment.get(row.id, ()):
            supports = tuple(
                _support_from_row(item)
                for item in supports_by_finding.get(finding_row.id, ())
            )
            findings.append(_finding_from_row(finding_row, supports))
        assessments.append(_assessment_from_row(row, tuple(findings)))
    return tuple(assessments)


class PostgresAssessmentQueryService(AssessmentQueryService):
    """Bounded keyset Assessment version listing over one active session."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(self, query: AssessmentListQuery) -> QueryPage[Assessment]:
        """Return one bounded page of Assessment versions, newest version first.

        Soft-deleted Assessments are hidden; the cursor is bound to the
        Investigation scope.
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.ASSESSMENTS,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_assessment_cursor(envelope)

        stmt = select(AssessmentRow).where(
            AssessmentRow.investigation_id == query.investigation_id,
            AssessmentRow.deleted_at.is_(None),
        )
        if cursor is not None:
            version, cursor_id = cursor
            stmt = stmt.where(
                or_(
                    AssessmentRow.version < version,
                    and_(
                        AssessmentRow.version == version,
                        AssessmentRow.id > cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            AssessmentRow.version.desc(),
            AssessmentRow.id.asc(),
        ).limit(limit + 1)
        rows = list((await self._session.execute(stmt)).scalars().all())
        page = rows[:limit]
        items = await self._with_findings_for_page(page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.ASSESSMENTS,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=assessment_sort_values(last.version, last.id),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)

    async def current(self, investigation_id: UUID) -> Assessment | None:
        """Return the Investigation's current/final Assessment, if any.

        The durable ``assessment_id`` pointer inside the Investigation's
        operational state is authoritative; ``MAX(version)`` inference is
        never used. A missing investigation or a missing pointer yields
        ``None``.
        """
        row = (
            await self._session.execute(
                select(InvestigationRow).where(
                    InvestigationRow.id == investigation_id,
                    InvestigationRow.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        pointer = (row.operational_state or {}).get("assessment_id")
        if pointer is None:
            return None
        try:
            assessment_id = UUID(str(pointer))
        except ValueError:
            return None
        assessment_row = (
            await self._session.execute(
                select(AssessmentRow).where(
                    AssessmentRow.id == assessment_id,
                    AssessmentRow.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if assessment_row is None:
            return None
        items = await self._with_findings_for_page([assessment_row])
        return items[0] if items else None

    async def _with_findings_for_page(
        self, rows: Sequence[AssessmentRow]
    ) -> tuple[Assessment, ...]:
        """Attach Findings/supports to a page in two bounded batched reads."""
        if not rows:
            return ()
        assessment_ids = [row.id for row in rows]
        finding_rows = (
            (
                await self._session.execute(
                    select(AssessmentFindingRow)
                    .where(AssessmentFindingRow.assessment_id.in_(assessment_ids))
                    .order_by(
                        AssessmentFindingRow.assessment_id,
                        AssessmentFindingRow.ordinal,
                    )
                )
            )
            .scalars()
            .all()
        )
        if not finding_rows:
            return tuple(_assessment_from_row(row, ()) for row in rows)
        finding_ids = [finding.id for finding in finding_rows]
        support_rows = (
            (
                await self._session.execute(
                    select(AssessmentFindingSupportRow)
                    .where(AssessmentFindingSupportRow.finding_id.in_(finding_ids))
                    .order_by(
                        AssessmentFindingSupportRow.finding_id,
                        AssessmentFindingSupportRow.ordinal,
                    )
                )
            )
            .scalars()
            .all()
        )
        return _with_findings(rows, finding_rows, support_rows)
