# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL report read queries (PR 23B extension of PR 23A).

Version listing is ordered ``version DESC, id ASC`` backed by the
``investigation_report_version_listing_idx`` partial index. Nested snapshots
are read from the authoritative JSONB columns in bounded reads — never one
query per row. The current report is resolved through the Investigation's
durable ``report_id`` pointer, never ``MAX(version)``.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.models import QueryLimits, QueryPage
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    QueryKind,
    encode_cursor,
    require_cursor_for_query,
)
from agentic_threat_investigator.app.query.reports import (
    ReportListQuery,
    ReportQueryService,
    parse_report_cursor,
    report_sort_values,
)
from agentic_threat_investigator.domain.report import InvestigationReport

from ..postgresql.models import InvestigationReportRow, InvestigationRow
from ..postgresql.report_repositories import report_from_row


class PostgresReportQueryService(ReportQueryService):
    """Bounded keyset report version listing over one active session."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(self, query: ReportListQuery) -> QueryPage[InvestigationReport]:
        """Return one bounded page of report versions, newest version first.

        Soft-deleted reports are hidden; the cursor is bound to the
        Investigation scope.
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.REPORTS,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_report_cursor(envelope)

        stmt = select(InvestigationReportRow).where(
            InvestigationReportRow.investigation_id == query.investigation_id,
            InvestigationReportRow.deleted_at.is_(None),
        )
        if cursor is not None:
            version, cursor_id = cursor
            stmt = stmt.where(
                or_(
                    InvestigationReportRow.version < version,
                    and_(
                        InvestigationReportRow.version == version,
                        InvestigationReportRow.id > cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            InvestigationReportRow.version.desc(),
            InvestigationReportRow.id.asc(),
        ).limit(limit + 1)
        rows = list((await self._session.execute(stmt)).scalars().all())
        page = rows[:limit]
        items = tuple(report_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.REPORTS,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=report_sort_values(last.version, last.id),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)

    async def current(self, investigation_id: UUID) -> InvestigationReport | None:
        """Return the Investigation's current report, if any.

        The durable ``report_id`` pointer inside the Investigation's
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
        pointer = (row.operational_state or {}).get("report_id")
        if pointer is None:
            return None
        try:
            report_id = UUID(str(pointer))
        except ValueError:
            return None
        return await self.get(report_id)

    async def get(self, report_id: UUID) -> InvestigationReport | None:
        """Return one visible report by identity, if any."""
        row = (
            await self._session.execute(
                select(InvestigationReportRow).where(
                    InvestigationReportRow.id == report_id,
                    InvestigationReportRow.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        return None if row is None else report_from_row(row)
