# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL ResearchResult read queries (PR 23A).

ResearchResults are immutable and append-only; the analyst-facing canonical
order is ``created_at DESC, id ASC`` backed by the new DESC indexes added in
migration 0022 (the pre-existing ASC index continues to serve the internal
execution reconciliation read).
"""

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
from agentic_threat_investigator.app.query.research import (
    ResearchResultListQuery,
    ResearchResultQueryService,
    parse_research_result_cursor,
    research_result_sort_values,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.domain.research import ResearchResult

from ..postgresql.models import ResearchResultRow


def _result_from_row(row: ResearchResultRow) -> ResearchResult:
    """Map one persisted research-result row to its exact typed model.

    Claims and citations are authoritative typed JSONB snapshots validated by
    the application domain model; the JSONB containers are thawed into
    mutable JSON-compatible values before Pydantic re-validates and freezes
    them into immutable tuples.
    """
    values = {
        "id": row.id,
        "investigation_id": row.investigation_id,
        "subject_entity_id": row.subject_entity_id,
        "query": row.query,
        "claims": tuple(thaw_json(row.claims)),
        "citations": tuple(thaw_json(row.citations)),
        "created_at": row.created_at,
    }
    return ResearchResult.model_validate(values)


class PostgresResearchResultQueryService(ResearchResultQueryService):
    """Bounded keyset ResearchResult listing over one active session."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(self, query: ResearchResultListQuery) -> QueryPage[ResearchResult]:
        """Return one bounded page of immutable research results, newest first.

        All predicates are static SQLAlchemy expressions over fixed columns;
        no SQL fragment, column name, or order-by expression is ever
        interpolated from caller input.
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.RESEARCH_RESULTS,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_research_result_cursor(envelope)

        stmt = select(ResearchResultRow).where(
            ResearchResultRow.investigation_id == query.investigation_id
        )
        if query.subject_entity_id is not None:
            stmt = stmt.where(
                ResearchResultRow.subject_entity_id == query.subject_entity_id
            )
        if query.created_from is not None:
            stmt = stmt.where(ResearchResultRow.created_at >= query.created_from)
        if query.created_to is not None:
            stmt = stmt.where(ResearchResultRow.created_at < query.created_to)
        if cursor is not None:
            created_at, cursor_id = cursor
            stmt = stmt.where(
                or_(
                    ResearchResultRow.created_at < created_at,
                    and_(
                        ResearchResultRow.created_at == created_at,
                        ResearchResultRow.id > cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            ResearchResultRow.created_at.desc(),
            ResearchResultRow.id.asc(),
        ).limit(limit + 1)
        rows = (await self._session.execute(stmt)).scalars().all()
        page = rows[:limit]
        items = tuple(_result_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.RESEARCH_RESULTS,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=research_result_sort_values(last.created_at, last.id),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)

    async def get(
        self, investigation_id: UUID, result_id: UUID
    ) -> ResearchResult | None:
        """Return one ResearchResult bound to the Investigation, if any.

        The binding predicate makes a cross-Investigation lookup fail closed
        with ``None``.
        """
        row = (
            await self._session.execute(
                select(ResearchResultRow).where(
                    ResearchResultRow.id == result_id,
                    ResearchResultRow.investigation_id == investigation_id,
                )
            )
        ).scalar_one_or_none()
        return None if row is None else _result_from_row(row)
