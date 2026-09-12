# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL Investigation read queries (PR 23A).

Keyset continuation for ``created_at DESC, id ASC``:

.. code-block:: sql

    WHERE (
        created_at < :cursor_created_at
        OR (
            created_at = :cursor_created_at
            AND id > :cursor_id
        )
    )
    ORDER BY created_at DESC, id ASC
    LIMIT :limit_plus_one
"""

from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.investigations import (
    InvestigationListQuery,
    InvestigationQueryService,
    investigation_sort_values,
    parse_investigation_cursor,
)
from agentic_threat_investigator.app.query.models import QueryLimits, QueryPage
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    QueryKind,
    encode_cursor,
    require_cursor_for_query,
)
from agentic_threat_investigator.domain.investigation import InvestigationState

from ..postgresql.investigation_repositories import investigation_state_from_row
from ..postgresql.models import InvestigationRow


class PostgresInvestigationQueryService(InvestigationQueryService):
    """Bounded keyset Investigation listing over one active session."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(
        self, query: InvestigationListQuery
    ) -> QueryPage[InvestigationState]:
        """Return one bounded page of visible investigations, newest first.

        Soft-deleted rows are always hidden; the cursor is bound to the exact
        filter set and fails closed on any mismatch.
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.INVESTIGATIONS,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_investigation_cursor(envelope)

        stmt = select(InvestigationRow).where(InvestigationRow.deleted_at.is_(None))
        if query.status is not None:
            stmt = stmt.where(InvestigationRow.status == query.status.value)
        if query.created_from is not None:
            stmt = stmt.where(InvestigationRow.created_at >= query.created_from)
        if query.created_to is not None:
            stmt = stmt.where(InvestigationRow.created_at < query.created_to)
        if cursor is not None:
            created_at, cursor_id = cursor
            stmt = stmt.where(
                or_(
                    InvestigationRow.created_at < created_at,
                    and_(
                        InvestigationRow.created_at == created_at,
                        InvestigationRow.id > cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            InvestigationRow.created_at.desc(),
            InvestigationRow.id.asc(),
        ).limit(limit + 1)
        rows = (await self._session.execute(stmt)).scalars().all()
        page = rows[:limit]
        items = tuple(investigation_state_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = self._encode_next_cursor(query, last)
        return QueryPage(items=items, next_cursor=next_cursor)

    def _encode_next_cursor(
        self, query: InvestigationListQuery, row: InvestigationRow
    ) -> str:
        """Encode the continuation cursor for the last returned row."""
        return encode_cursor(
            CursorEnvelope(
                query_kind=QueryKind.INVESTIGATIONS,
                filter_fingerprint=query.fingerprint(),
                sort_values=investigation_sort_values(row.created_at, row.id),
            )
        )

    async def get(self, investigation_id: UUID) -> InvestigationState | None:
        """Return one visible Investigation by identity, if any.

        Soft-deleted rows are hidden; the returned state carries the
        authoritative database-owned version and timestamps.
        """
        row = (
            await self._session.execute(
                select(InvestigationRow).where(
                    InvestigationRow.id == investigation_id,
                    InvestigationRow.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        return None if row is None else investigation_state_from_row(row)
