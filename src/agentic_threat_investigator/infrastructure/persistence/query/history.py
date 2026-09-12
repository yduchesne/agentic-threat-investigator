# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL generic domain-object history read queries (PR 23A).

Generic resource-state history lives in ``domain_object_history`` with stable
object identity ``object_type + object_id``; the history row's own primary
key ``id`` (which already exists) is the stable pagination tie-breaker under
``occurred_at DESC, id ASC``. Exact version lookup uses the pre-existing
``domain_object_history_object_idx`` index; no uniqueness constraint is
invented and no ``natural_key`` column exists.
"""

from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.history import (
    DomainHistoryListQuery,
    DomainHistoryQueryService,
    DomainObjectHistoryRecord,
    domain_history_sort_values,
    history_record_from_row,
    parse_domain_history_cursor,
    validate_object_version,
)
from agentic_threat_investigator.app.query.models import QueryLimits, QueryPage
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    QueryKind,
    encode_cursor,
    require_cursor_for_query,
)

from ..postgresql.models import DomainObjectHistoryRow


def _history_from_row(row: DomainObjectHistoryRow) -> DomainObjectHistoryRecord:
    """Build the immutable read model from one canonical history row."""
    return history_record_from_row(
        row_id=row.id,
        object_type=row.object_type,
        object_id=row.object_id,
        version=row.version,
        operation=row.operation,
        state=row.state,
        diff=row.diff,
        actor_id=row.actor_id,
        request_id=row.request_id,
        investigation_id=row.investigation_id,
        occurred_at=row.occurred_at,
    )


class PostgresDomainHistoryQueryService(DomainHistoryQueryService):
    """Bounded keyset generic history browsing over one active session."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(
        self, query: DomainHistoryListQuery
    ) -> QueryPage[DomainObjectHistoryRecord]:
        """Return one bounded page of immutable history rows, newest first.

        Supports global chronological browsing, object-type scope,
        ``object_type + object_id`` object scope, investigation scope, and
        the bounded operation/date filters.
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.DOMAIN_HISTORY,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_domain_history_cursor(envelope)

        stmt = select(DomainObjectHistoryRow)
        if query.object_type is not None:
            stmt = stmt.where(DomainObjectHistoryRow.object_type == query.object_type)
        if query.object_id is not None:
            stmt = stmt.where(DomainObjectHistoryRow.object_id == query.object_id)
        if query.investigation_id is not None:
            stmt = stmt.where(
                DomainObjectHistoryRow.investigation_id == query.investigation_id
            )
        if query.operation is not None:
            stmt = stmt.where(DomainObjectHistoryRow.operation == query.operation.value)
        if query.occurred_from is not None:
            stmt = stmt.where(DomainObjectHistoryRow.occurred_at >= query.occurred_from)
        if query.occurred_to is not None:
            stmt = stmt.where(DomainObjectHistoryRow.occurred_at < query.occurred_to)
        if cursor is not None:
            occurred_at, cursor_id = cursor
            stmt = stmt.where(
                or_(
                    DomainObjectHistoryRow.occurred_at < occurred_at,
                    and_(
                        DomainObjectHistoryRow.occurred_at == occurred_at,
                        DomainObjectHistoryRow.id > cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            DomainObjectHistoryRow.occurred_at.desc(),
            DomainObjectHistoryRow.id.asc(),
        ).limit(limit + 1)
        rows = (await self._session.execute(stmt)).scalars().all()
        page = rows[:limit]
        items = tuple(_history_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.DOMAIN_HISTORY,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=domain_history_sort_values(last.occurred_at, last.id),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)

    async def get_object_version(
        self,
        *,
        object_type: str,
        object_id: UUID,
        version: int,
    ) -> DomainObjectHistoryRecord | None:
        """Return the exact history row for one object version, if any.

        The stable lookup identity is ``object_type + object_id + version``,
        served by the pre-existing ``domain_object_history_object_idx`` index.
        """
        validate_object_version(object_type, version)
        row = (
            await self._session.execute(
                select(DomainObjectHistoryRow).where(
                    DomainObjectHistoryRow.object_type == object_type,
                    DomainObjectHistoryRow.object_id == object_id,
                    DomainObjectHistoryRow.version == version,
                )
            )
        ).scalar_one_or_none()
        return None if row is None else _history_from_row(row)
