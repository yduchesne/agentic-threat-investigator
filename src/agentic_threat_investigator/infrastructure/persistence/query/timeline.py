# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL investigation timeline read queries (PR 23A).

The bounded keyset variant preserves the established chronological order
``occurred_at ASC, sequence ASC`` backed by the existing
``investigation_timeline_event_chronological_idx`` index. ``sequence`` is a
table-wide monotonic sequence, so it is the stable tie-breaker; no UUID is
required.
"""

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.models import QueryLimits, QueryPage
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    QueryKind,
    encode_cursor,
    require_cursor_for_query,
)
from agentic_threat_investigator.app.query.timeline import (
    TimelineListQuery,
    TimelineQueryService,
    parse_timeline_cursor,
    timeline_sort_values,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)

from ..postgresql.models import InvestigationTimelineEventRow


def _event_from_row(row: InvestigationTimelineEventRow) -> InvestigationTimelineEvent:
    """Map a timeline row to its framework-independent domain model."""
    return InvestigationTimelineEvent(
        id=row.id,
        investigation_id=row.investigation_id,
        type=InvestigationTimelineEventType(row.event_type),
        occurred_at=row.occurred_at,
        provider=SourceId(row.provider) if row.provider is not None else None,
        target_entity_id=row.target_entity_id,
        evidence_ids=tuple(row.evidence_ids),
        entity_ids=tuple(row.entity_ids),
        relationship_ids=tuple(row.relationship_ids),
        error_code=row.error_code,
        pivot_depth=row.pivot_depth,
        reason_code=row.reason_code,
        provider_calls_used=row.provider_calls_used,
        replans_used=row.replans_used,
        entity_count=row.entity_count,
    )


class PostgresTimelineQueryService(TimelineQueryService):
    """Bounded keyset timeline listing over one active session."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(
        self, query: TimelineListQuery
    ) -> QueryPage[InvestigationTimelineEvent]:
        """Return one bounded page of timeline events in chronological order.

        ``event_type`` and the occurred-at range are bounded filters; the
        event-type filter is a residual filter in v0.1 (low cardinality).
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.TIMELINE,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_timeline_cursor(envelope)

        stmt = select(InvestigationTimelineEventRow).where(
            InvestigationTimelineEventRow.investigation_id == query.investigation_id
        )
        if query.event_type is not None:
            stmt = stmt.where(
                InvestigationTimelineEventRow.event_type == query.event_type.value
            )
        if query.occurred_from is not None:
            stmt = stmt.where(
                InvestigationTimelineEventRow.occurred_at >= query.occurred_from
            )
        if query.occurred_to is not None:
            stmt = stmt.where(
                InvestigationTimelineEventRow.occurred_at < query.occurred_to
            )
        if cursor is not None:
            occurred_at, sequence = cursor
            stmt = stmt.where(
                or_(
                    InvestigationTimelineEventRow.occurred_at > occurred_at,
                    and_(
                        InvestigationTimelineEventRow.occurred_at == occurred_at,
                        InvestigationTimelineEventRow.sequence > sequence,
                    ),
                )
            )
        stmt = stmt.order_by(
            InvestigationTimelineEventRow.occurred_at,
            InvestigationTimelineEventRow.sequence,
        ).limit(limit + 1)
        rows = (await self._session.execute(stmt)).scalars().all()
        page = rows[:limit]
        items = tuple(_event_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.TIMELINE,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=timeline_sort_values(last.occurred_at, last.sequence),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)
