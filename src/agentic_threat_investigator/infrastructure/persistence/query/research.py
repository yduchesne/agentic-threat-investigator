# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL ResearchResult read queries (PR 23A).

ResearchResults are immutable and append-only; the analyst-facing canonical
order is ``created_at DESC, id ASC`` backed by the new DESC indexes added in
migration 0022 (the pre-existing ASC index continues to serve the internal
execution reconciliation read).
"""

from sqlalchemy import text
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


def _result_from_row(values: dict[str, object]) -> ResearchResult:
    """Map one research_result row to its exact typed domain model."""
    payload = dict(values)
    payload["claims"] = tuple(thaw_json(values["claims"]))
    payload["citations"] = tuple(thaw_json(values["citations"]))
    return ResearchResult.model_validate(payload)


class PostgresResearchResultQueryService(ResearchResultQueryService):
    """Bounded keyset ResearchResult listing over one active session."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(self, query: ResearchResultListQuery) -> QueryPage[ResearchResult]:
        """Return one bounded page of immutable research results, newest first.

        The statement is static SQL with optional fixed predicates; no column
        or order-by expression is ever interpolated from caller input.
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.RESEARCH_RESULTS,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_research_result_cursor(envelope)

        predicates: list[str] = []
        params: dict[str, object] = {
            "investigation_id": query.investigation_id,
        }
        if query.subject_entity_id is not None:
            predicates.append("subject_entity_id = :subject_entity_id")
            params["subject_entity_id"] = query.subject_entity_id
        if query.created_from is not None:
            predicates.append("created_at >= :created_from")
            params["created_from"] = query.created_from
        if query.created_to is not None:
            predicates.append("created_at < :created_to")
            params["created_to"] = query.created_to
        if cursor is not None:
            created_at, cursor_id = cursor
            predicates.append(
                "(created_at < :cursor_created_at OR "
                "(created_at = :cursor_created_at AND id > :cursor_id))"
            )
            params["cursor_created_at"] = created_at
            params["cursor_id"] = cursor_id
        where_clause = " AND ".join(predicates)
        statement = text(
            "SELECT id, investigation_id, subject_entity_id, query, "
            "claims, citations, created_at "
            "FROM ati.research_result "
            "WHERE investigation_id = :investigation_id"
            + (f" AND {where_clause}" if where_clause else "")
            + " ORDER BY created_at DESC, id ASC LIMIT :limit_plus_one"
        )
        params["limit_plus_one"] = limit + 1
        result = await self._session.execute(statement, params)
        rows = result.mappings().all()
        page = rows[:limit]
        items = tuple(_result_from_row(dict(row)) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = dict(page[-1])
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.RESEARCH_RESULTS,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=research_result_sort_values(
                        last["created_at"], last["id"]
                    ),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)
