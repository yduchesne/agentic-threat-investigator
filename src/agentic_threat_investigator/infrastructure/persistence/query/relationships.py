# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL Relationship and RelationshipObservation read queries (PR 23A).

Investigation relationship visibility derives from RelationshipObservation
correlation; the stable Relationship resource is never denormalized with an
``investigation_id`` column. RelationshipObservation is queried directly as
the immutable historical record and never through ``domain_object_history``.
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
from agentic_threat_investigator.app.query.relationships import (
    RelationshipListQuery,
    RelationshipObservationListQuery,
    RelationshipObservationQueryService,
    RelationshipQueryService,
    parse_relationship_cursor,
    parse_relationship_observation_cursor,
    relationship_observation_sort_values,
    relationship_sort_values,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)

from ..postgresql.models import (
    RelationshipObservationRow,
    RelationshipRow,
)


def _relationship_from_row(row: RelationshipRow) -> Relationship:
    """Map a relationship row to its stable domain model."""
    return Relationship(
        id=row.id,
        source_entity_id=row.source_entity_id,
        target_entity_id=row.target_entity_id,
        type=RelationshipType(row.relationship_type_urn),
    )


def _observation_from_row(row: RelationshipObservationRow) -> RelationshipObservation:
    """Map an observation row to its immutable domain model."""
    return RelationshipObservation(
        id=row.id,
        relationship_id=row.relationship_id,
        evidence_id=row.evidence_id,
        investigation_id=row.investigation_id,
        observed_at=row.observed_at,
        retrieved_at=row.retrieved_at,
        source=row.source,
        confidence=row.confidence,
    )


class PostgresRelationshipQueryService(RelationshipQueryService):
    """Distinct stable Relationship listing visible through observations."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(self, query: RelationshipListQuery) -> QueryPage[Relationship]:
        """Return distinct Relationships observed by the Investigation.

        Repeated observations never duplicate an edge; the canonical order is
        the stable ``relationship.id ASC``.
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.RELATIONSHIPS,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_relationship_cursor(envelope)

        stmt = (
            select(RelationshipRow)
            .join(
                RelationshipObservationRow,
                RelationshipObservationRow.relationship_id == RelationshipRow.id,
            )
            .where(
                RelationshipObservationRow.investigation_id == query.investigation_id,
                RelationshipRow.deleted_at.is_(None),
            )
        )
        if query.source_entity_id is not None:
            stmt = stmt.where(
                RelationshipRow.source_entity_id == query.source_entity_id
            )
        if query.target_entity_id is not None:
            stmt = stmt.where(
                RelationshipRow.target_entity_id == query.target_entity_id
            )
        if query.relationship_type is not None:
            stmt = stmt.where(
                RelationshipRow.relationship_type_urn == query.relationship_type.value
            )
        if cursor is not None:
            stmt = stmt.where(RelationshipRow.id > cursor)
        stmt = stmt.distinct().order_by(RelationshipRow.id.asc()).limit(limit + 1)
        rows = (await self._session.execute(stmt)).scalars().all()
        page = rows[:limit]
        items = tuple(_relationship_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.RELATIONSHIPS,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=relationship_sort_values(last.id),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)


class PostgresRelationshipObservationQueryService(RelationshipObservationQueryService):
    """Independent historical RelationshipObservation listing."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(
        self, query: RelationshipObservationListQuery
    ) -> QueryPage[RelationshipObservation]:
        """Return one bounded page of immutable observations, newest first.

        At least one scope (investigation or relationship) is required by the
        contract; ``observed_at`` ranges filter independently and never enter
        the cursor.
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.RELATIONSHIP_OBSERVATIONS,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = (
            None
            if envelope is None
            else parse_relationship_observation_cursor(envelope)
        )

        stmt = select(RelationshipObservationRow)
        if query.investigation_id is not None:
            stmt = stmt.where(
                RelationshipObservationRow.investigation_id == query.investigation_id
            )
        if query.relationship_id is not None:
            stmt = stmt.where(
                RelationshipObservationRow.relationship_id == query.relationship_id
            )
        if query.source is not None:
            stmt = stmt.where(RelationshipObservationRow.source == query.source)
        if query.retrieved_from is not None:
            stmt = stmt.where(
                RelationshipObservationRow.retrieved_at >= query.retrieved_from
            )
        if query.retrieved_to is not None:
            stmt = stmt.where(
                RelationshipObservationRow.retrieved_at < query.retrieved_to
            )
        if query.observed_from is not None:
            stmt = stmt.where(
                RelationshipObservationRow.observed_at >= query.observed_from
            )
        if query.observed_to is not None:
            stmt = stmt.where(
                RelationshipObservationRow.observed_at < query.observed_to
            )
        if cursor is not None:
            retrieved_at, cursor_id = cursor
            stmt = stmt.where(
                or_(
                    RelationshipObservationRow.retrieved_at < retrieved_at,
                    and_(
                        RelationshipObservationRow.retrieved_at == retrieved_at,
                        RelationshipObservationRow.id > cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            RelationshipObservationRow.retrieved_at.desc(),
            RelationshipObservationRow.id.asc(),
        ).limit(limit + 1)
        rows = (await self._session.execute(stmt)).scalars().all()
        page = rows[:limit]
        items = tuple(_observation_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.RELATIONSHIP_OBSERVATIONS,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=relationship_observation_sort_values(
                        last.retrieved_at, last.id
                    ),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)
