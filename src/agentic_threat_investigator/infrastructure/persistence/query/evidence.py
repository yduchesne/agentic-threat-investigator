# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL Evidence read queries (PR 23A).

Canonical ordering preserves the persisted execution semantics
(``retrieved_at DESC, id ASC``) backed by the existing
``evidence_investigation_listing_idx`` for the investigation scope and by the
new filter composites added in migration 0022.
"""

from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.evidence import (
    EvidenceListQuery,
    EvidenceQueryService,
    evidence_sort_values,
    parse_evidence_cursor,
)
from agentic_threat_investigator.app.query.models import QueryLimits, QueryPage
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    QueryKind,
    encode_cursor,
    require_cursor_for_query,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)

from ..postgresql.models import EntityRow, EvidenceRow


def _evidence_from_row(row: EvidenceRow, subject: EntityRow) -> Evidence:
    """Map an evidence row and its subject entity to the immutable domain model."""
    return Evidence(
        id=row.id,
        investigation_id=row.investigation_id,
        type=EvidenceType(row.evidence_type),
        subject=EntityRef(
            id=subject.id,
            type=EntityType(subject.entity_type),
            value=subject.canonical_value,
        ),
        source=row.source,
        source_record_id=row.source_record_id,
        source_url=row.source_url,
        observed_at=row.observed_at,
        retrieved_at=row.retrieved_at,
        facts=row.facts,
        raw_payload=row.raw_payload,
    )


class PostgresEvidenceQueryService(EvidenceQueryService):
    """Bounded keyset Evidence listing over one active session."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def list(self, query: EvidenceListQuery) -> QueryPage[Evidence]:
        """Return one bounded page of immutable Evidence observations.

        The Investigation scope is mandatory; optional source, subject,
        evidence-type, and retrieved-time filters are bounded typed fields.
        """
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.EVIDENCE,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_evidence_cursor(envelope)

        stmt = (
            select(EvidenceRow, EntityRow)
            .join(EntityRow, EntityRow.id == EvidenceRow.subject_entity_id)
            .where(EvidenceRow.investigation_id == query.investigation_id)
        )
        if query.source is not None:
            stmt = stmt.where(EvidenceRow.source == query.source)
        if query.subject_entity_id is not None:
            stmt = stmt.where(EvidenceRow.subject_entity_id == query.subject_entity_id)
        if query.evidence_type is not None:
            stmt = stmt.where(EvidenceRow.evidence_type == query.evidence_type.value)
        if query.retrieved_from is not None:
            stmt = stmt.where(EvidenceRow.retrieved_at >= query.retrieved_from)
        if query.retrieved_to is not None:
            stmt = stmt.where(EvidenceRow.retrieved_at < query.retrieved_to)
        if cursor is not None:
            retrieved_at, cursor_id = cursor
            stmt = stmt.where(
                or_(
                    EvidenceRow.retrieved_at < retrieved_at,
                    and_(
                        EvidenceRow.retrieved_at == retrieved_at,
                        EvidenceRow.id > cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            EvidenceRow.retrieved_at.desc(),
            EvidenceRow.id.asc(),
        ).limit(limit + 1)
        rows = (await self._session.execute(stmt)).fetchall()
        page = rows[:limit]
        items = tuple(_evidence_from_row(row[0], row[1]) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.EVIDENCE,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=evidence_sort_values(last[0].retrieved_at, last[0].id),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)

    async def get(self, investigation_id: UUID, evidence_id: UUID) -> Evidence | None:
        """Return one Evidence observation bound to the Investigation, if any.

        The binding predicate makes a cross-Investigation lookup fail closed
        with ``None``; raw provider payloads are never returned by the read
        layer (the HTTP layer excludes them explicitly).
        """
        row = (
            await self._session.execute(
                select(EvidenceRow, EntityRow)
                .join(EntityRow, EntityRow.id == EvidenceRow.subject_entity_id)
                .where(
                    EvidenceRow.id == evidence_id,
                    EvidenceRow.investigation_id == investigation_id,
                )
            )
        ).first()
        return None if row is None else _evidence_from_row(row[0], row[1])
