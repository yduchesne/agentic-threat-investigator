# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL admitted-observation read queries (PR 23A + PR 28B).

Canonical ordering preserves the persisted execution semantics
(``retrieved_at DESC, observation id ASC``) and the Investigation scope is
exclusively the ``ati.investigation_evidence`` admission: unadmitted global
observations never appear, and newer global observations never leak into an
Investigation.
"""

from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.evidence import (
    EvidenceListQuery,
    EvidenceQueryService,
    EvidenceReadItem,
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
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.evidence_repositories import (
    _evidence,
    observation_from_row,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.models import (
    EntityRow,
    EvidenceObservationEntityRow,
    EvidenceObservationRow,
    EvidenceRow,
    InvestigationEvidenceRow,
)


def _admission(row: InvestigationEvidenceRow) -> InvestigationEvidence:
    """Map an admission row to its immutable domain model."""
    return InvestigationEvidence(
        investigation_id=row.investigation_id,
        evidence_observation_id=row.evidence_observation_id,
        inclusion_reason=InvestigationEvidenceReason(row.inclusion_reason),
        discovered_from_evidence_observation_id=(
            row.discovered_from_evidence_observation_id
        ),
        added_at=row.added_at,
        added_by=InvestigationEvidenceActor(row.added_by),
    )


def _entity(row: EntityRow) -> Entity:
    """Map an entity row to its domain model."""
    return Entity(
        id=row.id,
        type=EntityType(row.entity_type),
        value=row.canonical_value,
        display_name=row.display_name,
        attributes=row.attributes,
        content_hash=row.content_hash,
        version=row.version,
        deleted_at=row.deleted_at,
        deleted_by_actor_id=row.deleted_by_actor_id,
    )


class PostgresEvidenceQueryService(EvidenceQueryService):
    """Bounded keyset admitted-observation listing over one active session."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the read session and the configured page-size limits."""
        self._session = session
        self._limits = limits

    async def _associated_entities(
        self, observation_ids: tuple[UUID, ...]
    ) -> dict[UUID, tuple[Entity, ...]]:
        """Return the deterministic associated Entities of the given observations."""
        if not observation_ids:
            return {}
        result = await self._session.execute(
            select(
                EvidenceObservationEntityRow.evidence_observation_id,
                EntityRow,
            )
            .join(
                EntityRow,
                EntityRow.id == EvidenceObservationEntityRow.entity_id,
            )
            .where(
                EvidenceObservationEntityRow.evidence_observation_id.in_(
                    observation_ids
                ),
                EntityRow.deleted_at.is_(None),
            )
            .order_by(
                EvidenceObservationEntityRow.evidence_observation_id,
                EntityRow.id,
            )
        )
        associated: dict[UUID, list[Entity]] = {}
        for observation_id, entity_row in result.fetchall():
            associated.setdefault(observation_id, []).append(_entity(entity_row))
        return {key: tuple(value) for key, value in associated.items()}

    async def list(self, query: EvidenceListQuery) -> QueryPage[EvidenceReadItem]:
        """Return one bounded page of exactly admitted observations."""
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.EVIDENCE,
            filter_fingerprint=query.fingerprint(),
        )
        cursor = None if envelope is None else parse_evidence_cursor(envelope)

        stmt = (
            select(
                EvidenceObservationRow,
                EvidenceRow,
                InvestigationEvidenceRow,
            )
            .join(
                InvestigationEvidenceRow,
                InvestigationEvidenceRow.evidence_observation_id
                == EvidenceObservationRow.id,
            )
            .join(
                EvidenceRow,
                EvidenceRow.id == EvidenceObservationRow.evidence_id,
            )
            .where(InvestigationEvidenceRow.investigation_id == query.investigation_id)
        )
        if query.source is not None:
            stmt = stmt.where(EvidenceRow.source == query.source)
        if query.entity_id is not None:
            stmt = stmt.where(
                EvidenceObservationRow.id.in_(
                    select(EvidenceObservationEntityRow.evidence_observation_id).where(
                        EvidenceObservationEntityRow.entity_id == query.entity_id
                    )
                )
            )
        if query.evidence_type is not None:
            stmt = stmt.where(EvidenceRow.evidence_type == query.evidence_type.value)
        if query.retrieved_from is not None:
            stmt = stmt.where(
                EvidenceObservationRow.retrieved_at >= query.retrieved_from
            )
        if query.retrieved_to is not None:
            stmt = stmt.where(EvidenceObservationRow.retrieved_at < query.retrieved_to)
        if cursor is not None:
            retrieved_at, cursor_id = cursor
            stmt = stmt.where(
                or_(
                    EvidenceObservationRow.retrieved_at < retrieved_at,
                    and_(
                        EvidenceObservationRow.retrieved_at == retrieved_at,
                        EvidenceObservationRow.id > cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            EvidenceObservationRow.retrieved_at.desc(),
            EvidenceObservationRow.id.asc(),
        ).limit(limit + 1)
        rows = (await self._session.execute(stmt)).fetchall()
        page = rows[:limit]
        observation_ids = tuple(row[0].id for row in page)
        associated = await self._associated_entities(observation_ids)
        items = tuple(
            EvidenceReadItem(
                observation=observation_from_row(row[0]),
                evidence=_evidence(row[1]),
                entities=associated.get(row[0].id, ()),
                admission=_admission(row[2]),
            )
            for row in page
        )
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

    async def get(
        self, investigation_id: UUID, observation_id: UUID
    ) -> EvidenceReadItem | None:
        """Return one exactly admitted observation bound to the Investigation, if any.

        The binding predicate makes a cross-Investigation lookup fail closed
        with ``None``; raw provider payloads are never returned by the read
        layer (the HTTP layer excludes them explicitly).
        """
        row = (
            await self._session.execute(
                select(
                    EvidenceObservationRow,
                    EvidenceRow,
                    InvestigationEvidenceRow,
                )
                .join(
                    InvestigationEvidenceRow,
                    InvestigationEvidenceRow.evidence_observation_id
                    == EvidenceObservationRow.id,
                )
                .join(
                    EvidenceRow,
                    EvidenceRow.id == EvidenceObservationRow.evidence_id,
                )
                .where(
                    EvidenceObservationRow.id == observation_id,
                    InvestigationEvidenceRow.investigation_id == investigation_id,
                )
            )
        ).first()
        if row is None:
            return None
        associated = await self._associated_entities((observation_id,))
        return EvidenceReadItem(
            observation=observation_from_row(row[0]),
            evidence=_evidence(row[1]),
            entities=associated.get(observation_id, ()),
            admission=_admission(row[2]),
        )
