# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapter for the append-only investigation timeline.

Timeline events are immutable: the repository exposes only append and
chronological read operations. Inserts never commit; they participate in the
short explicit UnitOfWork transaction owned by the caller.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationTimelineRepository,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)

from .models import InvestigationTimelineEventRow


class PostgresInvestigationTimelineRepository(InvestigationTimelineRepository):
    """Append and query immutable investigation timeline events."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _domain(row: InvestigationTimelineEventRow) -> InvestigationTimelineEvent:
        """Map a database row to its framework-independent model."""
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

    async def append(self, event: InvestigationTimelineEvent) -> None:
        """Insert one event and flush without committing the caller's transaction."""
        row = InvestigationTimelineEventRow(
            id=event.id,
            investigation_id=event.investigation_id,
            event_type=event.type.value,
            occurred_at=event.occurred_at,
            provider=event.provider.value if event.provider is not None else None,
            target_entity_id=event.target_entity_id,
            evidence_ids=list(event.evidence_ids),
            entity_ids=list(event.entity_ids),
            relationship_ids=list(event.relationship_ids),
            error_code=event.error_code,
            pivot_depth=event.pivot_depth,
            reason_code=event.reason_code,
            provider_calls_used=event.provider_calls_used,
            replans_used=event.replans_used,
            entity_count=event.entity_count,
        )
        self._session.add(row)
        await self._session.flush()

    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> list[InvestigationTimelineEvent]:
        """Return events ordered chronologically, then by event identity."""
        rows = await self._session.execute(
            select(InvestigationTimelineEventRow)
            .where(InvestigationTimelineEventRow.investigation_id == investigation_id)
            .order_by(
                InvestigationTimelineEventRow.occurred_at,
                InvestigationTimelineEventRow.sequence,
            )
        )
        return [self._domain(row) for row in rows.scalars().all()]
