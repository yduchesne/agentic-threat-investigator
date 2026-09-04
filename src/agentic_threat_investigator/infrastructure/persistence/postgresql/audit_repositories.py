# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapter for immutable audit events."""

# The filtered audit query intentionally exposes one argument per supported
# query dimension; keeping these filters explicit avoids an untyped criteria map.
# pylint: disable=too-many-arguments
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    AuditEventRepository,
)
from agentic_threat_investigator.domain.audit import AuditEvent, AuditOutcome
from agentic_threat_investigator.domain.immutable_json import thaw_json

from .models import AuditEventRow


class PostgresAuditEventRepository(AuditEventRepository):
    """Append and query audit events in the supplied transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _domain(row: AuditEventRow) -> AuditEvent:
        """Map a database row to its framework-independent model."""
        return AuditEvent(
            id=row.id,
            action=row.action,
            outcome=AuditOutcome(row.outcome),
            occurred_at=row.occurred_at,
            actor_id=row.actor_id,
            actor_username=row.actor_username,
            object_type=row.object_type,
            object_id=row.object_id,
            metadata=row.metadata_,
            request_id=row.request_id,
            version=row.version,
        )

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Insert and flush an event without committing the caller's transaction."""
        values = event.model_dump(exclude={"version"})
        values["metadata_"] = thaw_json(values.pop("metadata"))
        row = AuditEventRow(**values)
        self._session.add(row)
        await self._session.flush()
        return self._domain(row)

    async def list_events(
        self,
        *,
        actor_id: UUID | None = None,
        action: str | None = None,
        outcome: AuditOutcome | None = None,
        object_type: str | None = None,
        object_id: UUID | None = None,
        occurred_after: datetime | None = None,
        occurred_before: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """Read a bounded, newest-first event page."""
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        limit = min(limit, 1000)
        query = select(AuditEventRow)
        filters = []
        if actor_id is not None:
            filters.append(AuditEventRow.actor_id == actor_id)
        if action is not None:
            filters.append(AuditEventRow.action == action)
        if outcome is not None:
            filters.append(AuditEventRow.outcome == outcome.value)
        if object_type is not None:
            filters.append(AuditEventRow.object_type == object_type)
        if object_id is not None:
            filters.append(AuditEventRow.object_id == object_id)
        if occurred_after is not None:
            filters.append(AuditEventRow.occurred_at >= occurred_after)
        if occurred_before is not None:
            filters.append(AuditEventRow.occurred_at <= occurred_before)
        result = await self._session.execute(
            query.where(*filters)
            .order_by(AuditEventRow.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [self._domain(row) for row in result.scalars()]
