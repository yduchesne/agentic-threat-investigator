# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PostgreSQL audit-event adapter's mapping logic."""

# Fakes emulate the narrow async session seam and the database's
# server-side version default.
# pylint: disable=too-few-public-methods

from datetime import datetime, timezone
from typing import Any, cast
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql import (
    audit_repositories,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.models import (
    AuditEventRow,
)

_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


class FakeResult:
    """Execute result double exposing scalars()."""

    def __init__(self, rows: list[AuditEventRow]) -> None:
        self._rows = rows

    def scalars(self) -> list[AuditEventRow]:
        """Return the configured rows."""
        return self._rows


class FakeSession:
    """AsyncSession double emulating the adapter's narrow usage."""

    def __init__(self, rows: list[AuditEventRow] | None = None) -> None:
        self._rows = rows or []
        self.added: list[AuditEventRow] = []

    def add(self, row: AuditEventRow) -> None:
        """Record one added row."""
        self.added.append(row)

    async def flush(self) -> None:
        """Apply the version server default like the database would."""
        for row in self.added:
            if row.version is None:
                row.version = 1

    async def execute(self, _query: Any) -> FakeResult:
        """Return the configured rows for any query."""
        return FakeResult(self._rows)


def _event() -> AuditEvent:
    """Build one valid audit event fixture."""
    return AuditEvent(
        action=AuditAction.AUTH_LOGIN,
        outcome=AuditOutcome.SUCCESS,
        occurred_at=_NOW,
        actor_id=UUID(int=1),
        actor_username="alice",
        object_type="user",
        object_id=UUID(int=2),
        metadata={"attempted": "value"},
        version=0,
    )


def _row() -> AuditEventRow:
    """Build one persisted row fixture."""
    return AuditEventRow(
        id=UUID(int=3),
        action=AuditAction.AUTH_LOGOUT.value,
        outcome=AuditOutcome.FAILURE.value,
        occurred_at=_NOW,
        actor_id=UUID(int=1),
        actor_username="alice",
        object_type="user",
        object_id=UUID(int=2),
        metadata_={"attempted": "value"},
        version=4,
    )


@pytest.mark.asyncio
async def test_append_maps_the_event_and_its_metadata() -> None:
    """Append stores the metadata under its column name and maps it back."""
    session = FakeSession()
    repository = audit_repositories.PostgresAuditEventRepository(
        cast(AsyncSession, session)
    )
    event = _event()

    stored = await repository.append(event)

    assert len(session.added) == 1
    row = session.added[0]
    assert row.metadata_ == {"attempted": "value"}
    assert row.action == AuditAction.AUTH_LOGIN.value
    assert stored.id == event.id
    assert stored.metadata == {"attempted": "value"}
    assert stored.version == 1
    assert stored.actor_username == "alice"


@pytest.mark.asyncio
async def test_list_events_maps_rows_to_domain_models() -> None:
    """List maps persisted rows back to framework-independent events."""
    session = FakeSession(rows=[_row()])
    repository = audit_repositories.PostgresAuditEventRepository(
        cast(AsyncSession, session)
    )

    events = await repository.list_events()

    assert len(events) == 1
    event = events[0]
    assert event.id == UUID(int=3)
    assert event.action == AuditAction.AUTH_LOGOUT.value
    assert event.outcome is AuditOutcome.FAILURE
    assert event.occurred_at == _NOW
    assert event.metadata == {"attempted": "value"}
    assert event.version == 4


@pytest.mark.asyncio
async def test_list_events_applies_every_filter_dimension() -> None:
    """All supported filters pass through without changing the mapping."""
    session = FakeSession(rows=[])
    repository = audit_repositories.PostgresAuditEventRepository(
        cast(AsyncSession, session)
    )

    events = await repository.list_events(
        actor_id=UUID(int=1),
        action="urn:ati:action:auth:login",
        outcome=AuditOutcome.SUCCESS,
        object_type="user",
        object_id=UUID(int=2),
        occurred_after=_NOW,
        occurred_before=_NOW,
        limit=10,
        offset=5,
    )

    assert events == []


@pytest.mark.asyncio
async def test_list_events_rejects_negative_bounds() -> None:
    """Negative limits and offsets are refused before querying."""
    repository = audit_repositories.PostgresAuditEventRepository(
        cast(AsyncSession, FakeSession())
    )

    with pytest.raises(ValueError, match="non-negative"):
        await repository.list_events(limit=-1)
    with pytest.raises(ValueError, match="non-negative"):
        await repository.list_events(offset=-1)
