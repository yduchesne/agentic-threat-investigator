# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL coverage for the append-only investigation timeline."""

# pylint: disable=redefined-outer-name

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.investigation_timeline import (
    UnitOfWorkInvestigationTimelineSink,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.timeline_repositories import (
    PostgresInvestigationTimelineRepository,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
]

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


async def seed_investigation(uow: PostgresUnitOfWork) -> UUID:
    """Create one visible investigation through the current unit of work."""
    investigation_id = uuid4()
    await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[uuid4()],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
        )
    )
    await uow.commit()
    return investigation_id


def timeline_event(
    investigation_id: UUID, occurred_at: datetime
) -> InvestigationTimelineEvent:
    """Build one deterministic timeline event for the investigation."""
    return InvestigationTimelineEvent(
        id=uuid4(),
        investigation_id=investigation_id,
        type=InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
        occurred_at=occurred_at,
        provider=SourceId.GOOGLE_PUBLIC_DNS,
        target_entity_id=uuid4(),
    )


async def test_append_and_chronological_read(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Events append and read back in deterministic chronological order."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        first = timeline_event(investigation_id, _RETRIEVED_AT)
        second = timeline_event(
            investigation_id, datetime(2026, 1, 2, 3, 4, 6, tzinfo=UTC)
        )
        await uow.timeline_events.append(second)
        await uow.timeline_events.append(first)
        await uow.commit()

    async with uow_factory() as reader:
        events = await reader.timeline_events.list_by_investigation(investigation_id)
    assert [event.id for event in events] == [first.id, second.id]
    assert events[0].type is InvestigationTimelineEventType.PROVIDER_WORK_STARTED
    assert events[0].provider == SourceId.GOOGLE_PUBLIC_DNS


async def test_foreign_key_rejects_unknown_investigation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Timeline events cannot reference an unknown investigation."""
    async with uow_factory() as uow:
        event = timeline_event(uuid4(), _RETRIEVED_AT)
        with pytest.raises(Exception):  # noqa: B017,PT011 - foreign-key violation
            await uow.timeline_events.append(event)
        await uow.rollback()


async def test_timeline_append_rolls_back_with_transaction(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A rolled-back transaction leaves no timeline rows behind."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await uow.timeline_events.append(
            timeline_event(investigation_id, _RETRIEVED_AT)
        )
        await uow.rollback()

    async with uow_factory() as reader:
        events = await reader.timeline_events.list_by_investigation(investigation_id)
    assert events == []


async def test_timeline_is_append_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The repository exposes no update or delete path for timeline events."""
    assert not hasattr(PostgresInvestigationTimelineRepository, "update")
    assert not hasattr(PostgresInvestigationTimelineRepository, "delete")
    assert not hasattr(PostgresInvestigationTimelineRepository, "soft_delete")


async def test_uow_sink_persists_events(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The application sink appends through one short transaction."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    sink = UnitOfWorkInvestigationTimelineSink(uow_factory)
    event = timeline_event(investigation_id, _RETRIEVED_AT)
    await sink.append(event)
    async with uow_factory() as reader:
        events = await reader.timeline_events.list_by_investigation(investigation_id)
    assert [item.id for item in events] == [event.id]
