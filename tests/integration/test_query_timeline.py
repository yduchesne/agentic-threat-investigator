# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A integration: timeline bounded chronological listing (23A-I09)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.timeline import TimelineListQuery
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import seed_investigation

_EVENT_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def timeline_event_factory(
    investigation_id: UUID,
    *,
    event_type: InvestigationTimelineEventType,
    occurred_at: datetime,
) -> InvestigationTimelineEvent:
    """Build one deterministic timeline event of the required shape."""
    if event_type is InvestigationTimelineEventType.INVESTIGATION_STARTED:
        return InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=investigation_id,
            type=event_type,
            occurred_at=occurred_at,
        )
    return InvestigationTimelineEvent(
        id=uuid4(),
        investigation_id=investigation_id,
        type=event_type,
        occurred_at=occurred_at,
        provider=SourceId("urn:ati:source:google_public_dns"),
        target_entity_id=uuid4(),
    )


async def _collect_event_ids(
    services: PostgresQueryServices, query: TimelineListQuery
) -> list[UUID]:
    """Follow cursors to completion, returning every event ID."""
    collected: list[UUID] = []
    cursor: str | None = None
    while True:
        page = await services.timeline_events.list(
            query.model_copy(update={"cursor": cursor})
        )
        collected.extend(item.id for item in page.items)
        if page.next_cursor is None:
            return collected
        cursor = page.next_cursor


@pytest.mark.asyncio
@pytest.mark.integration
async def test_timeline_chronological_then_sequence(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Timeline events order by occurred_at ASC then sequence ASC."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        started = timeline_event_factory(
            investigation_id,
            event_type=InvestigationTimelineEventType.INVESTIGATION_STARTED,
            occurred_at=_EVENT_TIME,
        )
        work_1 = timeline_event_factory(
            investigation_id,
            event_type=InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            occurred_at=_EVENT_TIME,
        )
        work_2 = timeline_event_factory(
            investigation_id,
            event_type=InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
            occurred_at=_EVENT_TIME + timedelta(minutes=1),
        )
        # All three share the same occurred_at: sequence decides the order.
        for event in (started, work_1):
            await uow.timeline_events.append(event)
        await uow.timeline_events.append(work_2)

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_event_ids(
            services,
            TimelineListQuery(investigation_id=investigation_id, limit=1),
        )
        assert collected == [started.id, work_1.id, work_2.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_timeline_event_type_filter(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The bounded event-type filter isolates one event family."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        started = timeline_event_factory(
            investigation_id,
            event_type=InvestigationTimelineEventType.INVESTIGATION_STARTED,
            occurred_at=_EVENT_TIME,
        )
        work = timeline_event_factory(
            investigation_id,
            event_type=InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            occurred_at=_EVENT_TIME + timedelta(minutes=1),
        )
        await uow.timeline_events.append(started)
        await uow.timeline_events.append(work)

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_event_ids(
            services,
            TimelineListQuery(
                investigation_id=investigation_id,
                event_type=InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
                limit=10,
            ),
        )
        assert collected == [work.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_timeline_occurred_range_and_isolation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The occurred-at range filters and other investigations never appear."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        other = await seed_investigation(uow)
        inside = timeline_event_factory(
            investigation_id,
            event_type=InvestigationTimelineEventType.INVESTIGATION_STARTED,
            occurred_at=_EVENT_TIME,
        )
        outside = timeline_event_factory(
            investigation_id,
            event_type=InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            occurred_at=_EVENT_TIME + timedelta(hours=2),
        )
        other_event = timeline_event_factory(
            other,
            event_type=InvestigationTimelineEventType.INVESTIGATION_STARTED,
            occurred_at=_EVENT_TIME,
        )
        for event in (inside, outside, other_event):
            await uow.timeline_events.append(event)

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_event_ids(
            services,
            TimelineListQuery(
                investigation_id=investigation_id,
                occurred_from=_EVENT_TIME,
                occurred_to=_EVENT_TIME + timedelta(hours=1),
                limit=10,
            ),
        )
        assert collected == [inside.id]
        # Events of another investigation never appear.
        isolated = await _collect_event_ids(
            services,
            TimelineListQuery(investigation_id=investigation_id, limit=10),
        )
        assert other_event.id not in isolated
