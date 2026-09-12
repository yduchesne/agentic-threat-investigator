# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A integration: ResearchResult keyset listing (23A-I07)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.research import ResearchResultListQuery
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import FIXED_TIME, seed_entity, seed_investigation


def research_result_factory(
    investigation_id: UUID,
    subject_entity_id: UUID,
    *,
    created_at: datetime,
) -> ResearchResult:
    """Build one deterministic immutable research result."""
    return ResearchResult(
        id=uuid4(),
        investigation_id=investigation_id,
        subject_entity_id=subject_entity_id,
        query="context for the subject",
        created_at=created_at,
    )


async def _collect_result_ids(
    services: PostgresQueryServices, query: ResearchResultListQuery
) -> list[UUID]:
    """Follow cursors to completion, returning every result ID."""
    collected: list[UUID] = []
    cursor: str | None = None
    while True:
        page = await services.research_results.list(
            query.model_copy(update={"cursor": cursor})
        )
        collected.extend(item.id for item in page.items)
        if page.next_cursor is None:
            return collected
        cursor = page.next_cursor


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_listing_subject_filter_and_range(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Research results list newest-first with subject/time filtering."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        subject_a = await seed_entity(uow, value="malware-a")
        subject_b = await seed_entity(uow, value="malware-b")

        result_b = research_result_factory(
            investigation_id,
            subject_b,
            created_at=FIXED_TIME + timedelta(days=2),
        )
        result_a_1 = research_result_factory(
            investigation_id,
            subject_a,
            created_at=FIXED_TIME + timedelta(days=1),
        )
        result_a_2 = research_result_factory(
            investigation_id,
            subject_a,
            created_at=FIXED_TIME,
        )
        await uow.research_results.add(result_b)
        await uow.research_results.add(result_a_1)
        await uow.research_results.add(result_a_2)

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        all_results = await _collect_result_ids(
            services,
            ResearchResultListQuery(investigation_id=investigation_id, limit=1),
        )
        assert all_results == [result_b.id, result_a_1.id, result_a_2.id]

        subject_a_results = await _collect_result_ids(
            services,
            ResearchResultListQuery(
                investigation_id=investigation_id,
                subject_entity_id=subject_a,
                limit=10,
            ),
        )
        assert subject_a_results == [result_a_1.id, result_a_2.id]

        ranged = await _collect_result_ids(
            services,
            ResearchResultListQuery(
                investigation_id=investigation_id,
                created_from=FIXED_TIME,
                created_to=FIXED_TIME + timedelta(days=2),
                limit=10,
            ),
        )
        assert ranged == [result_a_1.id, result_a_2.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_scope_isolation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Research results of another investigation never appear."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        subject = await seed_entity(uow, value="malware-a")
        other_investigation_id = await seed_investigation(uow)
        await uow.research_results.add(
            research_result_factory(
                other_investigation_id,
                subject,
                created_at=FIXED_TIME,
            )
        )
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.research_results.list(
            ResearchResultListQuery(investigation_id=investigation_id, limit=10)
        )
        assert page.items == ()
        assert page.next_cursor is None
