# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A integration: Investigation keyset listing (23A-I01)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from agentic_threat_investigator.app.query.investigations import (
    InvestigationListQuery,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.pagination import (
    CursorFilterMismatchError,
    CursorQueryMismatchError,
)
from agentic_threat_investigator.domain.investigation import InvestigationStatus
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import FIXED_TIME, seed_investigation


async def _collect_all(
    services: PostgresQueryServices,
    query: InvestigationListQuery,
) -> list[UUID]:
    """Follow cursors to completion, returning every investigation ID."""
    collected: list[UUID] = []
    cursor: str | None = None
    while True:
        page = await services.investigations.list(
            query.model_copy(update={"cursor": cursor})
        )
        collected.extend(item.investigation_id for item in page.items)
        if page.next_cursor is None:
            return collected
        cursor = page.next_cursor


@pytest.mark.asyncio
@pytest.mark.integration
async def test_newest_first_with_cursor_continuation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Investigations list newest-first with no skips or duplicates."""
    async with uow_factory() as uow:
        first = await seed_investigation(uow, created_at=FIXED_TIME)
        second = await seed_investigation(
            uow, created_at=FIXED_TIME + timedelta(days=1)
        )
        third = await seed_investigation(uow, created_at=FIXED_TIME + timedelta(days=2))
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_all(services, InvestigationListQuery(limit=2))
        assert collected == [third, second, first]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_duplicate_created_at_uuid_tie_break(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Identical created_at values order deterministically by ascending id."""
    async with uow_factory() as uow:
        ids = [await seed_investigation(uow, created_at=FIXED_TIME) for _ in range(4)]
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_all(services, InvestigationListQuery(limit=2))
        assert collected == sorted(ids)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_status_filter_isolation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A status filter returns only matching investigations."""
    async with uow_factory() as uow:
        running = await seed_investigation(uow, status=InvestigationStatus.RUNNING)
        await seed_investigation(uow, status=InvestigationStatus.COMPLETED)
        await seed_investigation(uow, status=InvestigationStatus.FAILED)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_all(
            services,
            InvestigationListQuery(status=InvestigationStatus.RUNNING, limit=10),
        )
        assert collected == [running]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_created_date_bounds_are_half_open(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """created_from is inclusive and created_to is exclusive (UTC)."""
    async with uow_factory() as uow:
        before = await seed_investigation(
            uow, created_at=datetime(2026, 1, 1, tzinfo=UTC)
        )
        inside = await seed_investigation(
            uow, created_at=datetime(2026, 1, 2, tzinfo=UTC)
        )
        await seed_investigation(uow, created_at=datetime(2026, 1, 3, tzinfo=UTC))
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.investigations.list(
            InvestigationListQuery(
                created_from=datetime(2026, 1, 1, tzinfo=UTC),
                created_to=datetime(2026, 1, 3, tzinfo=UTC),
                limit=50,
            )
        )
        # before == from is included; the to boundary is excluded.
        assert {item.investigation_id for item in page.items} == {before, inside}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_soft_deleted_investigations_hidden(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Normal listing never returns soft-deleted investigations."""
    async with uow_factory() as uow:
        visible = await seed_investigation(uow)
        deleted = await seed_investigation(uow)
        await uow.investigations.soft_delete(deleted)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_all(services, InvestigationListQuery(limit=10))
        assert collected == [visible]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_cursor_filter_mismatch_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A cursor from another filter set is rejected with a typed error."""
    async with uow_factory() as uow:
        # Two RUNNING investigations guarantee a continuation cursor.
        await seed_investigation(uow, status=InvestigationStatus.RUNNING)
        await seed_investigation(uow, status=InvestigationStatus.RUNNING)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.investigations.list(
            InvestigationListQuery(status=InvestigationStatus.RUNNING, limit=1)
        )
        assert page.next_cursor is not None
        with pytest.raises(CursorFilterMismatchError):
            await services.investigations.list(
                InvestigationListQuery(
                    status=InvestigationStatus.COMPLETED,
                    limit=1,
                    cursor=page.next_cursor,
                )
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_cursor_query_kind_mismatch_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A cursor from another collection is rejected with a typed error."""
    async with uow_factory() as uow:
        # Two investigations guarantee a continuation cursor.
        await seed_investigation(uow)
        await seed_investigation(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.investigations.list(InvestigationListQuery(limit=1))
        assert page.next_cursor is not None
        # Re-encode the same values under the Evidence query kind.
        from agentic_threat_investigator.app.query.pagination import (
            CursorEnvelope,
            QueryKind,
            decode_cursor,
            encode_cursor,
        )

        envelope = decode_cursor(page.next_cursor)
        forged = encode_cursor(
            CursorEnvelope(
                query_kind=QueryKind.EVIDENCE,
                filter_fingerprint=envelope.filter_fingerprint,
                sort_values=envelope.sort_values,
            )
        )
        with pytest.raises(CursorQueryMismatchError):
            await services.investigations.list(
                InvestigationListQuery(limit=1, cursor=forged)
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_limit_above_configured_maximum_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Page limits over the configured maximum fail closed."""
    async with uow_factory() as uow:
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        with pytest.raises(ValueError):
            await services.investigations.list(InvestigationListQuery(limit=201))


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unknown_investigation_returns_empty_page(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An investigation scope with no rows yields an empty final page."""
    async with uow_factory() as uow:
        await seed_investigation(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.investigations.list(
            InvestigationListQuery(status=InvestigationStatus.FAILED, limit=50)
        )
        assert page.items == ()
        assert page.next_cursor is None
