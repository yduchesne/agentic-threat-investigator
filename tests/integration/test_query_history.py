# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A integration: generic domain-object history queries (23A-I10..I13)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

import pytest

from agentic_threat_investigator.app.query.history import (
    DomainHistoryListQuery,
    DomainObjectHistoryRecord,
    HistoryOperation,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import seed_investigation


async def _collect_history_ids(
    services: PostgresQueryServices, query: DomainHistoryListQuery
) -> list[UUID]:
    """Follow cursors to completion, returning every history row ID."""
    collected: list[UUID] = []
    cursor: str | None = None
    while True:
        page = await services.domain_history.list(
            query.model_copy(update={"cursor": cursor})
        )
        collected.extend(item.id for item in page.items)
        if page.next_cursor is None:
            return collected
        cursor = page.next_cursor


@pytest.mark.asyncio
@pytest.mark.integration
async def test_history_global_and_type_scoped(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Global history browses newest-first; type scope isolates one type."""
    async with uow_factory() as uow:
        await seed_investigation(uow)
        entity = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert entity.id is not None
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        # Global: investigation CREATE + entity CREATE rows, newest first.
        global_rows = await _collect_history_ids(
            services, DomainHistoryListQuery(limit=1)
        )
        assert len(global_rows) == 2
        type_rows = await _collect_history_ids(
            services,
            DomainHistoryListQuery(object_type="entity", limit=10),
        )
        assert len(type_rows) == 1
        type_rows_all = await _collect_history_ids(
            services,
            DomainHistoryListQuery(object_type="investigation", limit=10),
        )
        assert len(type_rows_all) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_history_one_object_complete_order(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """object_type + object_id returns only that object's complete history."""
    async with uow_factory() as uow:
        entity = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert entity.id is not None
        assert entity.version is not None
        entity_id = entity.id
        create_version = entity.version
        await uow.entities.upsert(
            Entity(
                type=EntityType.DOMAIN,
                value="example.com",
                display_name="renamed",
            )
        )
        await uow.entities.upsert(
            Entity(
                type=EntityType.DOMAIN,
                value="example.com",
                display_name="renamed-again",
            )
        )
        other = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="other.example.com")
        )
        assert other.id is not None
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        rows = await _collect_history_ids(
            services,
            DomainHistoryListQuery(object_type="entity", object_id=entity_id, limit=1),
        )
        # CREATE + two UPDATE history rows for this object only.
        assert len(rows) == 3
        records: list[DomainObjectHistoryRecord] = []
        cursor: str | None = None
        while True:
            page = await services.domain_history.list(
                DomainHistoryListQuery(
                    object_type="entity",
                    object_id=entity_id,
                    limit=2,
                    cursor=cursor,
                )
            )
            records.extend(page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        # Complete deterministic history: only this object's rows, exactly one
        # CREATE and two UPDATEs, and the CREATE carries the object's smallest
        # version. Within one transaction all rows may share occurred_at, so
        # ordering is the documented occurred_at DESC, id ASC contract rather
        # than semantic version order; the version set below is the robust
        # semantic assertion.
        assert all(record.object_id == entity_id for record in records)
        assert len(records) == 3
        assert [record.operation for record in records].count(
            HistoryOperation.CREATE
        ) == 1
        assert [record.operation for record in records].count(
            HistoryOperation.UPDATE
        ) == 2
        assert all(
            record.operation is not HistoryOperation.DELETE for record in records
        )
        versions = {record.version for record in records}
        assert len(versions) == 3
        assert create_version == min(versions)
        assert all(
            record.version > create_version
            for record in records
            if record.operation is HistoryOperation.UPDATE
        )
        # occurred_at is non-increasing under the canonical ordering contract.
        stamps = [record.occurred_at for record in records]
        assert stamps == sorted(stamps, reverse=True)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_history_exact_version_lookup(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Exact object_type + object_id + version lookup returns one row."""
    async with uow_factory() as uow:
        entity = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert entity.id is not None
        assert entity.version is not None
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        record = await services.domain_history.get_object_version(
            object_type="entity",
            object_id=entity.id,
            version=entity.version,
        )
        assert record is not None
        assert record.object_type == "entity"
        assert record.object_id == entity.id
        assert record.version == entity.version
        assert record.operation is HistoryOperation.CREATE
        assert (
            await services.domain_history.get_object_version(
                object_type="entity",
                object_id=entity.id,
                version=entity.version + 99,
            )
            is None
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_history_investigation_scope(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Investigation-scoped history isolates correlated rows strictly."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        # An unrelated entity create carries no investigation correlation.
        await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="unrelated.example.com")
        )
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        rows = await _collect_history_ids(
            services,
            DomainHistoryListQuery(investigation_id=investigation_id, limit=10),
        )
        # Only the investigation CREATE row is correlated.
        assert len(rows) == 1
        record = (
            await services.domain_history.list(
                DomainHistoryListQuery(investigation_id=investigation_id, limit=10)
            )
        ).items[0]
        assert record.investigation_id == investigation_id
        assert record.object_type == "investigation"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_history_operation_and_date_filters(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The bounded operation and date filters narrow history browsing."""
    async with uow_factory() as uow:
        await seed_investigation(uow)
        await uow.entities.upsert(Entity(type=EntityType.DOMAIN, value="example.com"))
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        creates = await _collect_history_ids(
            services,
            DomainHistoryListQuery(operation=HistoryOperation.CREATE, limit=10),
        )
        assert len(creates) == 2
        updates = await _collect_history_ids(
            services,
            DomainHistoryListQuery(operation=HistoryOperation.UPDATE, limit=10),
        )
        assert updates == []
        future = await _collect_history_ids(
            services,
            DomainHistoryListQuery(
                occurred_from=datetime(2030, 1, 1, tzinfo=UTC), limit=10
            ),
        )
        assert future == []
