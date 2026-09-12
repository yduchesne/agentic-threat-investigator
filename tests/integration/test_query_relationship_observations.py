# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A integration: RelationshipObservation historical queries (23A-I05/I06/I14)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.relationships import (
    RelationshipObservationListQuery,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import (
    FIXED_TIME,
    evidence_factory,
    seed_entity,
    seed_investigation,
    seed_observation,
    seed_relationship,
)


async def _collect_observation_ids(
    services: PostgresQueryServices,
    query: RelationshipObservationListQuery,
) -> list[UUID]:
    """Follow cursors to completion, returning every observation ID."""
    collected: list[UUID] = []
    cursor: str | None = None
    while True:
        page = await services.relationship_observations.list(
            query.model_copy(update={"cursor": cursor})
        )
        collected.extend(item.id for item in page.items)
        if page.next_cursor is None:
            return collected
        cursor = page.next_cursor


async def _seed_observation_series(
    uow: PostgresUnitOfWork,
) -> tuple[UUID, tuple[UUID, ...], UUID]:
    """Seed one investigation, one edge, and three observations of it.

    Returns the investigation, the observed IDs in newest-retrieved-first
    order, and the relationship ID.
    """
    investigation_id = await seed_investigation(uow)
    source = await seed_entity(uow, value="example.com")
    target = await seed_entity(uow, value="192.0.2.1")
    edge = await seed_relationship(
        uow, source_entity_id=source, target_entity_id=target
    )
    observed: list[UUID] = []
    for minutes in (30, 20, 10):
        evidence = await uow.evidence.insert(
            evidence_factory(
                investigation_id,
                source,
                retrieved_at=FIXED_TIME + timedelta(minutes=minutes),
            )
        )
        observation = await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence=evidence,
            retrieved_at=FIXED_TIME + timedelta(minutes=minutes),
            observed_at=FIXED_TIME + timedelta(minutes=minutes),
        )
        observed.append(observation.id)
    return investigation_id, tuple(observed), edge.id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_observation_retrieved_history_newest_first(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Multiple observations of one relationship stay independently queryable."""
    async with uow_factory() as uow:
        _, observed, relationship_id = await _seed_observation_series(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_observation_ids(
            services,
            RelationshipObservationListQuery(relationship_id=relationship_id, limit=1),
        )
        # Newest retrieved first, exactly the seeding order, with stable
        # pagination across all three observations and no duplicates.
        assert collected == list(observed)
        assert len(collected) == 3


@pytest.mark.asyncio
@pytest.mark.integration
async def test_observation_investigation_scope(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Investigation-scoped observation listing isolates the investigation."""
    async with uow_factory() as uow:
        investigation_id, _, _ = await _seed_observation_series(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=investigation_id, limit=10
            )
        )
        assert len(page.items) == 3


@pytest.mark.asyncio
@pytest.mark.integration
async def test_observation_retrieved_date_range(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The retrieved-at half-open range filters the history series."""
    async with uow_factory() as uow:
        _, _, relationship_id = await _seed_observation_series(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_observation_ids(
            services,
            RelationshipObservationListQuery(
                relationship_id=relationship_id,
                retrieved_from=FIXED_TIME + timedelta(minutes=15),
                retrieved_to=FIXED_TIME + timedelta(minutes=35),
                limit=10,
            ),
        )
        assert len(collected) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_observation_observed_range_handles_null(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Observed-at filtering is half-open and handles NULL observed_at."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        before = await uow.evidence.insert(evidence_factory(investigation_id, source))
        inside = await uow.evidence.insert(evidence_factory(investigation_id, source))
        after = await uow.evidence.insert(evidence_factory(investigation_id, source))
        missing = await uow.evidence.insert(evidence_factory(investigation_id, source))
        inside_obs = await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence=inside,
            observed_at=FIXED_TIME + timedelta(days=1),
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence=before,
            observed_at=FIXED_TIME - timedelta(days=1),
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence=after,
            observed_at=FIXED_TIME + timedelta(days=2),
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence=missing,
            observed_at=None,
        )
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_observation_ids(
            services,
            RelationshipObservationListQuery(
                relationship_id=edge.id,
                observed_from=FIXED_TIME,
                observed_to=FIXED_TIME + timedelta(days=2),
                limit=10,
            ),
        )
        assert collected == [inside_obs.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_observation_not_duplicated_into_generic_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PR 22E regression: observations never appear in domain_object_history."""
    async with uow_factory() as uow:
        investigation_id, _, _ = await _seed_observation_series(uow)
        assert uow.session is not None
        history_count = int(
            (
                await uow.session.execute(
                    text(
                        "SELECT count(*) FROM ati.domain_object_history "
                        "WHERE object_type = 'relationship_observation'"
                    )
                )
            ).scalar_one()
        )
        assert history_count == 0
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=investigation_id, limit=10
            )
        )
        assert len(page.items) == 3
