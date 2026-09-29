# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A integration: Investigation-scoped Relationship listing (23A-I04)."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

import pytest

from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.relationships import (
    RelationshipListQuery,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import RelationshipType
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import (
    seed_entity,
    seed_evidence_observation,
    seed_investigation,
    seed_observation,
    seed_relationship,
)


async def _collect_relationship_ids(
    services: PostgresQueryServices, query: RelationshipListQuery
) -> list[UUID]:
    """Follow cursors to completion, returning every relationship ID."""
    collected: list[UUID] = []
    cursor: str | None = None
    while True:
        page = await services.relationships.list(
            query.model_copy(update={"cursor": cursor})
        )
        collected.extend(item.relationship.id for item in page.items)
        if page.next_cursor is None:
            return collected
        cursor = page.next_cursor


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_appears_once_per_investigation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A relationship observed repeatedly appears exactly once per list."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        source = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        other = await seed_entity(uow, value="192.0.2.2")

        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        second_edge = await seed_relationship(
            uow,
            source_entity_id=source,
            target_entity_id=other,
            relationship_type=RelationshipType.CNAME_OF,
        )
        # Three observations of the same edge inside investigation A.
        for _ in range(3):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_a, entity_id=source
            )
            await seed_observation(
                uow,
                investigation_id=investigation_a,
                relationship=edge,
                evidence_observation_id=evidence,
            )
        # One observation of the same edge inside investigation B.
        evidence_b = await seed_evidence_observation(
            uow, investigation_id=investigation_b, entity_id=source
        )
        await seed_observation(
            uow,
            investigation_id=investigation_b,
            relationship=edge,
            evidence_observation_id=evidence_b,
        )
        # A single observation of the second edge inside investigation A.
        evidence_a2 = await seed_evidence_observation(
            uow, investigation_id=investigation_a, entity_id=source
        )
        await seed_observation(
            uow,
            investigation_id=investigation_a,
            relationship=second_edge,
            evidence_observation_id=evidence_a2,
        )

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        in_a = await _collect_relationship_ids(
            services,
            RelationshipListQuery(investigation_id=investigation_a, limit=1),
        )
        assert in_a == sorted([edge.id, second_edge.id])
        in_b = await _collect_relationship_ids(
            services,
            RelationshipListQuery(investigation_id=investigation_b, limit=10),
        )
        assert in_b == [edge.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_source_target_type_filters(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Source, target, and type filters narrow the distinct edge set."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(uow, value="example.com")
        target_a = await seed_entity(uow, value="192.0.2.1")
        target_b = await seed_entity(uow, value="192.0.2.2")
        other_source = await seed_entity(uow, value="other.example.net")

        edge_a = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target_a
        )
        edge_b = await seed_relationship(
            uow,
            source_entity_id=source,
            target_entity_id=target_b,
            relationship_type=RelationshipType.CNAME_OF,
        )
        edge_c = await seed_relationship(
            uow, source_entity_id=other_source, target_entity_id=target_a
        )
        for edge in (edge_a, edge_b, edge_c):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=source
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        by_source = await _collect_relationship_ids(
            services,
            RelationshipListQuery(
                investigation_id=investigation_id,
                source_entity_id=source,
                limit=10,
            ),
        )
        assert by_source == sorted([edge_a.id, edge_b.id])
        by_target = await _collect_relationship_ids(
            services,
            RelationshipListQuery(
                investigation_id=investigation_id,
                target_entity_id=target_a,
                limit=10,
            ),
        )
        assert by_target == sorted([edge_a.id, edge_c.id])
        by_type = await _collect_relationship_ids(
            services,
            RelationshipListQuery(
                investigation_id=investigation_id,
                relationship_type=RelationshipType.CNAME_OF,
                limit=10,
            ),
        )
        assert by_type == [edge_b.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_soft_deleted_relationship_hidden(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A soft-deleted edge is never listed through observations."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=source
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
        )
        await uow.relationships.soft_delete(edge.id)

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationships.list(
            RelationshipListQuery(investigation_id=investigation_id, limit=10)
        )
        assert page.items == ()
        assert page.next_cursor is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_endpoint_presentation_metadata(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """List and exact GET carry endpoint Entity type/value (PR 31F-5 D3).

    The stable Relationship identity stays primary while the joined
    source/target Entity presentation semantics ship with the page — never
    one Entity GET per edge and no persisted duplicates. A self-edge joins
    both endpoint aliases to the same row.
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(
            uow, entity_type=EntityType.DOMAIN, value="update-package.test"
        )
        target = await seed_entity(
            uow, entity_type=EntityType.MALWARE, value="malware.badloader_v2"
        )
        self_source = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.1"
        )
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        self_edge = await seed_relationship(
            uow,
            source_entity_id=self_source,
            target_entity_id=self_source,
            relationship_type=RelationshipType.USES_MAIL_SERVER,
        )
        for current in (edge, self_edge):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=source
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=current,
                evidence_observation_id=evidence,
            )

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationships.list(
            RelationshipListQuery(investigation_id=investigation_id, limit=10)
        )
        by_id = {item.relationship.id: item for item in page.items}
        assert by_id[edge.id].source_entity_value == "update-package.test"
        assert by_id[edge.id].source_entity_type == EntityType.DOMAIN
        assert by_id[edge.id].target_entity_value == "malware.badloader_v2"
        assert by_id[edge.id].target_entity_type == EntityType.MALWARE
        # A self-edge joins both aliases to the same Entity row.
        assert by_id[self_edge.id].source_entity_value == "192.0.2.1"
        assert by_id[self_edge.id].target_entity_value == "192.0.2.1"
        assert by_id[self_edge.id].target_entity_type == EntityType.IP_ADDRESS

        exact = await services.relationships.get(investigation_id, edge.id)
        assert exact is not None
        assert exact.relationship.id == edge.id
        assert exact.source_entity_type == EntityType.DOMAIN
        assert exact.target_entity_value == "malware.badloader_v2"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_endpoint_presentation_is_investigation_scoped(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Cross-Investigation exact reads stay fail-closed with enrichment."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        source = await seed_entity(
            uow, entity_type=EntityType.DOMAIN, value="update-package.test"
        )
        target = await seed_entity(
            uow, entity_type=EntityType.MALWARE, value="malware.badloader_v2"
        )
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        evidence_a = await seed_evidence_observation(
            uow, investigation_id=investigation_a, entity_id=source
        )
        await seed_observation(
            uow,
            investigation_id=investigation_a,
            relationship=edge,
            evidence_observation_id=evidence_a,
        )

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        visible = await services.relationships.get(investigation_a, edge.id)
        hidden = await services.relationships.get(investigation_b, edge.id)
        assert visible is not None
        assert visible.source_entity_value == "update-package.test"
        assert hidden is None
