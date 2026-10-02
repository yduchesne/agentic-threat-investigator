# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31I one-hop consolidation parity suite (P-N01..P-N16).

PR 31I migrates the legacy direct-SQL one-hop ``neighborhood`` read onto the
existing ``ati.traverse_graph(..., max_depth=1)`` stored-function boundary.
These real-PostgreSQL parity tests are the acceptance gate for removing the
legacy SQL: for representative graph contexts, ``neighborhood(query)`` must
behave EXACTLY like ``traverse(equivalent query, max_depth=1)`` on nodes,
edges, per-edge support summaries, ``truncated``, focal-only results and the
``None`` visibility outcome. Every test exercises the production
``PostgresGraphQueryService`` against the isolated PostgreSQL database.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.graph import (
    GraphNeighborhoodQuery,
    GraphResult,
    GraphScope,
    GraphTraversalQuery,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import (
    FIXED_TIME,
    seed_entity,
    seed_evidence_observation,
    seed_investigation,
    seed_observation,
    seed_relationship,
)

DNS = "urn:ati:source:google_public_dns"
RDAP = "urn:ati:source:rdap"


async def _services(uow: PostgresUnitOfWork) -> PostgresQueryServices:
    """Return a query bundle bound to the isolated read session."""
    assert uow.session is not None
    return PostgresQueryServices(
        uow.session, QueryLimits(default_page_size=50, max_page_size=200)
    )


async def _both(
    services: PostgresQueryServices,
    investigation_id: UUID,
    entity_id: UUID,
    *,
    limit: int = 50,
    scope: GraphScope = GraphScope.INVESTIGATION,
    direction: RelationshipDirection = RelationshipDirection.EITHER,
    relationship_type: RelationshipType | None = None,
    entity_type: EntityType | None = None,
    source: str | None = None,
    observed_from: datetime | None = None,
    observed_to: datetime | None = None,
) -> tuple[GraphResult | None, GraphResult | None]:
    """Run neighborhood and the equivalent depth-1 traversal side by side."""
    neighborhood = await services.graph.neighborhood(
        GraphNeighborhoodQuery(
            investigation_id=investigation_id,
            entity_id=entity_id,
            limit=limit,
            scope=scope,
            direction=direction,
            relationship_type=relationship_type,
            entity_type=entity_type,
            source=source,
            observed_from=observed_from,
            observed_to=observed_to,
        )
    )
    traversal = await services.graph.traverse(
        GraphTraversalQuery(
            investigation_id=investigation_id,
            entity_id=entity_id,
            max_depth=1,
            limit=limit,
            scope=scope,
            direction=direction,
            relationship_type=relationship_type,
            entity_type=entity_type,
            source=source,
            observed_from=observed_from,
            observed_to=observed_to,
        )
    )
    return neighborhood, traversal


def _assert_parity(
    neighborhood: GraphResult | None, traversal: GraphResult | None
) -> None:
    """Assert exact one-hop parity on structure, ordering and summaries."""
    assert (neighborhood is None) == (traversal is None)
    if neighborhood is None or traversal is None:
        return
    assert [node.entity_id for node in neighborhood.nodes] == [
        node.entity_id for node in traversal.nodes
    ]
    assert [edge.relationship_id for edge in neighborhood.edges] == [
        edge.relationship_id for edge in traversal.edges
    ]
    assert neighborhood.truncated == traversal.truncated
    neighborhood_by_id = {edge.relationship_id: edge for edge in neighborhood.edges}
    for edge in traversal.edges:
        counterpart = neighborhood_by_id[edge.relationship_id]
        assert edge.observation_count == counterpart.observation_count
        assert edge.investigation_observation_count == (
            counterpart.investigation_observation_count
        )
        assert edge.first_observed_at == counterpart.first_observed_at
        assert edge.last_observed_at == counterpart.last_observed_at
        assert edge.source_entity_id == counterpart.source_entity_id
        assert edge.target_entity_id == counterpart.target_entity_id


async def _admit_edge(
    uow: PostgresUnitOfWork,
    *,
    investigation_id: UUID,
    source_entity_id: UUID,
    target_entity_id: UUID,
    relationship_type: RelationshipType = RelationshipType.RESOLVES_TO,
    source: str = DNS,
    observed_at: datetime | None = None,
) -> UUID:
    """Seed one Relationship with one admitted observation; return edge id."""
    rel = await seed_relationship(
        uow,
        source_entity_id=source_entity_id,
        target_entity_id=target_entity_id,
        relationship_type=relationship_type,
    )
    evidence = await seed_evidence_observation(
        uow, investigation_id=investigation_id, entity_id=source_entity_id
    )
    await seed_observation(
        uow,
        investigation_id=investigation_id,
        relationship=rel,
        evidence_observation_id=evidence,
        source=source,
        observed_at=observed_at,
    )
    return rel.id


async def _focal_world(
    uow: PostgresUnitOfWork,
    investigation_id: UUID,
    focal: UUID,
) -> tuple[UUID, UUID]:
    """Seed focal -> out and in -> focal; return (out edge id, in edge id)."""
    b = await seed_entity(uow, value="b.test")
    c = await seed_entity(uow, value="c.test")
    out_edge = await _admit_edge(
        uow,
        investigation_id=investigation_id,
        source_entity_id=focal,
        target_entity_id=b,
    )
    in_edge = await _admit_edge(
        uow,
        investigation_id=investigation_id,
        source_entity_id=c,
        target_entity_id=focal,
    )
    return out_edge, in_edge


async def _visible_focal(uow: PostgresUnitOfWork, investigation_id: UUID) -> UUID:
    """Create and admit one visible isolated focal Entity."""
    focal = await seed_entity(uow, value="focal.test")
    await seed_evidence_observation(
        uow, investigation_id=investigation_id, entity_id=focal
    )
    return focal


# --- P-N01/N02 scope parity -----------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn01_investigation_scope_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N01: Investigation-scope neighborhood equals depth-1 traversal."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        await _focal_world(uow, investigation_id, focal)
        services = await _services(uow)
        neighborhood, traversal = await _both(services, investigation_id, focal)
        _assert_parity(neighborhood, traversal)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn02_known_scope_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N02: Known-scope neighborhood equals depth-1 traversal."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        focal = await _visible_focal(uow, i1)
        # Global-only support (admitted to another Investigation).
        b = await seed_entity(uow, value="global.test")
        rel = await seed_relationship(uow, source_entity_id=focal, target_entity_id=b)
        evidence = await seed_evidence_observation(
            uow, investigation_id=i2, entity_id=focal
        )
        await seed_observation(
            uow, investigation_id=i2, relationship=rel, evidence_observation_id=evidence
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services, i1, focal, scope=GraphScope.KNOWN
        )
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None
        assert {e.relationship_id for e in neighborhood.edges} == {rel.id}


# --- P-N03..N06 source/time filter parity ---------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn03_source_filter_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N03: an exact source filter changes both reads identically."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=b,
            source=DNS,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=c,
            source=RDAP,
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services, investigation_id, focal, source=DNS
        )
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None
        assert len(neighborhood.edges) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn04_observed_from_only_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N04: an observed_from-only bound filters both reads identically."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        b = await seed_entity(uow, value="b.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=b,
            observed_at=FIXED_TIME + timedelta(days=10),
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services,
            investigation_id,
            focal,
            observed_from=FIXED_TIME + timedelta(days=5),
        )
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None and len(neighborhood.edges) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn05_observed_to_only_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N05: an observed_to-only bound filters both reads identically."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=b,
            observed_at=FIXED_TIME,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=c,
            observed_at=FIXED_TIME + timedelta(days=30),
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services,
            investigation_id,
            focal,
            observed_to=FIXED_TIME + timedelta(days=10),
        )
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None and len(neighborhood.edges) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn06_half_open_interval_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N06: half-open [from, to) semantics match exactly, boundary excluded."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=b,
            observed_at=FIXED_TIME,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=c,
            observed_at=FIXED_TIME + timedelta(days=10),
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services,
            investigation_id,
            focal,
            observed_from=FIXED_TIME,
            observed_to=FIXED_TIME + timedelta(days=10),
        )
        _assert_parity(neighborhood, traversal)
        # The interval is half-open: the boundary observation is excluded.
        assert neighborhood is not None and len(neighborhood.edges) == 1


# --- P-N07..N10 type/direction parity -------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn07_relationship_type_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N07: a Relationship type filter changes both reads identically."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=b,
            relationship_type=RelationshipType.RESOLVES_TO,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=c,
            relationship_type=RelationshipType.CNAME_OF,
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services,
            investigation_id,
            focal,
            relationship_type=RelationshipType.CNAME_OF,
        )
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None and len(neighborhood.edges) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn08_entity_type_source_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N08: a connected-Entity-type filter (SOURCE) matches exactly."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, entity_type=EntityType.DOMAIN, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        ip = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.1"
        )
        domain = await seed_entity(uow, entity_type=EntityType.DOMAIN, value="b.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=ip,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=domain,
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services,
            investigation_id,
            focal,
            entity_type=EntityType.IP_ADDRESS,
        )
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None and len(neighborhood.edges) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn09_entity_type_target_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N09: a connected-Entity-type filter (TARGET focal-relative) matches."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        ip = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.1"
        )
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=ip
        )
        domain = await seed_entity(uow, entity_type=EntityType.DOMAIN, value="a.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=domain,
            target_entity_id=ip,
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services,
            investigation_id,
            ip,
            direction=RelationshipDirection.TARGET,
            entity_type=EntityType.DOMAIN,
        )
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None and len(neighborhood.edges) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn10_entity_type_either_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N10: a connected-Entity-type filter (EITHER) matches exactly."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        ip_target = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.1"
        )
        domain_source = await seed_entity(
            uow, entity_type=EntityType.DOMAIN, value="in.test"
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=ip_target,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=domain_source,
            target_entity_id=focal,
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services, investigation_id, focal, entity_type=EntityType.IP_ADDRESS
        )
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None
        assert {e.relationship_id for e in neighborhood.edges} == {
            e.relationship_id for e in neighborhood.edges if e.target_entity_id != focal
        }


# --- P-N11..N12 self-loop / mixed support ---------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn11_self_loop_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N11: a self-loop appears once in both reads."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        loop = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=focal,
        )
        services = await _services(uow)
        neighborhood, traversal = await _both(services, investigation_id, focal)
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None
        assert {e.relationship_id for e in neighborhood.edges} == {loop}
        assert [n.entity_id for n in neighborhood.nodes] == [focal]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn12_mixed_support_parity_with_counts(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N12: mixed admitted/global support counts match across both reads."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        focal = await _visible_focal(uow, i1)
        b = await seed_entity(uow, value="b.test")
        edge = await seed_relationship(uow, source_entity_id=focal, target_entity_id=b)
        evidence = await seed_evidence_observation(
            uow, investigation_id=i1, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=i1,
            relationship=edge,
            evidence_observation_id=evidence,
            source=DNS,
        )
        # One extra global observation from another Investigation.
        global_evidence = await seed_evidence_observation(
            uow, investigation_id=i2, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=i2,
            relationship=edge,
            evidence_observation_id=global_evidence,
            source=DNS,
        )
        services = await _services(uow)
        for scope in (GraphScope.INVESTIGATION, GraphScope.KNOWN):
            neighborhood, traversal = await _both(services, i1, focal, scope=scope)
            _assert_parity(neighborhood, traversal)
            assert neighborhood is not None
        known_neighborhood, _ = await _both(services, i1, focal, scope=GraphScope.KNOWN)
        assert known_neighborhood is not None
        edge_projection = known_neighborhood.edges[0]
        assert edge_projection.observation_count == 2
        assert edge_projection.investigation_observation_count == 1


# --- P-N13..N16 visibility / truncation / determinism ---------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn13_visible_isolated_focal_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N13: a visible isolated focal is focal-only in both reads."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        services = await _services(uow)
        neighborhood, traversal = await _both(services, investigation_id, focal)
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None
        assert [n.entity_id for n in neighborhood.nodes] == [focal]
        assert neighborhood.edges == ()
        assert neighborhood.truncated is False
        assert traversal is not None and traversal.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn14_invisible_focal_both_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N14: an Investigation-invisible focal returns None from both reads."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        invisible = await seed_entity(uow, value="invisible.test")
        await seed_evidence_observation(uow, investigation_id=i2, entity_id=invisible)
        services = await _services(uow)
        for scope in (GraphScope.INVESTIGATION, GraphScope.KNOWN):
            neighborhood, traversal = await _both(services, i1, invisible, scope=scope)
            _assert_parity(neighborhood, traversal)
            assert neighborhood is None
        # A wholly missing focal is also None in both reads.
        neighborhood, traversal = await _both(services, i1, uuid4())
        _assert_parity(neighborhood, traversal)
        assert neighborhood is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn15_truncating_limit_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N15: a truncating limit yields exact parity including truncated."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        for index in range(3):
            target = await seed_entity(uow, value=f"t{index}.test")
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=focal,
                target_entity_id=target,
            )
        services = await _services(uow)
        neighborhood, traversal = await _both(
            services, investigation_id, focal, limit=2
        )
        _assert_parity(neighborhood, traversal)
        assert neighborhood is not None
        assert len(neighborhood.edges) == 2
        assert neighborhood.truncated is True
        assert traversal is not None and len(traversal.edges) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pn16_deterministic_repeated_call_parity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-N16: repeated calls return identical deterministic ordering."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await _visible_focal(uow, investigation_id)
        for index in range(4):
            target = await seed_entity(uow, value=f"t{index}.test")
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=focal,
                target_entity_id=target,
            )
        services = await _services(uow)
        first_neighborhood, first_traversal = await _both(
            services, investigation_id, focal
        )
        second_neighborhood, second_traversal = await _both(
            services, investigation_id, focal
        )
        assert first_neighborhood is not None and second_neighborhood is not None
        assert [e.relationship_id for e in first_neighborhood.edges] == [
            e.relationship_id for e in second_neighborhood.edges
        ]
        assert first_traversal is not None and second_traversal is not None
        assert [e.relationship_id for e in first_traversal.edges] == [
            e.relationship_id for e in second_traversal.edges
        ]
        _assert_parity(first_neighborhood, first_traversal)
