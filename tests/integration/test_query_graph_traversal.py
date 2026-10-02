# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31H integration: bounded PostgreSQL multi-hop graph traversal.

Every test exercises the real schema, the versioned ``ati.traverse_graph``
stored function and the production service adapter:

``Entity / EvidenceObservation / InvestigationEvidence -> Relationship /
RelationshipObservation -> ati.traverse_graph -> PostgresGraphQueryService
.traverse() -> GraphResult``

The H-I matrix validates depth boundaries, direction at every frontier,
cycle/self-loop safety, filters before recursion, scope provenance,
deletion, deterministic ordering, truthful truncation, summary correctness
and endpoint closure against real PostgreSQL. The stored-function boundary
tests (H-SF) prove the function is created by the migration and that
visibility/eligibility/recursion/aggregation are stored-function-owned.
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


async def _traverse(
    services: PostgresQueryServices,
    investigation_id: UUID,
    entity_id: UUID,
    *,
    max_depth: int = 2,
    limit: int = 50,
    scope: GraphScope = GraphScope.INVESTIGATION,
    direction: RelationshipDirection = RelationshipDirection.EITHER,
    relationship_type: RelationshipType | None = None,
    entity_type: EntityType | None = None,
    source: str | None = None,
) -> GraphResult | None:
    """Run one bounded traversal query through the production service."""
    return await services.graph.traverse(
        GraphTraversalQuery(
            investigation_id=investigation_id,
            entity_id=entity_id,
            max_depth=max_depth,
            limit=limit,
            scope=scope,
            direction=direction,
            relationship_type=relationship_type,
            entity_type=entity_type,
            source=source,
        )
    )


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


async def _chain(
    uow: PostgresUnitOfWork,
    investigation_id: UUID,
    focal: UUID,
    size: int,
    *,
    entity_type: EntityType = EntityType.DOMAIN,
) -> tuple[list[UUID], list[UUID]]:
    """Seed focal -> e1 -> ... and return (non-focal entity ids, edge ids)."""
    entities: list[UUID] = []
    edges: list[UUID] = []
    previous = focal
    for index in range(size):
        entity_id = await seed_entity(
            uow, entity_type=entity_type, value=f"chain-{index + 1}.test"
        )
        entities.append(entity_id)
        edges.append(
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=previous,
                target_entity_id=entity_id,
            )
        )
        previous = entity_id
    return entities, edges


# ---------------------------------------------------------------------------
# H-I01..H-I07 topology and depth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi01_chain_depth_boundaries(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I01: A→B→C→D→E returns exactly the depth-1/2/3 boundary edges."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        entities, edges = await _chain(uow, investigation_id, focal, 4)
        services = await _services(uow)

        depth1 = await _traverse(services, investigation_id, focal, max_depth=1)
        assert depth1 is not None
        assert {e.relationship_id for e in depth1.edges} == {edges[0]}
        assert depth1.truncated is False
        assert {n.entity_id for n in depth1.nodes} == {focal, entities[0]}

        depth2 = await _traverse(services, investigation_id, focal, max_depth=2)
        assert depth2 is not None
        assert {e.relationship_id for e in depth2.edges} == {edges[0], edges[1]}
        assert {n.entity_id for n in depth2.nodes} == {focal, entities[0], entities[1]}

        depth3 = await _traverse(services, investigation_id, focal, max_depth=3)
        assert depth3 is not None
        assert {e.relationship_id for e in depth3.edges} == {
            edges[0],
            edges[1],
            edges[2],
        }
        assert {n.entity_id for n in depth3.nodes} == {
            focal,
            entities[0],
            entities[1],
            entities[2],
        }
        # Depth 4 is rejected by the contract (H-U05) and never traversed:
        # the stored function refuses it defensively too.
        assert {e.relationship_id for e in depth3.edges} == set(edges[:3])


async def _mixed_world(
    uow: PostgresUnitOfWork, investigation_id: UUID
) -> tuple[UUID, list[UUID], list[UUID]]:
    """Seed D -> X (outgoing domain) and Y -> D (incoming domain).

    Returns (focal, entity ids, edge ids) with edge ids ordered focally:
    ``[outgoing D->X, incoming Y->D]``.
    """
    focal = await seed_entity(uow, value="focal.test")
    await seed_evidence_observation(
        uow, investigation_id=investigation_id, entity_id=focal
    )
    x = await seed_entity(uow, value="x.test")
    y = await seed_entity(uow, value="y.test")
    outgoing = await _admit_edge(
        uow,
        investigation_id=investigation_id,
        source_entity_id=focal,
        target_entity_id=x,
    )
    incoming = await _admit_edge(
        uow,
        investigation_id=investigation_id,
        source_entity_id=y,
        target_entity_id=focal,
    )
    return focal, [x, y], [outgoing, incoming]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi02_source_applies_at_every_frontier(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I02: SOURCE follows source→target at every frontier."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal, entities, edges = await _mixed_world(uow, investigation_id)
        services = await _services(uow)
        result = await _traverse(
            services,
            investigation_id,
            focal,
            max_depth=2,
            direction=RelationshipDirection.SOURCE,
        )
        assert result is not None
        assert {e.relationship_id for e in result.edges} == {edges[0]}
        assert {n.entity_id for n in result.nodes} == {focal, entities[0]}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi03_target_applies_at_every_frontier(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I03: TARGET follows target→source at every frontier."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal, entities, edges = await _mixed_world(uow, investigation_id)
        services = await _services(uow)
        result = await _traverse(
            services,
            investigation_id,
            focal,
            max_depth=2,
            direction=RelationshipDirection.TARGET,
        )
        assert result is not None
        assert {e.relationship_id for e in result.edges} == {edges[1]}
        assert {n.entity_id for n in result.nodes} == {focal, entities[1]}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi04_either_follows_opposite_endpoint(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I04: EITHER follows either incident edge to its opposite endpoint."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal, entities, edges = await _mixed_world(uow, investigation_id)
        services = await _services(uow)
        result = await _traverse(services, investigation_id, focal, max_depth=2)
        assert result is not None
        assert {e.relationship_id for e in result.edges} == set(edges)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi05_cycle_terminates_with_canonical_dedup(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I05: A→B→C→A terminates and deduplicates canonical identities."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=a
        )
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        ab = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
        )
        bc = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=b,
            target_entity_id=c,
        )
        ca = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=c,
            target_entity_id=a,
        )
        services = await _services(uow)
        result = await _traverse(services, investigation_id, a, max_depth=3)
        assert result is not None
        # The cycle edge C->A is traversed (blocked branch) at depth 3 and the
        # recursion terminates: all three canonical edges appear exactly once.
        assert {e.relationship_id for e in result.edges} == {ab, bc, ca}
        assert {n.entity_id for n in result.nodes} == {a, b, c}
        assert len(result.edges) == len({e.relationship_id for e in result.edges})


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi06_self_loop_once_no_recursive_growth(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I06: A→A plus A→B returns the self-loop once without recursing."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=a
        )
        b = await seed_entity(uow, value="b.test")
        loop = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=a,
        )
        ab = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
        )
        services = await _services(uow)
        result = await _traverse(services, investigation_id, a, max_depth=3)
        assert result is not None
        assert {e.relationship_id for e in result.edges} == {loop, ab}
        assert {n.entity_id for n in result.nodes} == {a, b}
        # The self-loop never spawns deeper recursion: no extra edges appear.
        assert len(result.edges) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi07_diamond_d_once_e_reachable(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I07: diamond A→B/C→D→E keeps D once and reaches E at depth 3."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=a
        )
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        d = await seed_entity(uow, value="d.test")
        e = await seed_entity(uow, value="e.test")
        ab = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
        )
        ac = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=c,
        )
        bd = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=b,
            target_entity_id=d,
        )
        cd = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=c,
            target_entity_id=d,
        )
        de = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=d,
            target_entity_id=e,
        )
        services = await _services(uow)
        result = await _traverse(services, investigation_id, a, max_depth=3)
        assert result is not None
        assert {e.relationship_id for e in result.edges} == {ab, ac, bd, cd, de}
        node_ids = [n.entity_id for n in result.nodes]
        assert node_ids[0] == a
        assert d in node_ids and node_ids.count(d) == 1
        assert e in node_ids


# ---------------------------------------------------------------------------
# H-I08..H-I15 summaries, scope, filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi08_repeated_observations_one_edge_correct_summary(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I08: repeated observations yield one edge with correct summaries."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=a
        )
        b = await seed_entity(uow, value="b.test")
        rel = await seed_relationship(uow, source_entity_id=a, target_entity_id=b)
        for offset in (0, 2, 5):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=a
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=rel,
                evidence_observation_id=evidence,
                source=DNS,
                observed_at=FIXED_TIME + timedelta(days=offset),
            )
        services = await _services(uow)
        result = await _traverse(services, investigation_id, a, max_depth=1)
        assert result is not None
        assert len(result.edges) == 1
        edge = result.edges[0]
        assert edge.observation_count == 3
        assert edge.investigation_observation_count == 3
        assert edge.first_observed_at == FIXED_TIME
        assert edge.last_observed_at == FIXED_TIME + timedelta(days=5)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi09_cross_investigation_support_hidden(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I09: another Investigation's support is hidden in Investigation scope."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        focal = await seed_entity(uow, value="focal.test")
        await seed_evidence_observation(uow, investigation_id=i1, entity_id=focal)
        b = await seed_entity(uow, value="b.test")
        # The observation supporting focal->b is admitted only to I2.
        rel = await seed_relationship(uow, source_entity_id=focal, target_entity_id=b)
        evidence = await seed_evidence_observation(
            uow, investigation_id=i2, entity_id=focal
        )
        await seed_observation(
            uow, investigation_id=i2, relationship=rel, evidence_observation_id=evidence
        )
        services = await _services(uow)
        result = await _traverse(services, i1, focal, max_depth=2)
        assert result is not None
        assert result.edges == ()
        assert [n.entity_id for n in result.nodes] == [focal]
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi10_known_scope_global_support_traversable(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I10: Known scope traverses global edge support with truthful counts."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        focal = await seed_entity(uow, value="focal.test")
        await seed_evidence_observation(uow, investigation_id=i1, entity_id=focal)
        b = await seed_entity(uow, value="b.test")
        ab = await _admit_edge(
            uow, investigation_id=i1, source_entity_id=focal, target_entity_id=b
        )
        # focal -> c is supported only by an I2 observation (globally known).
        c = await seed_entity(uow, value="c.test")
        rel = await seed_relationship(uow, source_entity_id=focal, target_entity_id=c)
        evidence = await seed_evidence_observation(
            uow, investigation_id=i2, entity_id=focal
        )
        await seed_observation(
            uow, investigation_id=i2, relationship=rel, evidence_observation_id=evidence
        )
        services = await _services(uow)
        known = await _traverse(
            services, i1, focal, max_depth=1, scope=GraphScope.KNOWN
        )
        assert known is not None
        assert {e.relationship_id for e in known.edges} == {ab, rel.id}
        by_id = {e.relationship_id: e for e in known.edges}
        assert by_id[ab].investigation_observation_count == 1
        assert by_id[rel.id].investigation_observation_count == 0
        assert by_id[rel.id].observation_count == 1
        investigation = await _traverse(
            services, i1, focal, max_depth=1, scope=GraphScope.INVESTIGATION
        )
        assert investigation is not None
        assert {e.relationship_id for e in investigation.edges} == {ab}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi11_known_invisible_root_returns_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I11: Known scope never browses an Investigation-invisible root."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        invisible = await seed_entity(uow, value="invisible.test")
        await seed_evidence_observation(uow, investigation_id=i2, entity_id=invisible)
        services = await _services(uow)
        assert (
            await _traverse(
                services, i1, invisible, max_depth=2, scope=GraphScope.KNOWN
            )
            is None
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi12_source_filter_blocks_deeper_reach(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I12: a filtered intermediate edge blocks deeper reach."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=a
        )
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=b,
            target_entity_id=c,
            source=RDAP,
        )
        services = await _services(uow)
        result = await _traverse(services, investigation_id, a, max_depth=3, source=DNS)
        assert result is not None
        edge_ids = {e.relationship_id for e in result.edges}
        assert len(edge_ids) == 1
        assert {n.entity_id for n in result.nodes} == {a, b}
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi14_relationship_type_filter_blocks_deeper_reach(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I14: a filtered Relationship type blocks deeper reach."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=a
        )
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=b,
            target_entity_id=c,
            relationship_type=RelationshipType.CNAME_OF,
        )
        services = await _services(uow)
        result = await _traverse(
            services,
            investigation_id,
            a,
            max_depth=3,
            relationship_type=RelationshipType.RESOLVES_TO,
        )
        assert result is not None
        assert len(result.edges) == 1
        assert {n.entity_id for n in result.nodes} == {a, b}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi13_observed_interval_blocks_deeper_reach(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I13: an observed-interval-filtered intermediate edge blocks reach."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
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
            source_entity_id=b,
            target_entity_id=c,
            observed_at=FIXED_TIME + timedelta(days=30),
        )
        services = await _services(uow)
        query = GraphTraversalQuery(
            investigation_id=investigation_id,
            entity_id=focal,
            max_depth=3,
            limit=50,
            observed_from=FIXED_TIME,
            observed_to=FIXED_TIME + timedelta(days=1),
        )
        result = await services.graph.traverse(query)
        assert result is not None
        assert len(result.edges) == 1
        assert {n.entity_id for n in result.nodes} == {focal, b}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi15_connected_entity_type_applies_each_frontier(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I15: connected Entity type filters every next Entity, not just hop 1."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, entity_type=EntityType.DOMAIN, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        ip1 = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.1"
        )
        ip2 = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.2"
        )
        end = await seed_entity(uow, entity_type=EntityType.DOMAIN, value="end.test")
        for source_id, target_id in ((focal, ip1), (ip1, ip2), (ip2, end)):
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=source_id,
                target_entity_id=target_id,
            )
        services = await _services(uow)
        result = await _traverse(
            services,
            investigation_id,
            focal,
            max_depth=3,
            entity_type=EntityType.IP_ADDRESS,
        )
        assert result is not None
        # IP1 (hop 1) and IP2 (hop 2) qualify; the DOMAIN hop-3 target does not.
        ids = {e.relationship_id for e in result.edges}
        assert len(ids) == 2
        assert {n.entity_id for n in result.nodes} == {focal, ip1, ip2}
        assert end not in {n.entity_id for n in result.nodes}


# ---------------------------------------------------------------------------
# H-I16..H-I18 deletion semantics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi16_soft_deleted_relationship_not_traversable(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I16: a soft-deleted Relationship is absent and not traversable."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        ab = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=b,
        )
        bc = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=b,
            target_entity_id=c,
        )
        await uow.relationships.soft_delete(bc)
        services = await _services(uow)
        result = await _traverse(services, investigation_id, focal, max_depth=3)
        assert result is not None
        # The deleted intermediate edge is absent and never traversed: c is
        # unreachable while the still-live focal edge stays visible exactly once.
        assert {e.relationship_id for e in result.edges} == {ab}
        assert {n.entity_id for n in result.nodes} == {focal, b}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi17_soft_deleted_endpoint_not_traversable(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I17: a soft-deleted endpoint Entity is absent and not traversable."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        b = await seed_entity(uow, value="b.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=b,
        )
        await uow.entities.soft_delete(b)
        services = await _services(uow)
        result = await _traverse(services, investigation_id, focal, max_depth=2)
        assert result is not None
        assert result.edges == ()
        assert [n.entity_id for n in result.nodes] == [focal]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi18_null_observed_at_preserved(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I18: null observed_at follows current one-hop semantics."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        b = await seed_entity(uow, value="b.test")
        rel = await seed_relationship(uow, source_entity_id=focal, target_entity_id=b)
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=rel,
            evidence_observation_id=evidence,
            source=DNS,
            observed_at=None,
        )
        services = await _services(uow)
        result = await _traverse(services, investigation_id, focal, max_depth=1)
        assert result is not None
        assert len(result.edges) == 1
        edge = result.edges[0]
        assert edge.observation_count == 1
        assert edge.first_observed_at is None
        assert edge.last_observed_at is None


# ---------------------------------------------------------------------------
# H-I19..H-I21 equivalence/determinism
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi19_hi20_depth_one_equals_neighborhood(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I19/H-I20: depth-1 traversal topology+summary == one-hop neighborhood."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        # focal -> b carries two admitted observations (one canonical edge).
        rel_ab = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=b
        )
        for offset in (0, 3):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=rel_ab,
                evidence_observation_id=evidence,
                source=DNS,
                observed_at=FIXED_TIME + timedelta(days=offset),
            )
        # c -> focal carries one admitted observation.
        rel_ca = await seed_relationship(
            uow, source_entity_id=c, target_entity_id=focal
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=c
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=rel_ca,
            evidence_observation_id=evidence,
            source=DNS,
            observed_at=FIXED_TIME + timedelta(days=1),
        )
        services = await _services(uow)
        traversal = await _traverse(services, investigation_id, focal, max_depth=1)
        neighborhood = await services.graph.neighborhood(
            GraphNeighborhoodQuery(
                investigation_id=investigation_id,
                entity_id=focal,
                limit=50,
            )
        )
        assert traversal is not None and neighborhood is not None
        traversal_by_id = {e.relationship_id: e for e in traversal.edges}
        assert set(traversal_by_id) == {rel_ab.id, rel_ca.id}
        assert [e.relationship_id for e in traversal.edges] == [
            e.relationship_id for e in neighborhood.edges
        ]
        assert [n.entity_id for n in traversal.nodes] == [
            n.entity_id for n in neighborhood.nodes
        ]
        assert traversal.truncated == neighborhood.truncated
        for neighbor_edge in neighborhood.edges:
            edge = traversal_by_id[neighbor_edge.relationship_id]
            assert edge.observation_count == neighbor_edge.observation_count
            assert edge.investigation_observation_count == (
                neighbor_edge.investigation_observation_count
            )
            assert edge.first_observed_at == neighbor_edge.first_observed_at
            assert edge.last_observed_at == neighbor_edge.last_observed_at
        assert traversal_by_id[rel_ab.id].observation_count == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi21_deterministic_depth_uuid_ordering(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I21: relationships order by (minimum_hop_depth, relationship_id)."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=b,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=c,
        )
        services = await _services(uow)
        result = await _traverse(services, investigation_id, focal, max_depth=1)
        assert result is not None
        ids = [e.relationship_id for e in result.edges]
        assert ids == sorted(ids)
        assert ids[0] < ids[1]
        # Repeatability: identical query on the same snapshot repeats exactly.
        again = await _traverse(services, investigation_id, focal, max_depth=1)
        assert again is not None
        assert [e.relationship_id for e in again.edges] == ids


# ---------------------------------------------------------------------------
# H-I22..H-I28 bounds, truncation, isolation, cross-branch counts, max depth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi22_exactly_limit_edges_not_truncated(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I22: exactly ``limit`` eligible edges means truncated=False."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        for index in range(2):
            target = await seed_entity(uow, value=f"t{index}.test")
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=focal,
                target_entity_id=target,
            )
        services = await _services(uow)
        result = await _traverse(
            services, investigation_id, focal, max_depth=1, limit=2
        )
        assert result is not None
        assert len(result.edges) == 2
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi23_limit_plus_one_truncates(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I23: limit+1 eligible edges returns limit and truncated=True."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        for index in range(3):
            target = await seed_entity(uow, value=f"t{index}.test")
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=focal,
                target_entity_id=target,
            )
        services = await _services(uow)
        result = await _traverse(
            services, investigation_id, focal, max_depth=1, limit=2
        )
        assert result is not None
        assert len(result.edges) == 2
        assert result.truncated is True


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi24_truncated_result_endpoint_closure_retained(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I24: a truncated result keeps endpoint closure."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        targets = []
        for index in range(3):
            target = await seed_entity(uow, value=f"t{index}.test")
            targets.append(target)
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=focal,
                target_entity_id=target,
            )
        services = await _services(uow)
        result = await _traverse(
            services, investigation_id, focal, max_depth=1, limit=2
        )
        assert result is not None
        node_ids = {n.entity_id for n in result.nodes}
        for edge in result.edges:
            assert edge.source_entity_id in node_ids
            assert edge.target_entity_id in node_ids
        assert focal in node_ids


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi25_isolated_visible_focal_not_truncated(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I25: a visible isolated focal is focal-only, never truncated."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        services = await _services(uow)
        result = await _traverse(services, investigation_id, focal, max_depth=3)
        assert result is not None
        assert [n.entity_id for n in result.nodes] == [focal]
        assert result.edges == ()
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi26_missing_and_deleted_focal_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I26: missing or soft-deleted focal Entity returns None."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        services = await _services(uow)
        assert await _traverse(services, investigation_id, uuid4(), max_depth=2) is None
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await uow.entities.soft_delete(focal)
        assert await _traverse(services, investigation_id, focal, max_depth=2) is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi27_cross_branch_edge_no_count_multiplication(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I27: a cross-branch repeated edge is returned once with one summary."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        b = await seed_entity(uow, value="b.test")
        c = await seed_entity(uow, value="c.test")
        d = await seed_entity(uow, value="d.test")
        ab = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=b,
        )
        ac = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=focal,
            target_entity_id=c,
        )
        bd = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=b,
            target_entity_id=d,
        )
        cd = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=c,
            target_entity_id=d,
        )
        services = await _services(uow)
        result = await _traverse(services, investigation_id, focal, max_depth=2)
        assert result is not None
        assert len({e.relationship_id for e in result.edges}) == 4
        by_id = {e.relationship_id: e for e in result.edges}
        for edge_id in (ab, ac, bd, cd):
            assert by_id[edge_id].observation_count == 1
        assert by_id[bd].investigation_observation_count == by_id[bd].observation_count


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hi28_max_depth_three_never_traverses_four(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """H-I28: depth 3 works and depth 4 topology is never traversed."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="a.test")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        entities, edges = await _chain(uow, investigation_id, focal, 4)
        services = await _services(uow)
        result = await _traverse(services, investigation_id, focal, max_depth=3)
        assert result is not None
        assert edges[3] not in {e.relationship_id for e in result.edges}
        assert {n.entity_id for n in result.nodes} == {
            focal,
            entities[0],
            entities[1],
            entities[2],
        }
