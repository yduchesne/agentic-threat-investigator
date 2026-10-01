# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31G integration: two-scope filtered PostgreSQL graph neighborhood reads.

Every test exercises the real schema and the production query service with
the shared synthetic seeding helpers:

``Entity / EvidenceObservation / InvestigationEvidence -> Relationship /
RelationshipObservation -> PostgresGraphQueryService -> GraphResult``

The deterministic world seeds two Investigations (I1/I2), a focal DOMAIN D,
IP counterparties P1/P2, an ASN counterparty A1, plus an incoming ASN edge,
a DOMAIN self-loop and a null-``observed_at`` CNAME edge such that some
observations are admitted to I1, some only to I2, with distinct sources and
observed times; at least one edge is globally known but unsupported by I1.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import UUID

import pytest

from agentic_threat_investigator.app.query.graph import (
    GraphNeighborhoodQuery,
    GraphResult,
    GraphScope,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    Relationship,
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
NOPE = "urn:ati:source:whois"


class World:
    """The deterministic two-Investigation graph fixture world."""

    def __init__(self) -> None:
        self.i1: UUID
        self.i2: UUID
        self.d: UUID  # focal DOMAIN
        self.p1: UUID  # IP counterparty
        self.p2: UUID  # IP counterparty
        self.a1: UUID  # ASN counterparty
        self.r_d_p1: UUID  # RESOLVES_TO D -> P1 (2 I1-obs)
        self.r_d_p2: UUID  # RESOLVES_TO D -> P2 (I2-only obs => known-only for I1)
        self.r_d_a1: UUID  # REGISTERED_TO D -> A1 (mixed support)
        self.r_a1_d: UUID  # BELONGS_TO A1 -> D (I1-obs)
        self.r_d_d: UUID  # ASSOCIATED_WITH D -> D self-loop (I1-obs)
        self.r_d_p2_cname: UUID  # CNAME_OF D -> P2 (I1-obs)
        self.r_d_p1_null: UUID  # CNAME_OF D -> P1 (null observed_at) (I1-obs)

    @property
    def all_edge_ids(self) -> set[UUID]:
        """Every live Relationship id of the fixture world."""
        return {
            self.r_d_p1,
            self.r_d_p2,
            self.r_d_a1,
            self.r_a1_d,
            self.r_d_d,
            self.r_d_p2_cname,
            self.r_d_p1_null,
        }


async def _seed_world(uow: PostgresUnitOfWork) -> World:
    """Build the deterministic world and return its identities."""
    world = World()
    world.i1 = await seed_investigation(uow)
    world.i2 = await seed_investigation(uow)
    world.d = await seed_entity(uow, entity_type=EntityType.DOMAIN, value="example.com")
    world.p1 = await seed_entity(
        uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.1"
    )
    world.p2 = await seed_entity(
        uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.2"
    )
    world.a1 = await seed_entity(uow, entity_type=EntityType.ASN, value="AS64512")

    async def admit(
        *,
        relationship: Relationship,
        observed_at: datetime | None,
        source: str,
        investigation_id: UUID,
    ) -> None:
        """Persist one admitted evidence observation + relationship observation."""
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=world.d
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=relationship,
            evidence_observation_id=evidence,
            source=source,
            observed_at=observed_at,
        )

    created: dict[str, Relationship] = {}
    for name, source_id, target_id, relationship_type in [
        ("r_d_p1", world.d, world.p1, RelationshipType.RESOLVES_TO),
        ("r_d_p2", world.d, world.p2, RelationshipType.RESOLVES_TO),
        ("r_d_a1", world.d, world.a1, RelationshipType.REGISTERED_TO),
        ("r_a1_d", world.a1, world.d, RelationshipType.BELONGS_TO),
        ("r_d_d", world.d, world.d, RelationshipType.ASSOCIATED_WITH),
        ("r_d_p2_cname", world.d, world.p2, RelationshipType.CNAME_OF),
        ("r_d_p1_null", world.d, world.p1, RelationshipType.CNAME_OF),
    ]:
        created[name] = await seed_relationship(
            uow,
            source_entity_id=source_id,
            target_entity_id=target_id,
            relationship_type=relationship_type,
        )
    world.r_d_p1 = created["r_d_p1"].id
    world.r_d_p2 = created["r_d_p2"].id
    world.r_d_a1 = created["r_d_a1"].id
    world.r_a1_d = created["r_a1_d"].id
    world.r_d_d = created["r_d_d"].id
    world.r_d_p2_cname = created["r_d_p2_cname"].id
    world.r_d_p1_null = created["r_d_p1_null"].id

    for name, relationship in created.items():
        if name == "r_d_p1":
            await admit(
                relationship=relationship,
                observed_at=FIXED_TIME,
                source=DNS,
                investigation_id=world.i1,
            )
            await admit(
                relationship=relationship,
                observed_at=FIXED_TIME + timedelta(days=2),
                source=RDAP,
                investigation_id=world.i1,
            )
        elif name == "r_d_p2":
            await admit(
                relationship=relationship,
                observed_at=FIXED_TIME + timedelta(days=1),
                source=DNS,
                investigation_id=world.i2,
            )
        elif name == "r_d_a1":
            await admit(
                relationship=relationship,
                observed_at=FIXED_TIME + timedelta(days=1),
                source=RDAP,
                investigation_id=world.i1,
            )
            await admit(
                relationship=relationship,
                observed_at=FIXED_TIME + timedelta(days=3),
                source=RDAP,
                investigation_id=world.i2,
            )
        elif name == "r_a1_d":
            await admit(
                relationship=relationship,
                observed_at=FIXED_TIME,
                source=RDAP,
                investigation_id=world.i1,
            )
        elif name == "r_d_d":
            await admit(
                relationship=relationship,
                observed_at=FIXED_TIME,
                source=DNS,
                investigation_id=world.i1,
            )
        elif name == "r_d_p2_cname":
            await admit(
                relationship=relationship,
                observed_at=FIXED_TIME + timedelta(days=2),
                source=DNS,
                investigation_id=world.i1,
            )
        elif name == "r_d_p1_null":
            await admit(
                relationship=relationship,
                observed_at=None,
                source=DNS,
                investigation_id=world.i1,
            )
    return world


async def _services(
    uow: PostgresUnitOfWork,
) -> PostgresQueryServices:
    """Return a query bundle bound to the isolated read session."""
    assert uow.session is not None
    return PostgresQueryServices(
        uow.session, QueryLimits(default_page_size=50, max_page_size=200)
    )


async def _neighborhood(
    services: PostgresQueryServices,
    investigation_id: UUID,
    entity_id: UUID,
    *,
    limit: int = 50,
    direction: RelationshipDirection = RelationshipDirection.EITHER,
    relationship_type: RelationshipType | None = None,
    scope: GraphScope = GraphScope.INVESTIGATION,
    entity_type: EntityType | None = None,
    source: str | None = None,
    observed_from: datetime | None = None,
    observed_to: datetime | None = None,
) -> GraphResult | None:
    """Run one bounded neighborhood query through the production service."""
    return await services.graph.neighborhood(
        GraphNeighborhoodQuery(
            investigation_id=investigation_id,
            entity_id=entity_id,
            scope=scope,
            direction=direction,
            relationship_type=relationship_type,
            entity_type=entity_type,
            source=source,
            observed_from=observed_from,
            observed_to=observed_to,
            limit=limit,
        )
    )


# ---------------------------------------------------------------------------
# Scope semantics (PG01..PG05, PG21, PG28)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg01_investigation_scope_only_i1_supported_edges(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG01: Investigation scope shows only I1-admitted edges."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(services, world.i1, world.d)
        assert result is not None
        edge_ids = {edge.relationship_id for edge in result.edges}
        assert world.r_d_p2 not in edge_ids  # I2-only support is invisible
        assert world.r_d_a1 in edge_ids
        assert world.r_d_p1 in edge_ids
        assert len(result.edges) == 6


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg02_known_scope_is_broader_global_neighborhood(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG02: Known scope broadens to globally supported live Relationships."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN
        )
        assert result is not None
        assert {edge.relationship_id for edge in result.edges} == world.all_edge_ids


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg03_known_only_edge_has_zero_investigation_support(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG03: an edge with only I2 support has investigation count 0 in I1."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN
        )
        assert result is not None
        edge = next(e for e in result.edges if e.relationship_id == world.r_d_p2)
        assert edge.observation_count == 1
        assert edge.investigation_observation_count == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg04_mixed_support_edge_counts_are_correct(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG04: a mixed edge reports global total and I1 support separately."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN
        )
        assert result is not None
        edge = next(e for e in result.edges if e.relationship_id == world.r_d_a1)
        assert edge.observation_count == 2
        assert edge.investigation_observation_count == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg05_investigation_scope_counts_are_equal(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG05: in Investigation scope, support count equals observation count."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(services, world.i1, world.d)
        assert result is not None
        assert result.edges
        for edge in result.edges:
            assert edge.investigation_observation_count == edge.observation_count
        # R1 carries exactly its two I1-admitted observations.
        r1 = next(e for e in result.edges if e.relationship_id == world.r_d_p1)
        assert r1.observation_count == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg21_known_scope_still_requires_i1_visible_focal(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG21: Known never becomes arbitrary global lookup (None focal)."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.p1, scope=GraphScope.KNOWN
        )
        assert result is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg28_i2_only_edge_visible_from_i1_known_with_zero_support(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG28: cross-Investigation support never masquerades as I1 support."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN
        )
        assert result is not None
        edge = next(e for e in result.edges if e.relationship_id == world.r_d_p2)
        assert edge.investigation_observation_count == 0
        # In Investigation scope the same edge is absent entirely.
        scoped = await _neighborhood(services, world.i1, world.d)
        assert scoped is not None
        assert world.r_d_p2 not in {e.relationship_id for e in scoped.edges}


# ---------------------------------------------------------------------------
# Source and time filters (PG06..PG11)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg06_exact_source_match(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG06: exact RelationshipObservation source selects edges/counts."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN, source=DNS
        )
        assert result is not None
        by_id = {edge.relationship_id: edge for edge in result.edges}
        assert set(by_id) == {
            world.r_d_p1,
            world.r_d_p2,
            world.r_d_d,
            world.r_d_p2_cname,
            world.r_d_p1_null,
        }
        assert by_id[world.r_d_p1].observation_count == 1
        assert by_id[world.r_d_p1].investigation_observation_count == 1
        assert by_id[world.r_d_p2].observation_count == 1
        assert by_id[world.r_d_p2].investigation_observation_count == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg07_source_with_no_matches_is_focal_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG07: a source with no matches yields a focal-only 200-style graph."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN, source=NOPE
        )
        assert result is not None
        assert [node.entity_id for node in result.nodes] == [world.d]
        assert result.edges == ()
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg08_lower_time_bound_is_inclusive(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG08: observed_from is inclusive of the exact bound."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            observed_from=FIXED_TIME,
        )
        assert result is not None
        by_id = {edge.relationship_id: edge for edge in result.edges}
        # o1a sits exactly at the lower bound and must be retained.
        assert by_id[world.r_d_p1].observation_count == 2
        # The null-observed_at CNAME edge fails the active time bound.
        assert world.r_d_p1_null not in by_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg09_upper_time_bound_is_exclusive(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG09: observed_to is exclusive of the exact bound."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        bound = FIXED_TIME + timedelta(days=2)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            observed_to=bound,
        )
        assert result is not None
        by_id = {edge.relationship_id: edge for edge in result.edges}
        # R1's rdap observation at exactly +2d is excluded; only o1a remains.
        assert by_id[world.r_d_p1].observation_count == 1
        # The +2d CNAME edge disappears entirely.
        assert world.r_d_p2_cname not in by_id
        assert world.r_d_p1_null not in by_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg10_null_observed_at_excluded_by_time_filter(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG10: null observed_at fails an active time bound."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            observed_from=FIXED_TIME,
        )
        assert result is not None
        assert world.r_d_p1_null not in {e.relationship_id for e in result.edges}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg11_null_observed_at_contributes_without_time_filter(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG11: without a time filter, null observed_at observations count."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(services, world.i1, world.d)
        assert result is not None
        edge = next(e for e in result.edges if e.relationship_id == world.r_d_p1_null)
        assert edge.observation_count == 1


# ---------------------------------------------------------------------------
# Connected Entity type semantics (PG12..PG17)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg12_entity_type_ip_selects_ip_counterparties(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG12: entity_type=IP keeps only IP counterparty edges (either)."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            entity_type=EntityType.IP_ADDRESS,
        )
        assert result is not None
        assert {edge.relationship_id for edge in result.edges} == {
            world.r_d_p1,
            world.r_d_p2,
            world.r_d_p2_cname,
            world.r_d_p1_null,
        }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg13_entity_type_asn_selects_asn_counterparties(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG13: entity_type=ASN keeps only ASN counterparty edges (either)."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            entity_type=EntityType.ASN,
        )
        assert result is not None
        assert {edge.relationship_id for edge in result.edges} == {
            world.r_d_a1,
            world.r_a1_d,
        }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg14_entity_filter_with_source_direction_targets_counterparty(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG14: source direction + entity_type filters the target endpoint."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            direction=RelationshipDirection.SOURCE,
            entity_type=EntityType.IP_ADDRESS,
        )
        assert result is not None
        assert {edge.relationship_id for edge in result.edges} == {
            world.r_d_p1,
            world.r_d_p2,
            world.r_d_p2_cname,
            world.r_d_p1_null,
        }
        # The ASN->D incoming edge would never match source direction anyway.
        assert world.r_a1_d not in {e.relationship_id for e in result.edges}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg15_entity_filter_with_target_direction_filters_source(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG15: target direction + entity_type filters the source endpoint."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            direction=RelationshipDirection.TARGET,
            entity_type=EntityType.ASN,
        )
        assert result is not None
        assert {edge.relationship_id for edge in result.edges} == {world.r_a1_d}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg16_self_loop_matches_focal_type(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG16: a self-loop matches the entity type of the focal Entity itself."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            entity_type=EntityType.DOMAIN,
        )
        assert result is not None
        assert world.r_d_d in {e.relationship_id for e in result.edges}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg17_self_loop_excluded_for_nonmatching_type(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG17: a self-loop is excluded when the focal type differs."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            entity_type=EntityType.IP_ADDRESS,
        )
        assert result is not None
        assert world.r_d_d not in {e.relationship_id for e in result.edges}


# ---------------------------------------------------------------------------
# Combined semantics and bounds (PG18..PG27)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg18_relationship_type_filter_preserved(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG18: the canonical Relationship type filter keeps its semantics."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            relationship_type=RelationshipType.CNAME_OF,
        )
        assert result is not None
        assert {edge.relationship_id for edge in result.edges} == {
            world.r_d_p2_cname,
            world.r_d_p1_null,
        }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg19_combined_filters_intersect(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG19: scope + source + time + entity type intersect server-side."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            direction=RelationshipDirection.SOURCE,
            relationship_type=RelationshipType.RESOLVES_TO,
            entity_type=EntityType.IP_ADDRESS,
            source=DNS,
            observed_from=FIXED_TIME,
        )
        assert result is not None
        by_id = {edge.relationship_id: edge for edge in result.edges}
        # R1 o1a (dns@FIXED) survives; R1 o1b is rdap; R7 has null observed_at.
        assert set(by_id) == {world.r_d_p1, world.r_d_p2}
        assert by_id[world.r_d_p1].observation_count == 1
        assert by_id[world.r_d_p2].investigation_observation_count == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg20_all_edges_filtered_is_focal_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG20: filtering away every edge still returns a focal-only graph."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            source=NOPE,
        )
        assert result is not None
        assert result.edges == ()
        assert [node.entity_id for node in result.nodes] == [world.d]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg22_soft_deleted_relationship_excluded_in_both_scopes(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG22: a soft-deleted Relationship is never an edge in either scope."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        await uow.relationships.soft_delete(world.r_d_p2_cname)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN
        )
        assert result is not None
        assert world.r_d_p2_cname not in {e.relationship_id for e in result.edges}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg23_soft_deleted_endpoint_excluded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG23: an edge with a soft-deleted endpoint disappears."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        await uow.entities.soft_delete(world.p2)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN
        )
        assert result is not None
        edge_ids = {e.relationship_id for e in result.edges}
        assert world.r_d_p2 not in edge_ids
        assert world.r_d_p2_cname not in edge_ids
        assert world.r_d_p1 in edge_ids


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg24_truthful_truncation_after_filtering(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG24: limit+1 applies after filters; truncation stays truthful."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        # Four edges survive entity_type=IP in Known scope; bound is 3.
        result = await _neighborhood(
            services,
            world.i1,
            world.d,
            scope=GraphScope.KNOWN,
            entity_type=EntityType.IP_ADDRESS,
            limit=3,
        )
        assert result is not None
        surviving = {
            world.r_d_p1,
            world.r_d_p2,
            world.r_d_p2_cname,
            world.r_d_p1_null,
        }
        assert len(result.edges) == 3
        assert {e.relationship_id for e in result.edges} <= surviving
        assert result.truncated is True


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg25_edge_order_is_relationship_id_ascending(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG25: filtered edges keep deterministic Relationship ID ordering."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN
        )
        assert result is not None
        ids = [edge.relationship_id for edge in result.edges]
        assert ids == sorted(ids)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg26_duplicate_observations_still_one_edge(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG26: repeated observations never duplicate the canonical edge."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(services, world.i1, world.d)
        assert result is not None
        r1 = [e for e in result.edges if e.relationship_id == world.r_d_p1]
        assert len(r1) == 1
        assert r1[0].observation_count == 2
        assert len({e.relationship_id for e in result.edges}) == len(result.edges)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pg27_endpoint_closure_holds_with_filters(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PG27: every filtered edge endpoint is present in the result nodes."""
    async with uow_factory() as uow:
        world = await _seed_world(uow)
        services = await _services(uow)
        result = await _neighborhood(
            services, world.i1, world.d, scope=GraphScope.KNOWN, source=RDAP
        )
        assert result is not None
        node_ids = {node.entity_id for node in result.nodes}
        assert world.d in node_ids
        for edge in result.edges:
            assert edge.source_entity_id in node_ids
            assert edge.target_entity_id in node_ids
