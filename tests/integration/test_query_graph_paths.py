# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31I real-PostgreSQL path semantics (P-I01..P-I38 + vertical slice).

Every test exercises the real schema, the versioned ``ati.find_graph_paths``
stored function and the production service adapter:

``Entity / EvidenceObservation / InvestigationEvidence -> Relationship /
RelationshipObservation -> ati.find_graph_paths ->
PostgresGraphQueryService.find_paths() -> GraphPathResult``

The P-I matrix validates endpoint Investigation visibility in both scopes,
scope/source/time/type filters before recursion, direction and connected
Entity type at every frontier, explicit Entity-path cycle safety
(self-loops never grow), source==target zero-hop behavior, deterministic
shortest-first ordering with canonical tie-breaks, truthful ``max_paths``
truncation, canonical node/edge deduplication, observation-based support
summaries, soft-deletion semantics, selected-path closure, no-path endpoint
closure, and bounded depth-6 execution. The vertical slice (section 14 of
the PR 31I plan) additionally proves the public DTO identity preservation
through the mapper.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.api.dto.graph import GraphPathResponse
from agentic_threat_investigator.api.mappers import to_graph_path_response
from agentic_threat_investigator.app.query.graph import (
    GraphPathQuery,
    GraphPathResult,
    GraphScope,
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


async def _alive_entity(
    uow: PostgresUnitOfWork,
    investigation_id: UUID,
    *,
    value: str = "endpoint.test",
    entity_type: EntityType = EntityType.DOMAIN,
) -> UUID:
    """Create one Entity and admit it to the Investigation; return its id."""
    entity_id = await seed_entity(uow, entity_type=entity_type, value=value)
    await seed_evidence_observation(
        uow, investigation_id=investigation_id, entity_id=entity_id
    )
    return entity_id


async def _find(
    services: PostgresQueryServices,
    investigation_id: UUID,
    source_entity_id: UUID,
    target_entity_id: UUID,
    *,
    max_depth: int = 4,
    max_paths: int = 10,
    scope: GraphScope = GraphScope.INVESTIGATION,
    direction: RelationshipDirection = RelationshipDirection.EITHER,
    relationship_type: RelationshipType | None = None,
    entity_type: EntityType | None = None,
    source: str | None = None,
    observed_from: datetime | None = None,
    observed_to: datetime | None = None,
) -> GraphPathResult:
    """Run one bounded path query; visible endpoints are a test invariant."""
    result = await _find_maybe(
        services,
        investigation_id,
        source_entity_id,
        target_entity_id,
        max_depth=max_depth,
        max_paths=max_paths,
        scope=scope,
        direction=direction,
        relationship_type=relationship_type,
        entity_type=entity_type,
        source=source,
        observed_from=observed_from,
        observed_to=observed_to,
    )
    assert result is not None
    return result


async def _find_maybe(
    services: PostgresQueryServices,
    investigation_id: UUID,
    source_entity_id: UUID,
    target_entity_id: UUID,
    *,
    max_depth: int = 4,
    max_paths: int = 10,
    scope: GraphScope = GraphScope.INVESTIGATION,
    direction: RelationshipDirection = RelationshipDirection.EITHER,
    relationship_type: RelationshipType | None = None,
    entity_type: EntityType | None = None,
    source: str | None = None,
    observed_from: datetime | None = None,
    observed_to: datetime | None = None,
) -> GraphPathResult | None:
    """Run one bounded path query through the production service."""
    return await services.graph.find_paths(
        GraphPathQuery(
            investigation_id=investigation_id,
            entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            max_depth=max_depth,
            max_paths=max_paths,
            scope=scope,
            direction=direction,
            relationship_type=relationship_type,
            entity_type=entity_type,
            source=source,
            observed_from=observed_from,
            observed_to=observed_to,
        )
    )


def _path_ids(result: GraphPathResult) -> tuple[tuple[UUID, ...], ...]:
    """Project every returned path to its ordered Entity-ID tuple."""
    return tuple(path.entity_ids for path in result.paths)


def _path_set(result: GraphPathResult) -> set[tuple[UUID, ...]]:
    """Project every returned path to a set of Entity-ID tuples."""
    return {path.entity_ids for path in result.paths}


# ---------------------------------------------------------------------------
# P-I01..P-I05 topology and depth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi01_direct_one_edge_path(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I01: A->B returns exactly one 1-hop path."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="a.test")
        target = await _alive_entity(uow, investigation_id, value="b.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=source,
            target_entity_id=target,
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, source, target)
        assert result is not None
        assert _path_ids(result) == ((source, target),)
        path = result.paths[0]
        assert len(path.relationship_ids) == 1
        assert {n.entity_id for n in result.nodes} == {source, target}
        assert len(result.edges) == 1
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi02_simple_two_edge_chain(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I02: A->B->C returns exactly one 2-hop path."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
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
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, a, c)
        assert result is not None
        assert _path_ids(result) == ((a, b, c),)
        assert len(result.edges) == 2
        assert {n.entity_id for n in result.nodes} == {a, b, c}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi03_path_longer_than_max_depth(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I03: a connection longer than max_depth yields no path."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
        d = await _alive_entity(uow, investigation_id, value="d.test")
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
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=c,
            target_entity_id=d,
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, a, d, max_depth=2)
        assert result is not None
        assert result.paths == ()
        # No-path closure still projects both visible endpoints.
        assert {n.entity_id for n in result.nodes} == {a, d}
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi04_source_equals_target_zero_hop(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I04: source == target returns exactly one zero-hop path."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        node = await _alive_entity(uow, investigation_id, value="self.test")
        services = await _services(uow)
        result = await _find(services, investigation_id, node, node)
        assert result is not None
        assert len(result.paths) == 1
        path = result.paths[0]
        assert path.entity_ids == (node,)
        assert path.relationship_ids == ()
        assert [n.entity_id for n in result.nodes] == [node]
        assert result.edges == ()
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi05_no_connection_visible_endpoints(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I05: two visible endpoints with no connection yield empty paths."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="a.test")
        target = await _alive_entity(uow, investigation_id, value="b.test")
        services = await _services(uow)
        result = await _find(services, investigation_id, source, target)
        assert result is not None
        assert result.paths == ()
        assert result.edges == ()
        assert {n.entity_id for n in result.nodes} == {source, target}
        assert result.truncated is False


# ---------------------------------------------------------------------------
# P-I06..P-I10 endpoint visibility and scope
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi06_source_not_visible_is_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I06: an Investigation-invisible source endpoint maps to None."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        target = await _alive_entity(uow, i1, value="b.test")
        invisible = await seed_entity(uow, value="a.test")
        services = await _services(uow)
        assert await _find_maybe(services, i1, invisible, target) is None
        # A wholly missing source is None too.
        assert await _find_maybe(services, i1, uuid4(), target) is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi07_target_not_visible_is_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I07: an Investigation-invisible target endpoint maps to None."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        source = await _alive_entity(uow, i1, value="a.test")
        invisible = await seed_entity(uow, value="b.test")
        services = await _services(uow)
        assert await _find_maybe(services, i1, source, invisible) is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi08_target_global_only_in_known_scope_is_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I08: Known scope never permits a global-only target endpoint."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        source = await _alive_entity(uow, i1, value="a.test")
        global_target = await seed_entity(uow, value="b.test")
        await seed_evidence_observation(
            uow, investigation_id=i2, entity_id=global_target
        )
        services = await _services(uow)
        assert (
            await _find_maybe(
                services, i1, source, global_target, scope=GraphScope.KNOWN
            )
            is None
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi09_known_only_intermediate_is_found_only_in_known(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I09: a global-only intermediate edge blocks Investigation scope only."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        a = await _alive_entity(uow, i1, value="a.test")
        b = await seed_entity(uow, value="b.test")
        c = await _alive_entity(uow, i1, value="c.test")
        # a -> b is supported globally (admitted to another Investigation).
        rel_ab = await seed_relationship(uow, source_entity_id=a, target_entity_id=b)
        evidence = await seed_evidence_observation(
            uow, investigation_id=i2, entity_id=a
        )
        await seed_observation(
            uow,
            investigation_id=i2,
            relationship=rel_ab,
            evidence_observation_id=evidence,
        )
        await _admit_edge(
            uow, investigation_id=i1, source_entity_id=b, target_entity_id=c
        )
        services = await _services(uow)
        investigation = await _find(services, i1, a, c, scope=GraphScope.INVESTIGATION)
        assert investigation is not None and investigation.paths == ()
        known = await _find(services, i1, a, c, scope=GraphScope.KNOWN)
        assert _path_ids(known) == ((a, b, c),)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi10_investigation_scope_blocks_global_support(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I10: Investigation scope never traverses global-only support."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        a = await _alive_entity(uow, i1, value="a.test")
        b = await _alive_entity(uow, i1, value="b.test")
        # The only supporting observation is admitted to another Investigation.
        rel = await seed_relationship(uow, source_entity_id=a, target_entity_id=b)
        evidence = await seed_evidence_observation(
            uow, investigation_id=i2, entity_id=a
        )
        await seed_observation(
            uow, investigation_id=i2, relationship=rel, evidence_observation_id=evidence
        )
        services = await _services(uow)
        result = await _find(services, i1, a, b, scope=GraphScope.INVESTIGATION)
        assert result is not None and result.paths == ()


# ---------------------------------------------------------------------------
# P-I11..P-I15 source/time filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi11_source_filter_removes_edge(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I11: an exact source filter removes the one disqualifying edge."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
            source=RDAP,
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, a, b, source=DNS)
        assert result is not None and result.paths == ()
        unfiltered = await _find(services, investigation_id, a, b)
        assert _path_ids(unfiltered) == ((a, b),)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi12_observed_from_inclusive(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I12: observed_from is inclusive; an equal boundary still matches."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
            observed_at=FIXED_TIME,
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, a, b, observed_from=FIXED_TIME)
        assert _path_ids(result) == ((a, b),)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi13_observed_to_exclusive(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I13: observed_to is exclusive; the boundary observation is excluded."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
            observed_at=FIXED_TIME,
        )
        services = await _services(uow)
        result = await _find(
            services,
            investigation_id,
            a,
            b,
            observed_to=FIXED_TIME,
        )
        assert result is not None and result.paths == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi14_null_observed_at_excluded_under_time_filter(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I14: a null observed_at is excluded whenever a time bound is active."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        rel = await seed_relationship(uow, source_entity_id=a, target_entity_id=b)
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=a
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=rel,
            evidence_observation_id=evidence,
            observed_at=None,
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, a, b, observed_from=FIXED_TIME)
        assert result is not None and result.paths == ()
        unfiltered = await _find(services, investigation_id, a, b)
        assert _path_ids(unfiltered) == ((a, b),)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi15_retrieved_at_never_substitutes(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I15: retrieved_at never substitutes for a missing observed_at."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        rel = await seed_relationship(uow, source_entity_id=a, target_entity_id=b)
        evidence = await seed_evidence_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=a,
            retrieved_at=FIXED_TIME,
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=rel,
            evidence_observation_id=evidence,
            observed_at=None,
        )
        services = await _services(uow)
        result = await _find(
            services,
            investigation_id,
            a,
            b,
            observed_from=FIXED_TIME + timedelta(days=1),
        )
        assert result is not None and result.paths == ()


# ---------------------------------------------------------------------------
# P-I16..P-I20 type/direction at every frontier
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi16_relationship_type_blocks_every_hop(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I16: a mismatching Relationship type at any hop blocks the path."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
            relationship_type=RelationshipType.RESOLVES_TO,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=b,
            target_entity_id=c,
            relationship_type=RelationshipType.CNAME_OF,
        )
        services = await _services(uow)
        result = await _find(
            services,
            investigation_id,
            a,
            c,
            relationship_type=RelationshipType.RESOLVES_TO,
        )
        assert result is not None and result.paths == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi17_entity_type_blocks_ever_frontier(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I17: a mismatching reached-Entity type at any hop blocks the branch."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(
            uow, investigation_id, value="a.test", entity_type=EntityType.DOMAIN
        )
        b = await _alive_entity(
            uow, investigation_id, value="192.0.2.1", entity_type=EntityType.IP_ADDRESS
        )
        c = await _alive_entity(
            uow, investigation_id, value="c.test", entity_type=EntityType.DOMAIN
        )
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
        )
        services = await _services(uow)
        result = await _find(
            services, investigation_id, a, c, entity_type=EntityType.IP_ADDRESS
        )
        # B qualifies by type at hop 1 but C (a DOMAIN) blocks hop 2.
        assert result is not None and result.paths == ()
        unfiltered = await _find(services, investigation_id, a, c)
        assert _path_ids(unfiltered) == ((a, b, c),)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi18_source_direction_forward_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I18: SOURCE direction only follows source->target edges."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
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
        )
        services = await _services(uow)
        result = await _find(
            services,
            investigation_id,
            a,
            c,
            direction=RelationshipDirection.SOURCE,
        )
        assert _path_ids(result) == ((a, b, c),)
        # A reverse connection cannot be walked forward.
        reverse = await _find(
            services,
            investigation_id,
            c,
            a,
            direction=RelationshipDirection.SOURCE,
        )
        assert reverse is not None and reverse.paths == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi19_target_direction_reverse_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I19: TARGET direction only follows target->source edges."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
        # Storage direction is A->B->C; walking TARGET traverses in reverse.
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
        )
        services = await _services(uow)
        result = await _find(
            services,
            investigation_id,
            c,
            a,
            direction=RelationshipDirection.TARGET,
        )
        assert _path_ids(result) == ((c, b, a),)
        forward = await _find(
            services,
            investigation_id,
            a,
            c,
            direction=RelationshipDirection.TARGET,
        )
        assert forward is not None and forward.paths == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi20_either_undirected_adjacency(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I20: EITHER treats adjacency as undirected."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=c,
            target_entity_id=b,
        )
        services = await _services(uow)
        result = await _find(
            services,
            investigation_id,
            a,
            c,
            direction=RelationshipDirection.EITHER,
        )
        assert _path_ids(result) == ((a, b, c),)


# ---------------------------------------------------------------------------
# P-I21..P-I23 cycles and diamonds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi21_simple_cycle_no_repeated_entity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I21: cycles never produce a path that repeats an Entity."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
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
        # SOURCE traversal walks edges forward only, so the C->A cycle edge can
        # never be used to build a path from A: the only qualifying simple path
        # is A->B->C and the recursion terminates without Entity repeats.
        result = await _find(
            services,
            investigation_id,
            a,
            c,
            max_depth=4,
            direction=RelationshipDirection.SOURCE,
        )
        assert _path_ids(result) == ((a, b, c),)
        for path in result.paths:
            assert len(path.entity_ids) == len(set(path.entity_ids))
        # The cycle topology participates in no selected path closure.
        assert {e.relationship_id for e in result.edges} == {ab, bc}
        assert ca not in {e.relationship_id for e in result.edges}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi22_self_loop_no_recursive_growth(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I22: a self-loop never grows recursion or helps reach a target."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=a,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, a, b, max_depth=6)
        assert _path_ids(result) == ((a, b),)
        assert len(result.paths) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi23_diamond_two_deterministic_paths(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I23: a diamond A->B/C->D returns exactly two equal-length paths."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
        d = await _alive_entity(uow, investigation_id, value="d.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=c,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=b,
            target_entity_id=d,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=c,
            target_entity_id=d,
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, a, d)
        assert _path_set(result) == {(a, b, d), (a, c, d)}
        # Both paths share a single canonical node for each Entity.
        assert {n.entity_id for n in result.nodes} == {a, b, c, d}
        assert len(result.edges) == 4
        assert result.truncated is False


# ---------------------------------------------------------------------------
# P-I24..P-I27 ordering / truncation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi24_shorter_paths_first(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I24: a shorter qualifying path precedes a longer one."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
        d = await _alive_entity(uow, investigation_id, value="d.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=d,
        )
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
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=c,
            target_entity_id=d,
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, a, d, max_depth=4)
        assert _path_ids(result)[0] == (a, d)
        assert _path_ids(result)[1] == (a, b, c, d)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi25_equal_length_paths_deterministic_canonical_order(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I25: equal-length paths order by the canonical ID signature."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="s.test")
        target = await _alive_entity(uow, investigation_id, value="t.test")
        middle_ids: list[UUID] = []
        for index in range(3):
            middle = await _alive_entity(uow, investigation_id, value=f"m{index}.test")
            middle_ids.append(middle)
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=source,
                target_entity_id=middle,
            )
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=middle,
                target_entity_id=target,
            )
        services = await _services(uow)
        result = await _find(services, investigation_id, source, target)
        assert result is not None and len(result.paths) == 3
        expected = sorted(
            result.paths,
            key=lambda path: (path.relationship_ids, path.entity_ids),
        )
        assert [p.entity_ids for p in result.paths] == [p.entity_ids for p in expected]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi26_more_than_max_paths_truncates(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I26: more qualifying paths than max_paths returns N + truncated."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="s.test")
        target = await _alive_entity(uow, investigation_id, value="t.test")
        for index in range(5):
            middle = await _alive_entity(uow, investigation_id, value=f"m{index}.test")
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=source,
                target_entity_id=middle,
            )
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=middle,
                target_entity_id=target,
            )
        services = await _services(uow)
        result = await _find(services, investigation_id, source, target, max_paths=2)
        assert result is not None
        assert len(result.paths) == 2
        assert result.truncated is True


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi27_exactly_max_paths_not_truncated(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I27: exactly max_paths qualifying paths means truncated=false."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="s.test")
        target = await _alive_entity(uow, investigation_id, value="t.test")
        for index in range(2):
            middle = await _alive_entity(uow, investigation_id, value=f"m{index}.test")
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=source,
                target_entity_id=middle,
            )
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=middle,
                target_entity_id=target,
            )
        services = await _services(uow)
        result = await _find(services, investigation_id, source, target, max_paths=2)
        assert result is not None
        assert len(result.paths) == 2
        assert result.truncated is False


# ---------------------------------------------------------------------------
# P-I28..P-I31 canonical dedup and summaries
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi28_same_relationship_on_multiple_paths_one_edge(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I28: a Relationship used by several candidate paths returns once."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="s.test")
        target = await _alive_entity(uow, investigation_id, value="t.test")
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        # source -> target is a shared direct edge present in no simple path,
        # while two 2-hop candidate paths share nothing; assert one canonical
        # edge per relationship across the selected paths.
        edge_ids = set()
        for middle in (a, b):
            edge_ids.add(
                await _admit_edge(
                    uow,
                    investigation_id=investigation_id,
                    source_entity_id=source,
                    target_entity_id=middle,
                )
            )
            edge_ids.add(
                await _admit_edge(
                    uow,
                    investigation_id=investigation_id,
                    source_entity_id=middle,
                    target_entity_id=target,
                )
            )
        services = await _services(uow)
        result = await _find(services, investigation_id, source, target)
        assert result is not None and len(result.paths) == 2
        assert {e.relationship_id for e in result.edges} == edge_ids
        assert len(result.edges) == len(edge_ids)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi29_same_entity_on_multiple_paths_one_node(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I29: Entities shared by several selected paths return once."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="s.test")
        target = await _alive_entity(uow, investigation_id, value="t.test")
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        for middle in (a, b):
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=source,
                target_entity_id=middle,
            )
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=middle,
                target_entity_id=target,
            )
        services = await _services(uow)
        result = await _find(services, investigation_id, source, target)
        assert result is not None and len(result.paths) == 2
        assert {n.entity_id for n in result.nodes} == {source, target, a, b}
        assert len(result.nodes) == 4


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi30_observation_multiplicity_not_path_count(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I30: edge support counts reflect observations, never path counts."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
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
                observed_at=FIXED_TIME + timedelta(days=offset),
            )
        services = await _services(uow)
        result = await _find(services, investigation_id, a, b)
        assert _path_ids(result) == ((a, b),)
        edge = result.edges[0]
        assert edge.observation_count == 3
        assert edge.investigation_observation_count == 3
        assert edge.first_observed_at == FIXED_TIME
        assert edge.last_observed_at == FIXED_TIME + timedelta(days=5)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi31_mixed_support_known_scope_counts(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I31: Known scope reports truthful Investigation support counts."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        a = await _alive_entity(uow, i1, value="a.test")
        b = await _alive_entity(uow, i1, value="b.test")
        rel = await seed_relationship(uow, source_entity_id=a, target_entity_id=b)
        evidence = await seed_evidence_observation(
            uow, investigation_id=i1, entity_id=a
        )
        await seed_observation(
            uow, investigation_id=i1, relationship=rel, evidence_observation_id=evidence
        )
        global_evidence = await seed_evidence_observation(
            uow, investigation_id=i2, entity_id=a
        )
        await seed_observation(
            uow,
            investigation_id=i2,
            relationship=rel,
            evidence_observation_id=global_evidence,
        )
        services = await _services(uow)
        result = await _find(services, i1, a, b, scope=GraphScope.KNOWN)
        assert _path_ids(result) == ((a, b),)
        edge = result.edges[0]
        assert edge.observation_count == 2
        assert edge.investigation_observation_count == 1


# ---------------------------------------------------------------------------
# P-I32..P-I34 soft deletion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi32_soft_deleted_relationship_excluded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I32: a soft-deleted Relationship never participates in a path."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        edge = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=a,
            target_entity_id=b,
        )
        await uow.relationships.soft_delete(edge)
        services = await _services(uow)
        result = await _find(services, investigation_id, a, b)
        assert result is not None and result.paths == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi33_soft_deleted_intermediate_entity_excluded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I33: a soft-deleted intermediate Entity blocks the path."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        c = await _alive_entity(uow, investigation_id, value="c.test")
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
        )
        await uow.entities.soft_delete(b)
        services = await _services(uow)
        result = await _find(services, investigation_id, a, c)
        assert result is not None and result.paths == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi34_soft_deleted_target_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I34: a soft-deleted target endpoint maps to None."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        a = await _alive_entity(uow, investigation_id, value="a.test")
        b = await _alive_entity(uow, investigation_id, value="b.test")
        await uow.entities.soft_delete(b)
        services = await _services(uow)
        assert await _find_maybe(services, investigation_id, a, b) is None


# ---------------------------------------------------------------------------
# P-I35..P-I38 determinism / closure / depth bound
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi35_repeated_invocation_identical(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I35: repeated invocations return identical paths and summaries."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="s.test")
        target = await _alive_entity(uow, investigation_id, value="t.test")
        for index in range(3):
            middle = await _alive_entity(uow, investigation_id, value=f"m{index}.test")
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=source,
                target_entity_id=middle,
            )
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=middle,
                target_entity_id=target,
            )
        services = await _services(uow)
        first = await _find(services, investigation_id, source, target)
        second = await _find(services, investigation_id, source, target)
        assert first is not None and second is not None
        assert [path.entity_ids for path in first.paths] == [
            path.entity_ids for path in second.paths
        ]
        assert [path.relationship_ids for path in first.paths] == [
            path.relationship_ids for path in second.paths
        ]
        assert [(e.relationship_id, e.observation_count) for e in first.edges] == [
            (e.relationship_id, e.observation_count) for e in second.edges
        ]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi36_selected_path_closure_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I36: explored-but-not-selected topology never appears in the result."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="s.test")
        target = await _alive_entity(uow, investigation_id, value="t.test")
        on_path = await _alive_entity(uow, investigation_id, value="mid.test")
        dead_end = await _alive_entity(uow, investigation_id, value="dead.test")
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=source,
            target_entity_id=on_path,
        )
        await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=on_path,
            target_entity_id=target,
        )
        # The dead end is explored but never participates in a selected path.
        dead_edge = await _admit_edge(
            uow,
            investigation_id=investigation_id,
            source_entity_id=source,
            target_entity_id=dead_end,
        )
        services = await _services(uow)
        result = await _find(services, investigation_id, source, target, max_depth=4)
        assert _path_ids(result) == ((source, on_path, target),)
        assert dead_end not in {n.entity_id for n in result.nodes}
        assert dead_edge not in {e.relationship_id for e in result.edges}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi37_no_path_closure_endpoints(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I37: a no-path result still projects both visible endpoints."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await _alive_entity(uow, investigation_id, value="s.test")
        target = await _alive_entity(uow, investigation_id, value="t.test")
        services = await _services(uow)
        result = await _find(services, investigation_id, source, target, max_depth=6)
        assert result is not None
        assert result.paths == ()
        assert {n.entity_id for n in result.nodes} == {source, target}
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pi38_max_depth_six_bounded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P-I38: a depth-6 chain completes under the bounded-depth gate."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        previous = await _alive_entity(uow, investigation_id, value="hop0.test")
        chain: dict[int, UUID] = {0: previous}
        for index in range(1, 7):
            entity = await _alive_entity(
                uow, investigation_id, value=f"hop{index}.test"
            )
            chain[index] = entity
            await _admit_edge(
                uow,
                investigation_id=investigation_id,
                source_entity_id=previous,
                target_entity_id=entity,
            )
            previous = entity
        services = await _services(uow)
        result = await _find(
            services,
            investigation_id,
            chain[0],
            chain[6],
            max_depth=6,
        )
        assert _path_ids(result) == (tuple(chain[index] for index in range(7)),)
        # A depth-7 connection is not found within the hard ceiling.
        overshoot = await _find(
            services,
            investigation_id,
            chain[0],
            chain[6],
            max_depth=4,
        )
        assert overshoot is not None and overshoot.paths == ()


# ---------------------------------------------------------------------------
# PR 31I vertical slice (plan section 14) and public DTO identity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_vertical_slice_diamond_cycle_scope_filters_dto(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The canonical vertical slice proves the full production contract."""
    async with uow_factory() as uow:
        i1 = await seed_investigation(uow)
        i2 = await seed_investigation(uow)
        a = await _alive_entity(uow, i1, value="a.test")
        b = await _alive_entity(uow, i1, value="b.test")
        c = await _alive_entity(uow, i1, value="c.test")
        d = await _alive_entity(uow, i1, value="d.test")
        ek = await seed_entity(uow, value="known.test")
        fx = await _alive_entity(uow, i1, value="filtered.test")
        # A -> B -> D
        ab = await _admit_edge(
            uow,
            investigation_id=i1,
            source_entity_id=a,
            target_entity_id=b,
            observed_at=FIXED_TIME,
        )
        await _admit_edge(
            uow,
            investigation_id=i1,
            source_entity_id=b,
            target_entity_id=d,
            observed_at=FIXED_TIME + timedelta(days=1),
        )
        # A -> C -> D
        await _admit_edge(
            uow,
            investigation_id=i1,
            source_entity_id=a,
            target_entity_id=c,
            observed_at=FIXED_TIME + timedelta(days=2),
        )
        await _admit_edge(
            uow,
            investigation_id=i1,
            source_entity_id=c,
            target_entity_id=d,
            observed_at=FIXED_TIME + timedelta(days=3),
        )
        # B -> C and C -> A (cycle).
        await _admit_edge(
            uow, investigation_id=i1, source_entity_id=b, target_entity_id=c
        )
        await _admit_edge(
            uow, investigation_id=i1, source_entity_id=c, target_entity_id=a
        )
        # A Known-only support edge: a -> known is supported only by I2.
        rel_ak = await seed_relationship(uow, source_entity_id=a, target_entity_id=ek)
        known_evidence = await seed_evidence_observation(
            uow, investigation_id=i2, entity_id=a
        )
        await seed_observation(
            uow,
            investigation_id=i2,
            relationship=rel_ak,
            evidence_observation_id=known_evidence,
            source=RDAP,
        )
        # One filtered-out source edge: a -> filtered uses RDAP.
        await _admit_edge(
            uow,
            investigation_id=i1,
            source_entity_id=a,
            target_entity_id=fx,
            source=RDAP,
        )
        # One observation exactly on the requested interval boundary.
        await _admit_edge(
            uow,
            investigation_id=i1,
            source_entity_id=a,
            target_entity_id=b,
            observed_at=FIXED_TIME + timedelta(days=30),
        )
        services = await _services(uow)

        # Investigation scope, no filters: the two deterministic equal-length
        # paths sort first with canonical deduplication; the cycle topology
        # additionally enables the longer simple path A->B->C->D after them
        # (cycle safety: no Entity repeats and no loop path appears).
        result = await _find(services, i1, a, d)
        assert result is not None
        # The two deterministic equal-length paths (A->B->D and A->C->D) sort
        # before every longer qualifying simple path (the cycle topology adds
        # options such as A->B->C->D and A->C->B->D), with equal-length order
        # canonical-deterministic (never seed-dependent).
        assert {tuple(path.entity_ids) for path in result.paths[:2]} == {
            (a, b, d),
            (a, c, d),
        }
        hop_counts = [len(path.entity_ids) - 1 for path in result.paths]
        assert hop_counts == sorted(hop_counts)
        assert {n.entity_id for n in result.nodes} == {a, b, c, d}
        # Canonical closure: ab/ac/bd/cd for the two 2-hop paths plus bc for
        # the 3-hop path = five distinct canonical edges, each once.
        assert len(result.edges) == 5
        assert len({e.relationship_id for e in result.edges}) == 5
        assert result.truncated is False
        # Cycle safety: every path is simple and anchored at the endpoints.
        for path in result.paths:
            assert path.entity_ids[0] == a and path.entity_ids[-1] == d
            assert len(path.entity_ids) == len(set(path.entity_ids))
        # Support summaries: a->b carries two observations inside the window.
        ab_projection = next(
            edge for edge in result.edges if edge.relationship_id == ab
        )
        assert ab_projection.observation_count == 2
        assert ab_projection.investigation_observation_count == 2
        assert ab_projection.first_observed_at == FIXED_TIME
        # Known scope broadens intermediate topology: a->known->? has no extra
        # path to D, so paths stay identical but the Known-only edge can be
        # traversed (a -> known is a dead end to D).
        known = await _find(services, i1, a, d, scope=GraphScope.KNOWN)
        assert known is not None
        assert {tuple(path.entity_ids) for path in known.paths[:2]} == {
            (a, b, d),
            (a, c, d),
        }
        # The Known-only support edge does not introduce a new path to D.
        for edge in known.edges:
            assert edge.relationship_id != rel_ak.id
        # Exact source filter removes both the RDAP a->filtered edge and any
        # RDAP-supported topology; a->d still resolves via DNS edges.
        filtered_by_source = await _find(services, i1, a, d, source=DNS)
        assert filtered_by_source is not None
        assert {tuple(path.entity_ids) for path in filtered_by_source.paths[:2]} == {
            (a, b, d),
            (a, c, d),
        }
        # The a->filtered edge participates nowhere.
        assert fx not in {n.entity_id for n in filtered_by_source.nodes}
        # Half-open interval excludes the boundary observation (day 30 < to)
        # but keeps [from, to) support.
        windowed = await _find(
            services,
            i1,
            a,
            d,
            observed_from=FIXED_TIME,
            observed_to=FIXED_TIME + timedelta(days=10),
        )
        assert windowed is not None
        next(
            edge
            for edge in windowed.edges
            if edge.relationship_id == ab and edge.observation_count == 1
        )
        # Public DTO identity preservation: the mapper copies fields exactly.
        dto: GraphPathResponse = to_graph_path_response(result)
        assert len(dto.nodes) == len(result.nodes)
        assert len(dto.edges) == len(result.edges)
        assert len(dto.paths) == len(result.paths)
        assert dto.truncated is False
        assert [tuple(p.entity_ids) for p in dto.paths] == [
            tuple(path.entity_ids) for path in result.paths
        ]
        assert {p.relationship_ids for p in dto.paths} == {
            path.relationship_ids for path in result.paths
        }
