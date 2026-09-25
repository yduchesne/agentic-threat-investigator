# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31B integration: PostgreSQL one-hop graph neighborhood reads.

Every test exercises the real schema and the production query service:

``Entity / EvidenceObservation / InvestigationEvidence -> Relationship /
RelationshipObservation -> PostgresGraphQueryService -> GraphResult``

with the shared synthetic seeding helpers. No fake graph database or fake
query service is involved.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.graph import (
    GraphNeighborhoodQuery,
    GraphResult,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
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
) -> GraphResult | None:
    """Run one bounded neighborhood query through the production service."""
    return await services.graph.neighborhood(
        GraphNeighborhoodQuery(
            investigation_id=investigation_id,
            entity_id=entity_id,
            direction=direction,
            relationship_type=relationship_type,
            limit=limit,
        )
    )


# ---------------------------------------------------------------------------
# Visibility and isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_missing_focal_entity_returns_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-I01: a nonexistent focal Entity yields ``None``, not empty graph."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, uuid4())
        assert result is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_focal_entity_without_admitted_evidence_returns_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-I02: a global Entity without admitted association is invisible."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        other_investigation = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        # The focal Entity is associated with evidence admitted only to the
        # other Investigation, never to the requested one.
        await seed_evidence_observation(
            uow,
            investigation_id=other_investigation,
            entity_id=focal,
        )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_visible_isolated_focal_returns_one_node_graph(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-I03: a visible focal Entity with no edges returns a one-node graph."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        assert [node.entity_id for node in result.nodes] == [focal]
        assert result.edges == ()
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_focal_visibility_is_investigation_scoped(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-I04: visible in Investigation A, ``None`` in Investigation B."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await seed_evidence_observation(
            uow, investigation_id=investigation_a, entity_id=focal
        )
        services = await _services(uow)
        in_a = await _neighborhood(services, investigation_a, focal)
        assert in_a is not None
        assert [node.entity_id for node in in_a.nodes] == [focal]
        in_b = await _neighborhood(services, investigation_b, focal)
        assert in_b is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_soft_deleted_focal_entity_returns_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-I05: a soft-deleted focal Entity is never visible."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await uow.entities.soft_delete(focal)
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is None


# ---------------------------------------------------------------------------
# Direction and topology
# ---------------------------------------------------------------------------


async def _seed_source_target_fixture(
    uow: PostgresUnitOfWork,
    investigation_id: UUID,
    focal: UUID,
) -> tuple[UUID, UUID]:
    """Seed one outgoing (focal -> x) and one incoming (y -> focal) edge.

    Returns the x and y counterparty IDs.
    """
    outgoing_target = await seed_entity(uow, value="192.0.2.1")
    incoming_source = await seed_entity(uow, value="other.example.net")
    for counterparty in (outgoing_target, incoming_source):
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=(
                await seed_relationship(
                    uow,
                    source_entity_id=focal,
                    target_entity_id=counterparty,
                )
            )
            if counterparty == outgoing_target
            else (
                await seed_relationship(
                    uow,
                    source_entity_id=counterparty,
                    target_entity_id=focal,
                )
            ),
            evidence_observation_id=evidence,
        )
    return outgoing_target, incoming_source


@pytest.mark.asyncio
@pytest.mark.integration
async def test_source_direction_returns_only_outgoing(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-D01: SOURCE selects only edges whose source is the focal Entity."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        outgoing_target, incoming_source = await _seed_source_target_fixture(
            uow, investigation_id, focal
        )
        services = await _services(uow)
        result = await _neighborhood(
            services,
            investigation_id,
            focal,
            direction=RelationshipDirection.SOURCE,
        )
        assert result is not None
        assert [node.entity_id for node in result.nodes] == [focal, outgoing_target]
        assert len(result.edges) == 1
        assert result.edges[0].source_entity_id == focal
        assert result.edges[0].target_entity_id == outgoing_target
        assert incoming_source not in [node.entity_id for node in result.nodes]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_target_direction_returns_only_incoming(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-D02: TARGET selects only edges whose target is the focal Entity."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        outgoing_target, incoming_source = await _seed_source_target_fixture(
            uow, investigation_id, focal
        )
        services = await _services(uow)
        result = await _neighborhood(
            services,
            investigation_id,
            focal,
            direction=RelationshipDirection.TARGET,
        )
        assert result is not None
        assert [node.entity_id for node in result.nodes] == [focal, incoming_source]
        assert len(result.edges) == 1
        assert result.edges[0].source_entity_id == incoming_source
        assert result.edges[0].target_entity_id == focal
        assert outgoing_target not in [node.entity_id for node in result.nodes]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_either_direction_returns_both(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-D03: EITHER selects outgoing and incoming edges together."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        outgoing_target, incoming_source = await _seed_source_target_fixture(
            uow, investigation_id, focal
        )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        assert len(result.edges) == 2
        assert [node.entity_id for node in result.nodes] == [focal] + sorted(
            [outgoing_target, incoming_source]
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_self_relationship_appears_once(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-D04: a self-relationship yields one edge and one focal node."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        self_edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=self_edge,
            evidence_observation_id=evidence,
        )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        assert [node.entity_id for node in result.nodes] == [focal]
        assert len(result.edges) == 1
        assert result.edges[0].relationship_id == self_edge.id
        assert result.edges[0].source_entity_id == focal
        assert result.edges[0].target_entity_id == focal


@pytest.mark.asyncio
@pytest.mark.integration
async def test_repeated_counterparty_node_appears_once(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-D05: a counterparty shared by several edges is one node."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        counterparty = await seed_entity(uow, value="192.0.2.1")
        for relationship_type in (
            RelationshipType.RESOLVES_TO,
            RelationshipType.CNAME_OF,
        ):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            edge = await seed_relationship(
                uow,
                source_entity_id=focal,
                target_entity_id=counterparty,
                relationship_type=relationship_type,
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        assert len(result.edges) == 2
        assert [node.entity_id for node in result.nodes] == [focal, counterparty]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_type_filter(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-D06: the type filter selects only the canonical RelationshipType."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target_a = await seed_entity(uow, value="192.0.2.1")
        target_b = await seed_entity(uow, value="192.0.2.2")
        edge_a = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target_a
        )
        edge_b = await seed_relationship(
            uow,
            source_entity_id=focal,
            target_entity_id=target_b,
            relationship_type=RelationshipType.CNAME_OF,
        )
        for edge in (edge_a, edge_b):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )
        services = await _services(uow)
        result = await _neighborhood(
            services,
            investigation_id,
            focal,
            relationship_type=RelationshipType.CNAME_OF,
        )
        assert result is not None
        assert [edge.relationship_id for edge in result.edges] == [edge_b.id]
        assert [node.entity_id for node in result.nodes] == [focal, target_b]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_soft_deleted_relationship_excluded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-D07: a soft-deleted Relationship is never rendered as an edge."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
        )
        await uow.relationships.soft_delete(edge.id)
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        assert result.edges == ()
        assert [node.entity_id for node in result.nodes] == [focal]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_edge_with_soft_deleted_counterparty_excluded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-D08: an edge whose endpoint Entity is soft-deleted is excluded."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        live_target = await seed_entity(uow, value="192.0.2.1")
        dead_target = await seed_entity(uow, value="192.0.2.2")
        live_edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=live_target
        )
        dead_edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=dead_target
        )
        for edge in (live_edge, dead_edge):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )
        await uow.entities.soft_delete(dead_target)
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        assert [edge.relationship_id for edge in result.edges] == [live_edge.id]
        assert [node.entity_id for node in result.nodes] == [focal, live_target]
        assert dead_target not in [node.entity_id for node in result.nodes]


# ---------------------------------------------------------------------------
# Observation aggregation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_three_admitted_observations_aggregate_to_one_edge(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-A01: repeated admitted observations yield one edge with count 3."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        for _ in range(3):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        assert len(result.edges) == 1
        assert result.edges[0].relationship_id == edge.id
        assert result.edges[0].observation_count == 3


@pytest.mark.asyncio
@pytest.mark.integration
async def test_observation_summaries_are_investigation_scoped(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-A02: another Investigation's observations never affect summaries."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        for _ in range(2):
            evidence_a = await seed_evidence_observation(
                uow, investigation_id=investigation_a, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_a,
                relationship=edge,
                evidence_observation_id=evidence_a,
            )
        for _ in range(3):
            evidence_b = await seed_evidence_observation(
                uow, investigation_id=investigation_b, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_b,
                relationship=edge,
                evidence_observation_id=evidence_b,
            )
        services = await _services(uow)
        in_a = await _neighborhood(services, investigation_a, focal)
        assert in_a is not None
        assert in_a.edges[0].observation_count == 2
        in_b = await _neighborhood(services, investigation_b, focal)
        assert in_b is not None
        assert in_b.edges[0].observation_count == 3


@pytest.mark.asyncio
@pytest.mark.integration
async def test_first_last_observed_ignore_nulls(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-A03: first/last summarize non-null observed_at values only."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        first = FIXED_TIME
        last = FIXED_TIME + timedelta(days=2)
        for observed_at in (first, None, last):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
                observed_at=observed_at,
            )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        edge_summary = result.edges[0]
        assert edge_summary.observation_count == 3
        assert edge_summary.first_observed_at == first
        assert edge_summary.last_observed_at == last


@pytest.mark.asyncio
@pytest.mark.integration
async def test_all_null_observed_at_summaries_are_null(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-A04: count includes all observations, summaries stay null."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        for _ in range(2):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        edge_summary = result.edges[0]
        assert edge_summary.observation_count == 2
        assert edge_summary.first_observed_at is None
        assert edge_summary.last_observed_at is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_shared_evidence_observation_counts_once_per_investigation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-A05: one observation admitted to two Investigations counts in each."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        # One EvidenceObservation admitted to both Investigations exactly;
        # one RelationshipObservation references it.
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_a, entity_id=focal
        )
        assert uow.session is not None
        await uow.investigation_evidence.admit(
            InvestigationEvidence(
                investigation_id=investigation_b,
                evidence_observation_id=evidence,
                inclusion_reason=InvestigationEvidenceReason.INITIAL,
                added_at=FIXED_TIME,
                added_by=InvestigationEvidenceActor.SYSTEM,
            )
        )
        await seed_observation(
            uow,
            investigation_id=investigation_a,
            relationship=edge,
            evidence_observation_id=evidence,
        )
        services = await _services(uow)
        in_a = await _neighborhood(services, investigation_a, focal)
        assert in_a is not None
        assert in_a.edges[0].observation_count == 1
        in_b = await _neighborhood(services, investigation_b, focal)
        assert in_b is not None
        # The same observation contributes exactly once in B too -- but the
        # focal Entity is only visible in B through the shared observation,
        # which is admitted there, so the one-edge graph is visible.
        assert in_b.edges[0].observation_count == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_edge_with_unadmitted_observations_is_absent(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-A06: observations admitted only elsewhere never expose the edge."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        # Focal visibility in A, but the RelationshipObservation is only
        # admitted to B.
        await seed_evidence_observation(
            uow, investigation_id=investigation_a, entity_id=focal
        )
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        evidence_b = await seed_evidence_observation(
            uow, investigation_id=investigation_b, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_b,
            relationship=edge,
            evidence_observation_id=evidence_b,
        )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_a, focal)
        assert result is not None
        assert result.edges == ()
        assert [node.entity_id for node in result.nodes] == [focal]


# ---------------------------------------------------------------------------
# Bounds and deterministic order
# ---------------------------------------------------------------------------


async def _seed_fanout(
    uow: PostgresUnitOfWork, investigation_id: UUID, focal: UUID, edges: int
) -> list[UUID]:
    """Seed ``edges`` distinct focal-outgoing relationships; return their IDs.

    Relationship IDs are database-random, so the expected boundary ordering
    is derived by sorting the seeded IDs.
    """
    ids: list[UUID] = []
    for index in range(edges):
        target = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value=f"192.0.2.{index + 1}"
        )
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
        )
        ids.append(edge.id)
    return ids


@pytest.mark.asyncio
@pytest.mark.integration
async def test_exact_limit_is_not_truncated(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-B01: exactly ``limit`` matching edges return with no truncation."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        edge_ids = await _seed_fanout(uow, investigation_id, focal, 3)
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal, limit=3)
        assert result is not None
        assert {edge.relationship_id for edge in result.edges} == set(edge_ids)
        assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_limit_plus_one_truthfully_truncates(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-B02: with ``limit + 1`` edges, the first ``limit`` by ID are kept."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        edge_ids = await _seed_fanout(uow, investigation_id, focal, 4)
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal, limit=3)
        assert result is not None
        expected = sorted(edge_ids)[:3]
        assert [edge.relationship_id for edge in result.edges] == expected
        assert result.truncated is True
        counterparty_ids = {
            edge.target_entity_id
            for edge in result.edges
            if edge.source_entity_id == focal
        }
        assert [node.entity_id for node in result.nodes] == [focal] + sorted(
            counterparty_ids
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_oversized_limit_is_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-B03: a limit above the server maximum fails before any SQL."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=1, max_page_size=2)
        )
        query = GraphNeighborhoodQuery(
            investigation_id=investigation_id,
            entity_id=focal,
            limit=3,
        )
        with pytest.raises(ValueError):
            await services.graph.neighborhood(query)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_node_order_focal_first_then_entity_id(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-B04: nodes are ordered with the focal first, then Entity ID ASC."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await _seed_fanout(uow, investigation_id, focal, 3)
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal, limit=3)
        assert result is not None
        counterparty_ids = {
            edge.source_entity_id
            if edge.source_entity_id != focal
            else edge.target_entity_id
            for edge in result.edges
        }
        assert [node.entity_id for node in result.nodes] == [focal] + sorted(
            counterparty_ids
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_edge_order_is_relationship_id_ascending(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-B05: edges are ordered by canonical Relationship ID ascending."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        edge_ids = await _seed_fanout(uow, investigation_id, focal, 3)
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal, limit=3)
        assert result is not None
        assert [edge.relationship_id for edge in result.edges] == sorted(edge_ids)


# ---------------------------------------------------------------------------
# Projection correctness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_display_name_and_canonical_fields_projected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-P01/P02/P03: node projection maps canonical Entity fields exactly."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        named = await uow.entities.upsert(
            Entity(
                type=EntityType.DOMAIN,
                value="acme-corp",
                display_name="Acme Corp",
            )
        )
        assert named.id is not None
        unnamed = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.99"
        )
        for entity_id in (named.id, unnamed):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=entity_id
            )
            edge = await seed_relationship(
                uow,
                source_entity_id=named.id,
                target_entity_id=unnamed,
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, named.id)
        assert result is not None
        nodes_by_id = {node.entity_id: node for node in result.nodes}
        named_node = nodes_by_id[named.id]
        assert named_node.entity_type == EntityType.DOMAIN
        assert named_node.value == "acme-corp"
        assert named_node.display_name == "Acme Corp"
        unnamed_node = nodes_by_id[unnamed]
        assert unnamed_node.entity_type == EntityType.IP_ADDRESS
        assert unnamed_node.value == "192.0.2.99"
        assert unnamed_node.display_name is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_type_maps_through_canonical_enum(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-P04: the edge projection maps RelationshipType exactly."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow,
            source_entity_id=focal,
            target_entity_id=target,
            relationship_type=RelationshipType.REGISTERED_TO,
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
        )
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal)
        assert result is not None
        assert result.edges[0].relationship_type == RelationshipType.REGISTERED_TO


@pytest.mark.asyncio
@pytest.mark.integration
async def test_result_endpoint_closure(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G31B-P05: every edge endpoint is present in the result nodes."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await _seed_fanout(uow, investigation_id, focal, 3)
        services = await _services(uow)
        result = await _neighborhood(services, investigation_id, focal, limit=3)
        assert result is not None
        node_ids = {node.entity_id for node in result.nodes}
        for edge in result.edges:
            assert edge.source_entity_id in node_ids
            assert edge.target_entity_id in node_ids
        assert len(result.edges) == 3
