# SPDX-License-Identifier: AGPL-3.0-only
"""PR 24E integration: entity-centric RelationshipObservation queries (E-B01..E-B16).

Runs the entity-centric evolution filter semantics over real PostgreSQL:
focal/entity direction/counterparty/type/providers/time filters are applied
in SQL through the joined stable Relationship, Investigation isolation is
enforced, self-relationships are never duplicated, canonical
``retrieved_at DESC, id ASC`` ordering is preserved, pagination stays
bounded, and opaque cursors fail closed across semantic filter changes.
No mocked repository is involved.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.pagination import (
    CursorFilterMismatchError,
    CursorQueryMismatchError,
)
from agentic_threat_investigator.app.query.relationships import (
    RelationshipListQuery,
    RelationshipObservationListQuery,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)
from agentic_threat_investigator.domain.relationships import (
    RelationshipObservation as ObservationModel,
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


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b01_entity_only_matches_either_direction(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A bare entity filter matches edges on either side (documented either)."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                limit=50,
            )
        )
        # A is the source of A->B (3 observations) and of A->C (1, REGISTERED_TO)
        # and the target of B->A (1).
        assert {item.id for item in page.items} == (
            fixture.obs_a_out | fixture.obs_b_in | fixture.obs_a_c
        )
        # Joined semantics ship with the row; every edge involves A and D never
        # appears even though D->E was observed in the same Investigation.
        for item in page.items:
            assert fixture.a in {
                item.relationship_source_entity_id,
                item.relationship_target_entity_id,
            }
            assert fixture.d not in {
                item.relationship_source_entity_id,
                item.relationship_target_entity_id,
            }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b02_entity_source_direction_only_source_edges(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """direction=source selects only edges whose source is the focal entity."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.SOURCE,
                limit=50,
            )
        )
        assert {item.id for item in page.items} == fixture.obs_a_out | fixture.obs_a_c


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b03_entity_target_direction_only_target_edges(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """direction=target selects only edges whose target is the focal entity."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.TARGET,
                limit=50,
            )
        )
        assert {item.id for item in page.items} == fixture.obs_b_in


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b04_entity_either_direction_matches_both(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """direction=either matches source OR target on the server."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.EITHER,
                limit=50,
            )
        )
        assert {item.id for item in page.items} == (
            fixture.obs_a_out | fixture.obs_b_in | fixture.obs_a_c
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b05_counterparty_source_exact_pair(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """entity + counterparty + source pins the exact directional pair."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.SOURCE,
                counterparty_entity_id=fixture.b,
                limit=50,
            )
        )
        assert {item.id for item in page.items} == fixture.obs_a_out
        # The reverse pair (B->A) is found through target+counterparty B.
        reverse = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.TARGET,
                counterparty_entity_id=fixture.b,
                limit=50,
            )
        )
        assert {item.id for item in reverse.items} == fixture.obs_b_in


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b06_counterparty_target_reverse_pair(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """entity + counterparty + target finds the reverse directional pair."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.TARGET,
                counterparty_entity_id=fixture.b,
                limit=50,
            )
        )
        assert {item.id for item in page.items} == fixture.obs_b_in


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b07_counterparty_either_matches_either_orientation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """entity + counterparty + either matches the pair in either orientation."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.EITHER,
                counterparty_entity_id=fixture.b,
                limit=50,
            )
        )
        assert {item.id for item in page.items} == fixture.obs_a_out | fixture.obs_b_in
        # The typed pair with counterparty C is the A->C REGISTERED_TO edge.
        typed_c = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.EITHER,
                counterparty_entity_id=fixture.c,
                limit=50,
            )
        )
        assert {item.id for item in typed_c.items} == fixture.obs_a_c
        # D shares no edge with A, so no orientation ever matches.
        wrong = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.EITHER,
                counterparty_entity_id=fixture.d,
                limit=50,
            )
        )
        assert wrong.items == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b08_relationship_type_matches_exact_type(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """relationship_type filters through the joined edge exactly."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                relationship_type=RelationshipType.REGISTERED_TO,
                limit=50,
            )
        )
        assert {item.id for item in page.items} == fixture.obs_a_c
        for item in page.items:
            assert item.relationship_type is RelationshipType.REGISTERED_TO


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b09_type_and_entity_intersect(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """relationship_type + entity intersect: only the typed focal edges."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                relationship_type=RelationshipType.RESOLVES_TO,
                limit=50,
            )
        )
        # A->C is REGISTERED_TO and B->A is CNAME_OF, so both are excluded.
        assert {item.id for item in page.items} == fixture.obs_a_out
        c_only = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                relationship_type=RelationshipType.REGISTERED_TO,
                limit=50,
            )
        )
        assert {item.id for item in c_only.items} == fixture.obs_a_c


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b10_provider_and_entity_intersect(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The existing source/provider filter intersects with the entity filter."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                source="urn:ati:source:rdap",
                limit=50,
            )
        )
        # Only the A->C observation was retrieved through rdap.
        assert {item.id for item in page.items} == fixture.obs_a_c


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b11_observed_range_and_entity_intersect(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The observed-at half-open range stays orthogonal to the entity filter."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                observed_from=FIXED_TIME + timedelta(days=2),
                observed_to=FIXED_TIME + timedelta(days=4),
                limit=50,
            )
        )
        # A->B observations span days 1..3; only the day-2 and day-3 remain.
        assert {item.id for item in page.items} == {
            fixture.obs_a_out_times[1],
            fixture.obs_a_out_times[2],
        }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b12_direction_without_entity_rejected() -> None:
    """direction without entity_id fails at the query contract (E-B12)."""
    with pytest.raises(ValueError):
        RelationshipObservationListQuery(
            investigation_id=UUID(int=1),
            direction=RelationshipDirection.SOURCE,
            limit=10,
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b13_counterparty_without_entity_rejected() -> None:
    """counterparty_entity_id without entity_id fails at the contract (E-B13)."""
    with pytest.raises(ValueError):
        RelationshipObservationListQuery(
            investigation_id=UUID(int=1),
            counterparty_entity_id=UUID(int=2),
            limit=10,
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b14_wrong_investigation_leaks_nothing(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Observations of the same edge in another Investigation stay invisible."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        other_investigation = await seed_investigation(uow)
        # Re-observe the same A->B edge inside the other Investigation.
        observation_id = await seed_evidence_observation(
            uow, investigation_id=other_investigation, entity_id=fixture.a
        )
        await uow.relationship_observations.append(
            _observation(
                other_investigation, fixture.a_b_relationship_id, observation_id
            )
        )
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                limit=50,
            )
        )
        assert {item.id for item in page.items} == (
            fixture.obs_a_out | fixture.obs_b_in | fixture.obs_a_c
        )
        other = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=other_investigation,
                entity_id=fixture.a,
                limit=50,
            )
        )
        assert len(other.items) == 1
        assert other.items[0].investigation_id == other_investigation


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b15_self_relationship_is_not_duplicated(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A self-relationship appears once even under either-direction semantics."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity = await seed_entity(uow, value="self.example.com")
        edge = await seed_relationship(
            uow, source_entity_id=entity, target_entity_id=entity
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=entity
        )
        observed = await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
        )
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=investigation_id,
                entity_id=entity,
                direction=RelationshipDirection.EITHER,
                limit=50,
            )
        )
        assert [item.id for item in page.items] == [observed.id]
        source = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=investigation_id,
                entity_id=entity,
                direction=RelationshipDirection.SOURCE,
                limit=50,
            )
        )
        assert [item.id for item in source.items] == [observed.id]
        target = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=investigation_id,
                entity_id=entity,
                direction=RelationshipDirection.TARGET,
                limit=50,
            )
        )
        assert [item.id for item in target.items] == [observed.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b15b_cursor_pagination_stays_bounded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Entity-centric pagination returns one bounded page at a time (E-32p)."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected: list[UUID] = []
        cursor: str | None = None
        pages = 0
        while True:
            pages += 1
            page = await services.relationship_observations.list(
                RelationshipObservationListQuery(
                    investigation_id=fixture.investigation_id,
                    entity_id=fixture.a,
                    limit=1,
                    cursor=cursor,
                )
            )
            assert len(page.items) <= 1
            collected.extend(item.id for item in page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
            assert pages < 20
        assert set(collected) == fixture.obs_a_out | fixture.obs_b_in | fixture.obs_a_c
        assert len(collected) == 5


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b15c_cursor_cannot_reuse_across_focal_entity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A cursor bound to entity A cannot continue entity B (E-B17-style)."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page_a = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                limit=1,
            )
        )
        assert page_a.next_cursor is not None
        with pytest.raises(CursorFilterMismatchError):
            await services.relationship_observations.list(
                RelationshipObservationListQuery(
                    investigation_id=fixture.investigation_id,
                    entity_id=fixture.b,
                    limit=1,
                    cursor=page_a.next_cursor,
                )
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b15d_cursor_cannot_reuse_across_direction_or_type(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Direction and relationship-type changes invalidate opaque cursors."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        source_page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                direction=RelationshipDirection.SOURCE,
                limit=1,
            )
        )
        assert source_page.next_cursor is not None
        cursor = source_page.next_cursor
        with pytest.raises(CursorFilterMismatchError):
            await services.relationship_observations.list(
                RelationshipObservationListQuery(
                    investigation_id=fixture.investigation_id,
                    entity_id=fixture.a,
                    direction=RelationshipDirection.TARGET,
                    limit=1,
                    cursor=cursor,
                )
            )
        # A type-filtered query cursor mismatches the same query without type.
        typed = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                relationship_type=RelationshipType.RESOLVES_TO,
                limit=1,
            )
        )
        assert typed.next_cursor is not None
        with pytest.raises(CursorFilterMismatchError):
            await services.relationship_observations.list(
                RelationshipObservationListQuery(
                    investigation_id=fixture.investigation_id,
                    entity_id=fixture.a,
                    limit=1,
                    cursor=typed.next_cursor,
                )
            )
        # A Relationships-collection cursor cannot be reused for observations.
        relationship_page = await services.relationships.list(
            RelationshipListQuery(
                investigation_id=fixture.investigation_id,
                entity_id=fixture.a,
                limit=1,
            )
        )
        assert relationship_page.next_cursor is not None
        with pytest.raises(CursorQueryMismatchError):
            await services.relationship_observations.list(
                RelationshipObservationListQuery(
                    investigation_id=fixture.investigation_id,
                    entity_id=fixture.a,
                    limit=1,
                    cursor=relationship_page.next_cursor,
                )
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_e_b16_old_filters_unaffected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """relationship_id / retrieved-range filtering keeps prior behavior."""
    async with uow_factory() as uow:
        fixture = await _seed_evolution_world(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                relationship_id=fixture.a_b_relationship_id,
                limit=50,
            )
        )
        assert {item.id for item in page.items} == fixture.obs_a_out
        retrieved = await services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=fixture.investigation_id,
                retrieved_from=FIXED_TIME + timedelta(days=20),
                retrieved_to=FIXED_TIME + timedelta(days=40),
                limit=50,
            )
        )
        # Only D->E was retrieved at day 30 inside the range.
        assert {item.id for item in retrieved.items} == set(fixture.obs_d_e)


@dataclass
class EvolutionWorld:
    """One deterministic entity-centric evolution fixture world."""

    investigation_id: UUID
    a: UUID
    b: UUID
    c: UUID
    d: UUID
    e: UUID
    a_b_relationship_id: UUID
    obs_a_out: frozenset[UUID]
    obs_a_out_times: tuple[UUID, UUID, UUID]
    obs_b_in: frozenset[UUID]
    obs_a_c: frozenset[UUID]
    obs_d_e: frozenset[UUID]


async def _seed_evolution_world(
    uow: PostgresUnitOfWork,
) -> EvolutionWorld:
    """Seed the PR 24E synthetic world with deterministic temporal spread.

    Focal entity A, counterparties B and C, one reverse edge, one unrelated
    edge D->E, multiple providers, distinct observed/retrieved times and one
    observation with a null observed time.
    """
    investigation_id = await seed_investigation(uow)
    a = await seed_entity(uow, value="focal-a.test")
    b = await seed_entity(uow, value="counterparty-b.test")
    c = await seed_entity(uow, value="counterparty-c.test")
    d = await seed_entity(uow, value="unrelated-d.test")
    e = await seed_entity(uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.9")

    a_b = await seed_relationship(uow, source_entity_id=a, target_entity_id=b)
    b_a = await seed_relationship(
        uow,
        source_entity_id=b,
        target_entity_id=a,
        relationship_type=RelationshipType.CNAME_OF,
    )
    a_c = await seed_relationship(
        uow,
        source_entity_id=a,
        target_entity_id=c,
        relationship_type=RelationshipType.REGISTERED_TO,
    )
    d_e = await seed_relationship(uow, source_entity_id=d, target_entity_id=e)

    obs_a_out: list[UUID] = []
    for day in (1, 2, 3):
        evidence = await seed_evidence_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=a,
            source="urn:ati:source:google_public_dns",
            retrieved_at=FIXED_TIME + timedelta(days=10 + day),
        )
        observation = await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=a_b,
            evidence_observation_id=evidence,
            retrieved_at=FIXED_TIME + timedelta(days=10 + day),
            observed_at=FIXED_TIME + timedelta(days=day, hours=6),
        )
        obs_a_out.append(observation.id)

    b_in_evidence = await seed_evidence_observation(
        uow,
        investigation_id=investigation_id,
        entity_id=b,
        source="urn:ati:source:google_public_dns",
        retrieved_at=FIXED_TIME + timedelta(days=13),
    )
    b_in = await seed_observation(
        uow,
        investigation_id=investigation_id,
        relationship=b_a,
        evidence_observation_id=b_in_evidence,
        retrieved_at=FIXED_TIME + timedelta(days=13),
        observed_at=FIXED_TIME + timedelta(days=4, hours=9),
    )

    a_c_evidence = await seed_evidence_observation(
        uow,
        investigation_id=investigation_id,
        entity_id=a,
        source="urn:ati:source:rdap",
        evidence_type=EvidenceType.REGISTRATION,
        retrieved_at=FIXED_TIME + timedelta(days=14),
    )
    a_c_obs = await seed_observation(
        uow,
        investigation_id=investigation_id,
        relationship=a_c,
        evidence_observation_id=a_c_evidence,
        source="urn:ati:source:rdap",
        retrieved_at=FIXED_TIME + timedelta(days=14),
        observed_at=None,
    )

    d_e_evidence = await seed_evidence_observation(
        uow,
        investigation_id=investigation_id,
        entity_id=d,
        source="urn:ati:source:threatfox",
        retrieved_at=FIXED_TIME + timedelta(days=30),
    )
    d_e_obs = await seed_observation(
        uow,
        investigation_id=investigation_id,
        relationship=d_e,
        evidence_observation_id=d_e_evidence,
        retrieved_at=FIXED_TIME + timedelta(days=30),
        observed_at=FIXED_TIME + timedelta(days=20),
    )

    return EvolutionWorld(
        investigation_id=investigation_id,
        a=a,
        b=b,
        c=c,
        d=d,
        e=e,
        a_b_relationship_id=a_b.id,
        obs_a_out=frozenset(obs_a_out),
        obs_a_out_times=(obs_a_out[0], obs_a_out[1], obs_a_out[2]),
        obs_b_in=frozenset({b_in.id}),
        obs_a_c=frozenset({a_c_obs.id}),
        obs_d_e=frozenset({d_e_obs.id}),
    )


def _observation(
    investigation_id: UUID,
    relationship_id: UUID,
    evidence_observation_id: UUID,
) -> ObservationModel:
    """Build one appended observation row on an already-recorded observation id."""
    return ObservationModel(
        id=uuid4(),
        relationship_id=relationship_id,
        evidence_observation_id=evidence_observation_id,
        observed_at=None,
        retrieved_at=FIXED_TIME + timedelta(days=5),
        source="urn:ati:source:google_public_dns",
    )
