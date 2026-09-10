# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL integration coverage for the Evidence Analyst observation read.

Covers the narrow investigation-scoped observation listing added for PR 20B:
scoping through the observation's Evidence, deterministic ordering, mismatch
exclusion, and paging. The seeded graph mirrors the provider-pipeline shape:
Investigation -> Evidence -> Relationship -> RelationshipObservation rows.
"""

# pylint: disable=redefined-outer-name

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


async def seed_graph(
    uow: PostgresUnitOfWork,
) -> tuple[UUID, UUID, UUID]:
    """Create one investigation, one evidence row, and one resolved edge."""
    investigation_id = uuid4()
    await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[uuid4()],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
        )
    )
    source = await uow.entities.upsert(
        Entity(type=EntityType.DOMAIN, value=f"source-{uuid4().hex[:8]}.com")
    )
    target = await uow.entities.upsert(
        Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
    )
    assert source.id is not None and target.id is not None
    evidence = Evidence(
        investigation_id=investigation_id,
        type=EvidenceType.DNS,
        subject=EntityRef(id=source.id, type=EntityType.DOMAIN, value=source.value),
        source="urn:ati:source:google_public_dns",
        retrieved_at=_RETRIEVED_AT,
    )
    evidence = await uow.evidence.insert(evidence)
    assert evidence.id is not None
    evidence_id = evidence.id
    relationship = await uow.relationships.upsert(
        Relationship(
            id=uuid4(),
            source_entity_id=source.id,
            target_entity_id=target.id,
            type=RelationshipType.RESOLVES_TO,
        )
    )
    return investigation_id, evidence_id, relationship.id


def observation_factory(
    *,
    relationship_id: UUID,
    evidence_id: UUID,
    investigation_id: UUID | None = None,
    retrieved_at: datetime | None = None,
) -> tuple[RelationshipObservation, UUID]:
    """Build an observation and its deterministic identity for append."""
    observation_id = uuid4()
    return (
        RelationshipObservation(
            id=observation_id,
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            retrieved_at=retrieved_at or _RETRIEVED_AT,
            source="urn:ati:source:google_public_dns",
            confidence=0.9,
        ),
        observation_id,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_list_for_investigation_is_scoped_and_deterministic(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The listing returns only observations backed by the Investigation's Evidence."""
    async with uow_factory() as uow:
        investigation_id, evidence_id, relationship_id = await seed_graph(uow)
        older, older_id = observation_factory(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            retrieved_at=_RETRIEVED_AT - timedelta(minutes=10),
        )
        newer, newer_id = observation_factory(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            retrieved_at=_RETRIEVED_AT,
        )
        await uow.relationship_observations.append(older)
        await uow.relationship_observations.append(newer)

        listed = await uow.relationship_observations.list_for_investigation(
            investigation_id
        )

    assert [row.id for row in listed] == [newer_id, older_id]
    assert all(row.investigation_id == investigation_id for row in listed)
    assert all(row.evidence_id == evidence_id for row in listed)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_listing_excludes_other_investigation_evidence(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Observations backed by another Investigation's Evidence are excluded."""
    async with uow_factory() as uow:
        investigation_id, evidence_id, relationship_id = await seed_graph(uow)
        other_investigation_id, other_evidence_id, _ = await seed_graph(uow)
        await uow.relationship_observations.append(
            observation_factory(
                relationship_id=relationship_id,
                evidence_id=evidence_id,
                investigation_id=None,
                retrieved_at=_RETRIEVED_AT,
            )[0]
        )
        await uow.relationship_observations.append(
            observation_factory(
                relationship_id=relationship_id,
                evidence_id=other_evidence_id,
                investigation_id=other_investigation_id,
                retrieved_at=_RETRIEVED_AT + timedelta(minutes=1),
            )[0]
        )

        listed = await uow.relationship_observations.list_for_investigation(
            investigation_id
        )

    assert len(listed) == 1
    assert listed[0].evidence_id == evidence_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_listing_excludes_contradictory_correlation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An observation correlated to a different Investigation is excluded."""
    async with uow_factory() as uow:
        investigation_id, evidence_id, relationship_id = await seed_graph(uow)
        await uow.relationship_observations.append(
            observation_factory(
                relationship_id=relationship_id,
                evidence_id=evidence_id,
                investigation_id=uuid4(),
                retrieved_at=_RETRIEVED_AT,
            )[0]
        )

        listed = await uow.relationship_observations.list_for_investigation(
            investigation_id
        )

    assert listed == []


@pytest.mark.asyncio
@pytest.mark.integration
async def test_listing_honors_limit_and_offset(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Paging is deterministic and bounded."""
    async with uow_factory() as uow:
        investigation_id, evidence_id, relationship_id = await seed_graph(uow)
        ids: list[UUID] = []
        for index in range(3):
            _observation, observation_id = observation_factory(
                relationship_id=relationship_id,
                evidence_id=evidence_id,
                investigation_id=investigation_id,
                retrieved_at=_RETRIEVED_AT + timedelta(minutes=index),
            )
            ids.append(observation_id)
            await uow.relationship_observations.append(_observation)

        page_one = await uow.relationship_observations.list_for_investigation(
            investigation_id, limit=2, offset=0
        )
        page_two = await uow.relationship_observations.list_for_investigation(
            investigation_id, limit=2, offset=2
        )

    assert [row.id for row in page_one] == [ids[2], ids[1]]
    assert [row.id for row in page_two] == [ids[0]]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_listing_rejects_negative_paging_params(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Negative paging parameters are rejected before SQL execution."""
    async with uow_factory() as uow:
        investigation_id, _evidence_id, _relationship_id = await seed_graph(uow)

        with pytest.raises(ValueError, match="non-negative"):
            await uow.relationship_observations.list_for_investigation(
                investigation_id, limit=-1
            )
        with pytest.raises(ValueError, match="non-negative"):
            await uow.relationship_observations.list_for_investigation(
                investigation_id, offset=-1
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_probe_limit_of_1001_is_not_silently_reduced(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The loader overflow probe limit is honored without silent clamping.

    The Evidence Analyst asks for ``max + 1`` (up to 1001) to detect an
    oversize observation set; the repository must return up to that many
    rows rather than clamping to 1000 and hiding the overflow.
    """
    async with uow_factory() as uow:
        investigation_id, evidence_id, relationship_id = await seed_graph(uow)
        rows: list[RelationshipObservation] = []
        for index in range(3):
            observation, _observation_id = observation_factory(
                relationship_id=relationship_id,
                evidence_id=evidence_id,
                investigation_id=investigation_id,
                retrieved_at=_RETRIEVED_AT + timedelta(minutes=index),
            )
            rows.append(observation)
            await uow.relationship_observations.append(observation)

        listed = await uow.relationship_observations.list_for_investigation(
            investigation_id, limit=1001, offset=0
        )

    # Three eligible rows are returned even though the maximum analyst bound
    # is 1000 and the requested limit is the 1001 probe sentinel.
    assert len(listed) == 3


@pytest.mark.asyncio
@pytest.mark.integration
async def test_limit_above_probe_ceiling_is_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A limit beyond the explicit 1001 probe ceiling raises instead of clamping."""
    async with uow_factory() as uow:
        investigation_id, _evidence_id, _relationship_id = await seed_graph(uow)

        with pytest.raises(ValueError, match="must not exceed 1001"):
            await uow.relationship_observations.list_for_investigation(
                investigation_id, limit=1002
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_deterministic_uuid_tie_breaker_on_equal_timestamps(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Identical retrieved/observed timestamps order by ascending UUID."""
    async with uow_factory() as uow:
        investigation_id, evidence_id, relationship_id = await seed_graph(uow)
        first, first_id = observation_factory(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            retrieved_at=_RETRIEVED_AT,
        )
        second, second_id = observation_factory(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            retrieved_at=_RETRIEVED_AT,
        )
        assert first_id != second_id
        await uow.relationship_observations.append(first)
        await uow.relationship_observations.append(second)

        listed = await uow.relationship_observations.list_for_investigation(
            investigation_id
        )

    expected = sorted([first_id, second_id])
    assert [row.id for row in listed] == expected
    assert listed == sorted(listed, key=lambda row: row.id)


async def seed_many_observations(
    uow: PostgresUnitOfWork, count: int
) -> tuple[UUID, UUID]:
    """Seed one investigation with ``count`` eligible observations."""
    investigation_id, evidence_id, relationship_id = await seed_graph(uow)
    for index in range(count):
        observation, _observation_id = observation_factory(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            retrieved_at=_RETRIEVED_AT + timedelta(minutes=index),
        )
        await uow.relationship_observations.append(observation)
    return investigation_id, relationship_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_loader_detects_1001_observations_with_1000_bound(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """At the documented maximum, one extra observation fails before any LLM.

    The loader probes with limit 1001; because the repository no longer
    clamps to 1000, the 1001st row is returned and the loader raises
    ``EvidenceAnalystInputBoundsError`` instead of silently analyzing a
    truncated set.
    """
    from agentic_threat_investigator.app.evidence_analyst import (
        EvidenceAnalystInputBoundsError,
        EvidenceAnalystInputLoader,
    )

    async with uow_factory() as uow:
        investigation_id, _relationship_id = await seed_many_observations(uow, 1001)

    loader = EvidenceAnalystInputLoader(uow_factory, max_relationship_observations=1000)
    with pytest.raises(EvidenceAnalystInputBoundsError) as holder:
        await loader.load(investigation_id)

    assert holder.value.bound == "relationship_observations"
    assert holder.value.actual == 1001
    assert holder.value.limit == 1000
