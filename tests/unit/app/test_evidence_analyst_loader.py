# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for EvidenceAnalystInputLoader deterministic assembly."""

# Fixture arguments intentionally reuse fixture names; the fakes mirror the
# repository seam shape used by the persistence-service suites, and the single
# World fixture carries one terminal identity per persisted row.

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Self, cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.evidence_analyst import (
    EvidenceAnalystInputBoundsError,
    EvidenceAnalystInputLoader,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EntityBatchItem,
    EntityBatchResult,
    EntityRepository,
    EvidenceRepository,
    InvestigationNotFoundError,
    InvestigationRepository,
    InvestigationWriteResult,
    RelationshipObservationRepository,
    RelationshipRepository,
    UnitOfWork,
)
from agentic_threat_investigator.domain.analyst import (
    AnalystEntity,
    AnalystRelationshipObservation,
    EvidenceAnalystInput,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationBudget,
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


def cast_unit() -> UnitOfWork:
    """Return a placeholder UnitOfWork for constructor-only tests."""
    return cast(UnitOfWork, None)


_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class FakeInvestigationRepository(InvestigationRepository):
    """Serves exactly one configured investigation row."""

    visible: InvestigationState | None

    def __init__(self, visible: InvestigationState | None) -> None:
        self.visible = visible

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        return self.visible

    async def create(
        self,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_assessment_reference(
        self, investigation_id: UUID, assessment_id: UUID, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_budget(
        self,
        investigation_id: UUID,
        budget: InvestigationBudget,
        **_: object,
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_status(
        self, investigation_id: UUID, status: InvestigationStatus, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def soft_delete(
        self, investigation_id: UUID, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError


class FakeEvidenceRepository(EvidenceRepository):
    """Returns configured rows in configured order, scoped by investigation."""

    def __init__(self, rows: list[Evidence]) -> None:
        self.rows = rows

    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Evidence]:
        scoped = [row for row in self.rows if row.investigation_id == investigation_id]
        return scoped[offset : offset + limit]

    async def insert(self, evidence: Evidence, **_: object) -> Evidence:
        raise NotImplementedError

    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        raise NotImplementedError


class FakeObservationRepository(RelationshipObservationRepository):
    """Returns configured observations in configured order."""

    def __init__(self, rows: list[RelationshipObservation]) -> None:
        self.rows = rows

    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RelationshipObservation]:
        scoped = [
            row for row in self.rows if row.investigation_id in (None, investigation_id)
        ]
        return scoped[offset : offset + limit]

    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        raise NotImplementedError

    async def get_by_id(self, observation_id: UUID) -> RelationshipObservation | None:
        raise NotImplementedError


class FakeRelationshipRepository(RelationshipRepository):
    """Returns the configured eligible relationship rows."""

    def __init__(self, rows: dict[UUID, Relationship]) -> None:
        self.rows = rows

    async def get_by_id(
        self, relationship_id: UUID, *, include_deleted: bool = False
    ) -> Relationship | None:
        return self.rows.get(relationship_id)

    async def get_by_identity(
        self,
        source_entity_id: UUID,
        relationship_type: str,
        target_entity_id: UUID,
        *,
        include_deleted: bool = False,
    ) -> Relationship | None:
        raise NotImplementedError

    async def upsert(self, relationship: Relationship, **_: object) -> Relationship:
        raise NotImplementedError

    async def soft_delete(self, relationship_id: UUID, **_: object) -> Relationship:
        raise NotImplementedError


class FakeEntityRepository(EntityRepository):
    """Returns configured entity rows by identity."""

    def __init__(self, rows: dict[UUID, Entity]) -> None:
        self.rows = rows

    async def get_by_id(
        self, entity_id: UUID, *, include_deleted: bool = False
    ) -> Entity | None:
        return self.rows.get(entity_id)

    async def get_by_identity(
        self, entity_type: str, canonical_value: str, *, include_deleted: bool = False
    ) -> Entity | None:
        raise NotImplementedError

    async def upsert(self, entity: Entity, **_: object) -> Entity:
        raise NotImplementedError

    async def upsert_batch(
        self, items: Sequence[EntityBatchItem]
    ) -> list[EntityBatchResult]:
        raise NotImplementedError

    async def soft_delete(self, entity_id: UUID, **_: object) -> Entity:
        raise NotImplementedError


class FakeUnitOfWork(UnitOfWork):
    """In-memory transaction boundary tracking close/commit/rollback."""

    entities: FakeEntityRepository
    relationships: FakeRelationshipRepository
    relationship_observations: FakeObservationRepository
    evidence: FakeEvidenceRepository
    investigations: FakeInvestigationRepository

    def __init__(
        self,
        *,
        investigations: FakeInvestigationRepository,
        evidence: FakeEvidenceRepository,
        observations: FakeObservationRepository,
        relationships: FakeRelationshipRepository,
        entities: FakeEntityRepository,
    ) -> None:
        # One explicit argument per repository seam is the UnitOfWork
        # convention; the count is intrinsic to the boundary.
        self.investigations = investigations
        self.evidence = evidence
        self.relationship_observations = observations
        self.relationships = relationships
        self.entities = entities
        self.exited = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        self.exited += 1

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


class World:
    """One complete loader world served by the fakes."""

    def __init__(self) -> None:
        self.investigation: InvestigationState | None
        self.investigation_id = uuid4()
        self.source_id = uuid4()
        self.target_id = uuid4()
        self.evidence_id = uuid4()
        self.relationship_id = uuid4()
        self.observation_id = uuid4()
        self.investigation = InvestigationState(
            investigation_id=self.investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[self.source_id],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
            version=5,
        )
        self.evidence = Evidence(
            id=self.evidence_id,
            investigation_id=self.investigation_id,
            type=EvidenceType.DNS,
            subject=EntityRef(
                id=self.source_id, type=EntityType.DOMAIN, value="example.com"
            ),
            source="urn:ati:source:google_public_dns",
            retrieved_at=_RETRIEVED_AT,
            facts={"resolves_to": ["192.0.2.1"]},
            raw_payload={"http_headers": {"x-secret": "never-leak"}},
        )
        self.relationship = Relationship(
            id=self.relationship_id,
            source_entity_id=self.source_id,
            target_entity_id=self.target_id,
            type=RelationshipType.RESOLVES_TO,
        )
        self.observation = RelationshipObservation(
            id=self.observation_id,
            relationship_id=self.relationship_id,
            evidence_id=self.evidence_id,
            investigation_id=self.investigation_id,
            retrieved_at=_RETRIEVED_AT,
            source="urn:ati:source:google_public_dns",
        )
        self.entities = {
            self.source_id: Entity(
                id=self.source_id, type=EntityType.DOMAIN, value="example.com"
            ),
            self.target_id: Entity(
                id=self.target_id,
                type=EntityType.IP_ADDRESS,
                value="192.0.2.1",
            ),
        }
        self.evidence_rows: list[Evidence] = [self.evidence]
        self.observation_rows: list[RelationshipObservation] = [self.observation]
        self.relationship_rows: dict[UUID, Relationship] = {
            self.relationship_id: self.relationship
        }
        self.closed_before_return = False

    def unit(self) -> FakeUnitOfWork:
        """Build a UnitOfWork serving this world."""
        return FakeUnitOfWork(
            investigations=FakeInvestigationRepository(self.investigation),
            evidence=FakeEvidenceRepository(self.evidence_rows),
            observations=FakeObservationRepository(self.observation_rows),
            relationships=FakeRelationshipRepository(self.relationship_rows),
            entities=FakeEntityRepository(self.entities),
        )


@pytest.fixture
def world() -> World:
    """Return one deterministic loader world."""
    return World()


@pytest.fixture
def loader(
    world: World,
) -> Callable[[], EvidenceAnalystInputLoader]:
    """Return a factory building a loader bound to the world's UoW."""
    return lambda: EvidenceAnalystInputLoader(
        world.unit,
        max_evidence_items=100,
        max_relationship_observations=200,
        max_input_bytes=262_144,
    )


@pytest.mark.asyncio
async def test_loads_visible_investigation(
    world: World, loader: Callable[[], EvidenceAnalystInputLoader]
) -> None:
    """A visible Investigation loads with its objective and root entities."""
    analyst_input = await loader().load(world.investigation_id)

    assert isinstance(analyst_input, EvidenceAnalystInput)
    assert analyst_input.investigation_id == world.investigation_id
    assert analyst_input.objective == "Assess the root indicator."
    assert analyst_input.root_entities == (
        AnalystEntity(
            entity_id=world.source_id,
            entity_type=EntityType.DOMAIN,
            value="example.com",
        ),
    )


@pytest.mark.asyncio
async def test_missing_investigation_rejected(world: World) -> None:
    """A missing/deleted Investigation fails with the typed lookup error."""
    world.investigation = None
    loader = EvidenceAnalystInputLoader(
        world.unit,
    )

    with pytest.raises(InvestigationNotFoundError):
        await loader.load(world.investigation_id)


@pytest.mark.asyncio
async def test_evidence_scoped_and_ordered(
    world: World, loader: Callable[[], EvidenceAnalystInputLoader]
) -> None:
    """Evidence is scoped to the Investigation and keeps deterministic order."""
    second = world.evidence.model_copy(
        update={
            "id": uuid4(),
            "evidence_id": None,
            "type": EvidenceType.NETWORK,
            "retrieved_at": datetime(2026, 1, 1, tzinfo=UTC),
        }
    )
    world.evidence_rows = [world.evidence, second]

    analyst_input = await loader().load(world.investigation_id)

    assert [item.evidence_id for item in analyst_input.evidence] == [
        world.evidence_id,
        second.id,
    ]


@pytest.mark.asyncio
async def test_raw_payload_excluded_and_facts_preserved(
    world: World, loader: Callable[[], EvidenceAnalystInputLoader]
) -> None:
    """raw_payload never reaches the input; normalized facts are preserved."""
    analyst_input = await loader().load(world.investigation_id)

    serialized = analyst_input.model_dump(mode="json")
    assert "raw_payload" not in serialized
    assert "never-leak" not in str(serialized)
    assert serialized["evidence"][0]["facts"] == {"resolves_to": ["192.0.2.1"]}


@pytest.mark.asyncio
async def test_observation_resolves_relationship_and_entities(
    world: World, loader: Callable[[], EvidenceAnalystInputLoader]
) -> None:
    """An eligible observation resolves its Relationship and endpoint Entities."""
    analyst_input = await loader().load(world.investigation_id)

    [observation] = analyst_input.relationship_observations
    assert isinstance(observation, AnalystRelationshipObservation)
    assert observation.relationship_observation_id == world.observation_id
    assert observation.evidence_id == world.evidence_id
    assert observation.relationship_id == world.relationship_id
    assert observation.relationship_type == RelationshipType.RESOLVES_TO
    assert observation.source_entity.entity_id == world.source_id
    assert observation.target_entity.entity_id == world.target_id
    assert observation.source_entity.value == "example.com"
    assert observation.target_entity.value == "192.0.2.1"


@pytest.mark.asyncio
async def test_direct_evidence_without_observations_present(
    world: World,
) -> None:
    """Evidence with zero RelationshipObservations stays fully present."""
    world.observation_rows = []

    analyst_input = await EvidenceAnalystInputLoader(
        world.unit,
    ).load(world.investigation_id)

    assert len(analyst_input.evidence) == 1
    assert analyst_input.relationship_observations == ()


@pytest.mark.asyncio
async def test_ineligible_relationship_omits_observation(
    world: World,
) -> None:
    """An observation whose Relationship is missing/deleted is omitted."""
    world.relationship_rows = {}

    analyst_input = await EvidenceAnalystInputLoader(
        world.unit,
    ).load(world.investigation_id)

    assert analyst_input.relationship_observations == ()
    assert len(analyst_input.evidence) == 1


@pytest.mark.asyncio
async def test_ineligible_entity_omits_observation(
    world: World,
) -> None:
    """An observation with a missing endpoint Entity is omitted consistently."""
    del world.entities[world.target_id]

    analyst_input = await EvidenceAnalystInputLoader(
        world.unit,
    ).load(world.investigation_id)

    assert analyst_input.relationship_observations == ()


@pytest.mark.asyncio
async def test_observations_from_other_investigation_excluded(
    world: World,
) -> None:
    """Observations correlated to another Investigation are excluded."""
    world.observation_rows = [
        world.observation,
        RelationshipObservation(
            id=uuid4(),
            relationship_id=world.relationship_id,
            evidence_id=world.evidence_id,
            investigation_id=uuid4(),
            retrieved_at=_RETRIEVED_AT,
            source="urn:ati:source:google_public_dns",
        ),
    ]

    analyst_input = await EvidenceAnalystInputLoader(
        world.unit,
    ).load(world.investigation_id)

    assert [
        obs.relationship_observation_id
        for obs in analyst_input.relationship_observations
    ] == [world.observation_id]


@pytest.mark.asyncio
async def test_unit_of_work_closes_before_return(world: World) -> None:
    """The short read-only UnitOfWork is closed before the input escapes."""
    unit = world.unit()
    test_loader = EvidenceAnalystInputLoader(lambda: unit)

    await test_loader.load(world.investigation_id)

    assert unit.exited == 1


@pytest.mark.asyncio
async def test_evidence_bound_exceeded_fails_before_llm(world: World) -> None:
    """An oversize Evidence set fails with the typed bounds error."""
    world.evidence_rows = [
        Evidence(
            id=uuid4(),
            investigation_id=world.investigation_id,
            type=EvidenceType.DNS,
            subject=EntityRef(
                id=world.source_id, type=EntityType.DOMAIN, value="example.com"
            ),
            source="urn:ati:source:google_public_dns",
            retrieved_at=_RETRIEVED_AT,
        )
        for _ in range(3)
    ]
    loader = EvidenceAnalystInputLoader(world.unit, max_evidence_items=2)

    with pytest.raises(EvidenceAnalystInputBoundsError) as holder:
        await loader.load(world.investigation_id)

    assert holder.value.bound == "evidence_items"


@pytest.mark.asyncio
async def test_serialized_input_bound_exceeded(world: World) -> None:
    """The serialized input size is bounded before any model call."""
    world.evidence_rows = [
        world.evidence.model_copy(update={"facts": {"blob": "x" * 5000}})
    ]
    loader = EvidenceAnalystInputLoader(world.unit, max_input_bytes=1024)

    with pytest.raises(EvidenceAnalystInputBoundsError) as holder:
        await loader.load(world.investigation_id)

    assert holder.value.bound == "serialized_input"


@pytest.mark.asyncio
async def test_no_infrastructure_or_secret_material_in_dto(
    world: World, loader: Callable[[], EvidenceAnalystInputLoader]
) -> None:
    """The DTO carries only normalized analytical content."""
    analyst_input = await loader().load(world.investigation_id)

    serialized = analyst_input.model_dump_json()
    for forbidden in (
        '"api_key"',
        '"secret"',
        '"config"',
        '"provider_client"',
        '"session"',
        '"http_headers"',
        "ATI_",
    ):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_evidence_items": 0},
        {"max_evidence_items": -1},
        {"max_evidence_items": 501},
        {"max_relationship_observations": 0},
        {"max_relationship_observations": -1},
        {"max_relationship_observations": 1001},
        {"max_input_bytes": 999},
        {"max_input_bytes": 1_000_001},
        {"max_normalized_facts_bytes": 999},
        {"max_normalized_facts_bytes": 1_000_001},
    ],
)
def test_constructor_rejects_values_outside_hard_ceilings(
    kwargs: dict[str, int],
) -> None:
    """Direct construction cannot bypass the Settings-mirroring ceilings."""
    with pytest.raises(ValueError, match="range"):
        EvidenceAnalystInputLoader(
            cast_unit,
            **kwargs,
        )


@pytest.mark.parametrize("bound", [1, 500, 1000, 1_000_000], ids=str)
def test_constructor_accepts_boundary_values(bound: int) -> None:
    """Constructor boundary values at each hard ceiling are accepted."""
    loader = EvidenceAnalystInputLoader(
        cast_unit,
        max_evidence_items=min(bound, 500),
        max_relationship_observations=min(bound, 1000),
        max_normalized_facts_bytes=max(bound, 1000),
        max_input_bytes=max(bound, 1000),
    )
    assert loader is not None


@pytest.mark.parametrize("multibyte", [False, True])
@pytest.mark.asyncio
async def test_normalized_facts_bound_counts_utf8_bytes(
    world: World, multibyte: bool
) -> None:
    """The facts bound measures UTF-8 bytes, not Python characters.

    ``{"a":"é"*496}`` serializes deterministically to 504 characters but
    exactly 1000 UTF-8 bytes ({'a': 'é'} is 9 chars / 10 bytes, each é
    counting two bytes). A character-counting implementation would accept
    one extra é (505 chars) at a 1000 limit; the byte-counting
    implementation rejects it because the size is 1002 bytes.
    """
    if multibyte:
        within = {"a": "é" * 496}  # exactly 1000 bytes
        over = {"a": "é" * 497}  # 1002 bytes
    else:
        within = {"a": "x" * 992}  # exactly 1000 bytes
        over = {"a": "x" * 993}  # 1001 bytes
    world.evidence_rows = [world.evidence.model_copy(update={"facts": within})]
    exact_loader = EvidenceAnalystInputLoader(
        world.unit, max_normalized_facts_bytes=1000
    )
    analyst_input = await exact_loader.load(world.investigation_id)
    assert len(analyst_input.evidence) == 1

    world.evidence_rows = [world.evidence.model_copy(update={"facts": over})]
    over_loader = EvidenceAnalystInputLoader(
        world.unit, max_normalized_facts_bytes=1000
    )
    with pytest.raises(EvidenceAnalystInputBoundsError) as holder:
        await over_loader.load(world.investigation_id)
    assert holder.value.bound == "normalized_facts"


@pytest.mark.asyncio
async def test_normalized_facts_bound_before_any_other_side_effect(
    world: World,
) -> None:
    """The facts bound fails during load, before any LLM call is possible."""
    world.evidence_rows = [
        world.evidence.model_copy(update={"facts": {"blob": "x" * 1200}})
    ]
    loader = EvidenceAnalystInputLoader(world.unit, max_normalized_facts_bytes=1000)

    with pytest.raises(EvidenceAnalystInputBoundsError) as holder:
        await loader.load(world.investigation_id)

    assert holder.value.bound == "normalized_facts"
    assert holder.value.actual > holder.value.limit
