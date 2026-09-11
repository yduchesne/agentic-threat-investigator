# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic scenario fixture materialization.

An in-memory UnitOfWork records every persisted row so the materializer's
ordering, identity derivation, and resolution coverage can be asserted
without any database.
"""

from __future__ import annotations

from typing import cast
from uuid import UUID

import pytest

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import EntityRef, Evidence
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)
from agentic_threat_investigator.evaluation.analyst.materializer import (
    AnalystScenarioMaterializer,
)
from tests.support.evaluation_fixtures import unit_scenario


class MemoryInvestigationRepository:
    """Records investigation creations for materialization tests."""

    def __init__(self) -> None:
        """Initialize the created-state list."""
        self.created: list[InvestigationState] = []

    async def create(
        self,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> object:
        """Record the created state."""
        self.created.append(state)
        return None


class MemoryEntityRepository:
    """Records entity upserts, optionally substituting a repository-confirmed ID."""

    def __init__(
        self, *, id_override: UUID | None = None, drop_id: bool = False
    ) -> None:
        """Initialize the persisted list and optional ID substitution."""
        self.persisted: list[Entity] = []
        self.id_override = id_override
        self.drop_id = drop_id

    async def upsert(self, entity: Entity, **_: object) -> Entity:
        """Record and return the entity, optionally with a substituted ID."""
        self.persisted.append(entity)
        if self.drop_id:
            return entity.model_copy(update={"id": None})
        if self.id_override is not None:
            return entity.model_copy(update={"id": self.id_override})
        return entity


class MemoryEvidenceRepository:
    """Records evidence inserts, optionally substituting a repository ID."""

    def __init__(
        self, *, id_override: UUID | None = None, drop_id: bool = False
    ) -> None:
        """Initialize the persisted list and optional ID substitution."""
        self.persisted: list[Evidence] = []
        self.id_override = id_override
        self.drop_id = drop_id

    async def insert(self, evidence: Evidence, **_: object) -> Evidence:
        """Record and return the evidence, optionally with a substituted ID."""
        self.persisted.append(evidence)
        if self.drop_id:
            return evidence.model_copy(update={"id": None})
        if self.id_override is not None:
            return evidence.model_copy(update={"id": self.id_override})
        return evidence


class MemoryRelationshipRepository:
    """Records relationship upserts, optionally substituting a repository ID."""

    def __init__(
        self, *, id_override: UUID | None = None, drop_id: bool = False
    ) -> None:
        """Initialize the persisted list and optional ID substitution."""
        self.persisted: list[Relationship] = []
        self.id_override = id_override
        self.drop_id = drop_id

    async def upsert(self, relationship: Relationship, **_: object) -> Relationship:
        """Record and return the relationship, optionally with a substituted ID."""
        self.persisted.append(relationship)
        if self.drop_id:
            return relationship.model_copy(update={"id": None})
        if self.id_override is not None:
            return relationship.model_copy(update={"id": self.id_override})
        return relationship


class MemoryObservationRepository:
    """Records observation appends, optionally substituting a repository ID."""

    def __init__(
        self, *, id_override: UUID | None = None, drop_id: bool = False
    ) -> None:
        """Initialize the persisted list and optional ID substitution."""
        self.persisted: list[RelationshipObservation] = []
        self.id_override = id_override
        self.drop_id = drop_id

    async def append(
        self, observation: RelationshipObservation, **_: object
    ) -> RelationshipObservation:
        """Record and return the observation, optionally with a substituted ID."""
        self.persisted.append(observation)
        if self.drop_id:
            return observation.model_copy(update={"id": None})
        if self.id_override is not None:
            return observation.model_copy(update={"id": self.id_override})
        return observation


class MemoryUnitOfWork:
    """In-memory UnitOfWork recording every row the materializer persists.

    The class intentionally does not subclass the ``UnitOfWork`` ABC: it only
    needs the recording repository attributes the materializer touches, and
    tests pass it through :func:`cast` at the materializer boundary.

    Optional per-repository ``id_override`` values simulate the database
    redirecting a canonical identity (entity/relationship uniqueness) so
    tests can prove the materializer records repository-confirmed IDs only.
    """

    def __init__(
        self,
        *,
        entity_override: UUID | None = None,
        evidence_override: UUID | None = None,
        relationship_override: UUID | None = None,
        observation_override: UUID | None = None,
        entity_drop_id: bool = False,
        evidence_drop_id: bool = False,
        relationship_drop_id: bool = False,
        observation_drop_id: bool = False,
    ) -> None:
        """Bind the recording repositories with optional ID substitutions."""
        self.investigations = MemoryInvestigationRepository()
        self.entities = MemoryEntityRepository(
            id_override=entity_override, drop_id=entity_drop_id
        )
        self.evidence = MemoryEvidenceRepository(
            id_override=evidence_override, drop_id=evidence_drop_id
        )
        self.relationships = MemoryRelationshipRepository(
            id_override=relationship_override, drop_id=relationship_drop_id
        )
        self.relationship_observations = MemoryObservationRepository(
            id_override=observation_override, drop_id=observation_drop_id
        )


@pytest.mark.asyncio
async def test_materialize_persists_fixture_graph_in_order() -> None:
    """The fixture persists Investigation, entities, evidence, and graph rows."""
    scenario = unit_scenario()
    uow = MemoryUnitOfWork()
    resolution = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, uow), scenario
    )

    assert len(uow.investigations.created) == 1
    [state] = uow.investigations.created
    assert state.objective == scenario.fixture.objective
    assert state.root_entity_ids == [resolution.entity_ids["target_ip"]]

    assert [entity.value for entity in uow.entities.persisted] == [
        "203.0.113.42",
        "unit_malware",
    ]
    assert [entity.id for entity in uow.entities.persisted] == [
        resolution.entity_ids[entity.label] for entity in scenario.fixture.entities
    ]

    assert len(uow.evidence.persisted) == 2
    for evidence in uow.evidence.persisted:
        assert evidence.investigation_id == state.investigation_id
        assert isinstance(evidence.subject, EntityRef)

    assert len(uow.relationships.persisted) == 1
    assert len(uow.relationship_observations.persisted) == 1
    [observation] = uow.relationship_observations.persisted
    assert observation.investigation_id == state.investigation_id


@pytest.mark.asyncio
async def test_materialize_resolution_covers_fixture_labels() -> None:
    """Every fixture label resolves through the returned resolution."""
    scenario = unit_scenario()
    uow = MemoryUnitOfWork()
    resolution = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, uow), scenario
    )

    fixture_labels = (
        {item.label for item in scenario.fixture.entities}
        | {item.label for item in scenario.fixture.evidence}
        | {item.label for item in scenario.fixture.relationships}
        | {item.label for item in scenario.fixture.observations}
    )
    resolved = (
        set(resolution.entity_ids)
        | set(resolution.evidence_ids)
        | set(resolution.relationship_ids)
        | set(resolution.relationship_observation_ids)
    )
    assert resolved == fixture_labels


@pytest.mark.asyncio
async def test_materialize_is_deterministic_across_runs() -> None:
    """The same scenario materializes to exactly the same identities twice."""
    scenario = unit_scenario()
    first = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, MemoryUnitOfWork()), scenario
    )
    second = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, MemoryUnitOfWork()), scenario
    )
    assert first == second


@pytest.mark.asyncio
async def test_materialize_version_isolates_identities() -> None:
    """Bumping the scenario version changes every derived identity."""
    scenario = unit_scenario()
    bumped = scenario.model_copy(update={"version": 2})
    first = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, MemoryUnitOfWork()), scenario
    )
    second = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, MemoryUnitOfWork()), bumped
    )
    assert first.entity_ids != second.entity_ids
    assert first.evidence_ids != second.evidence_ids
    assert first.relationship_observation_ids != second.relationship_observation_ids


@pytest.mark.asyncio
async def test_materialize_evidence_subjects_resolve() -> None:
    """Evidence subject refs point at the persisted entity identities."""
    scenario = unit_scenario()
    uow = MemoryUnitOfWork()
    resolution = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, uow), scenario
    )
    for evidence in uow.evidence.persisted:
        subject = evidence.subject
        assert isinstance(subject, EntityRef)
        assert subject.id in resolution.entity_ids.values()

    # The observation backs a persisted relationship and evidence row.
    [observation] = uow.relationship_observations.persisted
    assert observation.relationship_id in resolution.relationship_ids.values()
    assert observation.evidence_id in resolution.evidence_ids.values()


@pytest.mark.asyncio
async def test_materialize_uses_fixture_objective_and_budget() -> None:
    """The investigation state comes verbatim from the fixture defaults."""
    scenario = unit_scenario()
    uow = MemoryUnitOfWork()
    await AnalystScenarioMaterializer().materialize(cast(UnitOfWork, uow), scenario)
    [state] = uow.investigations.created
    assert state.objective == scenario.fixture.objective
    assert state.budget.max_llm_calls >= 1
    assert len(state.root_entity_ids) == 1


@pytest.mark.parametrize(
    ("drop_flag", "expected_kind"),
    [
        ("entity_drop_id", "entity"),
        ("evidence_drop_id", "evidence"),
        ("relationship_drop_id", "relationship"),
        ("observation_drop_id", "relationship_observation"),
    ],
)
@pytest.mark.asyncio
async def test_materialize_fails_closed_when_repository_returns_no_id(
    drop_flag: str, expected_kind: str
) -> None:
    """A repository returning id=None must fail materialization, never invent one."""
    scenario = unit_scenario()
    if drop_flag == "entity_drop_id":
        uow = MemoryUnitOfWork(entity_drop_id=True)
    elif drop_flag == "evidence_drop_id":
        uow = MemoryUnitOfWork(evidence_drop_id=True)
    elif drop_flag == "relationship_drop_id":
        uow = MemoryUnitOfWork(relationship_drop_id=True)
    else:
        uow = MemoryUnitOfWork(observation_drop_id=True)
    with pytest.raises(ValueError, match=f"persisted {expected_kind} id"):
        await AnalystScenarioMaterializer().materialize(cast(UnitOfWork, uow), scenario)


@pytest.mark.asyncio
async def test_repository_redirected_entity_id_is_authoritative() -> None:
    """A canonical redirect returns an ID that drives the whole resolution."""
    scenario = unit_scenario()
    redirected = UUID("11111111-2222-3333-4444-555555555555")
    uow = MemoryUnitOfWork(entity_override=redirected)
    resolution = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, uow), scenario
    )

    # The resolution records the repository-confirmed ID, not the planned one.
    target_ip_id = resolution.entity_ids["target_ip"]
    assert target_ip_id == redirected

    # The Investigation root pointer and every Evidence subject ref use it.
    [state] = uow.investigations.created
    assert state.root_entity_ids == [redirected]
    for evidence in uow.evidence.persisted:
        assert isinstance(evidence.subject, EntityRef)
        if evidence.subject.value == "203.0.113.42":
            assert evidence.subject.id == redirected


@pytest.mark.asyncio
async def test_repository_redirected_relationship_id_is_authoritative() -> None:
    """A relationship redirect propagates into its observation link."""
    scenario = unit_scenario()
    redirected = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    uow = MemoryUnitOfWork(relationship_override=redirected)
    resolution = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, uow), scenario
    )

    assert resolution.relationship_ids["unit_relationship"] == redirected
    [observation] = uow.relationship_observations.persisted
    assert observation.relationship_id == redirected


@pytest.mark.asyncio
async def test_repository_redirected_observation_id_is_authoritative() -> None:
    """An observation redirect lands in the resolution."""
    scenario = unit_scenario()
    redirected = UUID("12121212-3434-5656-7878-909090909090")
    uow = MemoryUnitOfWork(observation_override=redirected)
    resolution = await AnalystScenarioMaterializer().materialize(
        cast(UnitOfWork, uow), scenario
    )

    assert resolution.relationship_observation_ids["obs_one"] == redirected


@pytest.mark.asyncio
async def test_materialize_fails_closed_on_non_uuid_repository_id() -> None:
    """A repository returning a non-UUID identity fails closed deterministically."""
    scenario = unit_scenario()
    uow = MemoryUnitOfWork(
        entity_drop_id=False,
        evidence_drop_id=False,
        relationship_drop_id=False,
        observation_drop_id=False,
    )

    # Simulate a misbehaving repository returning a non-UUID identity.
    async def bad_upsert(entity: Entity, **_: object) -> Entity:
        return entity.model_copy(update={"id": "not-a-uuid"})

    uow.entities.upsert = bad_upsert  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="non-UUID persisted entity id"):
        await AnalystScenarioMaterializer().materialize(cast(UnitOfWork, uow), scenario)
