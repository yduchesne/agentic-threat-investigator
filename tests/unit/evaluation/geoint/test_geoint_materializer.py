# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic GEOINT fixture materialization.

An in-memory UnitOfWork records every persisted row so the materializer's
ordering, identity derivation, cross-Investigation scoping, and resolution
coverage can be asserted without any database.
"""

from __future__ import annotations

from collections.abc import Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TypeVar, cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.geoint import (
    EntityLocationObservation,
    GeoResolution,
    Location,
    LocationPrecision,
    LocationType,
)
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.evaluation.geoint.materializer import (
    GeointScenarioMaterializer,
    other_investigation_id,
    scenario_investigation_id,
)
from agentic_threat_investigator.evaluation.geoint.models import (
    GeointGeographicState,
    GeointResolutionState,
    GeointScenario,
)
from tests.support.geoint_evaluation import unit_geoint_scenario

_FIXED = datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC)


class MemoryLocationRepository:
    """Records reference upserts and resolves parent labels."""

    def __init__(self) -> None:
        """Initialize the persisted location list."""
        self.persisted: list[Location] = []

    async def upsert_reference(self, location: Location) -> object:
        """Record and return the location with its planned identity."""
        self.persisted.append(location)
        return LocationWriteResultStub(location)


@dataclass
class LocationWriteResultStub:
    """Minimal LocationWriteResult shape for the materializer."""

    location: Location


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


class MemoryInvestigationRepository:
    """Records investigation creations."""

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


class MemoryEvidenceRepository:
    """Records evidence inserts, optionally substituting a repository ID."""

    def __init__(self) -> None:
        """Initialize the persisted list."""
        self.persisted: list[Evidence] = []

    async def insert(self, evidence: Evidence) -> Evidence:
        """Record and return the evidence."""
        self.persisted.append(evidence)
        return evidence

    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        """Return one persisted evidence row by identity."""
        return next((item for item in self.persisted if item.id == evidence_id), None)


class MemoryGeoResolutionRepository:
    """Records pending resolution creations."""

    def __init__(self) -> None:
        """Initialize the persisted list."""
        self.persisted: list[GeoResolution] = []

    async def create_pending(self, resolution: GeoResolution) -> GeoResolution:
        """Record and return the pending work."""
        self.persisted.append(resolution)
        return resolution


class MemoryObservationRepository:
    """Serves scripted persisted observations."""

    def __init__(self) -> None:
        """Initialize the scripted rows."""
        self.rows: dict[UUID, list[EntityLocationObservation]] = {}

    def seed(self, entity_id: UUID, rows: list[EntityLocationObservation]) -> None:
        """Bind one Entity to its observation rows."""
        self.rows[entity_id] = rows

    async def list_for_entity(
        self, entity_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[EntityLocationObservation]:
        """Return the scripted rows for one Entity."""
        return self.rows.get(entity_id, [])[:limit]


class MemoryUnitOfWork:
    """In-memory UnitOfWork satisfying the materializer's narrow seam."""

    def __init__(self) -> None:
        """Initialize every memory repository."""
        self.locations = MemoryLocationRepository()
        self.entities = MemoryEntityRepository()
        self.investigations = MemoryInvestigationRepository()
        self.evidence = MemoryEvidenceRepository()
        self.geo_resolutions = MemoryGeoResolutionRepository()
        self.entity_location_observations = MemoryObservationRepository()
        self.entity_locations = None  # unused by the materializer state builder


def _observation(
    *,
    observation_id: UUID,
    entity_id: UUID,
    location_id: UUID,
    evidence_id: UUID,
    precision: LocationPrecision = LocationPrecision.CITY,
    retrieved_at: datetime = _FIXED,
) -> EntityLocationObservation:
    """Build one persisted observation row shape."""
    return EntityLocationObservation(
        id=observation_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
        precision=precision,
        observed_at=retrieved_at,
        retrieved_at=retrieved_at,
        resolved_at=retrieved_at,
        resolution_method="canonical_geography_v1",
    )


def _as_uow(memory: MemoryUnitOfWork) -> UnitOfWork:
    """Cast the memory UoW to the repository protocol."""
    return cast(UnitOfWork, memory)


def test_materialize_persists_in_deterministic_order() -> None:
    """Geography, entities, investigation, evidence, then pending work."""
    scenario = unit_geoint_scenario()
    memory = MemoryUnitOfWork()
    materializer = GeointScenarioMaterializer()
    resolution = asyncio_run(materializer.materialize(_as_uow(memory), scenario))

    assert [item.label for item in scenario.fixture.geography] == [
        "us",
        "washington",
        "seattle",
    ]
    assert len(memory.locations.persisted) == 3
    assert [entity.value for entity in memory.entities.persisted] == ["203.0.113.42"]
    assert len(memory.investigations.created) == 1
    assert memory.investigations.created[
        0
    ].investigation_id == scenario_investigation_id(scenario)
    assert len(memory.evidence.persisted) == 1
    assert memory.evidence.persisted[0].investigation_id == scenario_investigation_id(
        scenario
    )
    assert len(memory.geo_resolutions.persisted) == 1
    pending = memory.geo_resolutions.persisted[0]
    assert pending.id == resolution.resolution_ids["seattle_obs"]
    assert pending.entity_id == resolution.entity_ids["target_ip"]
    assert pending.evidence_id == resolution.evidence_ids["seattle_evidence"]
    assert resolution.investigation_id == scenario_investigation_id(scenario)
    assert resolution.other_investigation_id is None


def test_materialize_identities_are_stable_uuid5() -> None:
    """The same scenario always derives the same persisted identities."""
    scenario = unit_geoint_scenario()
    first = asyncio_run(
        GeointScenarioMaterializer().materialize(_as_uow(MemoryUnitOfWork()), scenario)
    )
    second = asyncio_run(
        GeointScenarioMaterializer().materialize(_as_uow(MemoryUnitOfWork()), scenario)
    )
    assert first == second
    assert first.geography_ids["seattle"] == second.geography_ids["seattle"]


def _with_dallas_geography(scenario: GeointScenario) -> GeointScenario:
    """Return the scenario with Texas/Dallas reference geography added."""
    from agentic_threat_investigator.evaluation.geoint.models import (
        GeointFixtureLocation,
    )

    texas = GeointFixtureLocation(
        label="texas",
        location_type=LocationType.ADMINISTRATIVE_AREA,
        name="Texas",
        country_code="US",
        admin1_code="TX",
        parent="us",
        geometry=(
            "SRID=4326;POLYGON((-106.6 25.8,-93.5 25.8,-93.5 36.5,"
            "-106.6 36.5,-106.6 25.8))"
        ),
    )
    dallas = GeointFixtureLocation(
        label="dallas",
        location_type=LocationType.CITY,
        name="Dallas",
        country_code="US",
        admin1_code="TX",
        parent="texas",
        geometry="SRID=4326;POINT(-96.7969 32.7767)",
    )
    fixture = scenario.fixture.model_copy(
        update={"geography": scenario.fixture.geography + (texas, dallas)}
    )
    return scenario.model_copy(update={"fixture": fixture})


def test_cross_investigation_evidence_attaches_to_other_investigation() -> None:
    """Flagged evidence rows attach to the deterministic second Investigation."""
    scenario = _with_dallas_geography(unit_geoint_scenario())
    dallas_evidence = scenario.fixture.evidence[0].model_copy(
        update={
            "label": "dallas_evidence",
            "facts": {
                "country_code": "US",
                "region": "Texas",
                "city": "Dallas",
                "precision": "city",
            },
            "other_investigation": True,
        }
    )
    dallas_resolution = scenario.fixture.resolutions[0].model_copy(
        update={"label": "dallas_obs", "evidence": "dallas_evidence"}
    )
    fixture = scenario.fixture.model_copy(
        update={
            "evidence": (scenario.fixture.evidence[0], dallas_evidence),
            "resolutions": (scenario.fixture.resolutions[0], dallas_resolution),
        }
    )
    scenario = scenario.model_copy(update={"fixture": fixture})
    memory = MemoryUnitOfWork()
    resolution = asyncio_run(
        GeointScenarioMaterializer().materialize(_as_uow(memory), scenario)
    )
    assert resolution.other_investigation_id == other_investigation_id(scenario)
    assert len(memory.investigations.created) == 2
    scopes = {
        evidence.id: evidence.investigation_id for evidence in memory.evidence.persisted
    }
    assert (
        scopes[resolution.evidence_ids["seattle_evidence"]]
        == resolution.investigation_id
    )
    assert (
        scopes[resolution.evidence_ids["dallas_evidence"]]
        == resolution.other_investigation_id
    )


def test_read_observations_records_resolved_observations() -> None:
    """The resolution is completed with the exact persisted observation ids."""
    scenario = unit_geoint_scenario()
    memory = MemoryUnitOfWork()
    materializer = GeointScenarioMaterializer()
    resolution = asyncio_run(materializer.materialize(_as_uow(memory), scenario))
    observation_id = uuid4()
    memory.entity_location_observations.seed(
        resolution.entity_ids["target_ip"],
        [
            _observation(
                observation_id=observation_id,
                entity_id=resolution.entity_ids["target_ip"],
                location_id=resolution.geography_ids["seattle"],
                evidence_id=resolution.evidence_ids["seattle_evidence"],
            )
        ],
    )
    completed = asyncio_run(
        materializer.read_observations(_as_uow(memory), scenario, resolution)
    )
    assert completed.observation_ids["seattle_obs"] == observation_id


def test_build_geographic_state_scopes_to_investigation() -> None:
    """Other-Investigation observations never enter the state."""
    scenario = _with_dallas_geography(unit_geoint_scenario())
    dallas_evidence = scenario.fixture.evidence[0].model_copy(
        update={
            "label": "dallas_evidence",
            "facts": {
                "country_code": "US",
                "region": "Texas",
                "city": "Dallas",
                "precision": "city",
            },
            "other_investigation": True,
        }
    )
    dallas_resolution = scenario.fixture.resolutions[0].model_copy(
        update={"label": "dallas_obs", "evidence": "dallas_evidence"}
    )
    fixture = scenario.fixture.model_copy(
        update={
            "evidence": (scenario.fixture.evidence[0], dallas_evidence),
            "resolutions": (scenario.fixture.resolutions[0], dallas_resolution),
        }
    )
    scenario = scenario.model_copy(update={"fixture": fixture})
    memory = MemoryUnitOfWork()
    materializer = GeointScenarioMaterializer()
    resolution = asyncio_run(materializer.materialize(_as_uow(memory), scenario))
    seattle_obs = uuid4()
    dallas_obs = uuid4()
    # The worker completed both, but the Dallas Evidence belongs to I2.
    memory.entity_location_observations.seed(
        resolution.entity_ids["target_ip"],
        [
            _observation(
                observation_id=seattle_obs,
                entity_id=resolution.entity_ids["target_ip"],
                location_id=resolution.geography_ids["seattle"],
                evidence_id=resolution.evidence_ids["seattle_evidence"],
            ),
            _observation(
                observation_id=dallas_obs,
                entity_id=resolution.entity_ids["target_ip"],
                location_id=resolution.geography_ids["dallas"],
                evidence_id=resolution.evidence_ids["dallas_evidence"],
            ),
        ],
    )
    state = asyncio_run(
        materializer.build_geographic_state(_as_uow(memory), scenario, resolution)
    )
    assert isinstance(state, GeointGeographicState)
    # Only the I1-scoped observation is visible; the current stays Seattle.
    assert [item.observation_id for item in state.observations] == [seattle_obs]
    assert len(state.current) == 1
    assert state.current[0].location_id == resolution.geography_ids["seattle"]
    # Both work items completed though.
    by_label = {item.label: item for item in state.resolutions}
    assert by_label["dallas_obs"].status == "resolved"


def test_build_geographic_state_unresolved_reports_unresolvable() -> None:
    """Unresolved work reports the terminal unresolvable status."""
    scenario = unit_geoint_scenario()
    memory = MemoryUnitOfWork()
    materializer = GeointScenarioMaterializer()
    resolution = asyncio_run(materializer.materialize(_as_uow(memory), scenario))
    state = asyncio_run(
        materializer.build_geographic_state(_as_uow(memory), scenario, resolution)
    )
    assert isinstance(state, GeointGeographicState)
    [resolution_state] = state.resolutions
    assert isinstance(resolution_state, GeointResolutionState)
    assert resolution_state.status == "unresolvable"
    assert resolution_state.observation_id is None


def test_repository_without_persisted_id_fails_closed() -> None:
    """A repository returning id=None must never invent a persisted identity."""
    scenario = unit_geoint_scenario()
    memory = MemoryUnitOfWork()
    memory.entities = MemoryEntityRepository(drop_id=True)
    with pytest.raises(ValueError):
        asyncio_run(GeointScenarioMaterializer().materialize(_as_uow(memory), scenario))


T = TypeVar("T")


def asyncio_run(coroutine: Coroutine[object, object, T]) -> T:
    """Run one async materializer call synchronously in tests."""
    import asyncio

    return asyncio.run(coroutine)
