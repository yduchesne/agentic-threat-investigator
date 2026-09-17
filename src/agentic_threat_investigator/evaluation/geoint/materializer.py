# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic fixture materialization for GEOINT scenarios (PR 26G).

The materializer persists one :class:`GeointScenario` fixture through the
application ``UnitOfWork`` seam -- reference geography, Investigation,
Entities, GEOLOCATION LegacyEvidence, and PENDING ``GeoResolution`` work -- and
returns the :class:`GeointScenarioResolution` that maps every semantic
label to the exact persisted UUID. It is storage-agnostic (any
``UnitOfWork`` implementation works) and deterministic: stable UUID
namespaces derived from the scenario id/version mean the same scenario
always materializes to the same identities.

Derived geographic truth (``EntityLocationObservation``/``EntityLocation``)
is **never** inserted by this module. The caller runs the production
``GeoResolutionWorker`` with a real resolver after materialization, then
uses :meth:`read_observations` / :meth:`build_geographic_state` to read the
authoritative results back through the normal repositories. Persisted
identities are always taken from the repository return values.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid5

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.query.geoint import effective_observation_time
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    EvidenceObservationCandidate,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.domain.evidence import (
    Evidence as StableEvidence,
)
from agentic_threat_investigator.domain.geoint import (
    GeoResolution,
    Location,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.evaluation.geoint.models import (
    GeointCurrentState,
    GeointFixture,
    GeointFixtureEntity,
    GeointFixtureLocation,
    GeointGeographicState,
    GeointResolutionState,
    GeointScenario,
    GeointScenarioResolution,
    PersistedGeointObservation,
)

_FIXED_TIMESTAMP = datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC)
"""Fixed UTC timestamp used for persisted rows that declare none."""

DEFAULT_GEOINT_SCENARIO_NAMESPACE = uuid5(
    UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8"), "urn:ati:evaluation:geoint:v1"
)
"""Stable namespace for scenario-derived GEOINT fixture identities."""


def scenario_investigation_id(
    scenario: GeointScenario, *, namespace: UUID = DEFAULT_GEOINT_SCENARIO_NAMESPACE
) -> UUID:
    """Return the deterministic Investigation identity a scenario materializes.

    Callers that run the GEOINT pipeline against the materialized fixture use
    this same derivation instead of re-deriving URNs.
    """
    return uuid5(
        namespace,
        f"urn:ati:scenario:{scenario.id}:v{scenario.version}:investigation:root",
    )


def other_investigation_id(
    scenario: GeointScenario, *, namespace: UUID = DEFAULT_GEOINT_SCENARIO_NAMESPACE
) -> UUID:
    """Return the deterministic second Investigation identity (isolation cases).

    Only scenarios that declare a second Investigation use this identity;
    cross-Investigation fixtures attach the out-of-scope rows to it.
    """
    return uuid5(
        namespace,
        f"urn:ati:scenario:{scenario.id}:v{scenario.version}:investigation:other",
    )


class GeointScenarioMaterializer:
    """Persist one scenario fixture and resolve its labels to UUIDs.

    ``namespace`` defaults to the stable ATI evaluation namespace; callers
    only override it when they must isolate identities (for example when two
    fixture copies share one database within a test).
    """

    def __init__(self, *, namespace: UUID = DEFAULT_GEOINT_SCENARIO_NAMESPACE) -> None:
        """Bind the identity namespace used for stable fixture UUIDs."""
        self._namespace = namespace

    async def materialize(
        self, uow: UnitOfWork, scenario: GeointScenario
    ) -> GeointScenarioResolution:
        """Persist the fixture graph and return the label resolution.

        Persistence order is deterministic: reference geography (parents
        first, declaration order), Entities, the Investigation, LegacyEvidence,
        then PENDING GeoResolution work. Every id recorded in the resolution
        is the identity the repository actually persisted.
        """
        fixture = scenario.fixture

        geography_ids: dict[str, UUID] = {}
        for location in fixture.geography:
            persisted = await uow.locations.upsert_reference(
                self._domain_location(fixture, location)
            )
            persisted_id = persisted.location.id
            if persisted_id is None:
                raise ValueError(
                    f"repository did not return a persisted geography id for "
                    f"label {location.label!r}"
                )
            geography_ids[location.label] = persisted_id

        entity_ids: dict[str, UUID] = {}
        for entity in fixture.entities:
            persisted_entity = await uow.entities.upsert(
                Entity(
                    id=self._planned(scenario, "entity", entity.label),
                    type=entity.type,
                    value=entity.value,
                )
            )
            entity_ids[entity.label] = _persisted_id(
                persisted_entity, "entity", entity.label
            )

        investigation_id = scenario_investigation_id(
            scenario, namespace=self._namespace
        )
        other_id = None
        if any(evidence.other_investigation for evidence in fixture.evidence):
            other_id = other_investigation_id(scenario, namespace=self._namespace)
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[entity_ids[fixture.root_entity]],
                objective=fixture.objective,
                budget=default_investigation_budget(),
                started_at=_FIXED_TIMESTAMP,
            )
        )
        if other_id is not None:
            await uow.investigations.create(
                InvestigationState(
                    investigation_id=other_id,
                    status=InvestigationStatus.RUNNING,
                    trigger_type=InvestigationTriggerType.MANUAL,
                    root_entity_ids=[entity_ids[fixture.root_entity]],
                    objective=fixture.objective,
                    budget=default_investigation_budget(),
                    started_at=_FIXED_TIMESTAMP,
                )
            )

        evidence_ids: dict[str, UUID] = {}
        for evidence in fixture.evidence:
            if evidence.other_investigation:
                if other_id is None:  # pragma: no cover
                    raise ValueError(
                        "fixture evidence declares another Investigation but "
                        "none was created"
                    )
                scope_id = other_id
            else:
                scope_id = investigation_id
            _ = _entity_by_label(fixture, evidence.subject)
            planned_evidence = self._planned(scenario, "evidence", evidence.label)
            persisted_evidence = await uow.evidence.persist(
                ConvertedEvidence(
                    evidence=StableEvidence(
                        id=planned_evidence,
                        type=evidence.type,
                        source=evidence.source,
                        source_record_id=f"scenario:{scenario.id}:{evidence.label}",
                    ),
                    observation=EvidenceObservationCandidate(
                        evidence_id=planned_evidence,
                        observed_at=evidence.observed_at,
                        retrieved_at=evidence.retrieved_at or _FIXED_TIMESTAMP,
                        facts=dict(evidence.facts),
                    ),
                ),
                observation_id=self._planned(
                    scenario, "evidence_observation", evidence.label
                ),
            )
            await uow.evidence_observation_entities.associate(
                persisted_evidence.observation.id, entity_ids[evidence.subject]
            )
            await uow.investigation_evidence.admit(
                InvestigationEvidence(
                    investigation_id=scope_id,
                    evidence_observation_id=persisted_evidence.observation.id,
                    inclusion_reason=InvestigationEvidenceReason.INITIAL,
                    added_at=persisted_evidence.observation.retrieved_at,
                    added_by=InvestigationEvidenceActor.SYSTEM,
                )
            )
            evidence_ids[evidence.label] = _persisted_id(
                persisted_evidence.observation, "evidence_observation", evidence.label
            )

        resolution_ids: dict[str, UUID] = {}
        for resolution in fixture.resolutions:
            resolution_id = self._planned(scenario, "resolution", resolution.label)
            await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=resolution_id,
                    entity_id=entity_ids[resolution.entity],
                    evidence_observation_id=evidence_ids[resolution.evidence],
                )
            )
            resolution_ids[resolution.label] = resolution_id

        return GeointScenarioResolution(
            investigation_id=investigation_id,
            geography_ids=geography_ids,
            entity_ids=entity_ids,
            evidence_ids=evidence_ids,
            resolution_ids=resolution_ids,
            other_investigation_id=other_id,
        )

    async def read_observations(
        self,
        uow: UnitOfWork,
        scenario: GeointScenario,
        resolution: GeointScenarioResolution,
    ) -> GeointScenarioResolution:
        """Complete the resolution with persisted observation identities.

        For every fixture resolution the exact observation produced by the
        production worker completion (matching the resolution's Entity and
        LegacyEvidence) is recorded under the resolution label. An unresolved
        resolution records no observation.
        """
        observation_ids: dict[str, UUID] = {}
        for fixture_resolution in scenario.fixture.resolutions:
            entity_id = resolution.entity_ids[fixture_resolution.entity]
            evidence_id = resolution.evidence_ids[fixture_resolution.evidence]
            rows = await uow.entity_location_observations.list_for_entity(
                entity_id, limit=100
            )
            matched = [
                row for row in rows if row.evidence_observation_id == evidence_id
            ]
            if matched:
                observation_ids[fixture_resolution.label] = matched[0].id
        return resolution.model_copy(update={"observation_ids": observation_ids})

    async def build_geographic_state(
        self,
        uow: UnitOfWork,
        scenario: GeointScenario,
        resolution: GeointScenarioResolution,
    ) -> GeointGeographicState:
        """Build the authoritative persisted geographic state of the scenario.

        The state is read through the normal repositories after the
        production worker completed; the evaluator never reads a database
        itself. ``observations`` and the Investigation-relative current are
        scoped to the scenario Investigation exactly like the PR 26D query
        layer: rows whose LegacyEvidence belongs to the deterministic second
        Investigation (isolation scenarios) never enter the state, so the
        evaluator independently proves "I1 never sees I2 support/global
        current".
        """
        evidence_scopes = await self._evidence_scopes(uow, resolution)
        observations: list[PersistedGeointObservation] = []
        resolution_states: list[GeointResolutionState] = []
        for fixture_resolution in scenario.fixture.resolutions:
            entity_id = resolution.entity_ids[fixture_resolution.entity]
            evidence_id = resolution.evidence_ids[fixture_resolution.evidence]
            rows = await uow.entity_location_observations.list_for_entity(
                entity_id, limit=100
            )
            matched = [
                row for row in rows if row.evidence_observation_id == evidence_id
            ]
            if matched:
                row = matched[0]
                resolution_states.append(
                    GeointResolutionState(
                        label=fixture_resolution.label,
                        status="resolved",
                        observation_id=row.id,
                        location_id=row.location_id,
                        precision=row.precision,
                    )
                )
                if evidence_scopes.get(evidence_id) == resolution.investigation_id:
                    observations.append(
                        PersistedGeointObservation(
                            observation_id=row.id,
                            entity_id=row.entity_id,
                            location_id=row.location_id,
                            evidence_id=row.evidence_observation_id,
                            precision=row.precision,
                            observed_at=row.observed_at,
                            retrieved_at=row.retrieved_at,
                        )
                    )
            else:
                resolution_states.append(
                    GeointResolutionState(
                        label=fixture_resolution.label, status="unresolvable"
                    )
                )
        current_states = self._scoped_current(observations)
        return GeointGeographicState(
            observations=tuple(observations),
            current=tuple(current_states),
            resolutions=tuple(resolution_states),
        )

    @staticmethod
    async def _evidence_scopes(
        uow: UnitOfWork, resolution: GeointScenarioResolution
    ) -> dict[UUID, UUID]:
        """Return the Investigation of every scenario observation.

        The authoritative scope is read from the exact InvestigationEvidence
        admissions; cross-Investigation fixtures attach some observations to
        the deterministic second Investigation.
        """
        scopes: dict[UUID, UUID] = {}
        for observation_id in resolution.evidence_ids.values():
            for admission in await uow.investigation_evidence.list_for_investigation(
                resolution.investigation_id
            ):
                if admission.evidence_observation_id == observation_id:
                    scopes[observation_id] = resolution.investigation_id
            if (
                resolution.other_investigation_id is not None
                and observation_id not in scopes
            ):
                for (
                    admission
                ) in await uow.investigation_evidence.list_for_investigation(
                    resolution.other_investigation_id
                ):
                    if admission.evidence_observation_id == observation_id:
                        scopes[observation_id] = resolution.other_investigation_id
        return scopes

    @staticmethod
    def _scoped_current(
        observations: list[PersistedGeointObservation],
    ) -> list[GeointCurrentState]:
        """Derive Investigation-relative current from scoped observations.

        The current observation per Entity is the one with the greatest
        ``(effective time, observation id)`` pair -- the exact PR 26A
        currentness ordering -- and the current state never consults the
        global ``EntityLocation`` table, so a newer observation in another
        Investigation can never leak into this state.
        """
        by_entity: dict[UUID, PersistedGeointObservation] = {}
        for observation in observations:
            current = by_entity.get(observation.entity_id)
            if current is None or _observation_newer(observation, current):
                by_entity[observation.entity_id] = observation
        return [
            GeointCurrentState(
                entity_id=observation.entity_id,
                location_id=observation.location_id,
                precision=observation.precision,
                latest_observation_id=observation.observation_id,
            )
            for observation in by_entity.values()
        ]

    def _domain_location(
        self,
        fixture: GeointFixture,
        location: GeointFixtureLocation,
    ) -> Location:
        """Map one fixture geography record onto the canonical Location DTO.

        Canonical reference identity is the deterministic production UUIDv5
        (``canonical_location_uuid``), never a scenario-derived namespace:
        the reference corpus is shared system truth, so the same canonical
        record keeps the same identity across every scenario and reuses the
        same row without version churn.
        """
        parent_id = None
        if location.parent is not None:
            parent = _location_by_label(fixture, location.parent)
            parent_id = _canonical_location_id(parent)
        return Location(
            id=_canonical_location_id(location),
            type=location.location_type,
            name=location.name,
            canonical_name=location.name,
            country_code=location.country_code,
            admin1_code=location.admin1_code,
            admin2_code=location.admin2_code,
            parent_location_id=parent_id,
            geometry=location.geometry,
            centroid=location.centroid,
        )

    def _planned(self, scenario: GeointScenario, kind: str, label: str) -> UUID:
        """Return the deterministic planned UUID for one fixture label and kind."""
        return uuid5(
            self._namespace,
            f"urn:ati:scenario:{scenario.id}:v{scenario.version}:{kind}:{label}",
        )


def _entity_by_label(fixture: GeointFixture, label: str) -> GeointFixtureEntity:
    """Return the declared fixture entity for one label."""
    for entity in fixture.entities:
        if entity.label == label:
            return entity
    # Scenario validation guarantees fixture evidence subjects name declared
    # entities, so this defensive guard is not reachable through validated
    # scenario data.
    raise ValueError(  # pragma: no cover
        f"fixture declares no entity with label {label!r}"
    )


def _location_by_label(fixture: GeointFixture, label: str) -> GeointFixtureLocation:
    """Return the declared fixture geography record for one label."""
    for location in fixture.geography:
        if location.label == label:
            return location
    raise ValueError(  # pragma: no cover
        f"fixture declares no geography with label {label!r}"
    )


def _canonical_location_id(location: GeointFixtureLocation) -> UUID:
    """Return the deterministic production canonical Location UUIDv5."""
    from agentic_threat_investigator.domain.geoint import canonical_location_uuid

    return canonical_location_uuid(
        location_type=location.location_type,
        country_code=location.country_code,
        admin1_code=location.admin1_code,
        admin2_code=location.admin2_code,
        canonical_name=location.name,
    )


def _persisted_id(persisted: object, kind: str, label: str) -> UUID:
    """Return the repository-confirmed persisted identity or fail closed.

    A repository returning ``id=None`` means the write did not produce a
    durable identity; substituting the planned UUID would invent a persisted
    identity that the database does not confirm.
    """
    persisted_id = getattr(persisted, "id", None)
    if persisted_id is None:
        raise ValueError(
            f"repository did not return a persisted {kind} id for label {label!r}"
        )
    if not isinstance(persisted_id, UUID):
        raise ValueError(
            f"repository returned a non-UUID persisted {kind} id for label {label!r}"
        )
    return persisted_id


def _observation_newer(
    candidate: PersistedGeointObservation, current: PersistedGeointObservation
) -> bool:
    """Return whether one observation wins the PR 26A currentness ordering.

    The greater ``(effective time, observation id)`` pair wins, exactly like
    the persisted reconcile path.
    """
    candidate_time = effective_observation_time(
        candidate.observed_at, candidate.retrieved_at
    )
    current_time = effective_observation_time(current.observed_at, current.retrieved_at)
    return (candidate_time, candidate.observation_id) > (
        current_time,
        current.observation_id,
    )
