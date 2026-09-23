# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic fixture materialization for analyst scenarios (PR 20C).

The materializer persists one :class:`AnalystScenario` fixture through the
application ``UnitOfWork`` seam — Investigation, Entities, LegacyEvidence,
Relationships, and RelationshipObservations — and returns the
:class:`AnalystScenarioResolution` that maps every semantic label to the
exact persisted UUID. It is storage-agnostic (any ``UnitOfWork``
implementation works) and deterministic: stable UUID namespaces derived from
the scenario id/version mean the same scenario always materializes to the
same identities.

The materializer is not a provider and performs no analysis; it simply
materializes scenario-truth into the same durable shapes the Evidence Analyst
execution path consumes. Persisted identities are always taken from the
repository return values: canonical entity/relationship uniqueness rules mean
the database, not a pre-planned UUID, is authoritative for what row actually
exists.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid5

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
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
)
from agentic_threat_investigator.evaluation.analyst.models import (
    AnalystScenario,
    AnalystScenarioResolution,
    FixtureEntity,
)

_FIXED_TIMESTAMP = datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC)
"""Fixed UTC timestamp used for persisted rows that declare none.

Keeps materialization reproducible: the same scenario always persists the
same retrieved/observed timestamps.
"""

DEFAULT_SCENARIO_NAMESPACE = uuid5(
    UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8"), "urn:ati:evaluation:analyst:v1"
)
"""Stable namespace for scenario-derived fixture identities."""


def scenario_investigation_id(
    scenario: AnalystScenario, *, namespace: UUID = DEFAULT_SCENARIO_NAMESPACE
) -> UUID:
    """Return the deterministic Investigation identity a scenario materializes.

    The materializer persists the fixture under this identity; callers that
    run the analyst against the materialized fixture (verification slices,
    runners) use this same derivation instead of re-deriving URNs.
    """
    return uuid5(
        namespace,
        f"urn:ati:scenario:{scenario.id}:v{scenario.version}:investigation:root",
    )


class MaterializedScenarioStateError(RuntimeError):
    """A scenario Investigation exists but its fixture is incomplete or foreign.

    PR 30C reuses an already-materialized scenario without destructive
    cleanup: when the deterministic scenario Investigation exists but one or
    more expected fixture rows are missing, the materializer fails closed
    instead of repairing or mutating the existing Investigation (repairing
    could cross-contaminate case data), and it never deletes authoritative or
    history records.
    """

    def __init__(self, message: str) -> None:
        """Record the bounded failure message."""
        super().__init__(f"scenario fixture state is not reusable: {message}")


class AnalystScenarioMaterializer:
    """Persist one scenario fixture and resolve its labels to UUIDs.

    ``namespace`` defaults to the stable ATI evaluation namespace; callers
    only override it when they must isolate identities (for example when two
    fixture copies share one database within a test).
    """

    def __init__(self, *, namespace: UUID = DEFAULT_SCENARIO_NAMESPACE) -> None:
        """Bind the identity namespace used for stable fixture UUIDs."""
        self._namespace = namespace

    def investigation_id(self, scenario: AnalystScenario) -> UUID:
        """Return the deterministic Investigation identity of one fixture.

        Callers that run the analyst against a materialized fixture (verification
        slices, PR 30C target execution) use this method so the identity always
        matches the namespace this materializer persists into.
        """
        return scenario_investigation_id(scenario, namespace=self._namespace)

    async def materialize_or_reuse(
        self, uow: UnitOfWork, scenario: AnalystScenario
    ) -> AnalystScenarioResolution:
        """Materialize the fixture or reuse an already-materialized one (PR 30C).

        Repeated runs of the same case are deterministic without destructive
        cleanup: when the scenario Investigation already exists, the fixture is
        reused as-is and the resolution is rebuilt from the planned deterministic
        identities after verifying every fixture row exists. A scenario
        Investigation that exists but is missing expected fixture rows fails
        closed with :class:`MaterializedScenarioStateError`; this method never
        repairs or mutates an existing Investigation and never deletes
        authoritative/history records.
        """
        if await uow.investigations.get_by_id(self.investigation_id(scenario)) is None:
            return await self.materialize(uow, scenario)
        return await self._reuse(uow, scenario)

    async def materialize(
        self, uow: UnitOfWork, scenario: AnalystScenario
    ) -> AnalystScenarioResolution:
        """Persist the fixture graph and return the label resolution.

        Persistence order is deterministic: entities (in declaration order),
        then Investigation, evidence, relationships, observations. Entities
        are persisted first so the Investigation root pointer and every
        LegacyEvidence subject reference the identities the repository actually
        returned. Every id recorded in the resolution is the identity the
        repository actually persisted, so label resolution always matches
        durable rows.
        """
        fixture = scenario.fixture

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

        evidence_ids: dict[str, UUID] = {}
        for evidence in fixture.evidence:
            persisted = await uow.evidence.persist(
                ConvertedEvidence(
                    evidence=Evidence(
                        id=self._planned(scenario, "evidence", evidence.label),
                        type=evidence.type,
                        source=evidence.source,
                        source_record_id=f"scenario:{scenario.id}:{evidence.label}",
                    ),
                    observation=EvidenceObservationCandidate(
                        evidence_id=self._planned(scenario, "evidence", evidence.label),
                        observed_at=evidence.observed_at,
                        retrieved_at=evidence.retrieved_at or _FIXED_TIMESTAMP,
                        facts=dict(evidence.facts),
                    ),
                ),
                observation_id=self._planned(
                    scenario, "evidence_observation", evidence.label
                ),
            )
            # The fixture subject is associated with the exact observation as
            # ordinary observation-level provenance (no privileged subject)
            # and the observation is exactly admitted to the scenario
            # Investigation.
            _ = _entity_by_label(fixture.entities, evidence.subject)
            await uow.evidence_observation_entities.associate(
                persisted.observation.id, entity_ids[evidence.subject]
            )
            await uow.investigation_evidence.admit(
                InvestigationEvidence(
                    investigation_id=investigation_id,
                    evidence_observation_id=persisted.observation.id,
                    inclusion_reason=InvestigationEvidenceReason.INITIAL,
                    added_at=persisted.observation.retrieved_at,
                    added_by=InvestigationEvidenceActor.SYSTEM,
                )
            )
            evidence_ids[evidence.label] = _persisted_id(
                persisted.observation, "evidence_observation", evidence.label
            )

        relationship_ids: dict[str, UUID] = {}
        for relationship in fixture.relationships:
            persisted_relationship = await uow.relationships.upsert(
                Relationship(
                    id=self._planned(scenario, "relationship", relationship.label),
                    source_entity_id=entity_ids[relationship.source],
                    target_entity_id=entity_ids[relationship.target],
                    type=relationship.type,
                )
            )
            relationship_ids[relationship.label] = _persisted_id(
                persisted_relationship, "relationship", relationship.label
            )

        observation_ids: dict[str, UUID] = {}
        for observation in fixture.observations:
            persisted_observation = await uow.relationship_observations.append(
                RelationshipObservation(
                    id=self._planned(scenario, "observation", observation.label),
                    relationship_id=relationship_ids[observation.relationship],
                    evidence_observation_id=evidence_ids[observation.evidence],
                    retrieved_at=_FIXED_TIMESTAMP,
                    source=observation.source,
                    confidence=observation.confidence,
                )
            )
            observation_ids[observation.label] = _persisted_id(
                persisted_observation, "relationship_observation", observation.label
            )

        return AnalystScenarioResolution(
            evidence_ids=evidence_ids,
            relationship_observation_ids=observation_ids,
            entity_ids=entity_ids,
            relationship_ids=relationship_ids,
        )

    async def _reuse(
        self, uow: UnitOfWork, scenario: AnalystScenario
    ) -> AnalystScenarioResolution:
        """Rebuild the resolution over the already-persisted fixture rows.

        Every planned identity is verified through the normal repository read
        seam; a missing row means the existing Investigation is incomplete or
        foreign, which fails closed instead of silently repairing it.
        """
        fixture = scenario.fixture

        entity_ids: dict[str, UUID] = {}
        for entity in fixture.entities:
            # Entity identity is resolved exactly as the DB resolves upserts:
            # the canonical (type, value) identity, which survives entity
            # values shared across scenarios and database-assigned ids.
            persisted_entity = await uow.entities.get_by_identity(
                entity.type.value, entity.value
            )
            if persisted_entity is None or persisted_entity.id is None:
                raise MaterializedScenarioStateError(
                    f"expected entity {entity.label!r} is missing"
                )
            entity_ids[entity.label] = persisted_entity.id

        evidence_ids: dict[str, UUID] = {}
        for evidence in fixture.evidence:
            planned = self._planned(scenario, "evidence_observation", evidence.label)
            if await uow.evidence.get_observation(planned) is None:
                raise MaterializedScenarioStateError(
                    f"expected evidence observation {evidence.label!r} is missing"
                )
            evidence_ids[evidence.label] = planned

        relationship_ids: dict[str, UUID] = {}
        for relationship in fixture.relationships:
            # Relationship identity is database-owned: upsert resolves the
            # edge by canonical (source, type, target) identity, so the
            # persisted id is never a planned UUID. Reuse resolves the same
            # edge through the canonical repository lookup.
            persisted_relationship = await uow.relationships.get_by_identity(
                entity_ids[relationship.source],
                relationship.type.value,
                entity_ids[relationship.target],
            )
            if persisted_relationship is None or persisted_relationship.id is None:
                raise MaterializedScenarioStateError(
                    f"expected relationship {relationship.label!r} is missing"
                )
            relationship_ids[relationship.label] = persisted_relationship.id

        observation_ids: dict[str, UUID] = {}
        for observation in fixture.observations:
            planned = self._planned(scenario, "observation", observation.label)
            if await uow.relationship_observations.get_by_id(planned) is None:
                raise MaterializedScenarioStateError(
                    f"expected relationship observation {observation.label!r} is missing"
                )
            observation_ids[observation.label] = planned

        return AnalystScenarioResolution(
            evidence_ids=evidence_ids,
            relationship_observation_ids=observation_ids,
            entity_ids=entity_ids,
            relationship_ids=relationship_ids,
        )

    def _planned(self, scenario: AnalystScenario, kind: str, label: str) -> UUID:
        """Return the deterministic planned UUID for one fixture label and kind."""
        return uuid5(
            self._namespace,
            f"urn:ati:scenario:{scenario.id}:v{scenario.version}:{kind}:{label}",
        )


def _entity_by_label(entities: tuple[FixtureEntity, ...], label: str) -> FixtureEntity:
    """Return the declared fixture entity for one label."""
    for entity in entities:
        if entity.label == label:
            return entity
    # Scenario validation guarantees fixture evidence subjects name declared
    # entities, so this defensive guard is not reachable through validated
    # scenario data.
    raise ValueError(  # pragma: no cover
        f"fixture declares no entity with label {label!r}"
    )


def _persisted_id(persisted: object, kind: str, label: str) -> UUID:
    """Return the repository-confirmed persisted identity or fail closed.

    A repository returning ``id=None`` means the write did not produce a
    durable identity; substituting the planned UUID would invent a persisted
    identity that the database does not confirm. The materializer therefore
    raises a deterministic ``ValueError`` instead.
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
