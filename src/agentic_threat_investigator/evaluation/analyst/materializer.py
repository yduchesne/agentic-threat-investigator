# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic fixture materialization for analyst scenarios (PR 20C).

The materializer persists one :class:`AnalystScenario` fixture through the
application ``UnitOfWork`` seam — Investigation, Entities, Evidence,
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
from agentic_threat_investigator.domain.evidence import EntityRef, Evidence
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


class AnalystScenarioMaterializer:
    """Persist one scenario fixture and resolve its labels to UUIDs.

    ``namespace`` defaults to the stable ATI evaluation namespace; callers
    only override it when they must isolate identities (for example when two
    fixture copies share one database within a test).
    """

    def __init__(self, *, namespace: UUID = DEFAULT_SCENARIO_NAMESPACE) -> None:
        """Bind the identity namespace used for stable fixture UUIDs."""
        self._namespace = namespace

    async def materialize(
        self, uow: UnitOfWork, scenario: AnalystScenario
    ) -> AnalystScenarioResolution:
        """Persist the fixture graph and return the label resolution.

        Persistence order is deterministic: entities (in declaration order),
        then Investigation, evidence, relationships, observations. Entities
        are persisted first so the Investigation root pointer and every
        Evidence subject reference the identities the repository actually
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
            subject = _entity_by_label(fixture.entities, evidence.subject)
            persisted_evidence = await uow.evidence.insert(
                Evidence(
                    id=self._planned(scenario, "evidence", evidence.label),
                    investigation_id=investigation_id,
                    type=evidence.type,
                    subject=EntityRef(
                        id=entity_ids[evidence.subject],
                        type=subject.type,
                        value=subject.value,
                    ),
                    source=evidence.source,
                    observed_at=evidence.observed_at,
                    retrieved_at=evidence.retrieved_at or _FIXED_TIMESTAMP,
                    facts=dict(evidence.facts),
                )
            )
            evidence_ids[evidence.label] = _persisted_id(
                persisted_evidence, "evidence", evidence.label
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
                    evidence_id=evidence_ids[observation.evidence],
                    investigation_id=investigation_id,
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
