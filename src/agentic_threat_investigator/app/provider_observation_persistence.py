# SPDX-License-Identifier: AGPL-3.0-only
"""Atomic persistence of normalized provider observations and extracted graph data.

This service is the PR 18C application seam between deterministic extraction
and durable global graph state on the PR 28B model. Provider I/O and
extraction always happen before this boundary; one short UnitOfWork
transaction then persists the complete observation — exact global
EvidenceObservation (created/reused), canonical entities, observation-level
Entity associations, stable relationships and immutable relationship
observations (only for a new/appended observation), exact Investigation
admission, and the minimized audit event — or nothing at all.

Approved policy decisions implemented here:

- Preflight performs no database work; it validates the canonical identities,
  assertion endpoint coverage, and the deterministic duplicate policy before
  BEGIN.
- ``ati.persist_evidence_observation`` owns stable Evidence identity
  validation, atomic Evidence + v1 creation, race-safe per-Evidence version
  allocation, material no-op detection, and canonical diffs; an unchanged
  retrieval creates no observation and no duplicate RelationshipObservation.
- Repeated semantic edges under a new observation reuse the stable Entity
  and Relationship identities and append a new RelationshipObservation.
- Rediscovery of a soft-deleted Entity or Relationship is a fail-closed typed
  error: no second canonical row, no silent restore, and no new observation
  attached to a deleted graph object.
- Exact Investigation admission is append-only/idempotent; the invocation
  target Entity is associated with the exact observation as ordinary
  observation-level provenance (no privileged Evidence subject).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID, uuid4

from agentic_threat_investigator.app.extraction.models import (
    ExtractedEntity,
    ExtractionResult,
    RelationshipAssertion,
    assertion_order_key,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidencePersistenceOutcome,
    EvidencePersistenceResult,
    InvestigationNotFoundError,
    SoftDeletedIdentityError,
    UnitOfWork,
)
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType, canonicalize
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservation,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)

EntityIdentityKey = tuple[EntityType, str]


@dataclass(frozen=True)
class ProviderObservationPersistenceResult:
    """Objects written by one atomic provider-observation transaction."""

    evidence: Evidence
    observation: EvidenceObservation
    outcome: EvidencePersistenceOutcome
    entities: tuple[Entity, ...]
    relationships: tuple[Relationship, ...]
    observations: tuple[RelationshipObservation, ...]


def _evidence_audit_event(
    result: EvidencePersistenceResult,
    actor_id: UUID | None,
    request_id: UUID | None,
) -> AuditEvent:
    """Build the minimized audit record for one provider observation.

    The audit carries only bounded identities and the material outcome —
    never facts, raw payload, source bodies, or derived graph content.
    """
    return AuditEvent(
        action=AuditAction.EVIDENCE_RECORD,
        outcome=AuditOutcome.SUCCESS,
        actor_id=actor_id,
        object_type="evidence_observation",
        object_id=result.observation.id,
        request_id=request_id,
        metadata={
            "evidence_id": str(result.evidence.id),
            "outcome": result.outcome.value,
            "version": result.version,
        },
    )


class ProviderObservationPersistenceService:
    """Persist one already-normalized and already-extracted observation atomically.

    The service owns the UnitOfWork boundary only: repositories never commit,
    extraction and provider work never run inside the transaction, and every
    failure path rolls back the whole observation through the UnitOfWork.
    """

    def __init__(self, uow_factory: Callable[[], UnitOfWork]) -> None:
        self._uow_factory = uow_factory

    async def persist(
        self,
        converted: ConvertedEvidence,
        invocation_entity: Entity,
        extraction: ExtractionResult,
        *,
        investigation_id: UUID,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> ProviderObservationPersistenceResult:
        """Validate outside the transaction, then persist the complete observation."""
        self._validate(invocation_entity, extraction)
        entity_specs = self._ordered_entities(invocation_entity, extraction)
        assertions = self._ordered_assertions(extraction)

        async with self._uow_factory() as uow:
            # Validate the parent investigation before any graph mutation so a
            # missing or soft-deleted parent never leaves partial graph work
            # even transiently inside the transaction.
            if await uow.investigations.get_by_id(investigation_id) is None:
                raise InvestigationNotFoundError(str(investigation_id))

            # PostgreSQL owns the authoritative global persist/reuse decision:
            # CREATED (Evidence + v1), UNCHANGED (existing exact observation),
            # or APPENDED (next version with canonical diff).
            persisted = await uow.evidence.persist(converted)

            identity_map, persisted_entities = await self._resolve_entities(
                uow, entity_specs
            )
            # Observation-level Entity associations: every canonical Entity
            # materially represented in the exact observation. Idempotent.
            for entity in persisted_entities:
                if entity.id is None:  # pragma: no cover - repository invariant
                    raise RuntimeError(
                        "entity repository returned an entity without an ID"
                    )
                await uow.evidence_observation_entities.associate(
                    persisted.observation.id, entity.id
                )

            relationships: list[Relationship] = []
            observations: list[RelationshipObservation] = []
            if persisted.outcome is not EvidencePersistenceOutcome.UNCHANGED:
                # Derived global graph provenance is persisted only for a
                # new/appended observation; an unchanged retrieval reuses the
                # latest exact observation without duplicating
                # RelationshipObservations.
                (
                    relationships,
                    observations,
                ) = await self._resolve_relationships(
                    uow,
                    assertions,
                    identity_map,
                    persisted.observation,
                    persisted.evidence.source,
                )

            # Exact admission of the observation into this Investigation is
            # append-only/idempotent; a newer global observation never
            # silently enters an Investigation.
            await uow.investigation_evidence.admit(
                InvestigationEvidence(
                    investigation_id=investigation_id,
                    evidence_observation_id=persisted.observation.id,
                    inclusion_reason=InvestigationEvidenceReason.PROVIDER_RESULT,
                    added_at=persisted.observation.retrieved_at,
                    added_by=InvestigationEvidenceActor.SYSTEM,
                )
            )
            await uow.audit_events.append(
                _evidence_audit_event(persisted, actor_id, request_id)
            )
        return ProviderObservationPersistenceResult(
            evidence=persisted.evidence,
            observation=persisted.observation,
            outcome=persisted.outcome,
            entities=tuple(persisted_entities),
            relationships=tuple(relationships),
            observations=tuple(observations),
        )

    @staticmethod
    async def _resolve_entities(
        uow: UnitOfWork, entity_specs: tuple[ExtractedEntity, ...]
    ) -> tuple[dict[EntityIdentityKey, Entity], list[Entity]]:
        """Resolve every required identity into one transaction-local map.

        Existing rows are reused under the current Entity metadata semantics:
        missing extraction display names retain the stored value, supplied
        display names follow the ordinary upsert rules, and unchanged
        observations never bump the database version. Soft-deleted identities
        are a fail-closed typed error.
        """
        identity_map: dict[EntityIdentityKey, Entity] = {}
        persisted_entities: list[Entity] = []
        for spec in entity_specs:
            existing = await uow.entities.get_by_identity(
                spec.type.value, spec.value, include_deleted=True
            )
            if existing is not None and existing.deleted_at is not None:
                assert existing.id is not None  # database invariant
                raise SoftDeletedIdentityError("entity", existing.id)
            written = await uow.entities.upsert(
                Entity(
                    id=existing.id if existing else None,
                    type=spec.type,
                    value=spec.value,
                    display_name=(
                        spec.display_name
                        if spec.display_name is not None
                        else (existing.display_name if existing else None)
                    ),
                    attributes=existing.attributes if existing else {},
                    content_hash=existing.content_hash if existing else None,
                )
            )
            identity_map[(spec.type, spec.value)] = written
            persisted_entities.append(written)
        return identity_map, persisted_entities

    @staticmethod
    async def _resolve_relationships(
        uow: UnitOfWork,
        assertions: tuple[RelationshipAssertion, ...],
        identity_map: dict[EntityIdentityKey, Entity],
        observation: EvidenceObservation,
        source: str,
    ) -> tuple[list[Relationship], list[RelationshipObservation]]:
        """Resolve each stable edge and append exactly one observation per edge.

        RelationshipObservations reference the exact persisted
        ``EvidenceObservation``; the database validates that provenance.
        """
        persisted_relationships: list[Relationship] = []
        observations: list[RelationshipObservation] = []
        for assertion in assertions:
            source_entity = identity_map[
                (assertion.source.type, assertion.source.value)
            ]
            target_entity = identity_map[
                (assertion.target.type, assertion.target.value)
            ]
            if source_entity.id is None or target_entity.id is None:
                # pragma: no cover - repository invariant
                raise RuntimeError("entity repository returned an entity without an ID")
            relationship = await uow.relationships.upsert(
                Relationship(
                    id=uuid4(),
                    source_entity_id=source_entity.id,
                    target_entity_id=target_entity.id,
                    type=assertion.type,
                )
            )
            persisted_relationships.append(relationship)
            obs = RelationshipObservation(
                id=uuid4(),
                relationship_id=relationship.id,
                evidence_observation_id=observation.id,
                observed_at=observation.observed_at,
                retrieved_at=observation.retrieved_at,
                source=source,
            )
            observations.append(await uow.relationship_observations.append(obs))
        return persisted_relationships, observations

    @staticmethod
    def _validate(invocation_entity: Entity, extraction: ExtractionResult) -> None:
        """Perform all deterministic preflight validation without database work.

        Duplicate entities and duplicate assertions are rejected outright:
        PR 18B output is already deduplicated, so any duplicate that reaches
        this boundary is a contract violation rather than something the
        persistence layer silently repairs or merges.
        """
        if canonicalize(invocation_entity.type, invocation_entity.value) != (
            invocation_entity.value
        ):
            raise ValueError("invocation entity value is not canonical")
        identities: set[EntityIdentityKey] = {
            (invocation_entity.type, invocation_entity.value)
        }
        seen_entities: set[EntityIdentityKey] = set()
        for entity in extraction.entities:
            key = (entity.type, entity.value)
            if canonicalize(entity.type, entity.value) != entity.value:
                raise ValueError("extraction entity is not canonical")
            if key in seen_entities:
                raise ValueError(f"duplicate extracted entity identity: {key[1]}")
            seen_entities.add(key)
            identities.add(key)
        for assertion in extraction.relationships:
            for endpoint in (assertion.source, assertion.target):
                if canonicalize(endpoint.type, endpoint.value) != endpoint.value:
                    raise ValueError("relationship endpoint is not canonical")
                if (endpoint.type, endpoint.value) not in identities:
                    raise ValueError(
                        "relationship endpoint is not covered by extraction"
                    )
        seen_assertions: set[tuple[EntityType, str, object, EntityType, str]] = set()
        for assertion in extraction.relationships:
            assertion_key = assertion_order_key(assertion)
            if assertion_key in seen_assertions:
                raise ValueError("duplicate relationship assertion")
            seen_assertions.add(assertion_key)

    @staticmethod
    def _ordered_entities(
        invocation_entity: Entity, extraction: ExtractionResult
    ) -> tuple[ExtractedEntity, ...]:
        """Return invocation target and discoveries in stable identity order.

        The invocation target contributes no display metadata of its own; a
        discovery of the same identity wins so its display metadata is never
        lost.
        """
        by_identity: dict[EntityIdentityKey, ExtractedEntity] = {
            (entity.type, entity.value): entity for entity in extraction.entities
        }
        by_identity.setdefault(
            (invocation_entity.type, invocation_entity.value),
            ExtractedEntity(type=invocation_entity.type, value=invocation_entity.value),
        )
        return tuple(
            by_identity[key]
            for key in sorted(by_identity, key=lambda item: (item[0].value, item[1]))
        )

    @staticmethod
    def _ordered_assertions(
        extraction: ExtractionResult,
    ) -> tuple[RelationshipAssertion, ...]:
        """Return assertions in stable identity order for deterministic writes."""
        return tuple(sorted(extraction.relationships, key=assertion_order_key))
