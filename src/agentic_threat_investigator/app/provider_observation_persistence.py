# SPDX-License-Identifier: AGPL-3.0-only
"""Atomic persistence of normalized provider observations and extracted graph data.

This service is the PR 18C application seam between deterministic extraction
(PR 18B) and durable graph state. Provider I/O and extraction always happen
before this boundary; one short UnitOfWork transaction then persists the
complete observation — canonical entities, immutable evidence, stable
relationships, immutable relationship observations, and the required audit
event — or nothing at all.

Approved policy decisions implemented here:

- Preflight performs no database work; it validates the Evidence identity,
  canonical identities, assertion Evidence-ID equality, endpoint coverage,
  and the deterministic duplicate policy before BEGIN.
- Repeated semantic edges under a new Evidence ID reuse the stable Entity and
  Relationship identities and append a new RelationshipObservation.
- Replay of the same Evidence ID is a typed conflict; the UnitOfWork rolls
  back every earlier mutation in the transaction.
- Rediscovery of a soft-deleted Entity or Relationship is a fail-closed typed
  error: no second canonical row, no silent restore, and no new observation
  attached to a deleted graph object.
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
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)

EntityIdentityKey = tuple[EntityType, str]


@dataclass(frozen=True)
class ProviderObservationPersistenceResult:
    """Objects written by one atomic provider-observation transaction."""

    evidence: Evidence
    entities: tuple[Entity, ...]
    relationships: tuple[Relationship, ...]
    observations: tuple[RelationshipObservation, ...]


def _evidence_audit_event(
    evidence: Evidence,
    actor_id: UUID | None,
    request_id: UUID | None,
) -> AuditEvent:
    """Build the minimized audit record for a provider observation."""
    return AuditEvent(
        action=AuditAction.EVIDENCE_RECORD,
        outcome=AuditOutcome.SUCCESS,
        actor_id=actor_id,
        object_type="evidence",
        object_id=evidence.id,
        request_id=request_id,
        metadata={"investigation_id": str(evidence.investigation_id)},
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
        evidence: Evidence,
        extraction: ExtractionResult,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> ProviderObservationPersistenceResult:
        """Validate outside the transaction, then persist the complete observation."""
        self._validate(evidence, extraction)
        entity_specs = self._ordered_entities(evidence, extraction)
        assertions = self._ordered_assertions(extraction)

        async with self._uow_factory() as uow:
            # Validate the parent investigation before any graph mutation so a
            # missing or soft-deleted parent never leaves partial graph work
            # even transiently inside the transaction.
            if await uow.investigations.get_by_id(evidence.investigation_id) is None:
                raise InvestigationNotFoundError(str(evidence.investigation_id))

            identity_map, persisted_entities = await self._resolve_entities(
                uow, entity_specs
            )
            recorded = await self._insert_evidence(
                uow, evidence, identity_map, actor_id, request_id
            )
            (
                persisted_relationships,
                observations,
            ) = await self._resolve_relationships(
                uow, assertions, identity_map, recorded
            )
            await uow.audit_events.append(
                _evidence_audit_event(recorded, actor_id, request_id)
            )
        return ProviderObservationPersistenceResult(
            evidence=recorded,
            entities=tuple(persisted_entities),
            relationships=tuple(persisted_relationships),
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
    async def _insert_evidence(
        uow: UnitOfWork,
        evidence: Evidence,
        identity_map: dict[EntityIdentityKey, Entity],
        actor_id: UUID | None,
        request_id: UUID | None,
    ) -> Evidence:
        """Insert the immutable Evidence observation with its resolved subject."""
        subject = identity_map[(evidence.subject.type, evidence.subject.value)]
        if subject.id is None:  # pragma: no cover - repository invariant
            raise RuntimeError("entity repository returned an entity without an ID")
        recorded = await uow.evidence.insert(
            evidence.model_copy(
                update={
                    "subject": evidence.subject.model_copy(update={"id": subject.id})
                }
            ),
            actor_id=actor_id,
            request_id=request_id,
        )
        if recorded.id != evidence.id:  # pragma: no cover - repository invariant
            raise RuntimeError("evidence repository replaced the supplied identity")
        return recorded

    @staticmethod
    async def _resolve_relationships(
        uow: UnitOfWork,
        assertions: tuple[RelationshipAssertion, ...],
        identity_map: dict[EntityIdentityKey, Entity],
        recorded: Evidence,
    ) -> tuple[list[Relationship], list[RelationshipObservation]]:
        """Resolve each stable edge and append exactly one observation per edge."""
        if recorded.id is None:  # pragma: no cover - repository invariant
            raise RuntimeError("evidence repository returned no ID")
        persisted_relationships: list[Relationship] = []
        observations: list[RelationshipObservation] = []
        for assertion in assertions:
            source = identity_map[(assertion.source.type, assertion.source.value)]
            target = identity_map[(assertion.target.type, assertion.target.value)]
            if source.id is None or target.id is None:  # pragma: no cover
                raise RuntimeError("entity repository returned an entity without an ID")
            relationship = await uow.relationships.upsert(
                Relationship(
                    id=uuid4(),
                    source_entity_id=source.id,
                    target_entity_id=target.id,
                    type=assertion.type,
                )
            )
            persisted_relationships.append(relationship)
            observation = RelationshipObservation(
                id=uuid4(),
                relationship_id=relationship.id,
                evidence_id=recorded.id,
                investigation_id=recorded.investigation_id,
                observed_at=recorded.observed_at,
                retrieved_at=recorded.retrieved_at,
                source=recorded.source,
            )
            observations.append(await uow.relationship_observations.append(observation))
        return persisted_relationships, observations

    @staticmethod
    def _validate(evidence: Evidence, extraction: ExtractionResult) -> None:
        """Perform all deterministic preflight validation without database work.

        Duplicate entities and duplicate assertions are rejected outright:
        PR 18B output is already deduplicated, so any duplicate that reaches
        this boundary is a contract violation rather than something the
        persistence layer silently repairs or merges.
        """
        if evidence.id is None:
            raise ValueError("evidence id is required before persistence")
        if canonicalize(evidence.subject.type, evidence.subject.value) != (
            evidence.subject.value
        ):
            raise ValueError("evidence subject value is not canonical")
        identities: set[EntityIdentityKey] = {
            (evidence.subject.type, evidence.subject.value)
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
            if assertion.evidence_id != evidence.id:
                raise ValueError("relationship assertion Evidence ID does not match")
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
        evidence: Evidence, extraction: ExtractionResult
    ) -> tuple[ExtractedEntity, ...]:
        """Return subject and discoveries in stable identity order.

        When the subject and a discovered entity describe the same identity,
        the discovered specification wins so its display metadata is never
        lost; the subject contributes no display metadata of its own.
        """
        by_identity: dict[EntityIdentityKey, ExtractedEntity] = {
            (entity.type, entity.value): entity for entity in extraction.entities
        }
        subject_key = (evidence.subject.type, evidence.subject.value)
        by_identity.setdefault(
            subject_key,
            ExtractedEntity(type=evidence.subject.type, value=evidence.subject.value),
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
