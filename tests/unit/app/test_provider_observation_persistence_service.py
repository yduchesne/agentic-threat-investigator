# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the provider-observation persistence service boundary (PR 28B).

Fakes replace every repository and the UnitOfWork, proving that preflight
performs zero database work, that repositories never own the transaction
lifecycle, and that every failure path rolls the whole observation back.
The fake Evidence storage models the PR 28B global contract: stable
Evidence, per-Evidence ordered observations, material no-op, append on
material change, explicit observation/Entity pairs, and Investigation
admissions.
"""

# Fixture arguments intentionally reuse fixture names, and the fake
# repositories deliberately mirror the production contracts; the fake ABCs
# and builders are intentional structural boilerplate.

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from types import TracebackType
from typing import Self
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.extraction.models import (
    EntityIdentity,
    ExtractedEntity,
    ExtractionResult,
    RelationshipAssertion,
)
from agentic_threat_investigator.app.persistence.repositories import (
    AuditEventRepository,
    BatchOutcome,
    EntityRepository,
    EvidenceObservationEntityRepository,
    EvidencePersistenceOutcome,
    EvidencePersistenceResult,
    EvidenceRepository,
    InvestigationEvidenceRepository,
    InvestigationNotFoundError,
    InvestigationRepository,
    InvestigationWriteResult,
    RelationshipObservationRepository,
    RelationshipRepository,
    SoftDeletedIdentityError,
    UnitOfWork,
)
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceResult,
    ProviderObservationPersistenceService,
)
from agentic_threat_investigator.domain.audit import AuditEvent, AuditOutcome
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservation,
    EvidenceObservationCandidate,
    EvidenceObservationEntity,
    EvidenceType,
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
    RelationshipType,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_SUBJECT_VALUE = "malicious-domain.test"
_IP_VALUE = "203.0.113.42"
_SOURCE = "urn:ati:source:threatfox"


def entity_builder(
    entity_type: EntityType, value: str, display_name: str | None = None
) -> ExtractedEntity:
    """Build a canonical discovered entity."""
    return ExtractedEntity(type=entity_type, value=value, display_name=display_name)


def threatfox_extraction() -> ExtractionResult:
    """Build the canonical ThreatFox extraction for the global fixture."""
    return ExtractionResult(
        entities=(entity_builder(EntityType.MALWARE, "win.asyncrat"),),
        relationships=(
            RelationshipAssertion(
                source=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
                type=RelationshipType.ASSOCIATED_WITH,
                target=EntityIdentity(type=EntityType.MALWARE, value="win.asyncrat"),
            ),
        ),
    )


def dns_extraction() -> ExtractionResult:
    """Build the canonical DNS extraction for a global DNS fixture."""
    return ExtractionResult(
        entities=(
            entity_builder(EntityType.DOMAIN, _SUBJECT_VALUE),
            entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),
        ),
        relationships=(
            RelationshipAssertion(
                source=EntityIdentity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
                type=RelationshipType.RESOLVES_TO,
                target=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
            ),
        ),
    )


def converted_evidence(
    *,
    evidence_id: UUID | None = None,
    source: str = _SOURCE,
    evidence_type: EvidenceType = EvidenceType.THREAT_INTELLIGENCE,
    facts: dict[str, object] | None = None,
    observed_at: datetime | None = None,
    retrieved_at: datetime | None = None,
    source_record_id: str | None = None,
) -> ConvertedEvidence:
    """Build one deterministic global ConvertedEvidence.

    Stable Evidence never carries Investigation, subject, observation
    timestamps, facts, or payload.
    """
    identity = evidence_id if evidence_id is not None else uuid4()
    evidence = Evidence(
        id=identity,
        type=evidence_type,
        source=source,
        source_record_id=(
            source_record_id if source_record_id is not None else f"rec-{identity}"
        ),
    )
    candidate = EvidenceObservationCandidate(
        evidence_id=identity,
        observed_at=observed_at,
        retrieved_at=retrieved_at if retrieved_at is not None else _RETRIEVED_AT,
        facts=facts
        if facts is not None
        else {"matches": [{"malware": "win.asyncrat"}]},
        raw_payload=None,
    )
    return ConvertedEvidence(evidence=evidence, observation=candidate)


def invitation_entity() -> Entity:
    """Build the authoritative provider invocation target entity."""
    return Entity(type=EntityType.IP_ADDRESS, value=_IP_VALUE)


class FakeEntityRepository(EntityRepository):
    """In-memory entity repository with an injected failure seam."""

    def __init__(self) -> None:
        self.rows: dict[tuple[EntityType, str], Entity] = {}
        self.upsert_calls: list[Entity] = []
        self.get_calls: list[tuple[str, str]] = []
        self.fail_on_identity: tuple[EntityType, str] | None = None
        self.undo_actions: list[Callable[[], None]] = []

    def undo(self) -> None:
        """Undo every mutation recorded by this fake."""
        for action in reversed(self.undo_actions):
            action()
        self.undo_actions.clear()

    async def get_by_identity(
        self, entity_type: str, canonical_value: str, *, include_deleted: bool = False
    ) -> Entity | None:
        self.get_calls.append((entity_type, canonical_value))
        return self.rows.get((EntityType(entity_type), canonical_value))

    async def get_by_id(
        self, entity_id: UUID, *, include_deleted: bool = False
    ) -> Entity | None:
        """Return the visible entity with the given identifier, if any."""
        for row in self.rows.values():
            if row.id == entity_id:
                if not include_deleted and row.deleted_at is not None:
                    return None
                return row.model_copy()
        return None

    async def upsert(
        self, entity: Entity, *, expected_version: int | None = None
    ) -> Entity:
        self.upsert_calls.append(entity)
        key = (entity.type, entity.value)
        if self.fail_on_identity == key:
            raise RuntimeError("injected entity failure")
        existing = self.rows.get(key)
        if existing is not None:
            unchanged = (
                existing.display_name == entity.display_name
                and existing.attributes == entity.attributes
                and existing.content_hash == entity.content_hash
            )
            if unchanged:
                return existing.model_copy()
            version = (existing.version or 0) + 1
        else:
            version = 1
        written = entity.model_copy(
            update={"id": entity.id or uuid4(), "version": version}
        )
        previous = self.rows.get(key)
        self.rows[key] = written

        def _undo() -> None:
            if previous is None:
                self.rows.pop(key, None)
            else:
                self.rows[key] = previous

        self.undo_actions.append(_undo)
        return written.model_copy()

    async def upsert_batch(self, items: Sequence[object]) -> list[object]:  # type: ignore[override]
        raise NotImplementedError

    async def soft_delete(self, entity_id: UUID, **_: object) -> Entity:
        for row in self.rows.values():
            if row.id == entity_id:
                deleted = row.model_copy(update={"deleted_at": _RETRIEVED_AT})
                self.rows[(row.type, row.value)] = deleted
                return deleted
        raise LookupError("entity not found")


class FakeRelationshipRepository(RelationshipRepository):
    """In-memory relationship repository with an injected failure seam."""

    def __init__(self) -> None:
        self.rows: dict[tuple[UUID, RelationshipType, UUID], Relationship] = {}
        self.upsert_calls: list[Relationship] = []
        self.fail = False
        self.undo_actions: list[Callable[[], None]] = []

    def undo(self) -> None:
        """Undo every mutation recorded by this fake."""
        for action in reversed(self.undo_actions):
            action()
        self.undo_actions.clear()

    async def get_by_identity(
        self,
        source_entity_id: UUID,
        relationship_type: str,
        target_entity_id: UUID,
        *,
        include_deleted: bool = False,
    ) -> Relationship | None:
        return self.rows.get(
            (source_entity_id, RelationshipType(relationship_type), target_entity_id)
        )

    async def get_by_id(
        self, relationship_id: UUID, *, include_deleted: bool = False
    ) -> Relationship | None:
        """Return the row with the given identifier, if any."""
        return next(
            (row for row in self.rows.values() if row.id == relationship_id), None
        )

    async def upsert(
        self, relationship: Relationship, *, expected_version: int | None = None
    ) -> Relationship:
        self.upsert_calls.append(relationship)
        if self.fail:
            raise RuntimeError("injected relationship failure")
        key = (
            relationship.source_entity_id,
            relationship.type,
            relationship.target_entity_id,
        )
        existing = self.rows.get(key)
        if existing is not None:
            return existing
        self.rows[key] = relationship

        def _undo() -> None:
            self.rows.pop(key, None)

        self.undo_actions.append(_undo)
        return relationship

    async def soft_delete(self, relationship_id: UUID, **_: object) -> Relationship:
        for row in self.rows.values():
            if row.id == relationship_id:
                return row
        raise LookupError("relationship not found")


class FakeObservationRepository(RelationshipObservationRepository):
    """Append-only observation fake with an injected failure seam."""

    def __init__(self) -> None:
        self.rows: list[RelationshipObservation] = []
        self.fail = False
        self.undo_actions: list[Callable[[], None]] = []

    def undo(self) -> None:
        """Undo every mutation recorded by this fake."""
        for action in reversed(self.undo_actions):
            action()
        self.undo_actions.clear()

    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        if self.fail:
            raise RuntimeError("injected observation failure")
        self.rows.append(observation)

        def _undo() -> None:
            self.rows.remove(observation)

        self.undo_actions.append(_undo)
        return observation

    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RelationshipObservation]:
        raise NotImplementedError

    async def get_by_id(self, observation_id: UUID) -> RelationshipObservation | None:
        return next((row for row in self.rows if row.id == observation_id), None)


def _material_equal(
    observation: EvidenceObservation, candidate: EvidenceObservationCandidate
) -> bool:
    """Return whether the persisted observation and the candidate have equal
    material state (observed_at/source_url/facts/raw_payload)."""
    return (
        observation.observed_at == candidate.observed_at
        and observation.source_url == candidate.source_url
        and observation.facts == candidate.facts
        and observation.raw_payload == candidate.raw_payload
    )


class FakeEvidenceRepository(EvidenceRepository):
    """Global Evidence fake modeling CREATED/UNCHANGED/APPENDED."""

    def __init__(self) -> None:
        self.stable: dict[UUID, Evidence] = {}
        self.observations: dict[UUID, EvidenceObservation] = {}
        self.by_evidence: dict[UUID, list[UUID]] = {}
        self.persist_calls: list[ConvertedEvidence] = []
        self.fail = False
        self.undo_actions: list[Callable[[], None]] = []

    def undo(self) -> None:
        """Undo every mutation recorded by this fake (transaction rollback)."""
        for action in reversed(self.undo_actions):
            action()
        self.undo_actions.clear()

    def _track_created(self, evidence_id: UUID, observation_id: UUID) -> None:
        stable = self.stable
        observations = self.observations

        def undo() -> None:
            observations.pop(observation_id, None)
            by_evidence = self.by_evidence.get(evidence_id, [])
            if observation_id in by_evidence:
                by_evidence.remove(observation_id)
            if not by_evidence:
                self.by_evidence.pop(evidence_id, None)
                stable.pop(evidence_id, None)

        self.undo_actions.append(undo)

    async def persist(
        self, converted: ConvertedEvidence, *, observation_id: UUID | None = None
    ) -> EvidencePersistenceResult:
        self.persist_calls.append(converted)
        if self.fail:
            raise RuntimeError("injected evidence failure")
        evidence_id = converted.evidence.id
        if evidence_id in self.stable:
            existing = self.stable[evidence_id]
            if (
                existing.type is not converted.evidence.type
                or existing.source != converted.evidence.source
                or existing.source_record_id != converted.evidence.source_record_id
            ):
                from agentic_threat_investigator.app.persistence.repositories import (
                    EvidenceMetadataConflictError,
                )

                raise EvidenceMetadataConflictError(evidence_id)
        if evidence_id not in self.stable:
            self.stable[evidence_id] = converted.evidence
            version = 1
            identity = observation_id if observation_id is not None else uuid4()
            observation = EvidenceObservation(
                id=identity,
                evidence_id=evidence_id,
                version=version,
                source_url=converted.observation.source_url,
                observed_at=converted.observation.observed_at,
                retrieved_at=converted.observation.retrieved_at,
                facts=converted.observation.facts,
                raw_payload=converted.observation.raw_payload,
                diff=None,
            )
            self.observations[identity] = observation
            self.by_evidence[evidence_id] = [identity]
            self._track_created(evidence_id, identity)
            from agentic_threat_investigator.app.persistence.repositories import (
                EvidencePersistenceResult,
            )

            return EvidencePersistenceResult(
                evidence=converted.evidence,
                observation=observation,
                outcome=EvidencePersistenceOutcome.CREATED,
                version=1,
            )
        latest_id = self.by_evidence[evidence_id][-1]
        latest = self.observations[latest_id]
        if _material_equal(latest, converted.observation):
            from agentic_threat_investigator.app.persistence.repositories import (
                EvidencePersistenceResult,
            )

            return EvidencePersistenceResult(
                evidence=converted.evidence,
                observation=latest,
                outcome=EvidencePersistenceOutcome.UNCHANGED,
                version=latest.version,
            )
        identity = uuid4()
        observation = EvidenceObservation(
            id=identity,
            evidence_id=evidence_id,
            version=latest.version + 1,
            source_url=converted.observation.source_url,
            observed_at=converted.observation.observed_at,
            retrieved_at=converted.observation.retrieved_at,
            facts=converted.observation.facts,
            raw_payload=converted.observation.raw_payload,
            diff={"changed": True},
        )
        self.observations[identity] = observation
        self.by_evidence[evidence_id].append(identity)
        self._track_created(evidence_id, identity)
        from agentic_threat_investigator.app.persistence.repositories import (
            EvidencePersistenceResult,
        )

        return EvidencePersistenceResult(
            evidence=converted.evidence,
            observation=observation,
            outcome=EvidencePersistenceOutcome.APPENDED,
            version=observation.version,
        )

    async def get_stable_evidence(self, evidence_id: UUID) -> Evidence | None:
        return self.stable.get(evidence_id)

    async def get_observation(self, observation_id: UUID) -> EvidenceObservation | None:
        return self.observations.get(observation_id)

    async def list_observations(
        self,
        evidence_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceObservation]:
        ids = self.by_evidence.get(evidence_id, [])
        return [self.observations[i] for i in ids[offset : offset + limit]]

    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceObservation]:
        raise NotImplementedError


class FakeEvidenceObservationEntityRepository(EvidenceObservationEntityRepository):
    """Observation/Entity association fake with deduplication."""

    def __init__(self) -> None:
        self.pairs: set[tuple[UUID, UUID]] = set()
        self.associate_calls: list[tuple[UUID, UUID]] = []

    async def associate(
        self, observation_id: UUID, entity_id: UUID
    ) -> EvidenceObservationEntity:
        self.associate_calls.append((observation_id, entity_id))
        self.pairs.add((observation_id, entity_id))
        return EvidenceObservationEntity(
            evidence_observation_id=observation_id, entity_id=entity_id
        )

    async def list_for_observation(
        self, observation_id: UUID
    ) -> list[EvidenceObservationEntity]:
        return [
            EvidenceObservationEntity(
                evidence_observation_id=observation_id, entity_id=entity_id
            )
            for (obs, entity_id) in sorted(self.pairs)
            if obs == observation_id
        ]


class FakeInvestigationEvidenceRepository(InvestigationEvidenceRepository):
    """Exact admission fake with an injected failure seam."""

    def __init__(self) -> None:
        self.admissions: dict[UUID, set[UUID]] = {}
        self.admit_calls: list[InvestigationEvidence] = []
        self.fail = False
        self.undo_actions: list[Callable[[], None]] = []

    def undo(self) -> None:
        """Undo every mutation recorded by this fake."""
        for action in reversed(self.undo_actions):
            action()
        self.undo_actions.clear()

    async def admit(self, admission: InvestigationEvidence) -> InvestigationEvidence:
        self.admit_calls.append(admission)
        if self.fail:
            raise RuntimeError("injected admission failure")
        bucket = self.admissions.setdefault(admission.investigation_id, set())
        bucket.add(admission.evidence_observation_id)

        def _undo() -> None:
            bucket.discard(admission.evidence_observation_id)

        self.undo_actions.append(_undo)
        return admission

    async def list_for_investigation(
        self, investigation_id: UUID
    ) -> list[InvestigationEvidence]:
        return [
            InvestigationEvidence(
                investigation_id=investigation_id,
                evidence_observation_id=observation_id,
                inclusion_reason=InvestigationEvidenceReason.PROVIDER_RESULT,
                added_at=_RETRIEVED_AT,
                added_by=InvestigationEvidenceActor.SYSTEM,
            )
            for observation_id in sorted(self.admissions.get(investigation_id, set()))
        ]


class FakeInvestigationRepository(InvestigationRepository):
    """Investigation fake exposing only the visibility check."""

    def __init__(self, visible: set[UUID] | None = None) -> None:
        self.visible: set[UUID] = visible or set()

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        if investigation_id in self.visible:
            return InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[],
                objective="Unit test",
                budget=default_investigation_budget(),
                started_at=_RETRIEVED_AT,
            )
        return None

    async def create(
        self, state: InvestigationState, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_assessment_reference(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        **_: object,
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_report_reference(
        self,
        investigation_id: UUID,
        report_id: UUID,
        **_: object,
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_budget(
        self,
        investigation_id: UUID,
        budget: object,
        **_: object,
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_status(
        self, *args: object, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_coordinator_state(
        self,
        investigation_id: UUID,
        transition_kind: object,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        consumes_replan: bool = False,
    ) -> InvestigationWriteResult:
        """Test fake: accept the transition and report a new version."""
        return InvestigationWriteResult(investigation_id, 7, BatchOutcome.UPDATED)

    async def set_analysis_result(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        analyzed_evidence_ids: list[UUID],
        disposition: object,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationWriteResult:
        """Test fake: accept and report a new version."""
        del (
            assessment_id,
            analyzed_evidence_ids,
            disposition,
            actor_id,
            request_id,
            expected_version,
        )
        return InvestigationWriteResult(investigation_id, 8, BatchOutcome.UPDATED)

    async def soft_delete(self, *args: object, **_: object) -> InvestigationWriteResult:
        raise NotImplementedError


class FakeAuditRepository(AuditEventRepository):
    """Append-only audit fake with an injected failure seam."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self.fail = False
        self.undo_actions: list[Callable[[], None]] = []

    def undo(self) -> None:
        """Undo every mutation recorded by this fake."""
        for action in reversed(self.undo_actions):
            action()
        self.undo_actions.clear()

    async def append(self, event: AuditEvent) -> AuditEvent:
        if self.fail:
            raise RuntimeError("injected audit failure")
        self.events.append(event)

        def _undo() -> None:
            self.events.remove(event)

        self.undo_actions.append(_undo)
        return event

    async def list_events(self, **_: object) -> list[AuditEvent]:
        return list(self.events)


class FakeUnitOfWork(UnitOfWork):
    """UnitOfWork fake recording enter/commit/rollback lifecycle."""

    def __init__(
        self,
        *,
        entities: FakeEntityRepository,
        relationships: FakeRelationshipRepository,
        relationship_observations: FakeObservationRepository,
        evidence: FakeEvidenceRepository,
        evidence_observation_entities: FakeEvidenceObservationEntityRepository,
        investigation_evidence: FakeInvestigationEvidenceRepository,
        investigations: FakeInvestigationRepository,
        audit_events: FakeAuditRepository,
    ) -> None:
        self.entities: EntityRepository = entities
        self.relationships: RelationshipRepository = relationships
        self.relationship_observations: RelationshipObservationRepository = (
            relationship_observations
        )
        self.evidence: EvidenceRepository = evidence
        self.evidence_observation_entities: EvidenceObservationEntityRepository = (
            evidence_observation_entities
        )
        self.investigation_evidence: InvestigationEvidenceRepository = (
            investigation_evidence
        )
        self.investigations: InvestigationRepository = investigations
        self.audit_events: AuditEventRepository = audit_events
        self.entered = 0
        self.committed = 0
        self.rolled_back = 0
        self.active = False
        self._undoables: list[object] = [
            entities,
            relationships,
            relationship_observations,
            evidence,
            evidence_observation_entities,
            investigation_evidence,
            audit_events,
        ]

    async def __aenter__(self) -> Self:
        self.entered += 1
        self.active = True
        # Each transaction starts with a clean journal: prior committed
        # mutations are durable in the fake and must not be undone by a
        # later rollback.
        for undoable in self._undoables:
            undo_journal = getattr(undoable, "undo_actions", None)
            if undo_journal is not None:
                undo_journal.clear()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.active = False
        if exc_type is None:
            self.committed += 1
        else:
            for undoable in reversed(self._undoables):
                undo = getattr(undoable, "undo", None)
                if undo is not None:
                    undo()
            self.rolled_back += 1

    async def commit(self) -> None:
        self.committed += 1

    async def rollback(self) -> None:
        self.rolled_back += 1


@dataclass(frozen=True)
class FakeParts:
    """Typed bundle of fakes and the UnitOfWork under test."""

    uow: FakeUnitOfWork
    entities: FakeEntityRepository
    relationships: FakeRelationshipRepository
    observations: FakeObservationRepository
    evidence: FakeEvidenceRepository
    evidence_observation_entities: FakeEvidenceObservationEntityRepository
    investigation_evidence: FakeInvestigationEvidenceRepository
    investigations: FakeInvestigationRepository
    audit: FakeAuditRepository

    @staticmethod
    def build(investigation_id: UUID) -> "FakeParts":
        """Compose one deterministic fake UnitOfWork and its repositories."""
        entities = FakeEntityRepository()
        relationships = FakeRelationshipRepository()
        observations = FakeObservationRepository()
        evidence = FakeEvidenceRepository()
        evidence_observation_entities = FakeEvidenceObservationEntityRepository()
        investigation_evidence = FakeInvestigationEvidenceRepository()
        investigations = FakeInvestigationRepository({investigation_id})
        audit = FakeAuditRepository()
        uow = FakeUnitOfWork(
            entities=entities,
            relationships=relationships,
            relationship_observations=observations,
            evidence=evidence,
            evidence_observation_entities=evidence_observation_entities,
            investigation_evidence=investigation_evidence,
            investigations=investigations,
            audit_events=audit,
        )
        return FakeParts(
            uow=uow,
            entities=entities,
            relationships=relationships,
            observations=observations,
            evidence=evidence,
            evidence_observation_entities=evidence_observation_entities,
            investigation_evidence=investigation_evidence,
            investigations=investigations,
            audit=audit,
        )

    def factory(self) -> Callable[[], FakeUnitOfWork]:
        """Return the persistence service UnitOfWork factory."""
        return lambda: self.uow

    def service(self) -> ProviderObservationPersistenceService:
        """Return the service under test wired to this UnitOfWork factory."""
        return ProviderObservationPersistenceService(self.factory())


async def _persist(
    parts: FakeParts,
    converted: ConvertedEvidence | None = None,
    extraction: ExtractionResult | None = None,
) -> ProviderObservationPersistenceResult:
    """Run the service over one global fixture in the fake world."""
    investigation_id = next(iter(parts.investigations.visible))
    return await parts.service().persist(
        converted if converted is not None else converted_evidence(),
        invitation_entity(),
        extraction if extraction is not None else threatfox_extraction(),
        investigation_id=investigation_id,
    )


@pytest.mark.asyncio
async def test_preflight_failures_never_enter_the_unit_of_work() -> None:
    """Every preflight failure happens before any UnitOfWork is created."""
    scenarios = [
        (
            converted_evidence(),
            ExtractionResult(
                entities=(entity_builder(EntityType.DOMAIN, "Not.Canonical"),)
            ),
        ),  # non-canonical extracted entity
        (
            converted_evidence(),
            ExtractionResult(
                entities=(
                    entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),
                    entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),
                )
            ),
        ),  # duplicate extracted entity
        (
            converted_evidence(),
            ExtractionResult(
                relationships=(
                    RelationshipAssertion(
                        source=EntityIdentity(
                            type=EntityType.DOMAIN, value=_SUBJECT_VALUE
                        ),
                        type=RelationshipType.RESOLVES_TO,
                        target=EntityIdentity(
                            type=EntityType.DOMAIN, value="uncovered.test"
                        ),
                    ),
                )
            ),
        ),  # endpoint not covered
        (
            converted_evidence(),
            ExtractionResult(
                relationships=(
                    RelationshipAssertion(
                        source=EntityIdentity(
                            type=EntityType.DOMAIN, value=_SUBJECT_VALUE
                        ),
                        type=RelationshipType.RESOLVES_TO,
                        target=EntityIdentity(
                            type=EntityType.DOMAIN, value=_SUBJECT_VALUE
                        ),
                    ),
                    RelationshipAssertion(
                        source=EntityIdentity(
                            type=EntityType.DOMAIN, value=_SUBJECT_VALUE
                        ),
                        type=RelationshipType.RESOLVES_TO,
                        target=EntityIdentity(
                            type=EntityType.DOMAIN, value=_SUBJECT_VALUE
                        ),
                    ),
                )
            ),
        ),  # duplicate assertion
    ]
    for fixture_converted, extraction in scenarios:
        parts = FakeParts.build(uuid4())
        with pytest.raises(ValueError):
            await parts.service().persist(
                fixture_converted,
                invitation_entity(),
                extraction,
                investigation_id=next(iter(parts.investigations.visible)),
            )
        assert parts.uow.entered == 0
        assert not parts.entities.get_calls


@pytest.mark.asyncio
async def test_duplicate_assertion_is_rejected_in_preflight() -> None:
    """Duplicate assertions never reach the database; PR 18B output is deduplicated."""
    converted = converted_evidence()
    assertion = RelationshipAssertion(
        source=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
        type=RelationshipType.ASSOCIATED_WITH,
        target=EntityIdentity(type=EntityType.MALWARE, value="win.asyncrat"),
    )
    parts = FakeParts.build(uuid4())
    with pytest.raises(ValueError, match="duplicate relationship assertion"):
        await parts.service().persist(
            converted,
            invitation_entity(),
            ExtractionResult(
                entities=(entity_builder(EntityType.MALWARE, "win.asyncrat"),),
                relationships=(assertion, assertion),
            ),
            investigation_id=next(iter(parts.investigations.visible)),
        )
    assert parts.uow.entered == 0


@pytest.mark.asyncio
async def test_b2_p01_first_state_creates_complete_graph_once() -> None:
    """B2-P01: a successful first observation persists exactly once."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    result = await _persist(parts, converted, threatfox_extraction())

    assert parts.uow.committed == 1
    assert parts.uow.rolled_back == 0
    assert isinstance(result, ProviderObservationPersistenceResult)
    assert result.evidence.id == converted.evidence.id
    assert result.observation.evidence_id == converted.evidence.id
    assert result.observation.version == 1
    assert result.outcome is EvidencePersistenceOutcome.CREATED
    assert len(result.entities) == 2
    assert len(result.relationships) == 1
    assert len(result.observations) == 1
    assert result.observations[0].evidence_observation_id == result.observation.id
    assert result.observations[0].relationship_id == result.relationships[0].id
    # Exact admission of the observation into the Investigation.
    admitted = parts.investigation_evidence.admissions[
        next(iter(parts.investigations.visible))
    ]
    assert result.observation.id in admitted
    # Observation-level Entity associations (invocation target + discovered).
    associated = {
        entity_id
        for (obs, entity_id) in parts.evidence_observation_entities.pairs
        if obs == result.observation.id
    }
    assert len(associated) == 2
    assert len(parts.audit.events) == 1
    assert parts.audit.events[0].object_id == result.observation.id


@pytest.mark.asyncio
async def test_b2_p02_unchanged_reuses_existing_observation() -> None:
    """B2-P02: an unchanged material state reuses the existing observation."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    first = await _persist(parts, converted, threatfox_extraction())
    second = await _persist(parts, converted, threatfox_extraction())

    assert second.outcome is EvidencePersistenceOutcome.UNCHANGED
    assert second.observation.id == first.observation.id
    assert second.observation.version == 1
    assert len(parts.evidence.observations) == 1
    assert parts.uow.committed == 2


@pytest.mark.asyncio
async def test_b2_p03_changed_appends_exact_new_observation() -> None:
    """B2-P03: a material change appends the exact next observation version."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    first = await _persist(parts, converted, threatfox_extraction())
    changed = converted.model_copy(
        update={
            "observation": converted.observation.model_copy(
                update={"facts": {"matches": [{"malware": "win.trojan2"}]}}
            )
        }
    )
    second = await _persist(parts, changed, threatfox_extraction())

    assert second.outcome is EvidencePersistenceOutcome.APPENDED
    assert second.observation.id != first.observation.id
    assert second.observation.version == 2
    assert second.observation.evidence_id == converted.evidence.id
    assert len(parts.evidence.observations) == 2
    assert parts.evidence.observations[first.observation.id].version == 1


@pytest.mark.asyncio
async def test_b2_p04_unchanged_does_not_duplicate_relationship_observations() -> None:
    """B2-P04: unchanged state does not duplicate global RelationshipObservations."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    await _persist(parts, converted, threatfox_extraction())
    await _persist(parts, converted, threatfox_extraction())

    assert len(parts.observations.rows) == 1


@pytest.mark.asyncio
async def test_b2_p05_same_observation_two_investigations_admission_only() -> None:
    """B2-P05: a shared observation is admitted into a second Investigation."""
    first_investigation = uuid4()
    parts = FakeParts.build(first_investigation)
    converted = converted_evidence()
    await parts.service().persist(
        converted,
        invitation_entity(),
        threatfox_extraction(),
        investigation_id=first_investigation,
    )
    second_investigation = uuid4()
    parts.investigations.visible.add(second_investigation)
    await parts.service().persist(
        converted,
        invitation_entity(),
        threatfox_extraction(),
        investigation_id=second_investigation,
    )

    # One global observation and one global relationship observation.
    assert len(parts.evidence.observations) == 1
    assert len(parts.observations.rows) == 1
    # Two exact admissions.
    assert first_investigation in parts.investigation_evidence.admissions
    assert second_investigation in parts.investigation_evidence.admissions


@pytest.mark.asyncio
async def test_b2_p06_entity_associations_exact_and_deduplicated() -> None:
    """B2-P06: entities associate exactly once per observation (no roles)."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    await _persist(parts, converted, threatfox_extraction())

    associated_calls = parts.evidence_observation_entities.associate_calls
    obs_id = next(iter(parts.evidence.observations))
    entity_ids = {entity_id for (obs, entity_id) in associated_calls if obs == obs_id}
    # Invocation target IP + discovered MALWARE.
    assert len(entity_ids) == 2
    # No duplicate pairs.
    assert len(set(associated_calls)) == len(associated_calls)


@pytest.mark.asyncio
async def test_existing_entity_reuses_identity_and_retains_metadata() -> None:
    """Existing entities are reused; stored display metadata is retained."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    entities: FakeEntityRepository = parts.entities
    malware = await entities.upsert(
        Entity(
            type=EntityType.MALWARE,
            value="win.asyncrat",
            display_name="AsyncRAT",
        )
    )
    entities.upsert_calls.clear()
    result = await _persist(parts, converted, threatfox_extraction())

    persisted_malware = next(e for e in result.entities if e.value == "win.asyncrat")
    assert persisted_malware.id == malware.id
    assert persisted_malware.display_name == "AsyncRAT"
    assert entities.rows[(EntityType.MALWARE, "win.asyncrat")].version == 1


@pytest.mark.asyncio
async def test_empty_extraction_persists_evidence_only() -> None:
    """An empty extraction still persists the observation and its audit event."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    result = await _persist(parts, converted, ExtractionResult())

    assert result.observation.evidence_id == converted.evidence.id
    assert result.relationships == ()
    assert result.observations == ()
    assert len(result.entities) == 1  # only the invocation target
    assert parts.uow.committed == 1
    stored_obs_id = next(iter(parts.evidence.observations))
    assert result.observation.id == stored_obs_id
    assert len(parts.audit.events) == 1


@pytest.mark.asyncio
async def test_existing_relationship_is_reused_with_new_observation() -> None:
    """A repeated edge reuses the stable relationship and appends one observation."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    first = await _persist(parts, converted, threatfox_extraction())
    changed = converted.model_copy(
        update={
            "observation": converted.observation.model_copy(
                update={"observed_at": datetime(2026, 2, 1, 0, 0, tzinfo=UTC)}
            )
        }
    )
    relationships: FakeRelationshipRepository = parts.relationships
    relationships.upsert_calls.clear()
    second = await _persist(parts, changed, threatfox_extraction())

    assert second.outcome is EvidencePersistenceOutcome.APPENDED
    assert second.relationships[0].id == first.relationships[0].id
    assert len(relationships.upsert_calls) == 1
    assert second.observations[0].evidence_observation_id == second.observation.id
    assert second.observations[0].relationship_id == first.relationships[0].id


@pytest.mark.asyncio
async def test_assertions_are_persisted_in_deterministic_order() -> None:
    """Assertion writes follow the stable identity ordering, not input order."""
    converted = converted_evidence()
    second_ip = "198.51.100.7"
    assertions = (
        RelationshipAssertion(
            source=EntityIdentity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
            type=RelationshipType.RESOLVES_TO,
            target=EntityIdentity(type=EntityType.IP_ADDRESS, value=second_ip),
        ),
        RelationshipAssertion(
            source=EntityIdentity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
            type=RelationshipType.RESOLVES_TO,
            target=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
        ),
    )
    extraction = ExtractionResult(
        entities=(
            entity_builder(EntityType.DOMAIN, _SUBJECT_VALUE),
            entity_builder(EntityType.IP_ADDRESS, second_ip),
            entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),
        ),
        relationships=assertions,
    )
    converted_dns = converted_evidence(
        evidence_type=EvidenceType.DNS, source="urn:ati:source:threatfox"
    )
    parts = FakeParts.build(uuid4())
    # DNS-shaped extraction but the stable source stays the fixture source.
    result = await parts.service().persist(
        converted,
        Entity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
        extraction,
        investigation_id=next(iter(parts.investigations.visible)),
    )
    # Stable ordering is by canonical target value, not by input order.
    assert [r.target_entity_id for r in result.relationships] == [
        _entity_id(result, EntityType.IP_ADDRESS, second_ip),
        _entity_id(result, EntityType.IP_ADDRESS, _IP_VALUE),
    ]
    del converted_dns


def _entity_id(
    result: ProviderObservationPersistenceResult,
    entity_type: EntityType,
    value: str,
) -> UUID:
    """Return the persisted ID for one entity identity in a result."""
    match = next(
        e for e in result.entities if e.type is entity_type and e.value == value
    )
    assert match.id is not None  # persisted entities always have IDs
    return match.id


@pytest.mark.asyncio
async def test_duplicate_evidence_conflicts_and_rolls_back() -> None:
    """A replayed Evidence identity with conflicting stable metadata rolls back."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    await _persist(parts, converted, threatfox_extraction())

    conflicting = converted_evidence(
        evidence_id=converted.evidence.id,
        source_record_id="different-record",
    )
    with pytest.raises(ValueError):
        await parts.service().persist(
            conflicting,
            invitation_entity(),
            threatfox_extraction(),
            investigation_id=next(iter(parts.investigations.visible)),
        )
    assert parts.uow.rolled_back == 1
    # No new observation or relationship provenance from the conflict.
    assert len(parts.observations.rows) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("seam", "expected_stage"),
    [
        ("entity", "entity"),
        ("evidence", "evidence"),
        ("relationship", "relationship"),
        ("observation", "observation"),
        ("admission", "admission"),
        ("audit", "audit"),
    ],
)
async def test_injected_failure_at_each_stage_rolls_back(
    seam: str, expected_stage: str
) -> None:
    """A failure after any mutation stage rolls the whole observation back."""
    assert seam == expected_stage
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    if seam == "entity":
        parts.entities.fail_on_identity = (EntityType.MALWARE, "win.asyncrat")
    elif seam == "evidence":
        parts.evidence.fail = True
    elif seam == "relationship":
        parts.relationships.fail = True
    elif seam == "observation":
        parts.observations.fail = True
    elif seam == "admission":
        parts.investigation_evidence.fail = True
    else:
        parts.audit.fail = True
    with pytest.raises(RuntimeError, match="injected"):
        await parts.service().persist(
            converted,
            invitation_entity(),
            threatfox_extraction(),
            investigation_id=next(iter(parts.investigations.visible)),
        )
    assert parts.uow.committed == 0
    assert parts.uow.rolled_back == 1


@pytest.mark.asyncio
async def test_missing_investigation_is_a_typed_error_without_graph_work() -> None:
    """A missing investigation is rejected before any entity mutation."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())  # no visible investigation
    with pytest.raises(InvestigationNotFoundError):
        await parts.service().persist(
            converted,
            invitation_entity(),
            threatfox_extraction(),
            investigation_id=uuid4(),
        )
    assert parts.uow.rolled_back == 1
    assert not parts.entities.upsert_calls
    assert not parts.evidence.observations


@pytest.mark.asyncio
async def test_soft_deleted_entity_is_a_fail_closed_error() -> None:
    """Rediscovery of a soft-deleted entity raises the typed policy error."""
    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    entities: FakeEntityRepository = parts.entities
    existing = await entities.upsert(
        Entity(type=EntityType.MALWARE, value="win.asyncrat")
    )
    assert existing.id is not None  # the fake assigns IDs
    await entities.soft_delete(existing.id)
    entities.upsert_calls.clear()
    with pytest.raises(SoftDeletedIdentityError):
        await parts.service().persist(
            converted,
            invitation_entity(),
            threatfox_extraction(),
            investigation_id=next(iter(parts.investigations.visible)),
        )
    assert parts.uow.rolled_back == 1
    assert len(parts.evidence.observations) == 0
    assert entities.rows[(EntityType.MALWARE, "win.asyncrat")].deleted_at is not None


@pytest.mark.asyncio
async def test_soft_deleted_relationship_is_a_fail_closed_error() -> None:
    """Rediscovery of a soft-deleted relationship raises the typed policy error."""

    class SoftDeletedRelationships(FakeRelationshipRepository):
        """Simulate the database rejecting a soft-deleted edge rediscovery."""

        async def upsert(
            self, relationship: Relationship, *, expected_version: int | None = None
        ) -> Relationship:
            raise SoftDeletedIdentityError("relationship", relationship.id)

    converted = converted_evidence()
    first_parts = FakeParts.build(uuid4())
    failing_uow = FakeUnitOfWork(
        entities=first_parts.entities,
        relationships=SoftDeletedRelationships(),
        relationship_observations=first_parts.observations,
        evidence=first_parts.evidence,
        evidence_observation_entities=first_parts.evidence_observation_entities,
        investigation_evidence=first_parts.investigation_evidence,
        investigations=first_parts.investigations,
        audit_events=first_parts.audit,
    )

    def factory() -> FakeUnitOfWork:
        return failing_uow

    service = ProviderObservationPersistenceService(factory)
    with pytest.raises(SoftDeletedIdentityError):
        await service.persist(
            converted,
            invitation_entity(),
            threatfox_extraction(),
            investigation_id=next(iter(first_parts.investigations.visible)),
        )
    assert failing_uow.rolled_back == 1
    assert first_parts.uow.committed == 0


@pytest.mark.asyncio
async def test_actor_and_request_correlation_is_propagated() -> None:
    """Actor and request identifiers reach the audit event on the observation."""
    converted = converted_evidence()
    actor_id, request_id = uuid4(), uuid4()
    parts = FakeParts.build(uuid4())
    investigation_id = next(iter(parts.investigations.visible))
    await parts.service().persist(
        converted,
        invitation_entity(),
        threatfox_extraction(),
        investigation_id=investigation_id,
        actor_id=actor_id,
        request_id=request_id,
    )
    audit_event = parts.audit.events[0]
    assert audit_event.actor_id == actor_id
    assert audit_event.request_id == request_id
    assert audit_event.outcome is AuditOutcome.SUCCESS
    assert "outcome" in audit_event.metadata


@pytest.mark.asyncio
async def test_b2_p10_cancellation_propagates_and_rolls_back() -> None:
    """B2-P10: cancellation propagates and the active UoW rolls back."""

    class CancellingEntityRepository(FakeEntityRepository):
        async def upsert(
            self, entity: Entity, *, expected_version: int | None = None
        ) -> Entity:
            raise asyncio.CancelledError()

    import asyncio

    converted = converted_evidence()
    parts = FakeParts.build(uuid4())
    uow = FakeUnitOfWork(
        entities=CancellingEntityRepository(),
        relationships=parts.relationships,
        relationship_observations=parts.observations,
        evidence=parts.evidence,
        evidence_observation_entities=parts.evidence_observation_entities,
        investigation_evidence=parts.investigation_evidence,
        investigations=parts.investigations,
        audit_events=parts.audit,
    )
    service = ProviderObservationPersistenceService(lambda: uow)
    with pytest.raises(asyncio.CancelledError):
        await service.persist(
            converted,
            invitation_entity(),
            threatfox_extraction(),
            investigation_id=next(iter(parts.investigations.visible)),
        )
    assert uow.rolled_back == 1
    assert uow.committed == 0
