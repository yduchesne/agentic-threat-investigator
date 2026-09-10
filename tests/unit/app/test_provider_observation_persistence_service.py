# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the provider-observation persistence service boundary.

Fakes replace every repository and the UnitOfWork, proving that preflight
performs zero database work, that repositories never own the transaction
lifecycle, and that every failure path rolls the whole observation back.
"""

# Fixture arguments intentionally reuse fixture names, and the fake
# repositories deliberately mirror the production contracts.
# Pylint sees the fake ABCs and builders as structural boilerplate.
# pylint: disable=redefined-outer-name,too-many-arguments
# pylint: disable=too-few-public-methods,too-many-instance-attributes

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
    EntityRepository,
    EvidenceDuplicateIdentityError,
    EvidenceRepository,
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

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_SUBJECT_VALUE = "malicious-domain.test"
_IP_VALUE = "203.0.113.42"


def entity_builder(
    entity_type: EntityType, value: str, display_name: str | None = None
) -> ExtractedEntity:
    """Build a canonical discovered entity."""
    return ExtractedEntity(type=entity_type, value=value, display_name=display_name)


def dns_extraction(evidence_id: UUID | None) -> ExtractionResult:
    """Build the canonical DNS extraction for the fixture Evidence."""
    assert evidence_id is not None  # noqa: S101 - callers build persisted Evidence
    return ExtractionResult(
        entities=(entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),),
        relationships=(
            RelationshipAssertion(
                source=EntityIdentity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
                type=RelationshipType.RESOLVES_TO,
                target=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
                evidence_id=evidence_id,
            ),
        ),
    )


def evidence_builder(**overrides: object) -> Evidence:
    """Build a deterministic canonical Evidence observation."""
    values: dict[str, object] = {
        "id": uuid4(),
        "investigation_id": uuid4(),
        "type": EvidenceType.DNS,
        "subject": EntityRef(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
        "source": "urn:ati:source:google_public_dns",
        "observed_at": None,
        "retrieved_at": _RETRIEVED_AT,
        "facts": {"answers": [_IP_VALUE], "status": 0},
        "raw_payload": None,
    }
    values.update(overrides)
    return Evidence(**values)  # type: ignore[arg-type]


def require_id(evidence: Evidence) -> UUID:
    """Narrow the optional Evidence identity for assertion construction."""
    assert evidence.id is not None  # noqa: S101 - builders always set one
    return evidence.id


class FakeEntityRepository(EntityRepository):
    """In-memory entity repository with an injected failure seam."""

    def __init__(self) -> None:
        self.rows: dict[tuple[EntityType, str], Entity] = {}
        self.upsert_calls: list[Entity] = []
        self.get_calls: list[tuple[str, str]] = []
        self.fail_on_identity: tuple[EntityType, str] | None = None

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
        self.rows[key] = written
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

    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        if self.fail:
            raise RuntimeError("injected observation failure")
        self.rows.append(observation)
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
        """Return the immutable observation with the given identity, if any."""
        return next((row for row in self.rows if row.id == observation_id), None)


class FakeEvidenceRepository(EvidenceRepository):
    """Append-only evidence fake with duplicate and failure seams."""

    def __init__(self) -> None:
        self.existing_ids: set[UUID] = set()
        self.inserted: list[Evidence] = []
        self.calls: list[tuple[UUID | None, UUID | None]] = []
        self.fail = False

    async def insert(
        self,
        evidence: Evidence,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Evidence:
        assert evidence.id is not None  # noqa: S101 - preflight guarantees it
        self.calls.append((actor_id, request_id))
        if self.fail:
            raise RuntimeError("injected evidence failure")
        if evidence.id in self.existing_ids:
            raise EvidenceDuplicateIdentityError(evidence.id)
        self.existing_ids.add(evidence.id)
        self.inserted.append(evidence)
        return evidence

    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        return next((e for e in self.inserted if e.id == evidence_id), None)

    async def list_for_investigation(
        self, investigation_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[Evidence]:
        return [e for e in self.inserted if e.investigation_id == investigation_id]


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

    async def soft_delete(self, *args: object, **_: object) -> InvestigationWriteResult:
        raise NotImplementedError


class FakeAuditRepository(AuditEventRepository):
    """Audit fake with an injected failure seam."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self.fail = False

    async def append(self, event: AuditEvent) -> AuditEvent:
        if self.fail:
            raise RuntimeError("injected audit failure")
        self.events.append(event)
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
        investigations: FakeInvestigationRepository,
        audit_events: FakeAuditRepository,
    ) -> None:
        self.entities: EntityRepository = entities
        self.relationships: RelationshipRepository = relationships
        self.relationship_observations: RelationshipObservationRepository = (
            relationship_observations
        )
        self.evidence: EvidenceRepository = evidence
        self.investigations: InvestigationRepository = investigations
        self.audit_events: AuditEventRepository = audit_events
        self.entered = 0
        self.committed = 0
        self.rolled_back = 0
        self.active = False

    async def __aenter__(self) -> Self:
        self.entered += 1
        self.active = True
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
    investigations: FakeInvestigationRepository
    audit: FakeAuditRepository

    @staticmethod
    def build(investigation_id: UUID) -> "FakeParts":
        """Compose one deterministic fake UnitOfWork and its repositories."""
        entities = FakeEntityRepository()
        relationships = FakeRelationshipRepository()
        observations = FakeObservationRepository()
        evidence = FakeEvidenceRepository()
        investigations = FakeInvestigationRepository({investigation_id})
        audit = FakeAuditRepository()
        uow = FakeUnitOfWork(
            entities=entities,
            relationships=relationships,
            relationship_observations=observations,
            evidence=evidence,
            investigations=investigations,
            audit_events=audit,
        )
        return FakeParts(
            uow=uow,
            entities=entities,
            relationships=relationships,
            observations=observations,
            evidence=evidence,
            investigations=investigations,
            audit=audit,
        )

    def factory(self) -> Callable[[], FakeUnitOfWork]:
        """Return the persistence service UnitOfWork factory."""
        return lambda: self.uow

    def service(self) -> ProviderObservationPersistenceService:
        """Return the service under test wired to this UnitOfWork factory."""
        return ProviderObservationPersistenceService(self.factory())


@pytest.mark.asyncio
async def test_preflight_failures_never_enter_the_unit_of_work() -> None:
    """Every preflight failure happens before any UnitOfWork is created."""
    evidence = evidence_builder(id=None)
    scenarios = [
        (evidence, dns_extraction(uuid4())),  # evidence id missing
        (
            evidence_builder(
                subject=EntityRef(
                    type=EntityType.DOMAIN, value="Malicious-Domain.Test."
                )
            ),
            ExtractionResult(),
        ),  # non-canonical subject
        (
            evidence_builder(),
            ExtractionResult(
                entities=(entity_builder(EntityType.DOMAIN, "Not.Canonical"),)
            ),
        ),  # non-canonical extracted entity
        (
            evidence_builder(),
            ExtractionResult(
                entities=(
                    entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),
                    entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),
                )
            ),
        ),  # duplicate extracted entity
        (
            evidence_builder(),
            ExtractionResult(
                relationships=(
                    RelationshipAssertion(
                        source=EntityIdentity(
                            type=EntityType.DOMAIN, value=_SUBJECT_VALUE
                        ),
                        type=RelationshipType.RESOLVES_TO,
                        target=EntityIdentity(
                            type=EntityType.IP_ADDRESS, value=_IP_VALUE
                        ),
                        evidence_id=uuid4(),
                    ),
                )
            ),
        ),  # assertion evidence id mismatch
        (
            evidence_builder(),
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
                        evidence_id=uuid4(),
                    ),
                )
            ),
        ),  # endpoint not covered
    ]
    for scenario_evidence, extraction in scenarios:
        investigation_id = scenario_evidence.investigation_id
        parts = FakeParts.build(investigation_id)
        service = ProviderObservationPersistenceService(parts.factory())
        with pytest.raises(ValueError):
            await service.persist(scenario_evidence, extraction)
        assert parts.uow.entered == 0
        assert not parts.entities.get_calls


@pytest.mark.asyncio
async def test_duplicate_assertion_is_rejected_in_preflight() -> None:
    """Duplicate assertions never reach the database; PR 18B output is deduplicated."""
    evidence = evidence_builder()
    assertion = RelationshipAssertion(
        source=EntityIdentity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
        type=RelationshipType.RESOLVES_TO,
        target=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
        evidence_id=require_id(evidence),
    )
    parts = FakeParts.build(evidence.investigation_id)
    service = ProviderObservationPersistenceService(parts.factory())
    with pytest.raises(ValueError, match="duplicate relationship assertion"):
        await service.persist(
            evidence,
            ExtractionResult(
                entities=(entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),),
                relationships=(assertion, assertion),
            ),
        )
    assert parts.uow.entered == 0


@pytest.mark.asyncio
async def test_new_observation_persists_the_complete_graph_once() -> None:
    """A successful observation commits exactly once with durable identities."""
    evidence = evidence_builder()
    parts = FakeParts.build(evidence.investigation_id)
    service = ProviderObservationPersistenceService(parts.factory())
    result = await service.persist(evidence, dns_extraction(evidence.id))

    assert parts.uow.committed == 1
    assert parts.uow.rolled_back == 0
    assert result.evidence.id == evidence.id
    assert [e.type for e in result.entities] == [
        EntityType.DOMAIN,
        EntityType.IP_ADDRESS,
    ]
    assert len(result.relationships) == 1
    assert len(result.observations) == 1
    assert result.observations[0].evidence_id == evidence.id
    assert result.observations[0].relationship_id == result.relationships[0].id
    assert result.observations[0].investigation_id == evidence.investigation_id
    assert result.observations[0].source == evidence.source
    assert len(parts.audit.events) == 1
    assert parts.audit.events[0].object_id == evidence.id


@pytest.mark.asyncio
async def test_existing_subject_reuses_identity_and_retains_metadata() -> None:
    """Existing entities are reused; stored display metadata is retained."""
    evidence = evidence_builder()
    parts = FakeParts.build(evidence.investigation_id)
    entities: FakeEntityRepository = parts.entities
    stored = await entities.upsert(
        Entity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE, display_name="Stored Name")
    )
    entities.upsert_calls.clear()
    service = ProviderObservationPersistenceService(parts.factory())
    result = await service.persist(evidence, dns_extraction(evidence.id))

    subject_entity = next(e for e in result.entities if e.value == _SUBJECT_VALUE)
    assert subject_entity.id == stored.id
    assert subject_entity.display_name == "Stored Name"
    # Re-persisting identical metadata must not version-bump the identity.
    assert entities.rows[(EntityType.DOMAIN, _SUBJECT_VALUE)].version == 1


@pytest.mark.asyncio
async def test_discovered_subject_display_metadata_is_not_lost() -> None:
    """When the subject and a discovery share an identity, discovery metadata wins."""
    evidence = evidence_builder()
    extraction = ExtractionResult(
        entities=(
            entity_builder(
                EntityType.DOMAIN, _SUBJECT_VALUE, display_name="Discovered"
            ),
            entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),
        ),
        relationships=(
            RelationshipAssertion(
                source=EntityIdentity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
                type=RelationshipType.RESOLVES_TO,
                target=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
                evidence_id=require_id(evidence),
            ),
        ),
    )
    parts = FakeParts.build(evidence.investigation_id)
    service = ProviderObservationPersistenceService(parts.factory())
    result = await service.persist(evidence, extraction)
    subject_entity = next(e for e in result.entities if e.value == _SUBJECT_VALUE)
    assert subject_entity.display_name == "Discovered"


@pytest.mark.asyncio
async def test_supplied_display_metadata_follows_extraction() -> None:
    """A supplied extraction display name is passed to the entity upsert."""
    evidence = evidence_builder(
        subject=EntityRef(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
        type=EvidenceType.THREAT_INTELLIGENCE,
        source="urn:ati:source:threatfox",
        facts={
            "matches": [{"malware": "win.asyncrat", "malware_printable": "AsyncRAT"}]
        },
    )
    extraction = ExtractionResult(
        entities=(
            entity_builder(EntityType.MALWARE, "win.asyncrat", display_name="AsyncRAT"),
        ),
        relationships=(
            RelationshipAssertion(
                source=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
                type=RelationshipType.ASSOCIATED_WITH,
                target=EntityIdentity(type=EntityType.MALWARE, value="win.asyncrat"),
                evidence_id=require_id(evidence),
            ),
        ),
    )
    parts = FakeParts.build(evidence.investigation_id)
    service = ProviderObservationPersistenceService(parts.factory())
    result = await service.persist(evidence, extraction)
    malware = next(e for e in result.entities if e.type is EntityType.MALWARE)
    assert malware.display_name == "AsyncRAT"


@pytest.mark.asyncio
async def test_empty_extraction_persists_evidence_only() -> None:
    """An empty extraction still persists the Evidence and its audit event."""
    evidence = evidence_builder()
    parts = FakeParts.build(evidence.investigation_id)
    service = ProviderObservationPersistenceService(parts.factory())
    result = await service.persist(evidence, ExtractionResult())
    assert result.evidence.id == evidence.id
    assert result.relationships == ()
    assert result.observations == ()
    assert len(result.entities) == 1
    assert parts.uow.committed == 1
    assert len(parts.audit.events) == 1


@pytest.mark.asyncio
async def test_existing_relationship_is_reused_with_new_observation() -> None:
    """A repeated edge reuses the stable relationship and appends one observation."""
    evidence = evidence_builder()
    parts = FakeParts.build(evidence.investigation_id)
    service = ProviderObservationPersistenceService(parts.factory())
    first = await service.persist(evidence, dns_extraction(evidence.id))

    second_evidence = evidence_builder(
        investigation_id=evidence.investigation_id,
        facts={"answers": [_IP_VALUE], "status": 0},
    )
    relationships: FakeRelationshipRepository = parts.relationships
    relationships.upsert_calls.clear()
    second = await service.persist(
        second_evidence, dns_extraction(require_id(second_evidence))
    )

    assert second.relationships[0].id == first.relationships[0].id
    assert len(relationships.upsert_calls) == 1
    assert second.observations[0].evidence_id == second_evidence.id
    assert second.observations[0].relationship_id == first.relationships[0].id


@pytest.mark.asyncio
async def test_assertions_are_persisted_in_deterministic_order() -> None:
    """Assertion writes follow the stable identity ordering, not input order."""
    evidence = evidence_builder()
    second_ip = "198.51.100.7"
    assertions = (
        RelationshipAssertion(
            source=EntityIdentity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
            type=RelationshipType.RESOLVES_TO,
            target=EntityIdentity(type=EntityType.IP_ADDRESS, value=second_ip),
            evidence_id=require_id(evidence),
        ),
        RelationshipAssertion(
            source=EntityIdentity(type=EntityType.DOMAIN, value=_SUBJECT_VALUE),
            type=RelationshipType.RESOLVES_TO,
            target=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP_VALUE),
            evidence_id=require_id(evidence),
        ),
    )
    extraction = ExtractionResult(
        entities=(
            entity_builder(EntityType.IP_ADDRESS, second_ip),
            entity_builder(EntityType.IP_ADDRESS, _IP_VALUE),
        ),
        relationships=assertions,
    )
    parts = FakeParts.build(evidence.investigation_id)
    service = ProviderObservationPersistenceService(parts.factory())
    result = await service.persist(evidence, extraction)
    # Stable ordering is by canonical target value, not by input order.
    assert [r.target_entity_id for r in result.relationships] == [
        _entity_id(result, EntityType.IP_ADDRESS, second_ip),
        _entity_id(result, EntityType.IP_ADDRESS, _IP_VALUE),
    ]


def _entity_id(
    result: ProviderObservationPersistenceResult,
    entity_type: EntityType,
    value: str,
) -> UUID:
    """Return the persisted ID for one entity identity in a result."""
    match = next(
        e for e in result.entities if e.type is entity_type and e.value == value
    )
    assert match.id is not None  # noqa: S101 - persisted entities always have IDs
    return match.id


@pytest.mark.asyncio
async def test_duplicate_evidence_conflicts_and_rolls_back() -> None:
    """A replayed Evidence ID is a typed conflict with full rollback."""
    evidence = evidence_builder()
    parts = FakeParts.build(evidence.investigation_id)
    service = ProviderObservationPersistenceService(parts.factory())
    await service.persist(evidence, dns_extraction(evidence.id))

    replay = evidence_builder(
        id=evidence.id, investigation_id=evidence.investigation_id
    )
    with pytest.raises(EvidenceDuplicateIdentityError):
        await service.persist(replay, dns_extraction(require_id(replay)))
    assert parts.uow.rolled_back == 1
    observations: FakeObservationRepository = parts.observations
    # No new observation may be appended by the replay, and the original
    # observation from the first successful persist remains intact.
    assert len(observations.rows) == 1
    assert observations.rows[0].evidence_id == evidence.id
    inserted_with_replay_id = [e for e in parts.evidence.inserted if e.id == replay.id]
    assert len(inserted_with_replay_id) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("seam", "expected_stage"),
    [
        ("entity", "entity"),
        ("evidence", "evidence"),
        ("relationship", "relationship"),
        ("observation", "observation"),
        ("audit", "audit"),
    ],
)
async def test_injected_failure_at_each_stage_rolls_back(
    seam: str, expected_stage: str
) -> None:
    """A failure after any mutation stage rolls the whole observation back."""
    assert seam == expected_stage
    evidence = evidence_builder()
    parts = FakeParts.build(evidence.investigation_id)
    if seam == "entity":
        parts.entities.fail_on_identity = (
            EntityType.DOMAIN,
            _SUBJECT_VALUE,
        )
    elif seam == "evidence":
        parts.evidence.fail = True
    elif seam == "relationship":
        parts.relationships.fail = True
    elif seam == "observation":
        parts.observations.fail = True
    else:
        parts.audit.fail = True
    service = ProviderObservationPersistenceService(parts.factory())
    with pytest.raises(RuntimeError, match="injected"):
        await service.persist(evidence, dns_extraction(evidence.id))
    assert parts.uow.committed == 0
    assert parts.uow.rolled_back == 1


@pytest.mark.asyncio
async def test_missing_investigation_is_a_typed_error_without_graph_work() -> None:
    """A missing investigation is rejected before any entity mutation."""
    evidence = evidence_builder()
    parts = FakeParts.build(uuid4())  # no visible investigation
    service = ProviderObservationPersistenceService(parts.factory())
    with pytest.raises(InvestigationNotFoundError):
        await service.persist(evidence, dns_extraction(evidence.id))
    assert parts.uow.rolled_back == 1
    assert not parts.entities.upsert_calls
    assert not parts.evidence.inserted


@pytest.mark.asyncio
async def test_soft_deleted_entity_is_a_fail_closed_error() -> None:
    """Rediscovery of a soft-deleted entity raises the typed policy error."""
    evidence = evidence_builder()
    parts = FakeParts.build(evidence.investigation_id)
    entities: FakeEntityRepository = parts.entities
    existing = await entities.upsert(
        Entity(type=EntityType.IP_ADDRESS, value=_IP_VALUE)
    )
    assert existing.id is not None  # noqa: S101 - the fake assigns IDs
    await entities.soft_delete(existing.id)
    entities.upsert_calls.clear()
    service = ProviderObservationPersistenceService(parts.factory())
    with pytest.raises(SoftDeletedIdentityError):
        await service.persist(evidence, dns_extraction(evidence.id))
    assert parts.uow.rolled_back == 1
    assert not parts.evidence.inserted
    assert entities.rows[(EntityType.IP_ADDRESS, _IP_VALUE)].deleted_at is not None


@pytest.mark.asyncio
async def test_soft_deleted_relationship_is_a_fail_closed_error() -> None:
    """Rediscovery of a soft-deleted relationship raises the typed policy error."""
    evidence = evidence_builder()
    parts = FakeParts.build(evidence.investigation_id)

    class SoftDeletedRelationships(FakeRelationshipRepository):
        """Simulate the database rejecting a soft-deleted edge rediscovery."""

        async def upsert(
            self, relationship: Relationship, *, expected_version: int | None = None
        ) -> Relationship:
            raise SoftDeletedIdentityError("relationship", relationship.id)

    failing_uow = FakeUnitOfWork(
        entities=parts.entities,
        relationships=SoftDeletedRelationships(),
        relationship_observations=parts.observations,
        evidence=parts.evidence,
        investigations=parts.investigations,
        audit_events=parts.audit,
    )

    def factory() -> FakeUnitOfWork:
        return failing_uow

    service = ProviderObservationPersistenceService(factory)
    with pytest.raises(SoftDeletedIdentityError):
        await service.persist(evidence, dns_extraction(evidence.id))
    assert failing_uow.rolled_back == 1
    assert parts.uow.committed == 0


@pytest.mark.asyncio
async def test_actor_and_request_correlation_is_propagated() -> None:
    """Actor and request identifiers reach the evidence write and the audit event."""
    evidence = evidence_builder()
    actor_id, request_id = uuid4(), uuid4()
    parts = FakeParts.build(evidence.investigation_id)
    service = ProviderObservationPersistenceService(parts.factory())
    await service.persist(
        evidence, dns_extraction(evidence.id), actor_id=actor_id, request_id=request_id
    )
    assert parts.evidence.calls == [(actor_id, request_id)]
    audit_event = parts.audit.events[0]
    assert audit_event.actor_id == actor_id
    assert audit_event.request_id == request_id
    assert audit_event.outcome is AuditOutcome.SUCCESS
