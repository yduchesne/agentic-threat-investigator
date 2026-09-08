# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL integration coverage for immutable evidence persistence."""

# pylint: disable=redefined-outer-name

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.investigation_persistence import (
    InvestigationPersistenceService,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceDuplicateIdentityError,
    InvestigationNotFoundError,
)
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
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.relationship_repositories import (
    PostgresEvidenceRepository,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


async def seed_investigation(
    uow: PostgresUnitOfWork,
) -> tuple[UUID, UUID]:
    """Create one visible investigation and one canonical subject entity."""
    investigation_id = uuid4()
    await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[uuid4()],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
        )
    )
    entity = await uow.entities.upsert(
        Entity(type=EntityType.DOMAIN, value="Example.COM.")
    )
    assert entity.id is not None
    return investigation_id, entity.id


def evidence_factory(
    investigation_id: UUID, entity_id: UUID, **overrides: object
) -> Evidence:
    """Build a deterministic valid evidence observation."""
    values: dict[str, object] = {
        "investigation_id": investigation_id,
        "type": EvidenceType.DNS,
        "subject": EntityRef(id=entity_id, type=EntityType.DOMAIN, value="example.com"),
        "source": "urn:ati:source:google_public_dns",
        "observed_at": None,
        "retrieved_at": _RETRIEVED_AT,
        "facts": {"answers": ["192.0.2.1", "192.0.2.2"], "status": 0},
        "raw_payload": None,
        "source_record_id": None,
    }
    values.update(overrides)
    return Evidence(**values)  # type: ignore[arg-type]


async def evidence_history_rows(
    uow: PostgresUnitOfWork, evidence_id: UUID
) -> list[tuple[int, str]]:
    """Return bounded (version, operation) history rows for one observation."""
    assert uow.session is not None
    result = await uow.session.execute(
        text("""
            SELECT version, operation FROM ati.domain_object_history
            WHERE object_type = 'evidence' AND object_id = :id
            ORDER BY version
        """),
        {"id": evidence_id},
    )
    return [(row[0], row[1]) for row in result.fetchall()]


async def evidence_row_count(uow: PostgresUnitOfWork) -> int:
    """Count all evidence rows."""
    assert uow.session is not None
    result = await uow.session.execute(text("SELECT count(*) FROM ati.evidence"))
    return int(result.scalar_one())


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_insert_read_round_trip(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Insert persists the observation exactly as normalized at the boundary."""
    async with uow_factory() as uow:
        investigation_id, entity_id = await seed_investigation(uow)
        evidence = evidence_factory(
            investigation_id,
            entity_id,
            source_record_id="synthetic-record-1",
            observed_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
            raw_payload={"status": 0, "comment": "synthetic"},
        )

        recorded = await uow.evidence.insert(
            evidence, actor_id=uuid4(), request_id=uuid4()
        )
        assert recorded.id is not None

        stored = await uow.evidence.get_by_id(recorded.id)
        assert stored is not None
        assert stored.id == recorded.id
        assert stored.investigation_id == investigation_id
        assert stored.type is EvidenceType.DNS
        # The subject is rebuilt from the canonical entity identity.
        assert stored.subject.id == entity_id
        assert stored.subject.type is EntityType.DOMAIN
        assert stored.subject.value == "example.com"
        assert stored.source == "urn:ati:source:google_public_dns"
        assert stored.source_record_id == "synthetic-record-1"
        assert stored.observed_at == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert stored.retrieved_at == _RETRIEVED_AT
        # Facts round trip through JSONB without reinterpretation.
        assert stored.facts["answers"] == ("192.0.2.1", "192.0.2.2")
        assert stored.facts["status"] == 0
        assert stored.raw_payload is not None
        assert stored.raw_payload["comment"] == "synthetic"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_null_fields_round_trip(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Nullable provenance fields and an absent raw payload round trip as NULL."""
    async with uow_factory() as uow:
        investigation_id, entity_id = await seed_investigation(uow)
        recorded = await uow.evidence.insert(
            evidence_factory(investigation_id, entity_id)
        )
        assert recorded.id is not None

        stored = await uow.evidence.get_by_id(recorded.id)
        assert stored is not None
        assert stored.source_record_id is None
        assert stored.source_url is None
        assert stored.observed_at is None
        assert stored.raw_payload is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_write_writes_create_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Immutable evidence receives exactly one CREATE history entry."""
    async with uow_factory() as uow:
        investigation_id, entity_id = await seed_investigation(uow)
        recorded = await uow.evidence.insert(
            evidence_factory(investigation_id, entity_id)
        )
        assert recorded.id is not None
        assert await evidence_history_rows(uow, recorded.id) == [(1, "CREATE")]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_second_retrieval_creates_distinct_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Separate retrievals create separate immutable observations."""
    async with uow_factory() as uow:
        investigation_id, entity_id = await seed_investigation(uow)
        first = await uow.evidence.insert(
            evidence_factory(
                investigation_id,
                entity_id,
                retrieved_at=_RETRIEVED_AT,
                facts={"answers": ["192.0.2.1"]},
            )
        )
        second = await uow.evidence.insert(
            evidence_factory(
                investigation_id,
                entity_id,
                retrieved_at=_RETRIEVED_AT + timedelta(minutes=5),
                facts={"answers": ["192.0.2.1", "192.0.2.9"]},
            )
        )
        assert first.id != second.id
        assert first.id is not None and second.id is not None
        stored_first = await uow.evidence.get_by_id(first.id)
        stored_second = await uow.evidence.get_by_id(second.id)
        assert stored_first is not None and stored_second is not None
        assert stored_first.facts["answers"] == ("192.0.2.1",)
        assert stored_second.facts["answers"] == ("192.0.2.1", "192.0.2.9")
        assert await evidence_row_count(uow) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_duplicate_evidence_identity_never_mutates(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A duplicate evidence identity is a conflict, never an update."""
    async with uow_factory() as uow:
        investigation_id, entity_id = await seed_investigation(uow)
        evidence = evidence_factory(investigation_id, entity_id)
        first = await uow.evidence.insert(evidence)
        assert first.id is not None

    async with uow_factory() as uow:
        # The stored function raises a typed conflict; the caller rolls back
        # the surrounding unit of work.
        with pytest.raises(EvidenceDuplicateIdentityError):
            await uow.evidence.insert(
                evidence.model_copy(
                    update={"facts": {"answers": ["mutated"]}, "id": first.id}
                )
            )

    async with uow_factory() as uow:
        # The prior observation and its history remain untouched.
        assert first.id is not None
        original = await uow.evidence.get_by_id(first.id)
        assert original is not None
        assert original.facts["answers"] == ("192.0.2.1", "192.0.2.2")
        assert await evidence_history_rows(uow, first.id) == [(1, "CREATE")]
        assert await evidence_row_count(uow) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_requires_existing_investigation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Evidence for an unknown investigation is rejected via the service."""
    service = InvestigationPersistenceService(uow_factory)
    async with uow_factory() as uow:
        entity = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert entity.id is not None
        entity_id = entity.id

    evidence = evidence_factory(uuid4(), entity_id)
    with pytest.raises(InvestigationNotFoundError):
        await service.record_evidence(evidence, actor_id=uuid4())

    async with uow_factory() as uow:
        assert await evidence_row_count(uow) == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_list_for_investigation_is_deterministic(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The listing contract is deterministic and newest-first."""
    async with uow_factory() as uow:
        investigation_id, entity_id = await seed_investigation(uow)
        older = await uow.evidence.insert(
            evidence_factory(
                investigation_id,
                entity_id,
                retrieved_at=_RETRIEVED_AT,
            )
        )
        newer = await uow.evidence.insert(
            evidence_factory(
                investigation_id,
                entity_id,
                retrieved_at=_RETRIEVED_AT + timedelta(minutes=5),
            )
        )
        assert older.id is not None and newer.id is not None

        observations = await uow.evidence.list_for_investigation(investigation_id)
        assert [observation.id for observation in observations] == [
            newer.id,
            older.id,
        ]

        paged = await uow.evidence.list_for_investigation(
            investigation_id, limit=1, offset=1
        )
        assert [observation.id for observation in paged] == [older.id]

        # Repeated queries return identical deterministic results.
        repeated = await uow.evidence.list_for_investigation(investigation_id)
        assert [observation.id for observation in repeated] == [
            newer.id,
            older.id,
        ]
        # Observations of another investigation never appear.
        assert await uow.evidence.list_for_investigation(uuid4()) == []


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_repository_has_no_mutation_surface(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The normal repository exposes no update or delete operation."""
    async with uow_factory() as uow:
        evidence_repository = uow.evidence
        assert isinstance(evidence_repository, PostgresEvidenceRepository)
        assert not hasattr(evidence_repository, "update")
        assert not hasattr(evidence_repository, "delete")
        assert not hasattr(evidence_repository, "soft_delete")
        assert not hasattr(evidence_repository, "upsert")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_rollback_leaves_no_row(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An uncommitted evidence insert disappears after rollback."""
    async with uow_factory() as uow:
        investigation_id, entity_id = await seed_investigation(uow)
        evidence = evidence_factory(investigation_id, entity_id)

    with pytest.raises(RuntimeError, match="injected failure"):
        async with uow_factory() as uow:
            await uow.evidence.insert(evidence)
            raise RuntimeError("injected failure")

    async with uow_factory() as uow:
        assert await evidence_row_count(uow) == 0
        stored = await uow.evidence.get_by_id(evidence.id or uuid4())
        assert stored is None
