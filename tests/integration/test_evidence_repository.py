# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL coverage for the PR 28B global Evidence repository.

Every scenario persists synthetic, deterministic global ``ConvertedEvidence``
through the exact ``EvidenceRepository`` against the isolated migrated
database, asserting atomic Evidence + observation v1 creation, DB-owned
race-safe versions, material no-op/append semantics, exact observation
reads, line-item admission, deterministic listing, typed conflicts, and
the absence of any generic Evidence history.
"""

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.investigation_persistence import (
    InvestigationPersistenceService,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceMetadataConflictError,
    EvidencePersistenceOutcome,
    InvestigationNotFoundError,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservation,
    EvidenceObservationCandidate,
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
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.evidence_repositories import (
    PostgresEvidenceRepository,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_SOURCE = "urn:ati:source:threatfox"


async def seed_investigation(uow: PostgresUnitOfWork) -> tuple[UUID, UUID]:
    """Create one visible investigation and its canonical domain entity."""
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
        Entity(type=EntityType.DOMAIN, value="example.com")
    )
    assert entity.id is not None
    return investigation_id, entity.id


def converted_factory(
    *,
    source_record_id: str | None = None,
    observed_at: datetime | None = None,
    retrieved_at: datetime | None = None,
    raw_payload: dict[str, object] | None = None,
    facts: dict[str, object] | None = None,
) -> ConvertedEvidence:
    """Build a deterministic valid global ConvertedEvidence."""
    evidence_id = uuid4()
    return ConvertedEvidence(
        evidence=Evidence(
            id=evidence_id,
            type=EvidenceType.DNS,
            source=_SOURCE,
            source_record_id=(
                source_record_id
                if source_record_id is not None
                else f"rec-{evidence_id}"
            ),
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=evidence_id,
            observed_at=observed_at,
            retrieved_at=(retrieved_at if retrieved_at is not None else _RETRIEVED_AT),
            facts=facts
            if facts is not None
            else {"answers": ["192.0.2.1", "192.0.2.2"], "status": 0},
            raw_payload=raw_payload,
        ),
    )


async def admit(
    uow: PostgresUnitOfWork,
    investigation_id: UUID,
    observation_id: UUID,
) -> None:
    """Admit one exact observation into the Investigation."""
    await uow.investigation_evidence.admit(
        InvestigationEvidence(
            investigation_id=investigation_id,
            evidence_observation_id=observation_id,
            inclusion_reason=InvestigationEvidenceReason.INITIAL,
            added_at=_RETRIEVED_AT,
            added_by=InvestigationEvidenceActor.SYSTEM,
        )
    )


async def observation_row_count(uow: PostgresUnitOfWork) -> int:
    """Count all evidence-observation rows."""
    assert uow.session is not None
    result = await uow.session.execute(
        text("SELECT count(*) FROM ati.evidence_observation")
    )
    return int(result.scalar_one())


async def evidence_history_rows(
    uow: PostgresUnitOfWork, observation_id: UUID
) -> list[tuple[int, str]]:
    """Return bounded (version, operation) generic-history rows for one observation."""
    assert uow.session is not None
    result = await uow.session.execute(
        text("""
            SELECT version, operation FROM ati.domain_object_history
            WHERE object_type = 'evidence_observation' AND object_id = :id
            ORDER BY version
        """),
        {"id": observation_id},
    )
    return [(row[0], row[1]) for row in result.fetchall()]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_persist_read_round_trip(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Persist creates the observation exactly as normalized at the boundary."""
    async with uow_factory() as uow:
        investigation_id, _entity_id = await seed_investigation(uow)
        converted = converted_factory(
            source_record_id="synthetic-record-1",
            observed_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
            raw_payload={"status": 0, "comment": "synthetic"},
        )
        recorded = await uow.evidence.persist(converted)
        assert recorded.outcome is EvidencePersistenceOutcome.CREATED
        assert recorded.observation.version == 1
        await admit(uow, investigation_id, recorded.observation.id)

        stored = await uow.evidence.get_observation(recorded.observation.id)
        assert stored is not None
        assert stored.id == recorded.observation.id
        assert stored.evidence_id == converted.evidence.id
        assert stored.observed_at == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert stored.retrieved_at == _RETRIEVED_AT
        assert stored.facts["answers"] == ("192.0.2.1", "192.0.2.2")
        assert stored.facts["status"] == 0
        assert stored.raw_payload is not None
        assert stored.raw_payload["comment"] == "synthetic"
        # The stable Evidence identity round-trips through the repository.
        stable = await uow.evidence.get_stable_evidence(converted.evidence.id)
        assert stable is not None
        assert stable.source == _SOURCE
        assert stable.source_record_id == "synthetic-record-1"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_null_fields_round_trip(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Nullable provenance fields and an absent raw payload round trip as NULL."""
    async with uow_factory() as uow:
        converted = converted_factory(source_record_id=None)
        recorded = await uow.evidence.persist(converted)
        stored = await uow.evidence.get_observation(recorded.observation.id)
        assert stored is not None
        assert stored.source_url is None
        assert stored.observed_at is None
        assert stored.raw_payload is None
        assert stored.diff is None  # the first observation carries no diff


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_observation_writes_no_generic_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """EvidenceObservation is authoritative history; no generic rows are written."""
    async with uow_factory() as uow:
        recorded = await uow.evidence.persist(converted_factory())
        assert await evidence_history_rows(uow, recorded.observation.id) == []
        assert await evidence_history_rows(uow, recorded.evidence.id) == []


@pytest.mark.asyncio
@pytest.mark.integration
async def test_material_change_appends_distinct_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A material change appends the next immutable observation version."""
    async with uow_factory() as uow:
        converted = converted_factory(facts={"answers": ["192.0.2.1"]})
        first = await uow.evidence.persist(converted)
        changed = converted.model_copy(
            update={
                "observation": converted.observation.model_copy(
                    update={"facts": {"answers": ["192.0.2.1", "192.0.2.9"]}}
                )
            }
        )
        second = await uow.evidence.persist(changed)
        assert second.outcome is EvidencePersistenceOutcome.APPENDED
        assert second.observation.version == 2
        assert first.observation.id != second.observation.id
        assert second.observation.diff is not None
        stored_first = await uow.evidence.get_observation(first.observation.id)
        stored_second = await uow.evidence.get_observation(second.observation.id)
        assert stored_first is not None and stored_second is not None
        assert stored_first.facts["answers"] == ("192.0.2.1",)
        assert stored_second.facts["answers"] == ("192.0.2.1", "192.0.2.9")
        assert await observation_row_count(uow) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unchanged_replay_is_a_noop(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Replaying the same material state creates no observation (P28B-02)."""
    async with uow_factory() as uow:
        converted = converted_factory()
        first = await uow.evidence.persist(converted)
        second = await uow.evidence.persist(converted)
        assert second.outcome is EvidencePersistenceOutcome.UNCHANGED
        assert second.observation.id == first.observation.id
        assert await observation_row_count(uow) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_conflicting_stable_metadata_never_mutates(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A conflicting stable-metadata replay is a typed conflict, never an update."""
    async with uow_factory() as uow:
        converted = converted_factory()
        first = await uow.evidence.persist(converted)
        assert first.observation.id is not None

    async with uow_factory() as uow:
        with pytest.raises(EvidenceMetadataConflictError):
            await uow.evidence.persist(
                converted.model_copy(
                    update={
                        "evidence": converted.evidence.model_copy(
                            update={"source_record_id": "mutated"}
                        )
                    }
                )
            )

    async with uow_factory() as uow:
        original = await uow.evidence.get_observation(first.observation.id)
        assert original is not None
        assert original.facts["answers"] == ("192.0.2.1", "192.0.2.2")
        assert await observation_row_count(uow) == 1
        assert await evidence_history_rows(uow, first.observation.id) == []


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_requires_existing_investigation_at_admission(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Admission of a global observation requires a visible Investigation."""
    service = InvestigationPersistenceService(uow_factory)
    converted = converted_factory()
    with pytest.raises(InvestigationNotFoundError):
        await service.record_evidence(converted, investigation_id=uuid4())

    async with uow_factory() as uow:
        assert await observation_row_count(uow) == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_list_for_investigation_is_deterministic(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The admitted listing contract is deterministic and newest-first."""
    async with uow_factory() as uow:
        investigation_id, _ = await seed_investigation(uow)
        # Strictly distinct retrieval times make the newest-first ordering
        # deterministic (the identical-timestamp UUID tie-break path is
        # covered by the geolocation projection tests).
        older = await uow.evidence.persist(
            converted_factory(
                facts={"answers": ["192.0.2.2"]},
                retrieved_at=_RETRIEVED_AT,
            )
        )
        newer = await uow.evidence.persist(
            converted_factory(
                facts={"answers": ["192.0.2.1"]},
                retrieved_at=_RETRIEVED_AT + timedelta(seconds=1),
            )
        )
        await admit(uow, investigation_id, older.observation.id)
        await admit(uow, investigation_id, newer.observation.id)

        observations = await uow.evidence.list_for_investigation(investigation_id)
        assert [observation.id for observation in observations] == [
            newer.observation.id,
            older.observation.id,
        ]
        paged = await uow.evidence.list_for_investigation(
            investigation_id, limit=1, offset=1
        )
        assert [observation.id for observation in paged] == [older.observation.id]
        # Observations not admitted never appear.
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
    """An uncommitted observation disappears after rollback."""
    async with uow_factory() as uow:
        converted = converted_factory()

    with pytest.raises(RuntimeError, match="injected failure"):
        async with uow_factory() as uow:
            await uow.evidence.persist(converted)
            raise RuntimeError("injected failure")

    async with uow_factory() as uow:
        assert await observation_row_count(uow) == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_first_persist_creates_one_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Concurrent identical first-state writers create one Evidence and one v1."""
    async with uow_factory() as uow:
        converted = converted_factory()

    async def writer() -> EvidenceObservation:
        async with uow_factory() as uow:
            recorded = await uow.evidence.persist(converted)
            await uow.commit()
            return recorded.observation

    observations = await asyncio.gather(
        asyncio.wait_for(writer(), 10),
        asyncio.wait_for(writer(), 10),
    )
    assert len({observation.id for observation in observations}) == 1

    async with uow_factory() as uow:
        assert await observation_row_count(uow) == 1
        stable_rows = await uow.session.execute(  # type: ignore[union-attr]
            text("SELECT count(*) FROM ati.evidence WHERE id = :id"),
            {"id": converted.evidence.id},
        )
        assert stable_rows.scalar_one() == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_observation_listing_indexes_exist(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The new listing/join access paths have their deterministic-order indexes."""
    async with uow_factory() as uow:
        assert uow.session is not None
        index_definitions = (
            (
                await uow.session.execute(
                    text("""
                    SELECT indexdef FROM pg_indexes
                    WHERE schemaname = 'ati'
                      AND tablename = 'investigation_evidence'
                      AND indexname = 'investigation_evidence_observation_idx'
                """)
                )
            )
            .scalars()
            .all()
        )
        assert len(index_definitions) == 1
        assert "evidence_observation_id" in index_definitions[0]
