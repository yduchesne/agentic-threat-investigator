# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL integration coverage for PR 28E batch persistence and consumer.

Exercises the exact SQL API v0027 migration head through the real
repository/service/consumer path:

- I28E-01..14: bounded global Evidence batch persistence — receipts, exact
  replay, candidate identity, unchanged candidates, material updates,
  atomic rollback, deterministic same-Evidence ordering, duplicate messages,
  soft-deleted conflicts, no generic Evidence history, no Investigation
  admission, exact RelationshipObservation provenance, and the SQL-side
  size bound;
- the required distinct-message recurrence test ([M1:A, M2:B, M3:A] — the
  second A is APPENDED, never mistaken for replay);
- V28E-01..05: real PR 28D log + real PostgreSQL vertical slices, including
  the DB-commit/log-commit failure boundary (multi-state replay lives in
  tests/integration/test_evidence_batch_replay.py).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4, uuid5

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.evidence_batch_persistence import (
    EVIDENCE_BATCH_HARD_LIMIT,
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_consumer import (
    EvidencePersistenceConsumer,
    prepare_evidence_batch,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceConsumerId,
    InMemoryEvidenceLog,
)
from agentic_threat_investigator.app.evidence_message import EvidenceMessage
from agentic_threat_investigator.app.extraction.models import (
    EntityIdentity,
    ExtractedEntity,
    ExtractionResult,
    RelationshipAssertion,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceBatchPersistenceResult,
    EvidenceBatchSizeLimitExceededError,
    EvidenceMetadataConflictError,
    EvidencePersistenceOutcome,
    PreparedEvidenceBatch,
    PreparedEvidenceRecord,
    SoftDeletedIdentityError,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.evidence_batch_fixtures import (
    build_threatfox_fact,
    message_batch,
    threatfox_message,
)

_RETRIEVED_AT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_DOMAIN = "malicious-domain.test"
_RECORD = "same-evidence-record"
_MANUAL_NAMESPACE = UUID("00000000-0000-0000-0000-00000000e28e")
"""Test-only namespace deriving deterministic manual message identities."""

StateFacts = dict[str, object]


def _facts(malware: str) -> StateFacts:
    """Build one ThreatFox material state with a distinct malware family."""
    return {
        "matches": [
            build_threatfox_fact(ioc=_DOMAIN, ioc_type="domain", malware=malware)
        ]
    }


async def _count(uow: PostgresUnitOfWork, table: str) -> int:
    """Count all rows of one ati table inside the active transaction."""
    assert uow.session is not None
    result = await uow.session.execute(text(f"SELECT count(*) FROM ati.{table}"))
    return int(result.scalar_one())


async def _observations(uow: PostgresUnitOfWork) -> list[tuple[int, object]]:
    """Return ordered (version, id) pairs of every evidence observation."""
    assert uow.session is not None
    result = await uow.session.execute(
        text("SELECT version, id FROM ati.evidence_observation ORDER BY version")
    )
    return [(row[0], row[1]) for row in result.fetchall()]


def _prepared(messages: tuple[EvidenceMessage, ...]) -> PreparedEvidenceBatch:
    """Prepare real messages through the consumer's pure preparation path."""
    return prepare_evidence_batch(message_batch(messages))


def _message(
    *,
    malware: str,
    sequence: int,
    execution_id: UUID | None = None,
    source_record_id: str = _RECORD,
) -> EvidenceMessage:
    """Build one valid ThreatFox message."""
    return threatfox_message(
        ioc=_DOMAIN,
        ioc_type="domain",
        source_record_id=source_record_id,
        sequence=sequence,
        retrieved_at=_RETRIEVED_AT,
        facts=_facts(malware),
        execution_id=execution_id,
    )[0]


async def _persist(
    uow: PostgresUnitOfWork, prepared: PreparedEvidenceBatch
) -> EvidenceBatchPersistenceResult:
    """Persist a prepared batch in the caller's transaction."""
    return await uow.evidence_batches.persist_batch(prepared)


# ---------------------------------------------------------------------------
# I28E-01..05: first batch, exact replay, candidate identity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_01_first_batch_creates_exact_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """One batch creates Evidence, observation, entities, and provenance."""
    prepared = _prepared((_message(malware="win.asyncrat", sequence=0),))
    async with uow_factory() as uow:
        assert uow.session is not None
        result = await _persist(uow, prepared)
        item = result.items[0]
        assert item.outcome is EvidencePersistenceOutcome.CREATED
        assert item.version == 1
        assert await _count(uow, "evidence") == 1
        observations = await _observations(uow)
        assert [(v) for v, _ in observations] == [1]
        # Subject + malware entity, one edge, one RO, one receipt.
        assert await _count(uow, "entity") == 2
        assert await _count(uow, "evidence_observation_entity") == 2
        assert await _count(uow, "relationship") == 1
        assert await _count(uow, "relationship_observation") == 1
        assert await _count(uow, "evidence_message_receipt") == 1
        # No Investigation admission and no generic Evidence history.
        assert await _count(uow, "investigation_evidence") == 0
        history = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.domain_object_history "
                    "WHERE object_type = 'evidence_observation'"
                )
            )
        ).scalar_one()
        assert int(history) == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_02_exact_replay_is_a_receipt_noop(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Replaying an identical prepared batch adds no observation or RO."""
    prepared = _prepared((_message(malware="win.asyncrat", sequence=0),))
    async with uow_factory() as uow:
        first = await _persist(uow, prepared)
    async with uow_factory() as uow:
        second = await _persist(uow, prepared)
        assert second.items[0].outcome is EvidencePersistenceOutcome.CREATED
        assert (
            second.items[0].evidence_observation_id
            == first.items[0].evidence_observation_id
        )
        assert await _count(uow, "evidence_observation") == 1
        assert await _count(uow, "relationship_observation") == 1
        assert await _count(uow, "entity") == 2
        assert await _count(uow, "evidence_message_receipt") == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_03_created_observation_id_equals_candidate(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """On CREATED the proposed candidate identity becomes the observation ID."""
    message = _message(malware="win.asyncrat", sequence=0)
    prepared = _prepared((message,))
    async with uow_factory() as uow:
        result = await _persist(uow, prepared)
    assert result.items[0].outcome is EvidencePersistenceOutcome.CREATED
    assert result.items[0].evidence_observation_id == message.observation_candidate_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_04_unchanged_candidate_is_unused(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A later same-state NEW message resolves UNCHANGED to the existing EO.

    The later candidate identity is never persisted as a new observation.
    """
    first_message = _message(malware="win.asyncrat", sequence=0)
    later_message = _message(malware="win.asyncrat", sequence=1, execution_id=uuid4())
    async with uow_factory() as uow:
        first = (await _persist(uow, _prepared((first_message,)))).items[0]
    async with uow_factory() as uow:
        later = (await _persist(uow, _prepared((later_message,)))).items[0]
        assert later.outcome is EvidencePersistenceOutcome.UNCHANGED
        assert later.evidence_observation_id == first.evidence_observation_id
        observations = await _observations(uow)
        assert [v for v, _ in observations] == [1]
        ids = [str(obs_id) for _, obs_id in observations]
        assert str(later_message.observation_candidate_id) not in ids


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_05_material_update_appends_authoritative_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A material change appends the next version with a canonical diff.

    The APPENDED observation ID is PostgreSQL-authoritative (Option A); the
    candidate identity is proposed but never required to become it.
    """
    first = _message(malware="win.asyncrat", sequence=0)
    second = _message(malware="agent.tesla", sequence=1)
    async with uow_factory() as uow:
        await _persist(uow, _prepared((first,)))
    async with uow_factory() as uow:
        second_item = (await _persist(uow, _prepared((second,)))).items[0]
        assert second_item.outcome is EvidencePersistenceOutcome.APPENDED
        assert second_item.version == 2
        assert second_item.evidence_observation_id != second.observation_candidate_id
        assert await _count(uow, "evidence_observation") == 2
        assert await _count(uow, "relationship_observation") == 2
    async with uow_factory() as uow:
        stored = await uow.evidence.get_observation(second_item.evidence_observation_id)
        assert stored is not None
        assert stored.version == 2
        assert stored.diff is not None
        assert stored.facts == second.facts


# ---------------------------------------------------------------------------
# I28E-06..08: atomicity, ordering, duplicates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_06_atomic_batch_rollback(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """One failing record rolls the whole batch back, including receipts."""
    valid = _message(malware="win.asyncrat", sequence=0)
    # A conflicting record: same Evidence ID but different stable metadata.
    conflicting = _manual_record(
        evidence_id=valid.evidence_id,
        evidence_type=EvidenceType.DNS,
        source_record_id="different-record",
        message_id=uuid5(_MANUAL_NAMESPACE, "conflicting-message"),
    )
    trailing = _message(malware="agent.tesla", sequence=1)
    prepared = _prepared((valid, trailing))
    records = [prepared.records[0], conflicting, prepared.records[1]]
    prepared = replace(prepared, records=tuple(records))
    async with uow_factory() as uow:
        with pytest.raises(EvidenceMetadataConflictError):
            await _persist(uow, prepared)
    async with uow_factory() as uow:
        assert await _count(uow, "evidence") == 0
        assert await _count(uow, "evidence_observation") == 0
        assert await _count(uow, "evidence_observation_entity") == 0
        assert await _count(uow, "entity") == 0
        assert await _count(uow, "relationship") == 0
        assert await _count(uow, "relationship_observation") == 0
        assert await _count(uow, "evidence_message_receipt") == 0


def _manual_record(
    *,
    evidence_id: UUID,
    evidence_type: EvidenceType,
    source_record_id: str,
    message_id: UUID,
    facts: StateFacts | None = None,
) -> PreparedEvidenceRecord:
    """Hand-build one prepared record bypassing the message contract.

    Test-only facility for conflict shapes the PR 28C wire cannot express
    (for example a stable Evidence ID bound to different stable metadata).
    """
    converted = ConvertedEvidence(
        evidence=Evidence(
            id=evidence_id,
            type=evidence_type,
            source="urn:ati:source:threatfox",
            source_record_id=source_record_id,
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=evidence_id,
            source_url=None,
            observed_at=None,
            retrieved_at=_RETRIEVED_AT,
            facts=facts or _facts("win.asyncrat"),
            raw_payload=None,
        ),
    )
    return PreparedEvidenceRecord(
        message_id=message_id,
        observation_candidate_id=uuid5(_MANUAL_NAMESPACE, str(message_id)),
        converted=converted,
        invocation_entity=Entity(type=EntityType.DOMAIN, value=_DOMAIN),
        extraction=ExtractionResult(),
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_07_same_evidence_sequential_states_in_one_batch(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A then B inside one batch appends v1 then v2 in log order."""
    a = _message(malware="win.asyncrat", sequence=0)
    b = _message(malware="agent.tesla", sequence=1)
    async with uow_factory() as uow:
        result = await _persist(uow, _prepared((a, b)))
        outcomes = [item.outcome for item in result.items]
        assert outcomes == [
            EvidencePersistenceOutcome.CREATED,
            EvidencePersistenceOutcome.APPENDED,
        ]
        assert [item.version for item in result.items] == [1, 2]
        assert await _observations(uow) == [
            (1, result.items[0].evidence_observation_id),
            (2, result.items[1].evidence_observation_id),
        ]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_08_duplicate_message_in_one_batch_is_safe(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The same message at two positions creates one semantic observation."""
    message = _message(malware="win.asyncrat", sequence=0)
    async with uow_factory() as uow:
        result = await _persist(uow, _prepared((message, message)))
        assert len(result.items) == 2
        assert result.items[1].outcome is EvidencePersistenceOutcome.CREATED
        assert (
            result.items[1].evidence_observation_id
            == result.items[0].evidence_observation_id
        )
        assert await _count(uow, "evidence_observation") == 1
        assert await _count(uow, "relationship_observation") == 1
        assert await _count(uow, "evidence_message_receipt") == 1


# ---------------------------------------------------------------------------
# I28E-09..14: soft-deleted conflicts, history, admissions, provenance, bounds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_09_soft_deleted_entity_fails_batch_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Rediscovering a soft-deleted Entity identity rolls the batch back."""
    async with uow_factory() as uow:
        entity = await uow.entities.upsert(
            Entity(id=uuid4(), type=EntityType.DOMAIN, value=_DOMAIN)
        )
        assert entity.id is not None
        await uow.entities.soft_delete(entity.id)
    prepared = _prepared((_message(malware="win.asyncrat", sequence=0),))
    async with uow_factory() as uow:
        with pytest.raises(SoftDeletedIdentityError):
            await _persist(uow, prepared)
    async with uow_factory() as uow:
        assert await _count(uow, "evidence") == 0
        assert await _count(uow, "evidence_observation") == 0
        assert await _count(uow, "evidence_message_receipt") == 0
        assert await _count(uow, "evidence_observation_entity") == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_10_soft_deleted_relationship_fails_batch_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Rediscovering a soft-deleted Relationship identity rolls the batch back."""
    record = _manual_record(
        evidence_id=uuid4(),
        evidence_type=EvidenceType.THREAT_INTELLIGENCE,
        source_record_id="rel-record",
        message_id=uuid5(_MANUAL_NAMESPACE, "rel-message"),
        facts=_facts("win.asyncrat"),
    )
    target_value = "win.asyncrat"
    async with uow_factory() as uow:
        subject = await uow.entities.upsert(
            Entity(id=uuid4(), type=EntityType.DOMAIN, value=_DOMAIN)
        )
        malware = await uow.entities.upsert(
            Entity(id=uuid4(), type=EntityType.MALWARE, value=target_value)
        )
        assert subject.id is not None and malware.id is not None
        relationship = await uow.relationships.upsert(
            Relationship(
                id=uuid4(),
                source_entity_id=subject.id,
                target_entity_id=malware.id,
                type=RelationshipType.ASSOCIATED_WITH,
            )
        )
        await uow.relationships.soft_delete(relationship.id)
    prepared_record = PreparedEvidenceRecord(
        message_id=record.message_id,
        observation_candidate_id=record.observation_candidate_id,
        converted=record.converted,
        invocation_entity=Entity(type=EntityType.DOMAIN, value=_DOMAIN),
        extraction=_threatfox_extraction(target_value),
    )
    async with uow_factory() as uow:
        with pytest.raises(SoftDeletedIdentityError):
            await _persist(uow, PreparedEvidenceBatch(records=(prepared_record,)))
    async with uow_factory() as uow:
        assert await _count(uow, "evidence") == 0
        assert await _count(uow, "evidence_observation") == 0
        assert await _count(uow, "relationship_observation") == 0


def _threatfox_extraction(malware: str) -> ExtractionResult:
    """Build the canonical ThreatFox extraction of one match."""
    return ExtractionResult(
        entities=(
            ExtractedEntity(type=EntityType.DOMAIN, value=_DOMAIN),
            ExtractedEntity(type=EntityType.MALWARE, value=malware),
        ),
        relationships=(
            RelationshipAssertion(
                source=EntityIdentity(type=EntityType.DOMAIN, value=_DOMAIN),
                type=RelationshipType.ASSOCIATED_WITH,
                target=EntityIdentity(type=EntityType.MALWARE, value=malware),
            ),
        ),
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_11_no_generic_evidence_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Evidence/EvidenceObservation never write domain_object_history rows."""
    prepared = _prepared((_message(malware="win.asyncrat", sequence=0),))
    async with uow_factory() as uow:
        assert uow.session is not None
        await _persist(uow, prepared)
        history = (
            await uow.session.execute(
                text(
                    "SELECT count(*) FROM ati.domain_object_history "
                    "WHERE object_type IN ('evidence', 'evidence_observation')"
                )
            )
        ).scalar_one()
        assert int(history) == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_12_no_investigation_admission(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Batch persistence never creates InvestigationEvidence rows."""
    prepared = _prepared(
        (
            _message(malware="win.asyncrat", sequence=0),
            _message(malware="agent.tesla", sequence=1),
        )
    )
    async with uow_factory() as uow:
        await _persist(uow, prepared)
        assert await _count(uow, "investigation_evidence") == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_13_exact_ro_provenance(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Every RO references exactly the authoritative observation of its record."""
    a = _message(malware="win.asyncrat", sequence=0)
    b = _message(malware="agent.tesla", sequence=1)
    async with uow_factory() as uow:
        assert uow.session is not None
        result = await _persist(uow, _prepared((a, b)))
        rows = (
            await uow.session.execute(
                text(
                    "SELECT relationship_id, evidence_observation_id, source "
                    "FROM ati.relationship_observation ORDER BY evidence_observation_id"
                )
            )
        ).fetchall()
        assert len(rows) == 2
        authoritative = {item.evidence_observation_id for item in result.items}
        assert {row[1] for row in rows} == authoritative
        assert {row[2] for row in rows} == {"urn:ati:source:threatfox"}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_14_oversized_direct_repository_call_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An oversized direct repository call fails before any mutation."""
    prepared_records = tuple(
        _manual_record(
            evidence_id=uuid4(),
            evidence_type=EvidenceType.THREAT_INTELLIGENCE,
            source_record_id=f"oversized-{index}",
            message_id=uuid5(_MANUAL_NAMESPACE, f"oversized-{index}"),
        )
        for index in range(EVIDENCE_BATCH_HARD_LIMIT + 1)
    )
    async with uow_factory() as uow:
        with pytest.raises(EvidenceBatchSizeLimitExceededError):
            await _persist(uow, PreparedEvidenceBatch(records=prepared_records))
        assert await _count(uow, "evidence") == 0
        assert await _count(uow, "evidence_message_receipt") == 0


# ---------------------------------------------------------------------------
# Required distinct-message recurrence test: [M1:A, M2:B, M3:A]
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i28e_15_distinct_message_recurrence_appends(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A NEW message with an OLD material state is APPENDED, not replay.

    M3 is a distinct message (fresh message_id) carrying the same material
    state as M1. Receipts are keyed by message identity, so M3 must run the
    authoritative transition against the latest state (B) and APPEND v3 with
    state A — the receipt table is never matched by material state and
    historical observations are never searched.
    """
    m1 = _message(malware="win.asyncrat", sequence=0)
    m2 = _message(malware="agent.tesla", sequence=1)
    m3 = _message(malware="win.asyncrat", sequence=0, execution_id=uuid4())
    assert m3.message_id != m1.message_id
    assert m3.facts == m1.facts
    async with uow_factory() as uow:
        result = await _persist(uow, _prepared((m1, m2, m3)))
        outcomes = [item.outcome for item in result.items]
        assert outcomes == [
            EvidencePersistenceOutcome.CREATED,
            EvidencePersistenceOutcome.APPENDED,
            EvidencePersistenceOutcome.APPENDED,
        ]
        assert [item.version for item in result.items] == [1, 2, 3]
        # v3's material state is A again — an append, never a replay hit.
        third = await uow.evidence.get_observation(
            result.items[2].evidence_observation_id
        )
        assert third is not None
        assert third.facts == m1.facts
        assert await _count(uow, "evidence_message_receipt") == 3


# ---------------------------------------------------------------------------
# V28E vertical slices: real log + real PostgreSQL + real consumer
# ---------------------------------------------------------------------------


def _consumer(
    log: InMemoryEvidenceLog,
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    consumer_id: str = "pr-28e-integration",
    batch_size: int = 10,
) -> EvidencePersistenceConsumer:
    """Wire one real consumer over one real log and the real service."""
    service = EvidenceBatchPersistenceService(uow_factory)
    return EvidencePersistenceConsumer(
        consumer=log.consumer(EvidenceConsumerId(consumer_id)),
        persistence=service,
        batch_size=batch_size,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_v28e_01_success(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Publish -> poll -> prepare/extract -> PostgreSQL commit -> log commit."""
    log = InMemoryEvidenceLog()
    messages = (
        _message(malware="win.asyncrat", sequence=0),
        _message(malware="agent.tesla", sequence=1),
    )
    await log.publisher().publish(messages)
    consumer = _consumer(log, uow_factory)
    result = await consumer.process_next_batch()
    assert result.persisted_count == 2
    assert result.committed is True
    async with uow_factory() as uow:
        assert await _count(uow, "evidence_observation") == 2
        assert await _count(uow, "evidence_message_receipt") == 2
    assert not (
        await log.consumer(EvidenceConsumerId("pr-28e-integration")).poll(10)
    ).records


@pytest.mark.asyncio
@pytest.mark.integration
async def test_v28e_02_db_failure_before_log_commit(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A real SQL failure rolls back; the cursor is unchanged; redelivery occurs.

    The canonical in-transaction DB failure is injected through the stable
    soft-delete policy: the batch's Entity canonicalization/upsert raises
    ``U18C2`` (soft-deleted identity rediscovered) after the Evidence row of
    the first record was already written inside the transaction. The whole
    transaction rolls back, the consumer never commits, and the next poll
    redelivers the identical batch (no receipts leaked).
    """
    log = InMemoryEvidenceLog()
    messages = (
        _message(malware="win.asyncrat", sequence=0),
        _message(malware="agent.tesla", sequence=1),
    )
    await log.publisher().publish(messages)
    # Fail the domain identity the whole batch depends on.
    async with uow_factory() as uow:
        entity = await uow.entities.upsert(
            Entity(id=uuid4(), type=EntityType.DOMAIN, value=_DOMAIN)
        )
        assert entity.id is not None
        await uow.entities.soft_delete(entity.id)

    consumer_id = EvidenceConsumerId("pr-28e-db-failure")
    consumer = _consumer(log, uow_factory, consumer_id=consumer_id.value)
    with pytest.raises(SoftDeletedIdentityError):
        await consumer.process_next_batch()

    async with uow_factory() as uow:
        assert await _count(uow, "evidence") == 0
        assert await _count(uow, "evidence_observation") == 0
        assert await _count(uow, "entity") == 1  # the pre-deleted entity only
        assert await _count(uow, "evidence_observation_entity") == 0
        assert await _count(uow, "evidence_message_receipt") == 0
    redelivered = await log.consumer(consumer_id).poll(10)
    assert len(redelivered.records) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_v28e_04_material_change_across_runs(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A later acquisition with changed material state appends exactly once."""
    log = InMemoryEvidenceLog()
    a = _message(malware="win.asyncrat", sequence=0)
    await log.publisher().publish((a,))
    consumer = _consumer(log, uow_factory)
    first = await consumer.process_next_batch()
    assert first.created_count == 1

    b = _message(malware="agent.tesla", sequence=0, execution_id=uuid4())
    await log.publisher().publish((b,))
    second = await consumer.process_next_batch()
    assert second.appended_count == 1

    async with uow_factory() as uow:
        assert uow.session is not None
        assert await _count(uow, "evidence_observation") == 2
        rows = (
            await uow.session.execute(
                text(
                    "SELECT o.version, o.diff IS NOT NULL "
                    "FROM ati.evidence_observation o ORDER BY o.version"
                )
            )
        ).fetchall()
        assert [(row[0], row[1]) for row in rows] == [(1, False), (2, True)]
        assert await _count(uow, "relationship_observation") == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_v28e_05_bounded_multiple_records(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Publishing beyond batch_size commits exactly the bounded prefix per run."""
    log = InMemoryEvidenceLog()
    await log.publisher().publish(
        (
            _message(malware="win.asyncrat", sequence=0),
            _message(malware="agent.tesla", sequence=1),
            _message(malware="redline.stealer", sequence=2),
        )
    )
    consumer_id = EvidenceConsumerId("pr-28e-bounded")
    service = EvidenceBatchPersistenceService(uow_factory)
    consumer = EvidencePersistenceConsumer(
        consumer=log.consumer(consumer_id), persistence=service, batch_size=2
    )
    first = await consumer.process_next_batch()
    assert first.persisted_count == 2
    async with uow_factory() as uow:
        assert await _count(uow, "evidence_observation") == 2
    second = await consumer.process_next_batch()
    assert second.persisted_count == 1
    async with uow_factory() as uow:
        assert await _count(uow, "evidence_observation") == 3
    third = await consumer.process_next_batch()
    assert third.polled_count == 0
    assert third.committed is False
