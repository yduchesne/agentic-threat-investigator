# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded one-iteration Evidence persistence consumer (PR 28E).

Connects the PR 28D :class:`EvidenceConsumer` seam to the PR 28B/28E
PostgreSQL global Evidence model through one atomic batch transaction:

.. code-block:: text

    EvidenceConsumer.poll(max_messages)
        -> EvidenceBatch
        -> prepare (PR 28C reconstruction + consumer-side extraction; pure)
        -> EvidenceBatchPersistenceService.persist  (one PostgreSQL transaction;
           the commit completes before this call returns)
        -> EvidenceConsumer.commit(batch)   ONLY after the DB commit
        -> EvidenceConsumerRunResult

Dominant invariants of this module:

- One non-empty polled batch is the atomic persistence unit; never
  acknowledge in a ``finally`` block and never commit the consumer before
  the PostgreSQL commit.
- All non-database work (validation, message reconstruction, extraction,
  preflight) happens before the UnitOfWork opens.
- A failure anywhere before the consumer commit redelivers the whole batch;
  the PostgreSQL receipt table (``ati.evidence_message_receipt``) makes the
  redelivery idempotent per stable PR 28C ``message_id``.
- No Investigation identity, no transport position, and no broker metadata
  enters the persistence boundary (see ``PreparedEvidenceRecord``).
- This consumer owns one iteration only; a future process/container may
  call :meth:`EvidencePersistenceConsumer.process_next_batch` repeatedly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from agentic_threat_investigator.app.evidence_batch_persistence import (
    EVIDENCE_BATCH_DEFAULT_SIZE,
    EVIDENCE_BATCH_HARD_LIMIT,
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceBatch,
    EvidenceConsumer,
)
from agentic_threat_investigator.app.evidence_message import (
    converted_evidence_from_message,
)
from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.extraction.message_context import (
    extraction_view_from_message,
)
from agentic_threat_investigator.app.extraction.models import (
    ExtractionResult,
    RelationshipAssertion,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceBatchPersistenceResult,
    EvidencePersistenceOutcome,
    PreparedEvidenceBatch,
    PreparedEvidenceRecord,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType, canonicalize

EntityIdentityKey: TypeAlias = tuple[EntityType, str]
"""Canonical ``(type, value)`` identity key of one Entity participation."""


def prepare_evidence_batch(batch: EvidenceBatch) -> PreparedEvidenceBatch:
    """Build the already-validated, already-extracted work of one polled batch.

    Pure (no database, network, broker, clock): reconstructs each PR 28C
    message through the existing contract code, derives the consumer-side
    extraction input from durable message content, runs the existing
    deterministic extractor, and runs the preflight validation. Record order
    is preserved from the polled batch. Any malformed or unsupported message
    raises a typed error and the whole batch stays unpersisted/redeliverable.
    """
    records: list[PreparedEvidenceRecord] = []
    for record in batch.records:
        message = record.message
        converted = converted_evidence_from_message(message)
        view = extraction_view_from_message(message, converted)
        extraction = extract(view)
        _validate_prepared(view.invocation_entity, extraction)
        records.append(
            PreparedEvidenceRecord(
                message_id=message.message_id,
                observation_candidate_id=message.observation_candidate_id,
                converted=converted,
                invocation_entity=view.invocation_entity,
                extraction=extraction,
            )
        )
    return PreparedEvidenceBatch(records=tuple(records))


def _validate_prepared(
    invocation_entity: Entity,
    extraction: ExtractionResult,
) -> None:
    """Deterministic preflight of one prepared record, without any database work.

    Mirrors the preflight rules of the Investigation-scoped persistence
    service (PR 28B): canonical identities, distinct entity identities,
    assertions whose endpoints are covered by the record's canonical Entity
    set, and distinct assertions. Any violation is a contract failure that
    fails the whole batch before the transaction opens.
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
                raise ValueError("relationship endpoint is not covered by extraction")
    seen_assertions: set[tuple[EntityType, str, object, EntityType, str]] = set()
    for assertion in extraction.relationships:
        assertion_key = _assertion_key(assertion)
        if assertion_key in seen_assertions:
            raise ValueError("duplicate relationship assertion")
        seen_assertions.add(assertion_key)


def _assertion_key(
    assertion: RelationshipAssertion,
) -> tuple[EntityType, str, object, EntityType, str]:
    """Return the deterministic deduplication key of one relationship assertion."""
    return (
        assertion.source.type,
        assertion.source.value,
        assertion.type,
        assertion.target.type,
        assertion.target.value,
    )


@dataclass(frozen=True)
class EvidenceConsumerRunResult:
    """Bounded metrics of one consumer iteration; never carries payloads."""

    polled_count: int
    persisted_count: int
    created_count: int
    unchanged_count: int
    appended_count: int
    committed: bool


_EMPTY_RUN_RESULT = EvidenceConsumerRunResult(
    polled_count=0,
    persisted_count=0,
    created_count=0,
    unchanged_count=0,
    appended_count=0,
    committed=False,
)
"""The documented result of an empty poll: no DB transaction, no commit."""


class EvidencePersistenceConsumer:
    """Poll one bounded batch, persist it atomically, then commit the consumer.

    The exact ordering is structural: poll, prepare, persist (the PostgreSQL
    commit completes inside this call), and only then ``commit(batch)``.
    Cancellation propagates and never becomes an acknowledgement.
    """

    def __init__(
        self,
        *,
        consumer: EvidenceConsumer,
        persistence: EvidenceBatchPersistenceService,
        batch_size: int = EVIDENCE_BATCH_DEFAULT_SIZE,
    ) -> None:
        """Bind the bounded consumer to its log handle and persistence service."""
        if (
            not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
            or batch_size <= 0
        ):
            raise ValueError("batch_size must be a positive integer")
        if batch_size > EVIDENCE_BATCH_HARD_LIMIT:
            raise ValueError(f"batch_size must not exceed {EVIDENCE_BATCH_HARD_LIMIT}")
        self._consumer = consumer
        self._persistence = persistence
        self._batch_size = batch_size

    @property
    def batch_size(self) -> int:
        """Return the configured poll bound."""
        return self._batch_size

    async def process_next_batch(self) -> EvidenceConsumerRunResult:
        """Process exactly one bounded batch and return bounded metrics.

        An empty poll returns the empty result with ``committed=False`` and
        opens no transaction and makes no consumer commit. Otherwise the
        PostgreSQL batch transaction commits before the consumer commit.
        """
        batch = await self._consumer.poll(self._batch_size)
        if not batch.records:
            return _EMPTY_RUN_RESULT
        prepared = prepare_evidence_batch(batch)
        persisted = await self._persistence.persist(prepared)
        # Only after the PostgreSQL commit has completed.
        await self._consumer.commit(batch)
        return _run_result(persisted)


def _run_result(persisted: EvidenceBatchPersistenceResult) -> EvidenceConsumerRunResult:
    """Map one committed persistence result to bounded consumer metrics."""
    items = persisted.items
    return EvidenceConsumerRunResult(
        polled_count=len(items),
        persisted_count=len(items),
        created_count=sum(
            1 for item in items if item.outcome is EvidencePersistenceOutcome.CREATED
        ),
        unchanged_count=sum(
            1 for item in items if item.outcome is EvidencePersistenceOutcome.UNCHANGED
        ),
        appended_count=sum(
            1 for item in items if item.outcome is EvidencePersistenceOutcome.APPENDED
        ),
        committed=True,
    )
