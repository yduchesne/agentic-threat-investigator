# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence consumer flow telemetry tests (PR 29A-1, E-C1..C8).

Proves the ``ati.evidence.consume`` operation's semantic counters against the
deterministic spy consumer/persistence doubles: messages count as fully
*processed* only after both the PostgreSQL persist and the broker commit
succeed, and persistence outcomes remain visible even when a later broker
commit fails.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from types import SimpleNamespace
from uuid import uuid4

import pytest
from opentelemetry.sdk.metrics.export import Metric

from agentic_threat_investigator.app.evidence_batch_persistence import (
    EVIDENCE_BATCH_DEFAULT_SIZE,
)
from agentic_threat_investigator.app.evidence_consumer import (
    EvidencePersistenceConsumer,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceBatch,
    EvidenceCommitError,
    EvidenceConsumer,
)
from agentic_threat_investigator.app.evidence_message import EvidenceMessage
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceBatchPersistenceItemResult,
    EvidenceBatchPersistenceResult,
    EvidencePersistenceOutcome,
)
from agentic_threat_investigator.telemetry.metrics import Metrics
from tests.support.evidence_batch_fixtures import message_batch, threatfox_message
from tests.support.otel import counter_value, metrics_by_name
from tests.unit.app.test_evidence_consumer import (
    RecordingBatchPersistence,
    SpyEvidenceConsumer,
)


def _message(sequence: int = 0) -> EvidenceMessage:
    """Build one valid ThreatFox message."""
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id=f"rec-flow-{sequence}",
        sequence=sequence,
    )
    return message


def _result(
    outcomes: tuple[EvidencePersistenceOutcome, ...],
    messages: tuple[EvidenceMessage, ...],
) -> EvidenceBatchPersistenceResult:
    """Build a persistence result with the requested outcome sequence."""
    return EvidenceBatchPersistenceResult(
        items=tuple(
            EvidenceBatchPersistenceItemResult(
                message_id=message.message_id,
                evidence_id=uuid4(),
                evidence_observation_id=uuid4(),
                outcome=outcome,
                version=1,
            )
            for message, outcome in zip(messages, outcomes, strict=True)
        )
    )


def _subject(
    messages: tuple[EvidenceMessage, ...],
    *,
    result: EvidenceBatchPersistenceResult | None = None,
    fail_poll: bool = False,
    fail_commit: bool = False,
) -> tuple[EvidencePersistenceConsumer, SpyEvidenceConsumer, RecordingBatchPersistence]:
    """Wire one consumer under test with deterministic doubles."""
    consumer = SpyEvidenceConsumer(
        poll_result=message_batch(messages),
        fail_poll=fail_poll,
        fail_commit=fail_commit,
    )
    persistence = RecordingBatchPersistence()
    if result is not None:
        persistence.result = result
    service = EvidencePersistenceConsumer(
        consumer=consumer,
        persistence=persistence,
        batch_size=EVIDENCE_BATCH_DEFAULT_SIZE,
    )
    return service, consumer, persistence


class TestEvidenceFlowCounters:
    """Semantic counters of one processed batch (E-C1..C4)."""

    @pytest.mark.asyncio
    async def test_created_batch(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """All-CREATED batch counts created and fully processed (E-C1)."""
        messages = (_message(0),)
        service, _consumer, _persistence = _subject(
            messages, result=_result((EvidencePersistenceOutcome.CREATED,), messages)
        )
        await service.process_next_batch()
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert counter_value(recorded[Metrics.EVIDENCE_OUTCOMES_CREATED]) == 1
        assert counter_value(recorded[Metrics.EVIDENCE_MESSAGES_PROCESSED]) == 1
        assert Metrics.EVIDENCE_OUTCOMES_APPENDED not in recorded
        assert Metrics.EVIDENCE_OUTCOMES_UNCHANGED not in recorded
        assert Metrics.EVIDENCE_PROCESSING_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_appended_batch(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """All-APPENDED batch counts appended and fully processed (E-C2)."""
        messages = tuple(_message(i) for i in range(2))
        service, _consumer, _persistence = _subject(
            messages,
            result=_result((EvidencePersistenceOutcome.APPENDED,) * 2, messages),
        )
        await service.process_next_batch()
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert counter_value(recorded[Metrics.EVIDENCE_OUTCOMES_APPENDED]) == 2
        assert counter_value(recorded[Metrics.EVIDENCE_MESSAGES_PROCESSED]) == 2

    @pytest.mark.asyncio
    async def test_unchanged_batch(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """All-UNCHANGED batch counts unchanged, never ignore (E-C3)."""
        messages = (_message(0),)
        service, _consumer, _persistence = _subject(
            messages,
            result=_result((EvidencePersistenceOutcome.UNCHANGED,), messages),
        )
        await service.process_next_batch()
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert counter_value(recorded[Metrics.EVIDENCE_OUTCOMES_UNCHANGED]) == 1
        assert counter_value(recorded[Metrics.EVIDENCE_MESSAGES_PROCESSED]) == 1

    @pytest.mark.asyncio
    async def test_mixed_batch_exact_counts(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A mixed batch yields exact per-outcome counts (E-C4)."""
        messages = tuple(_message(i) for i in range(4))
        outcomes = (
            EvidencePersistenceOutcome.CREATED,
            EvidencePersistenceOutcome.CREATED,
            EvidencePersistenceOutcome.APPENDED,
            EvidencePersistenceOutcome.UNCHANGED,
        )
        service, _consumer, _persistence = _subject(
            messages, result=_result(outcomes, messages)
        )
        await service.process_next_batch()
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert counter_value(recorded[Metrics.EVIDENCE_OUTCOMES_CREATED]) == 2
        assert counter_value(recorded[Metrics.EVIDENCE_OUTCOMES_APPENDED]) == 1
        assert counter_value(recorded[Metrics.EVIDENCE_OUTCOMES_UNCHANGED]) == 1
        assert counter_value(recorded[Metrics.EVIDENCE_MESSAGES_PROCESSED]) == 4


class TestEvidenceFlowFailures:
    """Failure semantics of the flow counters (E-C5..C8)."""

    @pytest.mark.asyncio
    async def test_db_failure_counts_processing_failure(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A persistence failure counts a processing failure, not processed (E-C5)."""
        messages = (_message(0),)
        service, _consumer, persistence = _subject(messages)
        persistence.fail = RuntimeError("db down")
        with pytest.raises(RuntimeError, match="db down"):
            await service.process_next_batch()
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert counter_value(recorded[Metrics.EVIDENCE_PROCESSING_FAILURES]) == 1
        assert Metrics.EVIDENCE_MESSAGES_PROCESSED not in recorded
        assert Metrics.EVIDENCE_OUTCOMES_CREATED not in recorded

    @pytest.mark.asyncio
    async def test_db_ok_kafka_commit_fails(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """DB commits but broker commit fails: outcomes count, processed stays 0 (E-C6)."""
        messages = (_message(0),)
        service, _consumer, _persistence = _subject(
            messages,
            result=_result((EvidencePersistenceOutcome.CREATED,), messages),
            fail_commit=True,
        )
        with pytest.raises(EvidenceCommitError):
            await service.process_next_batch()
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        # The database committed: persistence outcomes are authoritative.
        assert counter_value(recorded[Metrics.EVIDENCE_OUTCOMES_CREATED]) == 1
        # The application flow did not complete: not processed, failure counted.
        assert Metrics.EVIDENCE_MESSAGES_PROCESSED not in recorded
        assert counter_value(recorded[Metrics.EVIDENCE_PROCESSING_FAILURES]) == 1

    @pytest.mark.asyncio
    async def test_empty_poll_is_not_a_failure(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """An empty poll records no processing failure or processed count (E-C7)."""
        service, _consumer, _persistence = _subject(())
        result = await service.process_next_batch()
        assert result.committed is False and result.polled_count == 0
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert Metrics.EVIDENCE_PROCESSING_FAILURES not in recorded
        assert Metrics.EVIDENCE_MESSAGES_PROCESSED not in recorded
        assert _no_outcome_counters(recorded)

    @pytest.mark.asyncio
    async def test_cancellation_propagates_without_failure_counter(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Cancellation propagates and never counts as a processing failure (E-C8)."""

        class _CancelConsumer(EvidenceConsumer):
            """A consumer whose poll cancels."""

            async def poll(self, max_messages: int) -> EvidenceBatch:
                del max_messages
                raise asyncio.CancelledError()

            async def commit(self, batch: EvidenceBatch) -> None:
                del batch
                raise AssertionError("must not commit on cancellation")

        persistence = RecordingBatchPersistence()
        service = EvidencePersistenceConsumer(
            consumer=_CancelConsumer(),
            persistence=persistence,
            batch_size=EVIDENCE_BATCH_DEFAULT_SIZE,
        )
        with pytest.raises(asyncio.CancelledError):
            await service.process_next_batch()
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert Metrics.EVIDENCE_PROCESSING_FAILURES not in recorded
        assert Metrics.EVIDENCE_MESSAGES_PROCESSED not in recorded


def _no_outcome_counters(recorded: Mapping[str, Metric]) -> bool:
    """Return whether no outcome counter was recorded."""
    return not any(key.startswith("ati.evidence.outcomes.") for key in recorded)
