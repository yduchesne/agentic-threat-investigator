# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the bounded one-iteration Evidence persistence consumer (PR 28E).

Covers the E28E-C sequencing matrix with spy consumer/persistence doubles:
empty poll, bounded poll size, atomic batch persistence, PostgreSQL-commit
before consumer-commit ordering, DB failure without consumer commit,
consumer-commit failure after DB success, and cancellation without a false
acknowledgement.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.evidence_batch_persistence import (
    EVIDENCE_BATCH_DEFAULT_SIZE,
    EVIDENCE_BATCH_HARD_LIMIT,
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_consumer import (
    EvidenceConsumerRunResult,
    EvidencePersistenceConsumer,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceBatch,
    EvidenceCommitError,
    EvidenceConsumer,
    EvidencePollError,
)
from agentic_threat_investigator.app.evidence_message import EvidenceMessage
from agentic_threat_investigator.app.extraction.message_context import (
    MalformedMessageExtractionError,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceBatchPersistenceItemResult,
    EvidenceBatchPersistenceResult,
    EvidencePersistenceOutcome,
    PreparedEvidenceBatch,
)
from tests.support.evidence_batch_fixtures import (
    message_batch,
    threatfox_message,
)

pytestmark = pytest.mark.unit


class SpyEvidenceConsumer(EvidenceConsumer):
    """Deterministic consumer double recording poll bounds and commits."""

    def __init__(
        self,
        *,
        poll_result: EvidenceBatch,
        fail_poll: bool = False,
        fail_commit: bool = False,
    ) -> None:
        self.poll_result = poll_result
        self.fail_poll = fail_poll
        self.fail_commit = fail_commit
        self.poll_requests: list[int] = []
        self.committed: list[EvidenceBatch] = []

    async def poll(self, max_messages: int) -> EvidenceBatch:
        """Record the poll bound and optionally raise the injected fault."""
        self.poll_requests.append(max_messages)
        if self.fail_poll:
            raise EvidencePollError("injected poll failure")
        return self.poll_result

    async def commit(self, batch: EvidenceBatch) -> None:
        """Record the commit and optionally raise the injected fault."""
        if self.fail_commit:
            raise EvidenceCommitError("injected commit failure")
        self.committed.append(batch)


class RecordingBatchPersistence(EvidenceBatchPersistenceService):
    """Service double recording calls and exposing a pluggable implementation.

    ``impl`` overrides the default deterministic result path so tests can
    inject failures, cancellation, and ordering observations at the exact
    persistence boundary without any database.
    """

    def __init__(self) -> None:
        self.calls: list[PreparedEvidenceBatch] = []
        self.fail: BaseException | None = None
        self.impl: (
            Callable[
                [PreparedEvidenceBatch],
                Awaitable[EvidenceBatchPersistenceResult],
            ]
            | None
        ) = None
        self.result = EvidenceBatchPersistenceResult(items=())

    async def persist(
        self, prepared: PreparedEvidenceBatch
    ) -> EvidenceBatchPersistenceResult:
        """Record the prepared batch and apply the pluggable seam."""
        self.calls.append(prepared)
        if self.impl is not None:
            return await self.impl(prepared)
        if self.fail is not None:
            raise self.fail
        return self.result

    @property
    def hard_limit(self) -> int:  # pragma: no cover - unused in these tests
        """Return the configured hard ceiling (unused double attribute)."""
        return EVIDENCE_BATCH_HARD_LIMIT


def _created_result(
    messages: tuple[EvidenceMessage, ...],
) -> EvidenceBatchPersistenceResult:
    """Build the canonical all-CREATED result of one message tuple."""
    return EvidenceBatchPersistenceResult(
        items=tuple(
            EvidenceBatchPersistenceItemResult(
                message_id=message.message_id,
                evidence_id=uuid4(),
                evidence_observation_id=uuid4(),
                outcome=EvidencePersistenceOutcome.CREATED,
                version=1,
            )
            for message in messages
        )
    )


def _consumer_and_persistence(
    messages: tuple[EvidenceMessage, ...],
    *,
    fail_poll: bool = False,
    fail_commit: bool = False,
) -> tuple[EvidencePersistenceConsumer, SpyEvidenceConsumer, RecordingBatchPersistence]:
    """Wire one consumer under test with its two deterministic doubles."""
    consumer = SpyEvidenceConsumer(
        poll_result=message_batch(messages),
        fail_poll=fail_poll,
        fail_commit=fail_commit,
    )
    persistence = RecordingBatchPersistence()
    persistence.result = _created_result(messages)
    service = EvidencePersistenceConsumer(
        consumer=consumer,
        persistence=persistence,
        batch_size=EVIDENCE_BATCH_DEFAULT_SIZE,
    )
    return service, consumer, persistence


def _message(sequence: int = 0, record: str | None = None) -> EvidenceMessage:
    """Build one valid ThreatFox message with a unique execution slot."""
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id=record or f"rec-{sequence}",
        sequence=sequence,
    )
    return message


@pytest.mark.asyncio
async def test_c01_empty_poll_no_db_no_commit() -> None:
    """An empty poll opens no transaction and never commits the consumer."""
    service, consumer, persistence = _consumer_and_persistence(())
    result = await service.process_next_batch()
    assert persistence.calls == []
    assert consumer.committed == []
    assert result == EvidenceConsumerRunResult(
        polled_count=0,
        persisted_count=0,
        created_count=0,
        unchanged_count=0,
        appended_count=0,
        committed=False,
    )


@pytest.mark.asyncio
async def test_c02_one_valid_message_prepare_then_persist_then_commit() -> None:
    """One valid message runs prepare -> DB persist -> consumer commit."""
    message = _message()
    service, consumer, persistence = _consumer_and_persistence((message,))
    result = await service.process_next_batch()
    assert len(persistence.calls) == 1
    assert len(persistence.calls[0].records) == 1
    assert consumer.committed == [consumer.poll_result]
    assert result.polled_count == 1
    assert result.created_count == 1
    assert result.committed is True


@pytest.mark.asyncio
async def test_c03_several_messages_one_batch_persistence_call() -> None:
    """Several valid messages map to exactly one batch persistence call."""
    messages = tuple(_message(sequence=index) for index in range(3))
    service, consumer, persistence = _consumer_and_persistence(messages)
    result = await service.process_next_batch()
    assert len(persistence.calls) == 1
    assert len(persistence.calls[0].records) == 3
    assert result.persisted_count == 3
    assert consumer.committed == [consumer.poll_result]


@pytest.mark.asyncio
async def test_c04_configured_batch_size_is_the_poll_bound() -> None:
    """The consumer polls with exactly the configured bound."""
    service, consumer, _ = _consumer_and_persistence((_message(),))
    await service.process_next_batch()
    assert consumer.poll_requests == [EVIDENCE_BATCH_DEFAULT_SIZE]


@pytest.mark.asyncio
async def test_c05_zero_batch_size_rejected() -> None:
    """A non-positive batch size is rejected at construction."""
    consumer = SpyEvidenceConsumer(poll_result=message_batch(()))
    persistence = RecordingBatchPersistence()
    with pytest.raises(ValueError):
        EvidencePersistenceConsumer(
            consumer=consumer, persistence=persistence, batch_size=0
        )
    with pytest.raises(ValueError):
        EvidencePersistenceConsumer(
            consumer=consumer, persistence=persistence, batch_size=-1
        )


@pytest.mark.asyncio
async def test_c06_above_hard_limit_rejected() -> None:
    """A batch size above the hard limit is rejected at construction."""
    consumer = SpyEvidenceConsumer(poll_result=message_batch(()))
    persistence = RecordingBatchPersistence()
    with pytest.raises(ValueError, match="must not exceed"):
        EvidencePersistenceConsumer(
            consumer=consumer,
            persistence=persistence,
            batch_size=EVIDENCE_BATCH_HARD_LIMIT + 1,
        )


@pytest.mark.asyncio
async def test_c07_db_result_then_consumer_commit_ordering() -> None:
    """The consumer commits only after the persistence service returned."""
    message = _message()
    service, consumer, persistence = _consumer_and_persistence((message,))

    async def persist_then_record(
        prepared: PreparedEvidenceBatch,
    ) -> EvidenceBatchPersistenceResult:
        """Return the DB result first; the consumer must not have committed."""
        result = await _default_persist(persistence, prepared)
        assert consumer.committed == []
        return result

    persistence.impl = persist_then_record
    result = await service.process_next_batch()
    assert result.committed is True
    assert len(consumer.committed) == 1


async def _default_persist(
    persistence: RecordingBatchPersistence,
    prepared: PreparedEvidenceBatch,
) -> EvidenceBatchPersistenceResult:
    """Run the double's deterministic result path (failure seam included)."""
    if persistence.fail is not None:
        raise persistence.fail
    return persistence.result


@pytest.mark.asyncio
async def test_c08_db_failure_never_commits_consumer() -> None:
    """A persistence failure propagates and the consumer never commits."""
    message = _message()
    service, consumer, persistence = _consumer_and_persistence((message,))
    persistence.fail = RuntimeError("injected db failure")
    with pytest.raises(RuntimeError, match="injected db failure"):
        await service.process_next_batch()
    assert consumer.committed == []


@pytest.mark.asyncio
async def test_c09_consumer_commit_failure_after_db_success() -> None:
    """A commit failure after DB success propagates; DB stays committed."""
    message = _message()
    service, consumer, persistence = _consumer_and_persistence(
        (message,), fail_commit=True
    )
    with pytest.raises(EvidenceCommitError):
        await service.process_next_batch()
    assert len(persistence.calls) == 1
    assert consumer.committed == []


@pytest.mark.asyncio
async def test_c10_cancellation_propagates_no_false_acknowledgement() -> None:
    """Cancellation during persistence propagates and never commits."""
    message = _message()
    service, consumer, persistence = _consumer_and_persistence((message,))

    async def cancel_persist(
        _prepared: PreparedEvidenceBatch,
    ) -> EvidenceBatchPersistenceResult:
        raise asyncio.CancelledError

    persistence.impl = cancel_persist
    with pytest.raises(asyncio.CancelledError):
        await service.process_next_batch()
    assert consumer.committed == []


@pytest.mark.asyncio
async def test_c11_poll_failure_propagates_untouched() -> None:
    """A poll failure propagates before any preparation or DB work."""
    message = _message()
    service, consumer, persistence = _consumer_and_persistence(
        (message,), fail_poll=True
    )
    with pytest.raises(EvidencePollError):
        await service.process_next_batch()
    assert persistence.calls == []
    assert consumer.committed == []


@pytest.mark.asyncio
async def test_c12_malformed_message_fails_whole_batch_pre_db() -> None:
    """A malformed message fails the batch before any DB or commit."""
    malformed_message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id="rec-bad",
        facts={"matches": []},
    )
    service, consumer, persistence = _consumer_and_persistence((malformed_message,))
    with pytest.raises(MalformedMessageExtractionError):
        await service.process_next_batch()
    assert persistence.calls == []
    assert consumer.committed == []
