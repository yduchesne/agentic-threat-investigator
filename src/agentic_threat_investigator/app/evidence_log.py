# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Application-level distributed Evidence log contracts and deterministic in-memory log (PR 28D).

PR 28D defines ATI's broker-neutral Evidence log seam **before** Kafka/
Redpanda infrastructure exists. The log carries exactly PR 28C
:class:`EvidenceMessage` values — never ``ConvertedEvidence``, semantic
source objects, committed ``EvidenceObservation`` rows, graph state,
Investigation work, or arbitrary bytes.

Dominant invariants of this module:

- The log is an **ordered, replayable, append-only** stream. ``poll()`` is
  non-destructive: it never removes records and never acknowledges them.
  An uncommitted batch is always redeliverable; records remain present for
  the entire log-instance lifetime even after every consumer commits them.
- Delivery is **at-least-once**. Only an explicit ``commit(batch)`` advances
  one consumer's committed position. Polling without commit changes nothing.
- Positions are **transport state only**. ``EvidenceLogPosition`` is a
  per-instance ordering index, never an Evidence ID, a message ID, an
  observation-candidate ID, or a PostgreSQL idempotency key. Committed
  cursors are per-consumer transport state as well.
- The contracts are **broker-neutral**: no Kafka topics, partitions,
  offsets, consumer-group protocols, rebalance callbacks, broker objects,
  or generic event-bus framework types appear anywhere in this module.
- The in-memory implementation is **process-lifetime only**. It models
  restart within one log instance (recreating a consumer handle with the
  same identity resumes the same cursor) but is not durable across process
  restart and is not a production substitute for Kafka/Redpanda (PR 28G).
- Deterministic one-shot fault injection (``fail_next_publish()``,
  ``fail_next_poll()``, ``fail_next_commit()``) lets tests simulate the
  next publish/poll/commit failure and its natural redelivery without
  random probabilities or sleeps. Publish faults consume no position;
  poll faults change no cursor; commit faults leave the cursor unchanged so
  the next poll naturally redelivers the batch.

No database, network, UnitOfWork, or clock belongs here. ``publish`` is
the sole writer of records; ``commit`` mutates only one consumer's cursor.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

from agentic_threat_investigator.app.evidence_message import EvidenceMessage

EVIDENCE_CONSUMER_ID_MAX_LENGTH = 128
"""Maximum length of one :class:`EvidenceConsumerId` value (PR 28D).

The identity is bounded so unbounded user/content strings can never enter
log state; values longer than this fail closed at construction.
"""


class EvidenceLogError(RuntimeError):
    """Base failure of the distributed Evidence log contracts (PR 28D).

    All operational log failures are typed ``RuntimeError`` subclasses so
    callers can rely on one base class; the leaf types below distinguish
    publish, poll, and commit failures without exposing raw payloads or
    exception internals. Error text is bounded and never echoes message
    content.
    """


class EvidencePublishError(EvidenceLogError):
    """A publish call failed; no records were appended and no position used."""


class EvidencePollError(EvidenceLogError):
    """A poll call failed; the consumer cursor is unchanged."""


class EvidenceCommitError(EvidenceLogError):
    """A commit call failed; the consumer cursor is unchanged.

    A failed commit leaves the cursor at its previous value, so the next
    poll naturally redelivers the uncommitted batch.
    """


@dataclass(frozen=True, order=True)
class EvidenceLogPosition:
    """Zero-based ordered position of one record within one log instance.

    Positions are assigned monotonically at publication time, ordered by
    publication, and never reused. A position is transport state only: it
    is not an Evidence ID, a message ID, an observation-candidate ID, or a
    PostgreSQL idempotency key, and it is never serialized into an
    :class:`EvidenceMessage`.
    """

    value: int

    def __post_init__(self) -> None:
        """Reject negative or non-integer positions at construction."""
        if (
            not isinstance(self.value, int)
            or isinstance(self.value, bool)
            or self.value < 0
        ):
            raise ValueError("log position must be a non-negative integer")


@dataclass(frozen=True)
class EvidenceLogRecord:
    """One immutable log record: an ordered position plus a validated message.

    The application abstraction carries a validated PR 28C
    :class:`EvidenceMessage`, never arbitrary bytes; PR 28C owns
    serialization and a future infrastructure adapter may encode/decode at
    its own boundary.
    """

    position: EvidenceLogPosition
    message: EvidenceMessage


@dataclass(frozen=True)
class EvidenceConsumerId:
    """ATI-owned identity of one consumer cursor within one log instance.

    The identity is a bounded, non-blank string; it is not an Investigation
    ID, a datasource execution ID, a source ID, or a message ID. Recreating
    a consumer handle with the same identity against the same log resumes
    the same committed cursor; different identities are fully independent.
    """

    value: str

    def __post_init__(self) -> None:
        """Reject blank or oversized consumer identities at construction."""
        if not isinstance(self.value, str):
            raise ValueError("consumer id must be a string")
        if not self.value.strip():
            raise ValueError("consumer id must not be blank")
        if len(self.value) > EVIDENCE_CONSUMER_ID_MAX_LENGTH:
            raise ValueError(
                "consumer id must not exceed "
                f"{EVIDENCE_CONSUMER_ID_MAX_LENGTH} characters"
            )


@dataclass(frozen=True)
class EvidenceBatch:
    """One immutable poll result for exactly one consumer.

    The batch is descriptive only: it carries the owning consumer identity
    and the ordered records returned by one ``poll()`` call and contains no
    mutable acknowledgement state. An empty poll returns an empty batch for
    the same consumer; committing an empty batch is a no-op.
    """

    consumer_id: EvidenceConsumerId
    records: tuple[EvidenceLogRecord, ...]


@dataclass(frozen=True)
class EvidencePublishResult:
    """The ordered records appended by one successful publish call.

    Brokers, databases, consumers, and lifecycle metadata are deliberately
    absent; only the appended application records are returned.
    """

    records: tuple[EvidenceLogRecord, ...]


class EvidencePublisher(ABC):
    """Broker-neutral publisher contract of the Evidence log (PR 28D).

    Implementations append PR 28C messages in input order as one contiguous
    run of records. Publishing the same message twice creates two records:
    the log is not a dedupe service and downstream persistence owns
    semantic idempotency.
    """

    @abstractmethod
    async def publish(
        self, messages: Sequence[EvidenceMessage]
    ) -> EvidencePublishResult:
        """Publish one ordered run of messages and return the appended records.

        A single call appends all records contiguously and is all-or-nothing:
        on failure nothing is appended and no position is consumed. An empty
        run is a deterministic no-op returning zero records (unless a
        one-shot publish fault is armed).
        """


class EvidenceConsumer(ABC):
    """Broker-neutral consumer contract of the Evidence log (PR 28D).

    Polling is bounded and non-acknowledging: ``poll(max_messages)``
    returns at most ``max_messages`` records starting at the consumer's
    committed cursor without changing it, so a repeated poll before commit
    returns the same prefix and an uncommitted batch is redeliverable. Only
    an explicit ``commit(batch)`` advances the cursor, and only for an
    exact valid contiguous batch starting at the current cursor. Polling
    returns immediately when nothing is available; there is no blocking
    long-poll and no in-flight lease: the committed cursor is the
    authoritative consumer state.
    """

    @abstractmethod
    async def poll(self, max_messages: int) -> EvidenceBatch:
        """Return the bounded next uncommitted prefix without acknowledging it."""

    @abstractmethod
    async def commit(self, batch: EvidenceBatch) -> None:
        """Advance the committed cursor exactly past one valid batch.

        Foreign, forged, skipped, reversed, or stale batches fail closed;
        a commit failure never changes the cursor.
        """


class InMemoryEvidenceLog:
    """Deterministic append-only Evidence log with per-consumer cursors.

    Owns the ordered records, the next position, one committed cursor per
    :class:`EvidenceConsumerId`, the single ``asyncio.Lock`` serializing
    publish/poll/commit within one event loop, and the narrow one-shot
    fault controls. Records are retained for the entire log-instance
    lifetime — even after every consumer commits them — and are never
    removed or compacted.

    Public surface:

    - ``publisher()`` -> a broker-neutral publisher handle;
    - ``consumer(EvidenceConsumerId(...))`` -> a broker-neutral consumer
      handle bound to one identity;
    - ``fail_next_publish()`` / ``fail_next_poll()`` /
      ``fail_next_commit()`` -> deterministic one-shot fault controls.

    The implementation is in-memory only: it models restart within one log
    instance (same identity resumes the same cursor) but provides no
    durability across process restart and no cross-process guarantees.
    """

    def __init__(self) -> None:
        """Initialize an empty append-only log with no consumer cursors."""
        self._records: list[EvidenceLogRecord] = []
        self._committed: dict[EvidenceConsumerId, int] = {}
        self._lock = asyncio.Lock()
        self._fail_next_publish = False
        self._fail_next_poll_global = False
        self._fail_next_commit_global = False
        self._fail_next_poll_consumers: set[EvidenceConsumerId] = set()
        self._fail_next_commit_consumers: set[EvidenceConsumerId] = set()

    def publisher(self) -> EvidencePublisher:
        """Return a publisher handle sharing this log's state."""
        return _EvidencePublisherHandle(self)

    def consumer(self, consumer_id: EvidenceConsumerId) -> EvidenceConsumer:
        """Return a consumer handle bound to one identity.

        A first-seen identity begins at position 0; recreating a handle with
        the same identity against the same log resumes the same committed
        cursor.
        """
        return _EvidenceConsumerHandle(self, consumer_id)

    def fail_next_publish(self) -> None:
        """Arm a one-shot publish fault: the next publish call fails.

        The armed fault does not consume a position; a subsequent publish
        call continues from the original next position.
        """
        self._fail_next_publish = True

    def fail_next_poll(self, consumer_id: EvidenceConsumerId | None = None) -> None:
        """Arm a one-shot poll fault for one consumer or for the next poll.

        With a ``consumer_id`` only that consumer's next poll fails and
        other consumers are unaffected; without one, the next poll call from
        any consumer fails. A triggered fault changes no cursor.
        """
        if consumer_id is not None:
            self._fail_next_poll_consumers.add(consumer_id)
        else:
            self._fail_next_poll_global = True

    def fail_next_commit(self, consumer_id: EvidenceConsumerId | None = None) -> None:
        """Arm a one-shot commit fault for one consumer or for the next commit.

        With a ``consumer_id`` only that consumer's next commit fails and
        other consumers are unaffected; without one, the next commit call
        from any consumer fails. A triggered fault changes no cursor, so
        the next poll naturally redelivers the batch.
        """
        if consumer_id is not None:
            self._fail_next_commit_consumers.add(consumer_id)
        else:
            self._fail_next_commit_global = True

    async def _publish(
        self, messages: Sequence[EvidenceMessage]
    ) -> EvidencePublishResult:
        """Append one ordered run of validated messages under the log lock.

        Validates that every element is a PR 28C message, fires an armed
        one-shot publish fault before any mutation, treats an empty run as a
        documented no-op returning zero records, allocates contiguous
        positions, and appends all records atomically with respect to other
        log operations.
        """
        for message in messages:
            if not isinstance(message, EvidenceMessage):
                raise EvidencePublishError(
                    "publish accepts only EvidenceMessage values"
                )
        async with self._lock:
            if self._fail_next_publish:
                self._fail_next_publish = False
                raise EvidencePublishError("injected publish failure")
            if not messages:
                return EvidencePublishResult(records=())
            start = len(self._records)
            records = tuple(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(start + index),
                    message=message,
                )
                for index, message in enumerate(messages)
            )
            self._records.extend(records)
            return EvidencePublishResult(records=records)

    async def _poll(
        self, consumer_id: EvidenceConsumerId, max_messages: int
    ) -> EvidenceBatch:
        """Return the bounded next uncommitted prefix for one consumer.

        Rejects a non-positive bound before any state access, fires an armed
        one-shot poll fault without mutating the cursor, reads the
        consumer's committed cursor, and slices at most ``max_messages``
        ordered records. The cursor is never changed by a poll.
        """
        if (
            not isinstance(max_messages, int)
            or isinstance(max_messages, bool)
            or max_messages <= 0
        ):
            raise EvidencePollError("poll max_messages must be a positive integer")
        async with self._lock:
            if consumer_id in self._fail_next_poll_consumers:
                self._fail_next_poll_consumers.discard(consumer_id)
                raise EvidencePollError("injected poll failure")
            if self._fail_next_poll_global:
                self._fail_next_poll_global = False
                raise EvidencePollError("injected poll failure")
            cursor = self._committed.get(consumer_id, 0)
            records = tuple(self._records[cursor : cursor + max_messages])
            return EvidenceBatch(consumer_id=consumer_id, records=records)

    async def _commit(
        self, consumer_id: EvidenceConsumerId, batch: EvidenceBatch
    ) -> None:
        """Advance one consumer cursor only for an exact valid contiguous batch.

        Ownership of ``batch.consumer_id`` is validated first; an empty
        batch is a no-op (and never consumes an armed commit fault); then,
        under the lock, an armed one-shot commit fault fires before any
        mutation. A valid commit must start exactly at the consumer's
        current cursor, hold positions ordered and contiguous, and match the
        authoritative log record at every position; the cursor then becomes
        one past the batch's final record. Skipped, stale/repeated, forged,
        reversed, non-contiguous, or beyond-log batches fail closed with a
        typed :class:`EvidenceCommitError` and the cursor is unchanged.

        Committing a strict prefix of the currently uncommitted run is a
        valid whole-batch commit identical to committing the exact result
        of a smaller poll: the cursor advances exactly past the batch's
        final record and the remaining records stay redeliverable. No
        in-flight lease or partial-acknowledgement state is tracked; the
        committed cursor is the only per-consumer state.
        """
        if batch.consumer_id != consumer_id:
            raise EvidenceCommitError("batch belongs to another consumer")
        if not batch.records:
            return
        async with self._lock:
            if consumer_id in self._fail_next_commit_consumers:
                self._fail_next_commit_consumers.discard(consumer_id)
                raise EvidenceCommitError("injected commit failure")
            if self._fail_next_commit_global:
                self._fail_next_commit_global = False
                raise EvidenceCommitError("injected commit failure")
            cursor = self._committed.get(consumer_id, 0)
            first = batch.records[0].position.value
            if first < cursor:
                raise EvidenceCommitError(
                    "batch starts before the committed cursor "
                    "(stale or repeated commit)"
                )
            if first > cursor:
                raise EvidenceCommitError(
                    "batch starts after the committed cursor (skipped positions)"
                )
            expected = first
            for record in batch.records:
                position = record.position.value
                if position != expected:
                    raise EvidenceCommitError(
                        "batch positions must be contiguous and ordered"
                    )
                if position >= len(self._records):
                    raise EvidenceCommitError(
                        "batch references a position beyond the log"
                    )
                if self._records[position] != record:
                    raise EvidenceCommitError(
                        "batch record does not match the authoritative log record"
                    )
                expected = position + 1
            self._committed[consumer_id] = expected


class _EvidencePublisherHandle(EvidencePublisher):
    """Small publisher handle sharing one ``InMemoryEvidenceLog`` state."""

    def __init__(self, log: InMemoryEvidenceLog) -> None:
        """Bind the handle to exactly one log instance."""
        self._log = log

    async def publish(
        self, messages: Sequence[EvidenceMessage]
    ) -> EvidencePublishResult:
        """Delegate the ordered publish to the owning log."""
        return await self._log._publish(messages)


class _EvidenceConsumerHandle(EvidenceConsumer):
    """Small consumer handle bound to one identity on one log instance.

    The handle carries no cursor state: the committed cursor of its
    :class:`EvidenceConsumerId` lives in the owning log, so recreating a
    handle with the same identity resumes the same cursor.
    """

    def __init__(
        self, log: InMemoryEvidenceLog, consumer_id: EvidenceConsumerId
    ) -> None:
        """Bind the handle to one log instance and one consumer identity."""
        self._log = log
        self._consumer_id = consumer_id

    async def poll(self, max_messages: int) -> EvidenceBatch:
        """Poll the next uncommitted prefix for this consumer's cursor."""
        return await self._log._poll(self._consumer_id, max_messages)

    async def commit(self, batch: EvidenceBatch) -> None:
        """Commit exactly one valid batch for this consumer's cursor."""
        await self._log._commit(self._consumer_id, batch)
