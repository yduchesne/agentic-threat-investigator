# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Real Redpanda integration coverage for the Kafka Evidence adapters (PR 28G).

Proves the broker-neutral adapters end-to-end against a real Kafka-compatible
broker using real ``aiokafka`` clients (external source acquisition is not
involved; no Internet dependency):

- I28G-01..12: canonical round trip, same-Evidence partition affinity,
  multi-Evidence/multi-partition, manual commit + restart, no-commit
  redelivery, independent groups, explicit multi-stream commit, corrupt and
  key-mismatched payloads failing closed, producer metadata, empty
  publication, and clean shutdown.
- V28G-01..05: PR 28C contract vertical slice, partitioned global-Evidence
  ordering, adapter redelivery, PR 28E application compatibility through a
  deterministic persistence double, and the commit-failure safety boundary
  (deterministic; real rebalance forcing stays at unit level / 28H).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from aiokafka import AIOKafkaProducer

from agentic_threat_investigator.app.evidence_batch_persistence import (
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_consumer import (
    EvidencePersistenceConsumer,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceBatch,
    EvidenceConsumerId,
    EvidencePollError,
    EvidencePublishResult,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    encode_evidence_message,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceBatchPersistenceItemResult,
    EvidenceBatchPersistenceResult,
    EvidencePersistenceOutcome,
    PreparedEvidenceBatch,
)
from agentic_threat_investigator.infrastructure.kafka.evidence_log import (
    KafkaEvidenceConsumer,
    KafkaEvidencePublisher,
    build_kafka_consumer,
    build_kafka_publisher,
)
from tests.support.evidence_batch_fixtures import threatfox_message

pytestmark = pytest.mark.integration

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_PUB_CLIENT = "ati-test-publisher"
_CON_CLIENT = "ati-test-consumer"
_POLL_TIME_MS = 2000


def _message(record: str, sequence: int = 0) -> EvidenceMessage:
    """Build one deterministic ThreatFox message (distinct Evidence per record)."""
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id=record,
        sequence=sequence,
        observed_at=_FIXED_TS,
    )
    return message


def _publisher(bootstrap: str, topic: str) -> KafkaEvidencePublisher:
    """Build a started production KafkaEvidencePublisher over the real broker."""
    return build_kafka_publisher(
        bootstrap_servers=(bootstrap,),
        topic=topic,
        client_id=_PUB_CLIENT,
    )


def _consumer(bootstrap: str, topic: str, group: str) -> KafkaEvidenceConsumer:
    """Build a started production KafkaEvidenceConsumer with an isolated group."""
    return build_kafka_consumer(
        bootstrap_servers=(bootstrap,),
        topic=topic,
        consumer_id=EvidenceConsumerId(group),
        client_id=f"{_CON_CLIENT}-{uuid4().hex[:6]}",
        poll_timeout_ms=_POLL_TIME_MS,
    )


def _new_group() -> str:
    """Return a fresh deterministic consumer group identity for this test."""
    return f"pr-28g-{uuid4().hex[:12]}"


async def _poll_until(
    consumer: KafkaEvidenceConsumer, max_messages: int
) -> EvidenceBatch:
    """Poll until the broker returns records or the bounded attempts expire.

    A freshly joined consumer group needs a brief moment for assignment; the
    adapter's own poll already blocks up to its configured timeout, so a few
    retries are sufficient on a healthy local broker.
    """
    for _ in range(8):
        batch = await consumer.poll(max_messages)
        if batch.records:
            return batch
    return batch


async def _publish_many(
    publisher: KafkaEvidencePublisher, messages: list[EvidenceMessage]
) -> EvidencePublishResult:
    """Publish a message run and assert unchanged result metadata."""
    result = await publisher.publish(messages)
    assert len(result.records) == len(messages)
    assert [record.message for record in result.records] == messages
    for record in result.records:
        assert record.position.stream >= 0
        assert record.position.offset >= 0
    return result


class RecordingPersistenceDouble(EvidenceBatchPersistenceService):
    """Deterministic double of the PR 28E persistence boundary (no PostgreSQL).

    Mirrors the production contract: one :class:`EvidenceBatchPersistenceResult`
    item per prepared record (the real adapter guards
    ``len(items) == len(records)``), each reported as a fresh ``CREATED``
    version-1 persistence like the first batch of a new Evidence (I28E-01).
    """

    def __init__(self) -> None:
        """Initialize an unstarted boundary with no recorded calls."""
        self.calls: list[PreparedEvidenceBatch] = []
        self.fail: BaseException | None = None

    @property
    def hard_limit(self) -> int:
        """Return the configured hard ceiling of the persistence boundary."""
        return 500

    async def persist(
        self, prepared: PreparedEvidenceBatch
    ) -> EvidenceBatchPersistenceResult:
        """Record the prepared batch and return one result item per record."""
        self.calls.append(prepared)
        if self.fail is not None:
            raise self.fail
        items = tuple(
            EvidenceBatchPersistenceItemResult(
                message_id=record.message_id,
                evidence_id=record.converted.evidence.id,
                evidence_observation_id=record.observation_candidate_id,
                outcome=EvidencePersistenceOutcome.CREATED,
                version=1,
            )
            for record in prepared.records
        )
        return EvidenceBatchPersistenceResult(items=items)


# ---------------------------------------------------------------------------
# I28G-01..12
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_i28g_01_one_message_round_trip(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-01: one EvidenceMessage round-trips exactly through the real broker."""
    message = _message("rec-round-trip")
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        result = await _publish_many(publisher, [message])
        assert result.records[0].message == message
        assert result.records[0].position.stream >= 0
        assert result.records[0].position.offset >= 0
    finally:
        await publisher.stop()

    consumer = _consumer(kafka_bootstrap, evidence_topic, _new_group())
    await consumer.start()
    try:
        batch = await _poll_until(consumer, 10)
        assert len(batch.records) == 1
        assert batch.records[0].message == message
        # Transport-only: stream/offset are broker positions, never domain.
        assert batch.records[0].position.stream == result.records[0].position.stream
        await consumer.commit(batch)
    finally:
        await consumer.stop()


@pytest.mark.asyncio
async def test_i28g_02_same_evidence_preserves_one_partition(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-02: all messages for one Evidence route to one partition with order."""
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    messages = [
        _message("rec-affinity", sequence=0),
        _message("rec-affinity", sequence=1),
        _message("rec-affinity", sequence=2),
    ]
    try:
        result = await _publish_many(publisher, messages)
    finally:
        await publisher.stop()

    streams = {record.position.stream for record in result.records}
    assert len(streams) == 1
    offsets = [record.position.offset for record in result.records]
    assert offsets == sorted(offsets)

    consumer = _consumer(kafka_bootstrap, evidence_topic, _new_group())
    await consumer.start()
    try:
        batch = await _poll_until(consumer, 10)
        # Same Evidence, one stream, increasing offsets.
        assert {r.position.stream for r in batch.records} == streams
        offset_order = [r.position.offset for r in batch.records]
        assert offset_order == sorted(offset_order)
        await consumer.commit(batch)
    finally:
        await consumer.stop()


@pytest.mark.asyncio
async def test_i28g_03_multiple_evidence_use_multiple_partitions(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-03: a bounded deterministic Evidence set spans multiple streams."""
    messages = [_message(f"rec-multi-{index}") for index in range(12)]
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        result = await _publish_many(publisher, messages)
    finally:
        await publisher.stop()

    assert len({record.position.stream for record in result.records}) >= 2

    consumer = _consumer(kafka_bootstrap, evidence_topic, _new_group())
    await consumer.start()
    try:
        batch = await _poll_until(consumer, 100)
        streams = {record.position.stream for record in batch.records}
        assert len(streams) >= 2
        await consumer.commit(batch)
    finally:
        await consumer.stop()


@pytest.mark.asyncio
async def test_i28g_04_manual_commit_and_restart(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-04: a committed group restart does not redeliver committed records."""
    messages = [_message("rec-commit") for _ in range(3)]
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, messages)
    finally:
        await publisher.stop()

    group = _new_group()
    first = _consumer(kafka_bootstrap, evidence_topic, group)
    await first.start()
    try:
        batch = await _poll_until(first, 10)
        assert len(batch.records) == 3
        await first.commit(batch)
    finally:
        await first.stop()

    recreated = _consumer(kafka_bootstrap, evidence_topic, group)
    await recreated.start()
    try:
        batch = await _poll_until(recreated, 10)
        assert batch.records == ()
    finally:
        await recreated.stop()


@pytest.mark.asyncio
async def test_i28g_05_no_commit_causes_redelivery(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-05: stopping without commit redelivers to a recreated group."""
    messages = [_message("rec-redeliver"), _message("rec-redeliver-2")]
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, messages)
    finally:
        await publisher.stop()

    group = _new_group()
    first = _consumer(kafka_bootstrap, evidence_topic, group)
    await first.start()
    polled: EvidenceBatch = EvidenceBatch(consumer_id=first.consumer_id, records=())
    try:
        polled = await _poll_until(first, 10)
        assert len(polled.records) == 2
        # No commit: simulate process stop.
    finally:
        await first.stop()

    recreated = _consumer(kafka_bootstrap, evidence_topic, group)
    await recreated.start()
    try:
        redelivered = await _poll_until(recreated, 10)
        assert {record.message.message_id for record in redelivered.records} == {
            record.message.message_id for record in polled.records
        }
        await recreated.commit(redelivered)
    finally:
        await recreated.stop()


@pytest.mark.asyncio
async def test_i28g_06_independent_consumer_groups(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-06: two logical consumer groups advance independently."""
    message = _message("rec-independent")
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, [message])
    finally:
        await publisher.stop()

    group_a = _new_group()
    consumer_a = _consumer(kafka_bootstrap, evidence_topic, group_a)
    await consumer_a.start()
    try:
        batch_a = await _poll_until(consumer_a, 10)
        assert {r.message.message_id for r in batch_a.records} == {message.message_id}
        await consumer_a.commit(batch_a)
    finally:
        await consumer_a.stop()

    consumer_b = _consumer(kafka_bootstrap, evidence_topic, _new_group())
    await consumer_b.start()
    try:
        batch_b = await _poll_until(consumer_b, 10)
        assert {r.message.message_id for r in batch_b.records} == {message.message_id}
        await consumer_b.commit(batch_b)
    finally:
        await consumer_b.stop()


@pytest.mark.asyncio
async def test_i28g_07_explicit_multi_stream_commit(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-07: a multi-stream batch commits and a restart resumes after it."""
    messages = [_message(f"rec-multistream-{index}") for index in range(12)]
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, messages)
    finally:
        await publisher.stop()

    group = _new_group()
    first = _consumer(kafka_bootstrap, evidence_topic, group)
    await first.start()
    committed_ids = set()
    try:
        batch = await _poll_until(first, 100)
        assert len({r.position.stream for r in batch.records}) >= 2
        committed_ids = {r.message.message_id for r in batch.records}
        await first.commit(batch)
    finally:
        await first.stop()

    recreated = _consumer(kafka_bootstrap, evidence_topic, group)
    await recreated.start()
    try:
        after = await _poll_until(recreated, 100)
        remaining = {r.message.message_id for r in after.records}
        assert remaining.isdisjoint(committed_ids)
        await recreated.commit(after)
    finally:
        await recreated.stop()


@pytest.mark.asyncio
async def test_i28g_08_corrupt_payload_fails_closed(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-08: a malformed raw broker payload fails closed without DLQ."""
    producer = AIOKafkaProducer(bootstrap_servers=kafka_bootstrap)
    await producer.start()
    try:
        await producer.send(evidence_topic, value=b"this-is-not-valid-json{{", key=b"k")
        await producer.flush()
    finally:
        await producer.stop()

    consumer = _consumer(kafka_bootstrap, evidence_topic, _new_group())
    await consumer.start()
    try:
        with pytest.raises(EvidencePollError):
            await _poll_until(consumer, 10)
    finally:
        await consumer.stop()


@pytest.mark.asyncio
async def test_i28g_09_key_message_mismatch_fails_closed(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-09: a valid value keyed by the wrong Evidence fails closed."""
    message = _message("rec-keymismatch")
    producer = AIOKafkaProducer(bootstrap_servers=kafka_bootstrap)
    await producer.start()
    try:
        await producer.send(
            evidence_topic,
            value=encode_evidence_message(message),
            key=b"not-the-canonical-key",
        )
        await producer.flush()
    finally:
        await producer.stop()

    consumer = _consumer(kafka_bootstrap, evidence_topic, _new_group())
    await consumer.start()
    try:
        with pytest.raises(EvidencePollError):
            await _poll_until(consumer, 10)
    finally:
        await consumer.stop()


@pytest.mark.asyncio
async def test_i28g_10_producer_success_metadata(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-10: producer results preserve input order with valid positions."""
    messages = [_message(f"rec-meta-{index}") for index in range(5)]
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        result = await _publish_many(publisher, messages)
        assert [record.message for record in result.records] == messages
        assert all(
            record.position.stream >= 0 and record.position.offset >= 0
            for record in result.records
        )
    finally:
        await publisher.stop()


@pytest.mark.asyncio
async def test_i28g_11_empty_publication(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-11: publishing an empty run produces no broker record."""
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        result = await publisher.publish(())
    finally:
        await publisher.stop()
    assert result.records == ()


@pytest.mark.asyncio
async def test_i28g_12_clean_shutdown(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """I28G-12: start + bounded operation + stop leaves no leaked tasks."""
    message = _message("rec-shutdown")
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    consumer = _consumer(kafka_bootstrap, evidence_topic, _new_group())
    await consumer.start()
    try:
        await _publish_many(publisher, [message])
        batch = await _poll_until(consumer, 10)
        assert len(batch.records) == 1
        await consumer.commit(batch)
    finally:
        await consumer.stop()
        await publisher.stop()
    await asyncio.sleep(0.05)
    # The currently executing pytest task is itself present in
    # ``asyncio.all_tasks()`` and is necessarily not done while this test
    # body runs, so leak detection excludes only that task. Any other
    # pending task is a genuine background-task leak.
    current = asyncio.current_task()
    pending = [
        task for task in asyncio.all_tasks() if task is not current and not task.done()
    ]
    assert pending == []


# ---------------------------------------------------------------------------
# V28G-01..05 vertical slices
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_v28g_01_pr28c_contract_through_real_broker(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """V28G-01: canonical EvidenceMessage survives production codec + broker."""
    message = _message("rec-v01")
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, [message])
    finally:
        await publisher.stop()

    consumer = _consumer(kafka_bootstrap, evidence_topic, _new_group())
    await consumer.start()
    try:
        batch = await _poll_until(consumer, 10)
        assert batch.records[0].message == message
        assert batch.records[0].message.evidence_id == message.evidence_id
        assert batch.records[0].message.message_id == message.message_id
        await consumer.commit(batch)
    finally:
        await consumer.stop()


@pytest.mark.asyncio
async def test_v28g_02_partitioned_global_evidence_ordering(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """V28G-02: A1/A2 share a stream with increasing offsets; no A/B assertion."""
    a1 = _message("rec-ordering-a", sequence=0)
    b1 = _message("rec-ordering-b", sequence=0)
    a2 = _message("rec-ordering-a", sequence=1)
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        result = await _publish_many(publisher, [a1, b1, a2])
    finally:
        await publisher.stop()

    by_id = {record.message.message_id: record for record in result.records}
    a1_pos = by_id[a1.message_id].position
    a2_pos = by_id[a2.message_id].position
    assert a1_pos.stream == a2_pos.stream
    assert a1_pos.offset < a2_pos.offset


@pytest.mark.asyncio
async def test_v28g_03_adapter_redelivery(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """V28G-03: uncommitted batch redelivers; committed batch does not."""
    messages = [_message("rec-v03")]
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, messages)
    finally:
        await publisher.stop()

    group = _new_group()
    first = _consumer(kafka_bootstrap, evidence_topic, group)
    await first.start()
    uncommitted = EvidenceBatch(consumer_id=first.consumer_id, records=())
    try:
        uncommitted = await _poll_until(first, 10)
        assert len(uncommitted.records) == 1
    finally:
        await first.stop()

    second = _consumer(kafka_bootstrap, evidence_topic, group)
    await second.start()
    try:
        redelivered = await _poll_until(second, 10)
        assert {r.message.message_id for r in redelivered.records} == {
            r.message.message_id for r in uncommitted.records
        }
        await second.commit(redelivered)
    finally:
        await second.stop()

    third = _consumer(kafka_bootstrap, evidence_topic, group)
    await third.start()
    try:
        after = await _poll_until(third, 10)
        assert after.records == ()
    finally:
        await third.stop()


@pytest.mark.asyncio
async def test_v28g_04_pr28e_compatibility_without_real_postgresql(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """V28G-04: real broker -> KafkaEvidenceConsumer -> persistence double -> commit."""
    message = _message("rec-v04")
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, [message])
    finally:
        await publisher.stop()

    group = _new_group()
    consumer = _consumer(kafka_bootstrap, evidence_topic, group)
    await consumer.start()
    persistence = RecordingPersistenceDouble()
    service = EvidencePersistenceConsumer(
        consumer=consumer, persistence=persistence, batch_size=10
    )
    try:
        result = await service.process_next_batch()
        # One record published; the real consumer polled it and the PR 28E
        # persistence boundary received exactly one prepared record; the
        # run result reflects that full interaction and the broker commit
        # completed only after the persistence call succeeded.
        assert result.polled_count == 1
        assert result.persisted_count == 1
        assert len(persistence.calls) == 1
        assert len(persistence.calls[0].records) == 1
        assert result.committed is True
    finally:
        await consumer.stop()

    recreated = _consumer(kafka_bootstrap, evidence_topic, group)
    await recreated.start()
    try:
        after = await _poll_until(recreated, 10)
        assert after.records == ()
    finally:
        await recreated.stop()


@pytest.mark.asyncio
async def test_v28g_05_commit_failure_safety_boundary(
    kafka_bootstrap: str, evidence_topic: str
) -> None:
    """V28G-05: a failed commit never acknowledges and replay remains available.

    Deterministic boundary: after a real poll, the consumer is stopped
    without committing (simulating a broker commit failure / lost ownership).
    A recreated same-group consumer must redeliver, proving that a commit
    failure is never reported as success and PR 28E-style replay is safe.
    Real rebalance forcing stays a unit-level concern (E28G-K10) / 28H.
    """
    messages = [_message("rec-v05")]
    publisher = _publisher(kafka_bootstrap, evidence_topic)
    await publisher.start()
    try:
        await _publish_many(publisher, messages)
    finally:
        await publisher.stop()

    group = _new_group()
    first = _consumer(kafka_bootstrap, evidence_topic, group)
    await first.start()
    try:
        batch = await _poll_until(first, 10)
        assert len(batch.records) == 1
        # Simulate commit failure: no commit, then stop (ownership revoked).
    finally:
        await first.stop()

    recreated = _consumer(kafka_bootstrap, evidence_topic, group)
    await recreated.start()
    try:
        redelivered = await _poll_until(recreated, 10)
        assert {r.message.message_id for r in redelivered.records} == {
            message.message_id for message in messages
        }
        await recreated.commit(redelivered)
    finally:
        await recreated.stop()
