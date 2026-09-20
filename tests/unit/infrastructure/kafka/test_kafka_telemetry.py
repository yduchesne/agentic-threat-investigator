# SPDX-License-Identifier: AGPL-3.0-only
"""Kafka/Redpanda transport telemetry tests (PR 29A-1).

Exercises ``KafkaEvidencePublisher``/``KafkaEvidenceConsumer`` telemetry
against the same deterministic broker boundary doubles as the PR 28G
adapter matrix, asserting the PT-K publish/poll/commit counters, durations,
and privacy rules.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest
from aiokafka.structs import RecordMetadata, TopicPartition

from agentic_threat_investigator.app.evidence_log import (
    EvidenceBatch,
    EvidenceCommitError,
    EvidenceConsumerId,
    EvidenceLogPosition,
    EvidenceLogRecord,
    EvidencePollError,
)
from agentic_threat_investigator.infrastructure.kafka.evidence_log import (
    AsyncKafkaConsumer,
    AsyncKafkaProducer,
    KafkaEvidenceConsumer,
    KafkaEvidencePublisher,
    evidence_id_key,
)
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.otel import (
    counter_value,
    data_point_attributes,
    histogram_count,
    metrics_by_name,
)
from tests.unit.infrastructure.kafka.test_kafka_evidence_log import (
    TOPIC,
    _message,
    _metadata,
    _record,
)

GROUP = "evidence-persistence"
_CONSUMER_ID = EvidenceConsumerId(GROUP)


class FakeProducer(AsyncKafkaProducer):
    """Deterministic aiokafka producer double (PR 29A-1 telemetry matrix)."""

    def __init__(self) -> None:
        """Initialize delivery scripting and the injection force flags."""
        self.started = False
        self.stopped = False
        self.sends: list[dict[str, Any]] = []
        self.results: list[RecordMetadata | BaseException] = []

    async def start(self) -> None:
        """Mark started."""
        self.started = True

    async def stop(self) -> None:
        """Mark stopped."""
        self.stopped = True

    async def send(
        self,
        topic: str,
        value: bytes | None = None,
        key: bytes | None = None,
        partition: int | None = None,
    ) -> asyncio.Future[RecordMetadata]:
        """Return a delivery future scripted from ``results`` in order."""
        self.sends.append(
            {"topic": topic, "value": value, "key": key, "partition": partition}
        )
        index = len(self.sends) - 1
        outcome: RecordMetadata | BaseException = (
            self.results[index] if index < len(self.results) else _metadata(0, index)
        )
        delivery: asyncio.Future[RecordMetadata] = (
            asyncio.get_running_loop().create_future()
        )
        if isinstance(outcome, BaseException):
            delivery.set_exception(outcome)
        else:
            delivery.set_result(cast(RecordMetadata, outcome))
        return delivery


class FakeConsumer(AsyncKafkaConsumer):
    """Deterministic aiokafka consumer double (PR 29A-1 telemetry matrix)."""

    def __init__(self) -> None:
        """Initialize fetch/commit scripting and injection flags."""
        self.started = False
        self.stopped = False
        self.fetched: dict[int, list[Any]] = {}
        self.commits: list[dict[TopicPartition, int] | None] = []
        self.fail_getmany: BaseException | None = None
        self.fail_commit: BaseException | None = None

    async def start(self) -> None:
        """Mark started."""
        self.started = True

    async def stop(self) -> None:
        """Mark stopped."""
        self.stopped = True

    async def getmany(
        self,
        *partitions: TopicPartition,
        timeout_ms: int = 0,
        max_records: int | None = None,
    ) -> dict[TopicPartition, list[Any]]:
        """Return scripted records, honoring the global bound."""
        del partitions, timeout_ms
        if self.fail_getmany is not None:
            raise self.fail_getmany
        result: dict[TopicPartition, list[Any]] = {}
        count = 0
        for partition in sorted(self.fetched):
            take = len(self.fetched[partition])
            if max_records is not None:
                take = min(take, max_records - count)
            if take > 0:
                result[TopicPartition(TOPIC, partition)] = self.fetched[partition][
                    :take
                ]
                count += take
            if max_records is not None and count >= max_records:
                break
        return result

    async def commit(self, offsets: dict[TopicPartition, int] | None = None) -> None:
        """Record the commit or raise the injected fault."""
        if self.fail_commit is not None:
            raise self.fail_commit
        self.commits.append(None if offsets is None else dict(offsets))


async def _publisher(
    fake: FakeProducer,
) -> KafkaEvidencePublisher:
    """Build and start a publisher over the fake producer."""
    publisher = KafkaEvidencePublisher(topic=TOPIC, producer_factory=lambda: fake)
    await publisher.start()
    return publisher


async def _consumer(fake: FakeConsumer) -> KafkaEvidenceConsumer:
    """Build and start a consumer over the fake consumer."""
    consumer = KafkaEvidenceConsumer(
        topic=TOPIC,
        consumer_id=_CONSUMER_ID,
        poll_timeout_ms=1000,
        consumer_factory=lambda: fake,
    )
    await consumer.start()
    return consumer


def _recorded(reader: object) -> dict[str, Any]:
    """Return recorded metrics by name."""
    return metrics_by_name(reader)  # type: ignore[arg-type]


class TestPublisherTelemetry:
    """Publish counts messages only after broker acknowledgement (K-P1..P8)."""

    @pytest.mark.asyncio
    async def test_one_successful_message(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """One acknowledged message increments published by one (K-P1)."""
        publisher = await _publisher(FakeProducer())
        await publisher.publish([_message("m1")])
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert counter_value(recorded[Metrics.KAFKA_MESSAGES_PUBLISHED]) == 1
        assert Metrics.KAFKA_PUBLISH_FAILURES not in recorded
        assert DurationMetrics.KAFKA_PUBLISH in recorded

    @pytest.mark.asyncio
    async def test_n_successful_messages(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """N acknowledged messages increment published by N (K-P2)."""
        publisher = await _publisher(FakeProducer())
        result = await publisher.publish(
            [_message("m1"), _message("m2"), _message("m3")]
        )
        assert len(result.records) == 3
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert counter_value(recorded[Metrics.KAFKA_MESSAGES_PUBLISHED]) == 3

    @pytest.mark.asyncio
    async def test_empty_publish_counts_nothing(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """An empty publish performs no broker op and emits no telemetry (K-P3)."""
        publisher = await _publisher(FakeProducer())
        result = await publisher.publish([])
        assert result.records == ()
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert recorded == {}

    @pytest.mark.asyncio
    async def test_failure_before_any_ack(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """A failure before any acknowledgement counts failure only (K-P4)."""
        fake = FakeProducer()
        fake.results = [RuntimeError("broker down")]
        publisher = await _publisher(fake)
        with pytest.raises(Exception, match="broker"):
            await publisher.publish([_message("m1")])
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert Metrics.KAFKA_MESSAGES_PUBLISHED not in recorded
        assert counter_value(recorded[Metrics.KAFKA_PUBLISH_FAILURES]) == 1

    @pytest.mark.asyncio
    async def test_failure_after_n_acks(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """A failure after N acknowledgements counts N published (K-P5)."""
        fake = FakeProducer()
        fake.results = [_metadata(0, 0), RuntimeError("broker down")]
        publisher = await _publisher(fake)
        with pytest.raises(Exception, match="broker"):
            await publisher.publish([_message("m1"), _message("m2")])
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert counter_value(recorded[Metrics.KAFKA_MESSAGES_PUBLISHED]) == 1
        assert counter_value(recorded[Metrics.KAFKA_PUBLISH_FAILURES]) == 1

    @pytest.mark.asyncio
    async def test_cancellation_propagates_unchanged(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """Cancellation propagates and records no publish result (K-P6)."""
        fake = FakeProducer()
        fake.results = [asyncio.CancelledError()]
        publisher = await _publisher(fake)
        with pytest.raises(asyncio.CancelledError):
            await publisher.publish([_message("m1")])
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert Metrics.KAFKA_PUBLISH_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_publish_duration_seconds(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """Publish latency is recorded in seconds (K-P8)."""
        publisher = await _publisher(FakeProducer())
        await publisher.publish([_message("m1")])
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        metric = recorded[DurationMetrics.KAFKA_PUBLISH]
        assert metric.unit == "s"
        assert histogram_count(metric) == 1
        attrs = data_point_attributes(metric)
        assert attrs["ati.kafka.topic"] == TOPIC
        assert attrs["ati.outcome"] == "success"

    @pytest.mark.asyncio
    async def test_no_evidence_content_or_ids_on_labels(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """Sensitive Evidence content never enters publish telemetry (K-P7)."""
        publisher = await _publisher(FakeProducer())
        await publisher.publish([_message("secret-record")])
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        rendered = str(recorded)
        assert "malicious-domain" not in rendered
        assert "secret-record" not in rendered
        metric_attrs = data_point_attributes(recorded[Metrics.KAFKA_MESSAGES_PUBLISHED])
        assert set(metric_attrs) == {"ati.kafka.topic"}


class TestConsumerPollTelemetry:
    """Poll counts only decoded/admitted messages (K-C1..C4, C9)."""

    @pytest.mark.asyncio
    async def test_poll_n_valid_records(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """N decoded records increment received by N (K-C1)."""
        fake = FakeConsumer()
        messages = [_message("m1"), _message("m2")]
        fake.fetched = {0: [_record(messages[0], 0, 0), _record(messages[1], 0, 1)]}
        consumer = await _consumer(fake)
        batch = await consumer.poll(10)
        assert len(batch.records) == 2
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert counter_value(recorded[Metrics.KAFKA_MESSAGES_RECEIVED]) == 2
        batch_metric = recorded[DurationMetrics.KAFKA_POLL_BATCH_SIZE]
        assert histogram_count(batch_metric) == 1

    @pytest.mark.asyncio
    async def test_empty_poll_counts_nothing(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """An empty poll is not a received message and not a failure (K-C2)."""
        consumer = await _consumer(FakeConsumer())
        batch = await consumer.poll(10)
        assert batch.records == ()
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert Metrics.KAFKA_MESSAGES_RECEIVED not in recorded
        assert Metrics.KAFKA_POLL_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_decode_failure_counts_no_received(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """An undecodable record is not a received message (K-C3)."""
        from aiokafka.structs import ConsumerRecord

        bad = ConsumerRecord(
            topic=TOPIC,
            partition=0,
            offset=0,
            timestamp=0,
            timestamp_type=0,
            key=evidence_id_key(_message("bad").evidence_id),
            value=b"\x00\x01not-canonical",
            checksum=None,
            serialized_key_size=1,
            serialized_value_size=1,
            headers=[],
        )
        fake = FakeConsumer()
        fake.fetched = {0: [bad]}
        consumer = await _consumer(fake)
        with pytest.raises(EvidencePollError):
            await consumer.poll(10)
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert Metrics.KAFKA_MESSAGES_RECEIVED not in recorded
        assert counter_value(recorded[Metrics.KAFKA_POLL_FAILURES]) == 1

    @pytest.mark.asyncio
    async def test_poll_failure_counts(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """A broker poll failure counts a poll failure (K-C4)."""
        fake = FakeConsumer()
        fake.fail_getmany = RuntimeError("broker unreachable")
        consumer = await _consumer(fake)
        with pytest.raises(EvidencePollError):
            await consumer.poll(10)
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert counter_value(recorded[Metrics.KAFKA_POLL_FAILURES]) == 1
        assert Metrics.KAFKA_MESSAGES_RECEIVED not in recorded

    @pytest.mark.asyncio
    async def test_no_offset_ids_on_labels(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """Offsets and evidence IDs never appear on metric labels (K-C9)."""
        fake = FakeConsumer()
        messages = [_message("m1")]
        fake.fetched = {3: [_record(messages[0], 3, 42)]}
        consumer = await _consumer(fake)
        await consumer.poll(10)
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        attrs = data_point_attributes(recorded[Metrics.KAFKA_MESSAGES_RECEIVED])
        assert set(attrs) == {"ati.kafka.topic", "ati.kafka.consumer_group"}
        assert "partition" not in str(attrs)


class TestConsumerCommitTelemetry:
    """Commit counts only after broker acknowledgement (K-C5..C6)."""

    def _batch(self, count: int) -> EvidenceBatch:
        """Build a committed-format evidence batch with ``count`` records."""
        records = []
        for index in range(count):
            message = _message(f"c{index}")
            records.append(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=index),
                    message=message,
                )
            )
        return EvidenceBatch(consumer_id=_CONSUMER_ID, records=tuple(records))

    @pytest.mark.asyncio
    async def test_commit_n_records(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """A successful commit counts committed messages (K-C5)."""
        fake = FakeConsumer()
        consumer = await _consumer(fake)
        await consumer.commit(self._batch(4))
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert counter_value(recorded[Metrics.KAFKA_COMMITS]) == 1
        assert counter_value(recorded[Metrics.KAFKA_MESSAGES_COMMITTED]) == 4
        assert Metrics.KAFKA_COMMIT_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_commit_failure_counts_zero_committed(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """A failed commit counts committed+0 and a commit failure (K-C6)."""
        fake = FakeConsumer()
        fake.fail_commit = RuntimeError("rebalance")
        consumer = await _consumer(fake)
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(self._batch(3))
        recorded = _recorded(in_memory_persistence_telemetry.reader)  # type: ignore[attr-defined]
        assert Metrics.KAFKA_MESSAGES_COMMITTED not in recorded
        assert counter_value(recorded[Metrics.KAFKA_COMMIT_FAILURES]) == 1
        assert Metrics.KAFKA_COMMITS not in recorded
