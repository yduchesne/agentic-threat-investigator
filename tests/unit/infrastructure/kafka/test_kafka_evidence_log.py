# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Kafka-compatible Evidence publisher/consumer adapter unit tests (PR 28G).

Covers the E28G-P (publisher), E28G-R (consumer poll), and E28G-K (consumer
commit) matrices against narrow ``aiokafka`` boundary doubles — never a fake
ATI publisher. Real PR 28C ``EvidenceMessage`` values are built through the
public builder; broker objects are constructed with real ``aiokafka`` value
types so the adapters exercise their real Protocol boundaries.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from aiokafka.structs import ConsumerRecord, RecordMetadata, TopicPartition

from agentic_threat_investigator.app.evidence_log import (
    EvidenceBatch,
    EvidenceCommitError,
    EvidenceConsumerId,
    EvidenceLogPosition,
    EvidenceLogRecord,
    EvidencePollError,
    EvidencePublishError,
    EvidencePublishResult,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    encode_evidence_message,
)
from agentic_threat_investigator.app.secrets import EnvVarSecretsResolver
from agentic_threat_investigator.config.settings import (
    EvidenceLogKafkaSettings,
    KafkaSecurityProtocol,
)
from agentic_threat_investigator.infrastructure.kafka.composition import (
    compose_kafka_publisher,
)
from agentic_threat_investigator.infrastructure.kafka.evidence_log import (
    AsyncKafkaConsumer,
    AsyncKafkaProducer,
    KafkaEvidenceConsumer,
    KafkaEvidencePublisher,
    _consumer_kwargs,
    _producer_kwargs,
    evidence_id_key,
)
from tests.support.evidence_batch_fixtures import threatfox_message

pytestmark = pytest.mark.unit

TOPIC = "ati.evidence"
GROUP = "evidence-persistence"
_ID = EvidenceConsumerId(GROUP)
_ID_FOREIGN = EvidenceConsumerId("other-group")
_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def _message(record: str = "rec-1") -> EvidenceMessage:
    """Build one deterministic ThreatFox message."""
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id=record,
        sequence=0,
        observed_at=_FIXED_TS,
    )
    return message


def _metadata(partition: int, offset: int) -> RecordMetadata:
    """Build one real broker delivery metadata value."""
    return RecordMetadata(
        topic=TOPIC,
        partition=partition,
        topic_partition=TopicPartition(TOPIC, partition),
        offset=offset,
        timestamp=0,
        timestamp_type=0,
        log_start_offset=0,
    )


def _record(message: EvidenceMessage, partition: int, offset: int) -> ConsumerRecord:
    """Build one real encoded broker record with the canonical key."""
    return ConsumerRecord(
        topic=TOPIC,
        partition=partition,
        offset=offset,
        timestamp=0,
        timestamp_type=0,
        key=evidence_id_key(message.evidence_id),
        value=encode_evidence_message(message),
        checksum=None,
        serialized_key_size=1,
        serialized_value_size=1,
        headers=[],
    )


class FakeProducer(AsyncKafkaProducer):
    """Deterministic aiokafka producer boundary double.

    Faithfully models aiokafka 0.14.x's two-stage ``send`` contract:
    awaiting ``send()`` yields an ``asyncio.Future``, and awaiting that
    future yields the ``RecordMetadata`` (or raises the delivery failure).
    The fake never lets the adapter treat the first-await result as
    metadata.
    """

    def __init__(self) -> None:
        """Initialize an unstarted double with empty delivery records."""
        self.started = False
        self.stopped = False
        self.sends: list[dict[str, Any]] = []
        self.deliveries: list[asyncio.Future[RecordMetadata]] = []
        self.results: list[RecordMetadata | BaseException] = []
        self.fail_send: BaseException | None = None

    async def start(self) -> None:
        """Mark the double started."""
        self.started = True

    async def stop(self) -> None:
        """Mark the double stopped."""
        self.stopped = True

    async def send(
        self,
        topic: str,
        value: bytes | None = None,
        key: bytes | None = None,
        partition: int | None = None,
    ) -> asyncio.Future[RecordMetadata]:
        """Record the send and return the delivery future of the outcome."""
        self.sends.append(
            {"topic": topic, "value": value, "key": key, "partition": partition}
        )
        if self.fail_send is not None:
            raise self.fail_send
        index = len(self.sends) - 1
        if index < len(self.results):
            outcome = self.results[index]
        else:
            outcome = _metadata(partition=0, offset=len(self.sends) - 1)
        delivery: asyncio.Future[RecordMetadata] = (
            asyncio.get_running_loop().create_future()
        )
        self.deliveries.append(delivery)
        if isinstance(outcome, BaseException):
            delivery.set_exception(outcome)
        else:
            delivery.set_result(cast(RecordMetadata, outcome))
        return delivery


class FakeConsumer(AsyncKafkaConsumer):
    """Deterministic aiokafka consumer boundary double."""

    def __init__(self) -> None:
        """Initialize an unstarted double with no fetched records."""
        self.started = False
        self.stopped = False
        self.fetched: dict[int, list[ConsumerRecord]] = {}
        self.commits: list[dict[TopicPartition, int] | None] = []
        self.fail_getmany: BaseException | None = None
        self.fail_commit: BaseException | None = None

    async def start(self) -> None:
        """Mark the double started."""
        self.started = True

    async def stop(self) -> None:
        """Mark the double stopped."""
        self.stopped = True

    async def getmany(
        self,
        *partitions: TopicPartition,
        timeout_ms: int = 0,
        max_records: int | None = None,
    ) -> dict[TopicPartition, list[ConsumerRecord]]:
        """Return fetched records, honoring the global bound and timeout."""
        if self.fail_getmany is not None:
            raise self.fail_getmany
        result: dict[TopicPartition, list[ConsumerRecord]] = {}
        count = 0
        for partition in sorted(self.fetched):
            records = self.fetched[partition]
            take = record_count = len(records)
            if max_records is not None:
                take = min(record_count, max_records - count)
            if take > 0:
                result[TopicPartition(TOPIC, partition)] = records[:take]
                count += take
            if max_records is not None and count >= max_records:
                break
        return result

    async def commit(self, offsets: dict[TopicPartition, int] | None = None) -> None:
        """Record the commit or raise the injected failure."""
        if self.fail_commit is not None:
            raise self.fail_commit
        self.commits.append(None if offsets is None else dict(offsets))


async def _started_publisher(
    fake: FakeProducer | None = None,
) -> tuple[KafkaEvidencePublisher, FakeProducer]:
    """Build and start a publisher over a fake producer."""
    producer = fake or FakeProducer()
    publisher = KafkaEvidencePublisher(topic=TOPIC, producer_factory=lambda: producer)
    await publisher.start()
    return publisher, producer


async def _started_consumer(
    fake: FakeConsumer | None = None,
    consumer_id: EvidenceConsumerId = _ID,
) -> tuple[KafkaEvidenceConsumer, FakeConsumer]:
    """Build and start a consumer over a fake consumer."""
    consumer = fake or FakeConsumer()
    adapter = KafkaEvidenceConsumer(
        topic=TOPIC,
        consumer_id=consumer_id,
        poll_timeout_ms=100,
        consumer_factory=lambda: consumer,
    )
    await adapter.start()
    return adapter, consumer


# ---------------------------------------------------------------------------
# E28G-P publisher matrix
# ---------------------------------------------------------------------------


class TestPublisher:
    """E28G-P01..P13: publisher send, keying, mapping, and failure semantics."""

    @pytest.mark.asyncio
    async def test_p01_empty_input_no_send_empty_result(self) -> None:
        """E28G-P01: empty publication performs no broker send."""
        publisher, producer = await _started_publisher()
        result = await publisher.publish(())
        assert result == EvidencePublishResult(records=())
        assert producer.sends == []

    @pytest.mark.asyncio
    async def test_p02_one_message_canonical_codec_bytes(self) -> None:
        """E28G-P02: exactly the canonical PR 28C bytes are sent."""
        publisher, producer = await _started_publisher()
        message = _message()
        result = await publisher.publish([message])
        assert len(producer.sends) == 1
        assert producer.sends[0]["value"] == encode_evidence_message(message)
        assert result.records[0].message == message

    @pytest.mark.asyncio
    async def test_p03_key_is_canonical_evidence_id_bytes(self) -> None:
        """E28G-P03: the broker key is the canonical evidence_id bytes."""
        publisher, producer = await _started_publisher()
        message = _message()
        await publisher.publish([message])
        assert producer.sends[0]["key"] == evidence_id_key(message.evidence_id)
        assert producer.sends[0]["key"] == str(message.evidence_id).encode("utf-8")

    @pytest.mark.asyncio
    async def test_p04_two_messages_same_evidence_same_key(self) -> None:
        """E28G-P04: two messages sharing Evidence produce the same key."""
        publisher, producer = await _started_publisher()
        a1 = _message("same")
        a2 = _message("same")
        await publisher.publish([a1, a2])
        assert producer.sends[0]["key"] == producer.sends[1]["key"]

    @pytest.mark.asyncio
    async def test_p05_different_evidence_keys_differ(self) -> None:
        """E28G-P05: messages for different Evidence produce different keys."""
        publisher, producer = await _started_publisher()
        await publisher.publish([_message("one"), _message("two")])
        assert producer.sends[0]["key"] != producer.sends[1]["key"]

    @pytest.mark.asyncio
    async def test_p06_successful_metadata_maps_stream_offset(self) -> None:
        """E28G-P06: broker partition/offset map to stream/offset."""
        publisher, producer = await _started_publisher()
        producer.results = [_metadata(2, 9), _metadata(3, 4)]
        messages = [_message("a"), _message("b")]
        result = await publisher.publish(messages)
        assert result.records[0].position == EvidenceLogPosition(stream=2, offset=9)
        assert result.records[1].position == EvidenceLogPosition(stream=3, offset=4)

    @pytest.mark.asyncio
    async def test_p07_result_ordering_follows_input(self) -> None:
        """E28G-P07: the result tuple preserves input message order."""
        publisher, producer = await _started_publisher()
        # Broker acknowledgements complete in reverse partition order.
        producer.results = [_metadata(5, 0), _metadata(1, 0)]
        messages = [_message("a"), _message("b")]
        result = await publisher.publish(messages)
        assert [record.message for record in result.records] == messages
        assert result.records[0].position.stream == 5
        assert result.records[1].position.stream == 1

    @pytest.mark.asyncio
    async def test_p07b_send_first_await_is_delivery_future_regression(
        self,
    ) -> None:
        """E28G-P07b regression: publish awaits the delivery future for metadata.

        aiokafka 0.14.x ``send()`` yields an ``asyncio.Future`` on its first
        await; only a second await yields ``RecordMetadata``. If the adapter
        treated the first-await result as metadata, position construction
        would fail with an ``AttributeError``. The fake models the real
        two-stage contract, so this proves the adapter consumes both stages.
        """
        publisher, producer = await _started_publisher()
        producer.results = [_metadata(partition=2, offset=9)]
        result = await publisher.publish([_message()])
        # The first-await result is a Future, never already-made metadata.
        assert len(producer.deliveries) == 1
        assert isinstance(producer.deliveries[0], asyncio.Future)
        # The published position comes from the resolved RecordMetadata.
        assert result.records[0].position == EvidenceLogPosition(stream=2, offset=9)

    @pytest.mark.asyncio
    async def test_p08_operational_send_failure_typed_error(self) -> None:
        """E28G-P08: an operational send failure raises EvidencePublishError."""
        publisher, producer = await _started_publisher()
        producer.fail_send = RuntimeError("broker down")
        with pytest.raises(EvidencePublishError) as caught:
            await publisher.publish([_message()])
        assert "broker" in str(caught.value)

    @pytest.mark.asyncio
    async def test_p09_partial_ack_then_failure_no_extent_claim(self) -> None:
        """E28G-P09: a late failure after partial acks raises without extent claims.

        The error text never asserts that zero messages were published; ATI
        treats an ambiguous failure as unspecified publication extent.
        """
        publisher, producer = await _started_publisher()
        producer.results = [
            _metadata(0, 0),
            RuntimeError("late broker failure"),
        ]
        messages = [_message("a"), _message("b")]
        with pytest.raises(EvidencePublishError) as caught:
            await publisher.publish(messages)
        assert "zero" not in str(caught.value).lower()

    @pytest.mark.asyncio
    async def test_p10_cancellation_propagates(self) -> None:
        """E28G-P10: cancellation propagates instead of becoming a publish error."""

        class CancellingProducer(FakeProducer):
            """A producer whose first send raises CancelledError."""

            async def send(self, *args: Any, **kwargs: Any) -> RecordMetadata:
                """Simulate cancellation at the broker boundary."""
                raise asyncio.CancelledError

        publisher, _ = await _started_publisher(CancellingProducer())
        with pytest.raises(asyncio.CancelledError):
            await publisher.publish([_message()])

    @pytest.mark.asyncio
    async def test_p11_lifecycle_started_stopped_once(self) -> None:
        """E28G-P11: the producer client is started and stopped exactly once."""
        producer = FakeProducer()
        publisher = KafkaEvidencePublisher(
            topic=TOPIC, producer_factory=lambda: producer
        )
        assert not producer.started
        await publisher.start()
        assert producer.started
        await publisher.start()  # idempotent
        await publisher.publish([_message()])
        await publisher.stop()
        assert producer.stopped
        await publisher.stop()  # idempotent
        assert producer.sends and len(producer.sends) == 1

    @pytest.mark.asyncio
    async def test_p12_publish_requires_started(self) -> None:
        """E28G-P12 (lifecycle): publishing before start fails closed."""
        publisher = KafkaEvidencePublisher(topic=TOPIC, producer_factory=FakeProducer)
        with pytest.raises(EvidencePublishError):
            await publisher.publish([_message()])
        await publisher.start()
        await publisher.publish([_message()])
        await publisher.stop()

    def test_p13_producer_config_idempotent_no_transactional_id(self) -> None:
        """E28G-P13: producer config enables idempotence and never a tx ID."""
        kwargs = _producer_kwargs(
            bootstrap_servers=("h:1",),
            client_id="ati-evidence",
            security_protocol="PLAINTEXT",
            ssl_context=None,
            sasl_mechanism=None,
            sasl_plain_username=None,
            sasl_plain_password=None,
        )
        assert kwargs["enable_idempotence"] is True
        assert "transactional_id" not in kwargs

    @pytest.mark.asyncio
    async def test_p13b_publish_error_never_echoes_payload(self) -> None:
        """E28G-P13b: publish failure text never echoes payload bytes."""
        publisher, producer = await _started_publisher()
        producer.fail_send = RuntimeError("boom")
        message = _message()
        payload = encode_evidence_message(message)
        with pytest.raises(EvidencePublishError) as caught:
            await publisher.publish([message])
        assert payload not in str(caught.value).encode()
        assert str(message.source_record_id) not in str(caught.value)


# ---------------------------------------------------------------------------
# E28G-R consumer poll matrix
# ---------------------------------------------------------------------------


class TestConsumerPoll:
    """E28G-R01..R12: consumer poll decode, flatten, bound, and failure."""

    @pytest.mark.asyncio
    async def test_r01_empty_getmany_empty_batch(self) -> None:
        """E28G-R01: an empty broker result yields an empty batch."""
        adapter, _ = await _started_consumer()
        batch = await adapter.poll(5)
        assert batch.consumer_id == _ID
        assert batch.records == ()

    @pytest.mark.asyncio
    async def test_r02_one_record_decoded_with_position(self) -> None:
        """E28G-R02: one record decodes to the exact message and position."""
        adapter, consumer = await _started_consumer()
        message = _message()
        consumer.fetched = {2: [_record(message, 2, 9)]}
        batch = await adapter.poll(5)
        assert len(batch.records) == 1
        assert batch.records[0].message == message
        assert batch.records[0].position == EvidenceLogPosition(stream=2, offset=9)

    @pytest.mark.asyncio
    async def test_r03_multi_partition_one_batch(self) -> None:
        """E28G-R03: a multi-partition poll yields one batch spanning streams."""
        adapter, consumer = await _started_consumer()
        a = _message("a")
        b = _message("b")
        consumer.fetched = {
            0: [_record(a, 0, 0)],
            2: [_record(b, 2, 3)],
        }
        batch = await adapter.poll(10)
        streams = {record.position.stream for record in batch.records}
        assert streams == {0, 2}

    @pytest.mark.asyncio
    async def test_r04_global_max_bound_never_exceeded(self) -> None:
        """E28G-R04: a poll never returns more than the global bound."""
        adapter, consumer = await _started_consumer()
        consumer.fetched = {
            0: [_record(_message("a0"), 0, 0), _record(_message("a1"), 0, 1)],
            1: [_record(_message("b"), 1, 0)],
            2: [_record(_message("c"), 2, 0)],
        }
        batch = await adapter.poll(3)
        assert len(batch.records) == 3

    @pytest.mark.asyncio
    async def test_r05_per_stream_offsets_retain_order(self) -> None:
        """E28G-R05: each stream retains increasing broker offset order."""
        adapter, consumer = await _started_consumer()
        consumer.fetched = {
            1: [
                _record(_message("a0"), 1, 5),
                _record(_message("a1"), 1, 6),
                _record(_message("a2"), 1, 7),
            ]
        }
        batch = await adapter.poll(10)
        assert [record.position.offset for record in batch.records] == [5, 6, 7]

    @pytest.mark.asyncio
    async def test_r06_deterministic_flattening(self) -> None:
        """E28G-R06: streams are sorted ascending for deterministic output."""
        adapter, consumer = await _started_consumer()
        consumer.fetched = {
            # Inserted out of order deliberately.
            2: [_record(_message("c"), 2, 0)],
            0: [_record(_message("a"), 0, 0)],
            1: [_record(_message("b"), 1, 0)],
        }
        batch = await adapter.poll(10)
        assert [record.position.stream for record in batch.records] == [0, 1, 2]

    @pytest.mark.asyncio
    async def test_r07_malformed_payload_fails_closed(self) -> None:
        """E28G-R07: malformed PR 28C bytes fail closed without decoding."""
        adapter, consumer = await _started_consumer()
        bad = _record(_message(), 0, 0)
        consumer.fetched = {0: [_corrupt(bad)]}
        with pytest.raises(EvidencePollError):
            await adapter.poll(10)

    @pytest.mark.asyncio
    async def test_r08_key_message_mismatch_fails_closed(self) -> None:
        """E28G-R08: a key/evidence mismatch fails closed."""
        adapter, consumer = await _started_consumer()
        message = _message()
        record = _record(message, 0, 0)
        # Corrupt the key so it no longer matches the decoded Evidence.
        record = ConsumerRecord(
            topic=record.topic,
            partition=record.partition,
            offset=record.offset,
            timestamp=record.timestamp,
            timestamp_type=record.timestamp_type,
            key=b"definitely-not-the-canonical-key",
            value=record.value,
            checksum=None,
            serialized_key_size=len(record.key),
            serialized_value_size=len(record.value),
            headers=[],
        )
        consumer.fetched = {0: [record]}
        with pytest.raises(EvidencePollError):
            await adapter.poll(10)

    @pytest.mark.asyncio
    async def test_r09_poll_operational_failure_typed(self) -> None:
        """E28G-R09: an operational poll failure raises EvidencePollError."""
        adapter, consumer = await _started_consumer()
        consumer.fail_getmany = RuntimeError("broker down")
        with pytest.raises(EvidencePollError):
            await adapter.poll(10)

    @pytest.mark.asyncio
    async def test_r10_poll_cancellation_propagates(self) -> None:
        """E28G-R10: poll cancellation propagates as CancelledError."""

        class CancellingConsumer(FakeConsumer):
            """A consumer getmany that raises CancelledError."""

            async def getmany(
                self, *args: Any, **kwargs: Any
            ) -> dict[TopicPartition, list[ConsumerRecord]]:
                """Simulate cancellation at the broker boundary."""
                raise asyncio.CancelledError

        adapter, _ = await _started_consumer(CancellingConsumer())
        with pytest.raises(asyncio.CancelledError):
            await adapter.poll(10)

    def test_r11_consumer_config_auto_commit_disabled(self) -> None:
        """E28G-R11: consumer auto-commit is always disabled."""
        kwargs = _consumer_kwargs(
            group_id=GROUP,
            client_id="ati-evidence",
            bootstrap_servers=("h:1",),
            security_protocol="PLAINTEXT",
            auto_offset_reset="earliest",
            ssl_context=None,
            sasl_mechanism=None,
            sasl_plain_username=None,
            sasl_plain_password=None,
        )
        assert kwargs["enable_auto_commit"] is False
        assert kwargs["enable_auto_commit"] is not True

    def test_r12_consumer_group_from_consumer_id(self) -> None:
        """E28G-R12: the logical consumer identity selects the group."""
        kwargs = _consumer_kwargs(
            group_id=_ID.value,
            client_id="ati-evidence",
            bootstrap_servers=("h:1",),
            security_protocol="PLAINTEXT",
            auto_offset_reset="earliest",
            ssl_context=None,
            sasl_mechanism=None,
            sasl_plain_username=None,
            sasl_plain_password=None,
        )
        assert kwargs["group_id"] == "evidence-persistence"


# ---------------------------------------------------------------------------
# E28G-K consumer commit matrix
# ---------------------------------------------------------------------------


class TestConsumerCommit:
    """E28G-K01..K12: explicit per-stream commit semantics."""

    @pytest.mark.asyncio
    async def test_k01_empty_batch_no_commit(self) -> None:
        """E28G-K01: committing an empty batch performs no broker commit."""
        adapter, consumer = await _started_consumer()
        await adapter.commit(EvidenceBatch(consumer_id=_ID, records=()))
        assert consumer.commits == []

    @pytest.mark.asyncio
    async def test_k02_one_stream_commits_next_offset(self) -> None:
        """E28G-K02: one stream at offsets 5,6 commits next offset 7."""
        adapter, consumer = await _started_consumer()
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=5), message=_message()
                ),
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=6), message=_message()
                ),
            ),
        )
        await adapter.commit(batch)
        assert consumer.commits == [{TopicPartition(TOPIC, 0): 7}]

    @pytest.mark.asyncio
    async def test_k03_multi_stream_explicit_map(self) -> None:
        """E28G-K03: streams 0:5,6 and 2:9 commit {0:7, 2:10}."""
        adapter, consumer = await _started_consumer()
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=5), message=_message()
                ),
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=6), message=_message()
                ),
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=2, offset=9), message=_message()
                ),
            ),
        )
        await adapter.commit(batch)
        assert consumer.commits == [
            {TopicPartition(TOPIC, 0): 7, TopicPartition(TOPIC, 2): 10}
        ]

    @pytest.mark.asyncio
    async def test_k04_absent_partition_not_advanced(self) -> None:
        """E28G-K04: a partition absent from the batch is never committed."""
        adapter, consumer = await _started_consumer()
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=2, offset=9), message=_message()
                ),
            ),
        )
        await adapter.commit(batch)
        assert consumer.commits == [{TopicPartition(TOPIC, 2): 10}]
        committed = consumer.commits[0]
        assert committed is not None
        assert TopicPartition(TOPIC, 0) not in committed

    @pytest.mark.asyncio
    async def test_k05_foreign_consumer_rejected(self) -> None:
        """E28G-K05: a foreign consumer identity rejects the commit."""
        adapter, consumer = await _started_consumer()
        batch = EvidenceBatch(
            consumer_id=_ID_FOREIGN,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=0), message=_message()
                ),
            ),
        )
        with pytest.raises(EvidenceCommitError):
            await adapter.commit(batch)
        assert consumer.commits == []

    @pytest.mark.asyncio
    async def test_k06_duplicate_position_rejected(self) -> None:
        """E28G-K06: a duplicate (stream, offset) position is rejected."""
        adapter, consumer = await _started_consumer()
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=5), message=_message()
                ),
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=5), message=_message()
                ),
            ),
        )
        with pytest.raises(EvidenceCommitError):
            await adapter.commit(batch)
        assert consumer.commits == []

    @pytest.mark.asyncio
    async def test_k07_reversed_offsets_rejected(self) -> None:
        """E28G-K07: reversed offsets within a stream are rejected."""
        adapter, consumer = await _started_consumer()
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=7), message=_message()
                ),
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=6), message=_message()
                ),
            ),
        )
        with pytest.raises(EvidenceCommitError):
            await adapter.commit(batch)
        assert consumer.commits == []

    @pytest.mark.asyncio
    async def test_k08_gap_rejected(self) -> None:
        """E28G-K08: an offset gap violating the batch contract is rejected."""
        adapter, consumer = await _started_consumer()
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=5), message=_message()
                ),
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=9), message=_message()
                ),
            ),
        )
        with pytest.raises(EvidenceCommitError):
            await adapter.commit(batch)
        assert consumer.commits == []

    @pytest.mark.asyncio
    async def test_k09_commit_failure_typed(self) -> None:
        """E28G-K09: a broker commit failure raises EvidenceCommitError."""
        adapter, consumer = await _started_consumer()
        consumer.fail_commit = RuntimeError("broker down")
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=5), message=_message()
                ),
            ),
        )
        with pytest.raises(EvidenceCommitError):
            await adapter.commit(batch)

    @pytest.mark.asyncio
    async def test_k10_rebalance_commit_failure_typed(self) -> None:
        """E28G-K10: an ownership-loss commit failure raises EvidenceCommitError."""
        adapter, consumer = await _started_consumer()
        consumer.fail_commit = RuntimeError("partition revoked during rebalance")
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=5), message=_message()
                ),
            ),
        )
        with pytest.raises(EvidenceCommitError):
            await adapter.commit(batch)

    @pytest.mark.asyncio
    async def test_k11_commit_cancellation_propagates(self) -> None:
        """E28G-K11: commit cancellation propagates as CancelledError."""

        class CancellingCommitConsumer(FakeConsumer):
            """A consumer commit that raises CancelledError."""

            async def commit(
                self, offsets: dict[TopicPartition, int] | None = None
            ) -> None:
                """Simulate cancellation at the broker boundary."""
                raise asyncio.CancelledError

        adapter, _ = await _started_consumer(CancellingCommitConsumer())
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=5), message=_message()
                ),
            ),
        )
        with pytest.raises(asyncio.CancelledError):
            await adapter.commit(batch)

    @pytest.mark.asyncio
    async def test_k12_explicit_offset_map_never_generic(self) -> None:
        """E28G-K12: commit uses an explicit map, never a commit-all-position call."""
        adapter, consumer = await _started_consumer()
        batch = EvidenceBatch(
            consumer_id=_ID,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=5), message=_message()
                ),
            ),
        )
        await adapter.commit(batch)
        # The double records ``None`` only when offsets is None (a generic
        # commit-current-position); the adapter must always pass a map.
        assert consumer.commits == [{TopicPartition(TOPIC, 0): 6}]


def _corrupt(record: ConsumerRecord) -> ConsumerRecord:
    """Return a copy of a record whose value bytes are malformed JSON."""
    return ConsumerRecord(
        topic=record.topic,
        partition=record.partition,
        offset=record.offset,
        timestamp=record.timestamp,
        timestamp_type=record.timestamp_type,
        key=record.key,
        value=b"this is not canonical json{{",
        checksum=None,
        serialized_key_size=len(record.key),
        serialized_value_size=len(record.value),
        headers=[],
    )


class TestComposition:
    """PR 28G composition helpers wire adapters from typed configuration."""

    def test_plaintext_publisher_from_settings(self) -> None:
        """Composing a PLAINTEXT publisher needs no secrets and uses PLAINTEXT."""
        settings = EvidenceLogKafkaSettings(
            bootstrap_servers=("127.0.0.1:9092",), topic="ati.evidence"
        )
        publisher = compose_kafka_publisher(settings)
        assert publisher.topic == "ati.evidence"
        assert publisher.is_started is False

    def test_sasl_requires_secrets_resolver(self) -> None:
        """A SASL protocol without a SecretsResolver fails closed at composition."""
        settings = EvidenceLogKafkaSettings(
            bootstrap_servers=("h:1",),
            topic="t",
            security_protocol=KafkaSecurityProtocol.SASL_PLAINTEXT,
            sasl_mechanism="PLAIN",
            sasl_username_secret="USER",
            sasl_password_secret="PASS",
        )
        with pytest.raises(ValueError):
            compose_kafka_publisher(settings)

    def test_sasl_resolves_secret_reference_values(self) -> None:
        """SASL credits resolve through the injected SecretsResolver by name."""
        settings = EvidenceLogKafkaSettings(
            bootstrap_servers=("h:1",),
            topic="t",
            security_protocol=KafkaSecurityProtocol.SASL_PLAINTEXT,
            sasl_mechanism="PLAIN",
            sasl_username_secret="ATI_KAFKA_USER",
            sasl_password_secret="ATI_KAFKA_PASS",
        )
        secrets = EnvVarSecretsResolver(
            {"ATI_KAFKA_USER": "u", "ATI_KAFKA_PASS": "secret-value"}
        )
        publisher = compose_kafka_publisher(settings, secrets=secrets)
        assert publisher.topic == "t"
        assert publisher.is_started is False
