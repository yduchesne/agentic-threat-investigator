# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Kafka-compatible Evidence publisher and consumer adapters (PR 28G).

These adapters implement the PR 28D broker-neutral
:class:`EvidencePublisher` / :class:`EvidenceConsumer` contracts against a
Kafka-compatible broker using ``aiokafka``.

Architectural rules enforced here:

- **Evidence is the durable wire contract.** Records carry the exact PR 28C
  canonical bytes from :func:`encode_evidence_message`; the adapter never
  invents a second wire model and never serializes internal Pydantic/domain
  models.
- **Topology is transport state.** Each record is keyed by the stable
  ``EvidenceMessage.evidence_id``. Kafka partition/offset map to the
  broker-neutral :class:`EvidenceLogPosition` ``(stream, offset)`` and never
  become Evidence identity or a PostgreSQL idempotency key.
- **Ordering is per stream only.** All messages for one ``evidence_id``
  route to the same partition (under a stable partition count), preserving
  broker ordering within that stream; no cross-stream ordering is claimed.
- **At-least-once with manual commit.** The consumer disables auto-commit
  and commits explicit per-stream offsets (``highest offset + 1``) only
  after the caller reports a batch successfully processed.
- **Success-atomic, not failure-atomic, publication.** A returned publish
  succeeded means every supplied message was broker-acknowledged; a raised
  failure leaves the publication extent unspecified (zero, some, or all
  messages may already be accepted). The producer enables idempotent
  production and never uses Kafka transactions.
- **Cancellation propagates.** ``asyncio.CancelledError`` is never
  converted into a typed evidence-log error.

The producer/consumer clients are injected through narrow factories so unit
tests can substitute deterministic boundary doubles; real integration tests
use real ``aiokafka`` clients against Redpanda.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from typing import Protocol, cast
from uuid import UUID

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.structs import ConsumerRecord, RecordMetadata, TopicPartition

from agentic_threat_investigator.app.evidence_log import (
    EvidenceBatch,
    EvidenceCommitError,
    EvidenceConsumer,
    EvidenceConsumerId,
    EvidenceLogPosition,
    EvidenceLogRecord,
    EvidencePollError,
    EvidencePublisher,
    EvidencePublishError,
    EvidencePublishResult,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    decode_evidence_message,
    encode_evidence_message,
)


class AsyncKafkaProducer(Protocol):
    """Narrow aiokafka producer boundary used by the publisher adapter.

    Only the public operations the adapter relies on are declared, so unit
    tests can substitute a deterministic fake without constructing a real
    broker connection.

    ``send`` models aiokafka 0.14.x's two-stage contract exactly: awaiting
    ``send()`` yields a delivery ``asyncio.Future``, and awaiting that
    future yields the ``RecordMetadata`` once the broker acknowledges the
    record. The adapter therefore awaits both stages before constructing a
    transport position.
    """

    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def send(
        self,
        topic: str,
        value: bytes | None = None,
        key: bytes | None = None,
        partition: int | None = None,
    ) -> asyncio.Future[RecordMetadata]: ...


class AsyncKafkaConsumer(Protocol):
    """Narrow aiokafka consumer boundary used by the consumer adapter.

    Only the public operations the adapter relies on are declared, so unit
    tests can substitute a deterministic fake. ``getmany`` never commits;
    ``commit`` applies the caller-supplied explicit offset map.
    """

    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def getmany(
        self,
        *partitions: TopicPartition,
        timeout_ms: int = 0,
        max_records: int | None = None,
    ) -> dict[TopicPartition, list[ConsumerRecord]]: ...
    async def commit(
        self, offsets: dict[TopicPartition, int] | None = None
    ) -> None: ...


def evidence_id_key(evidence_id: UUID) -> bytes:
    """Return the deterministic Kafka record key of one Evidence identity.

    The canonical lowercase UUID string encoded as UTF-8. The exact byte
    representation is frozen by tests; it never depends on Python's
    randomized ``hash()`` and never uses ``message_id`` as the key.
    """
    return str(evidence_id).encode("utf-8")


def _canonical_key(message: EvidenceMessage) -> bytes:
    """Return the canonical routing key of one message's Evidence identity."""
    return evidence_id_key(message.evidence_id)


def _producer_kwargs(
    *,
    bootstrap_servers: tuple[str, ...],
    client_id: str,
    security_protocol: str,
    ssl_context: object | None,
    sasl_mechanism: str | None,
    sasl_plain_username: str | None,
    sasl_plain_password: str | None,
) -> dict[str, object]:
    """Build the bounded ``AIOKafkaProducer`` constructor arguments (PR 28G).

    Idempotent production is always enabled (implying ``acks=all``); no
    transactional ID and no Kafka-transaction APIs are ever configured.
    SASL credentials are injected values resolved outside configuration and
    are never logged or embedded in URLs.
    """
    kwargs: dict[str, object] = {
        "bootstrap_servers": list(bootstrap_servers),
        "client_id": client_id,
        "enable_idempotence": True,
        "security_protocol": security_protocol,
    }
    if ssl_context is not None:
        kwargs["ssl_context"] = ssl_context
    if sasl_mechanism is not None:
        kwargs["sasl_mechanism"] = sasl_mechanism
        if sasl_plain_username is not None:
            kwargs["sasl_plain_username"] = sasl_plain_username
        if sasl_plain_password is not None:
            kwargs["sasl_plain_password"] = sasl_plain_password
    return kwargs


def _consumer_kwargs(
    *,
    group_id: str,
    client_id: str,
    bootstrap_servers: tuple[str, ...],
    security_protocol: str,
    auto_offset_reset: str,
    ssl_context: object | None,
    sasl_mechanism: str | None,
    sasl_plain_username: str | None,
    sasl_plain_password: str | None,
) -> dict[str, object]:
    """Build the bounded ``AIOKafkaConsumer`` constructor arguments (PR 28G).

    Auto-commit is always disabled: no background acknowledgement may
    precede PR 28E PostgreSQL persistence. ``group_id`` carries the
    application's logical consumer identity; auto-offset-reset is the
    explicitly configured/documented policy (``earliest`` for ATI's fresh
    isolated groups). Kafka producer transactions are never used, so the
    default isolation level (``read_uncommitted``) is retained.
    """
    kwargs: dict[str, object] = {
        "bootstrap_servers": list(bootstrap_servers),
        "client_id": client_id,
        "group_id": group_id,
        "enable_auto_commit": False,
        "auto_offset_reset": auto_offset_reset,
        "security_protocol": security_protocol,
    }
    if ssl_context is not None:
        kwargs["ssl_context"] = ssl_context
    if sasl_mechanism is not None:
        kwargs["sasl_mechanism"] = sasl_mechanism
        if sasl_plain_username is not None:
            kwargs["sasl_plain_username"] = sasl_plain_username
        if sasl_plain_password is not None:
            kwargs["sasl_plain_password"] = sasl_plain_password
    return kwargs


class KafkaEvidencePublisher(EvidencePublisher):
    """Kafka-compatible producer adapter of the Evidence log (PR 28G).

    Holds one long-lived producer client across ``publish`` calls: explicit
    lifecycle (``start``/``stop``), idempotent production, PR 28C canonical
    value bytes, ``evidence_id`` routing key, delivery acknowledgement of
    every message before a successful return, and broker partition/offset
    mapped to broker-neutral stream/offset in input order.
    """

    def __init__(
        self,
        *,
        topic: str,
        producer_factory: Callable[[], AsyncKafkaProducer],
    ) -> None:
        """Bind the publisher to its configured topic and client factory.

        ``producer_factory`` creates the long-lived ``aiokafka`` (or test
        double) producer; it is invoked once by :meth:`start`.
        """
        self._topic = topic
        self._producer_factory = producer_factory
        self._producer: AsyncKafkaProducer | None = None

    @property
    def topic(self) -> str:
        """Return the configured Evidence topic name."""
        return self._topic

    @property
    def is_started(self) -> bool:
        """Return whether the underlying producer client is started."""
        return self._producer is not None

    async def start(self) -> None:
        """Create and start the underlying producer client (idempotent)."""
        if self._producer is not None:
            return
        producer = self._producer_factory()
        await producer.start()
        self._producer = producer

    async def stop(self) -> None:
        """Stop and drop the underlying producer client (idempotent)."""
        producer = self._producer
        self._producer = None
        if producer is not None:
            await producer.stop()

    def _require_started(self) -> AsyncKafkaProducer:
        """Return the started producer or fail closed with a bounded error."""
        if self._producer is None:
            raise EvidencePublishError("evidence publisher is not started")
        return self._producer

    def __aenter__(self) -> "KafkaEvidencePublisher":
        """Return ``self`` for async-context-manager composition."""
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Stop the producer when the async context exits."""
        await self.stop()

    async def publish(
        self, messages: Sequence[EvidenceMessage]
    ) -> EvidencePublishResult:
        """Publish one ordered run of messages and return their positions.

        For every message the adapter sends the PR 28C canonical bytes keyed
        by the stable ``evidence_id`` and awaits delivery acknowledgement
        before returning success. The returned record tuple corresponds to
        input message order even though broker acknowledgements may complete
        in a different order. An empty run is a no-op that performs no
        broker send and returns zero records.
        """
        for message in messages:
            if not isinstance(message, EvidenceMessage):
                raise EvidencePublishError(
                    "publish accepts only EvidenceMessage values"
                )
        producer = self._require_started()
        if not messages:
            return EvidencePublishResult(records=())
        records: list[EvidenceLogRecord] = []
        for message in messages:
            try:
                # aiokafka 0.14.x: awaiting send() yields the delivery future;
                # only awaiting that future yields the broker RecordMetadata.
                delivery: asyncio.Future[RecordMetadata] = await producer.send(
                    self._topic,
                    value=encode_evidence_message(message),
                    key=_canonical_key(message),
                )
                metadata: RecordMetadata = await delivery
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Never echo payload bytes or raw Evidence facts; never claim
                # zero messages were published.
                raise EvidencePublishError(
                    "evidence publication to the broker failed"
                ) from exc
            records.append(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(
                        stream=metadata.partition, offset=metadata.offset
                    ),
                    message=message,
                )
            )
        return EvidencePublishResult(records=tuple(records))


class KafkaEvidenceConsumer(EvidenceConsumer):
    """Kafka-compatible consumer adapter of the Evidence log (PR 28G).

    Subscribes to exactly the configured Evidence topic, derives the logical
    consumer group from the application :class:`EvidenceConsumerId`,
    disables auto-commit, decodes broker bytes with the PR 28C codec,
    validates the broker routing key against the decoded message, returns
    bounded multi-stream :class:`EvidenceBatch` values, and commits explicit
    per-stream ``highest offset + 1`` offsets only.
    """

    def __init__(
        self,
        *,
        topic: str,
        consumer_id: EvidenceConsumerId,
        poll_timeout_ms: int,
        consumer_factory: Callable[[], AsyncKafkaConsumer],
    ) -> None:
        """Bind the consumer to its topic, logical identity, and client factory.

        ``poll_timeout_ms`` is the bounded broker poll timeout; the logical
        ``consumer_id`` maps to the Kafka group identity (never an ephemeral
        member ID).
        """
        self._topic = topic
        self._consumer_id = consumer_id
        self._poll_timeout_ms = poll_timeout_ms
        self._consumer_factory = consumer_factory
        self._consumer: AsyncKafkaConsumer | None = None

    @property
    def topic(self) -> str:
        """Return the configured Evidence topic name."""
        return self._topic

    @property
    def consumer_id(self) -> EvidenceConsumerId:
        """Return the logical application consumer identity."""
        return self._consumer_id

    @property
    def is_started(self) -> bool:
        """Return whether the underlying consumer client is started."""
        return self._consumer is not None

    async def start(self) -> None:
        """Create and start the underlying consumer client (idempotent)."""
        if self._consumer is not None:
            return
        consumer = self._consumer_factory()
        await consumer.start()
        self._consumer = consumer

    async def stop(self) -> None:
        """Stop and drop the underlying consumer client (idempotent)."""
        consumer = self._consumer
        self._consumer = None
        if consumer is not None:
            await consumer.stop()

    def _require_started(self) -> AsyncKafkaConsumer:
        """Return the started consumer or fail closed with a bounded error."""
        if self._consumer is None:
            raise EvidencePollError("evidence consumer is not started")
        return self._consumer

    def __aenter__(self) -> "KafkaEvidenceConsumer":
        """Return ``self`` for async-context-manager composition."""
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Stop the consumer when the async context exits."""
        await self.stop()

    async def poll(self, max_messages: int) -> EvidenceBatch:
        """Poll at most ``max_messages`` records without acknowledging them.

        A single poll is bounded by the global ``max_messages`` (never a
        per-partition bound), may span several partitions/streams, and
        returns an empty batch when the broker has nothing within the
        configured timeout. Each represented stream's offsets are ordered.
        """
        if (
            not isinstance(max_messages, int)
            or isinstance(max_messages, bool)
            or max_messages <= 0
        ):
            raise EvidencePollError("poll max_messages must be a positive integer")
        consumer = self._require_started()
        try:
            fetched: dict[
                TopicPartition, list[ConsumerRecord]
            ] = await consumer.getmany(
                timeout_ms=self._poll_timeout_ms, max_records=max_messages
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise EvidencePollError("evidence poll from the broker failed") from exc
        records = self._flatten(fetched, max_messages)
        return EvidenceBatch(consumer_id=self._consumer_id, records=records)

    def _flatten(
        self,
        fetched: dict[TopicPartition, list[ConsumerRecord]],
        max_messages: int,
    ) -> tuple[EvidenceLogRecord, ...]:
        """Flatten one multi-partition fetch into a deterministic batch.

        Streams/partitions are sorted ascending for deterministic adapter
        output; within each stream the broker offset order is preserved.
        This is a representation rule only and does not claim cross-stream
        ordering.
        """
        records: list[EvidenceLogRecord] = []
        for partition in sorted(fetched, key=lambda tp: tp.partition):
            for broker_record in fetched[partition]:
                message = self._decode(broker_record)
                records.append(
                    EvidenceLogRecord(
                        position=EvidenceLogPosition(
                            stream=broker_record.partition,
                            offset=broker_record.offset,
                        ),
                        message=message,
                    )
                )
        return tuple(records[:max_messages])

    def _decode(self, broker_record: ConsumerRecord) -> EvidenceMessage:
        """Decode one broker record and validate key/message consistency.

        The broker value is decoded with the authoritative PR 28C codec; a
        non-null key must equal the canonical key derived from the decoded
        message's ``evidence_id``, otherwise the transport-contract check
        fails closed. The key is routing metadata only: Evidence identity is
        always reconstructed from the decoded message, never from the key.
        """
        try:
            message = decode_evidence_message(broker_record.value)
        except Exception as exc:
            raise EvidencePollError(
                "evidence message payload could not be decoded"
            ) from exc
        if broker_record.key is None or broker_record.key != _canonical_key(message):
            raise EvidencePollError(
                "broker record key does not match the Evidence identity"
            )
        return message

    async def commit(self, batch: EvidenceBatch) -> None:
        """Acknowledge one entire batch across every represented stream.

        Empty batches are a no-op. For each represented stream the adapter
        commits ``highest processed offset + 1``; absent partitions are never
        advanced. Rebalance/ownership and broker commit failures surface as
        :class:`EvidenceCommitError` and never report success.
        """
        if batch.consumer_id != self._consumer_id:
            raise EvidenceCommitError("batch belongs to another consumer")
        if not batch.records:
            return
        offsets = self._commit_offsets(batch)
        consumer = self._require_started()
        try:
            await consumer.commit(offsets)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise EvidenceCommitError(
                "evidence batch commit to the broker failed"
            ) from exc

    def _commit_offsets(self, batch: EvidenceBatch) -> dict[TopicPartition, int]:
        """Build the explicit broker offset map of one valid batch.

        Enforces per-stream strictly increasing contiguous offsets, rejecting
        duplicate, reversed, or gapped ``(stream, offset)`` positions; any
        violation fails the whole commit without contacting the broker.
        """
        next_offsets: dict[int, int] = {}
        for record in batch.records:
            stream = record.position.stream
            offset = record.position.offset
            if stream in next_offsets:
                if offset != next_offsets[stream]:
                    raise EvidenceCommitError(
                        "batch stream offsets must be contiguous and ordered"
                    )
                next_offsets[stream] = offset + 1
            else:
                next_offsets[stream] = offset + 1
        return {
            TopicPartition(self._topic, stream): next_offset
            for stream, next_offset in next_offsets.items()
        }


def build_kafka_publisher(
    *,
    bootstrap_servers: tuple[str, ...],
    topic: str,
    client_id: str,
    security_protocol: str = "PLAINTEXT",
    ssl_context: object | None = None,
    sasl_mechanism: str | None = None,
    sasl_plain_username: str | None = None,
    sasl_plain_password: str | None = None,
) -> KafkaEvidencePublisher:
    """Compose a production :class:`KafkaEvidencePublisher` from settings.

    The returned adapter owns the lifecycle of one real ``aiokafka``
    producer; call :meth:`KafkaEvidencePublisher.start` before publication
    and :meth:`KafkaEvidencePublisher.stop` on shutdown.
    """

    def factory() -> AsyncKafkaProducer:
        return cast(
            AsyncKafkaProducer,
            AIOKafkaProducer(
                **_producer_kwargs(
                    bootstrap_servers=bootstrap_servers,
                    client_id=client_id,
                    security_protocol=security_protocol,
                    ssl_context=ssl_context,
                    sasl_mechanism=sasl_mechanism,
                    sasl_plain_username=sasl_plain_username,
                    sasl_plain_password=sasl_plain_password,
                )
            ),
        )

    return KafkaEvidencePublisher(topic=topic, producer_factory=factory)


def build_kafka_consumer(
    *,
    bootstrap_servers: tuple[str, ...],
    topic: str,
    consumer_id: EvidenceConsumerId,
    client_id: str,
    poll_timeout_ms: int,
    security_protocol: str = "PLAINTEXT",
    auto_offset_reset: str = "earliest",
    ssl_context: object | None = None,
    sasl_mechanism: str | None = None,
    sasl_plain_username: str | None = None,
    sasl_plain_password: str | None = None,
) -> KafkaEvidenceConsumer:
    """Compose a production :class:`KafkaEvidenceConsumer` from settings.

    The logical ``consumer_id`` becomes the Kafka ``group_id``; auto-commit
    is disabled. Call :meth:`KafkaEvidenceConsumer.start` before polling and
    :meth:`KafkaEvidenceConsumer.stop` on shutdown.
    """

    def factory() -> AsyncKafkaConsumer:
        return cast(
            AsyncKafkaConsumer,
            AIOKafkaConsumer(
                topic,
                **_consumer_kwargs(
                    group_id=consumer_id.value,
                    client_id=client_id,
                    bootstrap_servers=bootstrap_servers,
                    security_protocol=security_protocol,
                    auto_offset_reset=auto_offset_reset,
                    ssl_context=ssl_context,
                    sasl_mechanism=sasl_mechanism,
                    sasl_plain_username=sasl_plain_username,
                    sasl_plain_password=sasl_plain_password,
                ),
            ),
        )

    return KafkaEvidenceConsumer(
        topic=topic,
        consumer_id=consumer_id,
        poll_timeout_ms=poll_timeout_ms,
        consumer_factory=factory,
    )
