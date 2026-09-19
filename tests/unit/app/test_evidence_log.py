# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 28D distributed-log application contracts and in-memory log tests (E28D matrix).

Matrix IDs:

- E28D-C01..C08: contract/value types (position bounds and immutability,
  consumer-ID bounds, real PR 28C messages in records, immutable batches,
  ABC conformance, no broker fields).
- E28D-P01..P09: publication (first position, contiguous multi-message
  runs, continuation, empty no-op, fail-next atomicity, retry, duplicate
  messages at distinct positions, concurrent calls, non-message rejection).
- E28D-R01..R13: poll/redelivery (empty poll, bounded prefixes, larger
  bounds, poll never advances, repeat-before-commit, invalid bounds, exact
  commit advance, poll after commit, final commit, append after caught up,
  handle recreation after commit/uncommitted poll).
- E28D-K01..K11: commit validation (empty no-op, foreign consumer, skipped,
  stale/repeat policy, non-contiguous, forged record, reversed, cursor
  unchanged on failure, exact repeat-policy, prefix-commit policy,
  beyond-log positions).
- E28D-G01..G05: consumer independence (same prefix, A/B commit isolation,
  same-ID shared cursor, different-ID independent cursors).
- E28D-F01..F09: deterministic failure injection (publish/poll/commit
  faults, retry after fault, consumer-targeted faults, cancellation).
- D28D-V01..V05: application vertical slices (ordered publish/poll/commit,
  crash/redelivery model, commit-failure redelivery, independent
  consumers, PR 28C identity surviving transport).

All tests are deterministic, offline, and involve no database, network,
broker, sleep, or UnitOfWork; real PR 28C ``EvidenceMessage`` values are
built through the public builder and never mocked.
"""

from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_log import (
    EVIDENCE_CONSUMER_ID_MAX_LENGTH,
    EvidenceBatch,
    EvidenceCommitError,
    EvidenceConsumer,
    EvidenceConsumerId,
    EvidenceLogError,
    EvidenceLogPosition,
    EvidenceLogRecord,
    EvidencePollError,
    EvidencePublisher,
    EvidencePublishError,
    EvidencePublishResult,
    InMemoryEvidenceLog,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    decode_evidence_message,
    encode_evidence_message,
    evidence_message_from_converted,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)

pytestmark = pytest.mark.unit

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"
_EXECUTION_ID = uuid4()

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)

_ID_A = EvidenceConsumerId("consumer-a")
_ID_B = EvidenceConsumerId("consumer-b")


def _context() -> SemanticSourceContext:
    """Build one deterministic semantic provenance context."""
    return SemanticSourceContext(
        datasource_id=_DEFINITION.datasource_id,
        source_id=SourceId.THREATFOX,
        semantic_format=SemanticFormatId.THREATFOX,
        retrieved_at=_FIXED_TS,
        source_reference=_ENDPOINT,
    )


def _converted(
    context: SemanticSourceContext, source_record_id: str
) -> ConvertedEvidence:
    """Build one deterministic ConvertedEvidence consistent with a context."""
    evidence_id = evidence_id_for_source_record(
        context.semantic_format, context.source_id, source_record_id
    )
    return ConvertedEvidence(
        evidence=Evidence(
            id=evidence_id,
            type=EvidenceType.THREAT_INTELLIGENCE,
            source=context.source_id.value,
            source_record_id=source_record_id,
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=evidence_id,
            source_url=context.source_reference,
            retrieved_at=context.retrieved_at,
            facts={},
        ),
    )


def _message(sequence: int = 0) -> EvidenceMessage:
    """Build one real deterministic V1 message through the public PR 28C builder."""
    context = _context()
    return evidence_message_from_converted(
        _converted(context, source_record_id=f"record-{sequence}"),
        datasource_execution_id=_EXECUTION_ID,
        semantic_source=context,
        sequence=sequence,
    )


class TestContractValues:
    """E28D-C01..C08 (generalized) + E28G-C: position, identity, records, batches.

    E28G generalizes the transport position from one scalar global index to
    a broker-neutral ``(stream, offset)`` pair while preserving every
    E28D-C value/immutability property on stream 0.
    """

    def test_g_c01_valid_zero_position(self) -> None:
        """E28G-C01: stream 0 offset 0 is a valid first position."""
        position = EvidenceLogPosition(stream=0, offset=0)
        assert position.stream == 0
        assert position.offset == 0

    def test_g_c02_negative_stream_rejected(self) -> None:
        """E28G-C02: a negative stream fails closed."""
        with pytest.raises(ValueError):
            EvidenceLogPosition(stream=-1, offset=0)

    def test_g_c03_negative_offset_rejected(self) -> None:
        """E28G-C03: a negative offset fails closed."""
        with pytest.raises(ValueError):
            EvidenceLogPosition(stream=0, offset=-1)
        with pytest.raises(ValueError):
            EvidenceLogPosition(stream=0, offset=-3)

    def test_g_c04_bool_stream_rejected(self) -> None:
        """E28G-C04: a boolean stream masquerading as an integer fails closed."""
        with pytest.raises(ValueError):
            EvidenceLogPosition(stream=True, offset=0)

    def test_g_c05_bool_offset_rejected(self) -> None:
        """E28G-C05: a boolean offset masquerading as an integer fails closed."""
        with pytest.raises(ValueError):
            EvidenceLogPosition(stream=0, offset=True)

    def test_c01_negative_position_rejected_legacy(self) -> None:
        """E28D-C01 (legacy): a negative scalar position still fails closed."""
        with pytest.raises(ValueError):
            EvidenceLogPosition(stream=0, offset=-1)
        with pytest.raises(ValueError):
            EvidenceLogPosition(stream=0, offset=-3)

    def test_c02_valid_position_immutable_value_equality(self) -> None:
        """E28D-C02: positions are immutable, comparable, and value-equal."""
        assert EvidenceLogPosition(stream=0, offset=3) == EvidenceLogPosition(
            stream=0, offset=3
        )
        # Ordering is meaningful within one stream (deterministic tests only).
        assert EvidenceLogPosition(stream=0, offset=0) < EvidenceLogPosition(
            stream=0, offset=1
        )
        assert EvidenceLogPosition(stream=1, offset=0) < EvidenceLogPosition(
            stream=1, offset=2
        )
        position = EvidenceLogPosition(stream=0, offset=2)
        with pytest.raises(FrozenInstanceError):
            position.offset = 5  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            position.stream = 1  # type: ignore[misc]

    def test_c05_record_contains_real_pr28c_message(self) -> None:
        """E28D-C05: a record carries the exact validated EvidenceMessage."""
        message = _message(sequence=2)
        record = EvidenceLogRecord(
            position=EvidenceLogPosition(stream=0, offset=4), message=message
        )
        assert record.position == EvidenceLogPosition(stream=0, offset=4)
        assert record.message == message
        assert record.message.message_id == message.message_id

    def test_c06_batch_collection_is_immutable_tuple(self) -> None:
        """E28D-C06: a batch owns an immutable tuple of records and is frozen."""
        record = EvidenceLogRecord(
            position=EvidenceLogPosition(stream=0, offset=0), message=_message()
        )
        batch = EvidenceBatch(consumer_id=_ID_A, records=(record,))
        assert isinstance(batch.records, tuple)
        assert batch.records == (record,)
        with pytest.raises(FrozenInstanceError):
            batch.records = ()  # type: ignore[misc]

    def test_c07_in_memory_handles_conform_to_abcs(self) -> None:
        """E28D-C07: log handles implement the broker-neutral contracts."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        assert isinstance(publisher, EvidencePublisher)
        assert isinstance(consumer, EvidenceConsumer)

    def test_c08_no_kafka_broker_fields(self) -> None:
        """E28D-C08: no broker/topic/partition/offset/group fields exist."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        record = EvidenceLogRecord(
            position=EvidenceLogPosition(stream=0, offset=0), message=_message()
        )
        batch = EvidenceBatch(consumer_id=_ID_A, records=(record,))
        result = EvidencePublishResult(records=(record,))
        for obj in (log, publisher, consumer, record, batch, result):
            for field in (
                "topic",
                "partition",
                "offset",
                "group",
                "group_id",
                "leader",
                "broker",
                "kafka",
            ):
                assert not hasattr(obj, field)

    def test_g_c10_position_absent_from_message_wire(self) -> None:
        """E28G-C10: stream/offset never enter the PR 28C message wire."""
        message = _message(sequence=2)
        record = EvidenceLogRecord(
            position=EvidenceLogPosition(stream=3, offset=7), message=message
        )
        wire = encode_evidence_message(record.message).decode("utf-8")
        assert "stream" not in wire
        assert "offset" not in wire
        assert decode_evidence_message(encode_evidence_message(message)) == message

    def test_c03_empty_consumer_id_rejected(self) -> None:
        """E28D-C03: blank or non-string consumer identities fail closed."""
        with pytest.raises(ValueError):
            EvidenceConsumerId("")
        with pytest.raises(ValueError):
            EvidenceConsumerId("   ")
        with pytest.raises(ValueError):
            EvidenceConsumerId(cast(Any, 123))

    def test_c04_oversized_consumer_id_rejected(self) -> None:
        """E28D-C04: consumer identities are length-bounded."""
        at_bound = EvidenceConsumerId("x" * EVIDENCE_CONSUMER_ID_MAX_LENGTH)
        assert len(at_bound.value) == EVIDENCE_CONSUMER_ID_MAX_LENGTH
        with pytest.raises(ValueError):
            EvidenceConsumerId("x" * (EVIDENCE_CONSUMER_ID_MAX_LENGTH + 1))

    @pytest.mark.asyncio
    async def test_g_c09_in_memory_rejects_nonzero_stream_commit(self) -> None:
        """E28G-C09: the in-memory log rejects a foreign nonzero-stream commit.

        The in-memory implementation owns exactly transport stream 0; a batch
        fabricating a different stream cannot correspond to its log and fails
        closed at commit.
        """
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        message = _message(0)
        await publisher.publish([message])
        foreign = EvidenceBatch(
            consumer_id=_ID_A,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=1, offset=0),
                    message=message,
                ),
            ),
        )
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(foreign)
        assert [
            record.position.offset for record in (await consumer.poll(5)).records
        ] == [0]


class TestPublication:
    """E28D-P01..P08: ordered, contiguous, atomic publication."""

    @pytest.mark.asyncio
    async def test_p01_first_message_position_zero(self) -> None:
        """E28D-P01: the first publish appends at position 0."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        result = await publisher.publish([_message(0)])
        assert len(result.records) == 1
        assert result.records[0].position == EvidenceLogPosition(stream=0, offset=0)
        assert result.records[0].message == _message(0)

    @pytest.mark.asyncio
    async def test_p02_multi_message_publish_contiguous_ordered(self) -> None:
        """E28D-P02: one publish call appends positions 0,1,2 in input order."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        messages = [_message(0), _message(1), _message(2)]
        result = await publisher.publish(messages)
        assert [record.position.offset for record in result.records] == [0, 1, 2]
        assert [record.message for record in result.records] == messages

    @pytest.mark.asyncio
    async def test_p03_subsequent_publish_continues_positions(self) -> None:
        """E28D-P03: a later publish continues from the previous position."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0)])
        result = await publisher.publish([_message(1), _message(2)])
        assert [record.position.offset for record in result.records] == [1, 2]

    @pytest.mark.asyncio
    async def test_p04_empty_publish_is_no_op(self) -> None:
        """E28D-P04: an empty publish is a documented no-op with no mutation."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        empty = await publisher.publish([])
        assert empty.records == ()
        result = await publisher.publish([_message(0)])
        assert result.records[0].position == EvidenceLogPosition(stream=0, offset=0)

    @pytest.mark.asyncio
    async def test_p05_fail_next_publish_typed_error_no_append_or_gap(self) -> None:
        """E28D-P05: a triggered publish fault appends nothing and uses no position."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        log.fail_next_publish()
        with pytest.raises(EvidencePublishError) as caught:
            await publisher.publish([_message(0), _message(1)])
        assert isinstance(caught.value, EvidenceLogError)
        consumer = log.consumer(_ID_A)
        assert (await consumer.poll(5)).records == ()

    @pytest.mark.asyncio
    async def test_p06_retry_after_fault_original_next_position(self) -> None:
        """E28D-P06: after a fault, the retry uses the original next position."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        log.fail_next_publish()
        with pytest.raises(EvidencePublishError):
            await publisher.publish([_message(0)])
        result = await publisher.publish([_message(1)])
        assert result.records[0].position == EvidenceLogPosition(stream=0, offset=0)
        assert result.records[0].message == _message(1)

    @pytest.mark.asyncio
    async def test_p07_same_message_twice_two_records(self) -> None:
        """E28D-P07: publishing the same message twice creates two records."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        message = _message(0)
        await publisher.publish([message])
        second = await publisher.publish([message])
        assert second.records[0].position == EvidenceLogPosition(stream=0, offset=1)
        assert second.records[0].message == message
        consumer = log.consumer(_ID_A)
        batch = await consumer.poll(5)
        assert len(batch.records) == 2
        assert batch.records[0].message == batch.records[1].message == message

    @pytest.mark.asyncio
    async def test_p08_concurrent_publish_unique_contiguous_positions(self) -> None:
        """E28D-P08: concurrent publishes keep unique contiguous positions."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        first_messages = [_message(0), _message(1)]
        second_message = _message(2)
        results = await asyncio.gather(
            publisher.publish(first_messages),
            publisher.publish([second_message]),
        )
        first = results[0].records
        second = results[1].records
        assert [record.message for record in first] == first_messages
        assert [record.message for record in second] == [second_message]
        positions = [record.position.offset for record in first] + [
            record.position.offset for record in second
        ]
        assert sorted(positions) == [0, 1, 2]
        assert first[0].position.offset + 1 == first[1].position.offset

    @pytest.mark.asyncio
    async def test_p09_non_message_element_rejected(self) -> None:
        """E28D-P09: a non-EvidenceMessage element fails the publish closed."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        bad = cast(list[EvidenceMessage], ["not-a-message"])
        with pytest.raises(EvidencePublishError):
            await publisher.publish(bad)
        assert (await log.consumer(_ID_A).poll(5)).records == ()


class TestPollRedelivery:
    """E28D-R01..R13: bounded non-destructive polling and redelivery."""

    @pytest.mark.asyncio
    async def test_r01_empty_log_poll_empty_batch(self) -> None:
        """E28D-R01: polling an empty log returns an empty batch."""
        log = InMemoryEvidenceLog()
        consumer = log.consumer(_ID_A)
        batch = await consumer.poll(5)
        assert batch.consumer_id == _ID_A
        assert batch.records == ()

    @pytest.mark.asyncio
    async def test_r02_bound_smaller_than_available_exact_prefix(self) -> None:
        """E28D-R02: a smaller bound returns exactly the first records."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1), _message(2)])
        batch = await log.consumer(_ID_A).poll(2)
        assert [record.position.offset for record in batch.records] == [0, 1]

    @pytest.mark.asyncio
    async def test_r03_bound_larger_returns_all_remaining(self) -> None:
        """E28D-R03: a bound larger than the log returns all remaining records."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        messages = [_message(0), _message(1), _message(2)]
        await publisher.publish(messages)
        batch = await log.consumer(_ID_A).poll(10)
        assert [record.message for record in batch.records] == messages

    @pytest.mark.asyncio
    async def test_r04_poll_only_does_not_advance_cursor(self) -> None:
        """E28D-R04: polling never advances the committed cursor."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1), _message(2)])
        consumer = log.consumer(_ID_A)
        await consumer.poll(2)
        await consumer.poll(2)
        assert [
            record.position.offset for record in (await consumer.poll(2)).records
        ] == [
            0,
            1,
        ]

    @pytest.mark.asyncio
    async def test_r05_repeat_before_commit_returns_same_records(self) -> None:
        """E28D-R05: repeated polls before commit return the identical prefix."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        first = await consumer.poll(5)
        second = await consumer.poll(5)
        assert first == second

    @pytest.mark.asyncio
    async def test_r06_zero_bound_rejected_no_mutation(self) -> None:
        """E28D-R06: a zero poll bound fails closed and mutates nothing."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        with pytest.raises(EvidencePollError):
            await consumer.poll(0)
        assert [
            record.position.offset for record in (await consumer.poll(5)).records
        ] == [
            0,
            1,
        ]

    @pytest.mark.asyncio
    async def test_r07_negative_bound_rejected_no_mutation(self) -> None:
        """E28D-R07: a negative poll bound fails closed and mutates nothing."""
        log = InMemoryEvidenceLog()
        consumer = log.consumer(_ID_A)
        with pytest.raises(EvidencePollError):
            await consumer.poll(-1)

    @pytest.mark.asyncio
    async def test_r08_commit_advances_cursor_exactly(self) -> None:
        """E28D-R08: committing a batch advances the cursor past its final record."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1), _message(2)])
        consumer = log.consumer(_ID_A)
        batch = await consumer.poll(2)
        await consumer.commit(batch)
        assert [
            record.position.offset for record in (await consumer.poll(1)).records
        ] == [
            2,
        ]

    @pytest.mark.asyncio
    async def test_r09_poll_after_commit_begins_at_cursor(self) -> None:
        """E28D-R09: after a commit, the next poll begins at the new cursor."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        await consumer.commit(await consumer.poll(2))
        batch = await consumer.poll(5)
        assert [record.position.offset for record in batch.records] == []

    @pytest.mark.asyncio
    async def test_r10_commit_final_next_poll_empty(self) -> None:
        """E28D-R10: committing the final records makes the next poll empty."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        await consumer.commit(await consumer.poll(2))
        assert (await consumer.poll(5)).records == ()

    @pytest.mark.asyncio
    async def test_r11_append_after_caught_up_new_records_visible(self) -> None:
        """E28D-R11: publishes after catch-up become visible to the next poll."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        await publisher.publish([_message(0)])
        await consumer.commit(await consumer.poll(5))
        assert (await consumer.poll(5)).records == ()
        await publisher.publish([_message(1)])
        batch = await consumer.poll(5)
        assert [record.position.offset for record in batch.records] == [1]

    @pytest.mark.asyncio
    async def test_r12_recreate_after_commit_resumes_cursor(self) -> None:
        """E28D-R12: recreating a handle after commit resumes the cursor."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1), _message(2)])
        first = log.consumer(_ID_A)
        await first.commit(await first.poll(2))
        recreated = log.consumer(_ID_A)
        assert [
            record.position.offset for record in (await recreated.poll(5)).records
        ] == [
            2,
        ]

    @pytest.mark.asyncio
    async def test_r13_recreate_after_uncommitted_poll_redelivers(self) -> None:
        """E28D-R13: an uncommitted poll redelivers to a recreated handle."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        first = log.consumer(_ID_A)
        await first.poll(5)
        recreated = log.consumer(_ID_A)
        batch = await recreated.poll(5)
        assert [record.position.offset for record in batch.records] == [0, 1]


class TestCommitValidation:
    """E28D-K01..K10: exact explicit commit with fail-closed validation."""

    @pytest.mark.asyncio
    async def test_k01_empty_batch_noop(self) -> None:
        """E28D-K01: committing an empty batch is a no-op."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0)])
        consumer = log.consumer(_ID_A)
        await consumer.commit(EvidenceBatch(consumer_id=_ID_A, records=()))
        assert [
            record.position.offset for record in (await consumer.poll(5)).records
        ] == [
            0,
        ]

    @pytest.mark.asyncio
    async def test_k02_foreign_batch_rejected(self) -> None:
        """E28D-K02: a batch belonging to another consumer is rejected."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0)])
        consumer_a = log.consumer(_ID_A)
        polled = await consumer_a.poll(5)
        foreign = EvidenceBatch(consumer_id=_ID_B, records=polled.records)
        with pytest.raises(EvidenceCommitError):
            await consumer_a.commit(foreign)

    @pytest.mark.asyncio
    async def test_k03_skipped_positions_rejected(self) -> None:
        """E28D-K03: a batch starting after the cursor skips positions and fails."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1), _message(2)])
        consumer = log.consumer(_ID_A)
        skipped = EvidenceBatch(
            consumer_id=_ID_A,
            records=(log._records[1], log._records[2]),
        )
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(skipped)

    @pytest.mark.asyncio
    async def test_k04_stale_batch_rejected(self) -> None:
        """E28D-K04: a batch starting before the cursor is stale and rejected."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        batch = await consumer.poll(2)
        await consumer.commit(batch)
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(batch)

    @pytest.mark.asyncio
    async def test_k05_non_contiguous_rejected(self) -> None:
        """E28D-K05: a batch with a position gap fails closed."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1), _message(2)])
        consumer = log.consumer(_ID_A)
        gappy = EvidenceBatch(
            consumer_id=_ID_A,
            records=(log._records[0], log._records[2]),
        )
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(gappy)

    @pytest.mark.asyncio
    async def test_k06_forged_record_rejected(self) -> None:
        """E28D-K06: a forged record at a valid position fails closed."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0)])
        consumer = log.consumer(_ID_A)
        forged = EvidenceBatch(
            consumer_id=_ID_A,
            records=(
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=0),
                    message=_message(1),
                ),
            ),
        )
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(forged)

    @pytest.mark.asyncio
    async def test_k07_reversed_records_rejected(self) -> None:
        """E28D-K07: reversed record positions fail closed."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        first = (await consumer.poll(1)).records
        await consumer.commit(EvidenceBatch(consumer_id=_ID_A, records=first))
        reversed_batch = EvidenceBatch(
            consumer_id=_ID_A,
            records=(log._records[1], log._records[0]),
        )
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(reversed_batch)

    @pytest.mark.asyncio
    async def test_k08_failed_validation_leaves_cursor_unchanged(self) -> None:
        """E28D-K08: a rejected commit never moves the cursor."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        invalid = EvidenceBatch(
            consumer_id=_ID_A,
            records=(log._records[1],),
        )
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(invalid)
        assert [
            record.position.offset for record in (await consumer.poll(5)).records
        ] == [
            0,
            1,
        ]

    @pytest.mark.asyncio
    async def test_k09_exact_already_committed_batch_strict_policy(self) -> None:
        """E28D-K09: an exact repeated commit is rejected under the stale policy."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        batch = await consumer.poll(2)
        await consumer.commit(batch)
        with pytest.raises(EvidenceCommitError) as caught:
            await consumer.commit(batch)
        assert "stale or repeated commit" in str(caught.value)

    @pytest.mark.asyncio
    async def test_k10_partial_commit_from_larger_poll_advances_exact_batch(
        self,
    ) -> None:
        """E28D-K10: a proper prefix commit is a valid whole-batch commit.

        Polling returns a prefix batch; committing a strict prefix of it is
        value-identical to committing the exact result of a smaller poll, so
        the cursor advances exactly past the batch's final record and the
        remaining records stay redeliverable. No partial-acknowledgement
        state is tracked: there is no way to acknowledge the remaining
        record without committing it.
        """
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        await publisher.publish([_message(0), _message(1), _message(2)])
        polled = await consumer.poll(3)
        assert [record.position.offset for record in polled.records] == [0, 1, 2]
        prefix = EvidenceBatch(
            consumer_id=polled.consumer_id, records=polled.records[:2]
        )
        await consumer.commit(prefix)
        assert [
            record.position.offset for record in (await consumer.poll(3)).records
        ] == [
            2,
        ]
        remaining = await consumer.poll(3)
        await consumer.commit(remaining)
        assert (await consumer.poll(3)).records == ()

    @pytest.mark.asyncio
    async def test_k11_beyond_log_position_rejected(self) -> None:
        """E28D-K11: a contiguous position beyond the log fails closed."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        await publisher.publish([_message(0)])
        beyond = EvidenceBatch(
            consumer_id=_ID_A,
            records=(
                log._records[0],
                EvidenceLogRecord(
                    position=EvidenceLogPosition(stream=0, offset=1),
                    message=_message(1),
                ),
            ),
        )
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(beyond)
        assert [
            record.position.offset for record in (await consumer.poll(5)).records
        ] == [
            0,
        ]


class TestConsumerIndependence:
    """E28D-G01..G05: per-consumer committed cursors."""

    @pytest.mark.asyncio
    async def test_g01_initial_poll_same_prefix(self) -> None:
        """E28D-G01: two consumers initially see the same prefix."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer_a = log.consumer(_ID_A)
        consumer_b = log.consumer(_ID_B)
        assert (await consumer_a.poll(5)).records == (await consumer_b.poll(5)).records

    @pytest.mark.asyncio
    async def test_g02_a_commits_b_unchanged(self) -> None:
        """E28D-G02: A's commit never moves B's cursor."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer_a = log.consumer(_ID_A)
        consumer_b = log.consumer(_ID_B)
        await consumer_a.commit(await consumer_a.poll(2))
        batch_b = await consumer_b.poll(5)
        assert [record.position.offset for record in batch_b.records] == [0, 1]

    @pytest.mark.asyncio
    async def test_g03_b_commits_a_unchanged(self) -> None:
        """E28D-G03: B's commit never moves A's cursor."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer_a = log.consumer(_ID_A)
        consumer_b = log.consumer(_ID_B)
        await consumer_b.commit(await consumer_b.poll(2))
        batch_a = await consumer_a.poll(5)
        assert [record.position.offset for record in batch_a.records] == [0, 1]

    @pytest.mark.asyncio
    async def test_g04_same_id_two_handles_shared_cursor(self) -> None:
        """E28D-G04: two handles with the same identity share one cursor."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1), _message(2)])
        first = log.consumer(_ID_A)
        second = log.consumer(_ID_A)
        await first.commit(await first.poll(2))
        assert [
            record.position.offset for record in (await second.poll(5)).records
        ] == [
            2,
        ]

    @pytest.mark.asyncio
    async def test_g05_different_ids_independent_cursors(self) -> None:
        """E28D-G05: different identities keep independent cursors."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1), _message(2)])
        consumer_a = log.consumer(_ID_A)
        consumer_b = log.consumer(_ID_B)
        await consumer_a.commit(await consumer_a.poll(2))
        assert [
            record.position.offset for record in (await consumer_a.poll(5)).records
        ] == [
            2,
        ]
        assert [
            record.position.offset for record in (await consumer_b.poll(5)).records
        ] == [
            0,
            1,
            2,
        ]


class TestFailureInjection:
    """E28D-F01..F09: deterministic one-shot publish/poll/commit faults."""

    @pytest.mark.asyncio
    async def test_f01_fail_publish_no_mutation(self) -> None:
        """E28D-F01: an armed publish fault raises and mutates nothing."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        await publisher.publish([_message(0)])
        log.fail_next_publish()
        with pytest.raises(EvidencePublishError) as caught:
            await publisher.publish([_message(1), _message(2)])
        assert isinstance(caught.value, EvidenceLogError)
        assert [
            record.position.offset for record in (await consumer.poll(5)).records
        ] == [
            0,
        ]

    @pytest.mark.asyncio
    async def test_f02_publish_after_fault_succeeds(self) -> None:
        """E28D-F02: a publish after the fault succeeds normally."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        log.fail_next_publish()
        with pytest.raises(EvidencePublishError):
            await publisher.publish([_message(0)])
        result = await publisher.publish([_message(1)])
        assert result.records[0].position == EvidenceLogPosition(stream=0, offset=0)

    @pytest.mark.asyncio
    async def test_f03_fail_poll_no_cursor_change(self) -> None:
        """E28D-F03: an armed poll fault raises with the cursor unchanged."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        log.fail_next_poll()
        with pytest.raises(EvidencePollError) as caught:
            await consumer.poll(5)
        assert isinstance(caught.value, EvidenceLogError)
        assert [
            record.position.offset for record in (await consumer.poll(5)).records
        ] == [
            0,
            1,
        ]

    @pytest.mark.asyncio
    async def test_f04_poll_after_fault_normal(self) -> None:
        """E28D-F04: a poll after the fault returns records normally."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0)])
        consumer = log.consumer(_ID_A)
        log.fail_next_poll()
        with pytest.raises(EvidencePollError):
            await consumer.poll(5)
        assert [
            record.position.offset for record in (await consumer.poll(5)).records
        ] == [
            0,
        ]

    @pytest.mark.asyncio
    async def test_f05_fail_commit_no_cursor_change(self) -> None:
        """E28D-F05: an armed commit fault raises with the cursor unchanged."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        batch = await consumer.poll(5)
        log.fail_next_commit()
        with pytest.raises(EvidenceCommitError) as caught:
            await consumer.commit(batch)
        assert isinstance(caught.value, EvidenceLogError)
        assert [
            record.position.offset for record in (await consumer.poll(5)).records
        ] == [
            0,
            1,
        ]

    @pytest.mark.asyncio
    async def test_f06_poll_after_failed_commit_same_batch(self) -> None:
        """E28D-F06: after a failed commit the next poll redelivers the batch."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        batch = await consumer.poll(5)
        log.fail_next_commit()
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(batch)
        redelivered = await consumer.poll(5)
        assert redelivered == batch

    @pytest.mark.asyncio
    async def test_f07_commit_after_fault_succeeds(self) -> None:
        """E28D-F07: a commit after the fault succeeds and advances."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer = log.consumer(_ID_A)
        batch = await consumer.poll(5)
        log.fail_next_commit()
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(batch)
        await consumer.commit(batch)
        assert (await consumer.poll(5)).records == ()

    @pytest.mark.asyncio
    async def test_f08_consumer_targeted_faults_do_not_affect_others(self) -> None:
        """E28D-F08: a consumer-targeted fault leaves other consumers unaffected."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1)])
        consumer_a = log.consumer(_ID_A)
        consumer_b = log.consumer(_ID_B)

        log.fail_next_poll(_ID_A)
        with pytest.raises(EvidencePollError):
            await consumer_a.poll(5)
        assert [
            record.position.offset for record in (await consumer_b.poll(5)).records
        ] == [
            0,
            1,
        ]

        batch_a = await consumer_a.poll(5)
        batch_b = await consumer_b.poll(5)
        log.fail_next_commit(_ID_A)
        with pytest.raises(EvidenceCommitError):
            await consumer_a.commit(batch_a)
        await consumer_b.commit(batch_b)
        assert [
            record.position.offset for record in (await consumer_a.poll(5)).records
        ] == [
            0,
            1,
        ]

    @pytest.mark.asyncio
    async def test_f09_cancellation_propagates_state_valid(self) -> None:
        """E28D-F09: cancellation propagates and leaves the log state valid.

        The test holds the log's internal lock so a poll task deterministically
        blocks at its single await point, then cancels it: cancellation must
        propagate unchanged and must not corrupt the cursor or consume state.
        """
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        await publisher.publish([_message(0), _message(1)])
        await log._lock.acquire()
        task = asyncio.create_task(consumer.poll(5))
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        log._lock.release()
        batch = await consumer.poll(5)
        assert [record.position.offset for record in batch.records] == [0, 1]
        await consumer.commit(batch)
        assert (await consumer.poll(5)).records == ()


class TestVerticalSlices:
    """D28D-V01..V05: application-level semantic vertical slices."""

    @pytest.mark.asyncio
    async def test_v01_ordered_publish_poll_commit(self) -> None:
        """D28D-V01: real messages publish to 0,1,2; A commits 0,1; poll -> 2."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        messages = [_message(0), _message(1), _message(2)]
        result = await publisher.publish(messages)
        assert [record.position.offset for record in result.records] == [0, 1, 2]
        first_batch = await consumer.poll(2)
        assert [record.message for record in first_batch.records] == messages[:2]
        await consumer.commit(first_batch)
        second_batch = await consumer.poll(5)
        assert [record.position.offset for record in second_batch.records] == [2]
        assert second_batch.records[0].message == messages[2]

    @pytest.mark.asyncio
    async def test_v02_crash_redelivery_model(self) -> None:
        """D28D-V02: a simulated crash before commit redelivers to a recreated handle."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        messages = [_message(0), _message(1)]
        await publisher.publish(messages)
        first = log.consumer(_ID_A)
        crash_batch = await first.poll(5)
        assert [record.message for record in crash_batch.records] == messages
        recreated = log.consumer(_ID_A)
        redelivered = await recreated.poll(5)
        assert redelivered == crash_batch
        await recreated.commit(redelivered)
        assert (await recreated.poll(5)).records == ()

    @pytest.mark.asyncio
    async def test_v03_commit_failure_redelivery(self) -> None:
        """D28D-V03: a failed commit redelivers the identical batch; then succeeds."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        await publisher.publish([_message(0), _message(1)])
        batch = await consumer.poll(5)
        log.fail_next_commit()
        with pytest.raises(EvidenceCommitError):
            await consumer.commit(batch)
        redelivered = await consumer.poll(5)
        assert redelivered == batch
        await consumer.commit(redelivered)
        assert (await consumer.poll(5)).records == ()

    @pytest.mark.asyncio
    async def test_v04_independent_consumers(self) -> None:
        """D28D-V04: A commits 0,1 while B still sees 0,1; A continues at 2."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        await publisher.publish([_message(0), _message(1), _message(2)])
        consumer_a = log.consumer(_ID_A)
        consumer_b = log.consumer(_ID_B)
        await consumer_a.commit(await consumer_a.poll(2))
        batch_b = await consumer_b.poll(2)
        assert [record.position.offset for record in batch_b.records] == [0, 1]
        batch_a = await consumer_a.poll(5)
        assert [record.position.offset for record in batch_a.records] == [2]

    @pytest.mark.asyncio
    async def test_v05_pr28c_identity_survives_transport(self) -> None:
        """D28D-V05: message identity survives the log and the log position stays out.

        The polled record carries the exact published message; the log
        position never appears inside the message or its canonical wire;
        and the PR 28C codec round-trips the transported message exactly.
        """
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        consumer = log.consumer(_ID_A)
        message = _message(3)
        await publisher.publish([message])
        (record,) = (await consumer.poll(5)).records
        assert record.message == message
        assert record.message.message_id == message.message_id
        assert record.message.evidence_id == message.evidence_id
        assert (
            record.message.observation_candidate_id == message.observation_candidate_id
        )
        assert not hasattr(message, "position")
        decoded = decode_evidence_message(encode_evidence_message(record.message))
        assert decoded == record.message
        assert decoded.message_id == message.message_id
        wire = encode_evidence_message(record.message).decode("utf-8")
        assert '"position"' not in wire
        assert '"topic"' not in wire
