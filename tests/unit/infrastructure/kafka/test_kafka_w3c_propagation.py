# SPDX-License-Identifier: AGPL-3.0-only
"""Kafka W3C trace-context propagation tests (PR 29B, P1..P6).

Proves the producer injects W3C ``traceparent`` into Kafka record headers,
the consumer extracts it into the batch so downstream durable processing
becomes a child of the propagated context, malformed headers are safe,
unrelated headers and the Evidence payload/identity are unchanged, and a
publish without an active span works normally.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from opentelemetry import trace as otl_trace
from opentelemetry.context import attach, detach
from opentelemetry.trace.propagation.tracecontext import (
    TraceContextTextMapPropagator,
)

from agentic_threat_investigator.app.evidence_message import (
    encode_evidence_message,
)
from agentic_threat_investigator.telemetry.propagation import (
    extract_trace_context,
)
from tests.unit.infrastructure.kafka.test_kafka_evidence_log import (
    _message,
    _record,
)
from tests.unit.infrastructure.kafka.test_kafka_telemetry import (
    FakeConsumer,
    FakeProducer,
    _consumer,
    _publisher,
)

_TRACEPARENT = "traceparent"


def _span_trace_id(telemetry: SimpleNamespace, span_name: str) -> int:
    """Return the trace id of one finished span by name."""
    for span in telemetry.exporter.get_finished_spans():
        if span.name == span_name:
            trace_id = span.context.trace_id
            assert trace_id is not None
            return int(trace_id)
    raise AssertionError(f"no finished span named {span_name}")


class TestProducerPropagation:
    """P1/P4/P5/P6: publisher injects W3C headers without payload changes."""

    @pytest.mark.asyncio
    async def test_p1_active_trace_publish_injects_traceparent(
        self, in_memory_telemetry: SimpleNamespace
    ) -> None:
        """An active trace produces a traceparent header on the record (P1)."""
        fake = FakeProducer()
        publisher = await _publisher(fake)
        message = _message("prop-1")
        with in_memory_telemetry.tracer.start_as_current_span(
            "ati.evidence.publish"
        ) as span:
            result = await publisher.publish([message])
        assert len(result.records) == 1
        sent = fake.sends[0]
        headers = dict(sent["headers"] or [])
        assert _TRACEPARENT in headers
        context = extract_trace_context(sent["headers"] or [])
        propagated = otl_trace.get_current_span(context).get_span_context()
        assert propagated.is_valid
        assert propagated.trace_id == span.context.trace_id

    @pytest.mark.asyncio
    async def test_p4_p5_payload_and_key_unchanged(
        self, in_memory_telemetry: SimpleNamespace
    ) -> None:
        """Headers carry only propagation data; payload/key are unchanged (P4/P5)."""
        from agentic_threat_investigator.app.evidence_message import (
            decode_evidence_message,
        )

        fake = FakeProducer()
        publisher = await _publisher(fake)
        message = _message("prop-2")
        with in_memory_telemetry.tracer.start_as_current_span("ati.evidence.publish"):
            await publisher.publish([message])
        sent = fake.sends[0]
        # The canonical wire payload is byte-identical.
        assert sent["value"] == encode_evidence_message(message)
        assert decode_evidence_message(sent["value"]) == message
        headers = dict(sent["headers"] or [])
        # Only ATI-owned W3C headers are added at this adapter boundary.
        for key in headers:
            assert key.lower() in {"traceparent", "tracestate"}
        assert sent["key"] == str(message.evidence_id).encode("utf-8")

    @pytest.mark.asyncio
    async def test_p6_no_active_span_publish_works(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A publish without an outer span works normally (P6).

        The adapter always opens its own ``ati.kafka.publish`` span, so the
        injected traceparent carries that real span's trace identity rather
        than a fabricated random one; no outer trace is required and the
        publish never fails.
        """
        fake = FakeProducer()
        publisher = await _publisher(fake)
        result = await publisher.publish([_message("prop-3")])
        assert len(result.records) == 1
        sent = fake.sends[0]
        headers = dict(sent["headers"] or [])
        assert _TRACEPARENT in headers
        context = extract_trace_context(sent["headers"] or [])
        propagated = otl_trace.get_current_span(context).get_span_context()
        assert propagated.is_valid
        assert propagated.trace_id == _span_trace_id(
            in_memory_persistence_telemetry, "ati.kafka.publish"
        )


class TestConsumerPropagation:
    """P2/P3: the consumer extracts the propagated context into the batch."""

    @pytest.mark.asyncio
    async def test_p2_consume_header_parent_extracted(
        self, in_memory_telemetry: SimpleNamespace
    ) -> None:
        """A record traceparent becomes the batch parent context (P2)."""
        message = _message("prop-4")
        carrier: dict[str, str] = {}
        with in_memory_telemetry.tracer.start_as_current_span(
            "ati.evidence.publish"
        ) as span:
            TraceContextTextMapPropagator().inject(carrier)
            expected_trace_id = span.context.trace_id
        record = _record(message, partition=0, offset=0)
        headers = [
            ("content-type", b"application/json"),
            (_TRACEPARENT, carrier[_TRACEPARENT].encode("utf-8")),
        ]
        record_with_headers = type(record)(
            topic=record.topic,
            partition=record.partition,
            offset=record.offset,
            timestamp=record.timestamp,
            timestamp_type=record.timestamp_type,
            key=record.key,
            value=record.value,
            checksum=record.checksum,
            serialized_key_size=record.serialized_key_size,
            serialized_value_size=record.serialized_value_size,
            headers=headers,
        )
        fake = FakeConsumer()
        fake.fetched = {0: [record_with_headers]}
        consumer = await _consumer(fake)
        batch = await consumer.poll(10)
        assert batch.trace_context is not None
        extracted = otl_trace.get_current_span(batch.trace_context).get_span_context()
        assert extracted.is_valid
        assert extracted.trace_id == expected_trace_id

    @pytest.mark.asyncio
    async def test_p2b_downstream_processing_is_child_of_context(
        self, in_memory_telemetry: SimpleNamespace
    ) -> None:
        """Downstream work attached to the batch context is a child (P2)."""
        message = _message("prop-5")
        carrier: dict[str, str] = {}
        with in_memory_telemetry.tracer.start_as_current_span(
            "ati.evidence.publish"
        ) as span:
            TraceContextTextMapPropagator().inject(carrier)
            expected_trace_id = span.context.trace_id
        record = _record(message, partition=0, offset=0)
        record_with_headers = type(record)(
            topic=record.topic,
            partition=record.partition,
            offset=record.offset,
            timestamp=record.timestamp,
            timestamp_type=record.timestamp_type,
            key=record.key,
            value=record.value,
            checksum=record.checksum,
            serialized_key_size=record.serialized_key_size,
            serialized_value_size=record.serialized_value_size,
            headers=[(_TRACEPARENT, carrier[_TRACEPARENT].encode("utf-8"))],
        )
        fake = FakeConsumer()
        fake.fetched = {0: [record_with_headers]}
        consumer = await _consumer(fake)
        batch = await consumer.poll(10)
        assert batch.trace_context is not None
        token = attach(batch.trace_context)
        try:
            tracer = in_memory_telemetry.tracer
            with tracer.start_as_current_span("ati.evidence.persist"):
                pass
        finally:
            detach(token)
        assert _span_trace_id(in_memory_telemetry, "ati.evidence.persist") == (
            expected_trace_id
        )

    @pytest.mark.asyncio
    async def test_p3_malformed_header_safe(
        self, in_memory_telemetry: SimpleNamespace
    ) -> None:
        """A malformed traceparent header yields a safe no-parent batch (P3)."""
        message = _message("prop-6")
        record = _record(message, partition=0, offset=0)
        record_with_headers = type(record)(
            topic=record.topic,
            partition=record.partition,
            offset=record.offset,
            timestamp=record.timestamp,
            timestamp_type=record.timestamp_type,
            key=record.key,
            value=record.value,
            checksum=record.checksum,
            serialized_key_size=record.serialized_key_size,
            serialized_value_size=record.serialized_value_size,
            headers=[(_TRACEPARENT, b"00-not-a-valid-traceparent")],
        )
        fake = FakeConsumer()
        fake.fetched = {0: [record_with_headers]}
        consumer = await _consumer(fake)
        batch = await consumer.poll(10)
        assert len(batch.records) == 1
        # A malformed parent never blocks processing and yields no context.
        assert (
            batch.trace_context is None
            or not otl_trace.get_current_span(batch.trace_context)
            .get_span_context()
            .is_valid
        )


class TestInMemoryLogCompatibility:
    """The in-memory log remains propagation-free and unchanged."""

    @pytest.mark.asyncio
    async def test_in_memory_batch_has_no_trace_context(
        self, in_memory_telemetry: SimpleNamespace
    ) -> None:
        """In-memory log batches carry no propagated context (P2/P6 compat)."""
        from agentic_threat_investigator.app.evidence_log import (
            EvidenceConsumerId,
            InMemoryEvidenceLog,
        )

        log = InMemoryEvidenceLog()
        await log.publisher().publish([_message("prop-7")])
        consumer = log.consumer(EvidenceConsumerId("w3c-test"))
        batch = await consumer.poll(10)
        assert batch.trace_context is None
        assert len(batch.records) == 1
