# SPDX-License-Identifier: AGPL-3.0-only
"""Datasource acquisition/conversion telemetry tests (PR 29B, DS1..DS7).

Proves the shared ``observe_semantic_acquisition`` seam and the
``convert_semantic_source_objects`` instrumentation: one logical acquisition
span/duration, one conversion span/duration with converted-item counts,
bounded failures, cancellation propagation, and no double-counted broker
publication telemetry on the producer path.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from opentelemetry.sdk.metrics.export import Metric

from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    DatasourceStageError,
    SemanticAcquisitionResult,
)
from agentic_threat_investigator.app.evidence_conversion import (
    ToEvidenceConverterRegistry,
    UnknownSemanticFormatError,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
)
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.otel import (
    counter_value,
    histogram_count,
    histogram_sum,
    metrics_by_name,
)
from tests.unit.app.test_datasource_evidence_producer import (
    _DOMAIN_ENTITY,
    _FakeAcquirer,
    _FixedCountConverter,
    _ProbePublisher,
    _producer,
    _semantic_context,
    _State,
    _threatfox_records,
)


def _recorded(telemetry: SimpleNamespace) -> dict[str, Metric]:
    """Return recorded metrics indexed by name."""
    return metrics_by_name(telemetry.reader)


def _spans(telemetry: SimpleNamespace) -> list[object]:
    """Return finished span names from the in-memory exporter."""
    return [span.name for span in telemetry.exporter.get_finished_spans()]


class TestAcquisitionTelemetry:
    """DS1..DS3: one logical semantic acquisition is observable."""

    @pytest.mark.asyncio
    async def test_ds1_acquisition_success(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A successful acquisition emits one acquire span and duration (DS1)."""
        state = _State()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state, _ProbePublisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        await producer.produce(_DOMAIN_ENTITY)
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.datasource.acquire") == 1
        recorded = _recorded(in_memory_persistence_telemetry)
        duration = recorded[DurationMetrics.DATASOURCE_ACQUIRE]
        assert histogram_count(duration) == 1
        assert Metrics.DATASOURCE_ACQUIRE_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_ds2_typed_acquisition_failure_is_bounded(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A typed stage error counts a failure and keeps the typed result (DS2)."""

        def _error() -> SemanticAcquisitionResult[ThreatFoxRecord]:
            return SemanticAcquisitionResult(
                context=_semantic_context(),
                error=DatasourceStageError(
                    stage=DatasourceStage.ACQUISITION,
                    code="timeout",
                    retryable=True,
                ),
            )

        state = _State()
        producer = _producer(state, _ProbePublisher(), acquirer=_FakeAcquirer(_error))
        outcome = await producer.produce(_DOMAIN_ENTITY)
        assert outcome.error_code == "timeout"
        assert outcome.outcome.value == "failed"
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.DATASOURCE_ACQUIRE_FAILURES]) == 1
        duration = recorded[DurationMetrics.DATASOURCE_ACQUIRE]
        assert histogram_count(duration) == 1

    @pytest.mark.asyncio
    async def test_ds3_acquisition_cancellation_propagates(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Cancellation propagates unchanged with no failure telemetry (DS3)."""

        async def _cancel() -> SemanticAcquisitionResult[ThreatFoxRecord]:
            raise asyncio.CancelledError()

        state = _State()
        producer = _producer(state, _ProbePublisher(), acquirer=_FakeAcquirer(_cancel))
        with pytest.raises(asyncio.CancelledError):
            await producer.produce(_DOMAIN_ENTITY)
        recorded = _recorded(in_memory_persistence_telemetry)
        assert Metrics.DATASOURCE_ACQUIRE_FAILURES not in recorded
        assert DurationMetrics.DATASOURCE_ACQUIRE not in recorded


class TestConversionTelemetry:
    """DS4..DS6: conversion is observable with exact item counts."""

    @pytest.mark.asyncio
    async def test_ds4_conversion_count_n(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Two objects x two items each records an item count of four (DS4)."""
        state = _State()
        result = SemanticAcquisitionResult(
            context=_semantic_context(),
            objects=_threatfox_records("864201", "864202"),
        )
        registry = ToEvidenceConverterRegistry(
            converters=(_FixedCountConverter(count=2),)
        )
        producer = _producer(
            state,
            _ProbePublisher(),
            acquirer=_FakeAcquirer(lambda: result),
            registry=registry,
        )
        await producer.produce(_DOMAIN_ENTITY)
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.datasource.convert") == 1
        recorded = _recorded(in_memory_persistence_telemetry)
        items = recorded[DurationMetrics.DATASOURCE_CONVERT_ITEMS]
        assert histogram_count(items) == 1
        # One sample whose summed value equals the flattened count.
        assert histogram_sum(items) == 4.0

    @pytest.mark.asyncio
    async def test_ds5_conversion_zero_is_success_count_zero(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Zero converted output is a success with a recorded count of zero (DS5)."""
        state = _State()
        result: SemanticAcquisitionResult[ThreatFoxRecord] = SemanticAcquisitionResult(
            context=_semantic_context(),
            objects=(),
        )
        producer = _producer(
            state, _ProbePublisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        outcome = await producer.produce(_DOMAIN_ENTITY)
        assert outcome.published_count == 0
        recorded = _recorded(in_memory_persistence_telemetry)
        items = recorded[DurationMetrics.DATASOURCE_CONVERT_ITEMS]
        assert histogram_sum(items) == 0.0
        assert Metrics.DATASOURCE_CONVERT_FAILURES not in recorded
        duration = recorded[DurationMetrics.DATASOURCE_CONVERT]
        assert histogram_count(duration) == 1

    @pytest.mark.asyncio
    async def test_ds6_conversion_exception_keeps_lifecycle(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A conversion violation counts a failure and preserves the typed flow (DS6)."""
        state = _State()
        # An unknown semantic format forces the registry lookup to fail inside
        # the conversion boundary with a typed error.
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        registry = ToEvidenceConverterRegistry(converters=())
        producer = _producer(
            state,
            _ProbePublisher(),
            acquirer=_FakeAcquirer(lambda: result),
            registry=registry,
        )
        with pytest.raises(UnknownSemanticFormatError):
            await producer.produce(_DOMAIN_ENTITY)
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.DATASOURCE_CONVERT_FAILURES]) == 1
        # The durable lifecycle got a bounded FAILED conversion event, exactly
        # as before telemetry (the lifecycle is never created by telemetry).
        assert state.types[-1] == "failed"


class TestProducerNoDoubleCount:
    """DS7: the producer path never duplicates broker publication telemetry."""

    @pytest.mark.asyncio
    async def test_ds7_no_duplicate_kafka_published_count(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A successful producer run does not fabricate Kafka publish counters (DS7)."""
        state = _State()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state, _ProbePublisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        await producer.produce(_DOMAIN_ENTITY)
        recorded = _recorded(in_memory_persistence_telemetry)
        assert Metrics.KAFKA_MESSAGES_PUBLISHED not in recorded
        assert Metrics.KAFKA_PUBLISH_FAILURES not in recorded
