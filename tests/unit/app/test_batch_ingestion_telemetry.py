# SPDX-License-Identifier: AGPL-3.0-only
"""Batch-ingestion observability tests (PR 38-9, BI1..BI10).

Proves ``IngestionService.ingest`` is the batch-ingestion instrumentation
seam: one logical span and duration sample per call, execution/failure/no-op
counters, committed source-record outcomes only, truthful partial-success
telemetry, a bounded source label, cancellation propagation, and no
Kafka/Evidence counter pollution.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from opentelemetry.sdk.metrics.export import Metric

from agentic_threat_investigator.app.ingestion import bounded_source_label
from agentic_threat_investigator.app.persistence import BatchOutcome
from agentic_threat_investigator.app.sources import SourceBatch
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.otel import (
    counter_value,
    histogram_count,
    metric_data_points,
    metrics_by_name,
)
from tests.unit.test_ingestion import (
    _artifact,
    _record,
    _service,
    _Source,
    _State,
)


def _recorded(telemetry: SimpleNamespace) -> dict[str, Metric]:
    """Return recorded metrics indexed by name."""
    return metrics_by_name(telemetry.reader)


def _spans(telemetry: SimpleNamespace) -> list[object]:
    """Return finished span names from the in-memory exporter."""
    return [span.name for span in telemetry.exporter.get_finished_spans()]


def test_bounded_source_mapper_is_finite() -> None:
    """Known sources map to stable labels and unknown sources collapse (BI10)."""
    assert bounded_source_label(SourceId.MITRE_ATTACK.value) == "mitre_attack"
    assert bounded_source_label("urn:ati:source:not_real") == "other"
    assert bounded_source_label("") == "other"


class TestBatchIngestionTelemetry:
    """BI1..BI9: batch ingestion observability behavior."""

    @pytest.mark.asyncio
    async def test_bi1_success_emits_executions_span_and_outcomes(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A successful ingest emits one span, executions, and outcomes (BI1)."""
        state = _State(
            outcome_batches=[
                [BatchOutcome.INSERTED, BatchOutcome.UNCHANGED],
                [BatchOutcome.UPDATED],
            ]
        )
        source = _Source(
            [
                SourceBatch((_record("one"), _record("two")), checkpoint="1"),
                SourceBatch((_record("three"),), checkpoint="2", complete=True),
            ],
            state,
        )
        await _service(state).ingest(source, _artifact())
        assert _spans(in_memory_persistence_telemetry) == ["ati.batch_ingestion.ingest"]
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.BATCH_INGESTION_EXECUTIONS]) == 1
        assert Metrics.BATCH_INGESTION_FAILURES not in recorded
        assert counter_value(recorded[Metrics.BATCH_INGESTION_RECORDS_INSERTED]) == 1
        assert counter_value(recorded[Metrics.BATCH_INGESTION_RECORDS_UPDATED]) == 1
        assert counter_value(recorded[Metrics.BATCH_INGESTION_RECORDS_UNCHANGED]) == 1
        assert histogram_count(recorded[DurationMetrics.BATCH_INGESTION]) == 1

    @pytest.mark.asyncio
    async def test_bi2_completed_checkpoint_is_noop(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A completed checkpoint counts noop and a zero workload (BI2)."""
        state = _State()
        artifact = _artifact()
        key = ("feed-a", artifact.uri, 1)
        from agentic_threat_investigator.app.persistence import IngestionCheckpoint

        state.checkpoints[key] = IngestionCheckpoint(*key, "done", True)
        source = _Source([], state)
        await _service(state).ingest(source, artifact)
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.BATCH_INGESTION_EXECUTIONS]) == 1
        assert counter_value(recorded[Metrics.BATCH_INGESTION_NOOP]) == 1
        assert histogram_count(recorded[DurationMetrics.BATCH_INGESTION_RECORDS]) == 1
        assert source.seen_artifact is None

    @pytest.mark.asyncio
    async def test_bi3_failure_counts_failure_and_preserves_committed_outcomes(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A later batch failure preserves committed outcomes (BI3)."""
        state = _State(outcome_batches=[[BatchOutcome.INSERTED]])
        source = _Source(
            [SourceBatch((_record("one"),), checkpoint="safe")],
            state,
            failure=RuntimeError("parse failed"),
        )
        with pytest.raises(RuntimeError, match="parse failed"):
            await _service(state).ingest(source, _artifact())
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.BATCH_INGESTION_EXECUTIONS]) == 1
        assert counter_value(recorded[Metrics.BATCH_INGESTION_FAILURES]) == 1
        assert counter_value(recorded[Metrics.BATCH_INGESTION_RECORDS_INSERTED]) == 1
        assert histogram_count(recorded[DurationMetrics.BATCH_INGESTION]) == 1

    @pytest.mark.asyncio
    async def test_bi4_repeated_idempotent_run_reports_unchanged(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Repeated unchanged outcomes are success, not no-op (BI4)."""
        state = _State(outcome_batches=[[BatchOutcome.UNCHANGED]])
        source = _Source(
            [SourceBatch((_record("one"),), checkpoint="done", complete=True)], state
        )
        await _service(state).ingest(source, _artifact())
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.BATCH_INGESTION_RECORDS_UNCHANGED]) == 1
        assert Metrics.BATCH_INGESTION_NOOP not in recorded

    @pytest.mark.asyncio
    async def test_bi5_cancellation_propagates_without_telemetry(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Cancellation propagates with no failure/execution counters (BI5)."""
        state = _State(outcome_batches=[[BatchOutcome.INSERTED]])
        source = _Source(
            [SourceBatch((_record("one"),), checkpoint="safe")],
            state,
            failure=asyncio.CancelledError(),
        )
        with pytest.raises(asyncio.CancelledError):
            await _service(state).ingest(source, _artifact())
        recorded = _recorded(in_memory_persistence_telemetry)
        assert Metrics.BATCH_INGESTION_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_bi6_span_carries_only_bounded_source(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """The span carries only the bounded source label, never the URN (BI6)."""
        state = _State(outcome_batches=[[BatchOutcome.INSERTED]])
        mitre = SourceId.MITRE_ATTACK.value
        source = _Source(
            [
                SourceBatch(
                    (_record("one", source_id=mitre),),
                    checkpoint="done",
                    complete=True,
                )
            ],
            state,
        )
        source.source_id = mitre
        await _service(state).ingest(source, _artifact(mitre))
        spans = in_memory_persistence_telemetry.exporter.get_finished_spans()
        assert len(spans) == 1
        attributes = dict(spans[0].attributes or {})
        assert attributes == {"ati.source": "mitre_attack"}

    @pytest.mark.asyncio
    async def test_bi7_record_outcomes_are_incremented_once_per_batch(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Outcome counters aggregate every committed batch exactly once (BI7)."""
        state = _State(
            outcome_batches=[
                [BatchOutcome.INSERTED, BatchOutcome.INSERTED],
                [BatchOutcome.INSERTED],
            ]
        )
        source = _Source(
            [
                SourceBatch((_record("one"), _record("two")), checkpoint="1"),
                SourceBatch((_record("three"),), checkpoint="2", complete=True),
            ],
            state,
        )
        await _service(state).ingest(source, _artifact())
        recorded = _recorded(in_memory_persistence_telemetry)
        metric = recorded[Metrics.BATCH_INGESTION_RECORDS_INSERTED]
        assert counter_value(metric) == 3
        assert len(metric_data_points(metric)) == 1

    @pytest.mark.asyncio
    async def test_bi8_no_kafka_or_evidence_outcome_pollution(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Batch ingestion never emits Kafka/Evidence metrics (BI8)."""
        state = _State(outcome_batches=[[BatchOutcome.INSERTED]])
        source = _Source(
            [SourceBatch((_record("one"),), checkpoint="done", complete=True)], state
        )
        await _service(state).ingest(source, _artifact())
        recorded = _recorded(in_memory_persistence_telemetry)
        forbidden = {
            Metrics.KAFKA_MESSAGES_PUBLISHED,
            Metrics.EVIDENCE_MESSAGES_PROCESSED,
            Metrics.EVIDENCE_OUTCOMES_CREATED,
            Metrics.EVIDENCE_OUTCOMES_APPENDED,
            Metrics.EVIDENCE_OUTCOMES_UNCHANGED,
        }
        assert forbidden.isdisjoint(recorded)

    @pytest.mark.asyncio
    async def test_bi9_disabled_telemetry_does_not_alter_behavior(self) -> None:
        """With no telemetry configured, ingestion behavior is unchanged (BI9)."""
        state = _State(outcome_batches=[[BatchOutcome.INSERTED]])
        source = _Source(
            [SourceBatch((_record("one"),), checkpoint="done", complete=True)], state
        )
        summary = await _service(state).ingest(source, _artifact())
        assert summary.inserted == 1
        assert summary.complete is True
