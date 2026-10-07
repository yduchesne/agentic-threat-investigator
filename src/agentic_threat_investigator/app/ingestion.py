# SPDX-License-Identifier: AGPL-3.0-only
"""Application orchestration for resumable source-record ingestion."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from opentelemetry.metrics import Counter
from opentelemetry.trace import Status, StatusCode

from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    BatchSizeLimitExceededError,
    IngestionCheckpoint,
    SourceRecordBatchItem,
    SourceRecordBatchResult,
    UnitOfWork,
)
from agentic_threat_investigator.app.sources import (
    CHECKPOINTING,
    ArtifactReference,
    BatchSource,
    SourceBatch,
    SourceCapability,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.telemetry.attributes import (
    AttributeKeys,
    validate_bounded_attributes,
)
from agentic_threat_investigator.telemetry.metrics import (
    DURATION_UNIT,
    DurationMetrics,
    Metrics,
    get_counter,
    get_histogram,
)
from agentic_threat_investigator.telemetry.tracing import SpanNames, get_tracer

LOGGER = logging.getLogger(__name__)

#: Bounded workload-size histogram unit for batch ingestion (``{item}``).
BATCH_ITEM_UNIT = "{item}"

#: Explicit finite mapper from a source identity to a bounded telemetry label.
#: Unknown sources collapse to ``other`` so arbitrary URNs can never become
#: metric dimensions.
_BOUNDED_SOURCE_LABELS: dict[str, str] = {
    SourceId.MITRE_ATTACK.value: "mitre_attack",
    SourceId.CISA_KEV.value: "cisa_kev",
    SourceId.MISP.value: "misp",
    SourceId.OPENCTI.value: "opencti",
    SourceId.IPINFO_LITE.value: "ipinfo_lite",
    SourceId.RDAP.value: "rdap",
    SourceId.GOOGLE_PUBLIC_DNS.value: "google_public_dns",
    SourceId.DBIP_CITY_LITE.value: "dbip_city_lite",
    SourceId.ABUSEIPDB.value: "abuseipdb",
    SourceId.THREATFOX.value: "threatfox",
    SourceId.URLHAUS.value: "urlhaus",
}


def bounded_source_label(source_id: str) -> str:
    """Map a source identity to a bounded telemetry label (unknown -> other)."""
    return _BOUNDED_SOURCE_LABELS.get(source_id, "other")


class IngestionConflictError(RuntimeError):
    """Raised when the database rejects a record batch conflict."""


IngestionRecordResult = SourceRecordBatchResult


@dataclass(frozen=True)
class IngestionSummary:
    """Deterministic aggregate for one artifact ingestion run."""

    inserted: int
    updated: int
    unchanged: int
    checkpoint: str | None
    complete: bool
    results: tuple[IngestionRecordResult, ...]
    changed: tuple[IngestionRecordResult, ...]


class IngestionService:
    """Coordinate source normalization and short atomic persistence transactions."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork], batch_size: int) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        self._uow_factory = uow_factory
        self._batch_size = batch_size

    async def ingest(
        self,
        source: BatchSource,
        artifact: ArtifactReference,
        *,
        restart: bool = False,
    ) -> IngestionSummary:
        """Ingest an artifact and emit one logical batch-ingestion observation.

        One call produces exactly one ``ati.batch_ingestion.ingest`` span and
        one duration sample. Record-outcome counters are incremented only from
        authoritative committed batch results: a completed checkpoint reports
        a successful no-op, and an early committed batch followed by a later
        failure still preserves the committed outcomes while reporting the
        overall execution failure.
        """
        source_label = bounded_source_label(source.source_id)
        attributes = validate_bounded_attributes({AttributeKeys.SOURCE: source_label})
        executions = get_counter(Metrics.BATCH_INGESTION_EXECUTIONS)
        failures = get_counter(Metrics.BATCH_INGESTION_FAILURES)
        noop = get_counter(Metrics.BATCH_INGESTION_NOOP)
        inserted = get_counter(Metrics.BATCH_INGESTION_RECORDS_INSERTED)
        updated = get_counter(Metrics.BATCH_INGESTION_RECORDS_UPDATED)
        unchanged = get_counter(Metrics.BATCH_INGESTION_RECORDS_UNCHANGED)
        duration = get_histogram(DurationMetrics.BATCH_INGESTION, unit=DURATION_UNIT)
        workload = get_histogram(
            DurationMetrics.BATCH_INGESTION_RECORDS, unit=BATCH_ITEM_UNIT
        )
        committed: list[SourceRecordBatchResult] = []
        start = time.perf_counter()
        with get_tracer().start_as_current_span(
            SpanNames.BATCH_INGESTION_INGEST, attributes=attributes
        ) as span:
            try:
                summary = await self._run(
                    source, artifact, restart=restart, committed=committed
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                self._record_outcomes(
                    committed, inserted, updated, unchanged, attributes
                )
                executions.add(1, attributes)
                failures.add(1, attributes)
                duration.record(
                    time.perf_counter() - start,
                    attributes={**attributes, AttributeKeys.OUTCOME: "error"},
                )
                workload.record(len(committed), attributes)
                raise
            executions.add(1, attributes)
            if summary.complete and not summary.results:
                noop.add(1, attributes)
                workload.record(0, attributes)
                duration.record(
                    time.perf_counter() - start,
                    attributes={**attributes, AttributeKeys.OUTCOME: "noop"},
                )
            else:
                self._record_outcomes(
                    list(summary.results), inserted, updated, unchanged, attributes
                )
                workload.record(len(summary.results), attributes)
                duration.record(
                    time.perf_counter() - start,
                    attributes={**attributes, AttributeKeys.OUTCOME: "success"},
                )
            return summary

    @staticmethod
    def _record_outcomes(
        results: list[SourceRecordBatchResult],
        inserted: Counter,
        updated: Counter,
        unchanged: Counter,
        attributes: dict[str, str],
    ) -> None:
        """Increment committed source-record outcome counters once."""
        inserted_count = sum(
            result.outcome is BatchOutcome.INSERTED for result in results
        )
        updated_count = sum(
            result.outcome is BatchOutcome.UPDATED for result in results
        )
        unchanged_count = sum(
            result.outcome is BatchOutcome.UNCHANGED for result in results
        )
        if inserted_count:
            inserted.add(inserted_count, attributes)
        if updated_count:
            updated.add(updated_count, attributes)
        if unchanged_count:
            unchanged.add(unchanged_count, attributes)

    async def _run(
        self,
        source: BatchSource,
        artifact: ArtifactReference,
        *,
        restart: bool,
        committed: list[SourceRecordBatchResult],
    ) -> IngestionSummary:
        """Ingest an artifact, committing each source batch with its checkpoint."""
        self._validate_source_artifact(source, artifact)
        async with self._uow_factory() as uow:
            prior = await uow.ingestion_checkpoints.get(
                source.source_id, artifact.uri, source.normalization_version
            )
        if restart:
            prior = None
            async with self._uow_factory() as uow:
                await uow.ingestion_checkpoints.reset(
                    source.source_id, artifact.uri, source.normalization_version
                )
        if prior is not None and prior.complete:
            return IngestionSummary(0, 0, 0, prior.checkpoint, True, (), ())
        if (
            prior is not None
            and prior.checkpoint is not None
            and CHECKPOINTING not in source.capabilities
        ):
            raise ValueError("stored checkpoint belongs to a non-checkpointing source")

        checkpoint = None if prior is None else prior.checkpoint
        all_results: list[IngestionRecordResult] = []
        complete = False
        batch_number = 0
        async for batch in source.batches(artifact, checkpoint):
            batch_number += 1
            if complete:
                raise ValueError("source emitted batches after completion")
            self._validate_batch(source, artifact, batch)
            if len(batch.records) > self._batch_size:
                raise BatchSizeLimitExceededError(
                    "source batch exceeds configured batch size"
                )
            async with self._uow_factory() as uow:
                results = await uow.source_records.upsert_batch(
                    [SourceRecordBatchItem(record=record) for record in batch.records]
                )
                if any(result.outcome is BatchOutcome.CONFLICT for result in results):
                    raise IngestionConflictError(
                        "source-record batch contains a conflict"
                    )
                expected_ordinals = set(range(1, len(batch.records) + 1))
                if {result.ordinal for result in results} != expected_ordinals:
                    raise ValueError("repository returned invalid batch ordinals")
                mapped = [
                    SourceRecordBatchResult(
                        r.ordinal, r.record_id, r.version, r.outcome
                    )
                    for r in results
                ]
                await uow.ingestion_checkpoints.put(
                    IngestionCheckpoint(
                        source.source_id,
                        artifact.uri,
                        source.normalization_version,
                        batch.checkpoint,
                        batch.complete,
                    )
                )
            all_results.extend(mapped)
            committed.extend(mapped)
            checkpoint, complete = batch.checkpoint, batch.complete
            LOGGER.info(
                "source ingestion batch committed",
                extra={
                    "source_id": source.source_id,
                    "artifact_uri": artifact.uri,
                    "batch_number": batch_number,
                    "record_count": len(mapped),
                    "inserted": sum(
                        result.outcome is BatchOutcome.INSERTED for result in mapped
                    ),
                    "updated": sum(
                        result.outcome is BatchOutcome.UPDATED for result in mapped
                    ),
                    "unchanged": sum(
                        result.outcome is BatchOutcome.UNCHANGED for result in mapped
                    ),
                },
            )

        changed = tuple(
            result
            for result in all_results
            if result.outcome in (BatchOutcome.INSERTED, BatchOutcome.UPDATED)
        )
        return IngestionSummary(
            sum(r.outcome is BatchOutcome.INSERTED for r in all_results),
            sum(r.outcome is BatchOutcome.UPDATED for r in all_results),
            sum(r.outcome is BatchOutcome.UNCHANGED for r in all_results),
            checkpoint,
            complete,
            tuple(all_results),
            changed,
        )

    @staticmethod
    def _validate_source_artifact(
        source: BatchSource, artifact: ArtifactReference
    ) -> None:
        """Validate stable identity before opening source iteration."""
        if source.source_id != artifact.source_id:
            raise ValueError("source and artifact source_id do not match")
        if (
            not isinstance(source.normalization_version, int)
            or source.normalization_version < 1
        ):
            raise ValueError("source normalization_version must be positive")
        if not isinstance(source.capabilities, frozenset) or not all(
            isinstance(capability, SourceCapability)
            for capability in source.capabilities
        ):
            raise ValueError("source capabilities must be an immutable typed set")

    @staticmethod
    def _validate_batch(
        source: BatchSource, artifact: ArtifactReference, batch: SourceBatch
    ) -> None:
        """Validate every emitted batch at the application boundary."""
        if batch.records[0].source_id != source.source_id:
            raise ValueError("batch record source_id does not match source")
        if batch.normalization_version != source.normalization_version:
            raise ValueError("batch normalization version does not match source")
        if CHECKPOINTING not in source.capabilities and batch.checkpoint is not None:
            raise ValueError("non-checkpointing source emitted a checkpoint")
        if (
            CHECKPOINTING in source.capabilities
            and batch.checkpoint is None
            and not batch.complete
        ):
            raise ValueError("checkpointing source must provide checkpoint progress")
        for record in batch.records:
            if (
                record.source_id != artifact.source_id
                or record.normalization_version != source.normalization_version
            ):
                raise ValueError("emitted record identity does not match ingestion")
