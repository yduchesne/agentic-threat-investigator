# SPDX-License-Identifier: AGPL-3.0-only
"""Application orchestration for resumable source-record ingestion."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import logging

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


LOGGER = logging.getLogger(__name__)


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


class IngestionService:  # pylint: disable=too-few-public-methods
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
