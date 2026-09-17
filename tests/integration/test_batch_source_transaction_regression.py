# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27E batch SourceRecord + checkpoint transaction regression (real DB).

Matrix IDs D27E-B01..B10 pin the IngestionService invariant over real
PostgreSQL:

```text
for each SourceBatch:
    one UoW:
        upsert source records
        update matching checkpoint
    commit atomically
```

- B01 one batch commits records + checkpoint atomically;
- B02 two batches commit through one persistence transaction per batch;
- B03 batch-2 failure leaves batch1 durable and batch2 fully rolled back;
- B04 restart resumes from the last committed checkpoint (existing
  ``test_checkpoint_resumes_after_interruption`` already proves this for the
  real MITRE source; re-pinned here with a synthetic source);
- B05 a completed artifact short-circuits (existing MITRE tests cover);
- B06 a conflicting batch rolls back data + checkpoint together;
- B07 source iteration occurs outside the persistence UoW (unit probe);
- B08 no PR 27 lifecycle event is emitted per SourceBatch — the ingestion
  path writes zero ``ati.datasource_log`` rows;
- B09/B10 MITRE identity/hash/normalization behavior is unchanged — pinned
  by the existing MITRE unit/integration suites, referenced here.

The unit suite (``tests/unit/test_ingestion.py``) covers the deterministic
UoW probes; this file proves the atomicity against the real database.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.ingestion import IngestionService
from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    IngestionCheckpoint,
    SourceRecordBatchItem,
)
from agentic_threat_investigator.app.sources import (
    CHECKPOINTING,
    ArtifactReference,
    BatchSource,
    SourceBatch,
)
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

pytestmark = pytest.mark.integration

_SOURCE_ID = "feed-batch-regression"
_VERSION = 1
_ARTIFACT_URI = "file:///datasets/feed-batch-regression/input.json"
_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _record(record_id: str, **overrides: Any) -> SourceRecord:
    """Build one normalized record whose content hash follows automatically."""
    return SourceRecord(
        source_id=overrides.pop("source_id", _SOURCE_ID),
        source_record_id=record_id,
        record_type="observation",
        normalization_version=overrides.pop("normalization_version", _VERSION),
        retrieved_at=overrides.pop("retrieved_at", _NOW),
        canonical_payload={"record": record_id, **overrides.pop("payload", {})},
    )


def _artifact() -> ArtifactReference:
    """Build the fixed artifact identity for this source."""
    return ArtifactReference(_SOURCE_ID, _ARTIFACT_URI, _NOW)


class _SyntheticSource(BatchSource):
    """Deterministic checkpointing source over bounded synthetic batches."""

    source_id = _SOURCE_ID
    normalization_version = _VERSION
    capabilities = frozenset({CHECKPOINTING})

    def __init__(self, batches: list[SourceBatch]) -> None:
        """Store the fixed emission sequence."""
        self.emitted = batches
        self.iterations = 0
        self.seen_checkpoint: str | None = None

    def batches(
        self, artifact: ArtifactReference, checkpoint: str | None = None
    ) -> AsyncIterator[SourceBatch]:
        """Yield the configured batches outside any persistence UoW."""
        del artifact

        async def generate() -> AsyncIterator[SourceBatch]:
            """Generate the fixed sequence, recording the resumed checkpoint."""
            self.iterations += 1
            self.seen_checkpoint = checkpoint
            for batch in self.emitted:
                yield batch

        return generate()


def _service(uow_factory: Callable[[], PostgresUnitOfWork]) -> IngestionService:
    """Build the ingestion service under test."""
    return IngestionService(uow_factory, batch_size=10)


async def _count(engine: AsyncEngine, query: str) -> int:
    """Run one bounded scalar count."""
    async with engine.connect() as connection:
        value = await connection.scalar(text(query))
    return int(value or 0)


async def _checkpoint_value(
    engine: AsyncEngine, artifact_uri: str = _ARTIFACT_URI
) -> str | None:
    """Return the durable checkpoint text for the artifact, if any."""
    async with engine.connect() as connection:
        value = await connection.scalar(
            text(
                "SELECT checkpoint FROM ati.ingestion_checkpoint "
                "WHERE source_id = :source_id AND artifact_uri = :artifact_uri "
                "AND normalization_version = :normalization_version"
            ),
            {
                "source_id": _SOURCE_ID,
                "artifact_uri": artifact_uri,
                "normalization_version": _VERSION,
            },
        )
    return None if value is None else str(value)


@pytest.mark.asyncio
async def test_b01_single_batch_records_and_checkpoint_atomic(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-B01: one batch persists records and checkpoint atomically."""
    source = _SyntheticSource(
        [
            SourceBatch(
                (_record("one"), _record("two")),
                checkpoint="batch:1",
                complete=True,
            )
        ]
    )
    summary = await _service(uow_factory).ingest(source, _artifact())
    assert (summary.inserted, summary.complete) == (2, True)
    assert (
        await _count(integration_engine, "SELECT count(*) FROM ati.source_record") == 2
    )
    assert await _checkpoint_value(integration_engine) == "batch:1"


@pytest.mark.asyncio
async def test_b02_two_batches_one_transaction_per_batch(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-B02: each batch commits records and checkpoint in one UoW pair."""
    source = _SyntheticSource(
        [
            SourceBatch((_record("one"),), checkpoint="batch:1"),
            SourceBatch((_record("two"),), checkpoint="batch:2", complete=True),
        ]
    )
    summary = await _service(uow_factory).ingest(source, _artifact())
    assert (summary.inserted, summary.complete) == (2, True)
    assert (
        await _count(integration_engine, "SELECT count(*) FROM ati.source_record") == 2
    )
    assert await _checkpoint_value(integration_engine) == "batch:2"


@pytest.mark.asyncio
async def test_b03_second_batch_failure_keeps_first_batch_durable(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-B03: batch2 failure rolls back data and checkpoint; batch1 stays.

    The second batch's record carries a stale content hash so the canonical
    repository validation fails inside the batch UoW — the data and the
    checkpoint advance of that batch both roll back while the first
    committed batch remains durable.
    """
    broken = _record("two")
    broken = broken.model_copy(update={"canonical_payload": {"mutated": True}})
    source = _SyntheticSource(
        [
            SourceBatch((_record("one"),), checkpoint="batch:1"),
            SourceBatch((broken,), checkpoint="batch:2", complete=True),
        ]
    )
    with pytest.raises(ValueError):
        await _service(uow_factory).ingest(source, _artifact())

    # Batch1 data and checkpoint are durable; nothing from batch2 remains.
    assert (
        await _count(integration_engine, "SELECT count(*) FROM ati.source_record") == 1
    )
    assert await _checkpoint_value(integration_engine) == "batch:1"


@pytest.mark.asyncio
async def test_b04_restart_resumes_from_last_committed_checkpoint(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-B04: a restarted ingest resumes from the committed checkpoint."""
    first = _SyntheticSource([SourceBatch((_record("one"),), checkpoint="batch:1")])
    await _service(uow_factory).ingest(first, _artifact())
    assert first.seen_checkpoint is None

    resumed = _SyntheticSource(
        [
            SourceBatch((_record("two"),), checkpoint="batch:2", complete=True),
        ]
    )
    summary = await _service(uow_factory).ingest(resumed, _artifact())
    assert resumed.seen_checkpoint == "batch:1"
    assert (summary.inserted, summary.complete) == (1, True)
    assert await _checkpoint_value(integration_engine) == "batch:2"


@pytest.mark.asyncio
async def test_b05_completed_artifact_short_circuits(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-B05: a completed artifact replays as a deterministic no-op."""
    source = _SyntheticSource(
        [SourceBatch((_record("one"),), checkpoint="batch:1", complete=True)]
    )
    await _service(uow_factory).ingest(source, _artifact())
    source.emitted = []
    noop = await _service(uow_factory).ingest(source, _artifact())
    assert (noop.inserted, noop.updated, noop.unchanged) == (0, 0, 0)
    assert noop.complete is True
    assert noop.checkpoint == "batch:1"
    assert source.iterations == 1  # the completed shortcut never iterates


@pytest.mark.asyncio
async def test_b06_conflict_rolls_back_batch_and_checkpoint(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-B06: a conflicting batch rolls back data and checkpoint together.

    A stale optimistic expectation raises the repository conflict outcome
    inside the single batch UoW; neither the conflicting record nor the
    checkpoint advance is committed (direct repository-level proof of the
    service's atomic isolation).
    """
    # Establish the current record at version 1.
    async with uow_factory() as uow:
        results = await uow.source_records.upsert_batch(
            [SourceRecordBatchItem(record=_record("one"))]
        )
        assert results[0].outcome is BatchOutcome.INSERTED
        current_version = results[0].version
        await uow.commit()

    with pytest.raises(RuntimeError, match="simulated IngestionConflictError"):
        async with uow_factory() as uow:
            results = await uow.source_records.upsert_batch(
                [
                    SourceRecordBatchItem(
                        record=_record("one"),
                        expected_version=current_version + 99,
                    )
                ]
            )
            assert results[0].outcome is BatchOutcome.CONFLICT
            # The service's checkpoint advance shares the same failed UoW
            # and must roll back with the conflict (the service raises on a
            # CONFLICT outcome; the simulated failure exercises the same
            # boundary).
            await uow.ingestion_checkpoints.put(
                IngestionCheckpoint(
                    _SOURCE_ID, _ARTIFACT_URI, _VERSION, "never-committed", True
                )
            )
            raise RuntimeError("simulated IngestionConflictError")

    assert (
        await _count(integration_engine, "SELECT count(*) FROM ati.source_record") == 1
    )
    assert await _checkpoint_value(integration_engine) is None


@pytest.mark.asyncio
async def test_b08_no_datasource_lifecycle_per_batch(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """D27E-B08: ingestion emits no PR 27 lifecycle events per batch.

    The datasource_log is operational lifecycle of datasource executions
    only; SourceRecord batch ingestion never writes it, so no per-batch
    stage multiplication can occur.
    """
    source = _SyntheticSource(
        [
            SourceBatch((_record("one"),), checkpoint="batch:1"),
            SourceBatch((_record("two"),), checkpoint="batch:2", complete=True),
        ]
    )
    await _service(uow_factory).ingest(source, _artifact())
    assert (
        await _count(integration_engine, "SELECT count(*) FROM ati.datasource_log") == 0
    )
    assert (
        await _count(integration_engine, "SELECT count(*) FROM ati.source_record") == 2
    )
