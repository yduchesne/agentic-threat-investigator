# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for thin PostgreSQL source persistence adapters."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence import (
    BatchOutcome,
    BatchSizeLimitExceededError,
    IngestionCheckpoint,
    SourceRecordBatchItem,
)
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.infrastructure.persistence.postgresql.source_repositories import (
    PostgresIngestionCheckpointRepository,
    PostgresSourceRecordRepository,
)


def _record() -> SourceRecord:
    """Support the test record behavior."""
    return SourceRecord(
        source_id="feed-a",
        source_record_id="record-1",
        record_type="observation",
        normalization_version=1,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        retrieved_at=datetime(2026, 1, 2, tzinfo=UTC),
        canonical_payload={"nested": {"value": 1}},
        raw_payload={"raw": [1]},
        metadata={"transport": "file"},
    )


def _result(*, rows: list[object] | None = None, mapping: object = None) -> object:
    """Support the test result behavior."""
    return SimpleNamespace(
        fetchall=lambda: rows or [],
        mappings=lambda: SimpleNamespace(first=lambda: mapping),
    )


@pytest.mark.asyncio
async def test_source_record_batch_serializes_and_maps_results() -> None:
    """Verify source record batch serializes and maps results."""
    record_id = uuid4()
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=_result(rows=[(1, record_id, 7, BatchOutcome.INSERTED.value)])
        )
    )
    repository = PostgresSourceRecordRepository(
        cast(AsyncSession, session), batch_size=1
    )
    results = await repository.upsert_batch([SourceRecordBatchItem(_record())])
    assert results[0].record_id == record_id
    assert results[0].outcome is BatchOutcome.INSERTED
    parameters = session.execute.await_args.args[1]
    item = parameters["items"][0]
    assert item[0] == 1
    assert item[10] == bytes.fromhex(_record().content_hash)


@pytest.mark.asyncio
async def test_source_record_batch_enforces_limit_and_recomputes_hash() -> None:
    """Verify source record batch enforces limit and recomputes hash."""
    session = SimpleNamespace(execute=AsyncMock())
    repository = PostgresSourceRecordRepository(
        cast(AsyncSession, session), batch_size=0
    )
    with pytest.raises(BatchSizeLimitExceededError):
        await repository.upsert_batch([SourceRecordBatchItem(_record())])

    record = _record().model_copy(update={"content_hash": "0" * 64})
    repository = PostgresSourceRecordRepository(cast(AsyncSession, session))
    with pytest.raises(ValueError, match="content_hash"):
        await repository.upsert_batch([SourceRecordBatchItem(record)])
    session.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_source_record_identity_lookup_round_trips_domain_model() -> None:
    """Verify source record identity lookup round trips domain model."""
    record = _record()
    row = record.model_dump(mode="python")
    row["content_hash"] = bytes.fromhex(record.content_hash)
    session = SimpleNamespace(execute=AsyncMock(return_value=_result(mapping=row)))
    repository = PostgresSourceRecordRepository(cast(AsyncSession, session))
    assert await repository.get_by_identity("feed-a", "record-1") == record

    session.execute.return_value = _result(mapping=None)
    assert await repository.get_by_identity("feed-a", "missing") is None


@pytest.mark.asyncio
async def test_checkpoint_repository_get_put_and_reset() -> None:
    """Verify checkpoint repository get put and reset."""
    checkpoint = IngestionCheckpoint(
        "feed-a", "file:///datasets/feed-a/input.json", 1, "cursor", True
    )
    row = {
        "source_id": checkpoint.source_id,
        "artifact_uri": checkpoint.artifact_uri,
        "normalization_version": checkpoint.normalization_version,
        "checkpoint": checkpoint.checkpoint,
        "complete": checkpoint.complete,
    }
    session = SimpleNamespace(execute=AsyncMock(return_value=_result(mapping=row)))
    repository = PostgresIngestionCheckpointRepository(cast(AsyncSession, session))
    assert await repository.get("feed-a", checkpoint.artifact_uri, 1) == checkpoint
    await repository.put(checkpoint)
    await repository.reset("feed-a", checkpoint.artifact_uri, 1)
    assert session.execute.await_count == 3

    session.execute.return_value = _result(mapping=None)
    assert await repository.get("feed-a", checkpoint.artifact_uri, 1) is None
