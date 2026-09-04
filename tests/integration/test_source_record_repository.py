# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL integration tests for normalized source-record persistence."""

from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.persistence import (
    BatchOutcome,
    IngestionCheckpoint,
    SourceRecordBatchItem,
)
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)


def _record(
    value: str = "one", *, retrieved_day: int = 1, metadata: str = "first"
) -> SourceRecord:
    """Support the test record behavior."""
    source_id = "feed-a"
    return SourceRecord(
        source_id=source_id,
        source_record_id="record-1",
        record_type="observation",
        normalization_version=1,
        retrieved_at=datetime(2026, 1, retrieved_day, tzinfo=UTC),
        canonical_payload={"value": value},
        raw_payload={"transport": metadata},
        metadata={"transport": metadata},
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_insert_unchanged_update_and_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Verify insert unchanged update and history."""
    async with uow_factory() as uow:
        inserted = await uow.source_records.upsert_batch(
            [SourceRecordBatchItem(_record())]
        )
    assert inserted[0].outcome is BatchOutcome.INSERTED

    async with uow_factory() as uow:
        unchanged = await uow.source_records.upsert_batch(
            [SourceRecordBatchItem(_record(retrieved_day=2, metadata="second"))]
        )
        current = await uow.source_records.get_by_identity("feed-a", "record-1")
    assert unchanged[0].outcome is BatchOutcome.UNCHANGED
    assert unchanged[0].version == inserted[0].version
    assert current is not None and current.metadata["transport"] == "first"

    async with uow_factory() as uow:
        updated = await uow.source_records.upsert_batch(
            [SourceRecordBatchItem(_record("two"))]
        )
        assert uow.session is not None
        history_count = await uow.session.scalar(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type='source_record'"
            )
        )
    assert updated[0].outcome is BatchOutcome.UPDATED
    assert updated[0].version > inserted[0].version
    assert history_count == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_record_and_checkpoint_share_transaction(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Verify record and checkpoint share transaction."""
    checkpoint = IngestionCheckpoint(
        "feed-a", "file:///datasets/feed-a/input.json", 1, "cursor", False
    )
    with pytest.raises(RuntimeError, match="rollback"):
        async with uow_factory() as uow:
            await uow.source_records.upsert_batch([SourceRecordBatchItem(_record())])
            await uow.ingestion_checkpoints.put(checkpoint)
            raise RuntimeError("rollback")

    async with uow_factory() as uow:
        assert await uow.source_records.get_by_identity("feed-a", "record-1") is None
        assert (
            await uow.ingestion_checkpoints.get(
                checkpoint.source_id,
                checkpoint.artifact_uri,
                checkpoint.normalization_version,
            )
            is None
        )
