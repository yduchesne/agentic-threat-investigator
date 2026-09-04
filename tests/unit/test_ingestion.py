# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for resumable batch-ingestion orchestration."""

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import TracebackType
from typing import Self
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.ingestion import (
    IngestionConflictError,
    IngestionService,
)
from agentic_threat_investigator.app.persistence import (
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
)
from agentic_threat_investigator.domain.source import SourceRecord


@dataclass
class _State:
    """Test helper for State."""

    checkpoints: dict[tuple[str, str, int], IngestionCheckpoint] = field(
        default_factory=dict
    )
    outcome_batches: list[list[BatchOutcome]] = field(default_factory=list)
    active: int = 0
    commits: int = 0
    rollbacks: int = 0
    written_batches: list[tuple[SourceRecordBatchItem, ...]] = field(
        default_factory=list
    )


class _Records:  # pylint: disable=too-few-public-methods
    """Test helper for Records."""

    def __init__(self, state: _State) -> None:
        """Support the test init   behavior."""
        self.state = state

    async def upsert_batch(
        self, items: list[SourceRecordBatchItem]
    ) -> list[SourceRecordBatchResult]:
        """Support the test upsert batch behavior."""
        self.state.written_batches.append(tuple(items))
        outcomes = self.state.outcome_batches.pop(0)
        return [
            SourceRecordBatchResult(index, uuid4(), index, outcome)
            for index, outcome in enumerate(outcomes, 1)
        ]


class _Checkpoints:
    """Test helper for Checkpoints."""

    def __init__(self, state: _State) -> None:
        """Support the test init   behavior."""
        self.state = state
        self.pending_put: IngestionCheckpoint | None = None
        self.pending_reset: tuple[str, str, int] | None = None

    async def get(
        self, source_id: str, artifact_uri: str, normalization_version: int
    ) -> IngestionCheckpoint | None:
        """Support the test get behavior."""
        return self.state.checkpoints.get(
            (source_id, artifact_uri, normalization_version)
        )

    async def put(self, checkpoint: IngestionCheckpoint) -> None:
        """Support the test put behavior."""
        self.pending_put = checkpoint

    async def reset(
        self, source_id: str, artifact_uri: str, normalization_version: int
    ) -> None:
        """Support the test reset behavior."""
        self.pending_reset = (source_id, artifact_uri, normalization_version)

    def commit(self) -> None:
        """Support the test commit behavior."""
        if self.pending_reset is not None:
            self.state.checkpoints.pop(self.pending_reset, None)
        if self.pending_put is not None:
            value = self.pending_put
            self.state.checkpoints[
                (value.source_id, value.artifact_uri, value.normalization_version)
            ] = value


class _Uow(UnitOfWork):
    """Test helper for Uow."""

    def __init__(self, state: _State) -> None:
        """Support the test init   behavior."""
        self.state = state
        self.source_records = _Records(state)  # type: ignore[assignment]
        self._checkpoints = _Checkpoints(state)
        self.ingestion_checkpoints = self._checkpoints  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        """Support the test aenter   behavior."""
        assert self.state.active == 0
        self.state.active += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Support the test aexit   behavior."""
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()
        self.state.active -= 1

    async def commit(self) -> None:
        """Support the test commit behavior."""
        self._checkpoints.commit()
        self.state.commits += 1

    async def rollback(self) -> None:
        """Support the test rollback behavior."""
        self.state.rollbacks += 1


class _Source(  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    BatchSource
):
    """Test helper for Source."""

    source_id = "feed-a"
    normalization_version = 1
    capabilities = frozenset({CHECKPOINTING})

    def __init__(
        self,
        batches: list[SourceBatch],
        state: _State,
        *,
        failure: Exception | None = None,
    ) -> None:
        """Support the test init   behavior."""
        self.emitted = batches
        self.state = state
        self.failure = failure
        self.seen_artifact: ArtifactReference | None = None
        self.seen_checkpoint: str | None = None

    def batches(
        self, artifact: ArtifactReference, checkpoint: str | None = None
    ) -> AsyncIterator[SourceBatch]:
        """Support the test batches behavior."""

        async def generate() -> AsyncIterator[SourceBatch]:
            """Support the test generate behavior."""
            self.seen_artifact = artifact
            self.seen_checkpoint = checkpoint
            for batch in self.emitted:
                assert self.state.active == 0
                yield batch
            if self.failure is not None:
                raise self.failure

        return generate()


def _record(
    record_id: str, *, source_id: str = "feed-a", version: int = 1
) -> SourceRecord:
    """Support the test record behavior."""
    return SourceRecord(
        source_id=source_id,
        source_record_id=record_id,
        record_type="observation",
        normalization_version=version,
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        canonical_payload={"record": record_id},
    )


def _artifact(source_id: str = "feed-a") -> ArtifactReference:
    """Support the test artifact behavior."""
    return ArtifactReference(
        source_id, "file:///datasets/feed-a/input.json", datetime.now(UTC)
    )


def _service(state: _State, batch_size: int = 10) -> IngestionService:
    """Support the test service behavior."""
    return IngestionService(lambda: _Uow(state), batch_size)


@pytest.mark.asyncio
async def test_ingest_aggregates_outcomes_and_changed_results() -> None:
    """Verify ingest aggregates outcomes and changed results."""
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
    artifact = _artifact()
    summary = await _service(state).ingest(source, artifact)
    assert (summary.inserted, summary.updated, summary.unchanged) == (1, 1, 1)
    assert [result.outcome for result in summary.changed] == [
        BatchOutcome.INSERTED,
        BatchOutcome.UPDATED,
    ]
    assert summary.checkpoint == "2" and summary.complete
    assert source.seen_artifact is artifact and source.seen_checkpoint is None
    assert state.checkpoints[("feed-a", artifact.uri, 1)].complete
    assert len(state.written_batches) == 2


@pytest.mark.asyncio
async def test_resume_and_completed_artifact_noop() -> None:
    """Verify resume and completed artifact noop."""
    state = _State(outcome_batches=[[BatchOutcome.UNCHANGED]])
    artifact = _artifact()
    key = ("feed-a", artifact.uri, 1)
    state.checkpoints[key] = IngestionCheckpoint(*key, "prior", False)
    source = _Source(
        [SourceBatch((_record("one"),), checkpoint="done", complete=True)], state
    )
    summary = await _service(state).ingest(source, artifact)
    assert source.seen_checkpoint == "prior"
    assert summary.unchanged == 1

    completed_source = _Source([], state)
    noop = await _service(state).ingest(completed_source, artifact)
    assert noop.results == () and noop.complete and noop.checkpoint == "done"
    assert completed_source.seen_artifact is None


@pytest.mark.asyncio
async def test_restart_clears_only_selected_checkpoint() -> None:
    """Verify restart clears only selected checkpoint."""
    state = _State(outcome_batches=[[BatchOutcome.INSERTED]])
    artifact = _artifact()
    key = ("feed-a", artifact.uri, 1)
    other = ("feed-a", "file:///datasets/feed-a/other.json", 1)
    state.checkpoints[key] = IngestionCheckpoint(*key, "old", True)
    state.checkpoints[other] = IngestionCheckpoint(*other, "keep", True)
    source = _Source(
        [SourceBatch((_record("one"),), checkpoint="new", complete=True)], state
    )
    await _service(state).ingest(source, artifact, restart=True)
    assert source.seen_checkpoint is None
    assert state.checkpoints[other].checkpoint == "keep"
    assert state.checkpoints[key].checkpoint == "new"


@pytest.mark.asyncio
async def test_conflict_rolls_back_batch_and_checkpoint() -> None:
    """Verify conflict rolls back batch and checkpoint."""
    state = _State(outcome_batches=[[BatchOutcome.CONFLICT]])
    source = _Source(
        [SourceBatch((_record("one"),), checkpoint="bad", complete=True)], state
    )
    with pytest.raises(IngestionConflictError):
        await _service(state).ingest(source, _artifact())
    assert not state.checkpoints
    assert state.rollbacks == 1


@pytest.mark.asyncio
async def test_source_failure_preserves_last_committed_checkpoint() -> None:
    """Verify source failure preserves last committed checkpoint."""
    state = _State(outcome_batches=[[BatchOutcome.INSERTED]])
    source = _Source(
        [SourceBatch((_record("one"),), checkpoint="safe")],
        state,
        failure=RuntimeError("parse failed"),
    )
    artifact = _artifact()
    with pytest.raises(RuntimeError, match="parse failed"):
        await _service(state).ingest(source, artifact)
    assert state.checkpoints[("feed-a", artifact.uri, 1)].checkpoint == "safe"


@pytest.mark.asyncio
async def test_batch_size_and_repository_ordinals_are_validated() -> None:
    """Verify batch size and repository ordinals are validated."""
    state = _State(outcome_batches=[])
    too_large = _Source(
        [SourceBatch((_record("one"), _record("two")), checkpoint="next")], state
    )
    with pytest.raises(BatchSizeLimitExceededError):
        await _service(state, 1).ingest(too_large, _artifact())

    state = _State(outcome_batches=[[]])
    bad_results = _Source([SourceBatch((_record("one"),), checkpoint="next")], state)
    with pytest.raises(ValueError, match="ordinals"):
        await _service(state).ingest(bad_results, _artifact())
    assert state.rollbacks == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source_id", "version", "artifact_id", "message"),
    [
        ("feed-a", 1, "feed-b", "source_id"),
        ("feed-a", 0, "feed-a", "positive"),
    ],
)
async def test_source_identity_is_validated(
    source_id: str, version: int, artifact_id: str, message: str
) -> None:
    """Verify source identity is validated."""
    state = _State()
    source = _Source([], state)
    source.source_id = source_id
    source.normalization_version = version
    with pytest.raises(ValueError, match=message):
        await _service(state).ingest(source, _artifact(artifact_id))


@pytest.mark.asyncio
async def test_source_capabilities_must_be_immutable_and_typed() -> None:
    """Verify source capabilities must be immutable and typed."""
    state = _State()
    source = _Source([], state)
    source.capabilities = {CHECKPOINTING}  # type: ignore[assignment]
    with pytest.raises(ValueError, match="immutable typed set"):
        await _service(state).ingest(source, _artifact())


@pytest.mark.asyncio
async def test_emitted_batch_identity_and_checkpoint_capability_are_validated() -> None:
    """Verify emitted batch identity and checkpoint capability are validated."""
    state = _State()
    source = _Source([SourceBatch((_record("one", version=2),))], state)
    with pytest.raises(ValueError, match="normalization version"):
        await _service(state).ingest(source, _artifact())

    source = _Source([SourceBatch((_record("one"),), checkpoint="not-allowed")], state)
    source.capabilities = frozenset()
    with pytest.raises(ValueError, match="non-checkpointing"):
        await _service(state).ingest(source, _artifact())

    source = _Source([SourceBatch((_record("one"),))], state)
    with pytest.raises(ValueError, match="provide checkpoint"):
        await _service(state).ingest(source, _artifact())


@pytest.mark.asyncio
async def test_stored_checkpoint_rejected_for_non_checkpoint_source() -> None:
    """Verify stored checkpoint rejected for non checkpoint source."""
    state = _State()
    artifact = _artifact()
    key = ("feed-a", artifact.uri, 1)
    state.checkpoints[key] = IngestionCheckpoint(*key, "cursor", False)
    source = _Source([], state)
    source.capabilities = frozenset()
    with pytest.raises(ValueError, match="stored checkpoint"):
        await _service(state).ingest(source, artifact)


@pytest.mark.parametrize(
    "values",
    [
        ("", "file:///input", 1, None),
        ("feed", "relative", 1, None),
        ("feed", "s3://user:secret@bucket/input", 1, None),
        ("feed", "file:///input", 0, None),
        ("feed", "file:///input", 1, ""),
    ],
)
def test_checkpoint_identity_is_validated(
    values: tuple[str, str, int, str | None],
) -> None:
    """Verify checkpoint identity is validated."""
    with pytest.raises(ValueError):
        IngestionCheckpoint(*values)


def test_service_rejects_invalid_batch_limit() -> None:
    """Verify service rejects invalid batch limit."""
    with pytest.raises(ValueError, match="positive"):
        IngestionService(lambda: _Uow(_State()), 0)
