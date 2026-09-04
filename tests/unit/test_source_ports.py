# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for artifact and structured batch-source contracts."""

import dataclasses
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest

from agentic_threat_investigator.app.sources import (
    CHECKPOINTING,
    ArtifactReference,
    ArtifactReferenceError,
    BatchSource,
    ObjectStore,
    SourceBatch,
    SourceCapability,
)
from agentic_threat_investigator.domain.source import SourceRecord


def _record(source_id: str = "feed-a", version: int = 1) -> SourceRecord:
    """Support the test record behavior."""
    return SourceRecord(
        source_id=source_id,
        source_record_id="rec-1",
        record_type="observation",
        normalization_version=version,
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        canonical_payload={"value": "example.com"},
    )


def _artifact(**overrides: object) -> ArtifactReference:
    """Support the test artifact behavior."""
    values: dict[str, object] = {
        "source_id": "feed-a",
        "uri": "file:///datasets/feed-a/input.json",
        "retrieved_at": datetime(2026, 1, 1, tzinfo=UTC),
        "metadata": {"headers": {"etag": "one"}, "parts": [1, 2]},
    }
    values.update(overrides)
    return ArtifactReference(**values)  # type: ignore[arg-type]


def test_artifact_reference_normalizes_time_and_freezes_metadata() -> None:
    """Verify artifact reference normalizes time and freezes metadata."""
    artifact = _artifact(
        retrieved_at=datetime(2026, 1, 1, 2, tzinfo=UTC) + timedelta(hours=1)
    )
    assert artifact.retrieved_at.tzinfo is UTC
    with pytest.raises(TypeError):
        artifact.metadata["new"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        artifact.metadata["headers"]["etag"] = "two"
    with pytest.raises(dataclasses.FrozenInstanceError):
        artifact.uri = "file:///other"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"source_id": " "}, "source_id"),
        ({"uri": "relative.json"}, "lowercase scheme"),
        ({"uri": "FILE:///input.json"}, "lowercase scheme"),
        ({"uri": "s3://user:secret@bucket/key"}, "credentials"),
        ({"retrieved_at": datetime(2026, 1, 1)}, "timezone-aware"),
        ({"content_hash": "ABC"}, "SHA-256"),
        ({"content_hash": "g" * 64}, "SHA-256"),
    ],
)
def test_artifact_reference_rejects_invalid_values(
    overrides: dict[str, object], message: str
) -> None:
    """Verify artifact reference rejects invalid values."""
    with pytest.raises(ArtifactReferenceError, match=message):
        _artifact(**overrides)


def test_artifact_reference_accepts_expected_digest() -> None:
    """Verify artifact reference accepts expected digest."""
    assert _artifact(content_hash="a" * 64).content_hash == "a" * 64


def test_source_batch_is_immutable_and_exposes_identity() -> None:
    """Verify source batch is immutable and exposes identity."""
    batch = SourceBatch((_record(),), checkpoint="next", complete=True)
    assert batch.source_id == "feed-a"
    assert batch.normalization_version == 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        batch.complete = False  # type: ignore[misc]


@pytest.mark.parametrize(
    ("records", "checkpoint", "message"),
    [
        ((), None, "at least one"),
        ((_record(), _record("feed-b")), None, "one source"),
        ((_record(), _record(version=2)), None, "one normalization"),
        ((_record(),), "", "must not be blank"),
    ],
)
def test_source_batch_rejects_invalid_content(
    records: tuple[SourceRecord, ...], checkpoint: str | None, message: str
) -> None:
    """Verify source batch rejects invalid content."""
    with pytest.raises(ValueError, match=message):
        SourceBatch(records, checkpoint=checkpoint)


class _Source(BatchSource):  # pylint: disable=too-few-public-methods
    """Test helper for Source."""

    source_id = "feed-a"
    normalization_version = 1
    capabilities = frozenset({CHECKPOINTING})

    def batches(
        self, artifact: ArtifactReference, checkpoint: str | None = None
    ) -> AsyncIterator[SourceBatch]:
        """Support the test batches behavior."""

        async def generate() -> AsyncIterator[SourceBatch]:
            """Support the test generate behavior."""
            assert artifact.source_id == self.source_id
            assert checkpoint == "before"
            yield SourceBatch((_record(),), checkpoint="after", complete=True)

        return generate()


@pytest.mark.asyncio
async def test_batch_source_receives_artifact_and_checkpoint() -> None:
    """Verify batch source receives artifact and checkpoint."""
    batches = [batch async for batch in _Source().batches(_artifact(), "before")]
    assert batches[0].checkpoint == "after"
    assert CHECKPOINTING is SourceCapability.CHECKPOINTING


def test_ports_are_abstract() -> None:
    """Verify ports are abstract."""
    with pytest.raises(TypeError):
        # pylint: disable-next=abstract-class-instantiated
        BatchSource()  # type: ignore[abstract]
    with pytest.raises(TypeError):
        # pylint: disable-next=abstract-class-instantiated
        ObjectStore()  # type: ignore[abstract]
