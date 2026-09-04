# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the structured batch source ports."""

import dataclasses
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentic_threat_investigator.app.sources import (
    CHECKPOINTING,
    BatchSource,
    SourceBatch,
    SourceCache,
    SourceCapability,
)
from agentic_threat_investigator.domain.source import (
    SourceRecord,
    source_record_content_hash,
)


def _record(source_id: str = "feed-a") -> SourceRecord:
    """Build one valid record fixture for the given source."""
    return SourceRecord(
        source_id=source_id,
        source_record_id="rec-1",
        record_type="observation",
        normalization_version=1,
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        canonical_payload={"value": "example.com"},
    )


def test_checkpointing_capability_constant() -> None:
    """The exported constant is the matching capability enum member."""
    assert CHECKPOINTING is SourceCapability.CHECKPOINTING
    assert CHECKPOINTING.value == "checkpointing"


def test_source_batch_defaults_and_immutability() -> None:
    """Batches default to no checkpoint/incompleteness and stay immutable."""
    batch = SourceBatch(records=(_record(),))
    assert batch.checkpoint is None
    assert batch.complete is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        batch.complete = True  # type: ignore[misc]


def test_source_batch_requires_records() -> None:
    """Empty batches are rejected."""
    with pytest.raises(ValueError, match="at least one record"):
        SourceBatch(records=())


def test_source_batch_requires_one_source() -> None:
    """Records from different sources never share one batch."""
    with pytest.raises(ValueError, match="one source"):
        SourceBatch(records=(_record("feed-a"), _record("feed-b")))


class _RecordingSource(BatchSource):
    # Minimal fake: the port intentionally exposes a single operation.
    # pylint: disable=too-few-public-methods

    """Fake source that yields one batch and records its checkpoint argument."""

    source_id = "feed-a"
    capabilities = frozenset({CHECKPOINTING})

    def __init__(self) -> None:
        self.seen_checkpoint: str | None = None

    def batches(self, checkpoint: str | None = None) -> AsyncIterator[SourceBatch]:
        """Yield one single-source batch after remembering the checkpoint."""

        async def generate() -> AsyncIterator[SourceBatch]:
            """Produce the single fake batch."""
            self.seen_checkpoint = checkpoint
            yield SourceBatch(
                records=(_record(),), checkpoint="cursor-1", complete=True
            )

        return generate()


@pytest.mark.asyncio
async def test_batch_source_yields_normalized_batches() -> None:
    """A concrete source streams batches and advertises capabilities."""

    source = _RecordingSource()

    batches = [batch async for batch in source.batches("cursor-0")]

    assert source.seen_checkpoint == "cursor-0"
    assert source.capabilities == frozenset({SourceCapability.CHECKPOINTING})
    assert len(batches) == 1
    assert batches[0].checkpoint == "cursor-1"
    assert batches[0].complete is True
    assert batches[0].records[0].source_id == "feed-a"


def test_batch_source_cannot_be_instantiated_directly() -> None:
    """The port stays abstract: retrieval must be implemented per source."""
    # Deliberate negative check: the port must not be instantiable.
    with pytest.raises(TypeError):
        # pylint: disable-next=abstract-class-instantiated
        BatchSource()  # type: ignore[abstract]


class _FakeCache(SourceCache):
    """In-memory cache used to exercise the port's default alias."""

    def __init__(self) -> None:
        self._entries: dict[str, bytes] = {}

    async def read(self, key: str) -> bytes | None:
        """Return the stored bytes for a key."""
        return self._entries.get(key)

    async def write(self, key: str, content: bytes) -> Path:
        """Store bytes and report the logical cache path."""
        self._entries[key] = content
        return Path(key)

    async def remove(self, key: str) -> None:
        """Drop one stored key when present."""
        self._entries.pop(key, None)


@pytest.mark.asyncio
async def test_source_cache_get_delegates_to_read() -> None:
    """The compatibility alias reads through the implementing port."""

    cache = _FakeCache()

    await cache.write("k.bin", b"payload")

    assert await cache.get("k.bin") == b"payload"
    assert await cache.get("absent.bin") is None


@pytest.mark.asyncio
async def test_source_cache_roundtrip_through_the_port() -> None:
    """Write, read, and remove behave as one artifact lifecycle."""

    cache = _FakeCache()

    path = await cache.write("k.bin", b"payload")
    assert path == Path("k.bin")
    assert await cache.read("k.bin") == b"payload"
    await cache.remove("k.bin")
    assert await cache.read("k.bin") is None


def test_source_cache_cannot_be_instantiated_directly() -> None:
    """The cache port stays abstract."""
    # Deliberate negative check: the port must not be instantiable.
    with pytest.raises(TypeError):
        # pylint: disable-next=abstract-class-instantiated
        SourceCache()  # type: ignore[abstract]


def test_batch_records_carry_semantic_hashes() -> None:
    """Records inside a batch are validated domain models."""

    batch = SourceBatch(records=(_record(),))

    record = batch.records[0]
    assert record.content_hash == source_record_content_hash(record)
