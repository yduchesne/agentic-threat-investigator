# SPDX-License-Identifier: AGPL-3.0-only
"""Ports and transport contracts for structured batch sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from agentic_threat_investigator.domain.source import SourceRecord


class SourceCapability(StrEnum):
    """Capabilities a source may advertise to the ingestion coordinator."""

    CHECKPOINTING = "checkpointing"


CHECKPOINTING = SourceCapability.CHECKPOINTING


@dataclass(frozen=True)
class SourceBatch:
    """A bounded normalized batch and its source-owned progress marker."""

    records: tuple[SourceRecord, ...]
    checkpoint: str | None = None
    complete: bool = False

    def __post_init__(self) -> None:
        """Reject an unbounded or cross-source batch."""
        if not self.records:
            raise ValueError("source batches must contain at least one record")
        source_ids = {record.source_id for record in self.records}
        if len(source_ids) != 1:
            raise ValueError("a source batch must contain one source")


class BatchSource(ABC):  # pylint: disable=too-few-public-methods
    """Async source adapter that retrieves and normalizes bounded batches."""

    source_id: str
    capabilities: frozenset[SourceCapability] = frozenset()

    @abstractmethod
    def batches(self, checkpoint: str | None = None) -> AsyncIterator[SourceBatch]:
        """Yield normalized batches after an optional source checkpoint."""


class SourceCache(ABC):
    """Cache port for reproducible downloaded source artifacts."""

    @abstractmethod
    async def read(self, key: str) -> bytes | None:
        """Return cached bytes, or ``None`` when the key is absent."""

    @abstractmethod
    async def write(self, key: str, content: bytes) -> Path:
        """Atomically store bytes and return their cache path."""

    @abstractmethod
    async def remove(self, key: str) -> None:
        """Remove one cache artifact when present."""

    async def get(self, key: str) -> bytes | None:
        """Compatibility alias for reading a cached artifact."""
        return await self.read(key)


# A typed, shallow settings view lets bootstrap code inject config without
# making the source/cache ports depend on a concrete settings implementation.
CacheConfig = Mapping[str, Any]
PathLike = str | Path
