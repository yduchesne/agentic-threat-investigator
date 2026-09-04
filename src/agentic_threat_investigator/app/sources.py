# SPDX-License-Identifier: AGPL-3.0-only
"""Application ports for credential-free batch artifacts and sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from agentic_threat_investigator.domain.immutable_json import freeze_mapping
from agentic_threat_investigator.domain.source import SourceRecord


class ArtifactReferenceError(ValueError):
    """Raised when an artifact reference is malformed or unsafe."""


@dataclass(frozen=True)
class ArtifactReference:
    """Identity and retrieval metadata for one already-acquired artifact."""

    source_id: str
    uri: str
    retrieved_at: datetime
    content_hash: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and snapshot a canonical, credential-free artifact identity."""
        if not self.source_id.strip():
            raise ArtifactReferenceError("source_id must not be blank")
        parsed = urlsplit(self.uri)
        raw_scheme = self.uri.split(":", 1)[0]
        if not parsed.scheme or raw_scheme != raw_scheme.lower():
            raise ArtifactReferenceError("artifact URI must use a lowercase scheme")
        if parsed.username is not None or parsed.password is not None:
            raise ArtifactReferenceError("artifact URI must not contain credentials")
        if urlunsplit(parsed) != self.uri:
            raise ArtifactReferenceError("artifact URI must be canonical")
        if self.retrieved_at.tzinfo is None or self.retrieved_at.utcoffset() is None:
            raise ArtifactReferenceError("retrieved_at must be timezone-aware")
        if self.content_hash is not None:
            digest = self.content_hash
            if len(digest) != 64 or digest != digest.lower():
                raise ArtifactReferenceError("content_hash must be lowercase SHA-256")
            try:
                bytes.fromhex(digest)
            except ValueError as exc:
                raise ArtifactReferenceError(
                    "content_hash must be lowercase SHA-256"
                ) from exc
        object.__setattr__(self, "retrieved_at", self.retrieved_at.astimezone(UTC))
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))


class ObjectStore(ABC):  # pylint: disable=too-few-public-methods  # pragma: no cover
    """Read existing artifacts addressed by canonical URIs."""

    @abstractmethod
    async def read(self, uri: str) -> bytes:
        """Read an artifact, raising a typed not-found error when absent."""


class SourceCapability(StrEnum):
    """Capabilities advertised by a batch source."""

    CHECKPOINTING = "checkpointing"


CHECKPOINTING = SourceCapability.CHECKPOINTING


@dataclass(frozen=True)
class SourceBatch:
    """A non-empty bounded batch and source-owned progress after that batch."""

    records: tuple[SourceRecord, ...]
    checkpoint: str | None = None
    complete: bool = False

    def __post_init__(self) -> None:
        """Reject empty, mixed-source, mixed-version, or blank checkpoints."""
        if not self.records:
            raise ValueError("source batches must contain at least one record")
        if len({record.source_id for record in self.records}) != 1:
            raise ValueError("a source batch must contain one source")
        if len({record.normalization_version for record in self.records}) != 1:
            raise ValueError("a source batch must contain one normalization version")
        if self.checkpoint is not None and not self.checkpoint:
            raise ValueError("checkpoint must not be blank")

    @property
    def source_id(self) -> str:
        """Return the single source identifier represented by this batch."""
        return self.records[0].source_id

    @property
    def normalization_version(self) -> int:
        """Return the single normalization version represented by this batch."""
        return self.records[0].normalization_version


class BatchSource(ABC):  # pylint: disable=too-few-public-methods  # pragma: no cover
    """Normalize one selected artifact into bounded asynchronous batches."""

    source_id: str
    normalization_version: int
    capabilities: frozenset[SourceCapability] = frozenset()

    @abstractmethod
    def batches(
        self, artifact: ArtifactReference, checkpoint: str | None = None
    ) -> AsyncIterator[SourceBatch]:
        """Yield batches for an artifact after an optional opaque checkpoint."""
