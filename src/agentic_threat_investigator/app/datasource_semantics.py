# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-cutting semantic-source acquisition contracts (PR 27C).

This module owns the narrow contracts shared by the acquisition-to-semantic
boundary: an immutable cross-cutting provenance context, a stage-aware
datasource failure contract, and a small generic semantic acquisition
result. Semantic modules themselves are format-specific and live under
``infrastructure/datasources``; nothing in this module understands
ThreatFox, STIX, or any other source's semantic model, and nothing here
constructs ATI Evidence (PR 27D owns conversion).

The context carries only cross-cutting provenance (datasource/source/
semantic-format identities, retrieval time, a credential-free reference,
and an optional existing ``ArtifactReference``). It never carries a union
of source-specific semantic fields, credentials, headers, Investigation
IDs, Evidence IDs, verdicts, or risk values. All three identity values
originate from one ``DatasourceDefinition``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Generic, TypeVar
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, field_validator

from agentic_threat_investigator.app.sources import ArtifactReference
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    validate_datasource_error_code,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)

_SOURCE_REFERENCE_MAX_LENGTH = 2048
"""Bounded length of one credential-free source reference."""


class DatasourceStage(StrEnum):
    """Typed acquisition failure stage on the PR 27C acquisition-to-semantic path.

    Distinguishes where a datasource acquisition failed so operational
    outcomes remain attributable to at least ACQUISITION, SERIALIZATION, or
    SEMANTIC_VALIDATION. PR 27D later adds CONVERSION. These are error
    stages, never overloaded lifecycle event types (PR 27B owns those).
    """

    ACQUISITION = "acquisition"
    SERIALIZATION = "serialization"
    SEMANTIC_VALIDATION = "semantic_validation"


class DatasourceStageError(BaseModel):
    """One immutable bounded stage-aware datasource failure.

    Carries only the typed stage, a bounded safe machine-readable code from
    the PR 27B error-code grammar, the natural retryability, and an optional
    provider-directed nonnegative ``retry_after_seconds``. No raw exception
    text, response body, credential, URL, or unbounded provider content is
    ever represented by this model.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: DatasourceStage
    code: str
    retryable: bool
    retry_after_seconds: int | None = None

    @field_validator("code")
    @classmethod
    def _validate_code(cls, value: str) -> str:
        """Reject error codes outside the stable bounded snake-case grammar."""
        validate_datasource_error_code(value)
        return value

    @field_validator("retry_after_seconds")
    @classmethod
    def _validate_retry_after(cls, value: int | None) -> int | None:
        """Reject negative provider-directed retry delays."""
        if value is not None and value < 0:
            raise ValueError("retry_after_seconds must be nonnegative")
        return value


def _validate_source_reference(value: str | None) -> str | None:
    """Validate a bounded credential-free source reference, or return ``None``.

    A documented ``None`` is valid. When present the reference must be a
    bounded ``http``/``https`` URL with a hostname, no credentials, and no
    embedded whitespace. The reference is metadata only; it is never
    fetched.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("source_reference must be a string or None")
    if (
        not value
        or len(value) > _SOURCE_REFERENCE_MAX_LENGTH
        or any(char.isspace() for char in value)
    ):
        raise ValueError("invalid source_reference member")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("invalid source_reference member")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("source_reference must not contain credentials")
    return value


@dataclass(frozen=True)
class SemanticSourceContext:
    """Immutable cross-cutting provenance of one semantic acquisition.

    Carries exactly the cross-cutting identities required for later
    provenance: one ``datasource_id``, one ``source_id``, one
    ``semantic_format``, the timezone-aware UTC-normalized ``retrieved_at``,
    and optional credential-free source/artifact references. The three
    identity values must originate from one ``DatasourceDefinition``;
    production code builds this context through
    :meth:`SemanticSourceContext.from_definition` so callers cannot
    independently substitute source or semantic identities.
    """

    datasource_id: DatasourceId
    source_id: SourceId
    semantic_format: SemanticFormatId
    retrieved_at: datetime
    source_reference: str | None = None
    artifact: ArtifactReference | None = None

    def __post_init__(self) -> None:
        """Validate the retrieval timestamp and the optional reference."""
        if self.retrieved_at.tzinfo is None or self.retrieved_at.utcoffset() is None:
            raise ValueError("retrieved_at must be timezone-aware")
        object.__setattr__(self, "retrieved_at", self.retrieved_at.astimezone(UTC))
        object.__setattr__(
            self, "source_reference", _validate_source_reference(self.source_reference)
        )

    @classmethod
    def from_definition(
        cls,
        definition: DatasourceDefinition,
        *,
        retrieved_at: datetime,
        source_reference: str | None = None,
        artifact: ArtifactReference | None = None,
    ) -> "SemanticSourceContext":
        """Build the context from one ``DatasourceDefinition``.

        All three identity values are derived from the single definition and
        never parameterized separately, so a definition/context mismatch is
        impossible through this constructor.
        """
        return cls(
            datasource_id=definition.datasource_id,
            source_id=definition.source_id,
            semantic_format=definition.semantic_format,
            retrieved_at=retrieved_at,
            source_reference=source_reference,
            artifact=artifact,
        )


T = TypeVar("T")


@dataclass(frozen=True)
class SemanticAcquisitionResult(Generic[T]):
    """A small generic outcome of one semantic acquisition execution.

    Invariant: success means ``error is None`` with ``objects`` possibly
    empty (a valid no-result is successful empty semantics, never benign
    evidence); failure means ``error`` is set and ``objects`` is empty.
    A valid no-result is never a benign evidence result.
    """

    context: SemanticSourceContext
    objects: tuple[T, ...] = ()
    error: DatasourceStageError | None = None

    def __post_init__(self) -> None:
        """Enforce the success/failure invariant of the generic result."""
        if self.error is not None and self.objects:
            raise ValueError("a failed semantic acquisition cannot carry objects")
