# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Typed datasource vocabulary and immutable datasource definitions.

A configured datasource is described by five independent dimensions: the
datasource-instance identity, the external source/provider identity, the
acquisition protocol, the physical serialization format, and the semantic
format. No dimension is inferred from another: future semantic conversion is
selected by ``semantic_format``, never by provider, protocol, serialization,
or datasource instance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)

DATASOURCE_ID_MAX_LENGTH = 64
"""Bounded length of one canonical datasource-instance identifier."""

DATASOURCE_LOG_ERROR_CODE_MAX_LENGTH = 64
"""Bounded length of one canonical datasource-log error code."""

_DATASOURCE_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
"""Stable bounded error-code grammar: lowercase snake-case, at most 64 chars."""

_DATASOURCE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
"""Canonical lowercase kebab form of a datasource-instance identifier."""


def validate_datasource_id(value: str) -> str:
    """Validate a canonical datasource-instance identifier and return it.

    Rejects blank, whitespace-only, padded, over-bound, and non-canonical
    values so a datasource ID is a stable configuration identity.
    """
    if not value.strip():
        raise ValueError("datasource_id must not be blank")
    if value != value.strip():
        raise ValueError("datasource_id must not have leading or trailing whitespace")
    if len(value) > DATASOURCE_ID_MAX_LENGTH:
        raise ValueError(
            f"datasource_id must not exceed {DATASOURCE_ID_MAX_LENGTH} characters"
        )
    if _DATASOURCE_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("datasource_id must use the canonical lowercase kebab form")
    return value


@dataclass(frozen=True)
class DatasourceId:
    """Typed identifier of one configured datasource definition.

    Identifies configuration, not provider and not execution: multiple
    datasource instances may share the same :class:`SourceId`.
    """

    value: str

    def __post_init__(self) -> None:
        """Validate the canonical identifier form."""
        validate_datasource_id(self.value)

    def __str__(self) -> str:
        """Return the canonical identifier text."""
        return self.value


class DatasourceProtocol(StrEnum):
    """Typed acquisition protocol vocabulary.

    Protocol identifies how ATI obtains the source material and determines
    acquisition mechanics, never the meaning of records. It is never a
    semantic format.
    """

    HTTPS = "https"
    FILE = "file"


class SerializationFormat(StrEnum):
    """Typed physical serialization vocabulary.

    Serialization answers how bytes/records are encoded, not what they mean.
    STIX, ThreatFox, MISP, and TAXII are semantic or protocol concepts and
    are never classified as serialization formats.
    """

    JSON = "json"


class DatasourceDefinition(BaseModel):
    """Immutable typed description of one configured datasource.

    All five classification dimensions are explicit: datasource instance,
    source/provider identity, acquisition protocol, serialization format,
    and semantic format. None is inferred from another; unknown typed values
    fail closed at construction.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    datasource_id: DatasourceId
    source_id: SourceId
    protocol: DatasourceProtocol
    serialization_format: SerializationFormat
    semantic_format: SemanticFormatId

    @field_validator("datasource_id", mode="before")
    @classmethod
    def _coerce_datasource_id(cls, value: object) -> DatasourceId:
        """Accept a plain string and validate it into the typed identifier."""
        if isinstance(value, DatasourceId):
            return value
        if not isinstance(value, str):
            raise ValueError("datasource_id must be a string or DatasourceId")
        return DatasourceId(value)


REPRESENTATIVE_DATASOURCE_DEFINITIONS: tuple[DatasourceDefinition, ...] = (
    DatasourceDefinition(
        datasource_id=DatasourceId("threatfox-live"),
        source_id=SourceId.THREATFOX,
        protocol=DatasourceProtocol.HTTPS,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.THREATFOX,
    ),
    DatasourceDefinition(
        datasource_id=DatasourceId("mitre-attack-enterprise"),
        source_id=SourceId.MITRE_ATTACK,
        protocol=DatasourceProtocol.FILE,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.STIX_21,
    ),
)
"""Repository-owned representative datasource definitions (PR 27A).

Proves the architectural separation without migrating runtime ingestion:
ThreatFox is HTTPS + JSON with its own proprietary semantic format, while
MITRE ATT&CK is FILE + JSON with the shared STIX 2.1 semantic format.
"""


class DatasourceExecutionEventType(StrEnum):
    """Closed operational-stage vocabulary of one acquisition execution (PR 27B).

    Describes operational stages of one acquisition execution correlated by
    one ``execution_id``. It does not assert that every current datasource
    runtime already implements all stages; non-terminal stages may be omitted
    because source paths differ. Terminal event types are exactly
    ``COMPLETED``, ``FAILED``, and ``CANCELLED``.
    """

    STARTED = "started"
    ACQUIRED = "acquired"
    DECODED = "decoded"
    CONVERTED = "converted"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_DATASOURCE_EXECUTION_EVENT_TYPES = frozenset(
    {
        DatasourceExecutionEventType.COMPLETED,
        DatasourceExecutionEventType.FAILED,
        DatasourceExecutionEventType.CANCELLED,
    }
)
"""Exactly the terminal event types of one acquisition execution."""


def validate_datasource_error_code(value: str) -> str:
    """Validate a canonical bounded datasource-log error code and return it.

    Rejects blank, whitespace-padded, over-bound, and malformed values so the
    durable log only ever carries safe machine-readable codes.
    """
    if not value:
        raise ValueError("datasource error_code must not be blank")
    if value != value.strip():
        raise ValueError("datasource error_code must not be whitespace-padded")
    if len(value) > DATASOURCE_LOG_ERROR_CODE_MAX_LENGTH:
        raise ValueError(
            f"datasource error_code must not exceed "
            f"{DATASOURCE_LOG_ERROR_CODE_MAX_LENGTH} characters"
        )
    if _DATASOURCE_ERROR_CODE_RE.fullmatch(value) is None:
        raise ValueError(
            "datasource error_code must match ^[a-z][a-z0-9_]{0,63}$ "
            "with no surrounding whitespace"
        )
    return value


class DatasourceLogEvent(BaseModel):
    """One immutable bounded operational event of one acquisition execution.

    Every event carries the exact ``execution_id`` and ``datasource_id`` of
    its execution; the database owns the lifecycle invariants (STARTED first
    and unique, at most one terminal, no append after terminal, datasource
    identity stability). Events carry only bounded operational metadata:
    optional non-negative stage-local counts and a bounded safe error code
    for ``FAILED``. No source body, decoded object, Evidence body,
    credential, token, URI query secret, or raw exception text is ever
    represented by this model.

    ``item_count``/``byte_count`` are stage-local: ACQUIRED may report
    acquired byte/artifact counts, DECODED decoded object counts, CONVERTED
    produced Evidence counts, and COMPLETED usually omits them. They are
    never interpreted globally.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: UUID
    datasource_id: DatasourceId
    event_type: DatasourceExecutionEventType
    occurred_at: datetime
    item_count: int | None = None
    byte_count: int | None = None
    error_code: str | None = None

    @field_validator("datasource_id", mode="before")
    @classmethod
    def _coerce_datasource_id(cls, value: object) -> DatasourceId:
        """Accept a plain string and validate it into the typed identifier."""
        if isinstance(value, DatasourceId):
            return value
        if not isinstance(value, str):
            raise ValueError("datasource_id must be a string or DatasourceId")
        return DatasourceId(value)

    @field_validator("occurred_at")
    @classmethod
    def _validate_occurred_at(cls, value: datetime) -> datetime:
        """Require a timezone-aware timestamp, normalized to UTC."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("datasource log timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("item_count", "byte_count")
    @classmethod
    def _validate_counts(cls, value: int | None) -> int | None:
        """Reject negative stage-local counts."""
        if value is not None and value < 0:
            raise ValueError("datasource log counts must be non-negative")
        return value

    @field_validator("error_code")
    @classmethod
    def _validate_error_code(cls, value: str | None) -> str | None:
        """Reject error codes outside the stable bounded snake-case grammar."""
        if value is None:
            return None
        validate_datasource_error_code(value)
        return value

    @model_validator(mode="after")
    def _validate_error_code_compatibility(self) -> "DatasourceLogEvent":
        """Bind error_code to FAILED events only.

        CANCELLED is never a failure and never carries an error code;
        COMPLETED and non-terminal stages never carry one either.
        """
        if self.event_type is DatasourceExecutionEventType.FAILED:
            if self.error_code is None:
                raise ValueError("failed events require a bounded error_code")
            return self
        if self.error_code is not None:
            raise ValueError(
                "datasource log error_code is allowed only for failed events"
            )
        return self
