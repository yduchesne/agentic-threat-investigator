# SPDX-License-Identifier: AGPL-3.0-only
"""Pure domain contracts for normalized structured source records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_threat_investigator.domain.immutable_json import (
    FrozenDict,
    freeze_json,
    freeze_mapping,
    thaw_json,
)


def _utc_timestamp(value: datetime | None) -> datetime | None:
    """Validate and normalize a timestamp to timezone-aware UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


def canonical_json_bytes(value: Mapping[str, Any] | list[Any]) -> bytes:
    """Validate and serialize JSON data deterministically without whitespace."""
    immutable = freeze_json(value)
    return json.dumps(
        thaw_json(immutable),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def semantic_source_record_payload(
    record: SourceRecord | Mapping[str, Any],
) -> dict[str, Any]:
    """Return only the fields that define normalized source-record semantics."""
    if isinstance(record, SourceRecord):
        values: Mapping[str, Any] = record.model_dump(mode="python")
    else:
        values = record
    return {
        "canonical_payload": values["canonical_payload"],
        "normalization_version": values["normalization_version"],
        "observed_at": _timestamp_text(values.get("observed_at")),
        "published_at": _timestamp_text(values.get("published_at")),
        "record_type": values["record_type"],
    }


def _timestamp_text(value: Any) -> str | None:
    """Render an already validated timestamp in its canonical UTC form."""
    if value is None:
        return None
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        timestamp = datetime.fromisoformat(value)
    else:
        raise ValueError("timestamps must be datetime instances or ISO-8601 strings")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return timestamp.astimezone(UTC).isoformat()


def source_record_content_hash(record: SourceRecord | Mapping[str, Any]) -> str:
    """Compute the lowercase SHA-256 digest of semantic canonical JSON."""
    digest = hashlib.sha256(
        canonical_json_bytes(semantic_source_record_payload(record))
    )
    return digest.hexdigest().lower()


class SourceRecord(BaseModel):
    """A normalized immutable observation from a structured batch source.

    ``id`` is ATI's internal identity.  The durable external identity is the
    pair ``(source_id, source_record_id)`` and is never replaced by ``id``.
    Retrieval, transport, cache, and arbitrary metadata are intentionally not
    included in semantic content hashing.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID | None = None
    source_id: str
    source_record_id: str
    record_type: str
    normalization_version: int = Field(ge=1)
    observed_at: datetime | None = None
    published_at: datetime | None = None
    retrieved_at: datetime
    canonical_payload: dict[str, Any]
    raw_payload: dict[str, Any] | None = None
    content_hash: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    _validate_observed_at = field_validator(
        "observed_at", "published_at", mode="after"
    )(_utc_timestamp)
    _validate_retrieved_at = field_validator("retrieved_at", mode="after")(
        _utc_timestamp
    )

    @model_validator(mode="before")
    @classmethod
    def validate_content_hash(cls, data: Any) -> Any:
        """Snapshot nested inputs and derive or verify the semantic digest."""
        if not isinstance(data, Mapping):
            return data
        values = dict(data)
        required_for_hash = {
            "canonical_payload",
            "normalization_version",
            "record_type",
        }
        if not required_for_hash.issubset(values):
            return values
        expected = source_record_content_hash(values)
        supplied = values.get("content_hash")
        if supplied is not None:
            if not isinstance(supplied, str) or supplied.lower() != expected:
                raise ValueError(
                    "content_hash does not match semantic source-record content"
                )
        values["content_hash"] = expected
        return values

    @field_validator("canonical_payload", "metadata", mode="after")
    @classmethod
    def freeze_required_json(cls, value: dict[str, Any]) -> FrozenDict:
        """Store JSON objects as recursively immutable snapshots."""
        return freeze_mapping(value)

    @field_validator("raw_payload", mode="after")
    @classmethod
    def freeze_optional_json(cls, value: dict[str, Any] | None) -> FrozenDict | None:
        """Store an optional JSON object as a recursively immutable snapshot."""
        return None if value is None else freeze_mapping(value)

    def semantic_payload(self) -> dict[str, Any]:
        """Return the payload used for deterministic change detection."""
        return semantic_source_record_payload(self)

    @property
    def external_identity(self) -> tuple[str, str]:
        """Return the source-owned identity tuple."""
        return self.source_id, self.source_record_id
