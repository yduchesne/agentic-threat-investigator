# SPDX-License-Identifier: AGPL-3.0-only
"""Opaque versioned cursor codec for deterministic keyset pagination.

Cursors are application-level opaque values. They encode only the ordering
identity required to continue a query, are bound to their query collection
and filter fingerprint, and never carry SQL fragments, table names, filter
dictionaries, or secrets.

Encoding:

- canonical JSON of the :class:`CursorEnvelope`;
- UTF-8;
- URL-safe base64 with padding stripped and re-added deterministically on
  decode, so no padding-normalization ambiguity exists.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationError


class QueryKind(str, Enum):
    """The collection identity a cursor belongs to."""

    INVESTIGATIONS = "investigations"
    EVIDENCE = "evidence"
    RELATIONSHIPS = "relationships"
    RELATIONSHIP_OBSERVATIONS = "relationship_observations"
    RESEARCH_RESULTS = "research_results"
    ASSESSMENTS = "assessments"
    TIMELINE = "timeline"
    DOMAIN_HISTORY = "domain_history"


CURSOR_VERSION: Literal[1] = 1
"""The only cursor envelope version accepted by the codec."""


class QueryCursorError(ValueError):
    """Base class for typed cursor codec failures.

    Callers must never surface base64 decoder errors, JSON parsing
    exceptions, or Pydantic internal messages; these typed errors are the
    stable application surface a future HTTP layer maps to 400 responses.
    """


class InvalidCursorError(QueryCursorError):
    """Raised when a cursor is malformed, unparseable, or unsupported."""


class CursorQueryMismatchError(QueryCursorError):
    """Raised when a cursor belongs to a different query collection."""


class CursorFilterMismatchError(QueryCursorError):
    """Raised when a cursor's filter fingerprint differs from the query.

    A cursor produced for one filter set must never silently continue a
    query with different filters.
    """


class CursorEnvelope(BaseModel):
    """Internal cursor payload; never exposed publicly as a schema.

    ``sort_values`` are decimal/ISO/UUID canonical strings in the exact
    order of the collection's canonical ordering, so continuation needs no
    table names, filter dictionaries, or arbitrary expressions.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1] = CURSOR_VERSION
    query_kind: QueryKind
    filter_fingerprint: str
    sort_values: tuple[str, ...]


def _json_default(value: object) -> object:
    """Serialize only the canonical scalar cursor/fingerprint types."""
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("cursor timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"cannot canonicalize cursor value: {type(value).__name__}")


def filter_fingerprint(values: Mapping[str, object]) -> str:
    """Return the SHA-256 of the canonical normalized filter set.

    Keys are sorted and every value is serialized canonically (UTC ISO-8601
    datetimes, canonical UUID strings, enum values), so equivalent filter
    sets always produce the same fingerprint.
    """
    payload = json.dumps(
        dict(values),
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def encode_cursor(envelope: CursorEnvelope) -> str:
    """Encode a cursor envelope into an opaque URL-safe string."""
    payload = envelope.model_dump_json().encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_cursor(value: str) -> CursorEnvelope:
    """Decode and strictly validate an opaque cursor string.

    Any malformed base64, malformed JSON, unknown field, wrong version, or
    missing/extra field raises :class:`InvalidCursorError`; raw decoder
    exceptions never escape.
    """
    try:
        padded = value + "=" * (-len(value) % 4)
        payload = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        raise InvalidCursorError("cursor is not valid base64-encoded JSON") from error
    try:
        envelope = CursorEnvelope.model_validate(data)
    except ValidationError as error:
        raise InvalidCursorError("cursor envelope is malformed") from error
    return envelope


def require_cursor_for_query(
    value: str | None,
    *,
    query_kind: QueryKind,
    filter_fingerprint: str,
) -> CursorEnvelope | None:
    """Decode and bind a cursor to its exact query/filter context.

    Returns ``None`` for an absent cursor. A cursor from another collection
    or another filter set fails closed with the dedicated typed errors; an
    unsupported envelope version is invalid.
    """
    if value is None:
        return None
    envelope = decode_cursor(value)
    if envelope.version != CURSOR_VERSION:
        raise InvalidCursorError(f"cursor version {envelope.version} is not supported")
    if envelope.query_kind is not query_kind:
        raise CursorQueryMismatchError(
            f"cursor belongs to {envelope.query_kind.value}, not {query_kind.value}"
        )
    if envelope.filter_fingerprint != filter_fingerprint:
        raise CursorFilterMismatchError(
            "cursor filters do not match the supplied query filters"
        )
    return envelope
