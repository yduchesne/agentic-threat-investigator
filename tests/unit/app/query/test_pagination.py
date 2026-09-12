# SPDX-License-Identifier: AGPL-3.0-only
"""Cursor codec and pagination unit tests (PR 23A U01-U10)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.query.models import QueryLimits, QueryPage
from agentic_threat_investigator.app.query.pagination import (
    CURSOR_VERSION,
    CursorEnvelope,
    CursorFilterMismatchError,
    CursorQueryMismatchError,
    InvalidCursorError,
    QueryKind,
    decode_cursor,
    encode_cursor,
    filter_fingerprint,
    require_cursor_for_query,
)


def envelope(
    *,
    query_kind: QueryKind = QueryKind.INVESTIGATIONS,
    fingerprint: str = "fp",
    sort_values: tuple[str, ...] = ("2026-01-01T00:00:00+00:00", str(uuid4())),
) -> CursorEnvelope:
    """Build a canonical valid cursor envelope for tests."""
    return CursorEnvelope(
        version=CURSOR_VERSION,
        query_kind=query_kind,
        filter_fingerprint=fingerprint,
        sort_values=sort_values,
    )


def test_u01_encode_decode_round_trip() -> None:
    """Encoding then decoding restores the exact envelope."""
    original = envelope(
        sort_values=(
            "2026-01-02T03:04:05+00:00",
            "11111111-1111-1111-1111-111111111111",
        )
    )
    encoded = encode_cursor(original)
    assert isinstance(encoded, str) and encoded
    assert decode_cursor(encoded) == original


def test_u01_padding_stripped_and_restored() -> None:
    """URL-safe base64 padding is stripped on encode and restored on decode."""
    original = envelope()
    encoded = encode_cursor(original)
    assert "=" not in encoded
    assert decode_cursor(encoded) == original


def test_u02_malformed_base64_is_typed_invalid_cursor() -> None:
    """Non-base64 text fails closed with the typed error."""
    with pytest.raises(InvalidCursorError):
        decode_cursor("!!!not-base64!!!")


def test_u03_malformed_json_is_typed_invalid_cursor() -> None:
    """Valid base64 of non-JSON fails closed with the typed error."""
    import base64

    payload = base64.urlsafe_b64encode(b"not json").decode("ascii").rstrip("=")
    with pytest.raises(InvalidCursorError):
        decode_cursor(payload)


def test_u03_unknown_fields_rejected() -> None:
    """An envelope carrying extra fields is invalid."""
    import base64
    import json

    data = json.dumps(
        {
            "version": 1,
            "query_kind": "investigations",
            "filter_fingerprint": "fp",
            "sort_values": ["x"],
            "extra": 1,
        }
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    with pytest.raises(InvalidCursorError):
        decode_cursor(encoded)


def test_u04_unknown_cursor_version_fails_closed() -> None:
    """An unsupported envelope version is rejected as invalid."""
    import base64
    import json

    data = json.dumps(
        {
            "version": 99,
            "query_kind": "investigations",
            "filter_fingerprint": "fp",
            "sort_values": ["x"],
        }
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    with pytest.raises(InvalidCursorError):
        require_cursor_for_query(
            encoded,
            query_kind=QueryKind.INVESTIGATIONS,
            filter_fingerprint="fp",
        )


def test_u05_wrong_query_kind_is_mismatch() -> None:
    """A cursor from another collection fails closed as a mismatch."""
    encoded = encode_cursor(envelope(query_kind=QueryKind.EVIDENCE))
    with pytest.raises(CursorQueryMismatchError):
        require_cursor_for_query(
            encoded,
            query_kind=QueryKind.INVESTIGATIONS,
            filter_fingerprint="fp",
        )


def test_u06_changed_filters_is_filter_mismatch() -> None:
    """A cursor whose filter fingerprint differs fails closed."""
    encoded = encode_cursor(envelope(fingerprint="fingerprint-a"))
    with pytest.raises(CursorFilterMismatchError):
        require_cursor_for_query(
            encoded,
            query_kind=QueryKind.INVESTIGATIONS,
            filter_fingerprint="fingerprint-b",
        )


def test_u07_canonical_filter_normalization_stable() -> None:
    """Equivalent normalized filters produce a stable fingerprint."""
    stamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    identifier = uuid4()
    first = filter_fingerprint(
        {"status": "running", "created_from": stamp, "entity": identifier}
    )
    second = filter_fingerprint(
        {
            "created_from": stamp.astimezone(UTC),
            "entity": identifier,
            "status": "running",
        }
    )
    assert first == second
    assert len(first) == 64


def test_u08_equivalent_filter_ordering_same_fingerprint() -> None:
    """Key ordering never changes the fingerprint."""
    assert filter_fingerprint({"a": 1, "b": 2}) == filter_fingerprint({"b": 2, "a": 1})


def test_u09_naive_timestamp_fingerprint_rejected() -> None:
    """A naive timestamp cannot be canonicalized into a fingerprint."""
    with pytest.raises(ValueError):
        filter_fingerprint({"created_from": datetime(2026, 1, 1)})


def test_u10_invalid_limit_rejected_by_limits_contract() -> None:
    """Page limits enforce the configured maximum."""
    limits = QueryLimits(default_page_size=50, max_page_size=200)
    with pytest.raises(ValueError):
        limits.validate_limit(0)
    with pytest.raises(ValueError):
        limits.validate_limit(201)
    assert limits.validate_limit(1) == 1
    assert limits.validate_limit(200) == 200


def test_u10_invalid_limit_defaults_rejected() -> None:
    """A default above the configured maximum is invalid configuration."""
    with pytest.raises(ValidationError):
        QueryLimits(default_page_size=300, max_page_size=200)


def test_query_page_is_frozen_and_bounded() -> None:
    """QueryPage rejects unknown fields and mutation."""
    page = QueryPage(items=(1, 2), next_cursor="c")
    with pytest.raises(ValidationError):
        QueryPage.model_validate({"items": (1,), "next_cursor": "c", "extra": "x"})
    with pytest.raises(ValidationError):
        page.items = (3,)
    assert page.items == (1, 2)
    assert page.next_cursor == "c"


def test_query_page_next_cursor_defaults_to_none() -> None:
    """The final page carries no next cursor."""
    assert QueryPage(items=()).next_cursor is None
