# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the normalized source-record domain contract."""

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.source import (
    SourceRecord,
    canonical_json_bytes,
    semantic_source_record_payload,
    source_record_content_hash,
)

_OFFSET = timezone(timedelta(hours=2))


def _record(**overrides: Any) -> SourceRecord:
    """Build one valid record fixture with optional field overrides."""
    values: dict[str, Any] = {
        "source_id": "crt-sh",
        "source_record_id": "rec-1",
        "record_type": "certificate",
        "normalization_version": 1,
        "observed_at": datetime(2026, 1, 1, tzinfo=UTC),
        "retrieved_at": datetime(2026, 1, 2, tzinfo=UTC),
        "canonical_payload": {"domain": "example.com"},
    }
    values.update(overrides)
    return SourceRecord(**values)


def test_record_derives_content_hash() -> None:
    """Construction computes the semantic digest when none is supplied."""
    record = _record()
    assert record.content_hash == source_record_content_hash(record)


def test_record_accepts_matching_hash_case_insensitively() -> None:
    """A supplied hash matching the semantic content is normalized."""

    expected = source_record_content_hash(_record())

    record = _record(content_hash=expected.upper())

    assert record.content_hash == expected


def test_record_rejects_mismatched_content_hash() -> None:
    """A supplied hash that disagrees with the content is rejected."""
    with pytest.raises(ValidationError, match="content_hash does not match"):
        _record(content_hash="0" * 64)


@pytest.mark.parametrize("field", ["observed_at", "published_at", "retrieved_at"])
def test_naive_timestamps_are_rejected(field: str) -> None:
    """Naive timestamps never enter the domain model."""
    with pytest.raises(ValidationError, match="timezone-aware"):
        _record(**{field: datetime(2026, 1, 1)})


def test_optional_timestamps_may_be_absent() -> None:
    """Optional timestamps pass through as None without validation."""

    record = _record(observed_at=None, published_at=None)

    assert record.observed_at is None
    assert record.published_at is None


def test_timestamps_are_normalized_to_utc() -> None:
    """Offset-aware timestamps are stored in their UTC form."""

    record = _record(
        observed_at=datetime(2026, 1, 1, 4, 0, tzinfo=_OFFSET),
        published_at=datetime(2026, 1, 1, 6, 0, tzinfo=_OFFSET),
    )

    assert record.observed_at == datetime(2026, 1, 1, 2, 0, tzinfo=UTC)
    assert record.published_at == datetime(2026, 1, 1, 4, 0, tzinfo=UTC)


def test_semantic_payload_excludes_nonsemantic_fields() -> None:
    """Only semantic fields participate in the payload and digest."""

    record = _record(
        raw_payload={"anything": "else"},
        metadata={"retrieved_by": "worker-1"},
        id=None,
    )

    assert set(record.semantic_payload()) == {
        "canonical_payload",
        "normalization_version",
        "observed_at",
        "published_at",
        "record_type",
    }
    assert (
        _record(
            raw_payload={"different": "raw"}, metadata={"other": "metadata"}
        ).content_hash
        == record.content_hash
    )


def test_semantic_change_alters_content_hash() -> None:
    """A changed observation timestamp changes the digest."""

    baseline = _record()

    changed = _record(observed_at=datetime(2026, 1, 2, tzinfo=UTC))

    assert changed.content_hash != baseline.content_hash


def test_content_hash_accepts_mapping_input() -> None:
    """The hash can be computed from plain mappings, not just models."""

    record = _record()

    mapping: dict[str, Any] = {
        "canonical_payload": {"domain": "example.com"},
        "normalization_version": 1,
        "observed_at": datetime(2026, 1, 1, tzinfo=UTC),
        "published_at": None,
        "record_type": "certificate",
    }

    assert source_record_content_hash(mapping) == record.content_hash
    assert semantic_source_record_payload(mapping) == record.semantic_payload()


def test_content_hash_normalizes_timestamp_strings() -> None:
    """ISO timestamp strings hash identically to datetime objects."""

    with_string: dict[str, Any] = {
        "canonical_payload": {"domain": "example.com"},
        "normalization_version": 1,
        "observed_at": "2026-01-01T00:00:00+00:00",
        "published_at": None,
        "record_type": "certificate",
    }
    with_datetime: dict[str, Any] = {
        "canonical_payload": {"domain": "example.com"},
        "normalization_version": 1,
        "observed_at": datetime(2026, 1, 1, tzinfo=UTC),
        "published_at": None,
        "record_type": "certificate",
    }

    assert source_record_content_hash(with_string) == source_record_content_hash(
        with_datetime
    )


def test_external_identity_is_source_owned() -> None:
    """The durable identity is the (source_id, source_record_id) pair."""

    record = _record(source_id="crt-sh", source_record_id="rec-7")

    assert record.external_identity == ("crt-sh", "rec-7")


@pytest.mark.parametrize(
    "overrides",
    [
        {"normalization_version": 0},
        {"normalization_version": -1},
        {"unexpected_field": "value"},
    ],
)
def test_invalid_record_fields_are_rejected(overrides: dict[str, Any]) -> None:
    """Version bounds and the closed schema are enforced."""
    with pytest.raises(ValidationError):
        _record(**overrides)


def test_canonical_json_bytes_is_deterministic() -> None:
    """Key order and whitespace never affect the canonical encoding."""
    first = canonical_json_bytes({"b": 1, "a": {"y": 2, "x": 3}})
    second = canonical_json_bytes({"a": {"x": 3, "y": 2}, "b": 1})
    assert first == second == b'{"a":{"x":3,"y":2},"b":1}'


def test_canonical_json_bytes_keeps_unicode_unescaped() -> None:
    """Non-ASCII text is encoded as UTF-8, not ASCII escapes."""
    assert canonical_json_bytes({"café": 1}) == '{"café":1}'.encode("utf-8")


def test_canonical_json_bytes_accepts_top_level_lists() -> None:
    """List roots serialize with the same canonical separators."""
    assert canonical_json_bytes([2, 1]) == b"[2,1]"


def test_canonical_json_bytes_rejects_non_json_values() -> None:
    """Canonical payloads cannot rely on process-specific string conversion."""

    payload = {"observed_at": datetime(2026, 1, 1, 12, 0, tzinfo=UTC)}

    with pytest.raises(ValueError, match="unsupported JSON value"):
        canonical_json_bytes(payload)


def test_canonical_json_bytes_rejects_nan() -> None:
    """Non-finite floats are never silently serialized."""
    with pytest.raises(ValueError):
        canonical_json_bytes({"score": float("nan")})


def test_source_record_nested_json_is_deeply_immutable() -> None:
    """Neither callers nor record holders can stale the semantic hash."""
    payload = {"nested": {"items": [1, 2]}}
    record = _record(canonical_payload=payload)
    expected_hash = record.content_hash

    payload["nested"]["items"].append(3)
    with pytest.raises(TypeError, match="immutable"):
        record.canonical_payload["nested"]["new"] = True

    assert record.content_hash == expected_hash
    assert source_record_content_hash(record) == expected_hash
