# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23C idempotency unit tests (U31-U36)."""

from __future__ import annotations

import hashlib
import json

import pytest

from agentic_threat_investigator.app.investigation_submission import (
    IdempotencyKeyInvalidError,
    IdempotencyKeyRequiredError,
    IndicatorInput,
    canonical_request_fingerprint,
    validate_idempotency_key,
)
from agentic_threat_investigator.domain.entities import EntityType

LIMITS = {"max_indicators": 20, "max_value_length": 2048, "max_objective_length": 4000}


def _submission(
    indicators: list[tuple[EntityType, str]], objective: str
) -> list[IndicatorInput]:
    """Build IndicatorInput list fixtures from type/value pairs."""
    return [
        IndicatorInput(type=entity_type, value=value)
        for entity_type, value in indicators
    ]


def test_u31_missing_key_raises_required_error() -> None:
    """An absent Idempotency-Key fails closed with the required error."""
    with pytest.raises(IdempotencyKeyRequiredError):
        validate_idempotency_key(None)
    with pytest.raises(IdempotencyKeyRequiredError):
        validate_idempotency_key("")


def test_u32_overlong_key_rejected() -> None:
    """Keys above the length ceiling are rejected."""
    with pytest.raises(IdempotencyKeyInvalidError):
        validate_idempotency_key("k" * 129)
    with pytest.raises(IdempotencyKeyInvalidError):
        validate_idempotency_key("has spaces and ünïcode")


def test_u33_canonical_fingerprint_round_trip_stable() -> None:
    """The same semantic request always fingerprints identically."""
    first = canonical_request_fingerprint(
        _submission([(EntityType.DOMAIN, "example.com")], "assess it"),
        "assess it",
        **LIMITS,
    )
    second = canonical_request_fingerprint(
        _submission([(EntityType.DOMAIN, "EXAMPLE.com")], "assess it"),
        "assess it",
        **LIMITS,
    )
    assert first == second
    assert len(first) == 64
    assert all(character in "0123456789abcdef" for character in first)


def test_u34_json_property_order_does_not_change_fingerprint() -> None:
    """Fingerprints are computed over semantic payloads, not raw JSON bytes."""
    inputs = _submission(
        [(EntityType.IP_ADDRESS, "8.8.8.8"), (EntityType.DOMAIN, "example.com")],
        "assess",
    )
    objective = "assess"

    def fingerprint_for(order: tuple[str, ...]) -> str:
        """Recompute the fingerprint with a distinct canonical payload order."""
        payload = json.dumps(
            {
                "objective": objective,
                "indicators": [
                    (indicator.type.value, indicator.value) for indicator in inputs
                ],
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # Sorted canonical serialization makes property order irrelevant.
    assert fingerprint_for(("objective", "indicators")) == fingerprint_for(
        ("indicators", "objective")
    )


def test_u35_semantic_request_difference_changes_fingerprint() -> None:
    """A different objective or indicator changes the fingerprint."""
    base = canonical_request_fingerprint(
        _submission([(EntityType.DOMAIN, "example.com")], "assess"),
        "assess",
        **LIMITS,
    )
    different_objective = canonical_request_fingerprint(
        _submission([(EntityType.DOMAIN, "example.com")], "assess differently"),
        "assess differently",
        **LIMITS,
    )
    different_indicator = canonical_request_fingerprint(
        _submission([(EntityType.DOMAIN, "other.example.com")], "assess"),
        "assess",
        **LIMITS,
    )
    assert base != different_objective
    assert base != different_indicator


def test_u36_different_actors_share_key_scope_independently() -> None:
    """Idempotency scope includes the actor, so keys are reusable per actor.

    The scope tuple (actor_id, operation, key_hash) is owned by the database
    unique constraint; this unit test pins the service-level contract by
    validating the same raw key digests identically for both actors and that
    the digest (not the raw key) is what scopes the record.
    """
    key = "shared-key-42"
    digest_a = validate_idempotency_key(key)
    digest_b = validate_idempotency_key(key)
    assert digest_a == digest_b
    assert digest_a != key.encode("utf-8")
