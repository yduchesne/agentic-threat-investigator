# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical bounded telemetry-attribute vocabulary (PR 29A).

Metric and decorative attributes are allowlist-first and bounded. High-
cardinality or content-bearing values (Evidence IDs, entity IDs,
investigation IDs, IP/domain/URL values, execution/message IDs, prompts,
model output, raw exception text) are rejected before any instrument is
touched, so a caller mistake can never leak unbounded identifiers or content
through monitoring.
"""

from __future__ import annotations

from collections.abc import Mapping

MAX_ATTRIBUTE_VALUE_LENGTH = 256
"""Upper bound for any telemetry attribute value produced by ATI helpers."""


class AttributeKeys:
    """Bounded, safe common attribute keys used by ATI telemetry.

    Only these keys (plus ATI vendor-neutral extensions added through the
    same review process) may be used as bounded decorator/metric attributes.
    """

    COMPONENT = "ati.component"
    OPERATION = "ati.operation"
    OUTCOME = "ati.outcome"
    DATASOURCE_SEMANTIC_FORMAT = "ati.datasource.semantic_format"
    CONSUMER = "ati.consumer"
    POSTGRES_REPOSITORY = "ati.postgres.repository"
    POSTGRES_OPERATION = "ati.postgres.operation"
    KAFKA_TOPIC = "ati.kafka.topic"
    KAFKA_CONSUMER_GROUP = "ati.kafka.consumer_group"
    PROVIDER = "ati.provider"
    AGENT = "ati.agent"


METRIC_ATTRIBUTE_ALLOWLIST: frozenset[str] = frozenset(
    {
        AttributeKeys.COMPONENT,
        AttributeKeys.OPERATION,
        AttributeKeys.OUTCOME,
        AttributeKeys.DATASOURCE_SEMANTIC_FORMAT,
        AttributeKeys.CONSUMER,
        AttributeKeys.POSTGRES_REPOSITORY,
        AttributeKeys.POSTGRES_OPERATION,
        AttributeKeys.KAFKA_TOPIC,
        AttributeKeys.KAFKA_CONSUMER_GROUP,
        AttributeKeys.PROVIDER,
        AttributeKeys.AGENT,
    }
)
"""The complete set of bounded keys permitted on telemetry attributes."""


PROHIBITED_METRIC_ATTRIBUTE_KEYS: frozenset[str] = frozenset(
    {
        "evidence_id",
        "entity_id",
        "investigation_id",
        "execution_id",
        "message_id",
        "ip",
        "domain",
        "url",
        "prompt",
        "response",
        "exception",
        "exception_message",
    }
)
"""Base names that are always rejected, regardless of qualification.

Both the bare name (``evidence_id``) and a fully-qualified form
(``ati.evidence_id``) are rejected because their base segment is prohibited.
"""


def _base_name(key: str) -> str:
    """Return the final dotted segment of a fully-qualified attribute key."""
    return key.rsplit(".", 1)[-1]


def validate_bounded_attributes(
    attributes: Mapping[str, str],
) -> dict[str, str]:
    """Validate a bounded attribute mapping (allowlist-first).

    Rejects non-allowlisted keys, keys whose base segment is a prohibited
    high-cardinality identifier, blank keys, and blank or over-long values.
    The returned mapping is a plain copy safe to attach to a span or metric
    instrument.
    """
    validated: dict[str, str] = {}
    for key, value in attributes.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("telemetry attribute keys must be non-blank strings")
        if _base_name(key) in PROHIBITED_METRIC_ATTRIBUTE_KEYS:
            raise ValueError(
                f"forbidden high-cardinality telemetry attribute key: {key}"
            )
        if key not in METRIC_ATTRIBUTE_ALLOWLIST:
            raise ValueError(f"telemetry attribute key not allowlisted: {key}")
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"telemetry attribute value must be a non-blank string: {key}"
            )
        if len(value) > MAX_ATTRIBUTE_VALUE_LENGTH:
            raise ValueError(f"telemetry attribute value too long: {key}")
        validated[key] = value
    return validated


__all__ = [
    "AttributeKeys",
    "MAX_ATTRIBUTE_VALUE_LENGTH",
    "METRIC_ATTRIBUTE_ALLOWLIST",
    "PROHIBITED_METRIC_ATTRIBUTE_KEYS",
    "validate_bounded_attributes",
]
