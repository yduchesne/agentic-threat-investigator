# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded telemetry-attribute policy tests (PR 29A)."""

from __future__ import annotations

import pytest

from agentic_threat_investigator.telemetry.attributes import (
    METRIC_ATTRIBUTE_ALLOWLIST,
    PROHIBITED_METRIC_ATTRIBUTE_KEYS,
    validate_bounded_attributes,
)


class TestAttributeAllowlist:
    """The bounded attribute vocabulary accepts only safe keys."""

    def test_bounded_allowed_attributes_accepted(self) -> None:
        """Allowlisted keys with bounded values pass validation."""
        attrs = {
            "ati.component": "evidence-analyst",
            "ati.operation": "ati.llm.invoke",
            "ati.outcome": "success",
            "ati.datasource.semantic_format": "json",
            "ati.consumer": "evidence-persistence",
            "ati.postgres.repository": "PostgresEvidenceBatchRepository",
            "ati.postgres.operation": "persist_batch",
            "ati.kafka.topic": "ati.evidence",
            "ati.kafka.consumer_group": "evidence-persistence",
            "ati.provider": "urn:ati:source:threatfox",
            "ati.agent": "research_agent",
        }
        assert validate_bounded_attributes(attrs) == attrs

    def test_allowlist_contains_only_ati_keys(self) -> None:
        """Every allowlisted key is a bounded ati.* identifier."""
        assert {
            "ati.component",
            "ati.operation",
            "ati.outcome",
            "ati.datasource.semantic_format",
            "ati.consumer",
            "ati.postgres.repository",
            "ati.postgres.operation",
            "ati.kafka.topic",
            "ati.kafka.consumer_group",
            "ati.provider",
            "ati.agent",
        } == METRIC_ATTRIBUTE_ALLOWLIST
        for key in METRIC_ATTRIBUTE_ALLOWLIST:
            assert key.startswith("ati.")

    def test_prohibited_base_names_are_never_allowlisted(self) -> None:
        """No prohibited high-cardinality key leaks into the allowlist."""
        assert set() == PROHIBITED_METRIC_ATTRIBUTE_KEYS & METRIC_ATTRIBUTE_ALLOWLIST

    @pytest.mark.parametrize(
        "key",
        [
            "evidence_id",
            "ati.evidence_id",
            "entity_id",
            "ati.entity_id",
            "investigation_id",
            "ati.investigation_id",
            "execution_id",
            "message_id",
            "ip",
            "domain",
            "url",
            "prompt",
            "response",
            "exception",
            "exception_message",
        ],
    )
    def test_high_cardinality_metric_attribute_rejected(self, key: str) -> None:
        """High-cardinality identifiers are rejected as telemetry attributes."""
        with pytest.raises(ValueError, match="forbidden|allowlisted"):
            validate_bounded_attributes({key: "value"})

    def test_non_allowlisted_key_rejected(self) -> None:
        """An unlisted key is rejected (allowlist-first policy)."""
        with pytest.raises(ValueError, match="not allowlisted"):
            validate_bounded_attributes({"ati.component_extra": "x"})

    def test_blank_value_rejected(self) -> None:
        """Blank attribute values are rejected."""
        with pytest.raises(ValueError, match="value"):
            validate_bounded_attributes({"ati.component": "   "})

    def test_overlong_value_rejected(self) -> None:
        """Over-long attribute values are rejected (bounds cardinality)."""
        with pytest.raises(ValueError, match="too long"):
            validate_bounded_attributes({"ati.component": "x" * 300})

    def test_blank_key_rejected(self) -> None:
        """Blank attribute keys are rejected."""
        with pytest.raises(ValueError, match="keys"):
            validate_bounded_attributes({"   ": "value"})
