# SPDX-License-Identifier: AGPL-3.0-only
"""Portable LLM-observability contract tests: metadata validation (PR 29A)."""

from __future__ import annotations

import pytest

from agentic_threat_investigator.app.llm_observability import (
    LlmObservation,
    validate_llm_observation,
)


def _safe_observation() -> LlmObservation:
    """Return a valid bounded observation."""
    return LlmObservation(
        operation_name="urn:ati:llm:evidence_analysis",
        model_provider="openai",
        model_name="gpt-4o-mini",
        model_profile="default",
        prompt_version="v1",
        investigation_id="inv-123",
    )


class TestLlmObservationValidation:
    """Safe observations pass; content-bearing metadata is rejected."""

    def test_safe_observation_accepted(self) -> None:
        """A bounded, content-free observation passes validation."""
        validate_llm_observation(_safe_observation())

    def test_blank_operation_name_rejected(self) -> None:
        """A blank operation name is rejected."""
        with pytest.raises(ValueError, match="operation_name"):
            validate_llm_observation(LlmObservation(operation_name="   "))

    def test_overlong_operation_name_rejected(self) -> None:
        """An over-long operation name is rejected."""
        with pytest.raises(ValueError, match="too long"):
            validate_llm_observation(LlmObservation(operation_name="x" * 5000))

    def test_content_bearing_control_character_rejected(self) -> None:
        """A content-bearing (control-character) name is rejected."""
        with pytest.raises(ValueError, match="control"):
            validate_llm_observation(
                LlmObservation(operation_name="urn:ati:llm:evidence\nuser prompt here")
            )

    def test_overlong_optional_metadata_rejected(self) -> None:
        """An over-long optional metadata field is rejected."""
        with pytest.raises(ValueError, match="model_name"):
            validate_llm_observation(
                LlmObservation(
                    operation_name="urn:ati:llm:evidence_analysis",
                    model_name="gpt-" + "x" * 5000,
                )
            )

    def test_optional_fields_may_be_absent(self) -> None:
        """Optional metadata fields may be left None."""
        validate_llm_observation(LlmObservation(operation_name="op"))
