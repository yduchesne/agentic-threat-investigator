# SPDX-License-Identifier: AGPL-3.0-only
"""Portable LLM/agent observability application boundary (PR 29A).

This is the ATI-owned seam between application code and user-selectable LLM
observability backends (LangSmith, Langfuse, or NoOp). It is deliberately
separate from :class:`agentic_threat_investigator.app.llm.LlmClient`: model
invocation and observability have different ownership, and this contract never
requires prompt/output content. The contract and metadata are backend-neutral;
the application layer never imports LangSmith or Langfuse.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from dataclasses import dataclass

MAX_LLM_METADATA_FIELD_LENGTH = 200
"""Upper bound for any portable LLM-observability metadata field."""


@dataclass(frozen=True)
class LlmObservation:
    """Bounded, content-free metadata for one LLM/agent observability operation.

    Only safe, bounded values are permitted; prompts, model output, Evidence
    facts, retrieved content, raw provider responses, credentials, and hidden
    reasoning are never representable here.
    """

    operation_name: str
    model_provider: str | None = None
    model_name: str | None = None
    model_profile: str | None = None
    prompt_version: str | None = None
    investigation_id: str | None = None


def _validate_optional_field(field: str, value: str | None) -> None:
    """Reject unbounded or content-bearing optional metadata values."""
    if value is None or value == "":
        return
    if len(value) > MAX_LLM_METADATA_FIELD_LENGTH:
        raise ValueError(f"{field} exceeds the maximum LLM metadata field length")
    if any(ord(char) < 32 for char in value):
        raise ValueError(f"{field} must not contain control characters")


def validate_llm_observation(observation: LlmObservation) -> None:
    """Validate that an observation carries only bounded, safe metadata.

    A blank ``operation_name``, over-long fields, or control characters are
    rejected so no unbounded or content-bearing value can reach a backend.
    """
    if not observation.operation_name or not observation.operation_name.strip():
        raise ValueError("LLM observation operation_name must be non-blank")
    if len(observation.operation_name) > MAX_LLM_METADATA_FIELD_LENGTH:
        raise ValueError("LLM observation operation_name is too long")
    if any(ord(char) < 32 for char in observation.operation_name):
        raise ValueError(
            "LLM observation operation_name must not contain control characters"
        )
    _validate_optional_field("model_provider", observation.model_provider)
    _validate_optional_field("model_name", observation.model_name)
    _validate_optional_field("model_profile", observation.model_profile)
    _validate_optional_field("prompt_version", observation.prompt_version)
    _validate_optional_field("investigation_id", observation.investigation_id)


class LlmObservability(ABC):
    """Record a portable LLM/agent observability operation lifecycle.

    ``observe`` returns a context manager whose scope covers one LLM/agent
    operation. Implementations are fail-open: a backend failure must never
    fail, retry, or otherwise alter the application-facing operation, and
    cancellation always propagates unchanged. Implementations never capture
    prompt/model output content by default.
    """

    @abstractmethod
    def observe(self, observation: LlmObservation) -> AbstractContextManager[None]:
        """Open an LLM-observability operation scope for ``observation``.

        ``observation`` must pass :func:`validate_llm_observation`. The
        returned context manager should be entered by the caller around the
        LLM/agent operation it describes.
        """


__all__ = [
    "LlmObservation",
    "LlmObservability",
    "MAX_LLM_METADATA_FIELD_LENGTH",
    "validate_llm_observation",
]
