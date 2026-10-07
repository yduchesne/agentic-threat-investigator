# SPDX-License-Identifier: AGPL-3.0-only
"""Provider-neutral LLM usage/accounting contract (PR 38-9).

This module is the single ATI-owned representation of authoritative LLM
token usage and the accounting context around one actual model attempt. It is
deliberately independent of any provider SDK: adapters normalize only usage
metadata the provider/framework actually reported, and missing fields remain
``None`` (unknown). Token counts are never estimated, cached/reasoning tokens
are never inferred, and provider response objects never escape
infrastructure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_SCOPE_URN_RE = re.compile(r"^urn:ati:llm:usage:[a-z0-9:_-]+$")
_MAX_BOUNDED_TEXT_LENGTH = 200


@dataclass(frozen=True)
class LlmUsage:
    """Authoritative token usage for one actual model attempt.

    Every field is optional: ``None`` means the provider did not
    authoritatively report that value. ATI never estimates tokens and never
    infers cached/reasoning tokens. ``total_tokens`` may be provider-reported;
    when a provider reports only components, ``total_tokens`` remains unknown
    rather than being silently derived unless the adapter can do so
    authoritatively.
    """

    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_tokens: int | None = None
    reasoning_tokens: int | None = None
    total_tokens: int | None = None

    def __post_init__(self) -> None:
        """Reject negative or non-integer token values."""
        for field_name in (
            "input_tokens",
            "output_tokens",
            "cached_tokens",
            "reasoning_tokens",
            "total_tokens",
        ):
            value = getattr(self, field_name)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{field_name} must be an integer or None")
            if value < 0:
                raise ValueError(f"{field_name} must not be negative")

    @property
    def has_any(self) -> bool:
        """Return whether any authoritative token value is present."""
        return any(
            value is not None
            for value in (
                self.input_tokens,
                self.output_tokens,
                self.cached_tokens,
                self.reasoning_tokens,
                self.total_tokens,
            )
        )


class LlmUsageScope(StrEnum):
    """Controlled ATI LLM usage-scope namespace.

    Scope URNs are semantic usage categories, deliberately mapped at the
    call site rather than generated from class names at runtime.
    """

    EVIDENCE_ANALYST = "urn:ati:llm:usage:investigations:scope:evidence_analyst"
    RESEARCH_AGENT = "urn:ati:llm:usage:investigations:scope:research_agent"
    REPORT_ANALYST = "urn:ati:llm:usage:investigations:scope:report_analyst"


def validate_scope_urn(scope_urn: str) -> str:
    """Validate a controlled usage scope URN and return it.

    Rejects blank, whitespace-padded, over-long, control-character-bearing, or
    out-of-namespace values so an arbitrary string can never become a metric
    dimension or durable scope.
    """
    if not scope_urn or scope_urn != scope_urn.strip():
        raise ValueError("LLM usage scope_urn must be a non-blank trimmed string")
    if len(scope_urn) > _MAX_BOUNDED_TEXT_LENGTH:
        raise ValueError("LLM usage scope_urn is too long")
    if any(ord(char) < 32 for char in scope_urn):
        raise ValueError("LLM usage scope_urn must not contain control characters")
    if _SCOPE_URN_RE.fullmatch(scope_urn) is None:
        raise ValueError("LLM usage scope_urn is outside the controlled namespace")
    return scope_urn


__all__ = [
    "LlmUsage",
    "LlmUsageScope",
    "validate_scope_urn",
]
