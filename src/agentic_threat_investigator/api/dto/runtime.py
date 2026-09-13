# SPDX-License-Identifier: AGPL-3.0-only
"""Public runtime-info DTOs (PR 23D).

The runtime endpoint exposes the selected intelligence-source composition
mode only. It never exposes provider credentials, secret reference names,
LLM provider identities, database URLs, filesystem paths, or the effective
configuration, and it never claims the LLM is fake merely because the
operating mode is ``fake``.
"""

from pydantic import BaseModel, ConfigDict, Field


class RuntimeInfoResponse(BaseModel):
    """Safe public runtime composition metadata for the analyst frontend.

    ``operating_mode`` is the lowercase ``fake``/``production`` value; PR 24
    uses it to display a persistent ``FAKE DATA`` indicator without
    hard-coding frontend deployment knowledge.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    operating_mode: str = Field(min_length=1)

    @classmethod
    def from_operating_mode(cls, value: str) -> "RuntimeInfoResponse":
        """Build the response from a validated lowercase operating mode."""
        normalized = value.strip().lower()
        if normalized not in ("fake", "production"):
            raise ValueError("operating_mode must be fake or production")
        return cls(operating_mode=normalized)
