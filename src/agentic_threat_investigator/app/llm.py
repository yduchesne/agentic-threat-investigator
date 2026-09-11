# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-owned typed LLM operation boundary.

This is the narrow, provider-neutral LLM seam used by application services.
It is structured-output only: every operation supplies an explicit ATI-owned
Pydantic ``response_model`` and receives an instance of exactly that type.
No provider-specific response object, chat history, configuration read,
persistence call, or hidden retry escapes this boundary.

LLM failures are typed and bounded. Messages never contain prompts, model
output, raw provider exceptions, credentials, or arbitrary provider error
strings; they are safe to propagate into application logs and errors.
``asyncio.CancelledError`` always propagates unchanged so cooperative
cancellation is never swallowed by error mapping.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import TypeVar

from pydantic import BaseModel

ResponseT = TypeVar("ResponseT", bound=BaseModel)
"""Type variable bound to ATI Pydantic output models."""


class LlmErrorCode(str, Enum):
    """Stable categories for typed LLM operation failures.

    The v0.1 taxonomy is deliberately small. Finer-grained provider
    categories (for example rate limiting or content refusal) remain
    future work; PR 20B maps them conservatively rather than exposing
    provider-specific detail.
    """

    TIMEOUT = "timeout"
    """The model operation exceeded the configured bounded timeout."""

    PROVIDER_FAILURE = "provider_failure"
    """The provider failed while serving the operation."""

    INVALID_STRUCTURED_OUTPUT = "invalid_structured_output"
    """The provider response could not be validated as the requested model."""

    CONFIGURATION_ERROR = "configuration_error"
    """The LLM was misconfigured or the provider rejected the configuration."""


class LlmError(RuntimeError):
    """A typed LLM operation failure with a stable code and retryability flag.

    ``retryable`` expresses the documented transport/schema retry policy:
    only ``INVALID_STRUCTURED_OUTPUT`` (and, at the caller's conservative
    discretion, configured transient ``PROVIDER_FAILURE``) may be retried.
    Authentication/configuration failures and cancellation are never retried.
    """

    def __init__(self, code: LlmErrorCode, *, retryable: bool = False) -> None:
        """Initialize with the stable category and retryability decision."""
        super().__init__(f"LLM operation failed: {code.value}")
        self.code = code
        self.retryable = retryable


class LlmClient(ABC):
    """Generate one schema-validated structured output from a model.

    Implementations are single-attempt transports: bounded structured-output
    repair is the application service's explicit, accounted policy, never a
    hidden adapter loop. No implementation may read environment/configuration
    directly, persist anything, or execute tools.
    """

    @abstractmethod
    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Return an instance of ``response_model`` or raise ``LlmError``.

        ``operation_name`` is a stable ATI operation identifier used for
        observable metadata (never for prompt content). Implementations map
        provider/framework failures to ``LlmError`` categories with bounded,
        safe messages and propagate cancellation unchanged.
        """
