# SPDX-License-Identifier: AGPL-3.0-only
"""LangChain structured-output adapter for the ATI ``LlmClient`` boundary.

The adapter depends on an injected LangChain ``BaseChatModel``; it never
constructs a provider-specific model, reads configuration or environment
variables, persists anything, or retries hidden behind the documented policy.
Structured output uses the framework's native ``with_structured_output``
path with explicit ``method="function_calling"`` steering (never OpenAI
native ``json_schema`` mode): the analyst schema uses ``oneOf`` across
complex nested items, which native structured outputs reject on
OpenAI-compatible providers while function calling is accepted. Manual
prose JSON parsing is deliberately never used.

Provider/framework failures are mapped to the bounded ``LlmError`` taxonomy
with safe, content-free messages: prompts, model output, raw exception text,
and credentials never appear in errors, and mapped errors never retain the
raw provider/framework exception as their public cause. Every mapped raise
therefore uses ``from None``. ``asyncio.CancelledError`` always propagates
unchanged.

Automatic content-bearing LangSmith/LangChain tracing is disabled for the
invocation via the installed langsmith tracing context (``enabled=False``);
safe operation metadata is prepared locally, but prompts, Evidence facts,
and structured output are never exported. See ``docs/OBSERVABILITY.md``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import httpx
from langchain_core.exceptions import (
    ModelAPIError,
    ModelAuthenticationError,
    ModelConnectionError,
    ModelError,
    ModelInvalidRequestError,
    ModelNotFoundError,
    ModelPermissionDeniedError,
    ModelRateLimitError,
    ModelTimeoutError,
    OutputParserException,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from langsmith import tracing_context
from pydantic import ValidationError

from agentic_threat_investigator.app.llm import (
    LlmClient,
    LlmError,
    LlmErrorCode,
    LlmInvocationResult,
    ResponseT,
)
from agentic_threat_investigator.app.llm_usage import LlmUsage

# Metadata keys permitted in the local runnable configuration. Only
# non-content keys may ever be emitted; prompts, Evidence facts, model
# output, and exception strings are content and stay local. ``operation``
# is derived exclusively from the per-call ``operation_name`` argument so it
# can never become stale constructor state.
_TRACE_METADATA_KEYS = ("investigation_id",)


def _metadata_int(metadata: Mapping[str, object], key: str) -> int | None:
    """Return a non-negative integer metadata value, or ``None`` when absent."""
    value = metadata.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def _extract_usage_metadata(raw_message: object) -> LlmUsage | None:
    """Normalize framework-reported usage metadata into ATI ``LlmUsage``.

    Only values actually reported by the framework are captured; absent fields
    remain ``None`` (unknown). Cached/reasoning tokens are read only from the
    framework's explicit detail maps and are never inferred. The raw message
    object never escapes this adapter, and ``None`` means no authoritative
    usage was reported.
    """
    metadata = getattr(raw_message, "usage_metadata", None)
    if not isinstance(metadata, Mapping):
        return None
    input_details = metadata.get("input_token_details")
    output_details = metadata.get("output_token_details")
    usage = LlmUsage(
        input_tokens=_metadata_int(metadata, "input_tokens"),
        output_tokens=_metadata_int(metadata, "output_tokens"),
        total_tokens=_metadata_int(metadata, "total_tokens"),
        cached_tokens=(
            _metadata_int(input_details, "cache_read")
            if isinstance(input_details, Mapping)
            else None
        ),
        reasoning_tokens=(
            _metadata_int(output_details, "reasoning")
            if isinstance(output_details, Mapping)
            else None
        ),
    )
    return usage if usage.has_any else None


class LangChainLlmClient(LlmClient):
    """Generate typed structured output through an injected chat model.

    Each ``generate_structured`` invocation performs exactly one model
    attempt; bounded structured-output repair is the application service's
    explicit, accounted policy.
    """

    def __init__(
        self,
        chat_model: BaseChatModel,
        *,
        trace_tags: tuple[str, ...] = (),
        trace_metadata: Mapping[str, str] | None = None,
    ) -> None:
        """Bind the injected chat model and the optional local metadata.

        ``trace_metadata`` contributes only the documented non-content keys
        (for example ``investigation_id``); any other key is rejected so
        content can never leak into the runnable configuration by accident.
        """
        if trace_metadata is not None:
            unknown = set(trace_metadata) - set(_TRACE_METADATA_KEYS)
            if unknown:
                raise ValueError(
                    "unexpected LLM trace metadata keys: "
                    + ", ".join(sorted(str(key) for key in unknown))
                )
        self._chat_model = chat_model
        self._trace_tags = tuple(trace_tags)
        self._trace_metadata = dict(trace_metadata or {})

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Return one validated instance of ``response_model``.

        Compatibility wrapper around :meth:`generate_structured_with_usage`
        that discards the normalized usage; one call still performs exactly
        one model attempt.
        """
        result = await self.generate_structured_with_usage(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            operation_name=operation_name,
        )
        return result.output

    async def generate_structured_with_usage(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> LlmInvocationResult[ResponseT]:
        """Return one validated instance plus any authoritative provider usage.

        ``operation_name`` must be non-blank and becomes the ``operation``
        metadata field; it is derived from this argument only. The framework's
        structured-output runnable is created and invoked inside one protected
        block so no setup-time or invocation-time provider/framework
        exception can escape the ``LlmError`` taxonomy. A returned object that
        is not the expected Pydantic type, or any schema/parse failure, is
        mapped to ``INVALID_STRUCTURED_OUTPUT`` rather than being trusted.

        Provider/framework usage metadata is normalized once into the
        ATI-owned :class:`LlmUsage`; when the provider reports nothing
        authoritative, ``usage`` is ``None``. Token counts are never
        estimated and no raw provider object escapes this adapter.
        """
        if not operation_name.strip():
            raise ValueError("operation_name must not be blank")
        config: RunnableConfig = {}
        if self._trace_tags:
            config["tags"] = list(self._trace_tags)
        metadata = dict(self._trace_metadata)
        metadata["operation"] = operation_name
        config["metadata"] = metadata
        try:
            # Automatic content-bearing LangSmith tracing would record the
            # message list and model outputs; PR 20B has no approved
            # content-capture opt-in, so the invocation runs with tracing
            # disabled at the framework level. Safe metadata stays local.
            # Structured outputs use explicit function-calling steering
            # (``method="function_calling"``), not the OpenAI native
            # ``json_schema`` mode that became the langchain-openai 0.3+
            # default: the analyst schema uses ``oneOf`` across complex
            # nested items, which native structured outputs reject (400)
            # on OpenAI-compatible providers, while function calling is
            # rejected by neither OpenAI nor OpenRouter-compatible vendors.
            # ``include_raw=True`` surfaces only the framework usage metadata;
            # the raw message never escapes this adapter.
            with tracing_context(enabled=False):
                runnable = self._chat_model.with_structured_output(
                    response_model, method="function_calling", include_raw=True
                )
                raw_result = await runnable.ainvoke(
                    [
                        SystemMessage(content=system_prompt),
                        HumanMessage(content=user_prompt),
                    ],
                    config=config or None,
                )
        except asyncio.CancelledError:
            # Cooperative cancellation must propagate unchanged; the
            # try/except exists only to prevent the error mapping below.
            raise
        except asyncio.TimeoutError, ModelTimeoutError, httpx.TimeoutException:
            raise LlmError(LlmErrorCode.TIMEOUT, retryable=False) from None
        except (
            ModelAuthenticationError,
            ModelPermissionDeniedError,
            ModelInvalidRequestError,
        ):
            raise LlmError(LlmErrorCode.CONFIGURATION_ERROR, retryable=False) from None
        except OutputParserException, ValidationError:
            raise LlmError(
                LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True
            ) from None
        except (
            ModelRateLimitError,
            ModelNotFoundError,
            ModelConnectionError,
            ModelAPIError,
            ModelError,
            httpx.HTTPError,
        ):
            # Conservative mapped failure: the bounded message carries only
            # the stable category, never provider error text.
            raise LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False) from None
        except Exception:  # noqa: BLE001 - unexpected failures map to the stable provider category
            # Any unexpected transport/framework failure becomes the stable
            # provider category; nothing provider-specific escapes this seam.
            raise LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False) from None

        parsed, raw_message = self._split_structured_result(raw_result, response_model)
        if not isinstance(parsed, response_model):
            raise LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True)
        return LlmInvocationResult(
            output=parsed, usage=_extract_usage_metadata(raw_message)
        )

    @staticmethod
    def _split_structured_result(
        raw_result: object, response_model: type[ResponseT]
    ) -> tuple[object, object]:
        """Split an ``include_raw=True`` result without trusting provider objects.

        Real LangChain returns ``{"raw": ..., "parsed": ..., "parsing_error":
        ...}``; deterministic fakes may return the parsed model directly. A
        non-null parsing error is mapped to the bounded invalid-output error.
        """
        del response_model  # reserved for future schema-specific diagnostics
        if isinstance(raw_result, Mapping) and "parsed" in raw_result:
            if raw_result.get("parsing_error") is not None:
                raise LlmError(
                    LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True
                ) from None
            return raw_result.get("parsed"), raw_result.get("raw")
        return raw_result, None
