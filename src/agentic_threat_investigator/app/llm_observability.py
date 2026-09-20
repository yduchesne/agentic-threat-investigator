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

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass

from opentelemetry.trace import Status, StatusCode

from agentic_threat_investigator.app.llm import LlmClient, ResponseT
from agentic_threat_investigator.telemetry.attributes import (
    AttributeKeys,
    validate_bounded_attributes,
)
from agentic_threat_investigator.telemetry.metrics import (
    DURATION_UNIT,
    DurationMetrics,
    Metrics,
    get_counter,
    get_histogram,
)
from agentic_threat_investigator.telemetry.tracing import SpanNames, get_tracer

logger = logging.getLogger(__name__)

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


class ObservedLlmClient(LlmClient):
    """ATI-owned observing ``LlmClient`` wrapper (PR 29B).

    Composes the existing contracts exactly once per actual model attempt:

    .. code-block:: text

        Agent
         -> ObservedLlmClient
              -> ati.llm.invoke span + duration
              -> LlmObservability.observe(LlmObservation)
              -> existing LlmClient delegate

    One actual ``generate_structured()`` call equals one OTel LLM span plus
    one selected LLM-observability observation plus one delegate invocation.
    Only bounded safe metadata (operation name plus the bounded configured
    model/provider/profile/prompt-version values) is ever recorded; prompts,
    model output, Evidence facts, and investigation IDs are never captured.
    ``asyncio.CancelledError`` propagates unchanged and the ``LlmError``
    taxonomy of the delegate is preserved; observability/backend export
    failures remain fail-open by the adapters' contract.
    """

    def __init__(
        self,
        delegate: LlmClient,
        observability: LlmObservability,
        *,
        model_provider: str | None = None,
        model_name: str | None = None,
        model_profile: str | None = None,
        prompt_version: str | None = None,
    ) -> None:
        """Bind the delegate, the selected backend, and bounded model metadata.

        The model metadata fields are bounded, code/deployment-controlled
        values (never prompts, outputs, or IDs) that every observation reuses;
        they are validated lazily at decoration time through
        :func:`validate_llm_observation`.
        """
        self._delegate = delegate
        self._observability = observability
        self._model_provider = model_provider
        self._model_name = model_name
        self._model_profile = model_profile
        self._prompt_version = prompt_version

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Generate one schema-validated structured output through the wrapper.

        Opens one ``ati.llm.invoke`` span (with the bounded per-call
        ``ati.operation`` attribute), records one seconds duration histogram,
        and counts one failure on any ordinary delegate exception. The
        selected observability backend observes the same single attempt with
        safe metadata only. Cancellation propagates without telemetry and the
        delegate's typed ``LlmError`` is re-raised unchanged.
        """
        if not operation_name.strip():
            raise ValueError("operation_name must not be blank")
        observation = LlmObservation(
            operation_name=operation_name,
            model_provider=self._model_provider,
            model_name=self._model_name,
            model_profile=self._model_profile,
            prompt_version=self._prompt_version,
        )
        validate_llm_observation(observation)
        attributes = validate_bounded_attributes(
            {AttributeKeys.OPERATION: operation_name}
        )
        tracer = get_tracer()
        histogram = get_histogram(DurationMetrics.LLM_INVOKE, unit=DURATION_UNIT)
        failures = get_counter(Metrics.LLM_INVOKE_FAILURES)
        start = time.perf_counter()
        with tracer.start_as_current_span(
            SpanNames.LLM_INVOKE, attributes=attributes
        ) as span:
            try:
                # Backend entry is fail-open: a defective adapter must never
                # fail, retry, or otherwise alter the model call.
                try:
                    observe_cm: AbstractContextManager[None] = (
                        self._observability.observe(observation)
                    )
                except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary
                    logger.debug("LLM observability could not start observation")
                    observe_cm = nullcontext()
                with observe_cm:
                    result = await self._delegate.generate_structured(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_model=response_model,
                        operation_name=operation_name,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                failures.add(1, attributes)
                histogram.record(
                    time.perf_counter() - start,
                    attributes={**attributes, AttributeKeys.OUTCOME: "error"},
                )
                raise
            else:
                histogram.record(
                    time.perf_counter() - start,
                    attributes={**attributes, AttributeKeys.OUTCOME: "success"},
                )
                return result


__all__ = [
    "LlmObservation",
    "LlmObservability",
    "MAX_LLM_METADATA_FIELD_LENGTH",
    "ObservedLlmClient",
    "validate_llm_observation",
]
