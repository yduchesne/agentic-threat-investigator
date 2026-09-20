# SPDX-License-Identifier: AGPL-3.0-only
"""ObservedLlmClient tests (PR 29B, A6..A13).

Proves the common ATI observing wrapper: one actual ``generate_structured``
call equals one OTel ``ati.llm.invoke`` span + one selected backend
observation + one delegate invocation; cancellation and the delegate's typed
``LlmError`` are preserved; prompts/outputs are never captured; token counts
are never fabricated; backend failures stay fail-open; and the NoOp backend
exports nothing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from opentelemetry.sdk.metrics.export import Metric
from pydantic import BaseModel

from agentic_threat_investigator.app.llm import LlmClient, LlmError, LlmErrorCode
from agentic_threat_investigator.app.llm_observability import (
    LlmObservability,
    LlmObservation,
    ObservedLlmClient,
)
from agentic_threat_investigator.infrastructure.observability.noop import (
    NoOpLlmObservability,
)
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.otel import (
    counter_value,
    data_point_attributes,
    histogram_count,
    metrics_by_name,
)


class _Outcome(BaseModel):
    """Minimal structured output model for the tests."""

    verdict: str


class _RecordingDelegate(LlmClient):
    """Delegate recording calls and returning/raising scripted outcomes."""

    def __init__(
        self, result: Any | None = None, error: LlmError | None = None
    ) -> None:
        """Bind the scripted result or typed error."""
        self.result = result
        self.error = error
        self.calls: list[dict[str, object]] = []

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        operation_name: str,
    ) -> Any:
        """Record the safe metadata and return or raise the scripted outcome."""
        self.calls.append(
            {
                "operation_name": operation_name,
                "response_model": response_model,
            }
        )
        if self.error is not None:
            raise self.error
        if self.result is None:
            return _Outcome(verdict="inconclusive")
        return self.result


class _RecordingObservability(LlmObservability):
    """Deterministic backend double recording observation lifecycles."""

    def __init__(self) -> None:
        """Start with no observations."""
        self.observations: list[LlmObservation] = []

    @contextmanager
    def observe(self, observation: LlmObservation) -> Iterator[None]:
        """Record the observation and yield."""
        self.observations.append(observation)
        yield


class _BoomObservability(LlmObservability):
    """A fail-open backend whose observation entry fails."""

    @contextmanager
    def observe(self, observation: LlmObservation) -> Iterator[None]:
        """Raise immediately, as a broken backend might."""
        del observation
        raise RuntimeError("backend export failed")


def _wrapper(
    delegate: LlmClient,
    observability: LlmObservability,
    *,
    model_name: str = "gpt-4o-mini",
    model_provider: str = "openai",
) -> ObservedLlmClient:
    """Build one observed client over the double seams."""
    return ObservedLlmClient(
        delegate,
        observability,
        model_provider=model_provider,
        model_name=model_name,
    )


def _recorded(telemetry: SimpleNamespace) -> dict[str, Metric]:
    """Return recorded metrics indexed by name."""
    return metrics_by_name(telemetry.reader)


def _spans(telemetry: SimpleNamespace) -> list[object]:
    """Return finished span names from the in-memory exporter."""
    return [span.name for span in telemetry.exporter.get_finished_spans()]


class TestObservedLlmClient:
    """One model attempt equals one span + one observation."""

    @pytest.mark.asyncio
    async def test_a6_success_one_span_one_observation(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A successful attempt emits one LLM span and one observation (A6)."""
        delegate = _RecordingDelegate()
        backend = _RecordingObservability()
        client = _wrapper(delegate, backend)
        result = await client.generate_structured(
            system_prompt="system",
            user_prompt="user",
            response_model=_Outcome,
            operation_name="urn:ati:llm:evidence_analysis",
        )
        assert result.verdict == "inconclusive"
        assert len(delegate.calls) == 1
        assert len(backend.observations) == 1
        assert backend.observations[0].operation_name == "urn:ati:llm:evidence_analysis"
        assert backend.observations[0].model_name == "gpt-4o-mini"
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.llm.invoke") == 1
        recorded = _recorded(in_memory_persistence_telemetry)
        duration = recorded[DurationMetrics.LLM_INVOKE]
        assert histogram_count(duration) == 1
        assert data_point_attributes(duration)["ati.operation"] == (
            "urn:ati:llm:evidence_analysis"
        )
        assert Metrics.LLM_INVOKE_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_a7_llm_error_preserved(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """The delegate's typed LlmError is re-raised unchanged (A7)."""
        delegate = _RecordingDelegate(
            error=LlmError(LlmErrorCode.TIMEOUT, retryable=False)
        )
        client = _wrapper(delegate, _RecordingObservability())
        with pytest.raises(LlmError) as holder:
            await client.generate_structured(
                system_prompt="s",
                user_prompt="u",
                response_model=_Outcome,
                operation_name="urn:ati:llm:evidence_analysis",
            )
        assert holder.value.code is LlmErrorCode.TIMEOUT
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.LLM_INVOKE_FAILURES]) == 1
        duration = recorded[DurationMetrics.LLM_INVOKE]
        assert data_point_attributes(duration)["ati.outcome"] == "error"

    @pytest.mark.asyncio
    async def test_a8_cancellation_propagates(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Cancellation propagates unchanged with no failure telemetry (A8)."""

        class _CancelDelegate(LlmClient):
            """A delegate that cancels."""

            async def generate_structured(
                self,
                *,
                system_prompt: str,
                user_prompt: str,
                response_model: type[BaseModel],
                operation_name: str,
            ) -> Any:
                del system_prompt, user_prompt, response_model, operation_name
                raise asyncio.CancelledError()

        client = _wrapper(_CancelDelegate(), _RecordingObservability())
        with pytest.raises(asyncio.CancelledError):
            await client.generate_structured(
                system_prompt="s",
                user_prompt="u",
                response_model=_Outcome,
                operation_name="urn:ati:llm:evidence_analysis",
            )
        recorded = _recorded(in_memory_persistence_telemetry)
        assert Metrics.LLM_INVOKE_FAILURES not in recorded
        assert DurationMetrics.LLM_INVOKE not in recorded

    @pytest.mark.asyncio
    async def test_a11_prompt_and_output_never_captured(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Prompts and model output never appear in spans or observations (A11)."""
        delegate = _RecordingDelegate()
        backend = _RecordingObservability()
        client = _wrapper(delegate, backend)
        await client.generate_structured(
            system_prompt="SECRET-PROMPT",
            user_prompt="SECRET-USER",
            response_model=_Outcome,
            operation_name="urn:ati:llm:evidence_analysis",
        )
        assert backend.observations[0].model_name != "SECRET-PROMPT"
        spans = in_memory_persistence_telemetry.exporter.get_finished_spans()
        for span in spans:
            for attribute in (span.attributes or {}).values():
                assert "SECRET" not in str(attribute)

    @pytest.mark.asyncio
    async def test_a12_backend_failure_is_fail_open(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A broken backend never fails the model call (A12)."""
        delegate = _RecordingDelegate()
        client = _wrapper(delegate, _BoomObservability())
        result = await client.generate_structured(
            system_prompt="s",
            user_prompt="u",
            response_model=_Outcome,
            operation_name="urn:ati:llm:evidence_analysis",
        )
        assert result.verdict == "inconclusive"
        assert len(delegate.calls) == 1

    @pytest.mark.asyncio
    async def test_a13_no_fabricated_token_metrics(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """No token metric is ever emitted (A13)."""
        delegate = _RecordingDelegate()
        client = _wrapper(delegate, _RecordingObservability())
        await client.generate_structured(
            system_prompt="s",
            user_prompt="u",
            response_model=_Outcome,
            operation_name="urn:ati:llm:evidence_analysis",
        )
        recorded = _recorded(in_memory_persistence_telemetry)
        assert not any("token" in name for name in recorded)

    @pytest.mark.asyncio
    async def test_a10_noop_backend_exports_nothing(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """The NoOp backend performs no vendor export and never raises (A10)."""
        delegate = _RecordingDelegate()
        client = _wrapper(delegate, NoOpLlmObservability())
        result = await client.generate_structured(
            system_prompt="s",
            user_prompt="u",
            response_model=_Outcome,
            operation_name="urn:ati:llm:evidence_analysis",
        )
        assert result.verdict == "inconclusive"
        assert len(delegate.calls) == 1
