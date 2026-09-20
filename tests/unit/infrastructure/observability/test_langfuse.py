# SPDX-License-Identifier: AGPL-3.0-only
"""Langfuse v4 adapter isolation, privacy, and fail-open tests (PR 29A)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from langfuse import Langfuse
from langfuse._client.resource_manager import LangfuseResourceManager
from langfuse.span_filter import is_default_export_span
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from agentic_threat_investigator.app.llm_observability import LlmObservation
from agentic_threat_investigator.infrastructure.observability.langfuse import (
    LangfuseLlmObservability,
)

_INSTRUMENTATION_SCOPE = "agentic_threat_investigator"


@pytest.fixture(autouse=True)
def reset_langfuse_instances() -> Iterator[None]:
    """Clear the langfuse client singleton registry between tests.

    The registry is langfuse's own public class attribute keyed by public key;
    clearing it (plus per-test shutdown) keeps tests deterministic and
    order-independent without touching OpenTelemetry internals.
    """
    LangfuseResourceManager._instances.clear()
    yield
    LangfuseResourceManager._instances.clear()


def _safe_observation() -> LlmObservation:
    """Return a valid bounded observation."""
    return LlmObservation(
        operation_name="urn:ati:llm:evidence_analysis",
        model_provider="openai",
        model_name="gpt-4o-mini",
        investigation_id="inv-123",
    )


class TestLangfuseIsolation:
    """Langfuse export is isolated from ATI's general OTel span stream."""

    def test_unrelated_generic_span_not_exported_as_llm(self) -> None:
        """An ATI general span is never exported through Langfuse (LLMO13).

        An ATI-scoped span created through the same provider reaches the
        Langfuse span processor, whose default filter drops it; only the
        Langfuse observation is exported.
        """
        prefix = "pk-isolation"

        def _build() -> tuple[Langfuse, InMemorySpanExporter, TracerProvider]:
            exporter = InMemorySpanExporter()
            provider = TracerProvider()
            client = Langfuse(
                public_key=f"{prefix}-lc",
                secret_key="sk",
                base_url="https://cloud.langfuse.com",
                tracer_provider=provider,
                span_exporter=exporter,
            )
            return client, exporter, provider

        lf, exporter, provider = _build()
        try:
            # An unrelated ATI general span shares the same provider.
            general_tracer = trace.get_tracer(
                _INSTRUMENTATION_SCOPE, "0.1", tracer_provider=provider
            )
            with general_tracer.start_as_current_span("ati.llm.invoke"):
                pass
            assert len(exporter.get_finished_spans()) == 0

            observability = LangfuseLlmObservability(
                public_key=f"{prefix}-lc",
                secret_key="sk",
                client=lf,
            )
            with observability.observe(_safe_observation()):
                pass
            lf.flush()

            spans = exporter.get_finished_spans()
            assert len(spans) == 1
            # The Langfuse observation was exported; the unrelated span was not.
            assert spans[0].name == "urn:ati:llm:evidence_analysis"
            assert spans[0].instrumentation_scope is not None
            assert spans[0].instrumentation_scope.name != _INSTRUMENTATION_SCOPE
            assert is_default_export_span(spans[0]) is True
        finally:
            lf.shutdown()

    def test_ati_general_span_is_not_default_export(self) -> None:
        """An ATI general span is not a default Langfuse export candidate."""
        provider = TracerProvider()
        exporter = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = trace.get_tracer(
            _INSTRUMENTATION_SCOPE, "0.1", tracer_provider=provider
        )
        with tracer.start_as_current_span("ati.llm.invoke"):
            pass
        span = exporter.get_finished_spans()[0]
        assert is_default_export_span(span) is False


class TestLangfuseAdapter:
    """Privacy, validation, and fail-open behavior of the adapter."""

    def test_success_exports_safe_observation(self) -> None:
        """A successful observation exports bounded metadata and no content."""
        prefix = "pk-safe"

        def _build() -> tuple[Langfuse, InMemorySpanExporter]:
            exporter = InMemorySpanExporter()
            provider = TracerProvider()
            client = Langfuse(
                public_key=f"{prefix}-c",
                secret_key="sk",
                base_url="https://cloud.langfuse.com",
                tracer_provider=provider,
                span_exporter=exporter,
            )
            return client, exporter

        lf, exporter = _build()
        try:
            observability = LangfuseLlmObservability(
                public_key=f"{prefix}-c", secret_key="sk", client=lf
            )
            with observability.observe(_safe_observation()):
                pass
            lf.flush()
            spans = exporter.get_finished_spans()
            assert len(spans) == 1
            rendered = str(spans[0].attributes)
            assert "prompt" not in rendered.lower()
            assert "sk-" not in rendered
        finally:
            lf.shutdown()

    def test_content_bearing_observation_rejected(self) -> None:
        """A content-bearing observation is rejected before any export."""
        observability = LangfuseLlmObservability(public_key="pk-cb", secret_key="sk")
        with (
            pytest.raises(ValueError, match="control|operation_name"),
            observability.observe(
                LlmObservation(operation_name="op\nuser prompt content")
            ),
        ):
            pass

    def test_setup_failure_is_fail_open(self) -> None:
        """A backend setup failure never fails the application operation."""

        class _RaisingClient:
            """A langfuse-like client whose observation start always fails."""

            def start_as_current_observation(
                self, *args: object, **kwargs: object
            ) -> object:
                del args, kwargs
                raise RuntimeError("langfuse backend down")

        observability = LangfuseLlmObservability(
            public_key="pk-fail", secret_key="sk", client=_RaisingClient()
        )
        with observability.observe(_safe_observation()):
            assert True
