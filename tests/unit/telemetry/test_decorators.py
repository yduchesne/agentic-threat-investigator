# SPDX-License-Identifier: AGPL-3.0-only
"""Decorator-first telemetry tests: sync/async, errors, cancellation, timing (PR 29A)."""

from __future__ import annotations

import asyncio
import time

import pytest
from opentelemetry.trace import StatusCode

from agentic_threat_investigator.telemetry.decorators import (
    telemetry_operation,
    timed,
    traced,
)
from tests.support.otel import (
    data_point_attributes,
    histogram_count,
    histogram_sum,
    metrics_by_name,
)

_SENTINEL = {"secret-prompt": "super-secret-content", "api_key": "sk-leak"}


def _sync_success() -> str:
    """A sync function used by traced tests."""
    return "ok"


def _sync_failure() -> str:
    """A sync function that raises."""
    raise RuntimeError("boom")


async def _async_success() -> str:
    """An async function used by traced tests."""
    return "ok"


async def _async_failure() -> str:
    """An async function that raises."""
    raise RuntimeError("boom")


async def _async_cancel() -> str:
    """An async function that cancels."""
    raise asyncio.CancelledError()


class TestTraced:
    """Span creation preserves application semantics."""

    def test_sync_success_one_span(self, in_memory_telemetry: object) -> None:
        """A traced sync success produces one span and returns unchanged."""
        wrapped = traced(span_name="ati.llm.invoke")(_sync_success)
        assert wrapped() == "ok"
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert [s.name for s in spans] == ["ati.llm.invoke"]
        assert spans[0].status.status_code is StatusCode.UNSET

    @pytest.mark.asyncio
    async def test_async_success_one_span(self, in_memory_telemetry: object) -> None:
        """A traced async success produces one span and returns unchanged."""
        wrapped = traced(span_name="ati.llm.invoke")(_async_success)
        assert await wrapped() == "ok"
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert [s.name for s in spans] == ["ati.llm.invoke"]

    def test_sync_exception_propagates_and_records_error(
        self, in_memory_telemetry: object
    ) -> None:
        """A sync exception propagates and is recorded on the span."""
        wrapped = traced(span_name="ati.llm.invoke")(_sync_failure)
        with pytest.raises(RuntimeError, match="boom"):
            wrapped()
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert len(spans) == 1
        assert spans[0].status.status_code is StatusCode.ERROR

    @pytest.mark.asyncio
    async def test_async_exception_propagates_and_records_error(
        self, in_memory_telemetry: object
    ) -> None:
        """An async exception propagates and is recorded on the span."""
        wrapped = traced(span_name="ati.llm.invoke")(_async_failure)
        with pytest.raises(RuntimeError, match="boom"):
            await wrapped()
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert len(spans) == 1
        assert spans[0].status.status_code is StatusCode.ERROR

    @pytest.mark.asyncio
    async def test_cancellation_propagates_unchanged(
        self, in_memory_telemetry: object
    ) -> None:
        """CancelledError propagates unchanged and is not recorded as an error."""
        wrapped = traced(span_name="ati.llm.invoke")(_async_cancel)
        with pytest.raises(asyncio.CancelledError):
            await wrapped()
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert len(spans) == 1
        assert spans[0].status.status_code is not StatusCode.ERROR

    @pytest.mark.asyncio
    async def test_nested_spans_preserve_parent_child(
        self, in_memory_telemetry: object
    ) -> None:
        """Nested traced calls form a correct parent/child relationship."""
        traced_outer = traced(span_name="ati.evidence.persist")(_async_success)
        traced_inner = traced(span_name="ati.evidence.convert")(_async_success)

        @traced(span_name="ati.investigation.execute")
        async def outer() -> str:
            await traced_inner()
            return await traced_outer()

        assert await outer() == "ok"
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        by_name = {s.name: s for s in spans}
        assert set(by_name) == {
            "ati.investigation.execute",
            "ati.evidence.persist",
            "ati.evidence.convert",
        }
        assert by_name["ati.evidence.persist"].parent is not None
        assert (
            by_name["ati.evidence.persist"].parent.span_id
            == by_name["ati.investigation.execute"].context.span_id
        )

    def test_disabled_noop_keeps_behavior(self) -> None:
        """Without a provider, traced functions still behave identically."""
        wrapped = traced(span_name="ati.llm.invoke")(_sync_success)
        assert wrapped() == "ok"

    def test_forbidden_metric_attribute_rejected_before_execution(self) -> None:
        """A forbidden static attribute fails fast at decoration time."""
        with pytest.raises(ValueError, match="forbidden|allowlisted"):
            traced(
                span_name="ati.llm.invoke",
                attributes={"ati.investigation_id": "inv-1"},
            )

    def test_no_args_or_results_captured(self, in_memory_telemetry: object) -> None:
        """Arguments/results never leak into span attributes."""

        @traced(span_name="ati.llm.invoke")
        def sensitive(arg: dict[str, str], secret: str) -> dict[str, str]:
            del arg, secret
            return _SENTINEL

        sensitive({"system_prompt": "you are an analyst"}, "pk-super-secret")
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        attrs = spans[0].attributes or {}
        assert "secret-prompt" not in attrs
        assert "sk-leak" not in str(attrs)
        assert "secret" not in attrs

    def test_wraps_preserves_metadata(self) -> None:
        """functools.wraps preserves __name__/__doc__ on the wrapper."""

        def documented() -> str:
            """Original docstring."""
            return "x"

        wrapped = traced(span_name="ati.llm.invoke")(documented)
        assert wrapped.__name__ == "documented"
        assert wrapped.__doc__ == "Original docstring."

    def test_blank_span_name_rejected(self) -> None:
        """A blank span name fails fast at decoration time."""
        with pytest.raises(ValueError, match="span_name"):
            traced(span_name="   ")

    def test_sync_cancellation_propagates(self, in_memory_telemetry: object) -> None:
        """A sync callable raising CancelledError propagates it unchanged."""

        def cancel() -> None:
            raise asyncio.CancelledError()

        wrapped = traced(span_name="ati.llm.invoke")(cancel)
        with pytest.raises(asyncio.CancelledError):
            wrapped()
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert len(spans) == 1
        assert spans[0].status.status_code is not StatusCode.ERROR


class TestTimed:
    """Duration measurement for sync and async callables."""

    @pytest.mark.asyncio
    async def test_timed_success_records_seconds(
        self, in_memory_telemetry: object
    ) -> None:
        """A timed async success records a seconds histogram with success outcome."""
        wrapped = timed(metric="ati.evidence.persist.duration")(_async_success)
        assert await wrapped() == "ok"
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        metric = recorded["ati.evidence.persist.duration"]
        assert metric.unit == "s"
        assert histogram_count(metric) == 1
        assert histogram_sum(metric) >= 0
        assert data_point_attributes(metric) == {"ati.outcome": "success"}

    @pytest.mark.asyncio
    async def test_timed_failure_records_error_outcome(
        self, in_memory_telemetry: object
    ) -> None:
        """A timed async failure records duration with the error outcome."""
        wrapped = timed(metric="ati.evidence.persist.duration")(_async_failure)
        with pytest.raises(RuntimeError, match="boom"):
            await wrapped()
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        metric = recorded["ati.evidence.persist.duration"]
        assert histogram_count(metric) == 1
        assert data_point_attributes(metric) == {"ati.outcome": "error"}

    @pytest.mark.asyncio
    async def test_timed_cancellation_records_nothing(
        self, in_memory_telemetry: object
    ) -> None:
        """Cancellation propagates and records no duration measurement."""
        wrapped = timed(metric="ati.evidence.persist.duration")(_async_cancel)
        with pytest.raises(asyncio.CancelledError):
            await wrapped()
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        assert recorded == {}

    def test_timed_measurement_is_monotonic(self, in_memory_telemetry: object) -> None:
        """Duration uses time.perf_counter and is a nonnegative real value."""

        @timed(metric="ati.evidence.persist.duration")
        def slow() -> None:
            time.sleep(0.001)

        slow()
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        assert histogram_sum(recorded["ati.evidence.persist.duration"]) > 0

    def test_blank_duration_metric_rejected(self) -> None:
        """A blank duration metric fails fast at decoration time."""
        with pytest.raises(ValueError, match="metric"):
            timed(metric="   ")

    def test_duration_metric_must_use_duration_suffix(self) -> None:
        """A duration metric without the canonical suffix is rejected."""
        with pytest.raises(ValueError, match="duration"):
            timed(metric="ati.evidence.persist")

    def test_timed_sync_success(self, in_memory_telemetry: object) -> None:
        """A timed sync success records a seconds histogram."""

        @timed(metric="ati.evidence.persist.duration")
        def work() -> str:
            return "done"

        assert work() == "done"
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        metric = recorded["ati.evidence.persist.duration"]
        assert histogram_count(metric) == 1
        assert data_point_attributes(metric) == {"ati.outcome": "success"}

    def test_timed_sync_failure(self, in_memory_telemetry: object) -> None:
        """A timed sync failure records the error outcome and propagates."""

        @timed(metric="ati.evidence.persist.duration")
        def work() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            work()
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        assert data_point_attributes(recorded["ati.evidence.persist.duration"]) == {
            "ati.outcome": "error"
        }

    def test_timed_sync_cancellation_propagates(
        self, in_memory_telemetry: object
    ) -> None:
        """Cancellation in a timed sync callable propagates and records nothing."""

        @timed(metric="ati.evidence.persist.duration")
        def cancel() -> None:
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            cancel()
        assert metrics_by_name(in_memory_telemetry.reader) == {}  # type: ignore[attr-defined]


class TestTelemetryOperation:
    """The combined decorator composes exactly one span and one duration."""

    @pytest.mark.asyncio
    async def test_combined_exactly_one_span_and_one_duration(
        self, in_memory_telemetry: object
    ) -> None:
        """telemetry_operation yields exactly one span and one measurement."""

        @telemetry_operation(
            span_name="ati.evidence.persist",
            duration_metric="ati.evidence.persist.duration",
        )
        async def persist() -> str:
            return "committed"

        assert await persist() == "committed"
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert [s.name for s in spans] == ["ati.evidence.persist"]
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        assert list(recorded) == ["ati.evidence.persist.duration"]
        assert histogram_count(recorded["ati.evidence.persist.duration"]) == 1
