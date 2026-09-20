# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL repository-operation telemetry decorator tests (PR 29A-1)."""

from __future__ import annotations

import asyncio

import pytest
from opentelemetry.trace import StatusCode

from agentic_threat_investigator.telemetry.decorators import (
    postgres_repository_operation,
)
from tests.support.otel import (
    counter_value,
    data_point_attributes,
    histogram_count,
    histogram_sum,
    metrics_by_name,
)

_REPOSITORY_DURATION = "ati.postgres.repository.duration"
_REPOSITORY_FAILURES = "ati.postgres.repository.failures"


class FakeTelemetryRepository:
    """A test-only repository whose public I/O methods carry real telemetry.

    Registered operations never collide with the real postgres package
    coverage test because the class lives outside the postgres package.
    """

    @postgres_repository_operation(
        repository="FakeTelemetryRepository", operation="read"
    )
    async def read(self) -> str:
        """A successful read-like operation."""
        return "ok"

    @postgres_repository_operation(
        repository="FakeTelemetryRepository", operation="write"
    )
    async def write(self) -> str:
        """A failing write-like operation."""
        raise RuntimeError("db boom")

    @postgres_repository_operation(
        repository="FakeTelemetryRepository", operation="cancel"
    )
    async def cancel(self) -> str:
        """A cancelled operation."""
        raise asyncio.CancelledError()

    @postgres_repository_operation(
        repository="FakeTelemetryRepository", operation="nested_inner"
    )
    async def nested_inner(self) -> str:
        """An inner read-like operation."""
        return "inner"

    @postgres_repository_operation(
        repository="FakeTelemetryRepository", operation="nested_outer"
    )
    async def nested_outer(self) -> str:
        """An outer operation calling an inner instrumented operation."""
        return await FakeTelemetryRepository().nested_inner()

    @postgres_repository_operation(
        repository="FakeTelemetryRepository", operation="sensitive"
    )
    async def sensitive(self, prompt: str, secret: str) -> str:
        """An operation that must never leak its arguments."""
        del prompt, secret
        return "done"


class TestRepositorySpan:
    """One repository operation maps to one bounded span plus duration."""

    @pytest.mark.asyncio
    async def test_success_produces_one_span_and_duration(
        self, in_memory_telemetry: object
    ) -> None:
        """A read success yields one span and one seconds histogram (PG-R1)."""
        repo = FakeTelemetryRepository()
        assert await repo.read() == "ok"
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert [s.name for s in spans] == ["ati.postgres.repository"]
        attrs = spans[0].attributes or {}
        assert attrs["ati.postgres.repository"] == "FakeTelemetryRepository"
        assert attrs["ati.postgres.operation"] == "read"
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        metric = recorded[_REPOSITORY_DURATION]
        assert metric.unit == "s"
        assert histogram_count(metric) == 1
        assert histogram_sum(metric) >= 0
        assert data_point_attributes(metric) == {
            "ati.postgres.repository": "FakeTelemetryRepository",
            "ati.postgres.operation": "read",
            "ati.outcome": "success",
        }
        assert _REPOSITORY_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_write_failure_propagates_and_counts(
        self, in_memory_telemetry: object
    ) -> None:
        """A DB exception propagates; failure telemetry is recorded (PG-R4)."""
        repo = FakeTelemetryRepository()
        with pytest.raises(RuntimeError, match="db boom"):
            await repo.write()
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert spans[0].status.status_code is StatusCode.ERROR
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        assert data_point_attributes(recorded[_REPOSITORY_DURATION])["ati.outcome"] == (
            "error"
        )
        assert counter_value(recorded[_REPOSITORY_FAILURES]) == 1

    @pytest.mark.asyncio
    async def test_cancellation_propagates_unchanged(
        self, in_memory_telemetry: object
    ) -> None:
        """Cancellation propagates and records no failure counter (PG-R5)."""
        repo = FakeTelemetryRepository()
        with pytest.raises(asyncio.CancelledError):
            await repo.cancel()
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        assert _REPOSITORY_FAILURES not in recorded
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert spans[0].status.status_code is not StatusCode.ERROR

    @pytest.mark.asyncio
    async def test_nested_operations_preserve_trace_parent_child(
        self, in_memory_telemetry: object
    ) -> None:
        """Nested repository operations form a parent/child trace (PG-R8)."""
        repo = FakeTelemetryRepository()
        assert await repo.nested_outer() == "inner"
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        by_name = {s.name: s for s in spans}
        assert set(by_name) == {"ati.postgres.repository"}
        by_op = {(s.attributes or {}).get("ati.postgres.operation"): s for s in spans}
        assert by_op["nested_inner"].parent is not None
        assert (
            by_op["nested_inner"].parent.span_id
            == by_op["nested_outer"].context.span_id
        )


class TestRepositoryPrivacy:
    """Repository telemetry carries only bounded static metadata."""

    @pytest.mark.asyncio
    async def test_sensitive_arguments_never_captured(
        self, in_memory_telemetry: object
    ) -> None:
        """Arguments/results are never attached to telemetry (PG-R6)."""
        repo = FakeTelemetryRepository()
        assert await repo.sensitive("user prompt content", "sk-super-secret") == "done"
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        attrs = spans[0].attributes or {}
        assert "user prompt content" not in str(attrs)
        assert "sk-super-secret" not in str(attrs)
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        rendered = str(recorded)
        assert "sk-super-secret" not in rendered
        assert "user prompt content" not in rendered

    @pytest.mark.asyncio
    async def test_high_cardinality_ids_absent_from_metric_labels(
        self, in_memory_telemetry: object
    ) -> None:
        """No Evidence/entity/investigation ID labels exist on metrics (PG-R7)."""
        repo = FakeTelemetryRepository()
        await repo.read()
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        metric = recorded[_REPOSITORY_DURATION]
        point_attrs = data_point_attributes(metric)
        for forbidden in ("evidence_id", "entity_id", "investigation_id"):
            assert not any(forbidden in key for key in point_attrs)
            assert not any(forbidden in str(value) for value in point_attrs.values())

    def test_blank_repository_or_operation_rejected(self) -> None:
        """Blank static metadata fails fast at decoration time."""
        with pytest.raises(ValueError, match="blank"):
            postgres_repository_operation(repository="   ", operation="read")
        with pytest.raises(ValueError, match="blank"):
            postgres_repository_operation(
                repository="PostgresEntityRepository", operation="   "
            )
