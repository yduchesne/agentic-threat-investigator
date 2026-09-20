# SPDX-License-Identifier: AGPL-3.0-only
"""PostgresUnitOfWork transaction-lifetime telemetry tests (PR 29A-1).

Exercises the UoW instrumentation against a deterministic fake
SQLAlchemy-like session: the composite-registration step is neutralized and
the database helper seams are wired to the shared in-memory tracer/meter.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import cast

import pytest
from opentelemetry.sdk.metrics.export import InMemoryMetricReader, Metric
from opentelemetry.trace import StatusCode
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.domain.audit import AuditAction, AuditOutcome
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.telemetry.metrics import Metrics
from tests.support.otel import (
    counter_value,
    data_point_attributes,
    histogram_count,
    histogram_sum,
    metrics_by_name,
)


class _RawDriverConnection:
    """Minimal driver connection stand-in for composite registration."""

    driver_connection: object = None


class _ConnectionAdapter:
    """Minimal SQLAlchemy connection adapter used by ``__aenter__``."""

    async def get_raw_connection(self) -> _RawDriverConnection:
        """Return the raw driver connection stand-in."""
        return _RawDriverConnection()


class FakeSession:
    """Deterministic AsyncSession-like double supporting the UoW lifecycle."""

    def __init__(
        self,
        *,
        fail_begin: bool = False,
        fail_commit: bool = False,
        fail_rollback: bool = False,
    ) -> None:
        """Initialize the counters and the injected failure seams."""
        self.fail_begin = fail_begin
        self.fail_commit = fail_commit
        self.fail_rollback = fail_rollback
        self.begin_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.close_calls = 0
        self.added: list[object] = []

    async def begin(self) -> None:
        """Record one begin or fail when scripted."""
        self.begin_calls += 1
        if self.fail_begin:
            raise RuntimeError("begin failed")

    async def commit(self) -> None:
        """Record one commit or fail when scripted."""
        self.commit_calls += 1
        if self.fail_commit:
            raise RuntimeError("commit failed")

    async def rollback(self) -> None:
        """Record one rollback or fail when scripted."""
        self.rollback_calls += 1
        if self.fail_rollback:
            raise RuntimeError("rollback failed")

    async def close(self) -> None:
        """Record one session close."""
        self.close_calls += 1

    async def connection(self) -> _ConnectionAdapter:
        """Return the fixed connection adapter."""
        return _ConnectionAdapter()

    def add(self, row: object) -> None:
        """Record an ORM add (used by simple repository operations)."""
        self.added.append(row)

    async def flush(self) -> None:
        """No-op flush for simple repository operations."""

    async def execute(self, *args: object, **kwargs: object) -> object:
        """Unused repository surface; raise to expose accidental use."""
        del args, kwargs
        raise AssertionError("no SQL may execute in UoW telemetry unit tests")


def _uow(session: FakeSession) -> PostgresUnitOfWork:
    """Build a real PostgresUnitOfWork bound to the fake session."""
    factory = cast(async_sessionmaker[AsyncSession], lambda: session)
    return PostgresUnitOfWork(session_factory=factory)


def _uow_duration(reader: InMemoryMetricReader) -> Metric:
    """Return the recorded transaction-lifetime duration metric."""
    return metrics_by_name(reader)["ati.postgres.uow.duration"]


class TestUnitOfWorkOutcomes:
    """The four terminal UoW outcomes are observable (PG-U1..U4)."""

    @pytest.mark.asyncio
    async def test_success_commits(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A clean body commit records outcome=commit (PG-U1)."""
        session = FakeSession()
        async with _uow(session):
            pass
        assert session.commit_calls == 1
        reader = in_memory_persistence_telemetry.reader
        recorded = metrics_by_name(reader)
        assert (
            data_point_attributes(recorded["ati.postgres.uow.duration"])["ati.outcome"]
            == "commit"
        )
        assert counter_value(recorded[Metrics.POSTGRES_UOW_COMMITS]) == 1
        ops = recorded["ati.postgres.transaction_operation.duration"]
        assert histogram_count(ops) == 1
        assert data_point_attributes(ops)["ati.postgres.operation"] == "commit"
        assert data_point_attributes(ops)["ati.outcome"] == "success"

    @pytest.mark.asyncio
    async def test_body_exception_rolls_back(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A body exception rolls back and records outcome=rollback (PG-U2)."""
        session = FakeSession()

        async def _boom() -> None:
            raise RuntimeError("body failed")

        with pytest.raises(RuntimeError, match="body failed"):
            async with _uow(session):
                await _boom()
        assert session.rollback_calls == 1
        reader = in_memory_persistence_telemetry.reader
        recorded = metrics_by_name(reader)
        assert (
            data_point_attributes(recorded["ati.postgres.uow.duration"])["ati.outcome"]
            == "rollback"
        )
        assert counter_value(recorded[Metrics.POSTGRES_UOW_ROLLBACKS]) == 1

    @pytest.mark.asyncio
    async def test_commit_failure_records_failure(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A failing commit propagates and records outcome=failure (PG-U3)."""
        session = FakeSession(fail_commit=True)
        with pytest.raises(RuntimeError, match="commit failed"):
            async with _uow(session):
                pass
        reader = in_memory_persistence_telemetry.reader
        recorded = metrics_by_name(reader)
        assert (
            data_point_attributes(recorded["ati.postgres.uow.duration"])["ati.outcome"]
            == "failure"
        )
        assert counter_value(recorded[Metrics.POSTGRES_UOW_FAILURES]) == 1
        # The failing commit is also visible as a slow/failed COMMIT operation.
        ops = recorded["ati.postgres.transaction_operation.duration"]
        assert data_point_attributes(ops)["ati.outcome"] == "failure"
        # DB semantics unchanged: commit was attempted exactly once.
        assert session.commit_calls == 1
        # The span is marked as an error span.
        spans = in_memory_persistence_telemetry.exporter.get_finished_spans()
        assert spans[0].status.status_code is StatusCode.ERROR

    @pytest.mark.asyncio
    async def test_rollback_failure_preserves_exception_precedence(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A failing rollback records failure; exception precedence is unchanged (PG-U4)."""
        session = FakeSession(fail_rollback=True)

        async def _boom() -> None:
            raise RuntimeError("body failed")

        with pytest.raises(RuntimeError, match="rollback failed"):
            async with _uow(session):
                await _boom()
        reader = in_memory_persistence_telemetry.reader
        recorded = metrics_by_name(reader)
        assert (
            data_point_attributes(recorded["ati.postgres.uow.duration"])["ati.outcome"]
            == "failure"
        )
        assert counter_value(recorded[Metrics.POSTGRES_UOW_FAILURES]) == 1

    @pytest.mark.asyncio
    async def test_cancellation_rolls_back_and_records_cancelled(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Cancellation in the body propagates; outcome=cancelled (PG-U5)."""
        session = FakeSession()
        with pytest.raises(asyncio.CancelledError):
            async with _uow(session):
                raise asyncio.CancelledError()
        assert session.rollback_calls == 1
        reader = in_memory_persistence_telemetry.reader
        recorded = metrics_by_name(reader)
        assert (
            data_point_attributes(recorded["ati.postgres.uow.duration"])["ati.outcome"]
            == "cancelled"
        )
        span = in_memory_persistence_telemetry.exporter.get_finished_spans()[0]
        assert span.status.status_code is not StatusCode.ERROR


class TestExplicitCommitRollback:
    """Explicit commit()/rollback() are measured independently (PG-U6/U7)."""

    @pytest.mark.asyncio
    async def test_explicit_commit_measured(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """An explicit commit() records a commit transaction operation."""
        session = FakeSession()
        async with _uow(session) as uow:
            await uow.commit()
        reader = in_memory_persistence_telemetry.reader
        recorded = metrics_by_name(reader)
        ops = recorded["ati.postgres.transaction_operation.duration"]
        assert histogram_count(ops) == 2  # explicit + implicit exit commit
        assert data_point_attributes(ops)["ati.postgres.operation"] == "commit"

    @pytest.mark.asyncio
    async def test_explicit_rollback_measured(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """An explicit rollback() records a rollback transaction operation."""
        session = FakeSession()
        async with _uow(session) as uow:
            await uow.rollback()
        reader = in_memory_persistence_telemetry.reader
        points = metrics_by_name(reader)["ati.postgres.transaction_operation.duration"]
        # Explicit rollback in the body, then the clean exit commits.
        assert histogram_count(points) == 2
        assert data_point_attributes(points)["ati.postgres.operation"] in {
            "commit",
            "rollback",
        }


class TestSessionCloseNotInDuration:
    """Session cleanup is not reported as transaction duration (PG-U8)."""

    @pytest.mark.asyncio
    async def test_close_time_excluded_from_uow_duration(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A slow session close does not inflate the recorded transaction duration."""

        class _SlowCloseSession(FakeSession):
            """A fake session whose close() delays the event loop."""

            async def close(self) -> None:
                """Simulate slow connection cleanup."""
                await asyncio.sleep(0.1)
                self.close_calls += 1

        session = _SlowCloseSession()
        async with _uow(session):
            pass
        reader = in_memory_persistence_telemetry.reader
        duration = histogram_sum(_uow_duration(reader))
        assert duration < 0.05  # well below the 0.1s close delay


class TestNestedRepositoryInUnitOfWork:
    """Repository spans nest under the transaction-lifetime span (PG-U9)."""

    @pytest.mark.asyncio
    async def test_audit_repository_span_is_child_of_uow_span(
        self,
        in_memory_persistence_telemetry: SimpleNamespace,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A repository operation inside a UoW is a child of the UoW span."""
        from uuid import uuid4

        from agentic_threat_investigator.domain.audit import AuditEvent
        from agentic_threat_investigator.infrastructure.persistence.postgresql.audit_repositories import (
            PostgresAuditEventRepository,
        )

        session = FakeSession()
        event = AuditEvent(
            id=uuid4(),
            action=AuditAction.AUTH_LOGIN,
            outcome=AuditOutcome.SUCCESS,
            version=1,
        )
        # Map the fake ORM row straight back; the fake session performs no real
        # SQLAlchemy flush to populate row defaults.
        monkeypatch.setattr(
            PostgresAuditEventRepository,
            "_domain",
            staticmethod(lambda row: event.model_copy()),
        )

        async def _audit() -> None:
            async with _uow(session) as uow:
                await uow.audit_events.append(event)

        await _audit()
        spans = in_memory_persistence_telemetry.exporter.get_finished_spans()
        by_name = {s.name: s for s in spans}
        assert set(by_name) == {"ati.postgres.uow", "ati.postgres.repository"}
        repository_span = by_name["ati.postgres.repository"]
        assert repository_span.parent is not None
        assert (
            repository_span.parent.span_id
            == by_name["ati.postgres.uow"].context.span_id
        )
        assert (repository_span.attributes or {})["ati.postgres.operation"] == "append"
