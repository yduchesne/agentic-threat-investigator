# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence persistence telemetry tests (PR 29B, EP1..EP4).

Proves the real ``EvidenceBatchPersistenceService.persist`` boundary emits
the ``ati.evidence.persist`` span, that the span nests over the PostgreSQL
UoW and repository spans, that failures preserve the existing rollback and
exception behavior, and that outcome counters are owned by the consumer
flow (never double-counted by the persistence service).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.evidence_batch_persistence import (
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_consumer import (
    prepare_evidence_batch,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidencePersistenceOutcome,
    PreparedEvidenceBatch,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.evidence_batch_fixtures import (
    message_batch,
    threatfox_message,
)
from tests.support.otel import histogram_count, metrics_by_name
from tests.unit.app.test_evidence_batch_persistence_service import (
    FakeBatchUnitOfWork,
    FakeEvidenceBatchRepository,
)
from tests.unit.infrastructure.test_postgres_unit_of_work_telemetry import (
    FakeSession,
)


def _prepared() -> PreparedEvidenceBatch:
    """Build one valid prepared batch from a real ThreatFox message."""
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id="ep-1",
        sequence=0,
    )
    return prepare_evidence_batch(message_batch((message,)))


def _spans(telemetry: SimpleNamespace) -> list[object]:
    """Return finished span names from the in-memory exporter."""
    return [span.name for span in telemetry.exporter.get_finished_spans()]


class TestPersistenceSpan:
    """EP1..EP3: the persist boundary is observable and nests correctly."""

    @pytest.mark.asyncio
    async def test_ep1_persist_span_present(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """The real persist service emits an ati.evidence.persist span (EP1)."""
        repository = FakeEvidenceBatchRepository()
        service = EvidenceBatchPersistenceService(
            lambda: FakeBatchUnitOfWork(repository)
        )
        result = await service.persist(_prepared())
        assert result.items[0].outcome is EvidencePersistenceOutcome.CREATED
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.evidence.persist") == 1
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert histogram_count(recorded[DurationMetrics.EVIDENCE_PERSIST]) == 1

    @pytest.mark.asyncio
    async def test_ep2_nesting_over_uow_and_repository(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """The persist span nests over the UoW and repository spans (EP2).

        The repository raises on the fake session (no SQL may execute), but
        the span nesting is emitted before any database work: the service
        span wraps the UoW transaction span which wraps the repository span.
        """
        session = FakeSession()
        uow_factory = cast(async_sessionmaker[AsyncSession], lambda: session)
        service = EvidenceBatchPersistenceService(
            lambda: PostgresUnitOfWork(session_factory=uow_factory)
        )
        with pytest.raises(AssertionError, match="no SQL"):
            await service.persist(_prepared())
        spans = in_memory_persistence_telemetry.exporter.get_finished_spans()
        persist_span = next(s for s in spans if s.name == "ati.evidence.persist")
        uow_span = next(s for s in spans if s.name == "ati.postgres.uow")
        repo_span = next(s for s in spans if s.name == "ati.postgres.repository")
        assert uow_span.parent is not None
        assert uow_span.parent.span_id == persist_span.context.span_id
        assert repo_span.parent is not None
        assert repo_span.parent.span_id == uow_span.context.span_id

    @pytest.mark.asyncio
    async def test_ep3_failure_preserves_rollback_and_exception(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A repository failure rolls back and propagates unchanged (EP3)."""
        repository = FakeEvidenceBatchRepository()
        repository.fail = RuntimeError("persist failed")
        uow = FakeBatchUnitOfWork(repository)
        service = EvidenceBatchPersistenceService(lambda: uow)
        with pytest.raises(RuntimeError, match="persist failed"):
            await service.persist(_prepared())
        assert uow.rolled_back == 1
        assert uow.committed == 0

    @pytest.mark.asyncio
    async def test_ep4_outcome_counters_not_duplicated(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """The persist service never emits outcome counters (EP4).

        Outcome counters belong to the consumer flow exactly once; calling
        the persistence service directly must not fabricate them.
        """
        repository = FakeEvidenceBatchRepository()
        service = EvidenceBatchPersistenceService(
            lambda: FakeBatchUnitOfWork(repository)
        )
        result = await service.persist(_prepared())
        assert len(result.items) == 1
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert Metrics.EVIDENCE_OUTCOMES_CREATED not in recorded
        assert Metrics.EVIDENCE_OUTCOMES_APPENDED not in recorded
        assert Metrics.EVIDENCE_OUTCOMES_UNCHANGED not in recorded
        assert Metrics.EVIDENCE_MESSAGES_PROCESSED not in recorded
