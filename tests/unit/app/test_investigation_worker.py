# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the durable investigation job worker seam (PR 23C).

The worker claims one durable job, invokes the InvestigationRunner outside
any transaction, and durably completes the job. These tests prove the
``202 -> job -> worker -> Runner -> terminal Investigation`` boundary with
deterministic fakes; no real provider, LLM, or database is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.investigation_worker import (
    InvestigationJobWorker,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_job import (
    InvestigationJob,
    InvestigationJobStatus,
)

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


class FakeJobsRepository:
    """Record claim/completion transitions."""

    def __init__(self, pending: list[InvestigationJob] | None = None) -> None:
        """Bind the pending queue and the completed transitions."""
        self.pending = list(pending or [])
        self.completed: list[tuple[UUID, InvestigationJobStatus]] = []
        self.claims = 0

    async def claim_next(self, claimed_at: datetime) -> InvestigationJob | None:
        """Claim the first pending job (one attempt per call)."""
        self.claims += 1
        if not self.pending:
            return None
        return self.pending.pop(0)

    async def complete(
        self,
        job_id: UUID,
        status: InvestigationJobStatus,
        completed_at: datetime,
        error_code: str | None = None,
    ) -> InvestigationJob:
        """Record the completion transition."""
        self.completed.append((job_id, status))
        return InvestigationJob(
            id=job_id,
            investigation_id=job_id,
            status=status,
            created_at=FIXED_NOW,
            completed_at=completed_at,
            error_code=error_code,
        )


class FakeUnitOfWork:
    """In-memory transaction boundary exposing the jobs repository."""

    def __init__(self, jobs: FakeJobsRepository | None = None) -> None:
        """Bind the jobs repository fake."""
        self.investigation_jobs = jobs or FakeJobsRepository()

    async def __aenter__(self) -> "FakeUnitOfWork":
        """Enter the transaction."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit the transaction (no-op)."""


class FakeRunner:
    """Deterministic InvestigationRunner double."""

    def __init__(self, fail: bool = False) -> None:
        """Bind the failure mode and the invocation history."""
        self.fail = fail
        self.ran: list[UUID] = []

    async def run(self, investigation_id: UUID) -> InvestigationState:
        """Record the invocation; optionally fail."""
        self.ran.append(investigation_id)
        if self.fail:
            raise RuntimeError("provider exploded")
        return InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.COMPLETED,
            trigger_type=InvestigationTriggerType.API,
            root_entity_ids=[],
            objective="assess",
            budget=default_investigation_budget(),
            started_at=FIXED_NOW,
            created_at=FIXED_NOW,
            completed_at=FIXED_NOW,
            version=2,
        )


def _job(investigation_id: UUID | None = None) -> InvestigationJob:
    """Build one pending job fixture."""
    return InvestigationJob(
        id=uuid4(),
        investigation_id=investigation_id or uuid4(),
        status=InvestigationJobStatus.PENDING,
        created_at=FIXED_NOW,
    )


def _worker(jobs: FakeJobsRepository, runner: FakeRunner) -> InvestigationJobWorker:
    """Build the worker over the fakes with a fixed clock."""
    return InvestigationJobWorker(
        cast(Any, lambda: FakeUnitOfWork(jobs)),
        cast(Any, runner),
        clock=lambda: FIXED_NOW,
    )


@pytest.mark.asyncio
async def test_worker_claims_runs_and_completes_one_job() -> None:
    """One claim -> Runner -> succeeded completion is the happy path."""
    job = _job()
    jobs = FakeJobsRepository([job])
    runner = FakeRunner()
    worker = _worker(jobs, runner)

    executed = await worker.claim_and_run_once()

    assert executed == job.investigation_id
    assert runner.ran == [job.investigation_id]
    assert jobs.claims == 1
    assert jobs.completed == [(job.id, InvestigationJobStatus.SUCCEEDED)]


@pytest.mark.asyncio
async def test_worker_marks_failed_when_runner_raises() -> None:
    """A failing runner durably marks the job failed and re-raises."""
    job = _job()
    jobs = FakeJobsRepository([job])
    runner = FakeRunner(fail=True)
    worker = _worker(jobs, runner)

    with pytest.raises(RuntimeError):
        await worker.claim_and_run_once()

    assert jobs.completed == [(job.id, InvestigationJobStatus.FAILED)]


@pytest.mark.asyncio
async def test_worker_returns_none_when_queue_empty() -> None:
    """An empty pending queue yields no execution."""
    jobs = FakeJobsRepository([])
    worker = _worker(jobs, FakeRunner())

    assert await worker.claim_and_run_once() is None
    assert jobs.claims == 1


@pytest.mark.asyncio
async def test_worker_run_until_empty_executes_all_jobs() -> None:
    """run_until_empty drains the durable queue deterministically."""
    jobs = FakeJobsRepository([_job(), _job(), _job()])
    runner = FakeRunner()
    worker = _worker(jobs, runner)

    executed = await worker.run_until_empty()

    assert executed == 3
    assert len(runner.ran) == 3
    assert all(
        status is InvestigationJobStatus.SUCCEEDED for _, status in jobs.completed
    )
