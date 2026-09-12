# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Minimal durable investigation job worker seam (PR 23C).

The API process persists a PENDING Investigation and its durable
PostgreSQL investigation job inside one transaction and returns ``202
Accepted``; it never runs the Investigation. :class:`InvestigationJobWorker`
is the minimum worker seam that proves the full boundary:

``POST -> persisted Investigation + job -> worker claim -> InvestigationRunner
-> terminal Investigation``

The worker claims one durable job atomically (``FOR UPDATE SKIP LOCKED``
through the versioned SQL API), invokes ``InvestigationRunner`` OUTSIDE any
database transaction, then durably marks the job succeeded or failed. It
never owns an in-memory queue, never uses FastAPI background tasks, and
never expands into PR 26 job administration/monitoring.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from agentic_threat_investigator.app.orchestration.runner import InvestigationRunner
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.investigation_job import (
    InvestigationJob,
    InvestigationJobStatus,
)

LOGGER = logging.getLogger(__name__)


class InvestigationJobWorker:
    """Claim and execute one durable investigation job at a time.

    The claim and the completion are each their own short transactions; the
    runner executes between them outside any enclosing transaction. A failed
    execution marks the job failed (with a bounded error code) and
    re-raises, so callers observe the failure.
    """

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        runner: InvestigationRunner,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the transaction factory and the production runner seam."""
        self._uow_factory = uow_factory
        self._runner = runner
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )

    async def claim_and_run_once(self) -> UUID | None:
        """Claim one pending job, execute it, and complete the job.

        Returns the executed Investigation ID, or ``None`` when no job was
        pending. The InvestigationRunner result is the authoritative terminal
        state; the job records only succeeded/failed completion.
        """
        now = self._clock()
        async with self._uow_factory() as uow:
            job = await uow.investigation_jobs.claim_next(now)
        if job is None:
            return None
        await self._run_job(job)
        return job.investigation_id

    async def _run_job(self, job: InvestigationJob) -> None:
        """Execute the claimed job through the production runner seam."""
        try:
            await self._runner.run(job.investigation_id)
        except BaseException as error:
            await self._mark_failed(job, error)
            raise
        await self._mark_succeeded(job)

    async def _mark_succeeded(self, job: InvestigationJob) -> None:
        """Durably complete the job as succeeded."""
        async with self._uow_factory() as uow:
            await uow.investigation_jobs.complete(
                job.id,
                InvestigationJobStatus.SUCCEEDED,
                self._clock(),
            )
        LOGGER.debug("completed investigation job %s", job.id)

    async def _mark_failed(self, job: InvestigationJob, error: BaseException) -> None:
        """Durably complete the job as failed with a bounded error code."""
        error_code = _bounded_error_code(type(error).__name__)
        async with self._uow_factory() as uow:
            await uow.investigation_jobs.complete(
                job.id,
                InvestigationJobStatus.FAILED,
                self._clock(),
                error_code=error_code,
            )
        LOGGER.warning("investigation job %s failed: %s", job.id, error_code)

    async def run_until_empty(self, *, max_rounds: int = 1000) -> int:
        """Claim and execute jobs until the queue is empty.

        Returns the number of executed jobs. ``max_rounds`` bounds a runaway
        queue for tests; the production worker loop is owned by deployment
        (PR 26), not by this seam.
        """
        executed = 0
        for _ in range(max_rounds):
            if await self.claim_and_run_once() is None:
                break
            executed += 1
        return executed


def _bounded_error_code(exception_name: str) -> str:
    """Derive a bounded snake-case error code from an exception class name.

    The code is an operational marker only: it never embeds messages, SQL
    text, provider payloads, or stack traces.
    """
    lowered = (
        "".join(
            "_" if character.isupper() else character for character in exception_name
        )
        .lower()
        .strip("_")
    )
    if not lowered:
        return "worker_failed"
    return f"worker_{lowered[:63]}"
