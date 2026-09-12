# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapters for the durable investigation job and idempotency.

The durable job's claim/completion transitions are owned by the versioned
SQL functions (``FOR UPDATE SKIP LOCKED``); Python never mutates the job
table directly. Idempotency records are plain operational rows inserted with
``ON CONFLICT DO NOTHING`` so the unique ``(actor_id, operation, key_hash)``
scope owns race safety.
"""

from dataclasses import replace
from datetime import datetime
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    IdempotencyRecord,
    IdempotencyRepository,
    InvestigationJobDuplicateError,
    InvestigationJobNotClaimedError,
    InvestigationJobNotFoundError,
    InvestigationJobRepository,
)
from agentic_threat_investigator.domain.investigation_job import (
    InvestigationJob,
    InvestigationJobStatus,
)

from .errors import sqlstate
from .models import ApiIdempotencyRow, InvestigationJobRow

SQLSTATE_JOB_NOT_FOUND = "U23C1"
SQLSTATE_JOB_NOT_CLAIMED = "U23C2"
SQLSTATE_JOB_INVALID_STATUS = "U23C3"


class InvestigationJobInvalidStatusError(ValueError):
    """Raised when a durable job status transition is rejected."""


class PostgresInvestigationJobRepository(InvestigationJobRepository):
    """Durable investigation job adapter over one active session."""

    def __init__(self, session: AsyncSession) -> None:
        """Bind the job repository to the caller's transaction session."""
        self._session = session

    async def create(self, job: InvestigationJob) -> InvestigationJob:
        """Create one durable pending job in the caller's transaction."""
        try:
            result = await self._session.execute(
                text(
                    "SELECT * FROM ati.create_investigation_job(:p_id, :p_created_at)"
                ),
                {"p_id": job.investigation_id, "p_created_at": job.created_at},
            )
        except DBAPIError as error:
            self._raise_from_dbapi(error, investigation_id=job.investigation_id)
            raise  # pragma: no cover - _raise_from_dbapi always raises
        row = result.first()
        if row is None:  # pragma: no cover - the function always returns a row
            raise AssertionError("create_investigation_job returned no row")
        return self._job_from_values(row[0], row[1], row[2], row[3], None, None, None)

    async def get_by_investigation(
        self, investigation_id: UUID
    ) -> InvestigationJob | None:
        """Return the durable job of one Investigation, if any."""
        row = (
            await self._session.execute(
                select(InvestigationJobRow).where(
                    InvestigationJobRow.investigation_id == investigation_id
                )
            )
        ).scalar_one_or_none()
        return None if row is None else self._domain(row)

    async def claim_next(self, claimed_at: datetime) -> InvestigationJob | None:
        """Atomically claim the oldest pending job, if any."""
        result = await self._session.execute(
            text("SELECT * FROM ati.claim_next_investigation_job(:p_claimed_at)"),
            {"p_claimed_at": claimed_at},
        )
        row = result.first()
        if row is None:
            return None
        return self._job_from_values(
            row[0], row[1], row[2], row[3], row[4], row[5], row[6]
        )

    async def complete(
        self,
        job_id: UUID,
        status: InvestigationJobStatus,
        completed_at: datetime,
        error_code: str | None = None,
    ) -> InvestigationJob:
        """Complete a claimed job as succeeded or failed."""
        try:
            result = await self._session.execute(
                text(
                    "SELECT * FROM ati.complete_investigation_job("
                    ":p_id, :p_status, :p_completed_at, :p_error_code)"
                ),
                {
                    "p_id": job_id,
                    "p_status": status.value,
                    "p_completed_at": completed_at,
                    "p_error_code": error_code,
                },
            )
        except DBAPIError as error:
            self._raise_from_dbapi(error)
            raise  # pragma: no cover - _raise_from_dbapi always raises
        row = result.first()
        if row is None:  # pragma: no cover - the function returns or raises
            raise AssertionError("complete_investigation_job returned no row")
        # complete_investigation_job returns (id, investigation_id, status,
        # completed_at); claimed_at/error_code are re-read from the row.
        job = await self.get_by_investigation(row[1])
        if job is None:  # pragma: no cover - the completed job must exist
            raise InvestigationJobNotFoundError("durable investigation job is absent")
        return job

    @staticmethod
    def _job_from_values(
        id_value: UUID,
        investigation_id: UUID,
        status: str,
        created_at: datetime,
        claimed_at: datetime | None,
        completed_at: datetime | None,
        error_code: str | None,
    ) -> InvestigationJob:
        """Map a stored-function result tuple to the domain model."""
        return InvestigationJob(
            id=id_value,
            investigation_id=investigation_id,
            status=InvestigationJobStatus(status),
            created_at=created_at,
            claimed_at=claimed_at,
            completed_at=completed_at,
            error_code=error_code,
        )

    @staticmethod
    def _domain(row: InvestigationJobRow) -> InvestigationJob:
        """Map a job row to the framework-independent domain model."""
        return InvestigationJob(
            id=row.id,
            investigation_id=row.investigation_id,
            status=InvestigationJobStatus(row.status),
            created_at=row.created_at,
            claimed_at=row.claimed_at,
            completed_at=row.completed_at,
            error_code=row.error_code,
        )

    @staticmethod
    def _raise_from_dbapi(
        error: BaseException, *, investigation_id: UUID | None = None
    ) -> None:
        """Translate a typed job SQLSTATE into the application error."""
        state = sqlstate(error)
        if state == SQLSTATE_JOB_NOT_FOUND:
            raise InvestigationJobNotFoundError(
                "durable investigation job is absent"
            ) from error
        if state == SQLSTATE_JOB_NOT_CLAIMED:
            raise InvestigationJobNotClaimedError(
                "investigation job is not claimed by a worker"
            ) from error
        if state == SQLSTATE_JOB_INVALID_STATUS:
            raise InvestigationJobInvalidStatusError(
                "investigation job status transition is invalid"
            ) from error
        # A duplicate investigation_id job violates the unique constraint and
        # is never an update of the prior job.
        if getattr(getattr(error, "orig", None), "sqlstate", None) == "23505":
            raise InvestigationJobDuplicateError(
                investigation_id or UUID("00000000-0000-0000-0000-000000000000")
            ) from error


class PostgresIdempotencyRepository(IdempotencyRepository):
    """Actor-scoped idempotency records over one active session."""

    def __init__(self, session: AsyncSession) -> None:
        """Bind the idempotency repository to the caller's transaction session."""
        self._session = session

    async def insert_if_absent(
        self, record: IdempotencyRecord
    ) -> IdempotencyRecord | None:
        """Insert unless the actor/operation/key scope already exists."""
        stmt = (
            pg_insert(ApiIdempotencyRow)
            .values(
                actor_id=record.actor_id,
                operation=record.operation,
                key_hash=record.key_hash,
                request_fingerprint=record.request_fingerprint,
                resource_type=record.resource_type,
                resource_id=record.resource_id,
                created_at=record.created_at,
            )
            .on_conflict_do_nothing(
                index_elements=["actor_id", "operation", "key_hash"]
            )
            .returning(ApiIdempotencyRow.id)
        )
        result = await self._session.execute(stmt)
        row = result.first()
        if row is None:
            return None
        return replace(record, id=row[0])

    async def get(
        self, *, actor_id: UUID, operation: str, key_hash: bytes
    ) -> IdempotencyRecord | None:
        """Return the existing record for one actor/operation/key scope."""
        row = (
            await self._session.execute(
                select(ApiIdempotencyRow).where(
                    ApiIdempotencyRow.actor_id == actor_id,
                    ApiIdempotencyRow.operation == operation,
                    ApiIdempotencyRow.key_hash == key_hash,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        return IdempotencyRecord(
            id=row.id,
            actor_id=row.actor_id,
            operation=row.operation,
            key_hash=row.key_hash,
            request_fingerprint=row.request_fingerprint,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            created_at=row.created_at,
        )
