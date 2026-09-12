# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Durable investigation-level job domain contract (PR 23C).

``POST /api/v1/investigations`` persists a PENDING Investigation together
with its durable ``InvestigationJob`` in one transaction and returns
``202 Accepted``; the FastAPI process never runs the Investigation. A worker
claims the pending job (``pending -> claimed``) and later completes it as
``succeeded`` or ``failed`` after invoking ``InvestigationRunner``.

The job is deliberately a minimal durable scheduler record: it carries
operational identifiers and lifecycle timestamps only. Job administration,
monitoring, retry policy, and scheduling vocabulary belong to PR 26 and are
not modelled here. The domain model carries no repository, SQL, HTTP, or
orchestration dependency.
"""

import re
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


class InvestigationJobStatus(str, Enum):
    """Lifecycle statuses of one durable investigation job."""

    PENDING = "pending"
    CLAIMED = "claimed"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


_TERMINAL_JOB_STATUSES: frozenset[InvestigationJobStatus] = frozenset(
    {
        InvestigationJobStatus.SUCCEEDED,
        InvestigationJobStatus.FAILED,
    }
)


def is_terminal_job_status(status: InvestigationJobStatus) -> bool:
    """Return whether a job status admits no further transitions."""
    return status in _TERMINAL_JOB_STATUSES


class InvestigationJob(BaseModel):
    """One durable investigation-level execution job.

    ``investigation_id`` is unique: one Investigation owns exactly one
    logical job, so a retried submission never creates a second job. The
    claim transition is owned by the persisted SQL API (``FOR UPDATE SKIP
    LOCKED``); this model only carries the authoritative row state.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    investigation_id: UUID
    status: InvestigationJobStatus
    created_at: datetime
    claimed_at: datetime | None = None
    completed_at: datetime | None = None
    error_code: str | None = None

    @field_validator("created_at", "claimed_at", "completed_at", mode="after")
    @classmethod
    def validate_utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized timestamps."""
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("job timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("error_code", mode="after")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        """Reject error codes outside the stable bounded snake-case grammar."""
        if value is None:
            return None
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
            raise ValueError(
                "job error_code must match ^[a-z][a-z0-9_]{0,63}$ "
                "with no surrounding whitespace"
            )
        return value
