# SPDX-License-Identifier: AGPL-3.0-only
"""Report version-list query contract and service boundary (PR 23B).

Report rows are versioned, insert-only presentation outputs. The version list
orders by ``version DESC, id ASC``; the current report is resolved through
the Investigation's durable ``report_id`` pointer and is never inferred with
``MAX(version)``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_threat_investigator.app.query.models import QueryPage
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    filter_fingerprint,
)
from agentic_threat_investigator.domain.report import InvestigationReport


class ReportListQuery(BaseModel):
    """Bounded report version listing for one Investigation.

    Canonical order is ``version DESC, id ASC``. Soft-deleted report rows are
    hidden by default; history queries expose deletion state separately.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    limit: int = Field(ge=1)
    cursor: str | None = None

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint({"investigation_id": self.investigation_id})


class ReportQueryService(ABC):
    """Analyst-facing report read contract (PR 23B extension of PR 23A)."""

    @abstractmethod
    async def list(self, query: ReportListQuery) -> QueryPage[InvestigationReport]:
        """Return one bounded page of report versions, newest version first.

        Nested snapshots are reconstructed from the authoritative JSONB
        columns; cursors are bound to the Investigation scope.
        """

    @abstractmethod
    async def current(self, investigation_id: UUID) -> InvestigationReport | None:
        """Return the Investigation's current report, if any.

        Resolution follows the durable Investigation ``report_id`` pointer;
        ``MAX(version)`` inference is never used.
        """

    @abstractmethod
    async def get(self, report_id: UUID) -> InvestigationReport | None:
        """Return one visible report by identity, if any."""


def report_sort_values(version: int, report_id: UUID) -> tuple[str, str]:
    """Return canonical cursor sort values for one report row.

    Versions use canonical decimal strings.
    """
    return str(version), str(report_id)


def parse_report_cursor(envelope: CursorEnvelope) -> tuple[int, UUID]:
    """Parse the typed continuation values from a validated cursor envelope."""
    if len(envelope.sort_values) != 2:
        raise ValueError("report cursor requires version and id")
    version = int(envelope.sort_values[0])
    if version < 1:
        raise ValueError("report cursor version must be positive")
    return version, UUID(envelope.sort_values[1])
