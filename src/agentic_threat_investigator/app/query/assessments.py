# SPDX-License-Identifier: AGPL-3.0-only
"""Assessment version-list query contract and service boundary.

Assessment rows are versioned, insert-only analytical outputs. The version
list orders by ``version DESC, id ASC``; the current Assessment continues to
be resolved through the Investigation's durable ``assessment_id`` pointer and
is never inferred with ``MAX(version)``.
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
from agentic_threat_investigator.domain.assessment import Assessment


class AssessmentListQuery(BaseModel):
    """Bounded Assessment version listing for one Investigation.

    Canonical order is ``version DESC, id ASC``. Soft-deleted Assessment rows
    are hidden by default; history queries expose deletion state separately.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    limit: int = Field(ge=1)
    cursor: str | None = None

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint({"investigation_id": self.investigation_id})


class AssessmentQueryService(ABC):
    """Analyst-facing Assessment read contract (PR 23A)."""

    @abstractmethod
    async def list(self, query: AssessmentListQuery) -> QueryPage[Assessment]:
        """Return one bounded page of Assessment versions, newest version first.

        Findings and support references are reconstructed in bounded batched
        reads; cursors are bound to the Investigation scope.
        """

    @abstractmethod
    async def current(self, investigation_id: UUID) -> Assessment | None:
        """Return the Investigation's current/final Assessment, if any.

        Resolution follows the durable Investigation ``assessment_id``
        pointer; ``MAX(version)`` inference is never used.
        """

    @abstractmethod
    async def get(
        self, investigation_id: UUID, assessment_id: UUID
    ) -> Assessment | None:
        """Return one Assessment version bound to the Investigation, if any.

        The exact version is returned regardless of the durable pointer;
        cross-Investigation lookups fail closed with ``None``.
        """


def assessment_sort_values(version: int, assessment_id: UUID) -> tuple[str, str]:
    """Return canonical cursor sort values for one assessment row.

    Versions use canonical decimal strings.
    """
    return str(version), str(assessment_id)


def parse_assessment_cursor(envelope: CursorEnvelope) -> tuple[int, UUID]:
    """Parse the typed continuation values from a validated cursor envelope."""
    if len(envelope.sort_values) != 2:
        raise ValueError("assessment cursor requires version and id")
    version = int(envelope.sort_values[0])
    if version < 1:
        raise ValueError("assessment cursor version must be positive")
    return version, UUID(envelope.sort_values[1])
