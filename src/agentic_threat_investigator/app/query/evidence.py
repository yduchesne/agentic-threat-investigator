# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Admitted-observation collection query contract and service boundary (PR 28B).

Investigation-scoped Evidence reads traverse ``InvestigationEvidence`` to
exact admitted ``EvidenceObservation`` values; they never infer scope from
Evidence ownership and never silently resolve to global latest state. The
narrow :class:`EvidenceReadItem` DTO enriches each exact observation with
its stable Evidence metadata, its deterministic associated Entities, and its
exact admission metadata.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_threat_investigator.app.query.models import (
    QueryPage,
    normalize_utc,
    require_ordered_half_open,
)
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    filter_fingerprint,
)
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import (
    Evidence,
    EvidenceObservation,
    EvidenceType,
    InvestigationEvidence,
)


class EvidenceListQuery(BaseModel):
    """Bounded admitted-observation listing filters for one Investigation.

    Canonical order preserves the persisted execution semantics:
    ``retrieved_at DESC, observation id ASC``. ``retrieved_from``/``retrieved_to``
    bound a half-open ``[from, to)`` UTC interval on the exact observation's
    retrieval. Investigation admission is mandatory; there is no global
    Evidence browse contract. ``entity_id`` filters by observation-level
    Entity association (the v0.1 privileged-subject filter is replaced by
    association semantics).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    source: str | None = None
    entity_id: UUID | None = None
    evidence_type: EvidenceType | None = None
    retrieved_from: datetime | None = None
    retrieved_to: datetime | None = None
    limit: int = Field(ge=1)
    cursor: str | None = None

    @field_validator("retrieved_from", "retrieved_to")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized timestamps."""
        return normalize_utc(value)

    @field_validator("source")
    @classmethod
    def source_not_blank(cls, value: str | None) -> str | None:
        """Reject blank source filters."""
        if value is not None and not value.strip():
            raise ValueError("source filter must not be blank")
        return value

    @model_validator(mode="after")
    def half_open(self) -> "EvidenceListQuery":
        """Require the retrieved-at interval to be well ordered."""
        require_ordered_half_open(
            ((self.retrieved_from, self.retrieved_to, "retrieved_at"),)
        )
        return self

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "investigation_id": self.investigation_id,
                "source": self.source,
                "entity_id": self.entity_id,
                "evidence_type": self.evidence_type,
                "retrieved_from": self.retrieved_from,
                "retrieved_to": self.retrieved_to,
            }
        )


@dataclass(frozen=True)
class EvidenceReadItem:
    """Narrow admitted-observation read view (PR 28B).

    Deliberately not an overloaded domain model: the exact observation is
    enriched with the stable Evidence metadata, the deterministic associated
    Entities (no privileged subject), and the exact admission metadata.
    """

    observation: EvidenceObservation
    evidence: Evidence
    entities: tuple[Entity, ...]
    admission: InvestigationEvidence


class EvidenceQueryService(ABC):
    """Analyst-facing admitted-observation read contract (PR 23A/28B)."""

    @abstractmethod
    async def list(self, query: EvidenceListQuery) -> QueryPage[EvidenceReadItem]:
        """Return one bounded page of exactly admitted observations.

        Ordering is ``retrieved_at DESC, observation id ASC``; cursors are
        bound to the exact filter set; unadmitted global observations never
        appear.
        """

    @abstractmethod
    async def get(
        self, investigation_id: UUID, observation_id: UUID
    ) -> EvidenceReadItem | None:
        """Return one exactly admitted observation bound to the Investigation, if any.

        A cross-Investigation lookup fails closed by returning ``None`` so
        the HTTP layer can map it to a 404 without enumerating resources.
        """


def evidence_sort_values(
    retrieved_at: datetime, observation_id: UUID
) -> tuple[str, str]:
    """Return canonical cursor sort values for one admitted observation."""
    return retrieved_at.astimezone(UTC).isoformat(), str(observation_id)


def parse_evidence_cursor(
    envelope: CursorEnvelope,
) -> tuple[datetime, UUID]:
    """Parse the typed continuation values from a validated cursor envelope."""
    if len(envelope.sort_values) != 2:
        raise ValueError("evidence cursor requires retrieved_at and id")
    retrieved_at = datetime.fromisoformat(envelope.sort_values[0])
    if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
        raise ValueError("evidence cursor timestamp must be timezone-aware")
    return retrieved_at.astimezone(UTC), UUID(envelope.sort_values[1])
