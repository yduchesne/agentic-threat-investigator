# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded Investigation-scoped support presentation resolution (PR 31F-5).

Report/Assessment findings reference evidence and relationship-observation
support by persisted ID only. Analyst-facing presentation needs the
semantic description of each support (Evidence source/type/subject and the
observation edge endpoints), but resolving them with one HTTP GET per
support would be a frontend N+1. This contract resolves the finite
support-ID sets of one loaded Report/Assessment through one bounded
Investigation-scoped, set-oriented query and returns presentation
projections only — exact observation identity, never global latest, and
never the raw provider payload.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType

#: Hard per-kind bound on one resolution request. The frontend collects at
#: most the unique support IDs of one loaded artifact (a bounded page of
#: findings), which is far below this bound; the server rejects anything
#: larger fail-closed instead of allowing an unbounded batch.
MAX_SUPPORT_IDS_PER_KIND = 200


class SupportPresentationQuery(BaseModel):
    """One bounded support-resolution request.

    ``investigation_id`` is mandatory: presentation resolves only against
    observations exactly admitted into the path Investigation, so
    cross-Investigation support IDs fail closed (absent from the result)
    instead of leaking global state.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    evidence_observation_ids: tuple[UUID, ...] = Field(
        default_factory=tuple, max_length=MAX_SUPPORT_IDS_PER_KIND
    )
    relationship_observation_ids: tuple[UUID, ...] = Field(
        default_factory=tuple, max_length=MAX_SUPPORT_IDS_PER_KIND
    )

    @field_validator(
        "evidence_observation_ids",
        "relationship_observation_ids",
        mode="before",
    )
    @classmethod
    def _sequence_to_tuple(cls, value: object) -> object:
        """Accept list inputs from the DTO layer as immutable tuples."""
        if value is None:
            return ()
        if isinstance(value, (list, tuple)):
            return tuple(value)
        return value


class EvidenceSupportPresentation(BaseModel):
    """One Evidence support projection (PR 31F-5 §3.5).

    The raw provider payload and any unallowlisted facts never cross this
    boundary: only the stable Evidence type/source and the deterministic
    first associated Entity (matching the Evidence read subject semantics)
    are projected.
    """

    model_config = ConfigDict(frozen=True)

    evidence_observation_id: UUID
    evidence_type: EvidenceType
    source: str
    subject_entity_id: UUID | None = None
    subject_entity_type: EntityType | None = None
    subject_entity_value: str | None = None


class RelationshipObservationSupportPresentation(BaseModel):
    """One RelationshipObservation support projection (PR 31F-5 §3.5).

    The stable edge identity/topology/type and the endpoint Entity
    presentation metadata are projected; the immutable observation's URL
    and raw provider payload never appear.
    """

    model_config = ConfigDict(frozen=True)

    relationship_observation_id: UUID
    relationship_id: UUID
    relationship_type: RelationshipType
    source_entity_id: UUID
    source_entity_type: EntityType | None = None
    source_entity_value: str | None = None
    target_entity_id: UUID
    target_entity_type: EntityType | None = None
    target_entity_value: str | None = None
    observed_at: datetime | None = None


class SupportPresentationResult(BaseModel):
    """The resolved presentation map of one bounded request.

    Only requested IDs that resolve inside the Investigation appear; the
    frontend renders the localized unavailable statement for the rest.
    Ordering is deterministic by requested observation ID so the frontend
    can index the result without scanning.
    """

    model_config = ConfigDict(frozen=True)

    evidence: tuple[EvidenceSupportPresentation, ...] = ()
    relationship_observations: tuple[
        RelationshipObservationSupportPresentation, ...
    ] = ()


class SupportPresentationQueryService(ABC):
    """Investigation-scoped support presentation read contract (PR 31F-5)."""

    @abstractmethod
    async def resolve(
        self, query: SupportPresentationQuery
    ) -> SupportPresentationResult:
        """Resolve the finite requested support-ID sets in Investigation scope.

        Duplicate requested IDs resolve exactly once; cross-Investigation
        and missing IDs are simply absent from the result (never global
        latest, never raw payload exposure). One bounded set-oriented read
        per resource kind — never one query per support ID.
        """
