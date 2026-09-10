# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence Analyst typed contracts: deterministic analyst input and LLM output.

These are ATI-owned Pydantic contracts only. They carry no repository,
provider, LangChain, LangGraph, or persistence dependency.

``EvidenceAnalystInput`` is the immutable, deterministic, minimized snapshot
the Evidence Analyst receives: persisted Investigation context plus the exact
Evidence and RelationshipObservation identities shown to the model. It is
assembled exclusively from persisted authoritative resources; ``raw_payload``
and other non-analytical content never appears here.

``EvidenceAnalystDecision`` is the semantic output of the LLM call. It carries
verdict, confidence, summary, Findings, and ordered text collections only.
Persistence-owned identifiers (``investigation_id``, ``id``, ``version``,
``created_at``, deletion metadata) are deliberately absent: the application
stamps them when it constructs the authoritative ``Assessment``. The model
cannot manufacture ``analyzed_evidence_ids``; ATI declares the analyzed set
to be exactly the Evidence deliberately supplied in the input.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.immutable_json import FrozenDict, freeze_mapping
from agentic_threat_investigator.domain.relationships import RelationshipType


class AnalystEntity(BaseModel):
    """Minimal entity identity provided for interpretation, never for citation.

    ``entity_id`` is the persisted canonical entity identity; ``entity_type``
    and ``value`` are the canonical identity values. Endpoint entities are
    included only so the analyst can interpret relationships.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    entity_type: EntityType
    value: str


def _empty_facts() -> FrozenDict:
    """Return an empty deeply immutable facts mapping."""
    return freeze_mapping({})


class AnalystEvidenceItem(BaseModel):
    """The minimized, normalized Evidence view shown to the model.

    ``facts`` are the normalized evidence facts: provider-specific scores stay
    normalized facts and analytical confidence belongs to the Assessment.
    ``raw_payload`` and HTTP headers are never included. ``source_url`` is
    omitted for PR 20B: normalized facts and stable source metadata are
    sufficient to reason and cite.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: UUID
    type: EvidenceType
    subject: AnalystEntity
    source: str
    source_record_id: str | None = None
    observed_at: datetime | None = None
    retrieved_at: datetime
    facts: dict[str, Any] = Field(default_factory=_empty_facts)

    @field_validator("facts", mode="after")
    @classmethod
    def freeze_facts(cls, value: dict[str, Any]) -> FrozenDict:
        """Store normalized facts as a deeply immutable JSON object."""
        return freeze_mapping(value)


class AnalystRelationshipObservation(BaseModel):
    """The minimized view of one historical relationship observation.

    The observation identity is the exact identity the model must cite for a
    graph-backed Finding. A bare Relationship is never citable, so the DTO
    always resolves the stable Relationship and its endpoint entities.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    relationship_observation_id: UUID
    evidence_id: UUID
    relationship_id: UUID
    relationship_type: RelationshipType
    source_entity: AnalystEntity
    target_entity: AnalystEntity
    observed_at: datetime | None = None
    retrieved_at: datetime
    source: str
    confidence: float | None = None


class EvidenceAnalystInput(BaseModel):
    """The deterministic, bounded context for one analyst execution.

    Ordering is deterministic: ``evidence`` and ``relationship_observations``
    follow the documented repository orders and ``root_entities`` follows the
    Investigation root list. The same persisted investigation state always
    produces the same serialized input.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    objective: str
    root_entities: tuple[AnalystEntity, ...] = ()
    evidence: tuple[AnalystEvidenceItem, ...] = ()
    relationship_observations: tuple[AnalystRelationshipObservation, ...] = ()

    @field_validator("objective", mode="after")
    @classmethod
    def objective_not_blank(cls, value: str) -> str:
        """Reject blank objectives."""
        if not value.strip():
            raise ValueError("investigation objective must not be blank")
        return value


class EvidenceAnalystDecision(BaseModel):
    """The semantic-only analytical output the model returns.

    The model sets verdict, confidence, summary, Findings, limitations,
    unresolved questions, and recommended next steps. The application stamps
    ``investigation_id``, ``analyzed_evidence_ids``, and every
    persistence-owned field when it constructs the authoritative
    :class:`~agentic_threat_investigator.domain.assessment.Assessment`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Verdict
    confidence: AssessmentConfidence
    summary: str
    findings: tuple[AnalyticalFinding, ...] = ()
    limitations: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    recommended_next_steps: tuple[str, ...] = ()

    @field_validator("summary", mode="after")
    @classmethod
    def summary_not_blank(cls, value: str) -> str:
        """Reject blank summaries."""
        if not value.strip():
            raise ValueError("decision summary must not be blank")
        return value

    @field_validator("limitations", "unresolved_questions", "recommended_next_steps")
    @classmethod
    def no_blank_entries(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject blank or empty-string entries in ordered text collections."""
        if any(not entry.strip() for entry in value):
            raise ValueError("decision text collections must not contain blank entries")
        return value
