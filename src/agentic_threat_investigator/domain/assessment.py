# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI's interpretation of evidence.

An Assessment is ATI's analytical conclusion, distinct from the evidence that
supports it. Every material conclusion must be traceable to typed provenance:
direct source-fact claims cite ``Evidence``, graph-backed claims cite the
:class:`~agentic_threat_investigator.domain.relationships.RelationshipObservation`
connecting the exact supporting Evidence observation to the stable
Relationship.

Verdict semantics:

- BENIGN: positive evidence supports a benign interpretation.
- SUSPICIOUS: meaningful risk indicators exist, but evidence is insufficient
  for MALICIOUS.
- MALICIOUS: evidence materially supports malicious activity/infrastructure.
- INCONCLUSIVE: evidence is absent, insufficient, weak, or materially
  conflicting.

"Nothing malicious found" is not equivalent to BENIGN. Confidence expresses
confidence in the verdict, not severity.

Assessments are versioned analytical outputs: a later analysis never mutates a
persisted conclusion, it creates a new persisted Assessment whose exact
Findings and support references are preserved forever. Domain code carries no
repository, SQL, provider, LangChain, or LangGraph dependency.
"""

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EVIDENCE_SUPPORT_KIND: Literal["evidence"] = "evidence"
"""Stable JSON/SQL discriminator for direct Evidence support."""

RELATIONSHIP_SUPPORT_KIND: Literal["relationship_observation"] = (
    "relationship_observation"
)
"""Stable JSON/SQL discriminator for RelationshipObservation support."""


class Verdict(str, Enum):
    """Analytical verdicts ATI may reach about an investigation."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


class AssessmentConfidence(str, Enum):
    """Confidence in the verdict, not severity of the finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingCategory(str, Enum):
    """The smallest stable analytical vocabulary for material Findings.

    Categories describe analytical meaning, never provider names. The v0.1
    vocabulary is anchored to the analytical distinctions documented in
    ``docs/EVALUATION.md`` and the Evidence types in
    :mod:`agentic_threat_investigator.domain.evidence`:

    - REPUTATION: third-party reputation and threat-intelligence signals
      (scores, block-list/report hits, report counts);
    - GEOLOCATION: approximate geographic context, never maliciousness
      evidence;
    - REGISTRATION: registration/WHOIS metadata;
    - NETWORK: DNS, network, and routing observations and relationships;
    - ASSOCIATION: graph-backed links to malware, threat actors, attack
      techniques, or exploited vulnerabilities.

    The vocabulary is intentionally small; semantic grading of how contextual
    evidence bears on maliciousness belongs to the PR 20C evaluation, not to
    additional category values.
    """

    REPUTATION = "reputation"
    GEOLOCATION = "geolocation"
    REGISTRATION = "registration"
    NETWORK = "network"
    ASSOCIATION = "association"


class FindingDisposition(str, Enum):
    """Whether the Finding supports or contradicts the Assessment verdict."""

    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"


class EvidenceSupport(BaseModel):
    """Typed provenance for a direct source-fact claim.

    ``kind`` is the explicit stable discriminator shared by the durable JSON
    representation and the SQL ``kind`` column; it is required and must equal
    ``"evidence"``. The claim derives from one immutable Evidence observation.
    The cited Evidence must have been analyzed by the Assessment and belong to
    the same Investigation; an Evidence with zero RelationshipObservations
    remains perfectly valid direct support.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["evidence"]
    evidence_id: UUID


class RelationshipSupport(BaseModel):
    """Typed provenance for a graph-backed claim.

    ``kind`` is the explicit stable discriminator shared by the durable JSON
    representation and the SQL ``kind`` column; it is required and must equal
    ``"relationship_observation"``. The claim cites exactly one
    RelationshipObservation; a bare Relationship (or a redundant
    ``(evidence_id, relationship_id)`` pair) is never valid graph support.
    The exact cited observation resolves to the exact Evidence and stable
    Relationship it recorded at observation time, so a different observation
    of the same Relationship cannot substitute.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["relationship_observation"]
    relationship_observation_id: UUID


FindingSupport = Annotated[
    EvidenceSupport | RelationshipSupport, Field(discriminator="kind")
]
"""A material Finding is backed by either direct Evidence or a RelationshipObservation.

The union is discriminated by the required ``kind`` field, so durable
Pydantic output carries exactly the same stable discriminator values the SQL
``kind`` column stores.
"""


def support_key(support: FindingSupport) -> tuple[str, UUID]:
    """Return a stable identity for one support reference.

    The key is derived from the explicit discriminator and the referenced
    UUID, so duplicate detection and durable representation never depend on
    which identifier field is set.
    """

    if isinstance(support, EvidenceSupport):
        return (support.kind, support.evidence_id)
    return (support.kind, support.relationship_observation_id)


class AnalyticalFinding(BaseModel):
    """One structured, provenance-backed analytical conclusion.

    Every material Finding carries at least one typed support reference.
    Duplicate support is a contract violation and is rejected rather than
    silently repaired.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: FindingCategory
    disposition: FindingDisposition
    statement: str
    confidence: AssessmentConfidence
    support: tuple[FindingSupport, ...]

    @field_validator("statement", mode="after")
    @classmethod
    def statement_not_blank(cls, value: str) -> str:
        """Reject blank statements."""
        if not value.strip():
            raise ValueError("finding statement must not be blank")
        return value

    @field_validator("support", mode="after")
    @classmethod
    def support_nonempty(
        cls, value: tuple[FindingSupport, ...]
    ) -> tuple[FindingSupport, ...]:
        """Require at least one support reference."""
        if not value:
            raise ValueError("finding must have at least one support reference")
        return value

    @field_validator("support", mode="after")
    @classmethod
    def no_duplicate_support(
        cls, value: tuple[FindingSupport, ...]
    ) -> tuple[FindingSupport, ...]:
        """Reject duplicate support references."""
        keys = [support_key(support) for support in value]
        if len(keys) != len(set(keys)):
            raise ValueError("finding support references must be unique")
        return value


class Assessment(BaseModel):
    """ATI's structured interpretation of investigation evidence.

    The Assessment is validated before persistence by the deterministic
    provenance validator; persistence then creates a new versioned analytical
    output rather than silently overwriting a prior conclusion. Persistence
    predicates (``id``, ``version``, ``created_at``, deletion metadata) are
    database-owned; callers must not supply them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID | None = None
    investigation_id: UUID
    verdict: Verdict
    confidence: AssessmentConfidence
    summary: str
    analyzed_evidence_ids: tuple[UUID, ...]
    findings: tuple[AnalyticalFinding, ...] = ()
    limitations: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    recommended_next_steps: tuple[str, ...] = ()
    version: int | None = None
    created_at: datetime | None = None
    deleted_at: datetime | None = None
    deleted_by_actor_id: UUID | None = None

    @model_validator(mode="after")
    def no_duplicate_analyzed_evidence(self) -> "Assessment":
        """Reject duplicate analyzed Evidence identities."""
        if len(self.analyzed_evidence_ids) != len(set(self.analyzed_evidence_ids)):
            raise ValueError("analyzed_evidence_ids must not contain duplicates")
        return self
