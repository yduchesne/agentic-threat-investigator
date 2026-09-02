# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI's interpretation of evidence.

An Assessment is ATI's analytical conclusion, distinct from the evidence that
supports it. Every material conclusion must be traceable to evidence IDs.

Verdict semantics:

- BENIGN: positive evidence supports a benign interpretation.
- SUSPICIOUS: meaningful risk indicators exist, but evidence is insufficient
  for MALICIOUS.
- MALICIOUS: evidence materially supports malicious activity/infrastructure.
- INCONCLUSIVE: evidence is absent, insufficient, weak, or materially
  conflicting.

"Nothing malicious found" is not equivalent to BENIGN. Confidence expresses
confidence in the verdict, not severity.
"""

from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


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


class EvidenceReference(BaseModel):
    """A referenced evidence item with the rationale for referencing it."""

    evidence_id: UUID
    rationale: str


class Assessment(BaseModel):
    """ATI's structured interpretation of investigation evidence.

    Every material conclusion must be traceable to evidence IDs through
    ``analyzed_evidence_ids`` and the supporting/contradicting references.
    """

    id: UUID | None = None
    investigation_id: UUID
    verdict: Verdict
    confidence: AssessmentConfidence
    summary: str
    analyzed_evidence_ids: list[UUID]
    supporting_evidence: list[EvidenceReference] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceReference] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
