# SPDX-License-Identifier: AGPL-3.0-only
"""Public Assessment DTOs.

Structured verdict, confidence, findings/support, caveats, and
recommendations are exposed; hidden reasoning, raw model output, and
prompts are never part of the public contract.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    Verdict,
)


class FindingSupportResponse(BaseModel):
    """One typed provenance reference of a Finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["evidence", "relationship_observation"]
    evidence_id: UUID | None = None
    relationship_observation_id: UUID | None = None


class FindingResponse(BaseModel):
    """One structured analytical conclusion with typed support references."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: FindingCategory
    disposition: FindingDisposition
    statement: str
    confidence: AssessmentConfidence
    support: tuple[FindingSupportResponse, ...]


class AssessmentResponse(BaseModel):
    """One versioned Assessment output."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    investigation_id: UUID
    verdict: Verdict
    confidence: AssessmentConfidence
    summary: str
    analyzed_evidence_ids: tuple[UUID, ...]
    findings: tuple[FindingResponse, ...]
    limitations: tuple[str, ...]
    unresolved_questions: tuple[str, ...]
    recommended_next_steps: tuple[str, ...]
    version: int
    created_at: datetime
