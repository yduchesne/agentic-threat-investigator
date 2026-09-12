# SPDX-License-Identifier: AGPL-3.0-only
"""Public Report DTOs.

The structured report DTO mirrors the persisted report resource explicitly;
GET never regenerates a report and never invokes an LLM.
"""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    Verdict,
)

from .assessment import FindingSupportResponse
from .research import ResearchCitationResponse


class AssessmentFindingRefResponse(BaseModel):
    """Typed reference to one supplied current-Assessment finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["assessment_finding"] = "assessment_finding"
    assessment_id: UUID
    finding_ordinal: int


class ResearchClaimRefResponse(BaseModel):
    """Typed reference to one persisted ResearchClaim of a supplied result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["research_claim"] = "research_claim"
    research_result_id: UUID
    research_claim_id: UUID


ReportSourceRefResponse = Annotated[
    AssessmentFindingRefResponse | ResearchClaimRefResponse,
    Field(discriminator="kind"),
]


class NarrativeStatementResponse(BaseModel):
    """One model-authored narrative statement with explicit typed support."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str
    support: tuple[ReportSourceRefResponse, ...]


class ReportFindingResponse(BaseModel):
    """Application-copied snapshot of one authoritative Assessment finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_finding_ordinal: int
    category: FindingCategory
    disposition: FindingDisposition
    statement: str
    confidence: AssessmentConfidence
    support: tuple[FindingSupportResponse, ...]


class ReportResearchClaimResponse(BaseModel):
    """Application-copied snapshot of one persisted ResearchClaim."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    research_result_id: UUID
    research_claim_id: UUID
    subject_entity_id: UUID
    claim_text: str
    citation_ids: tuple[UUID, ...]
    citations: tuple[ResearchCitationResponse, ...]


class ReportResponse(BaseModel):
    """One versioned structured InvestigationReport."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    investigation_id: UUID
    assessment_id: UUID
    verdict: Verdict
    confidence: AssessmentConfidence
    title: str
    executive_summary: tuple[NarrativeStatementResponse, ...]
    findings: tuple[ReportFindingResponse, ...]
    research_context: tuple[ReportResearchClaimResponse, ...]
    limitations: tuple[str, ...]
    unresolved_questions: tuple[str, ...]
    recommended_next_steps: tuple[str, ...]
    source_evidence_ids: tuple[UUID, ...]
    source_relationship_observation_ids: tuple[UUID, ...]
    source_research_result_ids: tuple[UUID, ...]
    version: int
    created_at: datetime
