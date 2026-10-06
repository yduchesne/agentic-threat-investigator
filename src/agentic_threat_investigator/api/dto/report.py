# SPDX-License-Identifier: AGPL-3.0-only
"""Public Report DTOs.

The structured report DTO mirrors the persisted Final Report resource
explicitly; GET never regenerates a report and never invokes an LLM.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    FindingCategory,
    FindingCriticality,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import InvestigationStatus

from .assessment import FindingSupportResponse
from .research import ResearchCitationResponse


class AssessmentFindingRefResponse(BaseModel):
    """Typed reference to one supplied current-Assessment finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["assessment_finding"] = "assessment_finding"
    assessment_id: UUID
    finding_ordinal: int


class ReportSummaryItemResponse(BaseModel):
    """One finding-centric Summary projection item."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    report_finding_number: int
    assessment_finding_ordinal: int
    text: str
    support: tuple[AssessmentFindingRefResponse, ...]


class ReportFindingResponse(BaseModel):
    """Application-copied snapshot of one canonical Assessment finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_finding_ordinal: int
    report_finding_number: int
    criticality: FindingCriticality
    title: str
    category: FindingCategory
    disposition: FindingDisposition
    statement: str
    confidence: AssessmentConfidence
    summary: str
    description: str
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
    criticality: FindingCriticality
    title: str
    summary: tuple[ReportSummaryItemResponse, ...]
    findings: tuple[ReportFindingResponse, ...]
    research_context: tuple[ReportResearchClaimResponse, ...]
    limitations: tuple[str, ...]
    unresolved_questions: tuple[str, ...]
    recommended_next_steps: tuple[str, ...]
    started_at: datetime | None
    ended_at: datetime | None
    outcome_status: InvestigationStatus
    stop_reason: str | None
    source_evidence_ids: tuple[UUID, ...]
    source_relationship_observation_ids: tuple[UUID, ...]
    source_research_result_ids: tuple[UUID, ...]
    version: int
    created_at: datetime
