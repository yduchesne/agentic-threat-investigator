# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Structured ``InvestigationReport`` domain contracts (PR 23B, PR 35-5).

The Report Writer is ATI's final analytical presentation agent. It never
collects Evidence, performs RAG retrieval, changes investigation policy,
decides the analytical verdict, changes finding criticality, or creates new
threat-intelligence facts. It transforms the already-persisted authoritative
inputs — the current Assessment, its Evidence/RelationshipObservation
provenance, persisted ResearchResults, and the persisted Investigation
lifecycle — into one canonical, provenance-backed Final Report.

The dominant invariant:

> ATI has one canonical ordered finding set. Summary and Details are
> deterministic projections of that same set; they are never independently
> generated competing interpretations.

Related contracts exist by design:

- :class:`ReportWriterOutput` — model-authored presentation only. It carries
  a bounded short title and Summary sentence for exactly one canonical
  finding, plus a bounded research-context selection. It deliberately
  carries no verdict, confidence, criticality, finding inclusion/order,
  numbering, Status, duration, table of contents, or caveat lists.
- :class:`InvestigationReport` — the authoritative persisted domain resource
  after deterministic validation and application stamping.

The application sorts findings criticality-first (tie-broken by the stable
Assessment ordinal), assigns contiguous reader-facing numbers, derives the
Summary projection from the Summary-eligible findings, and snapshots the
persisted Investigation lifecycle for deterministic later rendering.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from agentic_threat_investigator.domain.analyst import (
    AnalystEvidenceItem,
    AnalystRelationshipObservation,
)
from agentic_threat_investigator.domain.assessment import (
    CRITICALITY_RANK,
    SUMMARY_CRITICALITIES,
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    FindingCategory,
    FindingCriticality,
    FindingDisposition,
    FindingSupport,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import InvestigationStatus
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchResult,
)

MAX_REPORT_TITLE_CHARS = 300
"""Hard ceiling on report titles (model-authored or copied)."""

MAX_FINDING_TITLE_CHARS = 300
"""Hard ceiling on one reader-facing finding short title."""

MAX_SUMMARY_CHARS = 500
"""Hard ceiling on one finding-centric Summary sentence."""

MAX_DESCRIPTION_CHARS = 2000
"""Hard ceiling on one reader-facing finding description."""


class AssessmentFindingRef(BaseModel):
    """Typed reference to one supplied current-Assessment finding.

    ``finding_ordinal`` uses the same stable 1-based ordering as Assessment
    persistence; the model never cites a database-private finding row id.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["assessment_finding"] = "assessment_finding"
    assessment_id: UUID
    finding_ordinal: int = Field(ge=1)


class ReportResearchSelection(BaseModel):
    """Model-authored selection of one persisted ResearchClaim.

    The model selects contextual claims by the exact persisted
    ``(research_result_id, research_claim_id)`` pair; the final report
    snapshots application-owned claim/citation content, never model text.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    research_result_id: UUID
    research_claim_id: UUID


class FindingPresentation(BaseModel):
    """Model-authored bounded presentation for exactly one canonical finding.

    The model supplies a short factual heading, a concise Summary sentence,
    and detailed reader-facing analytical prose, tied to the referenced
    Assessment finding ordinal. It may not select, omit, reorder, or
    renumber findings, and it may not change any analytical field. The
    generated prose is presentation, not new analytical authority: it must
    remain entailed by the Finding and its supplied support context.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_finding_ordinal: int = Field(ge=1)
    title: str
    summary: str
    description: str

    @field_validator("title", mode="after")
    @classmethod
    def title_not_blank(cls, value: str) -> str:
        """Reject blank finding titles."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("finding presentation title must not be blank")
        return stripped

    @field_validator("title", mode="after")
    @classmethod
    def title_bounded(cls, value: str) -> str:
        """Reject finding titles above the hard length ceiling."""
        if len(value) > MAX_FINDING_TITLE_CHARS:
            raise ValueError(
                f"finding presentation title exceeds "
                f"{MAX_FINDING_TITLE_CHARS} characters"
            )
        return value

    @field_validator("summary", mode="after")
    @classmethod
    def summary_not_blank(cls, value: str) -> str:
        """Reject blank Summary sentences."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("finding presentation summary must not be blank")
        return stripped

    @field_validator("summary", mode="after")
    @classmethod
    def summary_bounded(cls, value: str) -> str:
        """Reject Summary sentences above the hard length ceiling."""
        if len(value) > MAX_SUMMARY_CHARS:
            raise ValueError(
                f"finding presentation summary exceeds {MAX_SUMMARY_CHARS} characters"
            )
        return value

    @field_validator("description", mode="after")
    @classmethod
    def description_not_blank(cls, value: str) -> str:
        """Reject blank finding descriptions."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("finding presentation description must not be blank")
        return stripped

    @field_validator("description", mode="after")
    @classmethod
    def description_bounded(cls, value: str) -> str:
        """Reject finding descriptions above the hard length ceiling."""
        if len(value) > MAX_DESCRIPTION_CHARS:
            raise ValueError(
                "finding presentation description exceeds "
                f"{MAX_DESCRIPTION_CHARS} characters"
            )
        return value


class ReportWriterOutput(BaseModel):
    """The presentation-only output the Report Writer model returns.

    The model authors a title, exactly one bounded presentation per supplied
    Assessment finding, and a selection of supplied persisted ResearchClaims.
    The application stamps every persistence-owned field, verdict,
    confidence, criticality, ordering, numbering, caveat lists, Status
    snapshot, and the source-identity sets when it constructs the
    authoritative :class:`InvestigationReport`.

    Deliberate exclusions: no verdict, no confidence, no criticality, no
    finding inclusion/order/numbering, no limitations, no unresolved
    questions, no recommended next steps, no Status/timeline, no persistence
    metadata, no tool/provider requests.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str
    finding_presentations: tuple[FindingPresentation, ...] = ()
    research_context: tuple[ReportResearchSelection, ...] = ()

    @field_validator("title", mode="after")
    @classmethod
    def title_not_blank(cls, value: str) -> str:
        """Reject blank titles."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("report title must not be blank")
        return stripped

    @field_validator("title", mode="after")
    @classmethod
    def title_bounded(cls, value: str) -> str:
        """Reject titles above the hard length ceiling."""
        if len(value) > MAX_REPORT_TITLE_CHARS:
            raise ValueError(
                f"report title exceeds {MAX_REPORT_TITLE_CHARS} characters"
            )
        return value

    @field_validator("finding_presentations", mode="after")
    @classmethod
    def presentation_ordinals_unique(
        cls, value: tuple[FindingPresentation, ...]
    ) -> tuple[FindingPresentation, ...]:
        """Reject duplicate presentation ordinals."""
        ordinals = [presentation.assessment_finding_ordinal for presentation in value]
        if len(ordinals) != len(set(ordinals)):
            raise ValueError(
                "finding_presentations must not contain duplicate ordinals"
            )
        return value

    @field_validator("research_context", mode="after")
    @classmethod
    def research_selections_unique(
        cls, value: tuple[ReportResearchSelection, ...]
    ) -> tuple[ReportResearchSelection, ...]:
        """Reject duplicate claim selections."""
        keys = [
            (selection.research_result_id, selection.research_claim_id)
            for selection in value
        ]
        if len(keys) != len(set(keys)):
            raise ValueError(
                "research_context must not contain duplicate claim selections"
            )
        return value


class ReportFindingSnapshot(BaseModel):
    """Application-copied snapshot of one authoritative Assessment finding.

    Analytical fields (category, disposition, statement, confidence,
    criticality, support) are copied exactly from the current Assessment
    finding at the referenced ordinal. ``report_finding_number`` is
    application-assigned after deterministic criticality-first sorting; the
    model may only contribute the bounded ``title``, ``summary``, and
    ``description``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_finding_ordinal: int = Field(ge=1)
    report_finding_number: int = Field(ge=1)
    criticality: FindingCriticality
    title: str
    category: FindingCategory
    disposition: FindingDisposition
    statement: str
    confidence: AssessmentConfidence
    summary: str
    description: str
    support: tuple[FindingSupport, ...]

    @field_validator("statement", mode="after")
    @classmethod
    def statement_not_blank(cls, value: str) -> str:
        """Reject blank finding statements."""
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


class ReportSummaryItem(BaseModel):
    """One finding-centric Summary projection item.

    The item's text is the canonical finding's bounded Summary sentence and
    its typed support references exactly that one Assessment finding, so a
    Summary bullet can never combine unrelated findings or cite research.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    report_finding_number: int = Field(ge=1)
    assessment_finding_ordinal: int = Field(ge=1)
    text: str
    support: tuple[AssessmentFindingRef, ...]

    @field_validator("text", mode="after")
    @classmethod
    def text_not_blank(cls, value: str) -> str:
        """Reject blank Summary item text."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("summary item text must not be blank")
        return stripped

    @field_validator("text", mode="after")
    @classmethod
    def text_bounded(cls, value: str) -> str:
        """Reject Summary item text above the hard length ceiling."""
        if len(value) > MAX_SUMMARY_CHARS:
            raise ValueError(
                f"summary item text exceeds {MAX_SUMMARY_CHARS} characters"
            )
        return value

    @field_validator("support", mode="after")
    @classmethod
    def support_exactly_one(
        cls, value: tuple[AssessmentFindingRef, ...]
    ) -> tuple[AssessmentFindingRef, ...]:
        """Require exactly one Assessment finding support reference."""
        if len(value) != 1:
            raise ValueError(
                "summary item must reference exactly one assessment finding"
            )
        return value


class ReportResearchClaimSnapshot(BaseModel):
    """Application-copied snapshot of one persisted ResearchClaim.

    ``claim_text``, ``citation_ids``, and the ``citations`` snapshots are
    copied from the persisted :class:`ResearchResult`; the model never
    rewrites research claims or citations.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    research_result_id: UUID
    research_claim_id: UUID
    subject_entity_id: UUID
    claim_text: str
    citation_ids: tuple[UUID, ...]
    citations: tuple[ResearchCitation, ...]

    @field_validator("claim_text", mode="after")
    @classmethod
    def claim_text_not_blank(cls, value: str) -> str:
        """Reject blank claim text."""
        if not value.strip():
            raise ValueError("research claim text must not be blank")
        return value


class ReportWriterInput(BaseModel):
    """The deterministic, bounded snapshot the Report Writer receives.

    Assembled exclusively from persisted authoritative resources by the
    application input loader: the current Assessment (resolved through the
    Investigation's durable ``assessment_id`` pointer), its analyzed
    Evidence, the RelationshipObservations referenced by its Findings (with
    the stable Relationships/entities needed to render them), bounded
    persisted ResearchResults, and the persisted Investigation lifecycle
    fields required for the Status snapshot. ``raw_payload`` never appears;
    the same persisted investigation state always produces the same
    serialized input.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    objective: str
    assessment: Assessment
    evidence: tuple[AnalystEvidenceItem, ...] = ()
    relationship_observations: tuple[AnalystRelationshipObservation, ...] = ()
    research_results: tuple[ResearchResult, ...] = ()
    investigation_status: InvestigationStatus
    started_at: datetime
    completed_at: datetime | None = None
    stop_reason: str | None = None

    @field_validator("objective", mode="after")
    @classmethod
    def objective_not_blank(cls, value: str) -> str:
        """Reject blank objectives."""
        if not value.strip():
            raise ValueError("investigation objective must not be blank")
        return value

    @field_validator("evidence", mode="after")
    @classmethod
    def evidence_unique(
        cls, value: tuple[AnalystEvidenceItem, ...]
    ) -> tuple[AnalystEvidenceItem, ...]:
        """Reject duplicate evidence identities."""
        ids = [item.evidence_observation_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("report input evidence must not contain duplicates")
        return value

    @model_validator(mode="after")
    def assessment_bound_to_investigation(self) -> "ReportWriterInput":
        """Require the Assessment to belong to the Investigation."""
        if self.assessment.investigation_id != self.investigation_id:
            raise ValueError(
                "report input assessment does not belong to the investigation"
            )
        return self

    def finding_by_ordinal(self, ordinal: int) -> AnalyticalFinding | None:
        """Return the Assessment finding at the stable 1-based ordinal, if any."""
        if ordinal < 1 or ordinal > len(self.assessment.findings):
            return None
        return self.assessment.findings[ordinal - 1]


class InvestigationReport(BaseModel):
    """The authoritative persisted report domain resource (PR 23B, PR 35-5).

    Persistence predicates (``id``, ``version``, ``created_at``, deletion
    metadata) are database-owned; callers must not supply them. Verdict,
    confidence, and the Status lifecycle snapshot are copied exactly from the
    authoritative current Assessment/Investigation; caveat lists are copied
    exactly; findings and Summary are application-derived projections of the
    same canonical ordered finding set; research context is an application
    snapshot.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID | None = None
    investigation_id: UUID
    assessment_id: UUID
    verdict: Verdict
    confidence: AssessmentConfidence
    criticality: FindingCriticality
    title: str
    summary: tuple[ReportSummaryItem, ...] = ()
    findings: tuple[ReportFindingSnapshot, ...] = ()
    research_context: tuple[ReportResearchClaimSnapshot, ...] = ()
    limitations: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    recommended_next_steps: tuple[str, ...] = ()
    started_at: datetime | None = None
    ended_at: datetime | None = None
    outcome_status: InvestigationStatus
    stop_reason: str | None = None
    source_evidence_ids: tuple[UUID, ...] = ()
    source_relationship_observation_ids: tuple[UUID, ...] = ()
    source_research_result_ids: tuple[UUID, ...] = ()
    version: int | None = None
    created_at: datetime | None = None
    deleted_at: datetime | None = None
    deleted_by_actor_id: UUID | None = None

    @field_validator("title", mode="after")
    @classmethod
    def title_not_blank(cls, value: str) -> str:
        """Reject blank titles."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("report title must not be blank")
        return stripped

    @field_validator("title", mode="after")
    @classmethod
    def title_bounded(cls, value: str) -> str:
        """Reject titles above the hard length ceiling."""
        if len(value) > MAX_REPORT_TITLE_CHARS:
            raise ValueError(
                f"report title exceeds {MAX_REPORT_TITLE_CHARS} characters"
            )
        return value

    @field_validator("findings", mode="after")
    @classmethod
    def findings_unique_ordinals(
        cls, value: tuple[ReportFindingSnapshot, ...]
    ) -> tuple[ReportFindingSnapshot, ...]:
        """Reject duplicate Assessment finding ordinals and report numbers."""
        ordinals = [finding.assessment_finding_ordinal for finding in value]
        if len(ordinals) != len(set(ordinals)):
            raise ValueError("report findings must have unique assessment ordinals")
        numbers = [finding.report_finding_number for finding in value]
        if len(numbers) != len(set(numbers)):
            raise ValueError("report findings must have unique report numbers")
        return value

    @field_validator("research_context", mode="after")
    @classmethod
    def research_unique(
        cls, value: tuple[ReportResearchClaimSnapshot, ...]
    ) -> tuple[ReportResearchClaimSnapshot, ...]:
        """Reject duplicate research claim snapshots."""
        keys = [
            (snapshot.research_result_id, snapshot.research_claim_id)
            for snapshot in value
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("report research context must not contain duplicates")
        return value


def criticality_first_ordering(
    findings: tuple[AnalyticalFinding, ...],
) -> tuple[tuple[int, AnalyticalFinding], ...]:
    """Return ``(assessment_ordinal, finding)`` pairs in canonical report order.

    Findings are ordered criticality-first (critical -> high -> medium -> low
    -> informational) and tie-broken by ascending authoritative Assessment
    ordinal. The returned assessment ordinals are the stable internal
    provenance ordinals; the reader-facing report number is the position in
    this sequence.
    """

    indexed = list(enumerate(findings, start=1))
    indexed.sort(key=lambda item: (CRITICALITY_RANK[item[1].criticality], item[0]))
    return tuple(indexed)


def is_summary_eligible(criticality: FindingCriticality) -> bool:
    """Return whether a finding of this criticality appears in the Summary."""
    return criticality in SUMMARY_CRITICALITIES
