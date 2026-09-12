# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Structured ``InvestigationReport`` domain contracts (PR 23B).

The Report Writer is ATI's final analytical presentation agent. It never
collects Evidence, performs RAG retrieval, changes investigation policy,
decides the analytical verdict, or creates new threat-intelligence facts. It
transforms the already-persisted authoritative inputs — the current
Assessment, its Evidence/RelationshipObservation provenance, and persisted
ResearchResults — into a structured, provenance-backed report.

The dominant invariant:

> The current persisted Assessment remains the sole authority for verdict and
> confidence. A report may organize, summarize, and present existing supported
> analytical material, but it may never change the Assessment
> verdict/confidence or introduce a material claim without an explicit
> reference to authoritative supplied Assessment or Research provenance.

Two related contracts exist by design:

- :class:`ReportWriterOutput` — model-authored structured synthesis/selections
  only. It deliberately carries no verdict, confidence, persistence-owned
  identifiers, timestamps, limitations, unresolved questions, or recommended
  next steps.
- :class:`InvestigationReport` — the authoritative persisted domain resource
  after deterministic validation and application stamping.

Every material model-authored narrative statement must carry at least one
typed :class:`ReportSourceRef` referencing a supplied Assessment finding or a
persisted ResearchClaim. Reference closure is proven deterministically by the
application validator; semantic entailment is a behavioral-evaluation
concern and is never claimed here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
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
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    FindingSupport,
    Verdict,
)
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchResult,
)

MAX_REPORT_TITLE_CHARS = 300
"""Hard ceiling on report titles (model-authored or copied)."""

MAX_NARRATIVE_STATEMENT_CHARS = 2000
"""Hard ceiling on one model-authored narrative statement."""


class AssessmentFindingRef(BaseModel):
    """Typed reference to one supplied current-Assessment finding.

    ``finding_ordinal`` uses the same stable 1-based ordering as Assessment
    persistence; the model never cites a database-private finding row id.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["assessment_finding"] = "assessment_finding"
    assessment_id: UUID
    finding_ordinal: int = Field(ge=1)


class ResearchClaimRef(BaseModel):
    """Typed reference to one persisted ResearchClaim of a supplied result.

    The exact ``(research_result_id, research_claim_id)`` pair must have been
    supplied to the Report Writer; a claim merely present in the corpus but
    absent from the input snapshot is rejected identically to an unknown one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["research_claim"] = "research_claim"
    research_result_id: UUID
    research_claim_id: UUID


ReportSourceRef = Annotated[
    AssessmentFindingRef | ResearchClaimRef, Field(discriminator="kind")
]
"""A material narrative statement references Assessment findings or Research claims.

Assessment findings already carry validated Evidence/RelationshipObservation
provenance; Research claims already carry validated citation closure. The
report composes these validated artifacts rather than inventing a third
provenance system, so direct Evidence/Relationship/DocumentChunk IDs are
never valid report-level material references.
"""


def report_source_ref_key(ref: ReportSourceRef) -> tuple[str, ...]:
    """Return a stable identity for one report source reference.

    The key is derived from the explicit discriminator and the referenced
    identities, so duplicate detection never depends on which fields are set.
    """

    if isinstance(ref, AssessmentFindingRef):
        return (
            ref.kind,
            str(ref.assessment_id),
            str(ref.finding_ordinal),
        )
    return (
        ref.kind,
        str(ref.research_result_id),
        str(ref.research_claim_id),
    )


class ReportNarrativeStatement(BaseModel):
    """One model-authored narrative statement with explicit typed support.

    Rules: nonblank; bounded length; at least one support reference; no
    duplicate support references. The statement is a presentation of supplied
    material — never a new material fact.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str
    support: tuple[ReportSourceRef, ...]

    @field_validator("text", mode="after")
    @classmethod
    def text_not_blank(cls, value: str) -> str:
        """Reject blank statements."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("narrative statement must not be blank")
        return stripped

    @field_validator("text", mode="after")
    @classmethod
    def text_bounded(cls, value: str) -> str:
        """Reject statements above the hard length ceiling."""
        if len(value) > MAX_NARRATIVE_STATEMENT_CHARS:
            raise ValueError(
                f"narrative statement exceeds {MAX_NARRATIVE_STATEMENT_CHARS} characters"
            )
        return value

    @field_validator("support", mode="after")
    @classmethod
    def support_nonempty(
        cls, value: tuple[ReportSourceRef, ...]
    ) -> tuple[ReportSourceRef, ...]:
        """Require at least one source reference."""
        if not value:
            raise ValueError(
                "narrative statement must carry at least one source reference"
            )
        return value

    @field_validator("support", mode="after")
    @classmethod
    def no_duplicate_support(
        cls, value: tuple[ReportSourceRef, ...]
    ) -> tuple[ReportSourceRef, ...]:
        """Reject duplicate source references."""
        keys = [report_source_ref_key(ref) for ref in value]
        if len(keys) != len(set(keys)):
            raise ValueError("narrative statement source references must be unique")
        return value


class ReportResearchSelection(BaseModel):
    """Model-authored selection of one persisted ResearchClaim.

    The model selects contextual claims by the exact persisted
    ``(research_result_id, research_claim_id)`` pair; the final report
    snapshots application-owned claim/citation content, never model text.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    research_result_id: UUID
    research_claim_id: UUID


class ReportWriterOutput(BaseModel):
    """The semantic-only output the Report Writer model returns.

    The model authors a title, bounded narrative statements (each with typed
    provenance), an ordering/subset of the supplied Assessment findings, and
    a selection of supplied persisted ResearchClaims. The application stamps
    every persistence-owned field, verdict, confidence, Assessment caveat
    lists, and the source-identity sets when it constructs the authoritative
    :class:`InvestigationReport`.

    Deliberate exclusions: no verdict, no confidence, no limitations, no
    unresolved questions, no recommended next steps, no persistence metadata,
    no tool/provider requests.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str
    executive_summary: tuple[ReportNarrativeStatement, ...] = ()
    finding_order: tuple[int, ...] = ()
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

    @field_validator("finding_order", mode="after")
    @classmethod
    def finding_order_valid(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        """Require positive, unique Assessment finding ordinals."""
        if any(ordinal < 1 for ordinal in value):
            raise ValueError("finding_order ordinals must be positive")
        if len(value) != len(set(value)):
            raise ValueError("finding_order must not contain duplicate ordinals")
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

    Every field except nothing: all fields are copied from the current
    Assessment finding at the referenced ordinal. The model never authors
    category, disposition, statement, confidence, or support; it may only
    order/subset the findings.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_finding_ordinal: int = Field(ge=1)
    category: FindingCategory
    disposition: FindingDisposition
    statement: str
    confidence: AssessmentConfidence
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
    Investigation's durable ``assessment_id`` pointer), its analyzed Evidence,
    the RelationshipObservations referenced by its Findings (with the stable
    Relationships/entities needed to render them), and bounded persisted
    ResearchResults. ``raw_payload`` never appears; the same persisted
    investigation state always produces the same serialized input.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    objective: str
    assessment: Assessment
    evidence: tuple[AnalystEvidenceItem, ...] = ()
    relationship_observations: tuple[AnalystRelationshipObservation, ...] = ()
    research_results: tuple[ResearchResult, ...] = ()

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
        ids = [item.evidence_id for item in value]
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
    """The authoritative persisted report domain resource (PR 23B).

    Persistence predicates (``id``, ``version``, ``created_at``, deletion
    metadata) are database-owned; callers must not supply them. Verdict and
    confidence are copied exactly from the current Assessment; caveat lists
    are copied exactly; findings and research context are application
    snapshots; the top-level source identity sets are application-derived.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID | None = None
    investigation_id: UUID
    assessment_id: UUID
    verdict: Verdict
    confidence: AssessmentConfidence
    title: str
    executive_summary: tuple[ReportNarrativeStatement, ...] = ()
    findings: tuple[ReportFindingSnapshot, ...] = ()
    research_context: tuple[ReportResearchClaimSnapshot, ...] = ()
    limitations: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    recommended_next_steps: tuple[str, ...] = ()
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
        """Reject duplicate Assessment finding ordinals."""
        ordinals = [finding.assessment_finding_ordinal for finding in value]
        if len(ordinals) != len(set(ordinals)):
            raise ValueError("report findings must have unique assessment ordinals")
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
