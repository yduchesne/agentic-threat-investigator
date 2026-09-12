# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared in-memory Report Writer world for PR 23B unit suites.

One fully-populated :class:`ReportWriterInput` (current Assessment with one
supported finding, one Evidence, one ResearchResult with one claim/citation)
built from pure domain objects — no database, no provider, no LLM.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from agentic_threat_investigator.domain.analyst import (
    AnalystEntity,
    AnalystEvidenceItem,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    ReportNarrativeStatement,
    ReportResearchSelection,
    ReportWriterInput,
    ReportWriterOutput,
    ResearchClaimRef,
)
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)

_FIXED = datetime(2026, 1, 2, tzinfo=UTC)


class ReportWriterUnitWorld:
    """One fully-populated in-memory report input world."""

    def __init__(self) -> None:
        self.investigation_id = uuid4()
        self.assessment_id = uuid4()
        self.entity_id = uuid4()
        self.evidence_id = uuid4()
        self.result_id = uuid4()
        self.claim_id = uuid4()
        self.citation_id = uuid4()

        self.citation = ResearchCitation(
            citation_id=self.citation_id,
            document_id=uuid4(),
            source_id="urn:ati:source:mitre_attack",
            source_record_id="report--x",
            document_type="test",
            chunk_sequence=1,
            text="citation text",
            title="title",
        )
        self.research = ResearchResult(
            id=self.result_id,
            investigation_id=self.investigation_id,
            subject_entity_id=self.entity_id,
            query="context query",
            claims=(
                ResearchClaim(
                    id=self.claim_id,
                    text="context claim",
                    citation_ids=(self.citation_id,),
                ),
            ),
            citations=(self.citation,),
            created_at=_FIXED,
        )
        self.assessment = Assessment(
            id=self.assessment_id,
            investigation_id=self.investigation_id,
            verdict=Verdict.MALICIOUS,
            confidence=AssessmentConfidence.HIGH,
            summary="The indicator is malicious.",
            analyzed_evidence_ids=(self.evidence_id,),
            findings=(
                AnalyticalFinding(
                    category=FindingCategory.REPUTATION,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="Reputation evidence indicates malicious activity.",
                    confidence=AssessmentConfidence.HIGH,
                    support=(
                        EvidenceSupport(kind="evidence", evidence_id=self.evidence_id),
                    ),
                ),
            ),
            limitations=("a limitation",),
            unresolved_questions=("a question",),
            recommended_next_steps=("a step",),
        )
        self.evidence = (
            AnalystEvidenceItem(
                evidence_id=self.evidence_id,
                type=EvidenceType.REPUTATION,
                subject=AnalystEntity(
                    entity_id=self.entity_id,
                    entity_type=EntityType.DOMAIN,
                    value="example.com",
                ),
                source="urn:ati:source:abuseipdb",
                retrieved_at=_FIXED,
                facts={"score": 90},
            ),
        )

    def input(self, **overrides: object) -> ReportWriterInput:
        """Build the report input with optional overrides."""
        payload: dict[str, object] = {
            "investigation_id": self.investigation_id,
            "objective": "Assess the root indicator.",
            "assessment": self.assessment,
            "evidence": self.evidence,
            "research_results": (self.research,),
        }
        payload.update(overrides)
        return ReportWriterInput.model_validate(payload)

    def output(
        self,
        *,
        finding_order: tuple[int, ...] = (1,),
        research: tuple[ReportResearchSelection, ...] | None = None,
        statements: tuple[ReportNarrativeStatement, ...] | None = None,
    ) -> ReportWriterOutput:
        """Build a canonical model output for this world."""
        selections = (
            research
            if research is not None
            else (
                ReportResearchSelection(
                    research_result_id=self.result_id,
                    research_claim_id=self.claim_id,
                ),
            )
        )
        narrative = statements
        if narrative is None:
            narrative = (
                ReportNarrativeStatement(
                    text="Canonical statement.",
                    support=(
                        AssessmentFindingRef(
                            kind="assessment_finding",
                            assessment_id=self.assessment_id,
                            finding_ordinal=1,
                        ),
                        ResearchClaimRef(
                            kind="research_claim",
                            research_result_id=self.result_id,
                            research_claim_id=self.claim_id,
                        ),
                    ),
                ),
            )
        return ReportWriterOutput(
            title="Canonical report title",
            executive_summary=narrative,
            finding_order=finding_order,
            research_context=selections,
        )

    def unsupported_output(self) -> ReportWriterOutput:
        """Build a schema-valid output with an unsupported research reference."""
        return self.output(
            research=(
                ReportResearchSelection(
                    research_result_id=self.result_id,
                    research_claim_id=uuid4(),
                ),
            ),
            statements=(),
        )
