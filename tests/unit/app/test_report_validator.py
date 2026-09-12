# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic report provenance validation (PR 23B)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.report_writer.errors import ReportProvenanceError
from agentic_threat_investigator.app.report_writer.validator import (
    ReportProvenanceValidator,
    build_investigation_report,
)
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


class World:
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


def _af_ref(world: World, ordinal: int = 1) -> AssessmentFindingRef:
    """Build an assessment finding ref for the world."""
    return AssessmentFindingRef(
        kind="assessment_finding",
        assessment_id=world.assessment_id,
        finding_ordinal=ordinal,
    )


def _rc_ref(
    world: World, result_id: UUID | None = None, claim_id: UUID | None = None
) -> ResearchClaimRef:
    """Build a research claim ref for the world."""
    return ResearchClaimRef(
        kind="research_claim",
        research_result_id=result_id or world.result_id,
        research_claim_id=claim_id or world.claim_id,
    )


def test_u21_unknown_finding_ref_rejected() -> None:
    """23B-U21: a finding order referencing an unknown ordinal fails."""
    world = World()
    output = world.output(finding_order=(9,), research=())
    with pytest.raises(ReportProvenanceError):
        build_investigation_report(world.input(), output)


def test_u22_unknown_research_claim_ref_rejected() -> None:
    """23B-U22: an unknown research claim reference fails closed."""
    world = World()
    output = world.output(
        research=(
            ReportResearchSelection(
                research_result_id=world.result_id,
                research_claim_id=uuid4(),
            ),
        )
    )
    with pytest.raises(ReportProvenanceError):
        build_investigation_report(world.input(), output)


def test_u23_wrong_research_result_for_claim_rejected() -> None:
    """23B-U23: a claim referenced under the wrong result fails."""
    world = World()
    other_result = world.research.model_copy(update={"id": uuid4()})
    output = world.output(
        research=(
            ReportResearchSelection(
                research_result_id=other_result.id,
                research_claim_id=world.claim_id,
            ),
        )
    )
    with pytest.raises(ReportProvenanceError):
        build_investigation_report(world.input(), output)


def test_u24_cross_investigation_ref_rejected() -> None:
    """23B-U24: a narrative ref naming another Assessment fails."""
    world = World()
    statement = ReportNarrativeStatement(
        text="Cross-investigation statement.",
        support=(
            AssessmentFindingRef(
                kind="assessment_finding",
                assessment_id=uuid4(),
                finding_ordinal=1,
            ),
        ),
    )
    output = world.output(statements=(statement,))
    report = build_investigation_report(world.input(), output)
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(report, world.input())


def test_u25_valid_mixed_statement_accepts() -> None:
    """23B-U25: a statement mixing Assessment and Research refs is accepted."""
    world = World()
    output = world.output()
    report = build_investigation_report(world.input(), output)
    ReportProvenanceValidator().validate(report, world.input())
    assert report.verdict is Verdict.MALICIOUS
    assert report.executive_summary[0].support[0].kind == "assessment_finding"
    assert report.executive_summary[0].support[1].kind == "research_claim"
    assert report.source_evidence_ids == (world.evidence_id,)
    assert report.source_research_result_ids == (world.result_id,)


def test_u26_limitations_changed_rejected() -> None:
    """23B-U26: changed limitations are rejected."""
    world = World()
    output = world.output()
    report = build_investigation_report(world.input(), output)
    altered = report.model_copy(update={"limitations": ("changed",)})
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_u27_unresolved_questions_changed_rejected() -> None:
    """23B-U27: changed unresolved questions are rejected."""
    world = World()
    output = world.output()
    report = build_investigation_report(world.input(), output)
    altered = report.model_copy(update={"unresolved_questions": ("changed",)})
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_u28_next_steps_changed_rejected() -> None:
    """23B-U28: changed recommended next steps are rejected."""
    world = World()
    output = world.output()
    report = build_investigation_report(world.input(), output)
    altered = report.model_copy(update={"recommended_next_steps": ("changed",)})
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_u29_finding_snapshot_differs_rejected() -> None:
    """23B-U29: a finding snapshot differing from the Assessment is rejected."""
    world = World()
    output = world.output()
    report = build_investigation_report(world.input(), output)
    from agentic_threat_investigator.domain.report import ReportFindingSnapshot

    altered = report.model_copy(
        update={
            "findings": (
                ReportFindingSnapshot(
                    assessment_finding_ordinal=1,
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="Changed statement.",
                    confidence=AssessmentConfidence.MEDIUM,
                    support=(
                        EvidenceSupport(kind="evidence", evidence_id=world.evidence_id),
                    ),
                ),
            )
        }
    )
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_u30_research_snapshot_differs_rejected() -> None:
    """23B-U30: a research snapshot differing from the ResearchResult is rejected."""
    world = World()
    output = world.output()
    report = build_investigation_report(world.input(), output)
    from agentic_threat_investigator.domain.report import ReportResearchClaimSnapshot

    altered = report.model_copy(
        update={
            "research_context": (
                ReportResearchClaimSnapshot(
                    research_result_id=world.result_id,
                    research_claim_id=world.claim_id,
                    subject_entity_id=world.entity_id,
                    claim_text="Rewritten claim text.",
                    citation_ids=(world.citation_id,),
                    citations=(world.citation,),
                ),
            )
        }
    )
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_verdict_confidence_stamped_from_assessment() -> None:
    """Verdict and confidence are application-stamped, never model-authored."""
    world = World()
    output = world.output()
    report = build_investigation_report(world.input(), output)
    assert report.verdict is world.assessment.verdict
    assert report.confidence is world.assessment.confidence
    assert report.assessment_id == world.assessment_id


def test_source_sets_derived_from_included_provenance() -> None:
    """Top-level source sets derive from actual included provenance."""
    world = World()
    output = world.output()
    report = build_investigation_report(world.input(), output)
    assert report.source_evidence_ids == (world.evidence_id,)
    assert report.source_relationship_observation_ids == ()
    assert report.source_research_result_ids == (world.result_id,)


def test_report_is_frozen() -> None:
    """The persisted report model is immutable."""
    from pydantic import ValidationError

    world = World()
    report = build_investigation_report(world.input(), world.output())
    with pytest.raises(ValidationError):
        report.title = "changed"
