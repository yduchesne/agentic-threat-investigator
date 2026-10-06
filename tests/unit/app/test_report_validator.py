# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic report provenance validation (PR 23B, PR 35-5)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

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
    FindingCriticality,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.investigation import InvestigationStatus
from agentic_threat_investigator.domain.report import (
    FindingPresentation,
    ReportFindingSnapshot,
    ReportResearchClaimSnapshot,
    ReportResearchSelection,
    ReportSummaryItem,
    ReportWriterInput,
    ReportWriterOutput,
)
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)

_FIXED = datetime(2026, 1, 2, tzinfo=UTC)
_COMPLETED = datetime(2026, 1, 2, 2, tzinfo=UTC)


class World:
    """One fully-populated in-memory report input world."""

    def __init__(
        self,
        criticalities: tuple[FindingCriticality, ...] = (FindingCriticality.HIGH,),
    ) -> None:
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
        self.findings = tuple(
            AnalyticalFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement=f"Statement {ordinal}.",
                confidence=AssessmentConfidence.HIGH,
                criticality=criticality,
                support=(
                    EvidenceSupport(kind="evidence", evidence_id=self.evidence_id),
                ),
            )
            for ordinal, criticality in enumerate(criticalities, start=1)
        )
        self.assessment = Assessment(
            id=self.assessment_id,
            investigation_id=self.investigation_id,
            verdict=Verdict.MALICIOUS,
            confidence=AssessmentConfidence.HIGH,
            summary="The indicator is malicious.",
            analyzed_evidence_ids=(self.evidence_id,),
            findings=self.findings,
            limitations=("a limitation",),
            unresolved_questions=("a question",),
            recommended_next_steps=("a step",),
        )
        self.evidence = (
            AnalystEvidenceItem(
                evidence_observation_id=self.evidence_id,
                type=EvidenceType.REPUTATION,
                entities=(
                    AnalystEntity(
                        entity_id=self.entity_id,
                        entity_type=EntityType.DOMAIN,
                        value="example.com",
                    ),
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
            "investigation_status": InvestigationStatus.COMPLETED,
            "started_at": _FIXED,
            "completed_at": _COMPLETED,
            "stop_reason": "evidence sufficient",
        }
        payload.update(overrides)
        return ReportWriterInput.model_validate(payload)

    def presentation(
        self,
        ordinal: int,
        *,
        title: str | None = None,
        summary: str | None = None,
    ) -> FindingPresentation:
        """Build a canonical presentation for one ordinal."""
        return FindingPresentation(
            assessment_finding_ordinal=ordinal,
            title=title or f"Finding {ordinal} title",
            summary=summary or f"Finding {ordinal} summary.",
            description="Deterministic description.",
        )

    def output(
        self,
        *,
        presentations: tuple[FindingPresentation, ...] | None = None,
        research: tuple[ReportResearchSelection, ...] | None = None,
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
        if presentations is None:
            presentations = tuple(
                self.presentation(ordinal)
                for ordinal in range(1, len(self.findings) + 1)
            )
        return ReportWriterOutput(
            title="Canonical report title",
            finding_presentations=presentations,
            research_context=selections,
        )


def test_unknown_presentation_ordinal_rejected() -> None:
    """A presentation referencing an unknown ordinal fails closed."""
    world = World()
    output = world.output(presentations=(world.presentation(9),), research=())
    with pytest.raises(ReportProvenanceError):
        build_investigation_report(world.input(), output)


def test_missing_presentation_rejected() -> None:
    """A missing presentation for a canonical finding fails closed."""
    world = World(criticalities=(FindingCriticality.HIGH, FindingCriticality.LOW))
    output = world.output(presentations=(world.presentation(1),), research=())
    with pytest.raises(ReportProvenanceError):
        build_investigation_report(world.input(), output)


def test_duplicate_presentation_rejected() -> None:
    """A duplicate presentation ordinal is rejected at the model boundary."""
    from pydantic import ValidationError

    world = World()
    with pytest.raises(ValidationError):
        world.output(
            presentations=(world.presentation(1), world.presentation(1)), research=()
        )


def test_unknown_research_claim_ref_rejected() -> None:
    """An unknown research claim reference fails closed."""
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


def test_wrong_research_result_for_claim_rejected() -> None:
    """A claim referenced under the wrong result fails."""
    world = World()
    output = world.output(
        research=(
            ReportResearchSelection(
                research_result_id=uuid4(),
                research_claim_id=world.claim_id,
            ),
        )
    )
    with pytest.raises(ReportProvenanceError):
        build_investigation_report(world.input(), output)


def test_valid_report_accepts() -> None:
    """A canonical report validates and derives its source sets."""
    world = World()
    output = world.output()
    report = build_investigation_report(world.input(), output)
    ReportProvenanceValidator().validate(report, world.input())
    assert report.verdict is Verdict.MALICIOUS
    assert report.summary[0].support[0].kind == "assessment_finding"
    assert report.source_evidence_ids == (world.evidence_id,)
    assert report.source_research_result_ids == (world.result_id,)


def test_limitations_changed_rejected() -> None:
    """Changed limitations are rejected."""
    world = World()
    report = build_investigation_report(world.input(), world.output())
    altered = report.model_copy(update={"limitations": ("changed",)})
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_unresolved_questions_changed_rejected() -> None:
    """Changed unresolved questions are rejected."""
    world = World()
    report = build_investigation_report(world.input(), world.output())
    altered = report.model_copy(update={"unresolved_questions": ("changed",)})
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_next_steps_changed_rejected() -> None:
    """Changed recommended next steps are rejected."""
    world = World()
    report = build_investigation_report(world.input(), world.output())
    altered = report.model_copy(update={"recommended_next_steps": ("changed",)})
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_finding_snapshot_differs_rejected() -> None:
    """A finding snapshot differing from the Assessment is rejected."""
    world = World()
    report = build_investigation_report(world.input(), world.output())
    altered = report.model_copy(
        update={
            "findings": (
                ReportFindingSnapshot(
                    assessment_finding_ordinal=1,
                    report_finding_number=1,
                    criticality=FindingCriticality.HIGH,
                    title="title",
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="Changed statement.",
                    confidence=AssessmentConfidence.MEDIUM,
                    summary="summary",
                    description="Deterministic description.",
                    support=(
                        EvidenceSupport(kind="evidence", evidence_id=world.evidence_id),
                    ),
                ),
            )
        }
    )
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_research_snapshot_differs_rejected() -> None:
    """A research snapshot differing from the ResearchResult is rejected."""
    world = World()
    report = build_investigation_report(world.input(), world.output())
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


def test_verdict_confidence_criticality_stamped_from_assessment() -> None:
    """Verdict, confidence, and maximum criticality are application-stamped."""
    world = World(
        criticalities=(
            FindingCriticality.HIGH,
            FindingCriticality.CRITICAL,
            FindingCriticality.LOW,
        )
    )
    report = build_investigation_report(world.input(), world.output())
    assert report.verdict is world.assessment.verdict
    assert report.confidence is world.assessment.confidence
    assert report.criticality is FindingCriticality.CRITICAL


def test_zero_findings_criticality_is_informational() -> None:
    """An empty finding set yields informational overall criticality."""
    world = World(criticalities=())
    report = build_investigation_report(world.input(), world.output())
    assert report.criticality is FindingCriticality.INFORMATIONAL
    assert report.summary == ()


def test_ordering_numbering_and_summary_completeness() -> None:
    """Findings order criticality-first and Summary contains every finding."""
    world = World(
        criticalities=(
            FindingCriticality.HIGH,
            FindingCriticality.INFORMATIONAL,
            FindingCriticality.CRITICAL,
            FindingCriticality.LOW,
            FindingCriticality.MEDIUM,
        )
    )
    report = build_investigation_report(world.input(), world.output())
    assert [f.assessment_finding_ordinal for f in report.findings] == [3, 1, 5, 4, 2]
    assert [f.report_finding_number for f in report.findings] == [1, 2, 3, 4, 5]
    assert [item.report_finding_number for item in report.summary] == [1, 2, 3, 4, 5]
    assert all(
        item.assessment_finding_ordinal == f.assessment_finding_ordinal
        for item, f in zip(report.summary, report.findings, strict=True)
    )


def test_summary_mutation_rejected() -> None:
    """A Summary item that does not match its canonical finding is rejected."""
    world = World()
    report = build_investigation_report(world.input(), world.output())
    altered = report.model_copy(
        update={
            "summary": (
                ReportSummaryItem(
                    report_finding_number=1,
                    assessment_finding_ordinal=1,
                    text="Mutated summary.",
                    support=report.summary[0].support,
                ),
            )
        }
    )
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_status_snapshot_stamped_from_input() -> None:
    """The Status snapshot is copied exactly from the persisted lifecycle."""
    world = World()
    report = build_investigation_report(world.input(), world.output())
    assert report.started_at == _FIXED
    assert report.ended_at == _COMPLETED
    assert report.outcome_status is InvestigationStatus.COMPLETED
    assert report.stop_reason == "evidence sufficient"


def test_status_snapshot_mutation_rejected() -> None:
    """A mutated Status snapshot is rejected."""
    world = World()
    report = build_investigation_report(world.input(), world.output())
    altered = report.model_copy(update={"outcome_status": InvestigationStatus.FAILED})
    with pytest.raises(ReportProvenanceError):
        ReportProvenanceValidator().validate(altered, world.input())


def test_source_sets_derived_from_included_provenance() -> None:
    """Top-level source sets derive from actual included provenance."""
    world = World()
    report = build_investigation_report(world.input(), world.output())
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
