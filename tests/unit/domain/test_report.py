# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the structured report domain contracts (PR 23B)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
    ReportFindingSnapshot,
    ReportNarrativeStatement,
    ReportResearchClaimSnapshot,
    ReportResearchSelection,
    ReportWriterOutput,
    ResearchClaimRef,
)
from agentic_threat_investigator.domain.research import ResearchCitation

_FIXED = datetime(2026, 1, 2, tzinfo=UTC)


def _assessment_finding_ref(
    ordinal: int = 1, assessment_id: UUID | None = None
) -> AssessmentFindingRef:
    """Build one valid assessment finding reference."""
    return AssessmentFindingRef(
        kind="assessment_finding",
        assessment_id=assessment_id or uuid4(),
        finding_ordinal=ordinal,
    )


def _research_claim_ref() -> ResearchClaimRef:
    """Build one valid research claim reference."""
    return ResearchClaimRef(
        kind="research_claim",
        research_result_id=uuid4(),
        research_claim_id=uuid4(),
    )


def _statement(
    support: tuple[AssessmentFindingRef | ResearchClaimRef, ...] = (),
    text: str = "Canonical statement.",
) -> ReportNarrativeStatement:
    """Build one narrative statement, defaulting to one valid support."""
    refs = support or (_assessment_finding_ref(),)
    return ReportNarrativeStatement(text=text, support=refs)


def _output(**overrides: object) -> ReportWriterOutput:
    """Build a canonical ReportWriterOutput with overrides applied."""
    payload: dict[str, object] = {
        "title": "Canonical report title",
        "executive_summary": (_statement(),),
        "finding_order": (1, 2),
        "research_context": (),
    }
    payload.update(overrides)
    return ReportWriterOutput.model_validate(payload)


def _report(**overrides: object) -> InvestigationReport:
    """Build a canonical InvestigationReport with overrides applied."""
    finding = ReportFindingSnapshot(
        assessment_finding_ordinal=1,
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement="Reputation evidence indicates malicious activity.",
        confidence=AssessmentConfidence.HIGH,
        support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
    )
    payload: dict[str, object] = {
        "investigation_id": uuid4(),
        "assessment_id": uuid4(),
        "verdict": Verdict.MALICIOUS,
        "confidence": AssessmentConfidence.HIGH,
        "title": "Canonical report title",
        "executive_summary": (_statement(),),
        "findings": (finding,),
        "limitations": ("a limitation",),
    }
    payload.update(overrides)
    return InvestigationReport.model_validate(payload)


def test_u01_blank_report_title_rejected() -> None:
    """23B-U01: a blank report title is rejected in model output and report."""
    with pytest.raises(ValidationError):
        _output(title="   ")
    with pytest.raises(ValidationError):
        _report(title="\t")


def test_u02_blank_narrative_statement_rejected() -> None:
    """23B-U02: a blank narrative statement is rejected."""
    with pytest.raises(ValidationError):
        _statement(text="   ")


def test_u03_narrative_with_no_support_rejected() -> None:
    """23B-U03: a narrative statement without support is rejected."""
    with pytest.raises(ValidationError):
        ReportNarrativeStatement(text="Unsupported statement.", support=())


def test_u04_duplicate_source_refs_rejected() -> None:
    """23B-U04: duplicate source references in one statement are rejected."""
    ref = _assessment_finding_ref()
    with pytest.raises(ValidationError):
        ReportNarrativeStatement(text="Duplicate refs.", support=(ref, ref))


def test_u05_invalid_finding_ordinal_rejected() -> None:
    """23B-U05: non-positive finding ordinals are rejected everywhere."""
    with pytest.raises(ValidationError):
        _assessment_finding_ref(ordinal=0)
    with pytest.raises(ValidationError):
        _output(finding_order=(0,))
    with pytest.raises(ValidationError):
        ReportFindingSnapshot(
            assessment_finding_ordinal=0,
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            statement="statement",
            confidence=AssessmentConfidence.HIGH,
            support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
        )


def test_u06_duplicate_selected_finding_rejected() -> None:
    """23B-U06: duplicate ordinals in finding_order are rejected."""
    with pytest.raises(ValidationError):
        _output(finding_order=(1, 1))


def test_u07_extra_model_authored_verdict_rejected() -> None:
    """23B-U07: a model output carrying a verdict field fails extra=forbid."""
    with pytest.raises(ValidationError):
        _output(verdict="malicious")


def test_u08_extra_model_authored_confidence_rejected() -> None:
    """23B-U08: a model output carrying a confidence field fails extra=forbid."""
    with pytest.raises(ValidationError):
        _output(confidence="high")


def test_u09_persistence_metadata_in_model_output_rejected() -> None:
    """23B-U09: persistence-owned metadata cannot be authored by the model."""
    for field in ("id", "version", "created_at", "deleted_at", "deleted_by_actor_id"):
        with pytest.raises(ValidationError):
            _output(**{field: uuid4() if field == "id" else 1})


def test_u10_malformed_research_ref_rejected() -> None:
    """23B-U10: malformed research claim references are rejected."""
    with pytest.raises(ValidationError):
        ResearchClaimRef.model_validate(
            {"kind": "research_claim", "research_result_id": uuid4()}
        )
    with pytest.raises(ValidationError):
        ResearchClaimRef.model_validate(
            {
                "kind": "evidence",
                "research_result_id": uuid4(),
                "research_claim_id": uuid4(),
            }
        )
    with pytest.raises(ValidationError):
        ResearchClaimRef.model_validate(
            {
                "kind": "research_claim",
                "research_result_id": uuid4(),
                "research_claim_id": uuid4(),
                "extra": "forbidden",
            }
        )


def test_research_selection_duplicates_rejected() -> None:
    """Duplicate research selections in model output are rejected."""
    result_id = uuid4()
    claim_id = uuid4()
    with pytest.raises(ValidationError):
        _output(
            research_context=(
                ReportResearchSelection(
                    research_result_id=result_id, research_claim_id=claim_id
                ),
                ReportResearchSelection(
                    research_result_id=result_id, research_claim_id=claim_id
                ),
            )
        )


def test_report_finding_ordinal_duplicates_rejected() -> None:
    """Duplicate finding ordinals in the persisted report are rejected."""
    finding = ReportFindingSnapshot(
        assessment_finding_ordinal=1,
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement="statement",
        confidence=AssessmentConfidence.HIGH,
        support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
    )
    with pytest.raises(ValidationError):
        _report(findings=(finding, finding))


def test_report_round_trip_serialization() -> None:
    """A fully stamped report serializes and deserializes exactly."""
    report = _report()
    restored = InvestigationReport.model_validate(report.model_dump(mode="json"))
    assert restored == report


def test_report_research_snapshot_valid() -> None:
    """A research claim snapshot carries the persisted citation data."""
    citation = ResearchCitation(
        citation_id=uuid4(),
        document_id=uuid4(),
        source_id="urn:ati:source:mitre_attack",
        source_record_id="report--x",
        document_type="test",
        chunk_sequence=1,
        text="citation text",
        title="title",
    )
    snapshot = ReportResearchClaimSnapshot(
        research_result_id=uuid4(),
        research_claim_id=uuid4(),
        subject_entity_id=uuid4(),
        claim_text="claim text",
        citation_ids=(citation.citation_id,),
        citations=(citation,),
    )
    assert snapshot.citations == (citation,)
    restored = ReportResearchClaimSnapshot.model_validate(
        snapshot.model_dump(mode="json")
    )
    assert restored == snapshot


def test_report_source_refs_discriminate() -> None:
    """The discriminated union resolves both reference kinds."""
    assessment_ref = _assessment_finding_ref()
    research_ref = _research_claim_ref()
    union = AssessmentFindingRef | ResearchClaimRef
    assert isinstance(assessment_ref, union)
    assert isinstance(research_ref, union)


def test_assessment_bound_to_investigation() -> None:
    """ReportWriterInput requires the Assessment to belong to the Investigation."""
    from agentic_threat_investigator.domain.report import ReportWriterInput

    investigation_id = uuid4()
    assessment = Assessment(
        id=uuid4(),
        investigation_id=uuid4(),  # wrong investigation
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="summary",
        analyzed_evidence_ids=(),
    )
    with pytest.raises(ValidationError):
        ReportWriterInput(
            investigation_id=investigation_id,
            objective="objective",
            assessment=assessment,
        )


def test_persistence_fields_tolerated_on_report() -> None:
    """The persisted report may carry database-owned metadata."""
    report = _report(
        id=uuid4(),
        version=7,
        created_at=_FIXED,
    )
    assert report.version == 7
    assert report.created_at == _FIXED
