# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the structured report domain contracts (PR 23B, PR 35-5)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

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
from agentic_threat_investigator.domain.investigation import InvestigationStatus
from agentic_threat_investigator.domain.report import (
    MAX_DESCRIPTION_CHARS,
    MAX_FINDING_TITLE_CHARS,
    MAX_SUMMARY_CHARS,
    AssessmentFindingRef,
    FindingPresentation,
    InvestigationReport,
    ReportFindingSnapshot,
    ReportResearchClaimSnapshot,
    ReportResearchSelection,
    ReportSummaryItem,
    ReportWriterOutput,
    criticality_first_ordering,
    is_summary_eligible,
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


def _presentation(
    ordinal: int = 1,
    *,
    title: str = "Short factual title",
    summary: str = "One concise factual sentence.",
    description: str = "Detailed reader-facing description.",
) -> FindingPresentation:
    """Build one valid finding presentation."""
    return FindingPresentation(
        assessment_finding_ordinal=ordinal,
        title=title,
        summary=summary,
        description=description,
    )


def _output(**overrides: object) -> ReportWriterOutput:
    """Build a canonical ReportWriterOutput with overrides applied."""
    payload: dict[str, object] = {
        "title": "Canonical report title",
        "finding_presentations": (_presentation(1), _presentation(2)),
        "research_context": (),
    }
    payload.update(overrides)
    return ReportWriterOutput.model_validate(payload)


def _snapshot(ordinal: int = 1, number: int = 1) -> ReportFindingSnapshot:
    """Build one canonical report finding snapshot."""
    return ReportFindingSnapshot(
        assessment_finding_ordinal=ordinal,
        report_finding_number=number,
        criticality=FindingCriticality.HIGH,
        title="Short factual title",
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement="Reputation evidence indicates malicious activity.",
        confidence=AssessmentConfidence.HIGH,
        summary="One concise factual sentence.",
        description="Deterministic description.",
        support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
    )


def _report(**overrides: object) -> InvestigationReport:
    """Build a canonical InvestigationReport with overrides applied."""
    finding = _snapshot()
    summary = ReportSummaryItem(
        report_finding_number=1,
        assessment_finding_ordinal=1,
        text=finding.summary,
        support=(
            AssessmentFindingRef(
                assessment_id=uuid4(),
                finding_ordinal=1,
            ),
        ),
    )
    payload: dict[str, object] = {
        "investigation_id": uuid4(),
        "assessment_id": uuid4(),
        "verdict": Verdict.MALICIOUS,
        "confidence": AssessmentConfidence.HIGH,
        "criticality": FindingCriticality.HIGH,
        "title": "Canonical report title",
        "summary": (summary,),
        "findings": (finding,),
        "limitations": ("a limitation",),
        "outcome_status": InvestigationStatus.COMPLETED,
    }
    payload.update(overrides)
    return InvestigationReport.model_validate(payload)


def test_u01_blank_report_title_rejected() -> None:
    """A blank report title is rejected in model output and report."""
    with pytest.raises(ValidationError):
        _output(title="   ")
    with pytest.raises(ValidationError):
        _report(title="\t")


def test_u02_blank_presentation_text_rejected() -> None:
    """A blank finding title, summary, or description is rejected."""
    with pytest.raises(ValidationError):
        _presentation(title="   ")
    with pytest.raises(ValidationError):
        _presentation(summary="   ")
    with pytest.raises(ValidationError):
        _presentation(description="   ")


def test_presentation_text_bounds_enforced() -> None:
    """Title, summary, and description are bounded."""
    with pytest.raises(ValidationError):
        _presentation(title="x" * (MAX_FINDING_TITLE_CHARS + 1))
    with pytest.raises(ValidationError):
        _presentation(summary="x" * (MAX_SUMMARY_CHARS + 1))
    with pytest.raises(ValidationError):
        _presentation(description="x" * (MAX_DESCRIPTION_CHARS + 1))


def test_persisted_description_distinct_from_statement() -> None:
    """The report keeps the authoritative statement and reader description."""
    report = _report()
    finding = report.findings[0]
    assert finding.statement == "Reputation evidence indicates malicious activity."
    assert finding.description == "Deterministic description."
    assert finding.summary == "One concise factual sentence."


def test_u03_blank_summary_item_rejected() -> None:
    """A blank summary item text is rejected."""
    with pytest.raises(ValidationError):
        ReportSummaryItem(
            report_finding_number=1,
            assessment_finding_ordinal=1,
            text="   ",
            support=(_assessment_finding_ref(),),
        )


def test_u04_summary_item_requires_exactly_one_support() -> None:
    """A summary item must reference exactly one assessment finding."""
    with pytest.raises(ValidationError):
        ReportSummaryItem(
            report_finding_number=1,
            assessment_finding_ordinal=1,
            text="text",
            support=(),
        )
    with pytest.raises(ValidationError):
        ReportSummaryItem(
            report_finding_number=1,
            assessment_finding_ordinal=1,
            text="text",
            support=(_assessment_finding_ref(1), _assessment_finding_ref(2)),
        )


def test_u05_invalid_finding_ordinal_rejected() -> None:
    """Non-positive finding ordinals and numbers are rejected everywhere."""
    with pytest.raises(ValidationError):
        _assessment_finding_ref(ordinal=0)
    with pytest.raises(ValidationError):
        _presentation(ordinal=0)
    with pytest.raises(ValidationError):
        _snapshot(ordinal=0)
    with pytest.raises(ValidationError):
        _snapshot(number=0)


def test_u06_duplicate_presentation_ordinal_rejected() -> None:
    """Duplicate ordinals in finding_presentations are rejected."""
    with pytest.raises(ValidationError):
        _output(finding_presentations=(_presentation(1), _presentation(1)))


def test_u07_extra_model_authored_authority_rejected() -> None:
    """A model output cannot author verdict, confidence, or criticality."""
    for field, value in (
        ("verdict", "malicious"),
        ("confidence", "high"),
        ("criticality", "high"),
        ("finding_order", [1]),
    ):
        with pytest.raises(ValidationError):
            _output(**{field: value})


def test_u09_persistence_metadata_in_model_output_rejected() -> None:
    """Persistence-owned metadata cannot be authored by the model."""
    for field in ("id", "version", "created_at", "deleted_at", "deleted_by_actor_id"):
        with pytest.raises(ValidationError):
            _output(**{field: uuid4() if field == "id" else 1})


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
    """Duplicate finding ordinals or numbers in the persisted report fail."""
    first = _snapshot(ordinal=1, number=1)
    duplicate_ordinal = _snapshot(ordinal=1, number=2)
    with pytest.raises(ValidationError):
        _report(findings=(first, duplicate_ordinal))
    duplicate_number = _snapshot(ordinal=2, number=1)
    with pytest.raises(ValidationError):
        _report(findings=(first, duplicate_number))


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
            investigation_status=InvestigationStatus.COMPLETED,
            started_at=_FIXED,
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


def test_criticality_first_ordering() -> None:
    """Findings are ordered by criticality then ascending Assessment ordinal."""
    criticalities = (
        FindingCriticality.HIGH,
        FindingCriticality.INFORMATIONAL,
        FindingCriticality.CRITICAL,
        FindingCriticality.LOW,
        FindingCriticality.MEDIUM,
    )
    findings = tuple(
        AnalyticalFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            statement=f"statement {ordinal}",
            confidence=AssessmentConfidence.MEDIUM,
            criticality=criticality,
            support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
        )
        for ordinal, criticality in enumerate(criticalities, start=1)
    )
    ordered = criticality_first_ordering(findings)
    assert [ordinal for ordinal, _ in ordered] == [3, 1, 5, 4, 2]


def test_summary_eligibility_threshold() -> None:
    """Only critical/high/medium are Summary-eligible."""
    assert is_summary_eligible(FindingCriticality.CRITICAL)
    assert is_summary_eligible(FindingCriticality.HIGH)
    assert is_summary_eligible(FindingCriticality.MEDIUM)
    assert not is_summary_eligible(FindingCriticality.LOW)
    assert not is_summary_eligible(FindingCriticality.INFORMATIONAL)
