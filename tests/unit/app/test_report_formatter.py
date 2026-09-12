# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic Markdown report rendering (PR 23B)."""

from __future__ import annotations

from uuid import uuid4

from agentic_threat_investigator.app.report_writer.formatter import (
    escape_markdown_text,
    format_investigation_report_markdown,
)
from agentic_threat_investigator.domain.assessment import (
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
    ResearchClaimRef,
)
from agentic_threat_investigator.domain.research import ResearchCitation


def _citation(title: str = "Citation title") -> ResearchCitation:
    """Build one deterministic citation snapshot."""
    return ResearchCitation(
        citation_id=uuid4(),
        document_id=uuid4(),
        source_id="urn:ati:source:mitre_attack",
        source_record_id="report--x",
        document_type="test",
        chunk_sequence=1,
        text="citation text",
        title=title,
        source_url="https://attack.mitre.org/example",
    )


def _report() -> InvestigationReport:
    """Build a fully-populated deterministic report."""
    assessment_id = uuid4()
    evidence_id = uuid4()
    citation = _citation()
    return InvestigationReport(
        investigation_id=uuid4(),
        assessment_id=assessment_id,
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        title="Canonical report title",
        executive_summary=(
            ReportNarrativeStatement(
                text="The indicator is malicious with high confidence.",
                support=(
                    AssessmentFindingRef(
                        kind="assessment_finding",
                        assessment_id=assessment_id,
                        finding_ordinal=1,
                    ),
                    ResearchClaimRef(
                        kind="research_claim",
                        research_result_id=uuid4(),
                        research_claim_id=uuid4(),
                    ),
                ),
            ),
        ),
        findings=(
            ReportFindingSnapshot(
                assessment_finding_ordinal=1,
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="Reputation evidence indicates malicious activity.",
                confidence=AssessmentConfidence.HIGH,
                support=(EvidenceSupport(kind="evidence", evidence_id=evidence_id),),
            ),
        ),
        research_context=(
            ReportResearchClaimSnapshot(
                research_result_id=uuid4(),
                research_claim_id=uuid4(),
                subject_entity_id=uuid4(),
                claim_text="The family operates credential theft infrastructure.",
                citation_ids=(citation.citation_id,),
                citations=(citation,),
            ),
        ),
        limitations=("reputation evidence is third-party",),
        unresolved_questions=("what is the operator?",),
        recommended_next_steps=("monitor for 30 days",),
        source_evidence_ids=(evidence_id,),
        source_research_result_ids=(uuid4(),),
    )


def test_u41_repeated_render_byte_identical() -> None:
    """23B-U41: rendering the same report twice is byte-identical."""
    report = _report()
    assert format_investigation_report_markdown(report) == (
        format_investigation_report_markdown(report)
    )


def test_u42_section_order_deterministic() -> None:
    """23B-U42: the section order is stable."""
    rendered = format_investigation_report_markdown(_report())
    order = [
        rendered.index("## Assessment"),
        rendered.index("## Executive Summary"),
        rendered.index("## Findings"),
        rendered.index("## Research Context"),
        rendered.index("## Limitations"),
        rendered.index("## Unresolved Questions"),
        rendered.index("## Recommended Next Steps"),
        rendered.index("## Sources / Provenance"),
    ]
    assert order == sorted(order)
    assert "## Assessment" in rendered


def test_u43_verdict_confidence_rendered_unchanged() -> None:
    """23B-U43: verdict and confidence render exactly as persisted."""
    rendered = format_investigation_report_markdown(_report())
    assert "malicious" in rendered
    assert "high" in rendered
    assert "Verdict:" in rendered
    assert "Confidence:" in rendered


def test_u44_findings_preserve_order() -> None:
    """23B-U44: findings render in persisted order."""
    report = _report()
    rendered = format_investigation_report_markdown(report)
    assert "Finding 1" in rendered
    assert "Reputation evidence indicates malicious activity." in rendered


def test_u45_research_citations_rendered() -> None:
    """23B-U45: research citations render their persisted snapshots."""
    rendered = format_investigation_report_markdown(_report())
    assert "Citation title" in rendered
    assert "attack.mitre.org" in rendered


def test_u46_markdown_metacharacters_escaped() -> None:
    """23B-U46: Markdown metacharacters in source text are safely escaped."""
    citation = _citation(title="Evil *title* [link](x) `code`")
    report = _report().model_copy(
        update={
            "research_context": (
                ReportResearchClaimSnapshot(
                    research_result_id=uuid4(),
                    research_claim_id=uuid4(),
                    subject_entity_id=uuid4(),
                    claim_text="claim *with* `metacharacters` # heading",
                    citation_ids=(citation.citation_id,),
                    citations=(citation,),
                ),
            )
        }
    )
    rendered = format_investigation_report_markdown(report)
    assert "*" in rendered
    # Escaped forms must be present for the untrusted text.
    assert "\\*with\\*" in rendered
    assert "\\[link\\]" in rendered
    assert "\\`code\\`" in rendered


def test_u47_empty_research_context_valid() -> None:
    """23B-U47: empty research context renders a deterministic empty section."""
    report = _report().model_copy(update={"research_context": ()})
    rendered = format_investigation_report_markdown(report)
    assert "## Research Context" in rendered
    assert "No research context was included" in rendered


def test_u48_empty_unresolved_questions_deterministic() -> None:
    """23B-U48: empty unresolved questions render deterministically."""
    report = _report().model_copy(update={"unresolved_questions": ()})
    rendered = format_investigation_report_markdown(report)
    assert "## Unresolved Questions" in rendered
    assert "None." in rendered


def test_u49_formatter_never_calls_llm() -> None:
    """23B-U49: the formatter is pure; no LLM/database access exists."""
    report = _report()
    rendered = format_investigation_report_markdown(report)
    assert isinstance(rendered, str)
    assert rendered.endswith("\n")
    assert "## Assessment" in rendered


def test_escape_markdown_text_deterministic() -> None:
    """Escaping is deterministic and backslash-safe."""
    assert escape_markdown_text("# heading *x*") == "\\# heading \\*x\\*"
    assert escape_markdown_text("\\") == "\\\\"
    assert escape_markdown_text("plain text") == "plain text"
