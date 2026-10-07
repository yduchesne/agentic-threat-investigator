# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic Markdown report rendering (PR 23B, PR 35-5)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.app.report_writer.formatter import (
    decode_report_text,
    escape_markdown_text,
    escape_report_markdown_text,
    format_duration,
    format_investigation_report_markdown,
)
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingCriticality,
    FindingDisposition,
    RelationshipSupport,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import InvestigationStatus
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
    ReportFindingSnapshot,
    ReportResearchClaimSnapshot,
    ReportSummaryItem,
)
from agentic_threat_investigator.domain.research import ResearchCitation

_STARTED = datetime(2026, 1, 2, tzinfo=UTC)
_ENDED = datetime(2026, 1, 2, 1, 30, tzinfo=UTC)


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


def _finding(
    ordinal: int,
    number: int,
    criticality: FindingCriticality,
    *,
    evidence_ids: tuple[UUID, ...] = (),
    observation_ids: tuple[UUID, ...] = (),
) -> ReportFindingSnapshot:
    """Build one report finding snapshot with optional support kinds."""
    support: list[EvidenceSupport | RelationshipSupport] = [
        EvidenceSupport(kind="evidence", evidence_id=evidence_id)
        for evidence_id in evidence_ids
    ]
    support.extend(
        RelationshipSupport(
            kind="relationship_observation",
            relationship_observation_id=observation_id,
        )
        for observation_id in observation_ids
    )
    if not support:
        support.append(EvidenceSupport(kind="evidence", evidence_id=uuid4()))
    return ReportFindingSnapshot(
        assessment_finding_ordinal=ordinal,
        report_finding_number=number,
        criticality=criticality,
        title=f"Short factual title {number}",
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement=f"Finding statement {number}.",
        confidence=AssessmentConfidence.HIGH,
        summary=f"Summary sentence {number}.",
        description="Deterministic description.",
        support=tuple(support),
    )


def _report() -> InvestigationReport:
    """Build a fully-populated deterministic report."""
    assessment_id = uuid4()
    evidence_id = uuid4()
    citation = _citation()
    findings = (
        _finding(1, 1, FindingCriticality.HIGH, evidence_ids=(evidence_id,)),
        _finding(
            2,
            2,
            FindingCriticality.LOW,
            observation_ids=(uuid4(),),
        ),
    )
    return InvestigationReport(
        investigation_id=uuid4(),
        assessment_id=assessment_id,
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        criticality=FindingCriticality.HIGH,
        title="Canonical report title",
        summary=tuple(
            ReportSummaryItem(
                report_finding_number=finding.report_finding_number,
                assessment_finding_ordinal=finding.assessment_finding_ordinal,
                text=finding.summary,
                support=(
                    AssessmentFindingRef(
                        kind="assessment_finding",
                        assessment_id=assessment_id,
                        finding_ordinal=finding.assessment_finding_ordinal,
                    ),
                ),
            )
            for finding in findings
        ),
        findings=findings,
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
        started_at=_STARTED,
        ended_at=_ENDED,
        outcome_status=InvestigationStatus.COMPLETED,
        stop_reason="evidence sufficient",
        source_evidence_ids=(evidence_id,),
        source_research_result_ids=(uuid4(),),
    )


def test_details_body_uses_persisted_description() -> None:
    """Details renders the persisted description, not the analytical statement."""
    rendered = format_investigation_report_markdown(_report())
    assert "Deterministic description." in rendered
    assert "Finding statement 1." not in rendered
    assert "Finding statement 2." not in rendered


def test_repeated_render_byte_identical() -> None:
    """Rendering the same report twice is byte-identical."""
    report = _report()
    assert format_investigation_report_markdown(report) == (
        format_investigation_report_markdown(report)
    )


def test_section_order_deterministic() -> None:
    """The Final Report section order is stable and Lifecycle is gone."""
    rendered = format_investigation_report_markdown(_report())
    order = [
        rendered.index("## Summary"),
        rendered.index("## Status"),
        rendered.index("## Details"),
        rendered.index("### Findings"),
        rendered.index("### Research Context"),
        rendered.index("### Limitations"),
        rendered.index("### Unresolved Questions"),
        rendered.index("### Recommended Next Steps"),
    ]
    assert order == sorted(order)
    assert "Executive Summary" not in rendered
    assert "Lifecycle" not in rendered
    assert "## Assessment" not in rendered


def test_summary_and_details_share_numbers() -> None:
    """The Summary contains every finding with the same Detail numbers."""
    rendered = format_investigation_report_markdown(_report())
    assert "- Finding 1: Summary sentence 1." in rendered
    assert "- Finding 2: Summary sentence 2." in rendered
    assert "#### Finding 1 — Short factual title 1" in rendered
    assert "#### Finding 2 — Short factual title 2" in rendered


def test_summary_complete_no_additional_note() -> None:
    """A complete Summary never renders an additional-findings note."""
    rendered = format_investigation_report_markdown(_report())
    assert "Additional findings are detailed below." not in rendered


def test_status_section_fields() -> None:
    """Status renders Criticality, Confidence, Timeline, and Outcome."""
    rendered = format_investigation_report_markdown(_report())
    assert "- Criticality: **high**" in rendered
    assert "- Confidence: **high**" in rendered
    assert "- Timeline:" in rendered
    assert "  - Started at: 2026-01-02T00:00:00+00:00" in rendered
    assert "  - Ended at: 2026-01-02T01:30:00+00:00" in rendered
    assert "  - Duration: 1 hour 30 minutes" in rendered
    assert "- Outcome / stop reason: evidence sufficient" in rendered


def test_corroboration_grouping() -> None:
    """Corroboration groups evidence and relationships and omits empty groups."""
    report = _report()
    rendered = format_investigation_report_markdown(report)
    assert "##### Corroboration" in rendered
    assert "###### Evidence" in rendered
    assert "###### Relationships" in rendered
    # The relationship-only finding has no Evidence subheading after it.
    second = rendered[rendered.index("#### Finding 2") :]
    assert "###### Evidence" not in second
    assert "###### Relationships" in second


def test_empty_optional_sections_omitted() -> None:
    """Optional empty structures and their headings are omitted."""
    report = _report().model_copy(
        update={
            "research_context": (),
            "limitations": (),
            "unresolved_questions": (),
            "recommended_next_steps": (),
        }
    )
    rendered = format_investigation_report_markdown(report)
    assert "### Research Context" not in rendered
    assert "### Limitations" not in rendered
    assert "### Unresolved Questions" not in rendered
    assert "### Recommended Next Steps" not in rendered
    assert "_None._" not in rendered
    assert "No research context" not in rendered


def test_research_citations_rendered() -> None:
    """Research citations render their persisted snapshots."""
    rendered = format_investigation_report_markdown(_report())
    assert "Citation title" in rendered
    assert "attack.mitre.org" in rendered


def test_markdown_metacharacters_escaped() -> None:
    """Markdown metacharacters in source text are safely escaped."""
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
    assert "\\*with\\*" in rendered
    assert "\\[link\\]" in rendered
    assert "\\`code\\`" in rendered


def test_format_duration_available() -> None:
    """Duration is deterministic and derived only from timestamps."""
    assert format_duration(_STARTED, _ENDED) == "1 hour 30 minutes"
    assert format_duration(None, _ENDED) is None
    assert format_duration(_STARTED, None) is None
    assert format_duration(_STARTED, _STARTED) == "0 seconds"


def test_escape_markdown_text_deterministic() -> None:
    """Escaping is deterministic and backslash-safe."""
    assert escape_markdown_text("# heading *x*") == "\\# heading \\*x\\*"
    assert escape_markdown_text("\\") == "\\\\"
    assert escape_markdown_text("plain text") == "plain text"


def test_decode_report_text_is_single_pass() -> None:
    """HTML character references decode exactly one layer."""
    assert decode_report_text("C&amp;C") == "C&C"
    assert decode_report_text("&#39;C&amp;C server&#39;") == "'C&C server'"
    assert decode_report_text("&amp;lt;script&amp;gt;") == "&lt;script&gt;"
    assert decode_report_text("AT&T") == "AT&T"


def test_escape_report_markdown_text_decodes_before_escaping() -> None:
    """Entity decoding happens before Markdown escaping, never after."""
    # Decoded markup is still Markdown-escaped, so it stays literal text.
    assert escape_report_markdown_text("&lt;script&gt;") == "\\<script\\>"
    assert escape_report_markdown_text("C&amp;C") == "C&C"
    assert escape_report_markdown_text("&amp;lt;b&amp;gt;") == "&lt;b&gt;"


def test_markdown_prose_decodes_entities_before_escaping() -> None:
    """Persisted encoded prose renders as plain text in the Markdown view."""
    report = _report().model_copy(
        update={
            "title": "C&amp;C &lt;script&gt;",
            "limitations": ("a &amp; b",),
            "research_context": (
                ReportResearchClaimSnapshot(
                    research_result_id=uuid4(),
                    research_claim_id=uuid4(),
                    subject_entity_id=uuid4(),
                    claim_text="context &amp; &#39;claim&#39;",
                    citation_ids=(_citation().citation_id,),
                    citations=(_citation(title="Title &amp; &quot;quoted&quot;"),),
                ),
            ),
            "findings": (
                _finding(1, 1, FindingCriticality.HIGH).model_copy(
                    update={
                        "title": "Encoded &amp; title",
                        "description": (
                            "C&amp;C described as &#39;C&amp;C server&#39;"
                        ),
                    }
                ),
            ),
            "summary": (
                ReportSummaryItem(
                    report_finding_number=1,
                    assessment_finding_ordinal=1,
                    text="Summary &amp; detail",
                    support=(
                        AssessmentFindingRef(
                            kind="assessment_finding",
                            assessment_id=uuid4(),
                            finding_ordinal=1,
                        ),
                    ),
                ),
            ),
        }
    )
    rendered = format_investigation_report_markdown(report)
    assert "# C&C \\<script\\>" in rendered
    assert "C&C described as 'C&C server'" in rendered
    assert "Summary & detail" in rendered
    assert "Encoded & title" in rendered
    assert "context & 'claim'" in rendered
    assert 'Title & "quoted"' in rendered
    assert "- a & b" in rendered
    # No encoded reference survives the Markdown presentation.
    assert "&amp;" not in rendered
    assert "&#39;" not in rendered
