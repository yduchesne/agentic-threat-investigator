# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Markdown rendering of a validated InvestigationReport (PR 23B).

The formatter is pure presentation code. It never calls the LLM, never loads
database state, never retrieves citations, never changes semantics, never
adds recommendations, and never infers facts. Given the same
:class:`InvestigationReport`, it always produces the same bytes: no current
wall-clock time, no locale-dependent formatting, and no unordered-set
iteration.

Source-originated text is deterministically escaped so untrusted content
cannot create headings, links, or code blocks; URLs are rendered as escaped
plain text (provenance display only, never a promise of browsing).
"""

from __future__ import annotations

from agentic_threat_investigator.domain.assessment import EvidenceSupport
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
    ResearchClaimRef,
)

_SECTION_ASSESSMENT = "Assessment"
_SECTION_EXECUTIVE_SUMMARY = "Executive Summary"
_SECTION_FINDINGS = "Findings"
_SECTION_RESEARCH = "Research Context"
_SECTION_LIMITATIONS = "Limitations"
_SECTION_UNRESOLVED = "Unresolved Questions"
_SECTION_NEXT_STEPS = "Recommended Next Steps"
_SECTION_SOURCES = "Sources / Provenance"

_MARKDOWN_ESCAPES = {
    "\\": "\\\\",
    "*": "\\*",
    "_": "\\_",
    "`": "\\`",
    "[": "\\[",
    "]": "\\]",
    "#": "\\#",
    "<": "\\<",
    ">": "\\>",
    "|": "\\|",
}


def escape_markdown_text(value: str) -> str:
    """Deterministically escape Markdown metacharacters in untrusted text.

    The backslash is escaped first so later escapes cannot be re-escaped or
    interpreted as control sequences; the result is safe inside headings,
    paragraphs, and list items.
    """
    result: list[str] = []
    for char in value:
        result.append(_MARKDOWN_ESCAPES.get(char, char))
    return "".join(result)


def format_investigation_report_markdown(report: InvestigationReport) -> str:
    """Render one report as deterministic Markdown.

    Section order is stable: Assessment, Executive Summary, Findings,
    Research Context, Limitations, Unresolved Questions, Recommended Next
    Steps, Sources / Provenance. Verdict and confidence render exactly as
    persisted. Findings preserve their persisted order; research citations
    render their persisted snapshots.
    """
    sections: list[str] = []
    sections.append(f"# {escape_markdown_text(report.title)}")
    sections.append("")

    sections.append(f"## {_SECTION_ASSESSMENT}")
    sections.append(f"- Verdict: **{report.verdict.value}**")
    sections.append(f"- Confidence: **{report.confidence.value}**")
    sections.append("")

    sections.append(f"## {_SECTION_EXECUTIVE_SUMMARY}")
    if report.executive_summary:
        for statement in report.executive_summary:
            sections.append(f"- {escape_markdown_text(statement.text)}")
    else:
        sections.append("_No executive summary was authored._")
    sections.append("")

    sections.append(f"## {_SECTION_FINDINGS}")
    if report.findings:
        for finding in report.findings:
            header = (
                f"- **Finding {finding.assessment_finding_ordinal}** "
                f"({finding.category.value} / {finding.disposition.value} / "
                f"{finding.confidence.value}): "
                f"{escape_markdown_text(finding.statement)}"
            )
            sections.append(header)
            for support in finding.support:
                if isinstance(support, EvidenceSupport):
                    sections.append(f"  - Evidence: `{support.evidence_id}`")
                else:
                    sections.append(
                        f"  - RelationshipObservation: "
                        f"`{support.relationship_observation_id}`"
                    )
    else:
        sections.append("_No findings were selected._")
    sections.append("")

    sections.append(f"## {_SECTION_RESEARCH}")
    if report.research_context:
        for snapshot in report.research_context:
            sections.append(
                f"- Claim `{snapshot.research_claim_id}` "
                f"(result `{snapshot.research_result_id}`): "
                f"{escape_markdown_text(snapshot.claim_text)}"
            )
            for citation in snapshot.citations:
                title = citation.title or citation.source_record_id
                sections.append(
                    f"  - Citation `{citation.citation_id}`: "
                    f"{escape_markdown_text(title)} "
                    f"(source {escape_markdown_text(citation.source_id)})"
                )
                if citation.source_url:
                    sections.append(
                        f"    - URL: {escape_markdown_text(citation.source_url)}"
                    )
    else:
        sections.append("_No research context was included._")
    sections.append("")

    sections.append(f"## {_SECTION_LIMITATIONS}")
    if report.limitations:
        for limitation in report.limitations:
            sections.append(f"- {escape_markdown_text(limitation)}")
    else:
        sections.append("_None._")
    sections.append("")

    sections.append(f"## {_SECTION_UNRESOLVED}")
    if report.unresolved_questions:
        for question in report.unresolved_questions:
            sections.append(f"- {escape_markdown_text(question)}")
    else:
        sections.append("_None._")
    sections.append("")

    sections.append(f"## {_SECTION_NEXT_STEPS}")
    if report.recommended_next_steps:
        for step in report.recommended_next_steps:
            sections.append(f"- {escape_markdown_text(step)}")
    else:
        sections.append("_None._")
    sections.append("")

    sections.append(f"## {_SECTION_SOURCES}")
    if report.executive_summary:
        sections.append("_Executive summary references:_")
        for statement in report.executive_summary:
            for ref in statement.support:
                sections.append(f"- {_render_source_ref(ref)}")
    for finding in report.findings:
        for support in finding.support:
            if isinstance(support, EvidenceSupport):
                sections.append(
                    f"- Evidence `{support.evidence_id}` "
                    f"(finding {finding.assessment_finding_ordinal})"
                )
            else:
                sections.append(
                    f"- RelationshipObservation "
                    f"`{support.relationship_observation_id}` "
                    f"(finding {finding.assessment_finding_ordinal})"
                )
    for snapshot in report.research_context:
        sections.append(
            f"- Research claim `{snapshot.research_claim_id}` "
            f"(result `{snapshot.research_result_id}`)"
        )
    if not (report.executive_summary or report.findings or report.research_context):
        sections.append("_No report provenance was included._")

    return "\n".join(sections).rstrip() + "\n"


def _render_source_ref(ref: AssessmentFindingRef | ResearchClaimRef) -> str:
    """Render one narrative source reference as escaped plain text."""
    if isinstance(ref, AssessmentFindingRef):
        return (
            f"Assessment finding `{ref.assessment_id}` ordinal `{ref.finding_ordinal}`"
        )
    return (
        f"Research claim `{ref.research_claim_id}` (result `{ref.research_result_id}`)"
    )
