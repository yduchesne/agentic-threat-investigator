# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Markdown rendering of a validated InvestigationReport.

The formatter is pure presentation code. It never calls the LLM, never loads
database state, never retrieves citations, never changes semantics, never
adds recommendations, and never infers facts. Given the same
:class:`InvestigationReport`, it always produces the same bytes: no current
wall-clock time, no locale-dependent formatting, and no unordered-set
iteration.

The rendered hierarchy is the canonical Final Report structure: Summary,
Status, and Details (Findings with nested Corroboration, then the optional
Research Context, Limitations, Unresolved Questions, and Recommended Next
Steps). Empty optional structures are omitted entirely rather than rendered
as placeholders.

Source-originated text is deterministically escaped so untrusted content
cannot create headings, links, or code blocks; URLs are rendered as escaped
plain text (provenance display only, never a promise of browsing).
"""

from __future__ import annotations

from datetime import datetime

from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    EvidenceSupport,
    FindingCriticality,
    RelationshipSupport,
)
from agentic_threat_investigator.domain.report import InvestigationReport

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


def _localized(value: FindingCriticality | AssessmentConfidence) -> str:
    """Return the stable human-readable label for a bounded enum value."""
    return str(value.value)


def format_duration(
    started_at: datetime | None, ended_at: datetime | None
) -> str | None:
    """Return a deterministic human-readable duration, if available.

    The duration is derived only from the persisted timestamps; it is never
    based on the current wall-clock time. When either timestamp is absent or
    the interval is negative the duration is unavailable.
    """
    if started_at is None or ended_at is None:
        return None
    total_seconds = int((ended_at - started_at).total_seconds())
    if total_seconds < 0:
        return None
    days, remainder = divmod(total_seconds, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, seconds = divmod(remainder, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days} day" + ("" if days == 1 else "s"))
    if hours:
        parts.append(f"{hours} hour" + ("" if hours == 1 else "s"))
    if minutes:
        parts.append(f"{minutes} minute" + ("" if minutes == 1 else "s"))
    if seconds and not days:
        parts.append(f"{seconds} second" + ("" if seconds == 1 else "s"))
    if not parts:
        return "0 seconds"
    return " ".join(parts)


def _render_status_lines(report: InvestigationReport) -> list[str]:
    """Render the deterministic Status section lines."""
    lines: list[str] = []
    lines.append(f"- Criticality: **{_localized(report.criticality)}**")
    lines.append(f"- Confidence: **{_localized(report.confidence)}**")
    timeline: list[str] = []
    if report.started_at is not None:
        timeline.append(f"  - Started at: {report.started_at.isoformat()}")
    if report.ended_at is not None:
        timeline.append(f"  - Ended at: {report.ended_at.isoformat()}")
    duration = format_duration(report.started_at, report.ended_at)
    if duration is not None:
        timeline.append(f"  - Duration: {duration}")
    if timeline:
        lines.append("- Timeline:")
        lines.extend(timeline)
    if report.stop_reason:
        lines.append(
            f"- Outcome / stop reason: {escape_markdown_text(report.stop_reason)}"
        )
    else:
        lines.append(
            f"- Outcome / stop reason: {escape_markdown_text(report.outcome_status.value)}"
        )
    return lines


def _render_finding_markdown(report: InvestigationReport) -> list[str]:
    """Render the Details -> Findings hierarchy including Corroboration."""
    sections: list[str] = []
    sections.append("### Findings")
    sections.append("")
    for finding in report.findings:
        title = escape_markdown_text(finding.title)
        sections.append(f"#### Finding {finding.report_finding_number} — {title}")
        sections.append("")
        sections.append(f"Criticality: **{_localized(finding.criticality)}**")
        sections.append(f"Confidence: **{_localized(finding.confidence)}**")
        sections.append("")
        sections.append(escape_markdown_text(finding.description))
        sections.append("")
        evidence_supports = [
            support
            for support in finding.support
            if isinstance(support, EvidenceSupport)
        ]
        relationship_supports = [
            support
            for support in finding.support
            if isinstance(support, RelationshipSupport)
        ]
        if evidence_supports or relationship_supports:
            sections.append("##### Corroboration")
            sections.append("")
            if evidence_supports:
                sections.append("###### Evidence")
                sections.append("")
                for evidence_support in evidence_supports:
                    sections.append(f"- Evidence `{evidence_support.evidence_id}`")
                sections.append("")
            if relationship_supports:
                sections.append("###### Relationships")
                sections.append("")
                for relationship_support in relationship_supports:
                    sections.append(
                        "- RelationshipObservation "
                        f"`{relationship_support.relationship_observation_id}`"
                    )
                sections.append("")
    return sections


def format_investigation_report_markdown(report: InvestigationReport) -> str:
    """Render one report as deterministic Markdown.

    Section order is stable: Summary, Status, Details (Findings, optionally
    Research Context, Limitations, Unresolved Questions, Recommended Next
    Steps). Optional sections with no content are omitted entirely. All
    finding numbers are the same deterministic numbers used everywhere else.
    """
    sections: list[str] = []
    sections.append(f"# {escape_markdown_text(report.title)}")
    sections.append("")

    sections.append("## Summary")
    sections.append("")
    if report.summary:
        for item in report.summary:
            sections.append(
                f"- Finding {item.report_finding_number}: "
                f"{escape_markdown_text(item.text)}"
            )
    sections.append("")

    sections.append("## Status")
    sections.append("")
    sections.extend(_render_status_lines(report))
    sections.append("")

    sections.append("## Details")
    sections.append("")
    sections.extend(_render_finding_markdown(report))

    if report.research_context:
        sections.append("### Research Context")
        sections.append("")
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
        sections.append("")

    if report.limitations:
        sections.append("### Limitations")
        sections.append("")
        for limitation in report.limitations:
            sections.append(f"- {escape_markdown_text(limitation)}")
        sections.append("")

    if report.unresolved_questions:
        sections.append("### Unresolved Questions")
        sections.append("")
        for question in report.unresolved_questions:
            sections.append(f"- {escape_markdown_text(question)}")
        sections.append("")

    if report.recommended_next_steps:
        sections.append("### Recommended Next Steps")
        sections.append("")
        for step in report.recommended_next_steps:
            sections.append(f"- {escape_markdown_text(step)}")
        sections.append("")

    return "\n".join(sections).rstrip() + "\n"
