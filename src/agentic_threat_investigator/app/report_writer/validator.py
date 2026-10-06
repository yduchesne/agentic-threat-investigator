# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Report provenance validation and authoritative assembly.

:func:`build_investigation_report` stamps every application-owned field onto
the authoritative :class:`InvestigationReport` from a
:class:`ReportWriterInput` and a :class:`ReportWriterOutput`. The canonical
finding set is the complete current Assessment finding set, ordered
deterministically criticality-first (tie-broken by ascending Assessment
ordinal) and numbered contiguously from one. The model contributes only one
bounded presentation (short title + Summary sentence) per canonical finding
plus research-context selections; it can never select, omit, reorder,
renumber, or change analytical fields.

:class:`ReportProvenanceValidator` then proves deterministic closure before
persistence:

- Assessment authority (investigation binding, assessment identity,
  verdict/confidence/caveat equality);
- presentation closure (exactly one presentation per canonical finding, no
  unknown/duplicate/missing ordinals);
- finding closure (every Assessment finding appears exactly once, snapshots
  match the authoritative finding exactly, numbering is contiguous, and the
  order is canonical);
- Summary closure (exactly the critical/high/medium findings in order, text
  equal to the canonical presentation sentence, exactly one typed
  Assessment-finding support reference each);
- Verdict/confidence/criticality authority (overall criticality is the
  deterministic maximum finding criticality);
- Status snapshot closure (lifecycle fields equal the persisted input);
- research closure (snapshots match the persisted claim/citation snapshots);
- source-set closure (top-level ID sets equal the derived sets).

This validator proves reference integrity, never semantic entailment:
whether a presentation faithfully paraphrases its cited finding is a
behavioral-evaluation question, not a deterministic property.
"""

from __future__ import annotations

from uuid import UUID

from agentic_threat_investigator.app.report_writer.errors import (
    ReportProvenanceError,
)
from agentic_threat_investigator.domain.assessment import (
    CRITICALITY_RANK,
    AnalyticalFinding,
    EvidenceSupport,
    FindingCriticality,
)
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    FindingPresentation,
    InvestigationReport,
    ReportFindingSnapshot,
    ReportResearchClaimSnapshot,
    ReportResearchSelection,
    ReportSummaryItem,
    ReportWriterInput,
    ReportWriterOutput,
    criticality_first_ordering,
    is_summary_eligible,
)
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)


def maximum_criticality(
    findings: tuple[AnalyticalFinding, ...],
) -> FindingCriticality:
    """Return the deterministic maximum criticality across a finding set.

    The most material criticality wins. An empty finding set is
    ``informational``: no finding exists, so no stronger claim may be made.
    """
    criticalities = [finding.criticality for finding in findings]
    if not criticalities:
        return FindingCriticality.INFORMATIONAL
    return min(criticalities, key=lambda value: CRITICALITY_RANK[value])


def _presentations_by_ordinal(
    output: ReportWriterOutput,
) -> dict[int, FindingPresentation]:
    """Return the model presentations keyed by Assessment finding ordinal."""
    return {
        presentation.assessment_finding_ordinal: presentation
        for presentation in output.finding_presentations
    }


def build_investigation_report(
    report_input: ReportWriterInput,
    output: ReportWriterOutput,
) -> InvestigationReport:
    """Assemble the authoritative report by application stamping only.

    The model contributes the title, one bounded presentation per canonical
    finding, and research-context selections; every other field is copied or
    derived from the authoritative input snapshot. Findings are ordered and
    numbered deterministically; the Summary is the deterministic
    Summary-eligible projection of the same canonical finding set.
    """
    assessment_id = report_input.assessment.id
    if assessment_id is None:  # pragma: no cover - loaded inputs carry it
        raise ReportProvenanceError("report input assessment has no persisted identity")

    presentations = _presentations_by_ordinal(output)
    ordered = criticality_first_ordering(report_input.assessment.findings)

    findings: list[ReportFindingSnapshot] = []
    for report_number, (ordinal, finding) in enumerate(ordered, start=1):
        presentation = presentations.get(ordinal)
        if presentation is None:
            raise ReportProvenanceError(
                "report output is missing a presentation for assessment "
                f"finding ordinal: {ordinal}"
            )
        findings.append(
            ReportFindingSnapshot(
                assessment_finding_ordinal=ordinal,
                report_finding_number=report_number,
                criticality=finding.criticality,
                title=presentation.title,
                category=finding.category,
                disposition=finding.disposition,
                statement=finding.statement,
                confidence=finding.confidence,
                summary=presentation.summary,
                description=presentation.description,
                support=finding.support,
            )
        )

    summary = tuple(
        ReportSummaryItem(
            report_finding_number=finding.report_finding_number,
            assessment_finding_ordinal=finding.assessment_finding_ordinal,
            text=finding.summary,
            support=(
                AssessmentFindingRef(
                    assessment_id=assessment_id,
                    finding_ordinal=finding.assessment_finding_ordinal,
                ),
            ),
        )
        for finding in findings
        if is_summary_eligible(finding.criticality)
    )

    research_context = tuple(
        _snapshot_research_claim(report_input, selection)
        for selection in output.research_context
    )

    source_evidence_ids: list[UUID] = []
    source_observation_ids: list[UUID] = []
    for snapshot in findings:
        for support in snapshot.support:
            if isinstance(support, EvidenceSupport):
                source_evidence_ids.append(support.evidence_id)
            else:
                source_observation_ids.append(support.relationship_observation_id)

    return InvestigationReport(
        investigation_id=report_input.investigation_id,
        assessment_id=assessment_id,
        verdict=report_input.assessment.verdict,
        confidence=report_input.assessment.confidence,
        criticality=maximum_criticality(report_input.assessment.findings),
        title=output.title,
        summary=summary,
        findings=tuple(findings),
        research_context=research_context,
        limitations=report_input.assessment.limitations,
        unresolved_questions=report_input.assessment.unresolved_questions,
        recommended_next_steps=report_input.assessment.recommended_next_steps,
        started_at=report_input.started_at,
        ended_at=report_input.completed_at,
        outcome_status=report_input.investigation_status,
        stop_reason=report_input.stop_reason,
        source_evidence_ids=_deduplicate(source_evidence_ids),
        source_relationship_observation_ids=_deduplicate(source_observation_ids),
        source_research_result_ids=_deduplicate(
            [snapshot.research_result_id for snapshot in research_context]
        ),
    )


def _snapshot_research_claim(
    report_input: ReportWriterInput, selection: ReportResearchSelection
) -> ReportResearchClaimSnapshot:
    """Snapshot the persisted claim/citation content for one selection."""
    result_id = selection.research_result_id
    claim_id = selection.research_claim_id
    result = _find_research_result(report_input.research_results, result_id)
    if result is None:
        raise ReportProvenanceError(
            f"research_context references an unsupplied research result: {result_id}"
        )
    claim = _find_research_claim(result, claim_id)
    if claim is None:
        raise ReportProvenanceError(
            f"research_context references an unknown research claim: {claim_id}"
        )
    citations_by_id = {citation.citation_id: citation for citation in result.citations}
    citations = tuple(
        citations_by_id[citation_id] for citation_id in claim.citation_ids
    )
    return ReportResearchClaimSnapshot(
        research_result_id=result_id,
        research_claim_id=claim_id,
        subject_entity_id=result.subject_entity_id,
        claim_text=claim.text,
        citation_ids=claim.citation_ids,
        citations=citations,
    )


def _find_research_result(
    results: tuple[ResearchResult, ...], result_id: UUID
) -> ResearchResult | None:
    """Return the supplied result with the exact identity, if any."""
    for result in results:
        if result.id == result_id:
            return result
    return None


def _find_research_claim(
    result: ResearchResult, claim_id: UUID
) -> ResearchClaim | None:
    """Return the exact persisted claim inside the result, if any."""
    for claim in result.claims:
        if claim.id == claim_id:
            return claim
    return None


def _deduplicate(values: list[UUID]) -> tuple[UUID, ...]:
    """Return the values in first-seen order without duplicates."""
    return tuple(dict.fromkeys(values))


class ReportProvenanceValidator:
    """Deterministic validation of report provenance closure rules.

    No provider, network, dispatcher, or LLM call is ever performed; the
    validator operates exclusively on its immutable input snapshot. It never
    claims to prove semantic entailment of narrative prose.
    """

    def validate(
        self, report: InvestigationReport, report_input: ReportWriterInput
    ) -> None:
        """Validate the assembled report or raise the first typed failure."""
        self._validate_assessment_authority(report, report_input)
        self._validate_finding_closure(report, report_input)
        self._validate_summary_closure(report, report_input)
        self._validate_research_closure(report, report_input)
        self._validate_source_set_closure(report)

    @staticmethod
    def _validate_assessment_authority(
        report: InvestigationReport, report_input: ReportWriterInput
    ) -> None:
        """Require the Assessment to remain the sole authority."""
        assessment = report_input.assessment
        if report.investigation_id != report_input.investigation_id:
            raise ReportProvenanceError(
                "report investigation does not match the input investigation"
            )
        if report.assessment_id != assessment.id:
            raise ReportProvenanceError(
                "report assessment does not match the current assessment"
            )
        if report.verdict is not assessment.verdict:
            raise ReportProvenanceError(
                "report verdict does not match the current assessment verdict"
            )
        if report.confidence is not assessment.confidence:
            raise ReportProvenanceError(
                "report confidence does not match the current assessment confidence"
            )
        expected_criticality = maximum_criticality(assessment.findings)
        if report.criticality is not expected_criticality:
            raise ReportProvenanceError(
                "report criticality is not the maximum assessment finding criticality"
            )
        if report.limitations != assessment.limitations:
            raise ReportProvenanceError(
                "report limitations do not match the current assessment"
            )
        if report.unresolved_questions != assessment.unresolved_questions:
            raise ReportProvenanceError(
                "report unresolved questions do not match the current assessment"
            )
        if report.recommended_next_steps != assessment.recommended_next_steps:
            raise ReportProvenanceError(
                "report recommended next steps do not match the current assessment"
            )
        if report.started_at != report_input.started_at:
            raise ReportProvenanceError(
                "report started_at does not match the persisted investigation"
            )
        if report.ended_at != report_input.completed_at:
            raise ReportProvenanceError(
                "report ended_at does not match the persisted investigation"
            )
        if report.outcome_status is not report_input.investigation_status:
            raise ReportProvenanceError(
                "report outcome status does not match the persisted investigation"
            )
        if report.stop_reason != report_input.stop_reason:
            raise ReportProvenanceError(
                "report stop reason does not match the persisted investigation"
            )

    @staticmethod
    def _validate_finding_closure(
        report: InvestigationReport, report_input: ReportWriterInput
    ) -> None:
        """Require every canonical finding to appear exactly once in order."""
        assessment_findings = report_input.assessment.findings
        ordered = criticality_first_ordering(assessment_findings)
        if len(report.findings) != len(ordered):
            raise ReportProvenanceError(
                "report findings must contain every assessment finding exactly once"
            )
        expected_numbers = list(range(1, len(ordered) + 1))
        actual_numbers = [
            snapshot.report_finding_number for snapshot in report.findings
        ]
        if actual_numbers != expected_numbers:
            raise ReportProvenanceError(
                "report finding numbers must be contiguous from one in canonical order"
            )
        for position, snapshot in enumerate(report.findings):
            ordinal, finding = ordered[position]
            if snapshot.assessment_finding_ordinal != ordinal:
                raise ReportProvenanceError(
                    "report finding order is not canonical criticality-first order"
                )
            if (
                snapshot.criticality is not finding.criticality
                or snapshot.category is not finding.category
                or snapshot.disposition is not finding.disposition
                or snapshot.statement != finding.statement
                or snapshot.confidence is not finding.confidence
                or snapshot.support != finding.support
            ):
                raise ReportProvenanceError(
                    "report finding snapshot differs from the authoritative "
                    f"assessment finding at ordinal {ordinal}"
                )

    @staticmethod
    def _validate_summary_closure(
        report: InvestigationReport, report_input: ReportWriterInput
    ) -> None:
        """Require the Summary to be the exact eligible canonical projection."""
        findings_by_ordinal = {
            finding.assessment_finding_ordinal: finding for finding in report.findings
        }
        expected = [
            finding
            for finding in report.findings
            if is_summary_eligible(finding.criticality)
        ]
        if len(report.summary) != len(expected):
            raise ReportProvenanceError(
                "report summary must contain exactly the summary-eligible findings"
            )
        assessment_id = report_input.assessment.id
        for item, finding in zip(report.summary, expected, strict=True):
            if item.report_finding_number != finding.report_finding_number:
                raise ReportProvenanceError(
                    "report summary item number does not match its finding"
                )
            if item.assessment_finding_ordinal != finding.assessment_finding_ordinal:
                raise ReportProvenanceError(
                    "report summary item references the wrong assessment finding"
                )
            if item.text != finding.summary:
                raise ReportProvenanceError(
                    "report summary item text differs from its finding presentation"
                )
            if len(item.support) != 1:
                raise ReportProvenanceError(
                    "report summary item must reference exactly one assessment finding"
                )
            ref = item.support[0]
            if (
                not isinstance(ref, AssessmentFindingRef)
                or ref.assessment_id != assessment_id
                or ref.finding_ordinal != finding.assessment_finding_ordinal
            ):
                raise ReportProvenanceError(
                    "report summary item support must reference its exact finding"
                )
        # Defensive: a Summary item can only ever reference a canonical finding.
        for item in report.summary:
            if item.assessment_finding_ordinal not in findings_by_ordinal:
                raise ReportProvenanceError(
                    "report summary item references a non-canonical finding"
                )

    @staticmethod
    def _validate_research_closure(
        report: InvestigationReport, report_input: ReportWriterInput
    ) -> None:
        """Require every research snapshot to match the persisted claim data."""
        for snapshot in report.research_context:
            result = _find_research_result(
                report_input.research_results, snapshot.research_result_id
            )
            if result is None:
                raise ReportProvenanceError(
                    "report research context references an unsupplied "
                    f"research result: {snapshot.research_result_id}"
                )
            claim = _find_research_claim(result, snapshot.research_claim_id)
            if claim is None:
                raise ReportProvenanceError(
                    "report research context references an unknown research "
                    f"claim: {snapshot.research_claim_id}"
                )
            expected_citations = _research_citations_for_claim(result, claim)
            if (
                snapshot.subject_entity_id != result.subject_entity_id
                or snapshot.claim_text != claim.text
                or snapshot.citation_ids != claim.citation_ids
                or snapshot.citations != expected_citations
            ):
                raise ReportProvenanceError(
                    "report research snapshot differs from the persisted "
                    f"research result claim {snapshot.research_claim_id}"
                )

    @staticmethod
    def _validate_source_set_closure(report: InvestigationReport) -> None:
        """Require the top-level source ID sets to equal the derived sets."""
        evidence_ids: list[UUID] = []
        observation_ids: list[UUID] = []
        for finding in report.findings:
            for support in finding.support:
                if isinstance(support, EvidenceSupport):
                    evidence_ids.append(support.evidence_id)
                else:
                    observation_ids.append(support.relationship_observation_id)
        research_result_ids = [
            snapshot.research_result_id for snapshot in report.research_context
        ]
        if report.source_evidence_ids != _deduplicate(evidence_ids):
            raise ReportProvenanceError(
                "report source_evidence_ids are not derived from the included findings"
            )
        if report.source_relationship_observation_ids != _deduplicate(observation_ids):
            raise ReportProvenanceError(
                "report source_relationship_observation_ids are not derived "
                "from the included findings"
            )
        if report.source_research_result_ids != _deduplicate(research_result_ids):
            raise ReportProvenanceError(
                "report source_research_result_ids are not derived from the "
                "included research context"
            )


def _research_citations_for_claim(
    result: ResearchResult, claim: ResearchClaim
) -> tuple[ResearchCitation, ...]:
    """Return the exact persisted citation snapshots cited by one claim."""
    citations_by_id = {citation.citation_id: citation for citation in result.citations}
    return tuple(citations_by_id[citation_id] for citation_id in claim.citation_ids)
