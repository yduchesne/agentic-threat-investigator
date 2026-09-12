# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Report provenance validation and authoritative assembly (PR 23B).

:func:`build_investigation_report` stamps every application-owned field onto
the authoritative :class:`InvestigationReport` from a
:class:`ReportWriterInput` and a :class:`ReportWriterOutput`: verdict and
confidence are copied exactly from the current Assessment, Assessment
findings are snapshotted application-side, Research claims/citations are
snapshotted from persisted ResearchResults, caveat lists are copied exactly,
and the top-level source identity sets are derived from the actual included
provenance.

:class:`ReportProvenanceValidator` then proves deterministic closure before
persistence:

- Assessment authority (investigation binding, assessment identity,
  verdict/confidence equality);
- finding closure (ordinals resolve, snapshots match the authoritative
  Assessment finding exactly, no new findings);
- narrative support closure (every reference resolves to a supplied
  Assessment finding or supplied persisted ResearchClaim of the current
  Investigation);
- research closure (snapshots match the persisted claim/citation snapshots);
- Assessment caveats preserved exactly;
- source-set closure (top-level ID sets equal the derived sets).

This validator proves reference integrity, never semantic entailment:
whether a narrative statement faithfully paraphrases its cited material is a
behavioral-evaluation question, not a deterministic property.
"""

from __future__ import annotations

from uuid import UUID

from agentic_threat_investigator.app.report_writer.errors import (
    ReportProvenanceError,
)
from agentic_threat_investigator.domain.assessment import (
    EvidenceSupport,
)
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
    ReportFindingSnapshot,
    ReportNarrativeStatement,
    ReportResearchClaimSnapshot,
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


def build_investigation_report(
    report_input: ReportWriterInput,
    output: ReportWriterOutput,
) -> InvestigationReport:
    """Assemble the authoritative report by application stamping only.

    The model contributes the title, narrative statements, finding
    ordering/subset, and research claim selections; every other field is
    copied or derived from the authoritative input snapshot. No model value
    can replace the Assessment verdict/confidence or caveats.
    """
    assessment_id = report_input.assessment.id
    if assessment_id is None:  # pragma: no cover - loaded inputs carry it
        raise ReportProvenanceError("report input assessment has no persisted identity")

    findings = tuple(
        _snapshot_finding(report_input, ordinal) for ordinal in output.finding_order
    )
    research_context = tuple(
        _snapshot_research_claim(report_input, selection)
        for selection in output.research_context
    )

    source_evidence_ids: list[UUID] = []
    source_observation_ids: list[UUID] = []
    for finding in findings:
        for support in finding.support:
            if isinstance(support, EvidenceSupport):
                source_evidence_ids.append(support.evidence_id)
            else:
                source_observation_ids.append(support.relationship_observation_id)

    return InvestigationReport(
        investigation_id=report_input.investigation_id,
        assessment_id=assessment_id,
        verdict=report_input.assessment.verdict,
        confidence=report_input.assessment.confidence,
        title=output.title,
        executive_summary=output.executive_summary,
        findings=findings,
        research_context=research_context,
        limitations=report_input.assessment.limitations,
        unresolved_questions=report_input.assessment.unresolved_questions,
        recommended_next_steps=report_input.assessment.recommended_next_steps,
        source_evidence_ids=_deduplicate(source_evidence_ids),
        source_relationship_observation_ids=_deduplicate(source_observation_ids),
        source_research_result_ids=_deduplicate(
            [snapshot.research_result_id for snapshot in research_context]
        ),
    )


def _snapshot_finding(
    report_input: ReportWriterInput, ordinal: int
) -> ReportFindingSnapshot:
    """Snapshot the authoritative Assessment finding at one ordinal."""
    finding = report_input.finding_by_ordinal(ordinal)
    if finding is None:
        raise ReportProvenanceError(
            f"finding_order references an unknown assessment finding ordinal: {ordinal}"
        )
    return ReportFindingSnapshot(
        assessment_finding_ordinal=ordinal,
        category=finding.category,
        disposition=finding.disposition,
        statement=finding.statement,
        confidence=finding.confidence,
        support=finding.support,
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
        for statement in report.executive_summary:
            self._validate_narrative_statement(statement, report_input)
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

    @staticmethod
    def _validate_finding_closure(
        report: InvestigationReport, report_input: ReportWriterInput
    ) -> None:
        """Require every report finding to snapshot the authoritative finding."""
        for snapshot in report.findings:
            finding = report_input.finding_by_ordinal(
                snapshot.assessment_finding_ordinal
            )
            if finding is None:
                raise ReportProvenanceError(
                    "report finding references an unknown assessment finding "
                    f"ordinal: {snapshot.assessment_finding_ordinal}"
                )
            if (
                snapshot.category is not finding.category
                or snapshot.disposition is not finding.disposition
                or snapshot.statement != finding.statement
                or snapshot.confidence is not finding.confidence
                or snapshot.support != finding.support
            ):
                raise ReportProvenanceError(
                    "report finding snapshot differs from the authoritative "
                    f"assessment finding at ordinal "
                    f"{snapshot.assessment_finding_ordinal}"
                )

    @staticmethod
    def _validate_narrative_statement(
        statement: ReportNarrativeStatement, report_input: ReportWriterInput
    ) -> None:
        """Require every narrative support reference to resolve to supplied material."""
        for ref in statement.support:
            if isinstance(ref, AssessmentFindingRef):
                if ref.assessment_id != report_input.assessment.id:
                    raise ReportProvenanceError(
                        "narrative statement references an assessment other "
                        "than the current assessment"
                    )
                if report_input.finding_by_ordinal(ref.finding_ordinal) is None:
                    raise ReportProvenanceError(
                        "narrative statement references an unknown assessment "
                        f"finding ordinal: {ref.finding_ordinal}"
                    )
            else:
                _validate_research_ref(report_input, ref)

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


def _validate_research_ref(
    report_input: ReportWriterInput, ref: ResearchClaimRef
) -> None:
    """Require a research claim reference to resolve to a supplied claim."""
    result = _find_research_result(
        report_input.research_results, ref.research_result_id
    )
    if result is None:
        raise ReportProvenanceError(
            "narrative statement references an unsupplied research result: "
            f"{ref.research_result_id}"
        )
    if _find_research_claim(result, ref.research_claim_id) is None:
        raise ReportProvenanceError(
            "narrative statement references an unknown research claim: "
            f"{ref.research_claim_id}"
        )


def _research_citations_for_claim(
    result: ResearchResult, claim: ResearchClaim
) -> tuple[ResearchCitation, ...]:
    """Return the exact persisted citation snapshots cited by one claim."""
    citations_by_id = {citation.citation_id: citation for citation in result.citations}
    return tuple(citations_by_id[citation_id] for citation_id in claim.citation_ids)
