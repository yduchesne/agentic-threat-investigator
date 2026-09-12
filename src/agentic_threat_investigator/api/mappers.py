# SPDX-License-Identifier: AGPL-3.0-only
"""Pure deterministic domain -> public DTO mappers.

Mappers perform no database access, no LLM calls, no policy decisions, and
no mutation. They are explicit field allowlists: internal domain fields are
never serialized wholesale.
"""

from __future__ import annotations

from agentic_threat_investigator.api.dto.assessment import (
    AssessmentResponse,
    FindingResponse,
    FindingSupportResponse,
)
from agentic_threat_investigator.api.dto.evidence import EvidenceResponse
from agentic_threat_investigator.api.dto.history import HistoryRecordResponse
from agentic_threat_investigator.api.dto.investigation import (
    CreateInvestigationResponse,
    InvestigationResponse,
)
from agentic_threat_investigator.api.dto.relationship import (
    RelationshipObservationResponse,
    RelationshipResponse,
)
from agentic_threat_investigator.api.dto.report import (
    AssessmentFindingRefResponse,
    NarrativeStatementResponse,
    ReportFindingResponse,
    ReportResearchClaimResponse,
    ReportResponse,
    ReportSourceRefResponse,
    ResearchClaimRefResponse,
)
from agentic_threat_investigator.api.dto.research import (
    ResearchCitationResponse,
    ResearchClaimResponse,
    ResearchResultResponse,
)
from agentic_threat_investigator.api.dto.timeline import TimelineEventResponse
from agentic_threat_investigator.app.query.history import DomainObjectHistoryRecord
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    EvidenceSupport,
    RelationshipSupport,
)
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
    ReportFindingSnapshot,
    ReportNarrativeStatement,
    ReportResearchClaimSnapshot,
    ReportSourceRef,
    ResearchClaimRef,
)
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)


def to_investigation_response(
    state: InvestigationState,
) -> InvestigationResponse:
    """Map one Investigation to its public operational-state DTO."""
    return InvestigationResponse(
        id=state.investigation_id,
        status=state.status,
        objective=state.objective,
        root_entity_ids=tuple(state.root_entity_ids),
        discovered_entity_ids=tuple(state.discovered_entity_ids),
        evidence_ids=tuple(state.evidence_ids),
        relationship_ids=tuple(state.relationship_ids),
        assessment_id=state.assessment_id,
        report_id=state.report_id,
        stop_reason=state.stop_reason,
        created_at=state.created_at or state.started_at,
        started_at=state.started_at,
        completed_at=state.completed_at,
        version=state.version or 0,
    )


def to_create_investigation_response(
    state: InvestigationState,
) -> CreateInvestigationResponse:
    """Map the authoritative Investigation to the 202 creation DTO."""
    return CreateInvestigationResponse(
        id=state.investigation_id,
        status=state.status,
        created_at=state.created_at or state.started_at,
    )


def to_evidence_response(evidence: Evidence) -> EvidenceResponse:
    """Map one Evidence observation; the raw provider payload is excluded.

    Read models always carry their persisted identity; a missing identity is
    an internal contract failure and never a synthesized fallback.
    """
    subject = evidence.subject
    if evidence.id is None or subject.id is None:
        raise ValueError("evidence response requires persisted identities")
    return EvidenceResponse(
        id=evidence.id,
        type=evidence.type,
        subject_entity_id=subject.id,
        subject_type=subject.type,
        subject_value=subject.value,
        source=evidence.source,
        source_record_id=evidence.source_record_id,
        source_url=evidence.source_url,
        observed_at=evidence.observed_at,
        retrieved_at=evidence.retrieved_at,
        facts=dict(evidence.facts),
    )


def to_relationship_response(
    relationship: Relationship,
) -> RelationshipResponse:
    """Map one stable relationship edge."""
    return RelationshipResponse(
        id=relationship.id,
        source_entity_id=relationship.source_entity_id,
        target_entity_id=relationship.target_entity_id,
        type=relationship.type,
    )


def to_relationship_observation_response(
    observation: RelationshipObservation,
) -> RelationshipObservationResponse:
    """Map one immutable observation, preserving observed/retrieved times."""
    return RelationshipObservationResponse(
        id=observation.id,
        relationship_id=observation.relationship_id,
        evidence_id=observation.evidence_id,
        investigation_id=observation.investigation_id,
        observed_at=observation.observed_at,
        retrieved_at=observation.retrieved_at,
        source=observation.source,
        confidence=observation.confidence,
    )


def to_research_citation_response(
    citation: ResearchCitation,
) -> ResearchCitationResponse:
    """Map one immutable citation snapshot."""
    return ResearchCitationResponse(
        citation_id=citation.citation_id,
        document_id=citation.document_id,
        source_id=citation.source_id,
        source_record_id=citation.source_record_id,
        document_type=citation.document_type,
        chunk_sequence=citation.chunk_sequence,
        text=citation.text,
        title=citation.title,
        source_url=citation.source_url,
        published_at=citation.published_at,
        similarity_score=citation.similarity_score,
    )


def to_research_claim_response(claim: ResearchClaim) -> ResearchClaimResponse:
    """Map one claim, preserving its citation closure."""
    return ResearchClaimResponse(
        id=claim.id,
        text=claim.text,
        citation_ids=claim.citation_ids,
    )


def to_research_result_response(result: ResearchResult) -> ResearchResultResponse:
    """Map one research result with its structured claims and citations."""
    return ResearchResultResponse(
        id=result.id,
        investigation_id=result.investigation_id,
        subject_entity_id=result.subject_entity_id,
        query=result.query,
        claims=tuple(to_research_claim_response(claim) for claim in result.claims),
        citations=tuple(
            to_research_citation_response(citation) for citation in result.citations
        ),
        created_at=result.created_at,
    )


def to_finding_support_response(
    support: EvidenceSupport | RelationshipSupport,
) -> FindingSupportResponse:
    """Map one typed provenance reference."""
    if isinstance(support, EvidenceSupport):
        return FindingSupportResponse(kind="evidence", evidence_id=support.evidence_id)
    return FindingSupportResponse(
        kind="relationship_observation",
        relationship_observation_id=support.relationship_observation_id,
    )


def to_finding_response(finding: AnalyticalFinding) -> FindingResponse:
    """Map one structured Finding."""
    return FindingResponse(
        category=finding.category,
        disposition=finding.disposition,
        statement=finding.statement,
        confidence=finding.confidence,
        support=tuple(to_finding_support_response(item) for item in finding.support),
    )


def to_assessment_response(assessment: Assessment) -> AssessmentResponse:
    """Map one Assessment version with its structured findings."""
    if (
        assessment.id is None
        or assessment.version is None
        or assessment.created_at is None
    ):
        raise ValueError("assessment response requires persisted metadata")
    return AssessmentResponse(
        id=assessment.id,
        investigation_id=assessment.investigation_id,
        verdict=assessment.verdict,
        confidence=assessment.confidence,
        summary=assessment.summary,
        analyzed_evidence_ids=assessment.analyzed_evidence_ids,
        findings=tuple(to_finding_response(finding) for finding in assessment.findings),
        limitations=assessment.limitations,
        unresolved_questions=assessment.unresolved_questions,
        recommended_next_steps=assessment.recommended_next_steps,
        version=assessment.version,
        created_at=assessment.created_at,
    )


def _report_source_ref(ref: ReportSourceRef) -> ReportSourceRefResponse:
    """Map one report narrative source reference."""
    if isinstance(ref, AssessmentFindingRef):
        return AssessmentFindingRefResponse(
            assessment_id=ref.assessment_id,
            finding_ordinal=ref.finding_ordinal,
        )
    if isinstance(ref, ResearchClaimRef):
        return ResearchClaimRefResponse(
            research_result_id=ref.research_result_id,
            research_claim_id=ref.research_claim_id,
        )
    raise TypeError("unknown report source reference type")


def _narrative_statement(
    statement: ReportNarrativeStatement,
) -> NarrativeStatementResponse:
    """Map one narrative statement with its typed support."""
    return NarrativeStatementResponse(
        text=statement.text,
        support=tuple(_report_source_ref(ref) for ref in statement.support),
    )


def _report_finding(finding: ReportFindingSnapshot) -> ReportFindingResponse:
    """Map one report finding snapshot."""
    return ReportFindingResponse(
        assessment_finding_ordinal=finding.assessment_finding_ordinal,
        category=finding.category,
        disposition=finding.disposition,
        statement=finding.statement,
        confidence=finding.confidence,
        support=tuple(to_finding_support_response(item) for item in finding.support),
    )


def _report_research_claim(
    snapshot: ReportResearchClaimSnapshot,
) -> ReportResearchClaimResponse:
    """Map one report research-claim snapshot."""
    return ReportResearchClaimResponse(
        research_result_id=snapshot.research_result_id,
        research_claim_id=snapshot.research_claim_id,
        subject_entity_id=snapshot.subject_entity_id,
        claim_text=snapshot.claim_text,
        citation_ids=snapshot.citation_ids,
        citations=tuple(
            to_research_citation_response(citation) for citation in snapshot.citations
        ),
    )


def to_report_response(report: InvestigationReport) -> ReportResponse:
    """Map one structured report; GET never regenerates a report."""
    if report.id is None or report.version is None or report.created_at is None:
        raise ValueError("report response requires persisted metadata")
    return ReportResponse(
        id=report.id,
        investigation_id=report.investigation_id,
        assessment_id=report.assessment_id,
        verdict=report.verdict,
        confidence=report.confidence,
        title=report.title,
        executive_summary=tuple(
            _narrative_statement(statement) for statement in report.executive_summary
        ),
        findings=tuple(_report_finding(finding) for finding in report.findings),
        research_context=tuple(
            _report_research_claim(snapshot) for snapshot in report.research_context
        ),
        limitations=report.limitations,
        unresolved_questions=report.unresolved_questions,
        recommended_next_steps=report.recommended_next_steps,
        source_evidence_ids=report.source_evidence_ids,
        source_relationship_observation_ids=report.source_relationship_observation_ids,
        source_research_result_ids=report.source_research_result_ids,
        version=report.version,
        created_at=report.created_at,
    )


def to_timeline_event_response(
    event: InvestigationTimelineEvent,
) -> TimelineEventResponse:
    """Map one observable timeline event."""
    return TimelineEventResponse(
        id=event.id,
        type=event.type,
        occurred_at=event.occurred_at,
        provider=event.provider.value if event.provider is not None else None,
        target_entity_id=event.target_entity_id,
        evidence_ids=event.evidence_ids,
        entity_ids=event.entity_ids,
        relationship_ids=event.relationship_ids,
        error_code=event.error_code,
        pivot_depth=event.pivot_depth,
        reason_code=event.reason_code,
        provider_calls_used=event.provider_calls_used,
        replans_used=event.replans_used,
        entity_count=event.entity_count,
    )


def to_history_response(
    record: DomainObjectHistoryRecord,
) -> HistoryRecordResponse:
    """Map one history row with allowlisted public state/diff.

    The caller supplies already-redacted ``state``/``diff`` projections;
    this mapper only copies the public metadata fields.
    """
    return HistoryRecordResponse(
        id=record.id,
        object_type=record.object_type,
        object_id=record.object_id,
        version=record.version,
        operation=record.operation.value,
        occurred_at=record.occurred_at,
        actor_id=record.actor_id,
        state=dict(record.state),
        diff=dict(record.diff),
    )
