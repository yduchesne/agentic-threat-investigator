# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared output fixtures for the PR 30F Investigation evaluator unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid5

from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    Evidence,
    EvidenceObservation,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationBudget,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    StopReason,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
    ReportFindingSnapshot,
    ReportNarrativeStatement,
    ReportResearchClaimSnapshot,
)
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)
from agentic_threat_investigator.evaluation.coordinator import CoordinatorActionRecord
from agentic_threat_investigator.evaluation.investigation.models import (
    InvestigationEvaluationOutput,
    InvestigationExecutionMetrics,
    InvestigationScenarioResolution,
)

ROOT_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "root")
RESOLVED_IP_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "ip")
MALWARE_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "malware")
INVESTIGATION_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "investigation")
OBSERVATION_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "observation")
RELATIONSHIP_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "relationship")
RELATIONSHIP_OBS_ID = uuid5(
    UUID("00000000-0000-0000-0000-0000000000ca"), "relationship-observation"
)
RESEARCH_RESULT_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "result")
RESEARCH_CLAIM_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "claim")
ASSESSMENT_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "assessment")
REPORT_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "report")
CITATION_ID = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "citation")

_FIXED = datetime(2026, 1, 1, tzinfo=UTC)

EVIDENCE_OBSERVATION = EvidenceObservation(
    id=OBSERVATION_ID,
    evidence_id=OBSERVATION_ID,
    version=1,
    retrieved_at=_FIXED,
    facts={"score": 90},
)

STABLE_EVIDENCE = Evidence(
    id=OBSERVATION_ID,
    type=EvidenceType.DNS,
    source="urn:ati:source:google_public_dns",
    source_record_id="r1",
)

RESOLVES_RELATIONSHIP = Relationship(
    id=RELATIONSHIP_ID,
    source_entity_id=ROOT_ID,
    target_entity_id=RESOLVED_IP_ID,
    type=RelationshipType.RESOLVES_TO,
)

RELATIONSHIP_OBSERVATION = RelationshipObservation(
    id=RELATIONSHIP_OBS_ID,
    relationship_id=RELATIONSHIP_ID,
    evidence_observation_id=OBSERVATION_ID,
    retrieved_at=_FIXED,
    source="urn:ati:source:google_public_dns",
)

RESEARCH_RESULT = ResearchResult(
    id=RESEARCH_RESULT_ID,
    investigation_id=INVESTIGATION_ID,
    subject_entity_id=MALWARE_ID,
    query="malware family context",
    claims=(
        ResearchClaim(
            id=RESEARCH_CLAIM_ID,
            text="The family operates credential-theft infrastructure.",
            citation_ids=(CITATION_ID,),
        ),
    ),
    citations=(
        ResearchCitation(
            citation_id=CITATION_ID,
            document_id=uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "document"),
            source_id="urn:ati:source:mitre_attack",
            source_record_id="report--1",
            document_type="report",
            chunk_sequence=1,
            text="Credential-theft infrastructure context.",
            title="Context report",
            source_url=None,
            published_at=None,
            similarity_score=0.4,
            metadata={},
            chunk_id=uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), "chunk"),
        ),
    ),
    created_at=_FIXED,
)


def terminal_state(
    *,
    status: InvestigationStatus = InvestigationStatus.COMPLETED,
    stop_reason: StopReason | None = StopReason.SUFFICIENT_EVIDENCE,
    assessment_id: UUID | None = ASSESSMENT_ID,
    report_id: UUID | None = REPORT_ID,
    entity_ids: tuple[UUID, ...] = (ROOT_ID, RESOLVED_IP_ID, MALWARE_ID),
) -> InvestigationState:
    """Build one durable terminal InvestigationState fixture."""
    return InvestigationState(
        investigation_id=INVESTIGATION_ID,
        status=status,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[ROOT_ID],
        discovered_entity_ids=[entity for entity in entity_ids if entity != ROOT_ID],
        evidence_ids=[OBSERVATION_ID],
        relationship_ids=[RELATIONSHIP_ID],
        objective="Assess the deterministic scenario world.",
        budget=InvestigationBudget(
            max_depth=2,
            max_entities=15,
            max_provider_calls=12,
            max_replans=2,
            max_llm_calls=12,
            provider_calls_used=4,
            replans_used=0,
        ),
        assessment_id=assessment_id,
        report_id=report_id,
        stop_reason=stop_reason.value if stop_reason is not None else None,
        started_at=_FIXED,
        version=7,
    )


def assessment(
    *,
    verdict: Verdict = Verdict.MALICIOUS,
    confidence: AssessmentConfidence = AssessmentConfidence.HIGH,
    findings: tuple[AnalyticalFinding, ...] | None = None,
    analyzed: tuple[UUID, ...] = (OBSERVATION_ID,),
    limitations: tuple[str, ...] = (),
) -> Assessment:
    """Build one final Assessment fixture."""
    return Assessment(
        id=ASSESSMENT_ID,
        investigation_id=INVESTIGATION_ID,
        verdict=verdict,
        confidence=confidence,
        summary="Deterministic assessment summary.",
        analyzed_evidence_ids=analyzed,
        findings=findings
        if findings is not None
        else (
            AnalyticalFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="Reputation signal supports the verdict.",
                confidence=confidence,
                support=(EvidenceSupport(kind="evidence", evidence_id=OBSERVATION_ID),),
            ),
        ),
        limitations=limitations,
        version=5,
        created_at=_FIXED,
    )


def report(
    *,
    verdict: Verdict = Verdict.MALICIOUS,
    confidence: AssessmentConfidence = AssessmentConfidence.HIGH,
    finding_ordinals: tuple[int, ...] = (1,),
    research_context: tuple[ReportResearchClaimSnapshot, ...] = (),
    narrative: tuple[ReportNarrativeStatement, ...] = (),
    limitations: tuple[str, ...] = (),
) -> InvestigationReport:
    """Build one persisted InvestigationReport fixture."""
    return InvestigationReport(
        id=REPORT_ID,
        investigation_id=INVESTIGATION_ID,
        assessment_id=ASSESSMENT_ID,
        verdict=verdict,
        confidence=confidence,
        title="Deterministic report",
        executive_summary=narrative
        or (
            ReportNarrativeStatement(
                text="The investigation reached a malicious verdict.",
                support=(
                    AssessmentFindingRef(
                        kind="assessment_finding",
                        assessment_id=ASSESSMENT_ID,
                        finding_ordinal=1,
                    ),
                ),
            ),
        ),
        findings=tuple(
            ReportFindingSnapshot(
                assessment_finding_ordinal=ordinal,
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="Reputation signal supports the verdict.",
                confidence=confidence,
                support=(EvidenceSupport(kind="evidence", evidence_id=OBSERVATION_ID),),
            )
            for ordinal in finding_ordinals
        ),
        research_context=research_context,
        limitations=limitations,
        source_evidence_ids=(OBSERVATION_ID,),
        source_relationship_observation_ids=(RELATIONSHIP_OBS_ID,),
        source_research_result_ids=tuple(
            snapshot.research_result_id for snapshot in research_context
        ),
        version=1,
        created_at=_FIXED,
    )


def research_claim_snapshot() -> ReportResearchClaimSnapshot:
    """Build one report research-context snapshot referencing the fixture claim."""
    return ReportResearchClaimSnapshot(
        research_result_id=RESEARCH_RESULT_ID,
        research_claim_id=RESEARCH_CLAIM_ID,
        subject_entity_id=MALWARE_ID,
        claim_text="The family operates credential-theft infrastructure.",
        citation_ids=(CITATION_ID,),
        citations=RESEARCH_RESULT.citations,
    )


def resolution() -> InvestigationScenarioResolution:
    """Build the label -> identity resolution fixture."""
    return InvestigationScenarioResolution(
        investigation_id=INVESTIGATION_ID,
        entity_ids={
            "root_domain": ROOT_ID,
            "resolved_ip": RESOLVED_IP_ID,
            "malware_family": MALWARE_ID,
        },
    )


def actions(*, include_research: bool = True) -> tuple[CoordinatorActionRecord, ...]:
    """Build a structured trajectory action fixture."""
    records = [
        CoordinatorActionRecord(
            action="urn:ati:action:provider_query",
            entity_id=ROOT_ID,
            provider="urn:ati:source:google_public_dns",
            depth=0,
            provider_calls_used=1,
        ),
        CoordinatorActionRecord(
            action="urn:ati:action:pivot_executed",
            entity_id=RESOLVED_IP_ID,
            depth=1,
            provider_calls_used=3,
        ),
        CoordinatorActionRecord(
            action="urn:ati:action:assessment_requested",
            provider_calls_used=3,
        ),
        CoordinatorActionRecord(
            action="urn:ati:action:investigation_stopped",
            reason="sufficient_evidence",
            provider_calls_used=4,
        ),
    ]
    if include_research:
        records.insert(
            2,
            CoordinatorActionRecord(
                action="urn:ati:action:research_requested",
                entity_id=MALWARE_ID,
                provider_calls_used=3,
            ),
        )
    return tuple(records)


def output(
    *,
    include_research: bool = True,
    report_value: InvestigationReport | None = None,
    include_report: bool = True,
    metrics: InvestigationExecutionMetrics | None = None,
    **update: object,
) -> InvestigationEvaluationOutput:
    """Build one InvestigationEvaluationOutput fixture."""
    base = InvestigationEvaluationOutput(
        final_investigation=terminal_state(),
        final_assessment=assessment(),
        report=report() if report_value is None and include_report else report_value,
        evidence_observations=(EVIDENCE_OBSERVATION,),
        stable_evidence=(STABLE_EVIDENCE,),
        entities=(
            Entity(id=ROOT_ID, type=EntityType.DOMAIN, value="update-package.test"),
            Entity(id=RESOLVED_IP_ID, type=EntityType.IP_ADDRESS, value="203.0.113.81"),
            Entity(
                id=MALWARE_ID, type=EntityType.MALWARE, value="malware.badloader_v2"
            ),
        ),
        relationships=(RESOLVES_RELATIONSHIP,),
        relationship_observations=(RELATIONSHIP_OBSERVATION,),
        research_results=(RESEARCH_RESULT,) if include_research else (),
        actions=actions(include_research=include_research),
        execution_metrics=metrics
        or InvestigationExecutionMetrics(
            provider_calls=4,
            llm_calls=6,
            analysis_calls=2,
            research_calls=1 if include_research else 0,
            report_calls=1,
            replans=0,
            pivot_count=1,
            duplicate_provider_calls=0,
            duplicate_entity_investigations=0,
            total_actions=5 if include_research else 4,
            maximum_depth_observed=1,
        ),
        resolution=resolution(),
    )
    return base.model_copy(update=update)
