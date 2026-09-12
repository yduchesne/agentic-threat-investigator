# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23C DTO validation and mapping unit tests (U01-U15)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.api.dto.auth import LoginRequest
from agentic_threat_investigator.api.dto.investigation import (
    CreateInvestigationRequest,
    IndicatorRequest,
)
from agentic_threat_investigator.api.mappers import (
    to_assessment_response,
    to_evidence_response,
    to_investigation_response,
    to_report_response,
    to_research_result_response,
    to_timeline_event_response,
)
from agentic_threat_investigator.app.investigation_submission import (
    DuplicateCanonicalIndicatorError,
    IndicatorInput,
    SubmissionBoundsError,
    canonical_indicator_identities,
)
from agentic_threat_investigator.app.query.evidence import EvidenceListQuery
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
    ReportNarrativeStatement,
)
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)


def _indicator(
    entity_type: EntityType = EntityType.DOMAIN, value: str = "example.com"
) -> IndicatorRequest:
    """Build one valid indicator request fixture."""
    return IndicatorRequest(type=entity_type, value=value)


# --- DTO validation (23C-U01..U08) -----------------------------------------


def test_u01_unknown_create_field_rejected() -> None:
    """Create-Investigation requests reject unknown fields."""
    with pytest.raises(ValidationError):
        CreateInvestigationRequest(
            indicators=(_indicator(),),
            objective="assess",
            unexpected="value",  # type: ignore[call-arg]
        )


def test_u02_zero_indicators_rejected() -> None:
    """Creation requires at least one indicator."""
    with pytest.raises(ValidationError):
        CreateInvestigationRequest(indicators=(), objective="assess")


def test_u03_too_many_indicators_rejected() -> None:
    """The submission service enforces the configured indicator ceiling."""
    inputs = [
        IndicatorInput(type=EntityType.DOMAIN, value=f"example-{index}.com")
        for index in range(3)
    ]
    with pytest.raises(SubmissionBoundsError):
        canonical_indicator_identities(inputs, max_indicators=2, max_value_length=2048)


def test_u04_blank_objective_rejected() -> None:
    """Creation rejects blank objectives."""
    with pytest.raises(ValidationError):
        CreateInvestigationRequest(indicators=(_indicator(),), objective="  ")


def test_u05_duplicate_canonical_indicator_rejected() -> None:
    """Duplicate canonical indicators fail deterministically."""
    inputs = [
        IndicatorInput(type=EntityType.DOMAIN, value="Example.COM"),
        IndicatorInput(type=EntityType.DOMAIN, value="example.com"),
    ]
    with pytest.raises(DuplicateCanonicalIndicatorError):
        canonical_indicator_identities(inputs, max_indicators=10, max_value_length=2048)


def test_u06_invalid_indicator_type_rejected() -> None:
    """An unknown indicator type is rejected by the strict enum."""
    with pytest.raises(ValidationError):
        IndicatorRequest(type="not-a-type", value="example.com")  # type: ignore[arg-type]


def test_u07_invalid_date_query_value_rejected_safely() -> None:
    """Naive timestamps and inverted ranges are rejected by the query DTO."""
    with pytest.raises(ValueError):
        EvidenceListQuery(
            investigation_id=uuid4(),
            retrieved_from=datetime(2026, 1, 2),  # naive
            limit=10,
        )
    with pytest.raises(ValueError):
        EvidenceListQuery(
            investigation_id=uuid4(),
            retrieved_from=datetime(2026, 1, 2, tzinfo=UTC),
            retrieved_to=datetime(2026, 1, 1, tzinfo=UTC),
            limit=10,
        )


def test_u08_extra_login_field_rejected() -> None:
    """Login requests reject unknown fields."""
    with pytest.raises(ValidationError):
        LoginRequest(
            username="alice",
            password="secret",  # type: ignore[arg-type]
            remember_me=True,  # type: ignore[call-arg]
        )


# --- Mapping (23C-U09..U15) -------------------------------------------------


def _investigation() -> InvestigationState:
    """Build one persisted Investigation state fixture."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return InvestigationState(
        investigation_id=UUID("11111111-1111-1111-1111-111111111111"),
        status=InvestigationStatus.COMPLETED,
        trigger_type=InvestigationTriggerType.API,
        root_entity_ids=[UUID("22222222-2222-2222-2222-222222222222")],
        objective="assess the indicator",
        assessment_id=UUID("33333333-3333-3333-3333-333333333333"),
        report_id=UUID("44444444-4444-4444-4444-444444444444"),
        budget=default_investigation_budget(),
        started_at=now,
        created_at=now,
        completed_at=now,
        version=3,
    )


def test_u09_investigation_mapping_omits_internal_fields() -> None:
    """Investigation mapping exposes public state only."""
    response = to_investigation_response(_investigation())
    assert response.id == UUID("11111111-1111-1111-1111-111111111111")
    assert response.status is InvestigationStatus.COMPLETED
    assert response.version == 3
    payload = response.model_dump()
    for internal in (
        "pending_pivots",
        "pending_provider_work",
        "completed_provider_work",
        "budget",
        "traversal",
        "research_executions",
    ):
        assert internal not in payload


def test_u10_evidence_mapping_omits_raw_payload() -> None:
    """Evidence mapping excludes the raw provider payload."""
    evidence = Evidence(
        id=uuid4(),
        investigation_id=uuid4(),
        type=EvidenceType.DNS,
        subject=EntityRef(id=uuid4(), type=EntityType.DOMAIN, value="example.com"),
        source="urn:ati:source:google_public_dns",
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        facts={"answers": ["93.184.216.34"]},
        raw_payload={"http_response": {"status": 200, "body": "secret"}},
    )
    import json

    response = to_evidence_response(evidence)
    payload = json.loads(response.model_dump_json())
    assert payload["facts"] == {"answers": ["93.184.216.34"]}
    assert "raw_payload" not in payload


def test_u11_research_mapping_preserves_claim_citation_closure() -> None:
    """Research mapping preserves claims and their citation associations."""
    citation = ResearchCitation(
        citation_id=uuid4(),
        document_id=uuid4(),
        source_id="urn:ati:source:mitre_attack",
        source_record_id="T1059",
        document_type="technique",
        chunk_sequence=1,
        text="Command and script interpreters",
    )
    claim = ResearchClaim(
        id=uuid4(), text="T1059 covers scripting", citation_ids=(citation.citation_id,)
    )
    result = ResearchResult(
        id=uuid4(),
        investigation_id=uuid4(),
        subject_entity_id=uuid4(),
        query="scripting",
        claims=(claim,),
        citations=(citation,),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    response = to_research_result_response(result)
    assert response.claims[0].citation_ids == (citation.citation_id,)
    assert response.citations[0].citation_id == citation.citation_id
    assert "similarity_score" in response.citations[0].model_dump()


def test_u12_assessment_mapping_preserves_structured_findings() -> None:
    """Assessment mapping preserves verdict, findings, and supports."""
    support = EvidenceSupport(kind="evidence", evidence_id=uuid4())
    finding = AnalyticalFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement="blocklisted by two sources",
        confidence=AssessmentConfidence.HIGH,
        support=(support,),
    )
    assessment = Assessment(
        id=uuid4(),
        investigation_id=uuid4(),
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        summary="malicious infrastructure",
        analyzed_evidence_ids=(support.evidence_id,),
        findings=(finding,),
        limitations=("none",),
        unresolved_questions=(),
        recommended_next_steps=("block",),
        version=2,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    response = to_assessment_response(assessment)
    assert response.verdict is Verdict.MALICIOUS
    assert response.findings[0].support[0].evidence_id == support.evidence_id
    assert response.limitations == ("none",)
    assert response.recommended_next_steps == ("block",)


def test_u13_report_mapping_preserves_structured_snapshots() -> None:
    """Report mapping preserves narrative statements and snapshots."""
    ref = AssessmentFindingRef(assessment_id=uuid4(), finding_ordinal=1)
    statement = ReportNarrativeStatement(text="malicious", support=(ref,))
    report = InvestigationReport(
        id=uuid4(),
        investigation_id=uuid4(),
        assessment_id=ref.assessment_id,
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        title="Investigation report",
        executive_summary=(statement,),
        version=1,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    from agentic_threat_investigator.api.dto.report import AssessmentFindingRefResponse

    response = to_report_response(report)
    assert response.executive_summary[0].text == "malicious"
    support = response.executive_summary[0].support[0]
    assert isinstance(support, AssessmentFindingRefResponse)
    assert support.assessment_id == ref.assessment_id


def test_u14_timeline_mapping_excludes_hidden_reasoning() -> None:
    """Timeline mapping carries observable fields only."""
    event = InvestigationTimelineEvent(
        id=uuid4(),
        investigation_id=uuid4(),
        type=InvestigationTimelineEventType.INVESTIGATION_STARTED,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    response = to_timeline_event_response(event)
    payload = response.model_dump()
    assert response.type is InvestigationTimelineEventType.INVESTIGATION_STARTED
    for internal in ("reasoning", "prompt", "chain_of_thought"):
        assert internal not in payload


def test_u15_history_mapping_carries_redacted_state_only() -> None:
    """History records never carry raw JSONB wholesale.

    The route-level allowlist is exercised separately; here the DTO shape is
    pinned to the public fields.
    """
    from agentic_threat_investigator.api.dto.history import HistoryRecordResponse

    record = HistoryRecordResponse(
        id=uuid4(),
        object_type="investigation",
        object_id=uuid4(),
        version=1,
        operation="CREATE",
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        actor_id=None,
        state={"status": "pending"},
        diff={},
    )
    payload = record.model_dump()
    assert "state" in payload
    assert "natural_key" not in payload
