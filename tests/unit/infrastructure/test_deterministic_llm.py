# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic offline LLM boundary tests (PR 24B).

Pins the scripted model boundary to the repository-owned deterministic
prompt renderings: the Evidence Analyst trajectory, an empty-context
research synthesis, Report Writer reflection of the supplied Assessment
finding ordinals, and fail-closed behavior for unknown operations or
unparseable inputs. Never touches the network.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TypeVar
from uuid import uuid4

import pytest
from pydantic import BaseModel

from agentic_threat_investigator.app.evidence_analyst.prompts import (
    OPERATION_EVIDENCE_ANALYSIS,
    build_evidence_analyst_prompts,
)
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.report_writer.prompts import (
    OPERATION_REPORT_WRITING,
    build_report_writer_prompts,
)
from agentic_threat_investigator.app.research_agent.prompts import (
    OPERATION_RESEARCH_SYNTHESIS,
)
from agentic_threat_investigator.domain.analyst import (
    AnalystEntity,
    AnalystEvidenceItem,
    AnalystRelationshipObservation,
    EvidenceAnalystDecision,
    EvidenceAnalystInput,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    RelationshipSupport,
    Verdict,
    support_key,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.domain.relationships import RelationshipType
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    ReportWriterInput,
    ReportWriterOutput,
)
from agentic_threat_investigator.domain.research_agent import ResearchAgentDecision
from agentic_threat_investigator.infrastructure.llm.deterministic import (
    DeterministicLlmClient,
)

ResponseT = TypeVar("ResponseT", bound=BaseModel)

_RETRIEVED_AT = datetime(2026, 6, 1, tzinfo=UTC)


def _evidence_input() -> EvidenceAnalystInput:
    """Build a deterministic analysis input with one Evidence + one observation."""
    source_id = uuid4()
    target_id = uuid4()
    evidence_id = uuid4()
    return EvidenceAnalystInput(
        investigation_id=uuid4(),
        objective="assess the update-package delivery domain",
        root_entities=(
            AnalystEntity(
                entity_id=source_id,
                entity_type=EntityType.DOMAIN,
                value="update-package.test",
            ),
        ),
        evidence=(
            AnalystEvidenceItem(
                evidence_observation_id=evidence_id,
                type=EvidenceType.DNS,
                entities=(
                    AnalystEntity(
                        entity_id=source_id,
                        entity_type=EntityType.DOMAIN,
                        value="update-package.test",
                    ),
                ),
                source="urn:ati:source:google_public_dns",
                retrieved_at=_RETRIEVED_AT,
                facts={"a_records": ["203.0.113.7"]},
            ),
        ),
        relationship_observations=(
            AnalystRelationshipObservation(
                relationship_observation_id=uuid4(),
                evidence_observation_id=evidence_id,
                relationship_id=uuid4(),
                relationship_type=RelationshipType.RESOLVES_TO,
                source_entity=AnalystEntity(
                    entity_id=source_id,
                    entity_type=EntityType.DOMAIN,
                    value="update-package.test",
                ),
                target_entity=AnalystEntity(
                    entity_id=target_id,
                    entity_type=EntityType.IP_ADDRESS,
                    value="203.0.113.7",
                ),
                retrieved_at=_RETRIEVED_AT,
                source="urn:ati:source:google_public_dns",
            ),
        ),
    )


def _report_input() -> ReportWriterInput:
    """Build a deterministic one-finding report input."""
    investigation_id = uuid4()
    evidence_id = uuid4()
    assessment_id = uuid4()
    assessment = Assessment(
        investigation_id=investigation_id,
        id=assessment_id,
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        summary="correlated multi-source evidence is sufficient",
        analyzed_evidence_ids=(evidence_id,),
        findings=(
            AnalyticalFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="threat-intelligence signal associates the root",
                confidence=AssessmentConfidence.HIGH,
                support=(EvidenceSupport(kind="evidence", evidence_id=evidence_id),),
            ),
        ),
    )
    return ReportWriterInput(
        investigation_id=investigation_id,
        objective="assess the update-package delivery domain",
        assessment=assessment,
    )


async def _capture(
    client: DeterministicLlmClient,
    system_prompt: str,
    user_prompt: str,
    response_model: type[ResponseT],
    operation_name: str,
) -> ResponseT:
    """Run one deterministic structured-output generation via the ABC seam."""
    return await client.generate_structured(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=response_model,
        operation_name=operation_name,
    )


@pytest.mark.asyncio
async def test_evidence_analysis_canonical_trajectory_and_reflection() -> None:
    """Rounds 1-3 request more evidence; later rounds conclude with Findings.

    The sufficient decision reflects only supplied Evidence and
    RelationshipObservation identities into its support references.
    """
    analysis_input = _evidence_input()
    system_prompt, user_prompt = build_evidence_analyst_prompts(analysis_input)
    client = DeterministicLlmClient()

    for _ in range(3):
        result = await _capture(
            client,
            system_prompt,
            user_prompt,
            EvidenceAnalystDecision,
            OPERATION_EVIDENCE_ANALYSIS,
        )
        assert isinstance(result, EvidenceAnalystDecision)
        assert result.disposition is AnalysisDisposition.NEEDS_MORE_EVIDENCE
        assert result.findings == ()

    final = await _capture(
        client,
        system_prompt,
        user_prompt,
        EvidenceAnalystDecision,
        OPERATION_EVIDENCE_ANALYSIS,
    )
    assert isinstance(final, EvidenceAnalystDecision)
    assert final.verdict is Verdict.MALICIOUS
    assert final.confidence is AssessmentConfidence.HIGH
    assert final.disposition is AnalysisDisposition.SUFFICIENT
    assert len(final.findings) == 2

    evidence_support = final.findings[0].support[0]
    observation_support = final.findings[1].support[0]
    assert isinstance(evidence_support, EvidenceSupport)
    assert isinstance(observation_support, RelationshipSupport)
    rendered_evidence = analysis_input.evidence[0].evidence_observation_id
    rendered_observation = analysis_input.relationship_observations[
        0
    ].relationship_observation_id
    assert evidence_support.evidence_id == rendered_evidence
    assert observation_support.relationship_observation_id == rendered_observation
    # Discriminators match the durable kind values.
    assert support_key(evidence_support) == ("evidence", rendered_evidence)
    assert support_key(observation_support) == (
        "relationship_observation",
        rendered_observation,
    )


@pytest.mark.asyncio
async def test_sufficient_round_without_observations_uses_evidence_only() -> None:
    """A decision without rendered observations still concludes via Evidence."""
    analysis_input = _evidence_input().model_copy(
        update={"relationship_observations": ()}
    )
    system_prompt, user_prompt = build_evidence_analyst_prompts(analysis_input)
    client = DeterministicLlmClient()
    for _ in range(3):
        await _capture(
            client,
            system_prompt,
            user_prompt,
            EvidenceAnalystDecision,
            OPERATION_EVIDENCE_ANALYSIS,
        )
    final = await _capture(
        client,
        system_prompt,
        user_prompt,
        EvidenceAnalystDecision,
        OPERATION_EVIDENCE_ANALYSIS,
    )
    assert isinstance(final, EvidenceAnalystDecision)
    assert len(final.findings) == 1
    assert isinstance(final.findings[0].support[0], EvidenceSupport)


@pytest.mark.asyncio
async def test_research_synthesis_is_empty_context() -> None:
    """Research synthesis deterministically expresses no relevant claims."""
    client = DeterministicLlmClient()
    result = await _capture(
        client, "system", "user", ResearchAgentDecision, OPERATION_RESEARCH_SYNTHESIS
    )
    assert isinstance(result, ResearchAgentDecision)
    assert result.claims == ()


@pytest.mark.asyncio
async def test_report_writer_reflects_supplied_assessment() -> None:
    """Report output supports exactly the rendered Assessment finding ordinal."""
    report_input = _report_input()
    system_prompt, user_prompt = build_report_writer_prompts(report_input)
    client = DeterministicLlmClient()
    output = await _capture(
        client, system_prompt, user_prompt, ReportWriterOutput, OPERATION_REPORT_WRITING
    )
    assert isinstance(output, ReportWriterOutput)
    assert output.title
    assert output.finding_order == (1,)
    assert len(output.executive_summary) == 1
    ref = output.executive_summary[0].support[0]
    assert isinstance(ref, AssessmentFindingRef)
    assert ref.assessment_id == report_input.assessment.id
    assert ref.finding_ordinal == 1


@pytest.mark.asyncio
async def test_report_writer_fails_closed_without_findings() -> None:
    """An Assessment without rendered finding ordinals fails closed."""
    client = DeterministicLlmClient()
    with pytest.raises(LlmError) as excinfo:
        await client.generate_structured(
            system_prompt="system",
            user_prompt=(
                "Current Assessment:\n  assessment_id: "
                "00000000-0000-4000-8000-000000000001"
            ),
            response_model=ReportWriterOutput,
            operation_name=OPERATION_REPORT_WRITING,
        )
    assert excinfo.value.code is LlmErrorCode.INVALID_STRUCTURED_OUTPUT


@pytest.mark.asyncio
async def test_unknown_operation_fails_closed() -> None:
    """An unknown operation identifier maps to a bounded LLM error."""
    client = DeterministicLlmClient()
    with pytest.raises(LlmError) as excinfo:
        await client.generate_structured(
            system_prompt="system",
            user_prompt="user",
            response_model=EvidenceAnalystDecision,
            operation_name="urn:ati:llm:unknown",
        )
    assert excinfo.value.code is LlmErrorCode.INVALID_STRUCTURED_OUTPUT
    assert "urn:ati:llm:unknown" not in str(excinfo.value)


@pytest.mark.asyncio
async def test_model_mismatch_fails_closed() -> None:
    """Requesting the wrong response model for an operation fails closed."""
    client = DeterministicLlmClient()
    with pytest.raises(LlmError) as excinfo:
        await client.generate_structured(
            system_prompt="system",
            user_prompt="user",
            response_model=ResearchAgentDecision,
            operation_name=OPERATION_EVIDENCE_ANALYSIS,
        )
    assert excinfo.value.code is LlmErrorCode.INVALID_STRUCTURED_OUTPUT
