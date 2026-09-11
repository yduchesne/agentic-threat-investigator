# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL + FakeLlmClient vertical slices for PR 20C.

Each test materializes one repository-owned analyst scenario through the
``UnitOfWork`` seam, runs the unchanged PR 20B Evidence Analyst execution
path with a scripted FakeLlmClient, reads the persisted Assessment back, and
feeds it to the deterministic EvidenceAnalystEvaluator.

Two distinct outcomes are proven:

- the canonical decision for every core scenario persists through the PR 20A
  seam and **passes** behavioral evaluation;
- a structurally valid but behaviorally wrong Assessment **still persists**
  (proving behavioral failure is not persistence failure) and **fails**
  evaluation with the stable bounded codes.

No external model, API key, or network participates.

Invalid support references (unknown Evidence, cross-investigation references,
substitute observations, soft-deleted graph resources) are PR 20A concerns;
the existing ``test_evidence_analyst_pipeline.py`` vertical slice proves such
candidates never persist, so no invalid support can ever become a PR 20C
evaluation input.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst import (
    EvidenceAnalyst,
    EvidenceAnalystInputLoader,
    LlmAccountingService,
)
from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.evaluation.analyst import (
    AnalystEvaluationFailureCode,
    AnalystScenario,
    AnalystScenarioMaterializer,
    EvidenceAnalystEvaluator,
    load_scenarios_directory,
)
from agentic_threat_investigator.evaluation.analyst.materializer import (
    scenario_investigation_id,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.analyst_scenarios import canonical_decision, evidence_only_finding
from tests.support.llm_fixtures import FakeLlmClient

SCENARIOS_DIRECTORY = Path("evals/scenarios/analyst")

# The canonical verdict chosen per scenario for the passing vertical slice.
# The evaluator only checks the envelope; the choice is scenario-author
# intent so the positive path stays semantically coherent.
CANONICAL_VERDICTS: dict[str, Verdict] = {
    "malicious_ioc_direct_evidence": Verdict.MALICIOUS,
    "graph_backed_malware_association": Verdict.MALICIOUS,
    "no_reputation_hit": Verdict.INCONCLUSIVE,
    "cloud_asn_context": Verdict.INCONCLUSIVE,
    "shared_asn": Verdict.INCONCLUSIVE,
    "geolocation_context": Verdict.INCONCLUSIVE,
    "conflicting_reputation": Verdict.SUSPICIOUS,
    "stale_evidence": Verdict.SUSPICIOUS,
}


def analyst_for(
    session_factory: async_sessionmaker[AsyncSession],
    llm: FakeLlmClient,
) -> EvidenceAnalyst:
    """Compose the full PR 20B analyst stack over the real PostgreSQL boundary."""

    def uow_factory() -> PostgresUnitOfWork:
        return PostgresUnitOfWork(session_factory)

    return EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(uow_factory),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            uow_factory, batch_size=100
        ),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=2,
    )


async def assessment_rows(uow: PostgresUnitOfWork, investigation_id: UUID) -> int:
    """Count durable Assessment rows for one Investigation."""
    assert uow.session is not None
    result = await uow.session.execute(
        text("SELECT count(*) FROM ati.assessment WHERE investigation_id = :id"),
        {"id": investigation_id},
    )
    return int(result.scalar_one())


# The scenario corpus is loaded once per session; every test materializes a
# fresh fixture copy into the isolated database (truncated between tests).
@pytest.fixture(scope="session")
def scenarios() -> tuple[AnalystScenario, ...]:
    """Load the committed analyst scenario corpus once."""
    return load_scenarios_directory(SCENARIOS_DIRECTORY)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_every_core_scenario_passes_end_to_end(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenarios: tuple[AnalystScenario, ...],
) -> None:
    """Each core scenario: fixture -> analyst -> persisted Assessment -> PASS.

    The canonical FakeLlmClient decision exercises the unchanged PR 20B
    execution path; the persisted Assessment is re-fetched through the
    repository before evaluation, proving evaluation consumes durable output.
    """
    for scenario in scenarios:
        async with uow_factory() as uow:
            resolution = await AnalystScenarioMaterializer().materialize(uow, scenario)
        decision = canonical_decision(
            scenario,
            resolution,
            verdict=CANONICAL_VERDICTS[scenario.id],
        )
        llm = FakeLlmClient()
        llm.set_default(decision)
        persisted = await analyst_for(session_factory, llm).analyze(
            scenario_investigation_id(scenario)
        )

        assert persisted.id is not None
        async with uow_factory() as uow:
            read_back = await uow.assessments.get_by_id(persisted.id)
        assert read_back is not None

        result = EvidenceAnalystEvaluator().evaluate(
            scenario=scenario, resolution=resolution, assessment=read_back
        )
        assert result.passed, f"scenario {scenario.id} failed: " + "; ".join(
            failure.message for failure in result.failures
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_behaviorally_bad_assessment_still_persists_and_fails(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenarios: tuple[AnalystScenario, ...],
) -> None:
    """A MALICIOUS verdict on geolocation-only evidence persists but fails.

    This is the canonical PR 20C regression: the support is structurally
    valid (PR 20A accepts it), yet the scenario designates city/country as
    contextual-only, so behavioral evaluation must reject it.
    """
    scenario = next(item for item in scenarios if item.id == "geolocation_context")
    async with uow_factory() as uow:
        resolution = await AnalystScenarioMaterializer().materialize(uow, scenario)

    dbip_id = resolution.evidence_ids["dbip_city_context"]
    bad_decision = EvidenceAnalystDecision(
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="The IP is malicious because of its country attribution.",
        findings=(
            evidence_only_finding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                evidence_ids=(dbip_id,),
                confidence=AssessmentConfidence.MEDIUM,
            ),
        ),
        disposition=AnalysisDisposition.EXHAUSTED,
    )
    llm = FakeLlmClient()
    llm.set_default(bad_decision)
    persisted = await analyst_for(session_factory, llm).analyze(
        scenario_investigation_id(scenario)
    )

    # The Assessment persists: behavioral failure must not imply persistence
    # failure.
    assert persisted.id is not None
    async with uow_factory() as uow:
        assert await assessment_rows(uow, persisted.investigation_id) == 1
        read_back = await uow.assessments.get_by_id(persisted.id)
    assert read_back is not None

    result = EvidenceAnalystEvaluator().evaluate(
        scenario=scenario, resolution=resolution, assessment=read_back
    )
    failure_codes = {failure.code for failure in result.failures}
    assert not result.passed
    assert AnalystEvaluationFailureCode.VERDICT_NOT_ALLOWED in failure_codes
    assert AnalystEvaluationFailureCode.FORBIDDEN_FINDING_PRESENT in failure_codes
    assert AnalystEvaluationFailureCode.CONTEXTUAL_EVIDENCE_MISUSED in failure_codes
    assert AnalystEvaluationFailureCode.UNSUPPORTED_MATERIAL_FINDING in failure_codes
    assert result.metrics.forbidden_support_violations == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_missing_limitation_is_behavioral_failure_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenarios: tuple[AnalystScenario, ...],
) -> None:
    """Omitting the required staleness limitation persists yet fails evaluation."""
    scenario = next(item for item in scenarios if item.id == "stale_evidence")
    async with uow_factory() as uow:
        resolution = await AnalystScenarioMaterializer().materialize(uow, scenario)
    decision = canonical_decision(
        scenario,
        resolution,
        verdict=Verdict.SUSPICIOUS,
    ).model_copy(update={"limitations": ()})

    llm = FakeLlmClient()
    llm.set_default(decision)
    persisted = await analyst_for(session_factory, llm).analyze(
        scenario_investigation_id(scenario)
    )

    assert persisted.id is not None
    async with uow_factory() as uow:
        assert await assessment_rows(uow, persisted.investigation_id) == 1
        read_back = await uow.assessments.get_by_id(persisted.id)
    assert read_back is not None

    result = EvidenceAnalystEvaluator().evaluate(
        scenario=scenario, resolution=resolution, assessment=read_back
    )
    assert not result.passed
    assert AnalystEvaluationFailureCode.REQUIRED_LIMITATION_MISSING in {
        failure.code for failure in result.failures
    }
    assert result.metrics.required_limitations_total == 1
    assert result.metrics.required_limitations_satisfied == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_missing_contradiction_is_behavioral_failure_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenarios: tuple[AnalystScenario, ...],
) -> None:
    """Representing only one provider side persists but fails contradiction."""
    scenario = next(item for item in scenarios if item.id == "conflicting_reputation")
    async with uow_factory() as uow:
        resolution = await AnalystScenarioMaterializer().materialize(uow, scenario)
    decision = canonical_decision(scenario, resolution, verdict=Verdict.SUSPICIOUS)
    # Drop the CONTRADICTING side finding to simulate the regression.
    one_sided = decision.model_copy(
        update={
            "findings": tuple(
                finding
                for finding in decision.findings
                if finding.disposition is not FindingDisposition.CONTRADICTING
            )
        }
    )

    llm = FakeLlmClient()
    llm.set_default(one_sided)
    persisted = await analyst_for(session_factory, llm).analyze(
        scenario_investigation_id(scenario)
    )

    assert persisted.id is not None
    async with uow_factory() as uow:
        assert await assessment_rows(uow, persisted.investigation_id) == 1
        read_back = await uow.assessments.get_by_id(persisted.id)
    assert read_back is not None

    result = EvidenceAnalystEvaluator().evaluate(
        scenario=scenario, resolution=resolution, assessment=read_back
    )
    assert not result.passed
    assert AnalystEvaluationFailureCode.REQUIRED_CONTRADICTION_MISSING in {
        failure.code for failure in result.failures
    }
    assert result.metrics.required_contradictions_total == 1
    assert result.metrics.required_contradictions_satisfied == 0
