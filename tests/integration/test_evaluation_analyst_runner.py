# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C Evidence Analyst evaluation vertical slice (real PostgreSQL).

Executes the full PR 30C target pipeline against real PostgreSQL:

.. code-block:: text

    real analyst JSON scenarios
     -> real typed loader
     -> real AnalystScenarioMaterializer (fresh, then materialize_or_reuse)
     -> real EvidenceAnalystInputLoader
     -> real EvidenceAnalyst
     -> FakeLlmClient exactly at the model boundary
     -> real AssessmentPersistenceService
     -> persisted Assessment
     -> real EvidenceAnalystEvaluator through the PR 30 adapter
     -> common EvaluationRunner

Covers at least: the direct-evidence PASS case, the contradiction PASS case,
an intentionally nonconforming fake output that FAILs, and an LLM execution
failure that is ERROR (never FAIL). Asserts persistence, exact scenario
investigation identity, analyzed-evidence authority, support resolution, and
isolation across cases. No live LLM or LangSmith participates.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
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
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.evaluation.analyst import (
    AnalystScenario,
    AnalystScenarioMaterializer,
    load_scenarios_directory,
)
from agentic_threat_investigator.evaluation.analyst.materializer import (
    scenario_investigation_id,
)
from agentic_threat_investigator.evaluation.analyst.run import (
    run_evidence_analyst_evaluation,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationTarget,
    EvaluationVerdict,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.analyst_scenarios import canonical_decision, evidence_only_finding
from tests.support.llm_fixtures import FakeLlmClient

SCENARIOS_DIRECTORY = Path("evals/scenarios/analyst")

DATASET_ID = EvaluationDatasetId(target=EvaluationTarget.EVIDENCE_ANALYST, version=1)

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


async def materialized_resolutions(
    uow_factory: Callable[[], PostgresUnitOfWork],
    scenarios: tuple[AnalystScenario, ...],
) -> dict[str, Any]:
    """Materialize each scenario fresh and return id -> resolution."""
    resolutions: dict[str, Any] = {}
    async with uow_factory() as uow:
        for scenario in scenarios:
            resolutions[scenario.id] = await AnalystScenarioMaterializer().materialize(
                uow, scenario
            )
    return resolutions


async def assessment_rows(uow: PostgresUnitOfWork, investigation_id: UUID) -> int:
    """Count durable Assessment rows for one Investigation."""
    assert uow.session is not None
    result = await uow.session.execute(
        text("SELECT count(*) FROM ati.assessment WHERE investigation_id = :id"),
        {"id": investigation_id},
    )
    return int(result.scalar_one())


@pytest.fixture(scope="session")
def scenarios() -> tuple[AnalystScenario, ...]:
    """Load the committed analyst scenario corpus once."""
    return load_scenarios_directory(SCENARIOS_DIRECTORY)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_vertical_slice_passes_and_persists(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenarios: tuple[AnalystScenario, ...],
) -> None:
    """Every core scenario executes through the real runner and PASSes.

    Every case must persist exactly one Assessment for the current invocation
    under its own deterministic scenario Investigation, with the authoritative
    analyzed Evidence identities, and every support label resolving into the
    materialized fixture. The contradiction case (``conflicting_reputation``)
    is explicitly asserted alongside the direct-evidence case.
    """
    resolutions = await materialized_resolutions(uow_factory, scenarios)

    llm = FakeLlmClient()
    for scenario in scenarios:
        llm.enqueue(
            canonical_decision(
                scenario,
                resolutions[scenario.id],
                verdict=CANONICAL_VERDICTS[scenario.id],
            )
        )
    result = await run_evidence_analyst_evaluation(
        dataset_id=DATASET_ID,
        analyst=analyst_for(session_factory, llm),
        uow_factory=uow_factory,
        scenarios=scenarios,
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.PASS
    assert len(result.cases) == len(scenarios)

    for scenario in scenarios:
        resolution = resolutions[scenario.id]
        investigation_id = scenario_investigation_id(scenario)
        case = next(item for item in result.cases if item.case_id == scenario.id)
        assert case.verdict is EvaluationVerdict.PASS, case.evaluator_results
        # Exactly one Assessment persisted for the current invocation, under
        # the correct scenario Investigation, with the authoritative analyzed
        # EvidenceObservation identities of the current materialization.
        async with uow_factory() as uow:
            assert await assessment_rows(uow, investigation_id) == 1
            current = (
                await uow.assessments.list_for_investigation(investigation_id, limit=1)
            )[0]
        assert current.investigation_id == investigation_id
        assert set(current.analyzed_evidence_ids) == set(
            resolution.evidence_ids.values()
        )

    # A rerun of one scenario reuses the deterministic fixture
    # (materialize_or_reuse) and still evaluates the current invocation.
    direct = next(
        item for item in scenarios if item.id == "malicious_ioc_direct_evidence"
    )
    llm2 = FakeLlmClient()
    llm2.set_default(
        canonical_decision(direct, resolutions[direct.id], verdict=Verdict.MALICIOUS)
    )
    rerun = await run_evidence_analyst_evaluation(
        dataset_id=DATASET_ID,
        analyst=analyst_for(session_factory, llm2),
        uow_factory=uow_factory,
        scenarios=(direct,),
    )
    assert rerun.execution_status is EvaluationExecutionStatus.COMPLETED
    assert rerun.verdict is EvaluationVerdict.PASS
    async with uow_factory() as uow:
        assert await assessment_rows(uow, scenario_investigation_id(direct)) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_nonconforming_output_is_fail_not_persistence_failure(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenarios: tuple[AnalystScenario, ...],
) -> None:
    """A structurally valid but behaviorally wrong Assessment yields FAIL."""
    scenario = next(item for item in scenarios if item.id == "geolocation_context")
    async with uow_factory() as uow:
        resolution = await AnalystScenarioMaterializer().materialize(uow, scenario)

    # Contextual-only city/country support used as MALICIOUS evidence.
    bad_decision = EvidenceAnalystDecision(
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="The IP is malicious because of its country attribution.",
        findings=(
            evidence_only_finding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                evidence_ids=(resolution.evidence_ids["dbip_city_context"],),
                confidence=AssessmentConfidence.MEDIUM,
            ),
        ),
        disposition=AnalysisDisposition.EXHAUSTED,
    )
    llm = FakeLlmClient()
    llm.enqueue(bad_decision)
    result = await run_evidence_analyst_evaluation(
        dataset_id=DATASET_ID,
        analyst=analyst_for(session_factory, llm),
        uow_factory=uow_factory,
        scenarios=(scenario,),
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.FAIL
    case = result.cases[0]
    assert case.verdict is EvaluationVerdict.FAIL
    explanation = case.evaluator_results[0].explanation
    assert "verdict_not_allowed" in explanation
    assert "contextual_evidence_misused" in explanation

    # The nonconforming Assessment still persisted for the current invocation:
    # behavioral failure is not persistence failure.
    async with uow_factory() as uow:
        assert await assessment_rows(uow, scenario_investigation_id(scenario)) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_llm_failure_is_error_not_fail(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenarios: tuple[AnalystScenario, ...],
) -> None:
    """An LLM provider failure through the real analyst is ERROR, never FAIL."""
    scenario = next(item for item in scenarios if item.id == "no_reputation_hit")
    async with uow_factory() as uow:
        await AnalystScenarioMaterializer().materialize(uow, scenario)

    llm = FakeLlmClient()
    llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False))
    result = await run_evidence_analyst_evaluation(
        dataset_id=DATASET_ID,
        analyst=analyst_for(session_factory, llm),
        uow_factory=uow_factory,
        scenarios=(scenario,),
    )
    assert result.execution_status is EvaluationExecutionStatus.ERROR
    assert result.verdict is None
    case = result.cases[0]
    assert case.execution_status is EvaluationExecutionStatus.ERROR
    assert case.verdict is None
    # No partial Assessment persists for the failed invocation.
    async with uow_factory() as uow:
        assert await assessment_rows(uow, scenario_investigation_id(scenario)) == 0
    # Exactly one bounded model attempt was made.
    assert len(llm.calls) == 1
