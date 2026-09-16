# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26G canonical real-stack closure: PostgreSQL/PostGIS + FakeLlmClient.

For every committed GEOINT scenario the production pipeline runs end to end:

```text
reference geography + Investigation + GEOLOCATION Evidence + PENDING work
  -> real GeoResolutionWorker + PostgresCanonicalGeographyResolver
  -> EntityLocationObservation / EntityLocation
  -> real PostgresGeointQueryService (recording wrapper)
  -> GeointAnalysisTools / GeointAnalysisContextPolicy
  -> real EvidenceAnalystInputLoader (with the GEOINT context loader)
  -> FakeLlmClient at the model boundary only
  -> deterministic geographic validation
  -> real AssessmentPersistenceService
  -> persisted Assessment read back
  -> GeointDeterministicEvaluator
```

S10/S11/S12 additionally drive the real retry/stale-lease/crash worker
lifecycles with deterministic test timestamp control (no sleeps), closing the
recovery matrix with exactly-one-final-truth assertions. No canonical closure
fixture directly inserts derived geographic truth, and ``FakeLlmClient`` is
the only model fake.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst import (
    EvidenceAnalyst,
    EvidenceAnalystInputLoader,
    LlmAccountingService,
)
from agentic_threat_investigator.app.evidence_analyst.geoint_validation import (
    GeographicFindingValidationError,
)
from agentic_threat_investigator.app.geoint.analysis_context import (
    GeointAnalysisContextPolicy,
    GeointAnalystContextLoader,
)
from agentic_threat_investigator.app.geoint.analysis_tools import GeointAnalysisTools
from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.geoint.worker import (
    GeoResolutionWorker,
    GeoResolutionWorkerConfig,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.analyst import (
    AnalystGeointContext,
    EvidenceAnalystDecision,
    EvidenceAnalystInput,
    GeographicFinding,
    GeographicFindingKind,
    GeographicTemporalInterpretation,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.evaluation.geoint.evaluator import (
    GeointDeterministicEvaluator,
)
from agentic_threat_investigator.evaluation.geoint.loader import (
    load_geoint_scenarios_directory,
)
from agentic_threat_investigator.evaluation.geoint.materializer import (
    GeointScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.geoint.models import (
    GeointAgentEvaluationInput,
    GeointEvaluationFailureCode,
    GeointEvaluationResult,
    GeointGeographicState,
    GeointScenario,
    GeointScenarioResolution,
    GeointValidationOutcome,
)
from agentic_threat_investigator.evaluation.geoint.tracing import (
    RecordingGeointQueryService,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.canonical_geography_resolver import (
    PostgresCanonicalGeographyResolver,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.geoint import (
    PostgresGeointQueryService,
)
from tests.integration.test_geo_resolution_lifecycle import (
    force_due,
    force_lease_expiry,
)
from tests.support.llm_fixtures import FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

SCENARIOS_DIRECTORY = Path("evals/scenarios/geoint")

_RETRY_SCENARIO = "g26g_s10_retry_then_resolve"
_STALE_SCENARIO = "g26g_s11_stale_lease_recovery"
_CRASH_SCENARIO = "g26g_s12_crash_after_claim"
_OVERSTATEMENT_SCENARIO = "g26g_s15_model_overstates_colocation"
_NO_TRUTH_SCENARIOS = {"g26g_s08_ambiguous_claim", "g26g_s09_unresolvable_claim"}


class _SessionBoundResolver(LocationResolver):
    """Production resolver seam with one short read session per resolve."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """Bind the read-session factory."""
        self._session_factory = session_factory

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Resolve through the real PostGIS canonical resolver."""
        async with self._session_factory() as session:
            return await PostgresCanonicalGeographyResolver(session).resolve(claim)


class _FailOnceResolver(LocationResolver):
    """Deterministic retry driver: fail the first attempts, then resolve."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        fail_attempts: int,
    ) -> None:
        """Bind the read-session factory and the failure plan."""
        self._delegate = _SessionBoundResolver(session_factory)
        self.fail_attempts = fail_attempts
        self.attempts = 0

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Fail the first attempts with a transient error, then resolve."""
        self.attempts += 1
        if self.attempts <= self.fail_attempts:
            raise RuntimeError("scripted transient resolver failure")
        return await self._delegate.resolve(claim)


def _worker_instance(
    uow_factory: Callable[[], UnitOfWork],
    resolver: LocationResolver,
    *,
    worker_id: str,
) -> GeoResolutionWorker:
    """Compose one production-style GeoResolution worker."""
    return GeoResolutionWorker(
        uow_factory=uow_factory,
        resolver=resolver,
        config=GeoResolutionWorkerConfig(
            enabled=True,
            worker_id=worker_id,
            batch_size=10,
            lease_seconds=300,
            poll_interval_seconds=1.0,
            max_attempts=4,
            retry_base_seconds=60.0,
            retry_max_seconds=3600.0,
        ),
    )


async def _complete_scenario(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    scenario: GeointScenario,
    resolution: GeointScenarioResolution,
) -> None:
    """Drive the production worker lifecycle to terminal state.

    Ordinary scenarios complete in one bounded worker pass. The retry,
    stale-lease, and crash scenarios drive the real claim/lease/reclaim
    lifecycle with deterministic test timestamp control (no sleeps).
    """
    if scenario.id == _RETRY_SCENARIO:
        resolver = _FailOnceResolver(session_factory, fail_attempts=1)
        worker = _worker_instance(uow_factory, resolver, worker_id="worker-retry")
        # Round 1: claim + transient failure -> scheduled bounded retry.
        assert await worker.run_once() == 1
        await force_due(integration_engine, resolution.resolution_ids["seattle_obs"])
        # Round 2: reclaim and resolve atomically.
        assert await worker.run_once() == 1
        return

    if scenario.id == _STALE_SCENARIO:
        # A claims and stalls; the lease expires; B reclaims and completes;
        # A's stale completion attempt is rejected by the stored function.
        async with uow_factory() as uow:
            claimed_a = await uow.geo_resolutions.claim_batch(
                claimed_by="worker-a-stale",
                limit=10,
                lease_seconds=300,
                max_attempts=4,
            )
        assert len(claimed_a) == 1
        resolution_id = resolution.resolution_ids["seattle_obs"]
        await force_lease_expiry(integration_engine, resolution_id)
        worker_b = _worker_instance(
            uow_factory,
            _SessionBoundResolver(session_factory),
            worker_id="worker-b-stale",
        )
        # B claims the reclaimed row and completes it atomically.
        assert await worker_b.run_once() == 1
        return

    if scenario.id == _CRASH_SCENARIO:
        # A claims and COMMITS then crashes before any completion; B reclaims
        # after lease expiry and completes with exactly one final truth.
        async with uow_factory() as uow:
            claimed_a = await uow.geo_resolutions.claim_batch(
                claimed_by="worker-a-crash",
                limit=10,
                lease_seconds=300,
                max_attempts=4,
            )
        assert len(claimed_a) == 1
        await force_lease_expiry(
            integration_engine, resolution.resolution_ids["seattle_obs"]
        )
        worker_b = _worker_instance(
            uow_factory,
            _SessionBoundResolver(session_factory),
            worker_id="worker-b-crash",
        )
        assert await worker_b.run_once() == 1
        return

    worker = _worker_instance(
        uow_factory, _SessionBoundResolver(session_factory), worker_id="worker-26g"
    )
    await worker.run_once()


def _shared_location_decision(
    scenario: GeointScenario,
    resolution: GeointScenarioResolution,
    state: GeointGeographicState,
) -> EvidenceAnalystDecision:
    """Build the canonical descriptive SHARED_LOCATION decision.

    Only observations visible in the scenario's Investigation state are
    cited; cross-Investigation observations never enter the finding.
    """
    visible = {item.observation_id for item in state.observations}
    observation_ids = tuple(
        resolution.observation_ids[item.label]
        for item in scenario.fixture.resolutions
        if item.label in resolution.observation_ids
        and resolution.observation_ids[item.label] in visible
    )
    by_id = {item.observation_id: item for item in state.observations}
    evidence_ids = tuple(
        by_id[observation_id].evidence_id for observation_id in observation_ids
    )
    entity_ids = tuple(
        sorted({by_id[observation_id].entity_id for observation_id in observation_ids})
    )
    location_ids = tuple(
        sorted(
            {by_id[observation_id].location_id for observation_id in observation_ids}
        )
    )
    finding = GeographicFinding(
        kind=GeographicFindingKind.SHARED_LOCATION,
        statement="The observations resolve to one shared canonical location.",
        temporal_interpretation=GeographicTemporalInterpretation.NONE,
        observation_ids=observation_ids,
        evidence_ids=evidence_ids,
        entity_ids=entity_ids,
        location_ids=location_ids,
    )
    return EvidenceAnalystDecision(
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="Descriptive geographic context only.",
        disposition=AnalysisDisposition.EXHAUSTED,
        geographic_findings=(finding,),
    )


def _history_decision(
    resolution: GeointScenarioResolution,
    state: GeointGeographicState,
) -> EvidenceAnalystDecision:
    """Build the canonical descriptive LOCATION_CHANGE_OBSERVED decision."""
    by_id = {item.observation_id: item for item in state.observations}
    ordered = sorted(
        state.observations,
        key=lambda item: (
            item.observed_at or item.retrieved_at,
            item.observation_id,
        ),
    )
    observation_ids = tuple(item.observation_id for item in ordered)
    finding = GeographicFinding(
        kind=GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
        statement=(
            "Two supported observations identify different canonical "
            "locations; the change is recorded descriptively."
        ),
        temporal_interpretation=GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED,
        observation_ids=observation_ids,
        evidence_ids=tuple(by_id[item].evidence_id for item in observation_ids),
        entity_ids=tuple({by_id[item].entity_id for item in observation_ids}),
        location_ids=tuple(
            sorted({by_id[item].location_id for item in observation_ids})
        ),
    )
    return EvidenceAnalystDecision(
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="Descriptive location history.",
        disposition=AnalysisDisposition.EXHAUSTED,
        geographic_findings=(finding,),
    )


def _independent_support_decision(
    resolution: GeointScenarioResolution,
    state: GeointGeographicState,
) -> EvidenceAnalystDecision:
    """Build the canonical independent-support decision (S16)."""
    observation_id = resolution.observation_ids["geo_obs"]
    by_id = {item.observation_id: item for item in state.observations}
    observation = by_id[observation_id]
    finding = GeographicFinding(
        kind=GeographicFindingKind.SHARED_LOCATION,
        statement="The IP was observed in Seattle; geography is context only.",
        temporal_interpretation=GeographicTemporalInterpretation.NONE,
        observation_ids=(observation_id,),
        evidence_ids=(observation.evidence_id,),
        entity_ids=(observation.entity_id,),
        location_ids=(observation.location_id,),
    )
    return EvidenceAnalystDecision(
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Independent DNS evidence supports a malicious interpretation.",
        disposition=AnalysisDisposition.SUFFICIENT,
        findings=(
            AnalyticalFinding(
                category=FindingCategory.NETWORK,
                disposition=FindingDisposition.SUPPORTING,
                statement="The domain resolves to a block-listed controller.",
                confidence=AssessmentConfidence.MEDIUM,
                support=(
                    EvidenceSupport(
                        kind="evidence",
                        evidence_id=resolution.evidence_ids["dns_evidence"],
                    ),
                ),
            ),
        ),
        geographic_findings=(finding,),
    )


def _overstatement_decision(
    resolution: GeointScenarioResolution,
    state: GeointGeographicState,
) -> EvidenceAnalystDecision:
    """Build the rejected overstatement decision (S15)."""
    by_id = {item.observation_id: item for item in state.observations}
    a_obs = resolution.observation_ids["a_obs"]
    b_obs = resolution.observation_ids["b_obs"]
    finding = GeographicFinding(
        kind=GeographicFindingKind.SHARED_LOCATION,
        statement="Both entities are effectively colocated.",
        temporal_interpretation=GeographicTemporalInterpretation.NONE,
        observation_ids=(a_obs, b_obs),
        evidence_ids=(by_id[a_obs].evidence_id, by_id[b_obs].evidence_id),
        entity_ids=(by_id[a_obs].entity_id, by_id[b_obs].entity_id),
        location_ids=(by_id[a_obs].location_id, by_id[b_obs].location_id),
    )
    return EvidenceAnalystDecision(
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="Overstated co-location attempt.",
        disposition=AnalysisDisposition.EXHAUSTED,
        geographic_findings=(finding,),
    )


def canonical_decision(
    scenario: GeointScenario,
    resolution: GeointScenarioResolution,
    state: GeointGeographicState,
) -> EvidenceAnalystDecision:
    """Build the scenario's canonical scripted FakeLlmClient decision."""
    if scenario.id in _NO_TRUTH_SCENARIOS:
        return EvidenceAnalystDecision(
            verdict=Verdict.INCONCLUSIVE,
            confidence=AssessmentConfidence.LOW,
            summary="No canonical geographic truth was produced.",
            disposition=AnalysisDisposition.EXHAUSTED,
        )
    if scenario.id == _OVERSTATEMENT_SCENARIO:
        return _overstatement_decision(resolution, state)
    if scenario.id == "g26g_s04_changing_location_history":
        return _history_decision(resolution, state)
    if scenario.id == "g26g_s16_independent_support_plus_geography":
        return _independent_support_decision(resolution, state)
    return _shared_location_decision(scenario, resolution, state)


class _CapturingGeointLoader(GeointAnalystContextLoader):
    """Capture the real delivered model-visible context for evaluation."""

    def __init__(self, delegate: GeointAnalystContextLoader) -> None:
        """Bind the delegate and the capture slot."""
        self._delegate = delegate
        self.captured: AnalystGeointContext | None = None

    async def load(
        self, investigation_id: UUID, analyst_input: EvidenceAnalystInput
    ) -> AnalystGeointContext:
        """Load through the delegate and record the context."""
        context = await self._delegate.load(investigation_id, analyst_input)
        self.captured = context
        return context


def build_analyst(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    llm: FakeLlmClient,
    trace_records: list[object],
    *,
    max_observations_per_entity: int = 5,
) -> tuple[EvidenceAnalyst, _CapturingGeointLoader]:
    """Compose the analyst stack with a recording query service and capture.

    Returns the composed analyst and the capturing GEOINT loader so the test
    can read the exact delivered context.
    """

    def tools_factory() -> GeointAnalysisTools:
        """Build one tools facade over a fresh read session."""
        session = session_factory()

        async def close() -> None:
            """Close the short-lived read session owned by this invocation."""
            await session.close()

        recording = RecordingGeointQueryService(
            PostgresGeointQueryService(
                session,
                QueryLimits(default_page_size=50, max_page_size=200),
                summary_top_locations=10,
            )
        )
        trace_records.append(recording)
        return GeointAnalysisTools(
            recording,
            max_observations_per_entity=max_observations_per_entity,
            on_close=close,
        )

    capturing = _CapturingGeointLoader(
        GeointAnalystContextLoader(
            tools_factory=tools_factory,
            policy=GeointAnalysisContextPolicy(
                max_entities=10,
                max_observations_per_entity=max_observations_per_entity,
                max_total_observations=25,
                max_context_bytes=262_144,
            ),
        )
    )
    analyst = EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(
            uow_factory, geoint_context_loader=capturing
        ),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            uow_factory, batch_size=100
        ),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=2,
    )
    return analyst, capturing


async def _materialize_and_complete(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    scenario: GeointScenario,
    materializer: GeointScenarioMaterializer,
) -> tuple[GeointScenarioResolution, GeointGeographicState]:
    """Materialize the fixture and drive the production worker to terminal."""
    async with uow_factory() as uow:
        resolution = await materializer.materialize(uow, scenario)
    await _complete_scenario(
        uow_factory, session_factory, integration_engine, scenario, resolution
    )
    async with uow_factory() as uow:
        resolution = await materializer.read_observations(uow, scenario, resolution)
        state = await materializer.build_geographic_state(uow, scenario, resolution)
    return resolution, state


@pytest.fixture(scope="session")
def scenarios() -> tuple[GeointScenario, ...]:
    """Load the committed GEOINT scenario corpus once."""
    return load_geoint_scenarios_directory(SCENARIOS_DIRECTORY)


async def assessment_count(
    uow_factory: Callable[[], PostgresUnitOfWork], investigation_id: UUID
) -> int:
    """Count durable Assessment rows for one Investigation."""
    async with uow_factory() as uow:
        assert uow.session is not None
        result = await uow.session.execute(
            text("SELECT count(*) FROM ati.assessment WHERE investigation_id = :id"),
            {"id": investigation_id},
        )
        return int(result.scalar_one())


async def relationship_count(uow_factory: Callable[[], PostgresUnitOfWork]) -> int:
    """Count every durable Relationship row."""
    async with uow_factory() as uow:
        assert uow.session is not None
        result = await uow.session.execute(
            text("SELECT count(*) FROM ati.relationship")
        )
        return int(result.scalar_one())


def _failure_codes(result: GeointEvaluationResult) -> set[GeointEvaluationFailureCode]:
    """Return the stable failure codes of one evaluation result."""
    return {failure.code for failure in result.failures}


@pytest.mark.asyncio
async def test_every_canonical_scenario_passes_end_to_end(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    scenarios: tuple[GeointScenario, ...],
) -> None:
    """Each corpus scenario: fixture -> worker -> analyst -> evaluator -> PASS.

    The canonical FakeLlmClient decision exercises the unchanged PR 26F
    execution path; the persisted Assessment is re-fetched through the
    repository before evaluation, proving evaluation consumes durable output.
    """
    materializer = GeointScenarioMaterializer()
    for scenario in scenarios:
        if scenario.id == _OVERSTATEMENT_SCENARIO:
            # S15 is a deterministic rejection case and has its own test.
            continue
        resolution, state = await _materialize_and_complete(
            uow_factory, session_factory, integration_engine, scenario, materializer
        )
        decision = canonical_decision(scenario, resolution, state)
        llm = FakeLlmClient()
        llm.set_default(decision)
        trace_records: list[object] = []
        analyst, capturing = build_analyst(
            uow_factory, session_factory, llm, trace_records
        )
        persisted = await analyst.analyze(resolution.investigation_id)

        assert persisted.id is not None
        async with uow_factory() as uow:
            read_back = await uow.assessments.get_by_id(persisted.id)
        assert read_back is not None

        recording = trace_records[-1]
        assert isinstance(recording, RecordingGeointQueryService)
        context = capturing.captured
        agent = GeointAgentEvaluationInput(
            decision=decision,
            validation=GeointValidationOutcome.ACCEPTED,
            assessment=read_back,
        )
        result = GeointDeterministicEvaluator().evaluate(
            scenario=scenario,
            resolution=resolution,
            state=state,
            context=context,
            tool_trace=tuple(recording.records),
            agent=agent,
        )
        assert result.passed, f"scenario {scenario.id} failed: " + "; ".join(
            failure.message for failure in result.failures
        )
        assert result.metrics.provenance_closure_rate == 1.0
        # No geography ever creates a Relationship (S05/S06/S14 world).
        assert await relationship_count(uow_factory) == 0


@pytest.mark.asyncio
async def test_overstatement_is_rejected_and_hard_fails(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    scenarios: tuple[GeointScenario, ...],
) -> None:
    """S15: the runtime validator rejects; evaluation hard-fails the predicate."""
    scenario = next(item for item in scenarios if item.id == _OVERSTATEMENT_SCENARIO)
    materializer = GeointScenarioMaterializer()
    resolution, state = await _materialize_and_complete(
        uow_factory, session_factory, integration_engine, scenario, materializer
    )
    decision = _overstatement_decision(resolution, state)
    llm = FakeLlmClient()
    llm.set_default(decision)
    trace_records: list[object] = []
    analyst, capturing = build_analyst(uow_factory, session_factory, llm, trace_records)

    with pytest.raises(GeographicFindingValidationError):
        await analyst.analyze(resolution.investigation_id)
    assert await assessment_count(uow_factory, resolution.investigation_id) == 0

    recording = trace_records[-1]
    assert isinstance(recording, RecordingGeointQueryService)
    agent = GeointAgentEvaluationInput(
        decision=decision,
        validation=GeointValidationOutcome.REJECTED,
        assessment=None,
    )
    result = GeointDeterministicEvaluator().evaluate(
        scenario=scenario,
        resolution=resolution,
        state=state,
        context=capturing.captured,
        tool_trace=tuple(recording.records),
        agent=agent,
    )
    assert not result.passed
    codes = _failure_codes(result)
    assert GeointEvaluationFailureCode.WRONG_FINDING_LOCATION_SUPPORT in codes
    assert GeointEvaluationFailureCode.UNEXPECTED_VALIDATION_OUTCOME not in codes


@pytest.mark.asyncio
async def test_recovery_scenarios_produce_exactly_one_final_truth(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    scenarios: tuple[GeointScenario, ...],
) -> None:
    """R01-R05 closure: retry/stale/crash produce one authoritative truth.

    The combined-state assertions are exactly the evaluator's spatial and
    provenance hard checks over the worker-completed state: one resolution,
    one observation, one current, correct precision, no duplicate truth.
    """
    materializer = GeointScenarioMaterializer()
    for scenario_id in (
        _RETRY_SCENARIO,
        _STALE_SCENARIO,
        _CRASH_SCENARIO,
    ):
        scenario = next(item for item in scenarios if item.id == scenario_id)
        resolution, state = await _materialize_and_complete(
            uow_factory, session_factory, integration_engine, scenario, materializer
        )
        # Exactly one authoritative observation and current row.
        assert len(state.observations) == 1
        assert len(state.current) == 1
        assert len(state.resolutions) == 1
        [resolution_state] = state.resolutions
        assert resolution_state.status == "resolved"
        assert resolution_state.observation_id is not None
        observation_id = resolution.observation_ids["seattle_obs"]
        assert observation_id == resolution_state.observation_id
        assert observation_id == state.observations[0].observation_id
        assert state.current[0].latest_observation_id == observation_id
        # The worker left no second work row in a non-terminal state.
        async with uow_factory() as uow:
            work = await uow.geo_resolutions.get_by_id(
                resolution.resolution_ids["seattle_obs"]
            )
        assert work is not None
        assert work.status.value in ("resolved", "failed")


@pytest.mark.asyncio
async def test_cross_investigation_never_leaks_into_context_or_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    scenarios: tuple[GeointScenario, ...],
) -> None:
    """S13: I2's observation never enters I1's state, context, or output."""
    scenario = next(
        item
        for item in scenarios
        if item.id == "g26g_s13_cross_investigation_isolation"
    )
    materializer = GeointScenarioMaterializer()
    resolution, state = await _materialize_and_complete(
        uow_factory, session_factory, integration_engine, scenario, materializer
    )
    # I1's scoped state sees only the Seattle observation.
    assert len(state.observations) == 1
    assert (
        state.observations[0].observation_id
        == resolution.observation_ids["seattle_obs"]
    )
    assert state.current[0].location_id == resolution.geography_ids["seattle"]
    # The Dallas work completed globally but is out of I1's scope.
    dallas = resolution.observation_ids.get("dallas_obs")
    assert dallas is not None and dallas not in {
        item.observation_id for item in state.observations
    }

    decision = canonical_decision(scenario, resolution, state)
    llm = FakeLlmClient()
    llm.set_default(decision)
    trace_records: list[object] = []
    analyst, capturing = build_analyst(uow_factory, session_factory, llm, trace_records)
    persisted = await analyst.analyze(resolution.investigation_id)
    assert persisted.id is not None
    assert capturing.captured is not None
    assert all(
        item.observation_id != dallas
        for entity in capturing.captured.entities
        for item in (entity.current_observation, *entity.history)
        if item is not None
    )
    result = GeointDeterministicEvaluator().evaluate(
        scenario=scenario,
        resolution=resolution,
        state=state,
        context=capturing.captured,
        tool_trace=(),
        agent=GeointAgentEvaluationInput(
            decision=decision,
            validation=GeointValidationOutcome.ACCEPTED,
            assessment=persisted,
        ),
    )
    assert result.passed, "; ".join(failure.message for failure in result.failures)


@pytest.mark.asyncio
async def test_precision_is_preserved_and_context_has_no_coordinates(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    scenarios: tuple[GeointScenario, ...],
) -> None:
    """S01-S03/S07: precision is never inflated and context carries no coords."""
    materializer = GeointScenarioMaterializer()
    expected_precisions = {
        "g26g_s01_country_precision_only": "country",
        "g26g_s02_administrative_precision": "administrative_area",
        "g26g_s03_city_precision": "city",
        "g26g_s07_coordinate_less_valid": "country",
    }
    for scenario_id, expected_precision in expected_precisions.items():
        scenario = next(item for item in scenarios if item.id == scenario_id)
        resolution, state = await _materialize_and_complete(
            uow_factory, session_factory, integration_engine, scenario, materializer
        )
        assert state.observations[0].precision.value == expected_precision
        assert state.current[0].precision.value == expected_precision
        assert len(resolution.observation_ids) == 1
        # The model-visible context serialization never carries coordinates.
        decision = canonical_decision(scenario, resolution, state)
        llm = FakeLlmClient()
        llm.set_default(decision)
        trace_records: list[object] = []
        analyst, capturing = build_analyst(
            uow_factory, session_factory, llm, trace_records
        )
        await analyst.analyze(resolution.investigation_id)
        assert capturing.captured is not None
        serialized = capturing.captured.model_dump_json()
        assert "latitude" not in serialized
        assert "longitude" not in serialized
