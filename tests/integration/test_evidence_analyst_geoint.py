# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26F canonical vertical slice: real PostgreSQL/PostGIS + FakeLlmClient.

Runs the production path end to end:

```text
seed Investigation + GEOLOCATION LegacyEvidence
  -> real GeoResolutionWorker + PostgresCanonicalGeographyResolver
  -> EntityLocationObservation
  -> real PostgresGeointQueryService
  -> GeointAnalysisTools / GeointAnalysisContextPolicy
  -> real EvidenceAnalystInputLoader (with the GEOINT context loader)
  -> FakeLlmClient at the model boundary only
  -> deterministic geographic validation
  -> real AssessmentPersistenceService
  -> persisted Assessment read back
```

G26F-I01..I07 cover descriptive current geography, location history, same
location with unrelated Entities, cross-Investigation isolation, bounded
history, independent support, and the no-GEOINT baseline. All seeds write
through the normal repositories; ``FakeLlmClient`` is the only fake.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

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
from agentic_threat_investigator.app.persistence.repositories import (
    UnitOfWork as UnitOfWorkType,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.analyst import (
    EvidenceAnalystDecision,
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
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
    GeoResolution,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.infrastructure.persistence.postgresql.canonical_geography_resolver import (
    PostgresCanonicalGeographyResolver,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.geoint import (
    PostgresGeointQueryService,
)
from tests.integration.test_geoint_query import (
    FIXED,
    seed_entity,
    seed_geography,
    seed_investigation,
)
from tests.support.llm_fixtures import FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_OBSERVED_AT = datetime(2026, 1, 5, 6, 7, 8, tzinfo=UTC)


class _SessionBoundResolver(LocationResolver):
    """LocationResolver adapter with one short read session per resolve."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """Bind the read-session factory."""
        self._session_factory = session_factory

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Resolve through the real PostGIS canonical resolver."""
        async with self._session_factory() as session:
            return await PostgresCanonicalGeographyResolver(session).resolve(claim)


def _worker_instance(
    uow_factory: Callable[[], UnitOfWorkType],
    session_factory: async_sessionmaker[AsyncSession],
) -> GeoResolutionWorker:
    """Compose one production-style GeoResolution worker over the real resolver."""
    return GeoResolutionWorker(
        uow_factory=uow_factory,
        resolver=_SessionBoundResolver(session_factory),
        config=GeoResolutionWorkerConfig(
            enabled=True,
            worker_id="worker-26f",
            batch_size=10,
            lease_seconds=300,
            poll_interval_seconds=1.0,
            max_attempts=3,
            retry_base_seconds=60.0,
            retry_max_seconds=3600.0,
        ),
    )


async def seed_geolocation_evidence(
    uow: PostgresUnitOfWork,
    *,
    investigation_id: UUID,
    entity_id: UUID,
    value: str,
    observed_at: datetime | None = _OBSERVED_AT,
    retrieved_at: datetime | None = None,
    facts: Mapping[str, object] | None = None,
) -> UUID:
    """Persist one normal GEOLOCATION global observation and admit it."""
    identity = uuid4()
    stable = Evidence(
        id=identity,
        type=EvidenceType.GEOLOCATION,
        source="urn:ati:source:test",
        source_record_id=f"geo-{identity}",
    )
    observation_time = (
        retrieved_at if retrieved_at is not None else observed_at or _OBSERVED_AT
    )
    persisted = await uow.evidence.persist(
        ConvertedEvidence(
            evidence=stable,
            observation=EvidenceObservationCandidate(
                evidence_id=stable.id,
                observed_at=observed_at,
                retrieved_at=observation_time,
                facts=(
                    dict(facts)
                    if facts is not None
                    else {
                        "country_code": "US",
                        "region": "Washington",
                        "city": "Seattle",
                        "precision": "city",
                    }
                ),
            ),
        ),
        observation_id=identity,
    )
    await uow.evidence_observation_entities.associate(
        persisted.observation.id, entity_id
    )
    await uow.investigation_evidence.admit(
        InvestigationEvidence(
            investigation_id=investigation_id,
            evidence_observation_id=persisted.observation.id,
            inclusion_reason=InvestigationEvidenceReason.INITIAL,
            added_at=_OBSERVED_AT,
            added_by=InvestigationEvidenceActor.SYSTEM,
        )
    )
    return persisted.observation.id


async def seed_dns_evidence(
    uow: PostgresUnitOfWork, *, investigation_id: UUID, entity_id: UUID, value: str
) -> UUID:
    """Persist one independent non-geographic DNS global observation."""
    identity = uuid4()
    stable = Evidence(
        id=identity,
        type=EvidenceType.DNS,
        source="urn:ati:source:test",
        source_record_id=f"dns-{identity}",
    )
    persisted = await uow.evidence.persist(
        ConvertedEvidence(
            evidence=stable,
            observation=EvidenceObservationCandidate(
                evidence_id=stable.id,
                retrieved_at=_OBSERVED_AT,
                facts={"a_records": ["192.0.2.1"]},
            ),
        ),
        observation_id=identity,
    )
    await uow.evidence_observation_entities.associate(
        persisted.observation.id, entity_id
    )
    await uow.investigation_evidence.admit(
        InvestigationEvidence(
            investigation_id=investigation_id,
            evidence_observation_id=persisted.observation.id,
            inclusion_reason=InvestigationEvidenceReason.INITIAL,
            added_at=_OBSERVED_AT,
            added_by=InvestigationEvidenceActor.SYSTEM,
        )
    )
    return persisted.observation.id


async def resolve_pending(
    uow_factory: Callable[[], UnitOfWorkType],
    session_factory: async_sessionmaker[AsyncSession],
) -> int:
    """Run the real resolution worker once and return completed work items."""
    return await _worker_instance(uow_factory, session_factory).run_once()


def build_analyst(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    llm: FakeLlmClient,
    *,
    max_observations_per_entity: int = 5,
) -> EvidenceAnalyst:
    """Compose the full analyst stack with the real GEOINT context loader."""

    def tools_factory() -> GeointAnalysisTools:
        """Build one tools facade over a fresh read session."""
        session = session_factory()

        async def close() -> None:
            """Close the short-lived read session owned by this invocation."""
            await session.close()

        return GeointAnalysisTools(
            PostgresGeointQueryService(
                session,
                QueryLimits(default_page_size=50, max_page_size=200),
                summary_top_locations=10,
            ),
            max_observations_per_entity=max_observations_per_entity,
            on_close=close,
        )

    geoint_loader = GeointAnalystContextLoader(
        tools_factory=tools_factory,
        policy=GeointAnalysisContextPolicy(
            max_entities=10,
            max_observations_per_entity=max_observations_per_entity,
            max_total_observations=25,
            max_context_bytes=262_144,
        ),
    )
    return EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(
            uow_factory, geoint_context_loader=geoint_loader
        ),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            uow_factory, batch_size=100
        ),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=2,
    )


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


async def seeded_investigation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    *,
    value: str = "203.0.113.201",
    city: str = "Seattle",
) -> tuple[UUID, UUID, UUID]:
    """Seed one Investigation resolved to one city via the normal path.

    Returns ``(investigation_id, entity_id, evidence_id)``.
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await seed_geography(uow)
        entity_id = await seed_entity(uow, value=value)
        evidence_id = await seed_geolocation_evidence(
            uow, investigation_id=investigation_id, entity_id=entity_id, value=value
        )
        await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(), entity_id=entity_id, evidence_observation_id=evidence_id
            )
        )
    completed = await resolve_pending(uow_factory, session_factory)
    assert completed == 1
    return investigation_id, entity_id, evidence_id


async def latest_observation(
    uow_factory: Callable[[], PostgresUnitOfWork], entity_id: UUID
) -> tuple[UUID, UUID]:
    """Return the exact ``(observation_id, evidence_id)`` persisted for an Entity."""
    async with uow_factory() as uow:
        rows = await uow.entity_location_observations.list_for_entity(
            entity_id, limit=100
        )
    assert len(rows) == 1
    assert rows[0].id is not None
    return rows[0].id, rows[0].evidence_observation_id


def descriptive_decision(
    *,
    observation_id: UUID,
    evidence_id: UUID,
    entity_id: UUID,
    location_id: UUID,
    verdict: Verdict = Verdict.INCONCLUSIVE,
) -> EvidenceAnalystDecision:
    """Build a single-observation descriptive shared-location decision."""
    return EvidenceAnalystDecision(
        verdict=verdict,
        confidence=AssessmentConfidence.LOW,
        summary="The resolved city observation is recorded descriptively.",
        disposition=AnalysisDisposition.EXHAUSTED,
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.SHARED_LOCATION,
                statement="The entity was observed in Seattle.",
                temporal_interpretation=GeographicTemporalInterpretation.NONE,
                observation_ids=(observation_id,),
                evidence_observation_ids=(evidence_id,),
                entity_ids=(entity_id,),
                location_ids=(location_id,),
            ),
        ),
    )


async def test_g26f_i01_descriptive_current_geography(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I01 one resolved city observation persists with exact LegacyEvidence support."""
    investigation_id, entity_id, evidence_id = await seeded_investigation(
        uow_factory, session_factory
    )
    observation_id, _ = await latest_observation(uow_factory, entity_id)

    async with uow_factory() as uow:
        rows = await uow.entity_location_observations.list_for_entity(
            entity_id, limit=1
        )
        location_id = rows[0].location_id

    llm = FakeLlmClient()
    llm.set_default(
        descriptive_decision(
            observation_id=observation_id,
            evidence_id=evidence_id,
            entity_id=entity_id,
            location_id=location_id,
        )
    )
    analyst = build_analyst(uow_factory, session_factory, llm)

    persisted = await analyst.analyze(investigation_id)

    assert persisted.investigation_id == investigation_id
    assert evidence_id in persisted.analyzed_evidence_ids
    [finding] = persisted.findings
    assert finding.category is FindingCategory.GEOLOCATION
    assert [
        s.evidence_id for s in finding.support if isinstance(s, EvidenceSupport)
    ] == [evidence_id]
    # The model prompt carried the exact observation/evidence pair.
    assert str(observation_id) in llm.calls[0].user_prompt
    assert str(evidence_id) in llm.calls[0].user_prompt
    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(investigation_id)
        assert state is not None and state.assessment_id == persisted.id
        assert state.budget.llm_calls_used == 1


async def test_g26f_i02_location_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I02 same Entity at two Locations allows descriptive location change."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        entity_id = await seed_entity(uow, value="203.0.113.202")
        seattle_evidence_id = await seed_geolocation_evidence(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            value="203.0.113.202",
        )
        dallas_evidence_id = await seed_geolocation_evidence(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            value="203.0.113.202",
            observed_at=_OBSERVED_AT + timedelta(days=1),
            retrieved_at=_OBSERVED_AT + timedelta(days=1, hours=1),
            facts={
                "country_code": "US",
                "region": "Texas",
                "city": "Dallas",
                "precision": "city",
            },
        )
        await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(),
                entity_id=entity_id,
                evidence_observation_id=seattle_evidence_id,
            )
        )
        await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(),
                entity_id=entity_id,
                evidence_observation_id=dallas_evidence_id,
            )
        )
    completed = await resolve_pending(uow_factory, session_factory)
    assert completed == 2

    async with uow_factory() as uow:
        rows = await uow.entity_location_observations.list_for_entity(
            entity_id, limit=100
        )
    assert len(rows) == 2
    by_location = {
        row.location_id: (row.id, row.evidence_observation_id) for row in rows
    }
    seattle_obs, seattle_ev = by_location[geography["Seattle"]]
    dallas_obs, dallas_ev = by_location[geography["Dallas"]]
    assert (seattle_obs, seattle_ev) != (dallas_obs, dallas_ev)

    decision = EvidenceAnalystDecision(
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="Two resolved city observations are recorded descriptively.",
        disposition=AnalysisDisposition.EXHAUSTED,
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
                statement=(
                    "Two supported observations identify different canonical "
                    "locations at different effective times."
                ),
                temporal_interpretation=(
                    GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED
                ),
                observation_ids=(seattle_obs, dallas_obs),
                evidence_observation_ids=(seattle_ev, dallas_ev),
                entity_ids=(entity_id,),
                location_ids=(geography["Seattle"], geography["Dallas"]),
            ),
        ),
    )
    llm = FakeLlmClient()
    llm.set_default(decision)
    persisted = await build_analyst(uow_factory, session_factory, llm).analyze(
        investigation_id
    )
    assert persisted.id is not None
    [finding] = persisted.findings
    assert finding.category is FindingCategory.GEOLOCATION
    assert {
        s.evidence_id for s in finding.support if isinstance(s, EvidenceSupport)
    } == {
        seattle_ev,
        dallas_ev,
    }


async def test_g26f_i03_same_location_unrelated_entities_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I03 same-city unrelated Entities cannot drive a positive verdict."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        first_id = await seed_entity(uow, value="203.0.113.211")
        second_id = await seed_entity(uow, value="203.0.113.212")
        first_evidence = await seed_geolocation_evidence(
            uow,
            investigation_id=investigation_id,
            entity_id=first_id,
            value="203.0.113.211",
        )
        second_evidence = await seed_geolocation_evidence(
            uow,
            investigation_id=investigation_id,
            entity_id=second_id,
            value="203.0.113.212",
        )
        await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(), entity_id=first_id, evidence_observation_id=first_evidence
            )
        )
        await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(), entity_id=second_id, evidence_observation_id=second_evidence
            )
        )
    completed = await resolve_pending(uow_factory, session_factory)
    assert completed == 2
    async with uow_factory() as uow:
        first_obs = await uow.entity_location_observations.list_for_entity(
            first_id, limit=1
        )
        second_obs = await uow.entity_location_observations.list_for_entity(
            second_id, limit=1
        )
    assert first_obs[0].location_id == second_obs[0].location_id == geography["Seattle"]

    # The model attempts the prohibited inference: same city -> coordination
    # expressed through the only valid structural shape (shared location) plus
    # a positive verdict with NO independent non-geographic support.
    decision = EvidenceAnalystDecision(
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Both entities are in Seattle, therefore coordinated.",
        disposition=AnalysisDisposition.SUFFICIENT,
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.SHARED_LOCATION,
                statement="Both entities were observed in Seattle.",
                temporal_interpretation=(
                    GeographicTemporalInterpretation.DIFFERENT_OBSERVATION_TIMES
                ),
                observation_ids=(first_obs[0].id, second_obs[0].id),
                evidence_observation_ids=(
                    first_obs[0].evidence_observation_id,
                    second_obs[0].evidence_observation_id,
                ),
                entity_ids=(first_id, second_id),
                location_ids=(geography["Seattle"],),
            ),
        ),
    )
    llm = FakeLlmClient()
    llm.set_default(decision)
    with pytest.raises(GeographicFindingValidationError):
        await build_analyst(uow_factory, session_factory, llm).analyze(investigation_id)

    assert await assessment_count(uow_factory, investigation_id) == 0
    async with uow_factory() as uow:
        assert uow.session is not None
        # PR 28B: no relationship observation was created and no admission
        # scope leaked during the rejected analysis.
        result = await uow.session.execute(
            text("SELECT count(*) FROM ati.relationship_observation")
        )
        assert int(result.scalar_one()) == 0


async def test_g26f_i04_cross_investigation_isolation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I04 I1 context contains only I1 observations; I2 citation is rejected."""
    investigation_a, entity_a, evidence_a = await seeded_investigation(
        uow_factory, session_factory, value="203.0.113.221"
    )
    investigation_b, entity_b, evidence_b = await seeded_investigation(
        uow_factory, session_factory, value="203.0.113.222"
    )
    observation_a, _ = await latest_observation(uow_factory, entity_a)
    observation_b, _ = await latest_observation(uow_factory, entity_b)

    # The I1 model context must not contain I2's observation id.
    llm = FakeLlmClient()
    llm.set_default(
        EvidenceAnalystDecision(
            verdict=Verdict.INCONCLUSIVE,
            confidence=AssessmentConfidence.LOW,
            summary="Descriptive geographic context.",
            disposition=AnalysisDisposition.EXHAUSTED,
            geographic_findings=(
                GeographicFinding(
                    kind=GeographicFindingKind.SHARED_LOCATION,
                    statement="The entity was observed in Seattle.",
                    temporal_interpretation=GeographicTemporalInterpretation.NONE,
                    observation_ids=(observation_b,),
                    evidence_observation_ids=(evidence_b,),
                    entity_ids=(entity_b,),
                    location_ids=(uuid4(),),
                ),
            ),
        )
    )
    with pytest.raises(GeographicFindingValidationError):
        await build_analyst(uow_factory, session_factory, llm).analyze(investigation_a)

    assert await assessment_count(uow_factory, investigation_a) == 0
    assert str(observation_b) not in llm.calls[0].user_prompt

    # A correct descriptive decision over I1's own observation persists.
    async with uow_factory() as uow:
        rows = await uow.entity_location_observations.list_for_entity(entity_a, limit=1)
        location_a = rows[0].location_id
    llm.set_default(
        descriptive_decision(
            observation_id=observation_a,
            evidence_id=evidence_a,
            entity_id=entity_a,
            location_id=location_a,
        )
    )
    persisted = await build_analyst(uow_factory, session_factory, llm).analyze(
        investigation_a
    )
    assert persisted.id is not None


async def test_g26f_i05_bounded_history_cannot_cite_omitted(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I05 only one bounded page is supplied; omitted observations are invisible."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        entity_id = await seed_entity(uow, value="203.0.113.230")
        cities = [
            ("Seattle", geography["Seattle"]),
            ("Dallas", geography["Dallas"]),
            ("Vancouver", geography["Vancouver"]),
            ("Auburn", geography["Auburn"]),
            ("Boundary Town", geography["Boundary Town"]),
        ]
        evidence_ids: list[UUID] = []
        for index, (city, _) in enumerate(cities):
            facts = {
                "country_code": "US" if city != "Vancouver" else "CA",
                "city": city,
                "precision": "city",
            }
            evidence_id = await seed_geolocation_evidence(
                uow,
                investigation_id=investigation_id,
                entity_id=entity_id,
                value="203.0.113.230",
                observed_at=FIXED + timedelta(days=index),
                retrieved_at=FIXED + timedelta(days=index, hours=1),
                facts=facts,
            )
            evidence_ids.append(evidence_id)
            await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=uuid4(),
                    entity_id=entity_id,
                    evidence_observation_id=evidence_id,
                )
            )
    completed = await resolve_pending(uow_factory, session_factory)
    assert completed == 5
    async with uow_factory() as uow:
        rows = await uow.entity_location_observations.list_for_entity(
            entity_id, limit=100
        )
    observations = {row.evidence_observation_id: row.id for row in rows}
    assert len(observations) == 5

    llm = FakeLlmClient()
    llm.set_default(
        EvidenceAnalystDecision(
            verdict=Verdict.INCONCLUSIVE,
            confidence=AssessmentConfidence.LOW,
            summary="Descriptive history findings.",
            disposition=AnalysisDisposition.EXHAUSTED,
            geographic_findings=(
                GeographicFinding(
                    kind=GeographicFindingKind.LOCATION_HISTORY,
                    statement="Multiple city observations are recorded.",
                    temporal_interpretation=(
                        GeographicTemporalInterpretation.DIFFERENT_OBSERVATION_TIMES
                    ),
                    observation_ids=(
                        observations[evidence_ids[2]],
                        observations[evidence_ids[4]],
                    ),
                    evidence_observation_ids=(evidence_ids[2], evidence_ids[4]),
                    entity_ids=(entity_id,),
                    location_ids=(geography["Vancouver"], geography["Boundary Town"]),
                ),
            ),
        )
    )
    analyst = build_analyst(
        uow_factory, session_factory, llm, max_observations_per_entity=3
    )

    persisted = await analyst.analyze(investigation_id)

    assert persisted.id is not None
    assert len(llm.calls) == 1
    joined = llm.calls[0].user_prompt
    # The bounded page (3 of 5 observations) arrived with explicit continuation.
    assert "has_more_history: true" in joined
    # The omitted observations were never supplied, so citing them is rejected.
    omitted = observations[evidence_ids[3]]
    llm.set_default(
        EvidenceAnalystDecision(
            verdict=Verdict.INCONCLUSIVE,
            confidence=AssessmentConfidence.LOW,
            summary="Descriptive history findings.",
            disposition=AnalysisDisposition.EXHAUSTED,
            geographic_findings=(
                GeographicFinding(
                    kind=GeographicFindingKind.LOCATION_HISTORY,
                    statement="History spans several cities.",
                    temporal_interpretation=(
                        GeographicTemporalInterpretation.DIFFERENT_OBSERVATION_TIMES
                    ),
                    observation_ids=(
                        observations[evidence_ids[0]],
                        omitted,
                    ),
                    evidence_observation_ids=(evidence_ids[0], evidence_ids[3]),
                    entity_ids=(entity_id,),
                    location_ids=(geography["Seattle"], geography["Auburn"]),
                ),
            ),
        )
    )
    with pytest.raises(GeographicFindingValidationError):
        await build_analyst(
            uow_factory, session_factory, llm, max_observations_per_entity=3
        ).analyze(investigation_id)
    assert await assessment_count(uow_factory, investigation_id) == 1


async def test_g26f_i06_independent_support_with_geoint_context(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I06 independently supported MALICIOUS may include descriptive GEOINT."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await seed_geography(uow)
        entity_id = await seed_entity(uow, value="203.0.113.240")
        dns_entity_id = await seed_entity(
            uow, value="dns-26f.example.com", entity_type=EntityType.DOMAIN
        )
        dns_evidence = await seed_dns_evidence(
            uow,
            investigation_id=investigation_id,
            entity_id=dns_entity_id,
            value="dns-26f.example.com",
        )
        geo_evidence = await seed_geolocation_evidence(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            value="203.0.113.240",
        )
        await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(), entity_id=entity_id, evidence_observation_id=geo_evidence
            )
        )
    completed = await resolve_pending(uow_factory, session_factory)
    assert completed == 1
    observation_id, _ = await latest_observation(uow_factory, entity_id)
    async with uow_factory() as uow:
        rows = await uow.entity_location_observations.list_for_entity(
            entity_id, limit=1
        )
        location_id = rows[0].location_id

    decision = EvidenceAnalystDecision(
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Independent evidence supports a malicious interpretation.",
        disposition=AnalysisDisposition.SUFFICIENT,
        findings=(
            AnalyticalFinding(
                category=FindingCategory.NETWORK,
                disposition=FindingDisposition.SUPPORTING,
                statement="The domain resolves to a block-listed controller.",
                confidence=AssessmentConfidence.MEDIUM,
                support=(EvidenceSupport(kind="evidence", evidence_id=dns_evidence),),
            ),
        ),
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.SHARED_LOCATION,
                statement="The entity was observed in Seattle.",
                temporal_interpretation=GeographicTemporalInterpretation.NONE,
                observation_ids=(observation_id,),
                evidence_observation_ids=(geo_evidence,),
                entity_ids=(entity_id,),
                location_ids=(location_id,),
            ),
        ),
    )
    llm = FakeLlmClient()
    llm.set_default(decision)
    persisted = await build_analyst(uow_factory, session_factory, llm).analyze(
        investigation_id
    )

    assert persisted.verdict is Verdict.MALICIOUS
    categories = {finding.category for finding in persisted.findings}
    assert categories == {FindingCategory.NETWORK, FindingCategory.GEOLOCATION}
    # The geographic finding remains contextual GEOLOCATION with exact support.
    geographic = next(
        f for f in persisted.findings if f.category is FindingCategory.GEOLOCATION
    )
    assert [
        s.evidence_id for s in geographic.support if isinstance(s, EvidenceSupport)
    ] == [geo_evidence]


async def test_g26f_i07_no_geoint_baseline(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I07 no geographic observations behave exactly like the baseline."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        root_entity_id = await seed_entity(
            uow, value="dns-26f.example.com", entity_type=EntityType.DOMAIN
        )
        await seed_dns_evidence(
            uow,
            investigation_id=investigation_id,
            entity_id=root_entity_id,
            value="dns-26f.example.com",
        )
    llm = FakeLlmClient()
    llm.set_default(
        EvidenceAnalystDecision(
            verdict=Verdict.INCONCLUSIVE,
            confidence=AssessmentConfidence.LOW,
            summary="No geographic context existed for this investigation.",
            disposition=AnalysisDisposition.EXHAUSTED,
        )
    )
    analyst = build_analyst(uow_factory, session_factory, llm)

    persisted = await analyst.analyze(investigation_id)

    assert persisted.id is not None
    assert persisted.verdict is Verdict.INCONCLUSIVE
    assert persisted.findings == ()
    # Exactly one normal accounted model call; the GEOINT context was empty.
    assert len(llm.calls) == 1
    assert "<geographic_context>" in llm.calls[0].user_prompt
    assert "observation_count: 0" in llm.calls[0].user_prompt
