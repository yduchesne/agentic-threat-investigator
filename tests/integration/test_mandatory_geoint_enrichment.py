# SPDX-License-Identifier: AGPL-3.0-only
"""Mandatory GEOINT enrichment vertical slices on real PostgreSQL (PR 35-4).

Exercises the real coordinator graph, real stored-function coordinator
transitions, real ``ProviderWorkExecutor``/``MandatoryEnrichmentExecutor``
kernel, real deterministic extraction, real
``ProviderObservationPersistenceService`` (EvidenceObservation, Entity
association, Investigation admission, and GeoResolution enqueue), and the
real Evidence Analyst with a ``FakeLlmClient``. The only fake at the
intelligence-source boundary is the deterministic Fake World DB-IP provider
(and controlled miss/failure variants); no live LLM, network, or real DB-IP
artifact is required.

Vertical slices I35-4-01/02/03/06 plus the budget/accounting matrix
(B01-B10) and the persistence/GEOINT matrix (G01-G10) are covered here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.evidence_analyst.analyst import EvidenceAnalyst
from agentic_threat_investigator.app.evidence_analyst.loader import (
    EvidenceAnalystInputLoader,
)
from agentic_threat_investigator.app.orchestration.composition import (
    build_provider_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.models import (
    schedule_mandatory_enrichment,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.persistence.repositories import (
    CoordinatorTransitionPersistenceError,
)
from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderError,
    ProviderErrorCode,
    ProviderResult,
)
from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import InvestigationEvidence
from agentic_threat_investigator.domain.geoint import GeoResolutionStatus
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    CoordinatorTransitionKind,
    EntityTraversalState,
    InvestigationBudget,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    MandatoryEnrichmentWorkItem,
    ProviderExecutionStatus,
    StopReason,
)
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeWorldCatalog,
)
from agentic_threat_investigator.infrastructure.fake_runtime.providers import (
    FakeWorldEvidenceProvider,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.llm_fixtures import FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

#: A retrieval clock after every packaged Fake World observation so the
#: deterministic DB-IP fixture is not withheld as "future" data.
_FIXED_TS = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
_DALLAS_IP = "203.0.113.81"
_MISS_IP = "203.0.113.250"
_DOMAIN = "mandatory-geoint.test"


class _FailingDbIpProvider(FakeWorldEvidenceProvider):
    """Deterministic typed provider failure at the DB-IP source boundary."""

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Return one bounded typed DB-IP failure."""
        del investigation_id, entity
        return ProviderResult(
            provider=self.id,
            errors=(
                ProviderError(
                    provider=self.id,
                    code=ProviderErrorCode.PROVIDER_UNAVAILABLE,
                    message="synthetic DB-IP outage",
                    retryable=True,
                ),
            ),
        )


def _catalog() -> FakeWorldCatalog:
    return FakeWorldCatalog.load_packaged()


def _dbip_provider(
    catalog: FakeWorldCatalog, *, failing: bool = False
) -> EvidenceProvider:
    provider_type = _FailingDbIpProvider if failing else FakeWorldEvidenceProvider
    return provider_type(SourceId.DBIP_CITY_LITE, catalog, clock=lambda: _FIXED_TS)


def _analyst_for(
    session_factory: async_sessionmaker[AsyncSession], llm: FakeLlmClient
) -> EvidenceAnalyst:
    return EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(
            lambda: PostgresUnitOfWork(session_factory)
        ),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            lambda: PostgresUnitOfWork(session_factory), batch_size=100
        ),
        llm_accounting=LlmAccountingService(
            lambda: PostgresUnitOfWork(session_factory)
        ),
        max_structured_output_attempts=2,
    )


def _sufficient_analyst(
    session_factory: async_sessionmaker[AsyncSession], investigation_id: UUID
) -> EvidenceAnalystAnalysisExecutor:
    llm = FakeLlmClient()
    llm.enqueue(
        EvidenceAnalystDecision(
            verdict=Verdict.SUSPICIOUS,
            confidence=AssessmentConfidence.MEDIUM,
            summary="Deterministic mandatory GEOINT analysis.",
            disposition=AnalysisDisposition.SUFFICIENT,
        )
    )
    return EvidenceAnalystAnalysisExecutor(
        _analyst_for(session_factory, llm), bound_investigation_id=investigation_id
    )


def _budget(**overrides: int) -> InvestigationBudget:
    params: dict[str, int] = {
        "max_depth": 2,
        "max_entities": 10,
        "max_provider_calls": 40,
        "max_replans": 3,
        "max_llm_calls": 10,
    }
    params.update(overrides)
    return InvestigationBudget(**params)


async def _seed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    root_type: EntityType,
    root_value: str,
    budget: InvestigationBudget,
    discovered: tuple[tuple[EntityType, str], ...] = (),
    analysis_disposition: AnalysisDisposition | None = None,
) -> tuple[InvestigationState, UUID, list[UUID]]:
    """Persist one RUNNING investigation and return its versioned state."""
    investigation_id = uuid4()
    root_id = uuid4()
    async with uow_factory() as uow:
        await uow.entities.upsert(Entity(id=root_id, type=root_type, value=root_value))
        discovered_entities = [
            await uow.entities.upsert(Entity(type=entity_type, value=value))
            for entity_type, value in discovered
        ]
        await uow.commit()
    async with uow_factory() as uow:
        persisted_root = await uow.entities.get_by_identity(root_type.value, root_value)
    assert persisted_root is not None and persisted_root.id is not None
    root_id = persisted_root.id
    discovered_ids = [
        entity.id for entity in discovered_entities if entity.id is not None
    ]
    traversal = [
        EntityTraversalState(
            entity_id=root_id, first_discovery_ordinal=0, minimum_depth=0
        )
    ]
    for ordinal, entity_id in enumerate(discovered_ids, start=1):
        traversal.append(
            EntityTraversalState(
                entity_id=entity_id,
                first_discovery_ordinal=ordinal,
                minimum_depth=1,
            )
        )
    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        discovered_entity_ids=discovered_ids,
        traversal=traversal,
        objective="Mandatory GEOINT enrichment vertical slice.",
        budget=budget,
        analysis_disposition=analysis_disposition,
        started_at=_FIXED_TS,
    )
    async with uow_factory() as uow:
        created = await uow.investigations.create(state)
        await uow.commit()
    state = state.model_copy(update={"version": created.version})
    return state, investigation_id, [root_id, *discovered_ids]


async def _run_graph(
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    investigation_id: UUID,
    state: InvestigationState,
    providers: Mapping[SourceId, EvidenceProvider],
    analysis_executor: object,
    recursion_limit: int = 200,
) -> InvestigationState:
    graph = build_provider_investigation_graph(
        uow_factory=uow_factory,
        provider_registry=dict(providers),
        context=ProviderExecutionContext(
            investigation_id=investigation_id, clock=lambda: _FIXED_TS
        ),
        analysis_executor=analysis_executor,  # type: ignore[arg-type]
    )
    final: InvestigationState | None = None
    async for snapshot in graph.astream(
        {"investigation": state},
        stream_mode="values",
        config={"recursion_limit": recursion_limit},
    ):
        candidate = snapshot.get("investigation")
        if isinstance(candidate, InvestigationState):
            final = candidate
    assert final is not None
    return final


async def _admissions(
    uow_factory: Callable[[], PostgresUnitOfWork], investigation_id: UUID
) -> list[InvestigationEvidence]:
    async with uow_factory() as uow:
        return await uow.investigation_evidence.list_for_investigation(investigation_id)


async def test_root_ip_zero_provider_budget_enriched_and_resolution_pending(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I35-4-01/B03/C07/G01-G03: root IP enriched with zero provider budget."""
    state, investigation_id, ids = await _seed(
        uow_factory,
        root_type=EntityType.IP_ADDRESS,
        root_value=_DALLAS_IP,
        budget=_budget(max_provider_calls=0),
    )
    root_id = ids[0]
    final = await _run_graph(
        uow_factory,
        investigation_id=investigation_id,
        state=state,
        providers={SourceId.DBIP_CITY_LITE: _dbip_provider(_catalog())},
        analysis_executor=_sufficient_analyst(session_factory, investigation_id),
    )

    item = MandatoryEnrichmentWorkItem(
        provider=SourceId.DBIP_CITY_LITE, entity_id=root_id
    )
    assert final.completed_mandatory_enrichment == [item]
    assert final.budget.provider_calls_used == 0
    assert final.pending_pivots == []
    assert final.investigated_entity_ids == []
    assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value

    admissions = await _admissions(uow_factory, investigation_id)
    assert len(admissions) == 1
    observation_id = admissions[0].evidence_observation_id
    async with uow_factory() as uow:
        entities = await uow.evidence_observation_entities.list_for_observation(
            observation_id
        )
        assert {entry.entity_id for entry in entities} == {root_id}
        resolution = await uow.geo_resolutions.get_by_entity_evidence(
            root_id, observation_id
        )
        assert resolution is not None
        assert resolution.status is GeoResolutionStatus.PENDING


async def test_discovered_ip_beyond_capacity_enriched_with_exhausted_budget(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I35-4-02/03/B10/C08/M13: a durable discovery beyond capacity is enriched."""
    state, investigation_id, ids = await _seed(
        uow_factory,
        root_type=EntityType.DOMAIN,
        root_value=_DOMAIN,
        budget=_budget(max_provider_calls=1, provider_calls_used=1, max_entities=1),
        discovered=((EntityType.IP_ADDRESS, _DALLAS_IP),),
    )
    discovered_id = ids[1]
    final = await _run_graph(
        uow_factory,
        investigation_id=investigation_id,
        state=state,
        providers={SourceId.DBIP_CITY_LITE: _dbip_provider(_catalog())},
        analysis_executor=_sufficient_analyst(session_factory, investigation_id),
    )

    item = MandatoryEnrichmentWorkItem(
        provider=SourceId.DBIP_CITY_LITE, entity_id=discovered_id
    )
    assert final.completed_mandatory_enrichment == [item]
    assert final.budget.provider_calls_used == 1
    assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value

    admissions = await _admissions(uow_factory, investigation_id)
    assert len(admissions) == 1
    observation_id = admissions[0].evidence_observation_id
    async with uow_factory() as uow:
        entities = await uow.evidence_observation_entities.list_for_observation(
            observation_id
        )
        assert {entry.entity_id for entry in entities} == {discovered_id}


async def test_domain_discovery_triggers_mandatory_ip_enrichment(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I35-4-02/C13: a provider-discovered IP is mandatorily enriched."""
    state, investigation_id, _ = await _seed(
        uow_factory,
        root_type=EntityType.DOMAIN,
        root_value="update-package.test",
        budget=_budget(max_provider_calls=1, max_entities=1),
    )
    catalog = _catalog()
    dns = FakeWorldEvidenceProvider(
        SourceId.GOOGLE_PUBLIC_DNS, catalog, clock=lambda: _FIXED_TS
    )
    final = await _run_graph(
        uow_factory,
        investigation_id=investigation_id,
        state=state,
        providers={
            SourceId.GOOGLE_PUBLIC_DNS: dns,
            SourceId.DBIP_CITY_LITE: _dbip_provider(catalog),
        },
        analysis_executor=_sufficient_analyst(session_factory, investigation_id),
    )

    # The ordinary DNS provider consumed exactly one provider call; the
    # mandatory DB-IP enrichment remains outside the investigative budget.
    assert final.budget.provider_calls_used == 1
    ip_items = [
        item
        for item in final.completed_mandatory_enrichment
        if item.provider is SourceId.DBIP_CITY_LITE
    ]
    assert len(ip_items) == 1
    assert ip_items[0].entity_id in final.discovered_entity_ids
    assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value

    # The discovered IP's GEOLOCATION observation is admitted with the IP
    # associated even though mandatory (not pivot) work caused the call.
    admissions = await _admissions(uow_factory, investigation_id)
    assert len(admissions) >= 1
    async with uow_factory() as uow:
        associated: set[UUID] = set()
        for admission in admissions:
            entities = await uow.evidence_observation_entities.list_for_observation(
                admission.evidence_observation_id
            )
            associated.update(entry.entity_id for entry in entities)
        assert ip_items[0].entity_id in associated


async def test_dbip_miss_completes_without_fabrication(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """I35-4-06/G08: a miss is a bounded completed attempt with no location."""
    from agentic_threat_investigator.app.orchestration.coordinator import (
        FakeAnalysisExecutor,
    )

    state, investigation_id, ids = await _seed(
        uow_factory,
        root_type=EntityType.IP_ADDRESS,
        root_value=_MISS_IP,
        budget=_budget(max_provider_calls=0),
        analysis_disposition=AnalysisDisposition.SUFFICIENT,
    )
    final = await _run_graph(
        uow_factory,
        investigation_id=investigation_id,
        state=state,
        providers={SourceId.DBIP_CITY_LITE: _dbip_provider(_catalog())},
        analysis_executor=FakeAnalysisExecutor(
            (), bound_investigation_id=investigation_id
        ),
    )
    assert final.last_mandatory_enrichment_outcome is not None
    assert (
        final.last_mandatory_enrichment_outcome.status
        is ProviderExecutionStatus.SUCCEEDED
    )
    assert final.completed_mandatory_enrichment == [
        MandatoryEnrichmentWorkItem(provider=SourceId.DBIP_CITY_LITE, entity_id=ids[0])
    ]
    assert final.budget.provider_calls_used == 0
    assert await _admissions(uow_factory, investigation_id) == []


async def test_dbip_typed_failure_completes_bounded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """I35-4-06/G09: a typed provider failure is recorded once, without retry."""
    from agentic_threat_investigator.app.orchestration.coordinator import (
        FakeAnalysisExecutor,
    )

    state, investigation_id, ids = await _seed(
        uow_factory,
        root_type=EntityType.IP_ADDRESS,
        root_value=_DALLAS_IP,
        budget=_budget(max_provider_calls=0),
        analysis_disposition=AnalysisDisposition.SUFFICIENT,
    )
    final = await _run_graph(
        uow_factory,
        investigation_id=investigation_id,
        state=state,
        providers={SourceId.DBIP_CITY_LITE: _dbip_provider(_catalog(), failing=True)},
        analysis_executor=FakeAnalysisExecutor(
            (), bound_investigation_id=investigation_id
        ),
    )
    outcome = final.last_mandatory_enrichment_outcome
    assert outcome is not None
    assert outcome.status is ProviderExecutionStatus.FAILED
    assert outcome.error is not None
    assert outcome.error.code == ProviderErrorCode.PROVIDER_UNAVAILABLE.value
    assert len(final.completed_mandatory_enrichment) == 1
    assert final.budget.provider_calls_used == 0
    assert await _admissions(uow_factory, investigation_id) == []


async def test_sql_rejects_provider_counter_mutation_on_mandatory_transition(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """B08: SQL independently rejects provider-counter mutation on scheduling."""
    state, investigation_id, ids = await _seed(
        uow_factory,
        root_type=EntityType.IP_ADDRESS,
        root_value=_DALLAS_IP,
        budget=_budget(),
    )
    item = MandatoryEnrichmentWorkItem(
        provider=SourceId.DBIP_CITY_LITE, entity_id=ids[0]
    )
    scheduled = schedule_mandatory_enrichment(state, [item])
    tampered = scheduled.model_copy(
        update={
            "budget": scheduled.budget.model_copy(update={"provider_calls_used": 1})
        }
    )
    with pytest.raises(CoordinatorTransitionPersistenceError):
        async with uow_factory() as uow:
            await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.SCHEDULE_MANDATORY_ENRICHMENT,
                tampered,
                expected_version=state.version or 1,
            )
            await uow.commit()


async def test_sql_rejects_replan_and_llm_counter_mutation_on_mandatory_transition(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """B06/B07: SQL rejects replan/LLM counter mutation on mandatory work."""
    state, investigation_id, ids = await _seed(
        uow_factory,
        root_type=EntityType.IP_ADDRESS,
        root_value=_DALLAS_IP,
        budget=_budget(),
    )
    item = MandatoryEnrichmentWorkItem(
        provider=SourceId.DBIP_CITY_LITE, entity_id=ids[0]
    )
    scheduled = schedule_mandatory_enrichment(state, [item])
    for mutation in ({"replans_used": 1}, {"llm_calls_used": 1}):
        tampered = scheduled.model_copy(
            update={"budget": scheduled.budget.model_copy(update=mutation)}
        )
        with pytest.raises(CoordinatorTransitionPersistenceError):
            async with uow_factory() as uow:
                await uow.investigations.update_coordinator_state(
                    investigation_id,
                    CoordinatorTransitionKind.SCHEDULE_MANDATORY_ENRICHMENT,
                    tampered,
                    expected_version=state.version or 1,
                )
                await uow.commit()


async def test_sql_rejects_mandatory_finalize_with_due_work(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A non-fatal stop cannot finalize while mandatory work remains queued."""
    state, investigation_id, ids = await _seed(
        uow_factory,
        root_type=EntityType.IP_ADDRESS,
        root_value=_DALLAS_IP,
        budget=_budget(),
    )
    item = MandatoryEnrichmentWorkItem(
        provider=SourceId.DBIP_CITY_LITE, entity_id=ids[0]
    )
    scheduled = schedule_mandatory_enrichment(state, [item]).model_copy(
        update={
            "status": InvestigationStatus.COMPLETED,
            "stop_reason": StopReason.SUFFICIENT_EVIDENCE.value,
        }
    )
    with pytest.raises(CoordinatorTransitionPersistenceError):
        async with uow_factory() as uow:
            await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.FINALIZE_STOP,
                scheduled,
                expected_version=state.version or 1,
            )
            await uow.commit()
