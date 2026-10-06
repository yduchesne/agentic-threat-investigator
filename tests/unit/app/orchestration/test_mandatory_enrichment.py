# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Mandatory GEOINT enrichment policy, planning, and bookkeeping unit tests.

Covers the PR 35-4 domain/state matrix (M01-M17) and the coordinator policy
priority matrix (C01-C18) at the pure/application layer. Mandatory
enrichment is scheduled from durable Investigation membership, never from
pivot authorization, depth, or the investigative provider budget.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.orchestration.composition import (
    RegistryMandatoryEnrichmentPlanner,
    RegistryProviderWorkPlanner,
)
from agentic_threat_investigator.app.orchestration.coordinator import (
    CoordinatorAction,
    CoordinatorEntityView,
    CoordinatorPolicy,
    CoordinatorPolicyContext,
    MappingProviderWorkPlanner,
)
from agentic_threat_investigator.app.orchestration.models import (
    record_mandatory_enrichment_outcome,
    schedule_mandatory_enrichment,
    select_mandatory_enrichment,
)
from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderExecutionPolicy,
    ProviderResult,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    InvestigationBudget,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    MandatoryEnrichmentOutcome,
    MandatoryEnrichmentWorkItem,
    ProviderExecutionStatus,
)

_INVESTIGATION = UUID("00000000-0000-0000-0000-0000000000f1")
_ROOT_IP = UUID("00000000-0000-0000-0000-0000000000f2")
_DISCOVERED_IP = UUID("00000000-0000-0000-0000-0000000000f3")
_ROOT_DOMAIN = UUID("00000000-0000-0000-0000-0000000000f4")
_MISSING_IP = UUID("00000000-0000-0000-0000-0000000000f5")
_FIXED_TS = datetime(2026, 1, 1, tzinfo=UTC)


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


def _state(**overrides: Any) -> InvestigationState:
    params: dict[str, Any] = {
        "investigation_id": _INVESTIGATION,
        "status": InvestigationStatus.RUNNING,
        "trigger_type": InvestigationTriggerType.MANUAL,
        "root_entity_ids": [_ROOT_IP],
        "objective": "Test mandatory enrichment",
        "budget": _budget(),
        "started_at": _FIXED_TS,
        "version": 1,
    }
    params.update(overrides)
    if "traversal" not in params:
        traversal: list[dict[str, Any]] = []
        ordinal = 0
        for entity_id in params.get("root_entity_ids", []):
            traversal.append(
                {
                    "entity_id": entity_id,
                    "first_discovery_ordinal": ordinal,
                    "minimum_depth": 0,
                }
            )
            ordinal += 1
        for entry in params.get("discovered_entity_ids", []):
            traversal.append(
                {
                    "entity_id": entry,
                    "first_discovery_ordinal": ordinal,
                    "minimum_depth": 1,
                }
            )
            ordinal += 1
        params["traversal"] = traversal
    return InvestigationState.model_validate(params)


class _Provider(EvidenceProvider):
    """Deterministic provider double with configurable policy/applicability."""

    def __init__(
        self,
        source: SourceId,
        supported: frozenset[EntityType],
        *,
        policy: ProviderExecutionPolicy = (ProviderExecutionPolicy.INVESTIGATIVE),
        provider_id: str | None = None,
    ) -> None:
        self._source = source
        self._supported = supported
        self._policy = policy
        self._provider_id = provider_id or source.value

    @property
    def id(self) -> str:
        return self._provider_id

    @property
    def execution_policy(self) -> ProviderExecutionPolicy:
        return self._policy

    def supports(self, entity: Entity) -> bool:
        return entity.type in self._supported

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:  # pragma: no cover - not exercised here
        return ProviderResult(provider=self.id)


def _mandatory_provider(**kwargs: Any) -> _Provider:
    return _Provider(
        SourceId.DBIP_CITY_LITE,
        frozenset({EntityType.IP_ADDRESS}),
        policy=ProviderExecutionPolicy.MANDATORY_GEOINT,
        **kwargs,
    )


def _entity_view(
    entity_id: UUID, entity_type: EntityType, value: str, *, deleted: bool = False
) -> CoordinatorEntityView:
    return CoordinatorEntityView(
        entity_id=entity_id, entity_type=entity_type, value=value, deleted=deleted
    )


def _context(
    *views: CoordinatorEntityView, missing: tuple[UUID, ...] = ()
) -> CoordinatorPolicyContext:
    return CoordinatorPolicyContext(entities=tuple(views), missing_entity_ids=missing)


class TestMandatoryWorkIdentity:
    """M01: depth-free logical work identity."""

    def test_identity_has_no_depth(self) -> None:
        item = MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
        )
        assert set(item.model_dump()) == {"provider", "entity_id"}
        assert item == MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
        )
        assert (
            len(
                {
                    item,
                    MandatoryEnrichmentWorkItem(
                        provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
                    ),
                }
            )
            == 1
        )

    def test_unexpected_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MandatoryEnrichmentWorkItem(
                provider=SourceId.DBIP_CITY_LITE,
                entity_id=_ROOT_IP,
                depth=0,  # type: ignore[call-arg]
            )


class TestMandatoryBookkeeping:
    """M02-M07, B03-B07: durable deduplication and budget neutrality."""

    def test_schedule_deduplicates_pending_current_completed(self) -> None:
        item = MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
        )
        state = _state()
        state = schedule_mandatory_enrichment(state, [item])
        state = schedule_mandatory_enrichment(state, [item])
        assert state.pending_mandatory_enrichment == [item]

        # Already current: not duplicated.
        selected = select_mandatory_enrichment(state)
        assert selected.current_mandatory_enrichment == item
        resent = schedule_mandatory_enrichment(selected, [item])
        assert resent.pending_mandatory_enrichment == [item]

        # Already completed: not re-enqueued.
        outcome = MandatoryEnrichmentOutcome(
            work_item=item,
            status=ProviderExecutionStatus.SUCCEEDED,
            evidence_ids=(UUID(int=1),),
        )
        recorded = record_mandatory_enrichment_outcome(selected, outcome)
        assert recorded.completed_mandatory_enrichment == [item]
        assert recorded.current_mandatory_enrichment is None
        assert recorded.pending_mandatory_enrichment == []
        assert recorded.evidence_ids == [UUID(int=1)]
        assert recorded.budget.provider_calls_used == 0
        rescheduled = schedule_mandatory_enrichment(recorded, [item])
        assert rescheduled.pending_mandatory_enrichment == []

    def test_miss_and_failure_complete_without_retry(self) -> None:
        item = MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
        )
        state = select_mandatory_enrichment(
            schedule_mandatory_enrichment(_state(), [item])
        )
        miss = MandatoryEnrichmentOutcome(
            work_item=item, status=ProviderExecutionStatus.SUCCEEDED
        )
        failed = MandatoryEnrichmentOutcome(
            work_item=item,
            status=ProviderExecutionStatus.FAILED,
            error=None,
        )
        for outcome in (miss, failed):
            recorded = record_mandatory_enrichment_outcome(state, outcome)
            assert recorded.completed_mandatory_enrichment == [item]
            assert recorded.current_mandatory_enrichment is None
            assert recorded.budget.provider_calls_used == 0
            # No automatic infinite retry: the same identity never re-enqueues.
            rescheduled = schedule_mandatory_enrichment(recorded, [item])
            assert rescheduled.pending_mandatory_enrichment == []

    def test_select_is_idempotent_and_fifo(self) -> None:
        first = MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
        )
        second = MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_DISCOVERED_IP
        )
        state = schedule_mandatory_enrichment(_state(), [first, second])
        selected = select_mandatory_enrichment(state)
        assert selected.current_mandatory_enrichment == first
        again = select_mandatory_enrichment(selected)
        assert again.current_mandatory_enrichment == first

    def test_record_requires_current_match(self) -> None:
        item = MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
        )
        outcome = MandatoryEnrichmentOutcome(
            work_item=item, status=ProviderExecutionStatus.SUCCEEDED
        )
        with pytest.raises(ValueError):
            record_mandatory_enrichment_outcome(_state(), outcome)


class TestMandatoryPlanner:
    """M08-M15, C12-C14, M17: deterministic membership/applicability planning."""

    def _planner(
        self, registry: dict[SourceId, EvidenceProvider]
    ) -> RegistryMandatoryEnrichmentPlanner:
        return RegistryMandatoryEnrichmentPlanner(registry)

    def test_applicable_root_and_discovery_scheduled_in_order(self) -> None:
        planner = self._planner({SourceId.DBIP_CITY_LITE: _mandatory_provider()})
        state = _state(
            root_entity_ids=[_ROOT_IP],
            discovered_entity_ids=[_DISCOVERED_IP],
        )
        context = _context(
            _entity_view(_ROOT_IP, EntityType.IP_ADDRESS, "203.0.113.10"),
            _entity_view(_DISCOVERED_IP, EntityType.IP_ADDRESS, "203.0.113.11"),
        )
        due = planner.plan(state=state, context=context)
        assert due == (
            MandatoryEnrichmentWorkItem(
                provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
            ),
            MandatoryEnrichmentWorkItem(
                provider=SourceId.DBIP_CITY_LITE, entity_id=_DISCOVERED_IP
            ),
        )

    def test_discovery_beyond_entity_budget_still_scheduled(self) -> None:
        planner = self._planner({SourceId.DBIP_CITY_LITE: _mandatory_provider()})
        state = _state(
            root_entity_ids=[_ROOT_DOMAIN],
            discovered_entity_ids=[_DISCOVERED_IP],
            budget=_budget(max_entities=0),
        )
        context = _context(
            _entity_view(_ROOT_DOMAIN, EntityType.DOMAIN, "example.test"),
            _entity_view(_DISCOVERED_IP, EntityType.IP_ADDRESS, "203.0.113.11"),
        )
        due = planner.plan(state=state, context=context)
        assert due == (
            MandatoryEnrichmentWorkItem(
                provider=SourceId.DBIP_CITY_LITE, entity_id=_DISCOVERED_IP
            ),
        )

    def test_deleted_missing_and_unsupported_not_scheduled(self) -> None:
        planner = self._planner({SourceId.DBIP_CITY_LITE: _mandatory_provider()})
        state = _state(
            root_entity_ids=[_ROOT_IP, _ROOT_DOMAIN],
            discovered_entity_ids=[_DISCOVERED_IP],
        )
        context = _context(
            _entity_view(_ROOT_IP, EntityType.IP_ADDRESS, "203.0.113.10"),
            _entity_view(_ROOT_DOMAIN, EntityType.DOMAIN, "example.test"),
            _entity_view(
                _DISCOVERED_IP, EntityType.IP_ADDRESS, "203.0.113.11", deleted=True
            ),
            missing=(_MISSING_IP,),
        )
        due = planner.plan(state=state, context=context)
        assert due == (
            MandatoryEnrichmentWorkItem(
                provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
            ),
        )

    def test_registry_identity_mismatch_not_scheduled(self) -> None:
        planner = self._planner(
            {
                SourceId.DBIP_CITY_LITE: _mandatory_provider(
                    provider_id=SourceId.RDAP.value
                )
            }
        )
        context = _context(
            _entity_view(_ROOT_IP, EntityType.IP_ADDRESS, "203.0.113.10")
        )
        assert planner.plan(state=_state(), context=context) == ()

    def test_absent_mandatory_provider_produces_no_work(self) -> None:
        planner = self._planner(
            {
                SourceId.RDAP: _Provider(
                    SourceId.RDAP, frozenset({EntityType.IP_ADDRESS})
                )
            }
        )
        context = _context(
            _entity_view(_ROOT_IP, EntityType.IP_ADDRESS, "203.0.113.10")
        )
        assert planner.plan(state=_state(), context=context) == ()

    def test_mandatory_only_provider_excluded_from_ordinary_planning(self) -> None:
        registry: dict[SourceId, EvidenceProvider] = {
            SourceId.DBIP_CITY_LITE: _mandatory_provider(),
            SourceId.RDAP: _Provider(SourceId.RDAP, frozenset({EntityType.IP_ADDRESS})),
        }
        ordinary = RegistryProviderWorkPlanner(registry).plan(
            entity=_entity_view(_ROOT_IP, EntityType.IP_ADDRESS, "203.0.113.10"),
            depth=0,
            state=_state(),
        )
        assert [item.provider for item in ordinary] == [SourceId.RDAP]

    def test_same_entity_rediscovered_is_one_attempt(self) -> None:
        planner = self._planner({SourceId.DBIP_CITY_LITE: _mandatory_provider()})
        item = MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
        )
        context = _context(
            _entity_view(_ROOT_IP, EntityType.IP_ADDRESS, "203.0.113.10")
        )
        state = _state()
        first = planner.plan(state=state, context=context)
        state = schedule_mandatory_enrichment(state, list(first))
        assert planner.plan(state=state, context=context) == ()
        assert state.pending_mandatory_enrichment == [item]


class TestCoordinatorMandatoryPriority:
    """C02, C06, C07, C12, C16: mandatory work precedes every stop/budget rule."""

    def _policy(self) -> CoordinatorPolicy:
        planner = RegistryMandatoryEnrichmentPlanner(
            {SourceId.DBIP_CITY_LITE: _mandatory_provider()}
        )
        return CoordinatorPolicy(
            MappingProviderWorkPlanner({}),
            mandatory_planner=planner,
        )

    def test_sufficient_disposition_cannot_skip_due_mandatory(self) -> None:
        state = _state(analysis_disposition=AnalysisDisposition.SUFFICIENT)
        context = CoordinatorPolicyContext(
            entities=(_entity_view(_ROOT_IP, EntityType.IP_ADDRESS, "203.0.113.10"),),
            analysis_disposition=AnalysisDisposition.SUFFICIENT,
        )
        decision = self._policy().decide(state=state, context=context)
        assert decision.action is CoordinatorAction.SCHEDULE_MANDATORY_ENRICHMENT
        assert decision.mandatory_work_items == (
            MandatoryEnrichmentWorkItem(
                provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
            ),
        )

    def test_zero_provider_budget_still_schedules_mandatory(self) -> None:
        state = _state(budget=_budget(max_provider_calls=0))
        context = _context(
            _entity_view(_ROOT_IP, EntityType.IP_ADDRESS, "203.0.113.10")
        )
        decision = self._policy().decide(state=state, context=context)
        assert decision.action is CoordinatorAction.SCHEDULE_MANDATORY_ENRICHMENT

    def test_exhausted_provider_budget_still_schedules_mandatory(self) -> None:
        state = _state(budget=_budget(max_provider_calls=1, provider_calls_used=1))
        context = _context(
            _entity_view(_ROOT_IP, EntityType.IP_ADDRESS, "203.0.113.10")
        )
        decision = self._policy().decide(state=state, context=context)
        assert decision.action is CoordinatorAction.SCHEDULE_MANDATORY_ENRICHMENT

    def test_pending_mandatory_selects_before_ordinary_work(self) -> None:
        item = MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
        )
        state = schedule_mandatory_enrichment(
            _state(analysis_disposition=AnalysisDisposition.SUFFICIENT), [item]
        )
        context = CoordinatorPolicyContext(
            analysis_disposition=AnalysisDisposition.SUFFICIENT
        )
        decision = self._policy().decide(state=state, context=context)
        assert decision.action is CoordinatorAction.SELECT_MANDATORY_ENRICHMENT

    def test_domain_only_has_no_mandatory_work(self) -> None:
        state = _state(root_entity_ids=[_ROOT_DOMAIN])
        context = _context(
            _entity_view(_ROOT_DOMAIN, EntityType.DOMAIN, "example.test")
        )
        decision = self._policy().decide(state=state, context=context)
        assert decision.action is not CoordinatorAction.SCHEDULE_MANDATORY_ENRICHMENT
