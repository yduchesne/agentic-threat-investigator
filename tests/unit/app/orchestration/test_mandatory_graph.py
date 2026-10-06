# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Mandatory GEOINT enrichment coordinator-graph routing tests (PR 35-4).

Proves the graph schedules, selects, executes, and durably records mandatory
enrichment through a dedicated route that never consumes the investigative
provider budget, never creates a pivot, and cannot be skipped by a terminal
``SUFFICIENT`` disposition with no ordinary provider work.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.app.orchestration.composition import (
    RegistryMandatoryEnrichmentPlanner,
)
from agentic_threat_investigator.app.orchestration.coordinator import (
    CoordinatorEntityView,
    CoordinatorPolicy,
    CoordinatorPolicyContext,
    FakeAnalysisExecutor,
    MappingProviderWorkPlanner,
)
from agentic_threat_investigator.app.orchestration.graph import (
    build_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    MandatoryEnrichmentExecutor,
)
from agentic_threat_investigator.app.orchestration.services import (
    CoordinatorContextLoader,
    CoordinatorTransitionService,
    FatalStopService,
    InvestigationStatusWriter,
)
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    DeterministicTimelineActionService,
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
    InvestigationError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    MandatoryEnrichmentOutcome,
    MandatoryEnrichmentWorkItem,
    ProviderExecutionStatus,
    StopReason,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)
from tests.support.orchestration_fixtures import FakeTaskDispatcher

_INVESTIGATION = UUID("00000000-0000-0000-0000-0000000000e1")
_ROOT_IP = UUID("00000000-0000-0000-0000-0000000000e2")
_EVIDENCE = UUID("00000000-0000-0000-0000-0000000000e3")
_FIXED_TS = datetime(2026, 1, 1, tzinfo=UTC)


class _MandatoryProvider(EvidenceProvider):
    def __init__(self) -> None:
        self._source = SourceId.DBIP_CITY_LITE

    @property
    def id(self) -> str:
        return self._source.value

    @property
    def execution_policy(self) -> ProviderExecutionPolicy:
        return ProviderExecutionPolicy.MANDATORY_GEOINT

    def supports(self, entity: Entity) -> bool:
        return entity.type is EntityType.IP_ADDRESS

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:  # pragma: no cover - kernel not used in this test
        return ProviderResult(provider=self.id)


class _FakeMandatoryExecutor(MandatoryEnrichmentExecutor):
    def __init__(self, *, with_evidence: bool = False) -> None:
        self.requested: list[MandatoryEnrichmentWorkItem] = []
        self._with_evidence = with_evidence

    async def execute(
        self, work_item: MandatoryEnrichmentWorkItem
    ) -> MandatoryEnrichmentOutcome:
        self.requested.append(work_item)
        return MandatoryEnrichmentOutcome(
            work_item=work_item,
            status=ProviderExecutionStatus.SUCCEEDED,
            evidence_ids=(_EVIDENCE,) if self._with_evidence else (),
        )


class _ContextLoader(CoordinatorContextLoader):
    async def load(
        self, investigation_id: UUID, expected_version: int
    ) -> CoordinatorPolicyContext:
        del investigation_id, expected_version
        return CoordinatorPolicyContext(
            entities=(
                CoordinatorEntityView(
                    entity_id=_ROOT_IP,
                    entity_type=EntityType.IP_ADDRESS,
                    value="203.0.113.10",
                ),
            ),
            analysis_disposition=AnalysisDisposition.SUFFICIENT,
        )


class _TransitionService(CoordinatorTransitionService):
    def __init__(self) -> None:
        self.kinds: list[object] = []
        self.events: list[InvestigationTimelineEvent] = []
        self._last: InvestigationState | None = None

    async def persist(
        self,
        investigation_id: UUID,
        transition_kind: object,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
        events: tuple[InvestigationTimelineEvent, ...] = (),
        consumes_replan: bool = False,
    ) -> InvestigationState:
        del actor_id, request_id, expected_version, consumes_replan
        self.kinds.append(transition_kind)
        self.events.extend(events)
        self._last = state
        return state

    async def reload(self, investigation_id: UUID) -> InvestigationState:
        if self._last is None:
            raise AssertionError("reload before any persisted state")
        return self._last

    async def emit(self, event: InvestigationTimelineEvent) -> None:
        self.events.append(event)


class _StatusWriter(InvestigationStatusWriter):
    def __init__(self) -> None:
        self.stop_reasons: list[StopReason] = []

    async def finalize(
        self,
        investigation_id: UUID,
        stop_reason: StopReason,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
        events: tuple[InvestigationTimelineEvent, ...] = (),
    ) -> InvestigationState:
        del investigation_id, actor_id, request_id, expected_version, events
        self.stop_reasons.append(stop_reason)
        return state


class _FatalStop(FatalStopService):
    def __init__(self) -> None:
        self.errors: list[InvestigationError] = []

    async def fatalize(
        self,
        investigation_id: UUID,
        error: InvestigationError,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationState:
        del investigation_id, actor_id, request_id, expected_version
        self.errors.append(error)
        return _state(
            status=InvestigationStatus.FAILED,
            stop_reason=StopReason.FATAL_ERROR.value,
            errors=[error],
        )


def _state(**overrides: Any) -> InvestigationState:
    params: dict[str, Any] = {
        "investigation_id": _INVESTIGATION,
        "status": InvestigationStatus.RUNNING,
        "trigger_type": InvestigationTriggerType.MANUAL,
        "root_entity_ids": [_ROOT_IP],
        "objective": "Mandatory enrichment graph test",
        "budget": default_investigation_budget(),
        "started_at": _FIXED_TS,
        "version": 1,
        "analysis_disposition": AnalysisDisposition.SUFFICIENT,
    }
    params.update(overrides)
    return InvestigationState.model_validate(params)


def _build(
    executor: _FakeMandatoryExecutor,
    transition: _TransitionService,
    status_writer: _StatusWriter,
    analysis_executor: FakeAnalysisExecutor | None = None,
    fatal: _FatalStop | None = None,
) -> Any:
    policy = CoordinatorPolicy(
        MappingProviderWorkPlanner({}),
        mandatory_planner=RegistryMandatoryEnrichmentPlanner(
            {SourceId.DBIP_CITY_LITE: _MandatoryProvider()}
        ),
    )
    return build_investigation_graph(
        FakeTaskDispatcher({}),
        coordinator_policy=policy,
        context_loader=_ContextLoader(),
        analysis_executor=analysis_executor
        or FakeAnalysisExecutor((), bound_investigation_id=_INVESTIGATION),
        transition_service=transition,
        status_writer=status_writer,
        timeline_action_service=DeterministicTimelineActionService(),
        fatal_stop_service=fatal or _FatalStop(),
        mandatory_executor=executor,
        expected_investigation_id=_INVESTIGATION,
    )


@pytest.mark.asyncio
async def test_root_ip_enriched_with_zero_provider_budget() -> None:
    """A root IP is mandatorily enriched without consuming provider budget."""
    executor = _FakeMandatoryExecutor()
    transition = _TransitionService()
    status_writer = _StatusWriter()
    graph = _build(executor, transition, status_writer)
    result = await graph.ainvoke({"investigation": _state()})
    state = result["investigation"]

    item = MandatoryEnrichmentWorkItem(
        provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
    )
    assert executor.requested == [item]
    assert state.completed_mandatory_enrichment == [item]
    assert state.pending_mandatory_enrichment == []
    assert state.current_mandatory_enrichment is None
    assert state.budget.provider_calls_used == 0
    assert state.pending_pivots == []
    assert state.investigated_entity_ids == []
    assert state.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
    assert status_writer.stop_reasons == [StopReason.SUFFICIENT_EVIDENCE]


@pytest.mark.asyncio
async def test_mandatory_evidence_defers_terminal_stop_to_analysis() -> None:
    """Mandatory Evidence triggers the normal analysis sync before stop."""
    executor = _FakeMandatoryExecutor(with_evidence=True)
    transition = _TransitionService()
    status_writer = _StatusWriter()
    analyst = FakeAnalysisExecutor((), bound_investigation_id=_INVESTIGATION)
    graph = _build(executor, transition, status_writer, analyst)
    result = await graph.ainvoke({"investigation": _state()})

    # The mandatory GEOLOCATION Evidence is ordinary Investigation Evidence:
    # the coordinator requests analysis before any terminal disposition.
    assert analyst.called_with == [_INVESTIGATION]
    assert executor.requested == [
        MandatoryEnrichmentWorkItem(
            provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
        )
    ]
    assert result["investigation"].status is InvestigationStatus.FAILED


@pytest.mark.asyncio
async def test_persisted_current_mandatory_item_fails_closed_without_reissue() -> None:
    """A crash-resumed current mandatory item fatalizes; no provider reissue."""
    item = MandatoryEnrichmentWorkItem(
        provider=SourceId.DBIP_CITY_LITE, entity_id=_ROOT_IP
    )
    executor = _FakeMandatoryExecutor()
    transition = _TransitionService()
    status_writer = _StatusWriter()
    fatal = _FatalStop()
    graph = _build(executor, transition, status_writer, fatal=fatal)
    result = await graph.ainvoke(
        {"investigation": _state(current_mandatory_enrichment=item)}
    )
    assert executor.requested == []
    assert [error.code for error in fatal.errors] == [
        "persisted_mandatory_enrichment_resume"
    ]
    assert result["investigation"].status is InvestigationStatus.FAILED
