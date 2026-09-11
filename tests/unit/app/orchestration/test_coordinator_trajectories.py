# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Layered deterministic coordinator graph trajectories (Phase 8.2).

Runs the real coordinator graph topology with fake services and a fake
dispatcher, asserting each documented trajectory terminates within an
explicit transition bound: no-eligible-pivot stop, unchanged-evidence
analysis suppression, cycle suppression, invented-target rejection, budget
stops, and persisted-work resume fatal handling.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.app.orchestration.coordinator import (
    AnalysisExecutor,
    AnalysisOutcome,
    CoordinatorAction,
    CoordinatorEntityView,
    CoordinatorPolicy,
    CoordinatorPolicyContext,
    FakeAnalysisExecutor,
    MappingProviderWorkPlanner,
)
from agentic_threat_investigator.app.orchestration.graph import (
    build_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.models import (
    enqueue_provider_work,
    select_provider_work,
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
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    CoordinatorTransitionKind,
    EntityTraversalState,
    InvestigationError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    ProviderExecutionOutcome,
    ProviderExecutionStatus,
    ProviderWorkItem,
    StopReason,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)
from agentic_threat_investigator.evaluation.coordinator import (
    load_coordinator_scenarios_directory,
)
from agentic_threat_investigator.evaluation.scenario_fixtures import (
    CoordinatorScenarioMaterializer,
    resolve_coordinator_scenario,
)
from tests.support.orchestration_fixtures import (
    FakeTaskDispatcher,
    scenario_dns_outcome,
    scenario_dns_work_item,
)

_ROOT = UUID("00000000-0000-0000-0000-0000000000a1")
_IP = UUID("00000000-0000-0000-0000-0000000000a2")
_E1 = UUID("00000000-0000-0000-0000-0000000000e1")
_E2 = UUID("00000000-0000-0000-0000-0000000000e2")

_MAX_TRANSITIONS = 30


class _StateTransitionService(CoordinatorTransitionService):
    """Echo the supplied state back with a monotonically increasing version."""

    def __init__(self) -> None:
        self._version = 1
        self.persisted_kinds: list[str] = []
        self._last: InvestigationState | None = None
        self.appended: list[InvestigationTimelineEvent] = []
        self.observed_transitions = 0

    async def persist(
        self,
        investigation_id: UUID,
        transition_kind: CoordinatorTransitionKind,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        events: tuple[InvestigationTimelineEvent, ...] = (),
        consumes_replan: bool = False,
    ) -> InvestigationState:
        del actor_id, request_id, expected_version, consumes_replan
        self.persisted_kinds.append(transition_kind.value)
        self.appended.extend(events)
        self._version += 1
        self._last = state.model_copy(update={"version": self._version})
        return self._last

    async def reload(self, investigation_id: UUID) -> InvestigationState:
        del investigation_id
        if self._last is None:
            raise LookupError("no persisted state")
        return self._last

    async def emit(self, event: InvestigationTimelineEvent) -> None:
        self.appended.append(event)


class _StatusWriter(InvestigationStatusWriter):
    """Echo the terminal state with a bumped version."""

    def __init__(self, service: _StateTransitionService) -> None:
        self._service = service

    async def finalize(
        self,
        investigation_id: UUID,
        stop_reason: StopReason,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        events: tuple[InvestigationTimelineEvent, ...] = (),
    ) -> InvestigationState:
        del actor_id, request_id
        self._service.appended.extend(events)
        self._service._version += 1
        return state.model_copy(
            update={
                "version": self._service._version,
                "completed_at": datetime.now(UTC),
            }
        )


class _RecordingFatalService(FatalStopService):
    """Record fatal stops without persisting."""

    def __init__(self) -> None:
        self.fatalized: list[tuple[UUID, InvestigationError]] = []

    async def fatalize(
        self,
        investigation_id: UUID,
        error: InvestigationError,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationState:
        del actor_id, request_id
        self.fatalized.append((investigation_id, error))
        return InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.FAILED,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[_ROOT],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            stop_reason=StopReason.FATAL_ERROR.value,
            errors=[error],
            version=expected_version + 1,
        )


class _ContextLoader(CoordinatorContextLoader):
    """Return a fixed policy context (optionally missing/deleted)."""

    def __init__(
        self,
        entities: tuple[CoordinatorEntityView, ...],
        missing: tuple[UUID, ...] = (),
        *,
        disposition: AnalysisDisposition | None = None,
    ) -> None:
        self._entities = entities
        self._missing = missing
        self._disposition = disposition

    async def load(
        self, investigation_id: UUID, expected_version: int
    ) -> CoordinatorPolicyContext:
        del investigation_id, expected_version
        return CoordinatorPolicyContext(
            entities=self._entities,
            missing_entity_ids=self._missing,
            analysis_disposition=self._disposition,
        )


def _state(
    *, discovered: tuple[UUID, ...] = (), evidence: tuple[UUID, ...] = ()
) -> InvestigationState:
    """Build a RUNNING state carrying the given lists."""
    traversal = [
        EntityTraversalState(
            entity_id=_ROOT,
            first_discovery_ordinal=0,
            minimum_depth=0,
        )
    ]
    traversal.extend(
        EntityTraversalState(
            entity_id=entity_id,
            first_discovery_ordinal=ordinal,
            minimum_depth=1,
        )
        for ordinal, entity_id in enumerate(discovered, start=1)
    )
    return InvestigationState(
        investigation_id=UUID("00000000-0000-0000-0000-0000000000b1"),
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[_ROOT],
        objective="Assess the root indicator.",
        budget=default_investigation_budget(),
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        discovered_entity_ids=list(discovered),
        evidence_ids=list(evidence),
        traversal=traversal,
        version=1,
    )


def _investigated_state(
    *, discovered: tuple[UUID, ...] = (), evidence: tuple[UUID, ...] = ()
) -> InvestigationState:
    """Build a RUNNING state whose root is already investigated at depth 0.

    Rooted at the root entity (ordinal 0) followed by each discovered entity
    at depth 1 in first-discovery order, so the traversal contract holds.
    """
    state = _state(discovered=discovered, evidence=evidence)
    entries = [
        EntityTraversalState(
            entity_id=_ROOT,
            first_discovery_ordinal=0,
            minimum_depth=0,
            best_investigated_depth=0,
        )
    ]
    for ordinal, entity_id in enumerate(discovered, start=1):
        entries.append(
            EntityTraversalState(
                entity_id=entity_id,
                first_discovery_ordinal=ordinal,
                minimum_depth=1,
            )
        )
    return state.model_copy(
        update={"investigated_entity_ids": [_ROOT], "traversal": entries}
    )


def _planner() -> MappingProviderWorkPlanner:
    """Return a planner covering DOMAIN and IP_ADDRESS."""
    return MappingProviderWorkPlanner(
        {
            SourceId.GOOGLE_PUBLIC_DNS: frozenset({EntityType.DOMAIN}),
            SourceId.ABUSEIPDB: frozenset({EntityType.IP_ADDRESS}),
        }
    )


async def _run(
    state: InvestigationState,
    *,
    ctx: CoordinatorPolicyContext,
    dispatcher_outcomes: dict[Any, ProviderExecutionOutcome] | None = None,
) -> tuple[InvestigationState, _StateTransitionService, _RecordingFatalService]:
    """Run the coordinator graph and return (state, service, fatal)."""
    service = _StateTransitionService()
    status = _StatusWriter(service)
    policy = CoordinatorPolicy(_planner())
    ctx_loader = _ContextLoader(
        ctx.entities,
        missing=ctx.missing_entity_ids,
        disposition=ctx.analysis_disposition,
    )
    fatal = _RecordingFatalService()
    graph = build_investigation_graph(
        FakeTaskDispatcher(dispatcher_outcomes or {}),
        coordinator_policy=policy,
        context_loader=ctx_loader,
        analysis_executor=FakeAnalysisExecutor(
            outcomes=(),
            bound_investigation_id=state.investigation_id,
        ),
        transition_service=service,
        status_writer=status,
        timeline_action_service=DeterministicTimelineActionService(),
        fatal_stop_service=fatal,
        expected_investigation_id=state.investigation_id,
    )
    recorded: InvestigationState | None = None
    async for snapshot in graph.astream(
        {"investigation": state},
        stream_mode="values",
        config={"recursion_limit": _MAX_TRANSITIONS},
    ):
        service.observed_transitions += 1
        candidate = snapshot.get("investigation")
        if isinstance(candidate, InvestigationState):
            recorded = candidate
    assert recorded is not None
    assert 0 < service.observed_transitions <= _MAX_TRANSITIONS
    return recorded, service, fatal


def _view(entity_id: UUID, entity_type: EntityType) -> CoordinatorEntityView:
    """Build a coordinator entity view for the given identity."""
    return CoordinatorEntityView(entity_id=entity_id, entity_type=entity_type)


def _scenario_checkpoint(
    scenario_id: str,
) -> tuple[InvestigationState, CoordinatorPolicyContext]:
    """Build the decisive real-policy checkpoint for one repository scenario."""
    corpus = Path(__file__).parents[4] / "evals/scenarios/coordinator"
    scenario = next(
        item
        for item in load_coordinator_scenarios_directory(corpus)
        if item.id == scenario_id
    )
    declared = resolve_coordinator_scenario(scenario)
    resolution = CoordinatorScenarioMaterializer().resolve_runtime(
        scenario, declared.entities
    )
    root = resolution.entities.get("root_domain") or next(
        iter(resolution.entities.values())
    )
    discovered = [
        entity_id
        for label, entity_id in resolution.entities.items()
        if label != "root_domain"
    ]
    traversal = [
        EntityTraversalState(entity_id=root, first_discovery_ordinal=0, minimum_depth=0)
    ]
    traversal.extend(
        EntityTraversalState(
            entity_id=entity_id,
            first_discovery_ordinal=ordinal,
            minimum_depth=(3 if scenario_id == "depth-limit" else 1),
        )
        for ordinal, entity_id in enumerate(discovered, start=1)
    )
    views: list[CoordinatorEntityView] = []
    for label, entity_id in resolution.entities.items():
        if label == "root_domain":
            entity_type = EntityType.DOMAIN
        elif "malware" in label:
            entity_type = EntityType.MALWARE
        elif "no_provider" in label:
            entity_type = EntityType.ORGANIZATION
        else:
            entity_type = EntityType.IP_ADDRESS
        views.append(
            CoordinatorEntityView(entity_id=entity_id, entity_type=entity_type)
        )

    budget = default_investigation_budget()
    investigated = [root]
    analysis_disposition: AnalysisDisposition | None = None
    evidence_ids: list[UUID] = []
    analyzed_ids: list[UUID] = []
    if scenario_id == "provider-budget":
        investigated = []
        budget = budget.model_copy(update={"max_provider_calls": 0})
    elif scenario_id == "entity-budget":
        budget = budget.model_copy(update={"max_entities": 1})
    elif scenario_id == "depth-limit":
        budget = budget.model_copy(update={"max_depth": 1})
    elif scenario_id in {"sufficient-evidence-stop", "already-investigated-ip"}:
        evidence_ids = [_E1]
        analyzed_ids = [_E1]
        analysis_disposition = AnalysisDisposition.SUFFICIENT
    elif scenario_id == "one-justified-replan":
        evidence_ids = [_E1]
        analyzed_ids = [_E1]
        analysis_disposition = AnalysisDisposition.NEEDS_MORE_EVIDENCE
    elif scenario_id == "replan-limit":
        evidence_ids = [_E1]
        analyzed_ids = [_E1]
        analysis_disposition = AnalysisDisposition.NEEDS_MORE_EVIDENCE
        budget = budget.model_copy(update={"max_replans": 1, "replans_used": 1})
    elif scenario_id in {"no-eligible-pivots", "non-pivotable-discovery"}:
        pass
    elif scenario_id == "already-investigated-ip":
        investigated.extend(discovered)

    if scenario_id == "already-investigated-ip":
        investigated.extend(
            entity_id for entity_id in discovered if entity_id not in investigated
        )
        traversal = [
            entry.model_copy(update={"best_investigated_depth": entry.minimum_depth})
            for entry in traversal
        ]
    elif scenario_id == "no-eligible-pivots":
        traversal[0] = traversal[0].model_copy(update={"best_investigated_depth": 0})

    state = InvestigationState(
        investigation_id=UUID("00000000-0000-0000-0000-00000000c021"),
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root],
        discovered_entity_ids=discovered,
        traversal=traversal,
        investigated_entity_ids=investigated,
        evidence_ids=evidence_ids,
        analyzed_evidence_ids=analyzed_ids,
        analysis_disposition=analysis_disposition,
        objective=f"Evaluate real policy for {scenario_id}.",
        budget=budget,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        version=1,
    )
    return state, CoordinatorPolicyContext(
        entities=tuple(views),
        analysis_disposition=analysis_disposition,
        analyzed_evidence_ids=tuple(analyzed_ids),
    )


class _PersistingAnalysisExecutor(AnalysisExecutor):
    """Persist a typed SUFFICIENT result into the in-memory durable service."""

    def __init__(
        self, service: _StateTransitionService, investigation_id: UUID
    ) -> None:
        self._service = service
        self._investigation_id = investigation_id

    @property
    def bound_investigation_id(self) -> UUID:
        return self._investigation_id

    async def analyze(self, investigation_id: UUID) -> AnalysisOutcome:
        if investigation_id != self._investigation_id or self._service._last is None:
            raise ValueError("analysis identity/state mismatch")
        assessment_id = UUID("00000000-0000-0000-0000-00000000a021")
        self._service._version += 1
        analyzed = tuple(self._service._last.evidence_ids)
        self._service._last = self._service._last.model_copy(
            update={
                "assessment_id": assessment_id,
                "analyzed_evidence_ids": list(analyzed),
                "analysis_disposition": AnalysisDisposition.SUFFICIENT,
                "version": self._service._version,
            }
        )
        return AnalysisOutcome(
            assessment_id=assessment_id,
            disposition=AnalysisDisposition.SUFFICIENT,
            analyzed_evidence_ids=analyzed,
            investigation_version=self._service._version,
        )


@pytest.mark.parametrize(
    ("scenario_id", "expected_action", "expected_stop"),
    [
        ("domain-discovers-ip", CoordinatorAction.AUTHORIZE_PIVOT, None),
        ("duplicate-ip-discovery", CoordinatorAction.AUTHORIZE_PIVOT, None),
        (
            "already-investigated-ip",
            CoordinatorAction.STOP,
            StopReason.SUFFICIENT_EVIDENCE,
        ),
        (
            "non-pivotable-discovery",
            CoordinatorAction.STOP,
            StopReason.NO_ELIGIBLE_PIVOTS,
        ),
        ("depth-limit", CoordinatorAction.STOP, StopReason.DEPTH_LIMIT_REACHED),
        (
            "provider-budget",
            CoordinatorAction.STOP,
            StopReason.PROVIDER_BUDGET_EXHAUSTED,
        ),
        ("entity-budget", CoordinatorAction.STOP, StopReason.ENTITY_BUDGET_EXHAUSTED),
        (
            "sufficient-evidence-stop",
            CoordinatorAction.STOP,
            StopReason.SUFFICIENT_EVIDENCE,
        ),
        ("no-eligible-pivots", CoordinatorAction.STOP, StopReason.NO_ELIGIBLE_PIVOTS),
        ("one-justified-replan", CoordinatorAction.AUTHORIZE_PIVOT, None),
        ("replan-limit", CoordinatorAction.STOP, StopReason.REPLAN_LIMIT_REACHED),
        ("cycle-suppression", CoordinatorAction.AUTHORIZE_PIVOT, None),
        ("malware-research-marker", CoordinatorAction.AUTHORIZE_PIVOT, None),
    ],
)
@pytest.mark.asyncio
async def test_every_repository_scenario_uses_real_coordinator_policy(
    scenario_id: str,
    expected_action: CoordinatorAction,
    expected_stop: StopReason | None,
) -> None:
    """Each scenario's decisive checkpoint is evaluated by CoordinatorPolicy."""
    state, context = _scenario_checkpoint(scenario_id)
    decision = CoordinatorPolicy(_planner()).decide(state=state, context=context)
    assert decision.action is expected_action
    assert decision.stop_reason is expected_stop
    if scenario_id == "one-justified-replan":
        assert decision.consumes_replan
    if scenario_id == "malware-research-marker":
        assert decision.research_entity_ids

    service = _StateTransitionService()
    status_writer = _StatusWriter(service)
    outcomes: dict[ProviderWorkItem, ProviderExecutionOutcome] = {}
    for entity in context.entities:
        if entity.entity_type is EntityType.DOMAIN:
            item = ProviderWorkItem(
                provider=SourceId.GOOGLE_PUBLIC_DNS,
                entity_id=entity.entity_id,
                depth=0,
            )
        elif entity.entity_type is EntityType.IP_ADDRESS:
            depth = next(
                entry.minimum_depth
                for entry in state.traversal
                if entry.entity_id == entity.entity_id
            )
            item = ProviderWorkItem(
                provider=SourceId.ABUSEIPDB,
                entity_id=entity.entity_id,
                depth=depth,
            )
        else:
            continue
        outcomes[item] = ProviderExecutionOutcome(
            work_item=item,
            status=ProviderExecutionStatus.SUCCEEDED,
            evidence_ids=(_E2,),
        )
    graph = build_investigation_graph(
        FakeTaskDispatcher(outcomes),
        coordinator_policy=CoordinatorPolicy(_planner()),
        context_loader=_ContextLoader(context.entities),
        analysis_executor=_PersistingAnalysisExecutor(service, state.investigation_id),
        transition_service=service,
        status_writer=status_writer,
        timeline_action_service=DeterministicTimelineActionService(),
        fatal_stop_service=_RecordingFatalService(),
        expected_investigation_id=state.investigation_id,
    )
    final: InvestigationState | None = None
    transitions = 0
    async for snapshot in graph.astream(
        {"investigation": state},
        stream_mode="values",
        config={"recursion_limit": 40},
    ):
        transitions += 1
        candidate = snapshot.get("investigation")
        if isinstance(candidate, InvestigationState):
            final = candidate
    assert final is not None
    assert 0 < transitions <= 40
    scenario = next(
        item
        for item in load_coordinator_scenarios_directory(
            Path(__file__).parents[4] / "evals/scenarios/coordinator"
        )
        if item.id == scenario_id
    )
    assert final.stop_reason == scenario.expected.expected_stop_reason.value


@pytest.mark.parametrize(
    "dependency_name",
    ["context", "analysis", "transition", "status", "fatal"],
)
def test_every_bound_dependency_conflict_fails_before_io(
    dependency_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every injected execution/persistence dependency is binding-checked."""
    expected = UUID("00000000-0000-0000-0000-0000000000a1")
    mismatched = UUID("00000000-0000-0000-0000-0000000000b2")
    transition = _StateTransitionService()
    dependencies: dict[str, object] = {
        "context": _ContextLoader(()),
        "analysis": FakeAnalysisExecutor(()),
        "transition": transition,
        "status": _StatusWriter(transition),
        "fatal": _RecordingFatalService(),
    }
    selected = dependencies[dependency_name]
    monkeypatch.setattr(
        type(selected),
        "bound_investigation_id",
        property(lambda _self: mismatched),
        raising=False,
    )
    with pytest.raises(ValueError, match="binding conflicts"):
        build_investigation_graph(
            FakeTaskDispatcher({}),
            coordinator_policy=CoordinatorPolicy(_planner()),
            context_loader=dependencies["context"],  # type: ignore[arg-type]
            analysis_executor=dependencies["analysis"],  # type: ignore[arg-type]
            transition_service=dependencies["transition"],  # type: ignore[arg-type]
            status_writer=dependencies["status"],  # type: ignore[arg-type]
            timeline_action_service=DeterministicTimelineActionService(),
            fatal_stop_service=dependencies["fatal"],  # type: ignore[arg-type]
            expected_investigation_id=expected,
        )
    assert transition.persisted_kinds == []
    assert transition.appended == []


class TestTrajectories:
    """Layered deterministic trajectories with explicit transition bounds."""

    @pytest.mark.asyncio
    async def test_no_eligible_pivot_stops(self) -> None:
        """An exhausted candidate set stops with NO_ELIGIBLE_PIVOTS."""
        state = _investigated_state()
        final, service, fatal = await _run(
            state,
            ctx=CoordinatorPolicyContext(entities=(_view(_ROOT, EntityType.DOMAIN),)),
            dispatcher_outcomes={},
        )
        assert final.stop_reason == StopReason.NO_ELIGIBLE_PIVOTS.value
        assert final.status is InvestigationStatus.COMPLETED
        assert len(service.persisted_kinds) < _MAX_TRANSITIONS
        assert not fatal.fatalized

    @pytest.mark.asyncio
    async def test_unchanged_evidence_does_not_reanalyze(self) -> None:
        """Already-analyzed evidence with SUFFICIENT stops without re-analysis."""
        state = _investigated_state(evidence=(_E1,), discovered=(_IP,)).model_copy(
            update={
                "analyzed_evidence_ids": [_E1],
                "analysis_disposition": AnalysisDisposition.SUFFICIENT.value,
            }
        )
        final, _service, _fatal = await _run(
            state,
            ctx=CoordinatorPolicyContext(
                entities=(
                    _view(_ROOT, EntityType.DOMAIN),
                    _view(_IP, EntityType.IP_ADDRESS),
                ),
                analysis_disposition=AnalysisDisposition.SUFFICIENT,
                analyzed_evidence_ids=(_E1,),
            ),
            dispatcher_outcomes={},
        )
        assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
        assert final.status is InvestigationStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_cycle_suppression_never_reexecutes(self) -> None:
        """An IP pivot completes, completing the cycle; no redundant replay."""
        state = enqueue_provider_work(_investigated_state(), [scenario_dns_work_item()])
        final, _service, _fatal = await _run(
            state,
            ctx=CoordinatorPolicyContext(
                entities=(
                    _view(_ROOT, EntityType.DOMAIN),
                    _view(_IP, EntityType.IP_ADDRESS),
                )
            ),
            dispatcher_outcomes={scenario_dns_work_item(): scenario_dns_outcome()},
        )
        assert final.stop_reason is not None
        assert final.status is InvestigationStatus.COMPLETED
        assert len(final.completed_provider_work) == 1

    @pytest.mark.asyncio
    async def test_invented_target_never_authorized(self) -> None:
        """A candidate missing from persistence yields NO_ELIGIBLE_PIVOTS."""
        state = _investigated_state(discovered=(_IP,))
        final, _service, _fatal = await _run(
            state,
            ctx=CoordinatorPolicyContext(
                entities=(_view(_ROOT, EntityType.DOMAIN),),
                missing_entity_ids=(_IP,),
            ),
            dispatcher_outcomes={},
        )
        assert final.stop_reason == StopReason.NO_ELIGIBLE_PIVOTS.value

    @pytest.mark.asyncio
    async def test_persisted_work_resume_fails_bounded(self) -> None:
        """A persisted current_provider_work resumes into a bounded fatal stop.

        The graph must never silently re-issue an external provider call for
        an in-progress item (no retry token exists in PR 21).
        """
        state = select_provider_work(
            enqueue_provider_work(_investigated_state(), [scenario_dns_work_item()])
        )
        final, _service, fatal = await _run(
            state,
            ctx=CoordinatorPolicyContext(entities=(_view(_ROOT, EntityType.DOMAIN),)),
            dispatcher_outcomes={},
        )
        assert fatal.fatalized
        assert fatal.fatalized[0][1].code == "persisted_provider_work_resume"
        assert final.status is InvestigationStatus.FAILED
        assert final.stop_reason == StopReason.FATAL_ERROR.value

    @pytest.mark.asyncio
    async def test_provider_budget_stop_specific(self) -> None:
        """Provider budget exhaustion produces the specific stop reason."""
        # The root must be an eligible candidate (not yet investigated) so the
        # provider budget is the sole blocker.
        state = _state()
        state = state.model_copy(
            update={
                "budget": default_investigation_budget().model_copy(
                    update={"max_provider_calls": 0}
                ),
            }
        )
        final, _service, _fatal = await _run(
            state,
            ctx=CoordinatorPolicyContext(entities=(_view(_ROOT, EntityType.DOMAIN),)),
            dispatcher_outcomes={},
        )
        assert final.stop_reason == StopReason.PROVIDER_BUDGET_EXHAUSTED.value
