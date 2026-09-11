# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic fake executor and PR 19A orchestration scenario fixtures."""

from datetime import UTC, datetime
from uuid import UUID

from agentic_threat_investigator.app.orchestration.coordinator import (
    CoordinatorEntityView,
    CoordinatorPolicyContext,
)
from agentic_threat_investigator.app.orchestration.dispatcher import TaskDispatcher
from agentic_threat_investigator.app.orchestration.executor import WorkExecutor
from agentic_threat_investigator.app.orchestration.models import enqueue_provider_work
from agentic_threat_investigator.app.orchestration.services import (
    CoordinatorContextLoader,
    CoordinatorTransitionService,
    InvestigationStatusWriter,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
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

SCENARIO_DOMAIN_ID = UUID("00000000-0000-0000-0000-0000000000d1")
"""Fixed root domain entity UUID for the PR 19A scenario."""

SCENARIO_IP_ID = UUID("00000000-0000-0000-0000-0000000001d1")
"""Fixed synthetic discovered IP entity UUID for the PR 19A scenario."""


def scenario_dns_work_item() -> ProviderWorkItem:
    """Return the fixed Google Public DNS work item for the scenario."""

    return ProviderWorkItem(
        provider=SourceId.GOOGLE_PUBLIC_DNS,
        entity_id=SCENARIO_DOMAIN_ID,
        depth=0,
    )


def scenario_rdap_work_item() -> ProviderWorkItem:
    """Return the fixed RDAP work item for the scenario."""

    return ProviderWorkItem(
        provider=SourceId.RDAP, entity_id=SCENARIO_DOMAIN_ID, depth=0
    )


def scenario_dns_outcome() -> ProviderExecutionOutcome:
    """Return the deterministic DNS outcome discovering the scenario IP."""

    return ProviderExecutionOutcome(
        work_item=scenario_dns_work_item(),
        status=ProviderExecutionStatus.SUCCEEDED,
        discovered_entity_ids=(SCENARIO_IP_ID,),
    )


def scenario_rdap_outcome() -> ProviderExecutionOutcome:
    """Return the deterministic RDAP outcome discovering nothing."""

    return ProviderExecutionOutcome(
        work_item=scenario_rdap_work_item(),
        status=ProviderExecutionStatus.SUCCEEDED,
    )


class FakeWorkExecutor(WorkExecutor):
    """Deterministic in-memory executor driven by an explicit outcome mapping.

    Records every requested work item in execution order for test assertions.
    Performs no network, database, or LLM I/O. This is the legacy PR 19A
    compatibility fixture: primary graph tests use
    :class:`FakeTaskDispatcher` instead.
    """

    def __init__(
        self, outcomes: dict[ProviderWorkItem, ProviderExecutionOutcome]
    ) -> None:
        self._outcomes = dict(outcomes)
        self.requested: list[ProviderWorkItem] = []

    async def execute(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        """Return the configured deterministic outcome for one work item."""

        self.requested.append(work_item)
        return self._outcomes[work_item]


class FakeTaskDispatcher(TaskDispatcher):
    """Deterministic in-memory dispatcher driven by an explicit outcome mapping.

    ``dispatch`` records the exact requested work item in call order and
    returns the configured deterministic outcome. It performs no state
    mutation and no external I/O, so the graph seam can be exercised without
    any concrete ``LocalTaskDispatcher`` or ``ProviderWorkExecutor``.
    """

    def __init__(
        self, outcomes: dict[ProviderWorkItem, ProviderExecutionOutcome]
    ) -> None:
        self._outcomes = dict(outcomes)
        self.requested: list[ProviderWorkItem] = []

    async def dispatch(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        """Record the item and return its configured deterministic outcome."""

        self.requested.append(work_item)
        return self._outcomes[work_item]


def scenario_dispatcher() -> FakeTaskDispatcher:
    """Return the fake dispatcher for the PR 19C minimal scenario."""

    return FakeTaskDispatcher(
        {
            scenario_dns_work_item(): scenario_dns_outcome(),
            scenario_rdap_work_item(): scenario_rdap_outcome(),
        }
    )


def scenario_investigation_state() -> InvestigationState:
    """Return the fixed initial investigation state for the PR 19A scenario."""

    return InvestigationState(
        investigation_id=UUID("00000000-0000-0000-0000-0000000000a1"),
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[SCENARIO_DOMAIN_ID],
        objective="Investigate the scenario domain.",
        budget=default_investigation_budget(),
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def scenario_initial_state() -> InvestigationState:
    """Return the scenario state seeded with the two initial work items."""

    return enqueue_provider_work(
        scenario_investigation_state(),
        [scenario_dns_work_item(), scenario_rdap_work_item()],
    )


class FakeContextLoader(CoordinatorContextLoader):
    """Return a fixed policy context without opening any transaction."""

    def __init__(
        self,
        context: CoordinatorPolicyContext | None = None,
        *,
        entities: tuple[CoordinatorEntityView, ...] = (),
    ) -> None:
        self._context = context or CoordinatorPolicyContext(entities=entities)

    async def load(
        self, investigation_id: UUID, expected_version: int
    ) -> CoordinatorPolicyContext:
        del investigation_id, expected_version
        return self._context


class NoopTransitionService(CoordinatorTransitionService):
    """Return the supplied state without persisting; records calls."""

    def __init__(self) -> None:
        self.persisted: list[tuple[UUID, InvestigationState]] = []
        self.appended_events: list[InvestigationTimelineEvent] = []
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
        del transition_kind, actor_id, request_id, expected_version, consumes_replan
        self.persisted.append((investigation_id, state))
        self.appended_events.extend(events)
        self._last = state
        return state

    async def reload(self, investigation_id: UUID) -> InvestigationState:
        del investigation_id
        if self._last is None:
            raise InvestigationNotFoundError("no persisted investigation state")
        return self._last

    async def emit(self, event: InvestigationTimelineEvent) -> None:
        self.appended_events.append(event)


class NoopStatusWriter(InvestigationStatusWriter):
    """Return the supplied terminal state without persisting; records calls."""

    def __init__(self) -> None:
        self.finalized: list[tuple[UUID, StopReason]] = []
        self.appended_events: list[object] = []

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
        del actor_id, request_id, expected_version
        self.finalized.append((investigation_id, stop_reason))
        self.appended_events.extend(events)
        return state


def empty_context_loader() -> FakeContextLoader:
    """Return a context loader that yields no candidates (no pivot path)."""
    return FakeContextLoader()
