# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 19B production graph composition factory."""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-few-public-methods

from typing import cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.extraction.models import ExtractionResult
from agentic_threat_investigator.app.orchestration import (
    InvestigationGraphBindingConflictError,
    InvestigationGraphContextMismatchError,
    build_investigation_graph,
    enqueue_provider_work,
)
from agentic_threat_investigator.app.orchestration.composition import (
    build_provider_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
    ProviderWorkExecutor,
)
from agentic_threat_investigator.app.providers import EvidenceProvider, ProviderResult
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from tests.support.orchestration_fixtures import (
    SCENARIO_DOMAIN_ID,
    scenario_dns_work_item,
)
from tests.support.provider_executor_fixtures import (
    FakeEntityReader,
    FakePersistenceService,
    domain_entity,
    fixed_clock,
    null_uow_factory,
)


class _FakeProvider(EvidenceProvider):  # pylint: disable=too-few-public-methods
    def __init__(self) -> None:
        self.supports_calls = 0
        self.investigate_calls = 0

    @property
    def id(self) -> str:
        return SourceId.GOOGLE_PUBLIC_DNS.value

    def supports(self, entity: Entity) -> bool:
        self.supports_calls += 1
        return True

    async def investigate(
        self, investigation_id: object, entity: Entity
    ) -> ProviderResult:
        self.investigate_calls += 1
        raise AssertionError("factory test must not invoke the provider")


def _state_for(investigation_id: UUID) -> InvestigationState:
    """Build a RUNNING state for the given investigation with one pending work item."""
    return enqueue_provider_work(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[SCENARIO_DOMAIN_ID],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=fixed_clock(),
        ),
        [scenario_dns_work_item()],
    )


def _exploding_uow_factory() -> object:
    """Return a factory that fails the test if the UoW is ever opened."""
    raise AssertionError("uow_factory must not be called")


@pytest.mark.asyncio
async def test_factory_assembles_graph_without_global_state() -> None:
    """The factory wires production seams into the existing graph topology."""
    registry: dict[SourceId, EvidenceProvider] = {
        SourceId.GOOGLE_PUBLIC_DNS: _FakeProvider()
    }
    context = ProviderExecutionContext(
        investigation_id=uuid4(),
        clock=fixed_clock,
    )
    graph = build_provider_investigation_graph(
        uow_factory=null_uow_factory,
        provider_registry=registry,
        context=context,
    )
    # The compiled graph exposes the deterministic PR 19A topology.
    assert "initialize" in graph.nodes
    assert "select_work" in graph.nodes
    assert "execute_work" in graph.nodes
    assert "record_outcome" in graph.nodes


@pytest.mark.asyncio
async def test_mismatched_investigation_fails_before_any_seam() -> None:
    """A graph built for investigation A rejects state B before every I/O seam.

    The mismatch is raised during initialize, so the UnitOfWork factory, the
    provider, and every persistence/timeline seam must never run. The fixed
    exception message contains neither UUID.
    """
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    investigation_b = UUID("00000000-0000-0000-0000-0000000000bb")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    graph = build_provider_investigation_graph(
        uow_factory=_exploding_uow_factory,  # type: ignore[arg-type]
        provider_registry=registry,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    with pytest.raises(InvestigationGraphContextMismatchError) as raised:
        await graph.ainvoke({"investigation": _state_for(investigation_b)})
    assert provider.supports_calls == 0
    assert provider.investigate_calls == 0
    message = str(raised.value)
    assert str(investigation_a) not in message
    assert str(investigation_b) not in message
    assert message == (
        "orchestration graph state does not match the bound investigation " "context"
    )


@pytest.mark.asyncio
async def test_matching_investigation_zero_work_terminates() -> None:
    """A matching investigation with no work terminates without any seam call."""
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    graph = build_provider_investigation_graph(
        uow_factory=_exploding_uow_factory,  # type: ignore[arg-type]
        provider_registry=registry,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    state = InvestigationState(
        investigation_id=investigation_a,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[SCENARIO_DOMAIN_ID],
        objective="Assess the root indicator.",
        budget=default_investigation_budget(),
        started_at=fixed_clock(),
    )
    result = await graph.ainvoke({"investigation": state})
    recorded = cast(InvestigationState, result["investigation"])
    assert recorded.investigation_id == investigation_a
    assert provider.supports_calls == 0
    assert provider.investigate_calls == 0
    assert recorded.budget.provider_calls_used == 0


@pytest.mark.asyncio
async def test_direct_builder_bypass_is_automatically_bound() -> None:
    """Direct generic-builder use of ProviderWorkExecutor cannot bypass binding.

    A caller who constructs the production executor for investigation A and
    builds the generic graph without an expected ID still gets automatic
    binding: invoking it with state B raises the typed mismatch error before
    the entity reader, provider, or any persistence/timeline seam runs.
    """
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    investigation_b = UUID("00000000-0000-0000-0000-0000000000bb")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    executor = ProviderWorkExecutor(
        entity_reader=FakeEntityReader({uuid4(): domain_entity()}),
        provider_registry=registry,
        extractor=lambda _evidence: ExtractionResult(),
        persistence_service=FakePersistenceService(),
        timeline_service=None,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    graph = build_investigation_graph(executor)
    with pytest.raises(InvestigationGraphContextMismatchError) as raised:
        await graph.ainvoke({"investigation": _state_for(investigation_b)})
    assert provider.supports_calls == 0
    assert provider.investigate_calls == 0
    message = str(raised.value)
    assert str(investigation_a) not in message
    assert str(investigation_b) not in message
    assert message == (
        "orchestration graph state does not match the bound investigation " "context"
    )


def test_direct_builder_conflict_rejected_at_construction() -> None:
    """An explicit conflicting ID with a provider executor fails at construction."""
    investigation_a = UUID("00000000-0000-0000-0000-0000000000aa")
    investigation_b = UUID("00000000-0000-0000-0000-0000000000bb")
    provider = _FakeProvider()
    registry: dict[SourceId, EvidenceProvider] = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    executor = ProviderWorkExecutor(
        entity_reader=FakeEntityReader({uuid4(): domain_entity()}),
        provider_registry=registry,
        extractor=lambda _evidence: ExtractionResult(),
        persistence_service=FakePersistenceService(),
        timeline_service=None,
        context=ProviderExecutionContext(
            investigation_id=investigation_a,
            clock=fixed_clock,
        ),
    )
    with pytest.raises(InvestigationGraphBindingConflictError) as raised:
        build_investigation_graph(
            executor,
            expected_investigation_id=investigation_b,
        )
    message = str(raised.value)
    assert message == (
        "orchestration graph binding conflicts with the executor "
        "investigation context"
    )
    assert str(investigation_a) not in message
    assert str(investigation_b) not in message
