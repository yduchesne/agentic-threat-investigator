# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 19B production graph composition factory."""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-few-public-methods

from uuid import uuid4

import pytest

from agentic_threat_investigator.app.orchestration.composition import (
    build_provider_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
)
from agentic_threat_investigator.app.providers import EvidenceProvider, ProviderResult
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.identifiers import SourceId
from tests.support.provider_executor_fixtures import fixed_clock, null_uow_factory


class _FakeProvider(EvidenceProvider):  # pylint: disable=too-few-public-methods
    @property
    def id(self) -> str:
        return SourceId.GOOGLE_PUBLIC_DNS.value

    def supports(self, entity: Entity) -> bool:
        return True

    async def investigate(
        self, investigation_id: object, entity: Entity
    ) -> ProviderResult:
        raise AssertionError("factory test must not invoke the provider")


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
