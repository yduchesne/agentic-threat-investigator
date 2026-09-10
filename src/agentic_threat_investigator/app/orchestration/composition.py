# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Production composition seam for the provider-backed investigation graph.

One public factory assembles the real PR 19B execution path from the injected
UnitOfWork factory, provider registry, and execution context, then wires it
into the existing PR 19A graph. A later worker/bootstrap entry point calls
this factory; no worker, HTTP client, provider instance, settings object,
engine, or global registry is constructed here — those remain bootstrap and
infrastructure concerns.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from langgraph.graph.state import CompiledStateGraph

from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.investigation_timeline import (
    UnitOfWorkInvestigationTimelineSink,
)
from agentic_threat_investigator.app.orchestration.executor import WorkExecutor
from agentic_threat_investigator.app.orchestration.graph import (
    OrchestrationGraphState,
    build_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
    ProviderWorkExecutor,
    UowEntityReader,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceService,
)
from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.domain.identifiers import SourceId


def build_provider_investigation_graph(
    *,
    uow_factory: Callable[[], UnitOfWork],
    provider_registry: Mapping[SourceId, EvidenceProvider],
    context: ProviderExecutionContext,
) -> CompiledStateGraph[
    OrchestrationGraphState, None, OrchestrationGraphState, OrchestrationGraphState
]:
    """Build the compiled provider-backed investigation graph.

    Assembles exactly the production seams: the short-transaction entity
    reader, the PR 18B extraction dispatcher, the PR 18C atomic persistence
    service, the UnitOfWork-backed timeline sink, the provider executor, and
    the existing PR 19A graph topology. No global state is created.

    The compiled graph is bound to exactly one investigation ID
    (``context.investigation_id``): every invocation validates the wrapped
    state's investigation ID during ``initialize`` and raises
    ``InvestigationGraphContextMismatchError`` before work selection, target
    lookup, timeline emission, provider I/O, extraction, or persistence when
    the state belongs to a different investigation. Validation executes at
    graph initialization on every invocation; it is never performed only at
    construction time.
    """
    executor: WorkExecutor = ProviderWorkExecutor(
        entity_reader=UowEntityReader(uow_factory),
        provider_registry=provider_registry,
        extractor=extract,
        persistence_service=ProviderObservationPersistenceService(uow_factory),
        timeline_service=UnitOfWorkInvestigationTimelineSink(uow_factory),
        context=context,
    )
    return build_investigation_graph(
        executor,
        expected_investigation_id=context.investigation_id,
    )
