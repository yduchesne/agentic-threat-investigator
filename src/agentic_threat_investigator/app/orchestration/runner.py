# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Application-level production runner for one ATI investigation (PR 21C).

:class:`InvestigationRunner` is the stable application seam that future
API/job/monitor entry points call to execute one persisted investigation
through the existing coordinator-driven provider graph.
:class:`LocalInvestigationRunner` is the in-process implementation: it loads
the authoritative Investigation through a short UnitOfWork, creates a fresh
investigation-bound ``AnalysisExecutor`` via an injected factory, delegates
graph composition to the existing ``build_provider_investigation_graph``,
executes the compiled graph outside any enclosing database transaction, then
reloads and returns the authoritative durable terminal state.

The runner coordinates application execution only. It never decides
investigative policy, constructs providers, LLM clients, or secrets, and no
UnitOfWork is ever held across graph/provider/LLM execution.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from uuid import UUID

from agentic_threat_investigator.app.orchestration.composition import (
    build_provider_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.coordinator import (
    AnalysisExecutor,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    UnitOfWork,
)
from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    is_terminal_status,
)


class InvestigationRunnerLifecycleError(ValueError):
    """Raised when a runner invocation cannot execute the current lifecycle.

    Covers both an unsupported non-terminal persisted status and a graph
    result that fails to reach a terminal state. The message is a fixed safe
    string that never embeds identifiers or provider payloads.
    """

    def __init__(self) -> None:
        """Build the fixed safe lifecycle-error message."""
        super().__init__(
            "investigation runner cannot execute the current investigation lifecycle"
        )


class InvestigationRunnerPersistenceMismatchError(ValueError):
    """Raised when the final durable Investigation contradicts graph output.

    The runner returns only authoritative persisted state; a successful graph
    completion whose durable row disagrees on the stable lifecycle fields
    fails closed with this typed error instead of returning contradictory
    state. The message is a fixed safe string.
    """

    def __init__(self) -> None:
        """Build the fixed safe durability-mismatch message."""
        super().__init__(
            "investigation runner final durable state does not match graph output"
        )


class InvestigationRunner(ABC):
    """Application seam that executes one persisted Investigation.

    Implementations load the authoritative Investigation, execute the
    coordinator-driven provider graph outside any enclosing transaction, and
    return the authoritative durable terminal state. Request/job DTOs are
    deliberately absent; the only business input is the Investigation ID.
    """

    @abstractmethod
    async def run(self, investigation_id: UUID) -> InvestigationState:
        """Execute the persisted Investigation and return its terminal state."""


class LocalInvestigationRunner(InvestigationRunner):
    """In-process production runner bound to one persisted Investigation.

    "Local" means the graph and the provider dispatcher execute in this
    process; it does not imply fake or in-memory persistence. The runner
    compiles a fresh investigation-bound graph on every invocation and never
    caches graphs or analysis executors, so one instance can execute
    different Investigation IDs without binding leakage.

    The runner constructs no providers, LLM clients, HTTP clients, secrets,
    settings objects, or engines: every infrastructure seam is injected as
    an already-composed application dependency.
    """

    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        provider_registry: Mapping[SourceId, EvidenceProvider],
        analysis_executor_factory: Callable[[UUID], AnalysisExecutor],
        clock: Callable[[], datetime] | None = None,
        recursion_limit: int = 40,
    ) -> None:
        """Bind the injected application seams and validate the recursion bound.

        ``recursion_limit`` bounds the LangGraph recursion depth for one
        invocation; the canonical trajectory measured value (40) is the
        default. The provider registry is copied defensively so a later caller
        mutation cannot change a compiled graph's enabled provider set.
        """
        if recursion_limit <= 0:
            raise ValueError("recursion_limit must be positive")
        self._uow_factory = uow_factory
        self._provider_registry = dict(provider_registry)
        self._analysis_executor_factory = analysis_executor_factory
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )
        self._recursion_limit = recursion_limit

    async def run(self, investigation_id: UUID) -> InvestigationState:
        """Execute one persisted Investigation and return its terminal state.

        Loads the authoritative persisted Investigation through one short
        UnitOfWork and closes it before any graph/provider/LLM work. A
        terminal Investigation is an idempotent no-op returned unchanged; a
        non-terminal status other than RUNNING fails closed with a typed
        lifecycle error. Otherwise a fresh bound AnalysisExecutor and a fresh
        compiled graph are created, the graph is invoked with the persisted
        state, and the final durable Investigation is reloaded and returned
        after requiring the graph output to be terminal and consistent with
        the durable row. ``asyncio.CancelledError`` propagates unchanged.
        """
        loaded = await self._load_investigation(investigation_id)

        # Terminal investigations are idempotent no-ops: no analysis executor,
        # graph composition, provider I/O, or timeline event is produced.
        if is_terminal_status(loaded.status):
            return loaded
        if loaded.status is not InvestigationStatus.RUNNING:
            raise InvestigationRunnerLifecycleError()

        analysis_executor = self._analysis_executor_factory(investigation_id)
        context = ProviderExecutionContext(
            investigation_id=investigation_id, clock=self._clock
        )
        graph = build_provider_investigation_graph(
            uow_factory=self._uow_factory,
            provider_registry=self._provider_registry,
            context=context,
            analysis_executor=analysis_executor,
        )
        result = await graph.ainvoke(
            {"investigation": loaded},
            config={"recursion_limit": self._recursion_limit},
        )
        graph_final = result["investigation"]
        if not isinstance(graph_final, InvestigationState):
            raise InvestigationRunnerLifecycleError()
        if not is_terminal_status(graph_final.status):
            raise InvestigationRunnerLifecycleError()

        # The durable row is authoritative: reload through a fresh short UoW
        # and require it to agree with the graph output on the stable
        # lifecycle fields before returning it.
        durable = await self._load_investigation(investigation_id)
        self._validate_durable(durable, graph_final)
        return durable

    async def _load_investigation(self, investigation_id: UUID) -> InvestigationState:
        """Load the authoritative Investigation through one short UnitOfWork.

        The UnitOfWork is closed before the state is returned; no repository
        or session object remains attached to the returned state.
        """
        async with self._uow_factory() as uow:
            investigation = await uow.investigations.get_by_id(investigation_id)
        if investigation is None:
            raise InvestigationNotFoundError(str(investigation_id))
        return investigation

    @staticmethod
    def _validate_durable(
        durable: InvestigationState, graph_final: InvestigationState
    ) -> None:
        """Require the durable row to agree with the graph output.

        Only stable lifecycle fields introduced by the coordinator graph are
        compared; database-owned timestamps (``completed_at``) are excluded.
        A mismatch raises :class:`InvestigationRunnerPersistenceMismatchError`
        so the runner fails closed rather than returning contradictory state.
        """
        if (
            durable.investigation_id != graph_final.investigation_id
            or durable.status is not graph_final.status
            or durable.stop_reason != graph_final.stop_reason
            or durable.version != graph_final.version
            or durable.assessment_id != graph_final.assessment_id
            or durable.evidence_ids != graph_final.evidence_ids
            or durable.completed_provider_work != graph_final.completed_provider_work
        ):
            raise InvestigationRunnerPersistenceMismatchError()
