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

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from uuid import UUID

from langgraph.errors import GraphRecursionError

from agentic_threat_investigator.app.error_messages import ErrorMessageSanitizer
from agentic_threat_investigator.app.orchestration.composition import (
    build_provider_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.coordinator import (
    AnalysisExecutor,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
)
from agentic_threat_investigator.app.orchestration.research import ResearchExecutor
from agentic_threat_investigator.app.orchestration.services import (
    FatalStopService,
    UowFatalStopService,
)
from agentic_threat_investigator.app.persistence.repositories import (
    CoordinatorTransitionPersistenceError,
    InvestigationNotFoundError,
    InvestigationVersionConflictError,
    UnitOfWork,
)
from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationBudget,
    InvestigationError,
    InvestigationState,
    InvestigationStatus,
    is_terminal_status,
)
from agentic_threat_investigator.telemetry.decorators import telemetry_operation
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
    get_counter,
)
from agentic_threat_investigator.telemetry.tracing import SpanNames

#: LangGraph supersteps one budget unit (provider call, replan, analysis,
#: entity admission, or depth) may legitimately consume. Each provider work
#: item costs roughly four graph supersteps (``select_work``,
#: ``execute_work``, ``record_outcome``, ``coordinator``); the remaining
#: budget units cost at most a couple. The bound is generous because it is a
#: safety net against runaway graphs, not the investment budget itself.
_RECURSION_SUPERSTEPS_PER_BUDGET_UNIT = 4

#: Fixed supersteps reserved for graph startup/teardown nodes.
_RECURSION_LIMIT_HEADROOM = 16

#: Error code recorded when the graph engine aborts outside any node.
_GRAPH_ABORT_ERROR_CODE = "graph_execution_aborted"

#: Persistence failures propagate unchanged; a fatal stop is never claimed
#: when the fatal write itself could not be persisted.
_PERSISTENCE_ERRORS = (
    CoordinatorTransitionPersistenceError,
    InvestigationNotFoundError,
    InvestigationVersionConflictError,
)


def recursion_limit_for_budget(budget: InvestigationBudget) -> int:
    """Return a LangGraph recursion bound large enough for one budget.

    The previous fixed production bound (40) was smaller than the number of
    supersteps a full provider budget requires, so a legitimate
    investigation aborted with LangGraph's ``GraphRecursionError`` before it
    could consume its budget. Deriving the bound from the persisted budget
    keeps the safety net above any trajectory the budget authorizes.
    """
    units = (
        budget.max_provider_calls
        + budget.max_replans
        + budget.max_llm_calls
        + budget.max_entities
        + budget.max_depth
    )
    return _RECURSION_SUPERSTEPS_PER_BUDGET_UNIT * units + _RECURSION_LIMIT_HEADROOM


def _record_investigation_failure() -> None:
    """Increment the bounded investigation-execution failure counter (PR 29B).

    Fired by the ``telemetry_operation`` decorator after an ordinary
    execution exception; it never fires for cancellation and never captures
    exception text or Investigation IDs.
    """
    get_counter(Metrics.INVESTIGATION_EXECUTE_FAILURES).add(1)


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
        research_executor_factory: Callable[[UUID], ResearchExecutor] | None = None,
        clock: Callable[[], datetime] | None = None,
        recursion_limit: int = 40,
    ) -> None:
        """Bind the injected application seams and validate the recursion bound.

        ``recursion_limit`` is the minimum LangGraph recursion depth for one
        invocation; the effective per-invocation bound is raised when needed
        so the graph can always consume the persisted investigation budget
        (see :func:`recursion_limit_for_budget`). The provider registry is
        copied defensively so a later caller mutation cannot change a compiled
        graph's enabled provider set. A ``research_executor_factory`` is
        optional: when absent the graph never executes research
        (already-marked requirements stay marked), preserving the pre-22C
        lifecycle for callers that opt out.
        """
        if recursion_limit <= 0:
            raise ValueError("recursion_limit must be positive")
        self._uow_factory = uow_factory
        self._provider_registry = dict(provider_registry)
        self._analysis_executor_factory = analysis_executor_factory
        self._research_executor_factory = research_executor_factory
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )
        self._recursion_limit = recursion_limit

    @telemetry_operation(
        span_name=SpanNames.INVESTIGATION_EXECUTE,
        duration_metric=DurationMetrics.INVESTIGATION_EXECUTE,
        on_error=_record_investigation_failure,
    )
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
        the durable row. An unexpected graph-engine abort (an error raised by
        LangGraph itself rather than inside a graph node, such as the
        recursion bound) is first persisted as a bounded fatal stop so the
        Investigation can never be stranded non-terminal, then re-raised.
        ``asyncio.CancelledError`` propagates unchanged and persistence
        failures propagate un-fatalized.

        Telemetry records one ``ati.investigation.execute`` span and seconds
        duration for the whole invocation, counts exactly one executed
        investigation only when the graph actually runs (never for the
        idempotent terminal no-op or a lifecycle rejection), and counts one
        failure on an ordinary exception. ``investigation_id`` is never a
        metric label.
        """
        loaded = await self._load_investigation(investigation_id)

        # Terminal investigations are idempotent no-ops: no analysis executor,
        # graph composition, provider I/O, or timeline event is produced.
        if is_terminal_status(loaded.status):
            return loaded
        if loaded.status is not InvestigationStatus.RUNNING:
            raise InvestigationRunnerLifecycleError()

        analysis_executor = self._analysis_executor_factory(investigation_id)
        research_executor = (
            self._research_executor_factory(investigation_id)
            if self._research_executor_factory is not None
            else None
        )
        context = ProviderExecutionContext(
            investigation_id=investigation_id, clock=self._clock
        )
        fatal_stop_service = UowFatalStopService(
            self._uow_factory,
            self._clock,
            bound_investigation_id=investigation_id,
        )
        graph = build_provider_investigation_graph(
            uow_factory=self._uow_factory,
            provider_registry=self._provider_registry,
            context=context,
            analysis_executor=analysis_executor,
            research_executor=research_executor,
            fatal_stop_service=fatal_stop_service,
        )
        effective_recursion_limit = max(
            self._recursion_limit, recursion_limit_for_budget(loaded.budget)
        )
        try:
            result = await graph.ainvoke(
                {"investigation": loaded},
                config={"recursion_limit": effective_recursion_limit},
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if isinstance(error, _PERSISTENCE_ERRORS):
                raise
            await self._fatalize_graph_abort(
                investigation_id, error, fatal_stop_service
            )
            raise
        # One actual runner execution: the graph ran to (possibly failed)
        # completion, never an idempotent no-op or a lifecycle rejection.
        get_counter(Metrics.INVESTIGATION_EXECUTED).add(1)
        # The graph output is untrusted runtime data: require a mapping that
        # carries a valid InvestigationState under the ``investigation`` key
        # so malformed output fails through the typed lifecycle contract
        # instead of leaking a raw KeyError/TypeError. Cancellation raised
        # by ``ainvoke`` itself is deliberately not intercepted here.
        if not isinstance(result, Mapping):
            raise InvestigationRunnerLifecycleError()
        graph_final = result.get("investigation")
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

    async def _fatalize_graph_abort(
        self,
        investigation_id: UUID,
        error: BaseException,
        fatal_stop_service: FatalStopService,
    ) -> None:
        """Persist a bounded fatal stop after a graph-engine abort.

        LangGraph can abort a run outside any node (for example when its
        recursion bound is reached), so no node-level fatal boundary claims
        the failure. Left unhandled, the Investigation would stay
        non-terminal forever while its durable job is already failed. The
        same fatal-stop lifecycle the graph nodes use is therefore applied
        here, with the sanitized root-cause diagnostic, before the original
        error is re-raised. An already-terminal Investigation is left
        untouched, and a state without a persisted version cannot authorize a
        transition.
        """
        try:
            current = await self._load_investigation(investigation_id)
        except InvestigationNotFoundError:
            # The Investigation disappeared during execution: there is no
            # durable state to terminalize, so the original abort propagates.
            return
        if is_terminal_status(current.status) or current.version is None:
            return
        code = (
            "graph_recursion_limit"
            if isinstance(error, GraphRecursionError)
            else _GRAPH_ABORT_ERROR_CODE
        )
        await fatal_stop_service.fatalize(
            investigation_id,
            InvestigationError(
                source="orchestration",
                code=code,
                message=ErrorMessageSanitizer().from_exception(error),
                recoverable=False,
            ),
            expected_version=current.version,
        )

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
