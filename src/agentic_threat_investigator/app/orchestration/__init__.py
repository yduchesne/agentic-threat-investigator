# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation orchestration (PR 19A skeleton + PR 19B/19C execution dispatch).

The package owns typed work orchestration contracts, the deterministic PR 19A
workflow skeleton that depends only on the ``TaskDispatcher`` boundary, the PR
19B real provider execution adapter, and the PR 19C task dispatch
contracts/local dispatch with its production composition factory. Because
``LocalTaskDispatcher`` is the single explicit executor-to-dispatcher
adapter, callers/composition must construct it around a ``WorkExecutor``;
the graph never accepts or adapts executors directly.

PR 21 extends the package with coordinator-driven pivot authorization, analysis
execution, and deterministic stopping. ``build_investigation_graph`` requires
all coordinator dependencies; ``build_legacy_investigation_graph`` exists
only for isolated mechanics tests. PR 21C adds the application-level
:class:`InvestigationRunner` seam (:class:`LocalInvestigationRunner`) that
loads the authoritative persisted Investigation, executes it through the
production coordinator graph outside any enclosing transaction, and returns
the authoritative durable terminal state.
"""

from .composition import (
    PROVIDER_SOURCE_ORDER,
    build_provider_investigation_graph,
)
from .coordinator import (
    AnalysisExecutor,
    AnalysisOutcome,
    CoordinatorAction,
    CoordinatorDecision,
    CoordinatorEntityView,
    CoordinatorPolicy,
    CoordinatorPolicyContext,
    FakeAnalysisExecutor,
    MappingProviderWorkPlanner,
    PivotRejection,
    PivotRejectionReason,
    ProviderWorkPlanner,
)
from .dispatcher import LocalTaskDispatcher, TaskDispatcher
from .executor import InvestigationBoundWorkExecutor, WorkExecutor
from .graph import (
    AuthorizeWithoutPivotError,
    CoordinatorDependencyError,
    InvestigationGraphBindingConflictError,
    InvestigationGraphContextMismatchError,
    MissingCoordinatorDecisionError,
    OrchestrationGraphState,
    StopWithoutReasonError,
    UnknownCoordinatorActionError,
    build_investigation_graph,
    build_legacy_investigation_graph,
)
from .models import (
    authorize_pivot,
    enqueue_provider_work,
    finalize_stop_state,
    record_analysis,
    record_provider_outcome,
    select_next_provider_work,
    select_provider_work,
)
from .provider_executor import (
    EntityReader,
    ProviderExecutionContext,
    ProviderWorkExecutor,
    UowEntityReader,
)
from .runner import (
    InvestigationRunner,
    InvestigationRunnerLifecycleError,
    InvestigationRunnerPersistenceMismatchError,
    LocalInvestigationRunner,
)
from .services import (
    CoordinatorContextLoader,
    CoordinatorTransitionService,
    EvidenceAnalystAnalysisExecutor,
    InvestigationStatusWriter,
    UowCoordinatorContextLoader,
    UowCoordinatorTransitionService,
    UowInvestigationStatusWriter,
)
from .timeline_actions import (
    ACTION_ASSESSMENT_REQUESTED,
    ACTION_ENTITY_DISCOVERED,
    ACTION_INVESTIGATION_STOPPED,
    ACTION_PIVOT_ENQUEUED,
    ACTION_PIVOT_EXECUTED,
    ACTION_PIVOT_SKIPPED,
    ACTION_PROVIDER_QUERY,
    DeterministicTimelineActionService,
    TimelineActionService,
    convert_timeline_actions,
)

__all__ = [
    "WorkExecutor",
    "TaskDispatcher",
    "LocalTaskDispatcher",
    "InvestigationBoundWorkExecutor",
    "OrchestrationGraphState",
    "InvestigationGraphContextMismatchError",
    "InvestigationGraphBindingConflictError",
    "CoordinatorDependencyError",
    "MissingCoordinatorDecisionError",
    "UnknownCoordinatorActionError",
    "StopWithoutReasonError",
    "AuthorizeWithoutPivotError",
    "ProviderExecutionContext",
    "ProviderWorkExecutor",
    "InvestigationRunner",
    "InvestigationRunnerLifecycleError",
    "InvestigationRunnerPersistenceMismatchError",
    "LocalInvestigationRunner",
    "EntityReader",
    "UowEntityReader",
    "build_investigation_graph",
    "build_legacy_investigation_graph",
    "build_provider_investigation_graph",
    "PROVIDER_SOURCE_ORDER",
    "enqueue_provider_work",
    "record_provider_outcome",
    "select_next_provider_work",
    "select_provider_work",
    "authorize_pivot",
    "finalize_stop_state",
    "record_analysis",
    "CoordinatorAction",
    "CoordinatorDecision",
    "CoordinatorEntityView",
    "CoordinatorPolicy",
    "CoordinatorPolicyContext",
    "AnalysisExecutor",
    "AnalysisOutcome",
    "FakeAnalysisExecutor",
    "MappingProviderWorkPlanner",
    "PivotRejection",
    "PivotRejectionReason",
    "ProviderWorkPlanner",
    "CoordinatorContextLoader",
    "CoordinatorTransitionService",
    "EvidenceAnalystAnalysisExecutor",
    "InvestigationStatusWriter",
    "UowCoordinatorContextLoader",
    "UowCoordinatorTransitionService",
    "UowInvestigationStatusWriter",
    "ACTION_PROVIDER_QUERY",
    "ACTION_ENTITY_DISCOVERED",
    "ACTION_PIVOT_ENQUEUED",
    "ACTION_PIVOT_EXECUTED",
    "ACTION_PIVOT_SKIPPED",
    "ACTION_ASSESSMENT_REQUESTED",
    "ACTION_INVESTIGATION_STOPPED",
    "DeterministicTimelineActionService",
    "TimelineActionService",
    "convert_timeline_actions",
]
