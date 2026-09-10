# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation orchestration (PR 19A skeleton + PR 19B/19C execution dispatch).

The package owns typed work orchestration contracts, the deterministic PR 19A
workflow skeleton that depends only on the ``TaskDispatcher`` boundary, the PR
19B real provider execution adapter, and the PR 19C task dispatch
contracts/local dispatch with its production composition factory. Because
``LocalTaskDispatcher`` is the single explicit executor-to-dispatcher
adapter, callers/composition must construct it around a ``WorkExecutor``;
the graph never accepts or adapts executors directly. The package performs
no provider-selection policy, budget enforcement, LLM behavior, adaptive
pivots, jobs, or workers.
"""

from .composition import build_provider_investigation_graph
from .dispatcher import LocalTaskDispatcher, TaskDispatcher
from .executor import InvestigationBoundWorkExecutor, WorkExecutor
from .graph import (
    InvestigationGraphBindingConflictError,
    InvestigationGraphContextMismatchError,
    OrchestrationGraphState,
    build_investigation_graph,
)
from .models import (
    enqueue_provider_work,
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

__all__ = [
    "WorkExecutor",
    "TaskDispatcher",
    "LocalTaskDispatcher",
    "InvestigationBoundWorkExecutor",
    "OrchestrationGraphState",
    "InvestigationGraphContextMismatchError",
    "InvestigationGraphBindingConflictError",
    "ProviderExecutionContext",
    "ProviderWorkExecutor",
    "EntityReader",
    "UowEntityReader",
    "build_investigation_graph",
    "build_provider_investigation_graph",
    "enqueue_provider_work",
    "record_provider_outcome",
    "select_next_provider_work",
    "select_provider_work",
]
