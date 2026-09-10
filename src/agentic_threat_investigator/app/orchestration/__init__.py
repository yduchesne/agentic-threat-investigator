# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation orchestration (PR 19A skeleton + PR 19B provider execution).

The package owns typed work orchestration contracts, the deterministic PR 19A
workflow skeleton, and the PR 19B real provider execution adapter with its
production composition factory. It performs no provider-selection policy,
budget enforcement, LLM behavior, adaptive pivots, jobs, or workers.
"""

from .composition import build_provider_investigation_graph
from .executor import WorkExecutor
from .graph import (
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
    "OrchestrationGraphState",
    "InvestigationGraphContextMismatchError",
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
