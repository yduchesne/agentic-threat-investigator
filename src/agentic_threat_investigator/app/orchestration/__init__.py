# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation orchestration (PR 19A deterministic LangGraph skeleton).

The package owns typed work orchestration contracts and deterministic
workflow logic. It performs no real provider calls, persistence, LLM
behavior, adaptive pivots, or budget-enforcement policy; those belong to
PR 19B and PR 21.
"""

from .executor import WorkExecutor
from .graph import OrchestrationGraphState, build_investigation_graph
from .models import (
    enqueue_provider_work,
    record_provider_outcome,
    select_next_provider_work,
    select_provider_work,
)

__all__ = [
    "WorkExecutor",
    "OrchestrationGraphState",
    "build_investigation_graph",
    "enqueue_provider_work",
    "record_provider_outcome",
    "select_next_provider_work",
    "select_provider_work",
]
