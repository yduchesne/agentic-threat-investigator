# SPDX-License-Identifier: AGPL-3.0-only
"""Concrete LLM-observability backends and their composition.

Backends translate the portable :class:`LlmObservability` contract onto
vendor-specific APIs. Application and domain code never import these modules
directly; they depend only on the ``app.llm_observability`` boundary.
"""

from agentic_threat_investigator.infrastructure.observability.composition import (
    build_llm_observability,
)
from agentic_threat_investigator.infrastructure.observability.langfuse import (
    LangfuseLlmObservability,
)
from agentic_threat_investigator.infrastructure.observability.langsmith import (
    LangSmithLlmObservability,
)
from agentic_threat_investigator.infrastructure.observability.noop import (
    NoOpLlmObservability,
)

__all__ = [
    "LangfuseLlmObservability",
    "LangSmithLlmObservability",
    "NoOpLlmObservability",
    "build_llm_observability",
]
