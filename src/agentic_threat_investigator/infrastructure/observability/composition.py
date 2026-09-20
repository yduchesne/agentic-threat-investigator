# SPDX-License-Identifier: AGPL-3.0-only
"""Composition of the selected LLM-observability backend (PR 29A).

Backend selection is configuration-driven and exactly one of
``langsmith``/``langfuse``/``none``. Vendor secrets are resolved only for the
selected, active backend, so unselected-backend secret absence never fails
composition. With the master observability switch disabled, or with any
backend selected while disabled, composition yields the NoOp backend.
"""

from __future__ import annotations

from agentic_threat_investigator.app.llm_observability import LlmObservability
from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config.settings import (
    LlmObservabilityBackend,
    Settings,
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


def build_llm_observability(
    settings: Settings,
    secrets: SecretsResolver,
) -> LlmObservability:
    """Compose the configured LLM-observability backend.

    When the master observability switch is disabled, or when the selected
    backend is ``none``, the NoOp backend is returned and no vendor credential
    is resolved. Otherwise secrets are resolved only for the selected backend;
    a missing required secret for the active backend fails composition with
    ``SecretNotFoundError`` before any runtime work begins.
    """
    if not settings.observability_enabled:
        return NoOpLlmObservability()
    backend = settings.llm_observability_backend
    if backend is LlmObservabilityBackend.NONE:
        return NoOpLlmObservability()
    if backend is LlmObservabilityBackend.LANGSMITH:
        return LangSmithLlmObservability()
    if backend is LlmObservabilityBackend.LANGFUSE:
        # Required only when Langfuse is the active, master-enabled backend.
        public_key = secrets.require(settings.langfuse_public_key_secret)
        secret_key = secrets.require(settings.langfuse_secret_key_secret)
        return LangfuseLlmObservability(
            public_key=public_key,
            secret_key=secret_key,
            base_url=settings.langfuse_base_url or None,
        )
    # The closed enum guarantees this branch is unreachable for valid settings.
    raise AssertionError(f"unsupported LLM observability backend: {backend.value}")


__all__ = ["build_llm_observability"]
