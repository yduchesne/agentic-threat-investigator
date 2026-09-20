# SPDX-License-Identifier: AGPL-3.0-only
"""LLM-observability composition factory tests (PR 29A)."""

from __future__ import annotations

import pytest

from agentic_threat_investigator.app.secrets import (
    EnvVarSecretsResolver,
    SecretNotFoundError,
)
from agentic_threat_investigator.config import settings_from_config
from agentic_threat_investigator.infrastructure.observability import (
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

_EMPTY_ENV: dict[str, str] = {}
_LANGFUSE_ENV = {
    "ATI_LANGFUSE_PUBLIC_KEY": "lf-pk",
    "ATI_LANGFUSE_SECRET_KEY": "lf-sk",
}


def _resolver(env: dict[str, str]) -> EnvVarSecretsResolver:
    """Return a deterministic env-backed secret resolver."""
    return EnvVarSecretsResolver(env=env)


class TestComposition:
    """Backend selection maps configuration to the correct adapter."""

    def test_backend_none_yields_noop(self) -> None:
        """backend=none always yields NoOp, even when master is enabled."""
        settings = settings_from_config(
            {
                "observability_enabled": True,
                "llm_observability_backend": "none",
            }
        )
        assert isinstance(
            build_llm_observability(settings, _resolver(_EMPTY_ENV)),
            NoOpLlmObservability,
        )

    def test_master_disabled_langsmith_yields_noop(self) -> None:
        """Master disabled + LangSmith yields NoOp with no secret lookup."""
        settings = settings_from_config(
            {
                "observability_enabled": False,
                "llm_observability_backend": "langsmith",
            }
        )
        assert isinstance(
            build_llm_observability(settings, _resolver(_EMPTY_ENV)),
            NoOpLlmObservability,
        )

    def test_master_disabled_langfuse_yields_noop(self) -> None:
        """Master disabled + Langfuse yields NoOp with no secret lookup."""
        settings = settings_from_config(
            {
                "observability_enabled": False,
                "llm_observability_backend": "langfuse",
            }
        )
        assert isinstance(
            build_llm_observability(settings, _resolver(_EMPTY_ENV)),
            NoOpLlmObservability,
        )

    def test_langsmith_selected_composes_langsmith(self) -> None:
        """Master enabled + LangSmith composes exactly the LangSmith adapter."""
        settings = settings_from_config(
            {
                "observability_enabled": True,
                "llm_observability_backend": "langsmith",
            }
        )
        assert isinstance(
            build_llm_observability(settings, _resolver(_EMPTY_ENV)),
            LangSmithLlmObservability,
        )

    def test_langfuse_selected_composes_langfuse(self) -> None:
        """Master enabled + Langfuse resolves keys and composes Langfuse."""
        settings = settings_from_config(
            {
                "observability_enabled": True,
                "llm_observability_backend": "langfuse",
            }
        )
        assert isinstance(
            build_llm_observability(settings, _resolver(_LANGFUSE_ENV)),
            LangfuseLlmObservability,
        )

    def test_langfuse_selected_missing_secret_fails_safely(self) -> None:
        """A missing selected-backend secret fails composition safely (LLMO6)."""
        settings = settings_from_config(
            {
                "observability_enabled": True,
                "llm_observability_backend": "langfuse",
            }
        )
        with pytest.raises(SecretNotFoundError):
            build_llm_observability(settings, _resolver(_EMPTY_ENV))

    def test_unselected_backend_secret_absent_is_ignored(self) -> None:
        """An unselected backend's missing secret never fails composition (LLMO7)."""
        settings = settings_from_config(
            {
                "observability_enabled": True,
                "llm_observability_backend": "langsmith",
            }
        )
        # Langfuse secrets are absent; composing LangSmith must not care.
        assert isinstance(
            build_llm_observability(settings, _resolver(_EMPTY_ENV)),
            LangSmithLlmObservability,
        )
