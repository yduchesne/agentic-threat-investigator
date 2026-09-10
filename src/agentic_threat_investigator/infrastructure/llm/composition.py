# SPDX-License-Identifier: AGPL-3.0-only
"""Settings-driven composition of the concrete v0.1 LLM provider.

Composition resolves the API key through the ``SecretsResolver`` bootstrap
contract and constructs the OpenAI chat model with deterministic analysis
configuration (temperature 0, streaming disabled, and no hidden
LangChain/provider retry layers). Configuration carries only the secret
reference name; the resolved key is injected here and never stored, logged,
or embedded in prompts.
"""

from __future__ import annotations

from typing import Any

from langchain_openai import ChatOpenAI

from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config.settings import Settings


def build_openai_chat_model(settings: Settings, secrets: SecretsResolver) -> ChatOpenAI:
    """Construct the configured OpenAI chat model for v0.1.

    A missing or blank configured key raises ``SecretNotFoundError`` here,
    at composition time, before any model object is created.
    """
    api_key = secrets.require(settings.llm_api_key_secret)
    kwargs: dict[str, Any] = {
        "model_name": settings.llm_model,
        "openai_api_key": api_key,
        "temperature": settings.llm_temperature,
        "request_timeout": settings.llm_timeout_seconds,
        # No hidden retry layers: PR 20B retry policy is explicit and
        # accounted at the application service boundary.
        "max_retries": 0,
        "disable_streaming": True,
    }
    if settings.llm_max_tokens is not None:
        kwargs["max_tokens"] = settings.llm_max_tokens
    return ChatOpenAI(**kwargs)
