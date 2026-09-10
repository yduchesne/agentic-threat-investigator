# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the concrete OpenAI chat-model composition (PR 20B)."""

from typing import cast

import pytest
from pydantic import SecretStr

from agentic_threat_investigator.app.secrets import SecretNotFoundError, SecretsResolver
from agentic_threat_investigator.config import settings_from_config
from agentic_threat_investigator.config.settings import Settings
from agentic_threat_investigator.infrastructure.llm.composition import (
    build_openai_chat_model,
)

_FAKE_KEY_SECRET_NAME = "ATI_OPENAI_API_KEY"


class _StaticSecretsResolver(SecretsResolver):
    """Deterministic resolver backed by an in-memory mapping."""

    def __init__(self, values: dict[str, str]) -> None:
        """Initialize with the resolved reference-value mapping."""
        self._values = values

    def get(self, name: str) -> str | None:
        """Return the mapping value for a reference name."""
        return self._values.get(name)


def _settings(**overrides: object) -> Settings:
    """Build Settings with the LLM fields overridden as needed."""
    kwargs: dict[str, object] = {
        "llm_model": "gpt-4o-mini",
        "llm_timeout_seconds": 45.0,
        "llm_max_structured_output_attempts": 2,
        "llm_temperature": 0.0,
        "llm_api_key_secret": _FAKE_KEY_SECRET_NAME,
        "llm_max_tokens": 300,
    }
    kwargs.update(overrides)
    return settings_from_config(kwargs)


def test_openai_model_composed_with_deterministic_settings() -> None:
    """Composition maps settings onto the provider model construction."""
    settings = _settings()
    secrets = _StaticSecretsResolver({_FAKE_KEY_SECRET_NAME: "sk-fake-key"})

    model = build_openai_chat_model(settings, secrets)

    dumped = model.model_dump()
    assert dumped["model_name"] == "gpt-4o-mini"
    assert dumped["temperature"] == 0.0
    assert dumped["request_timeout"] == 45.0
    assert dumped["max_tokens"] == 300
    assert dumped["max_retries"] == 0
    assert dumped["disable_streaming"] is True
    assert cast(SecretStr, model.openai_api_key).get_secret_value() == "sk-fake-key"


def test_max_tokens_omitted_when_unset() -> None:
    """An unset token cap is not passed to the provider."""
    settings = _settings(llm_max_tokens=None)
    secrets = _StaticSecretsResolver({_FAKE_KEY_SECRET_NAME: "sk-fake-key"})

    model = build_openai_chat_model(settings, secrets)

    assert model.max_tokens is None


def test_missing_key_fails_at_composition_time() -> None:
    """A missing/blank configured key raises before model construction."""
    settings = _settings()

    with pytest.raises(SecretNotFoundError) as holder:
        build_openai_chat_model(settings, _StaticSecretsResolver({}))

    assert holder.value.name == _FAKE_KEY_SECRET_NAME


def test_blank_key_fails_at_composition_time() -> None:
    """A whitespace-only resolved key is treated as unresolved."""
    settings = _settings()

    with pytest.raises(SecretNotFoundError):
        build_openai_chat_model(
            settings, _StaticSecretsResolver({_FAKE_KEY_SECRET_NAME: "   "})
        )


def test_custom_secret_reference_is_used() -> None:
    """The configured secret reference name drives resolution."""
    custom_reference = "ATI_MY_PROVIDER_KEY"
    settings = _settings(llm_api_key_secret=custom_reference)

    model = build_openai_chat_model(
        settings, _StaticSecretsResolver({custom_reference: "sk-resolved"})
    )

    assert cast(SecretStr, model.openai_api_key).get_secret_value() == "sk-resolved"
