# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the concrete OpenAI chat-model composition (PR 20B)."""

from typing import Any, cast

import pytest
from pydantic import BaseModel, SecretStr

from agentic_threat_investigator.app.llm import LlmClient
from agentic_threat_investigator.app.secrets import SecretNotFoundError, SecretsResolver
from agentic_threat_investigator.config import settings_from_config
from agentic_threat_investigator.config.settings import LlmDriver, Settings
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


def test_blank_base_url_does_not_override_sdk_endpoint() -> None:
    """C01: an omitted/blank base URL leaves the SDK endpoint untouched."""
    settings = _settings(llm_base_url="")
    secrets = _StaticSecretsResolver({_FAKE_KEY_SECRET_NAME: "sk-fake-key"})

    model = build_openai_chat_model(settings, secrets)

    assert model.model_dump()["openai_api_base"] is None


@pytest.mark.parametrize(
    "base_url",
    [
        "https://api.openai.com/v1",  # C02: OpenAI explicit URL
        "https://openrouter.ai/api/v1",  # C03: OpenRouter URL
        "http://localhost:8001/v1",  # C04: arbitrary compatible URL
    ],
)
def test_custom_base_url_reaches_chat_model(base_url: str) -> None:
    """C02-C04: an explicit base URL reaches ChatOpenAI exactly."""
    settings = _settings(llm_base_url=base_url)
    secrets = _StaticSecretsResolver({_FAKE_KEY_SECRET_NAME: "sk-fake-key"})

    model = build_openai_chat_model(settings, secrets)

    assert model.model_dump()["openai_api_base"] == base_url


def test_custom_endpoint_with_custom_secret_reference() -> None:
    """C05: a custom endpoint plus custom secret reference both apply."""
    custom_reference = "ATI_OPENROUTER_API_KEY"
    settings = _settings(
        llm_base_url="https://openrouter.ai/api/v1",
        llm_api_key_secret=custom_reference,
    )

    model = build_openai_chat_model(
        settings, _StaticSecretsResolver({custom_reference: "sk-openrouter"})
    )

    assert model.model_dump()["openai_api_base"] == "https://openrouter.ai/api/v1"
    assert cast(SecretStr, model.openai_api_key).get_secret_value() == "sk-openrouter"


def test_custom_endpoint_with_missing_secret_fails_at_composition_time() -> None:
    """C06: a custom endpoint with a missing key still fails closed."""
    custom_reference = "ATI_OPENROUTER_API_KEY"
    settings = _settings(
        llm_base_url="https://openrouter.ai/api/v1",
        llm_api_key_secret=custom_reference,
    )

    with pytest.raises(SecretNotFoundError) as holder:
        build_openai_chat_model(settings, _StaticSecretsResolver({}))

    assert holder.value.name == custom_reference


def test_custom_endpoint_with_blank_resolved_secret_fails_at_composition_time() -> None:
    """C07: a blank resolved key fails even when an endpoint is configured."""
    custom_reference = "ATI_OPENROUTER_API_KEY"
    settings = _settings(
        llm_base_url="https://openrouter.ai/api/v1",
        llm_api_key_secret=custom_reference,
    )

    with pytest.raises(SecretNotFoundError):
        build_openai_chat_model(
            settings, _StaticSecretsResolver({custom_reference: "   "})
        )


def test_optional_max_tokens_preserved_with_custom_endpoint() -> None:
    """C08: the optional token cap is preserved alongside a custom endpoint."""
    settings = _settings(llm_base_url="https://llm.example.test/v1", llm_max_tokens=300)
    secrets = _StaticSecretsResolver({_FAKE_KEY_SECRET_NAME: "sk-fake-key"})

    model = build_openai_chat_model(settings, secrets)
    dumped = model.model_dump()

    assert dumped["openai_api_base"] == "https://llm.example.test/v1"
    assert dumped["max_tokens"] == 300


def test_existing_model_arguments_preserved_with_custom_endpoint() -> None:
    """C09: retry/streaming/timeout/temperature are unchanged with a custom endpoint."""
    settings = _settings(llm_base_url="https://llm.example.test/v1")
    secrets = _StaticSecretsResolver({_FAKE_KEY_SECRET_NAME: "sk-fake-key"})

    model = build_openai_chat_model(settings, secrets)
    dumped = model.model_dump()

    assert dumped["openai_api_base"] == "https://llm.example.test/v1"
    assert dumped["model_name"] == "gpt-4o-mini"
    assert dumped["temperature"] == 0.0
    assert dumped["request_timeout"] == 45.0
    assert dumped["max_retries"] == 0
    assert dumped["disable_streaming"] is True
    assert cast(SecretStr, model.openai_api_key).get_secret_value() == "sk-fake-key"


def test_observed_client_wraps_delegate_with_bounded_metadata() -> None:
    """PR 29B: the common observing wrapper carries bounded model metadata."""
    from agentic_threat_investigator.app.llm_observability import (
        ObservedLlmClient,
    )
    from agentic_threat_investigator.infrastructure.llm.composition import (
        build_observed_llm_client,
    )
    from agentic_threat_investigator.infrastructure.observability.noop import (
        NoOpLlmObservability,
    )

    class _Delegate(LlmClient):
        """Minimal delegate double."""

        async def generate_structured(
            self,
            *,
            system_prompt: str,
            user_prompt: str,
            response_model: type[BaseModel],
            operation_name: str,
        ) -> Any:
            del system_prompt, user_prompt, response_model, operation_name
            raise AssertionError("must not be invoked")

    settings = _settings()
    observed = build_observed_llm_client(
        delegate=_Delegate(),
        observability=NoOpLlmObservability(),
        settings=settings,
    )
    assert isinstance(observed, ObservedLlmClient)
    assert observed._model_name == "gpt-4o-mini"
    assert observed._model_provider == "openai"


def test_observed_client_deterministic_driver_label() -> None:
    """The deterministic driver maps to a bounded provider label."""
    from agentic_threat_investigator.infrastructure.llm.composition import (
        build_observed_llm_client,
    )
    from agentic_threat_investigator.infrastructure.observability.noop import (
        NoOpLlmObservability,
    )

    class _Delegate(LlmClient):
        """Minimal delegate double."""

        async def generate_structured(
            self,
            *,
            system_prompt: str,
            user_prompt: str,
            response_model: type[BaseModel],
            operation_name: str,
        ) -> Any:
            del system_prompt, user_prompt, response_model, operation_name
            raise AssertionError("must not be invoked")

    settings = _settings(llm_driver=LlmDriver.DETERMINISTIC)
    observed = build_observed_llm_client(
        delegate=_Delegate(),
        observability=NoOpLlmObservability(),
        settings=settings,
    )
    assert observed._model_provider == "deterministic"


def test_observed_client_label_stable_with_custom_endpoint() -> None:
    """A custom endpoint never becomes an unbounded telemetry provider label."""
    from agentic_threat_investigator.infrastructure.llm.composition import (
        build_observed_llm_client,
    )
    from agentic_threat_investigator.infrastructure.observability.noop import (
        NoOpLlmObservability,
    )

    class _Delegate(LlmClient):
        """Minimal delegate double."""

        async def generate_structured(
            self,
            *,
            system_prompt: str,
            user_prompt: str,
            response_model: type[BaseModel],
            operation_name: str,
        ) -> Any:
            del system_prompt, user_prompt, response_model, operation_name
            raise AssertionError("must not be invoked")

    settings = _settings(llm_base_url="https://openrouter.ai/api/v1")
    observed = build_observed_llm_client(
        delegate=_Delegate(),
        observability=NoOpLlmObservability(),
        settings=settings,
    )
    assert observed._model_provider == "openai"
    assert observed._model_name == "gpt-4o-mini"


def test_deterministic_driver_ignores_configured_base_url() -> None:
    """A configured base URL never affects the deterministic driver.

    The deterministic boundary (PR 24B) must compose successfully with no LLM
    provider secret available and no ``ChatOpenAI`` construction even when an
    OpenAI-compatible endpoint is configured (PR 30A step 3.3).
    """
    from agentic_threat_investigator.app.llm_observability import ObservedLlmClient
    from agentic_threat_investigator.cli import _compose_llm
    from agentic_threat_investigator.infrastructure.llm.deterministic import (
        DeterministicLlmClient,
    )

    settings = _settings(
        llm_driver=LlmDriver.DETERMINISTIC,
        llm_base_url="https://openrouter.ai/api/v1",
    )
    composed = _compose_llm(settings)
    assert isinstance(composed, ObservedLlmClient)
    assert isinstance(composed._delegate, DeterministicLlmClient)
