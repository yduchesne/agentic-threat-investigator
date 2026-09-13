# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for PR 20B LLM settings and secret-reference semantics."""

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from agentic_threat_investigator.config import load_config, settings_from_config


class TestLlmSettings:
    """LLM setting defaults and validation."""

    def test_defaults(self) -> None:
        """Default LLM settings are accepted and bounded."""
        settings = settings_from_config({})
        assert settings.llm_model == "gpt-4o-mini"
        assert settings.llm_timeout_seconds == 60.0
        assert settings.llm_max_structured_output_attempts == 2
        assert settings.llm_api_key_secret == "ATI_OPENAI_API_KEY"
        assert settings.llm_temperature == 0.0
        assert settings.llm_max_tokens is None
        assert settings.llm_max_evidence_items == 100
        assert settings.llm_max_relationship_observations == 200
        assert settings.llm_max_normalized_facts_bytes == 131_072
        assert settings.llm_max_input_bytes == 262_144

    def test_profile_defaults_include_llm_keys(self) -> None:
        """The default profile declares the non-secret LLM settings."""
        config = load_config()
        assert config["llm_model"] == "gpt-4o-mini"
        assert config["llm_timeout_seconds"] == 60.0
        assert config["llm_max_structured_output_attempts"] == 2
        assert config["llm_temperature"] == 0.0
        assert config["llm_max_tokens"] is None
        assert config["llm_max_evidence_items"] == 100
        assert config["llm_max_relationship_observations"] == 200
        assert config["llm_max_normalized_facts_bytes"] == 131_072
        assert config["llm_max_input_bytes"] == 262_144
        # Secret REFERENCES live in Settings defaults, never in profiles.
        assert "llm_api_key_secret" not in config

    def test_default_profile_contains_no_secret_values(self) -> None:
        """No committed profile may ever carry an API key value."""
        settings = settings_from_config({})
        key = settings.llm_api_key_secret
        assert "sk-" not in key
        assert key == "ATI_OPENAI_API_KEY"

    def test_api_key_secret_reference_environment(
        self, monkeypatch: MonkeyPatch
    ) -> None:
        """The secret-reference name is configurable by environment."""
        monkeypatch.setenv("ATI_LLM_API_KEY_SECRET", "MY_CUSTOM_LLM_KEY_VAR")
        settings = settings_from_config({})
        assert settings.llm_api_key_secret == "MY_CUSTOM_LLM_KEY_VAR"

    def test_blank_model_rejected(self) -> None:
        """A blank model identifier is rejected."""
        with pytest.raises(ValidationError, match="blank"):
            settings_from_config({"llm_model": "   "})

    def test_blank_secret_reference_rejected(self) -> None:
        """A blank secret-reference name is rejected."""
        with pytest.raises(ValidationError, match="blank"):
            settings_from_config({"llm_api_key_secret": "   "})

    def test_llm_driver_defaults_to_openai(self) -> None:
        """Absent driver selects the safe real-model default (PR 24B)."""
        settings = settings_from_config({})
        assert settings.llm_driver.value == "openai"

    def test_llm_driver_deterministic_is_accepted(self) -> None:
        """The explicit deterministic driver parses to the typed enum value."""
        settings = settings_from_config({"llm_driver": "deterministic"})
        assert settings.llm_driver.value == "deterministic"

    def test_llm_driver_openai_is_accepted(self) -> None:
        """The explicit openai driver parses to the typed enum value."""
        settings = settings_from_config({"llm_driver": "openai"})
        assert settings.llm_driver.value == "openai"

    @pytest.mark.parametrize("value", ["unknown", "", "   ", "DETERMINISTIC"])
    def test_llm_driver_unknown_fails_closed(self, value: str) -> None:
        """Unknown or blank driver values fail validation; no silent fallback."""
        with pytest.raises(ValidationError):
            settings_from_config({"llm_driver": value})

    def test_profile_never_pins_the_llm_driver(self) -> None:
        """The driver is an env-resolved operational selection, never a profile key.

        Like ``operating_mode``, pinning ``llm_driver`` in a profile would
        silently override ``ATI_LLM_DRIVER``; the offline deterministic E2E
        worker relies on the environment variable.
        """
        config = load_config()
        assert "llm_driver" not in config

    def test_llm_driver_env_override(self, monkeypatch: MonkeyPatch) -> None:
        """``ATI_LLM_DRIVER=deterministic`` selects the offline boundary."""
        monkeypatch.setenv("ATI_LLM_DRIVER", "deterministic")
        settings = settings_from_config({})
        assert settings.llm_driver.value == "deterministic"

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("llm_max_structured_output_attempts", 0),
            ("llm_max_structured_output_attempts", 3),
            ("llm_max_structured_output_attempts", 4),
            ("llm_max_structured_output_attempts", 2.5),
            ("llm_max_structured_output_attempts", True),
            ("llm_max_evidence_items", 0),
            ("llm_max_evidence_items", 501),
            ("llm_max_evidence_items", True),
            ("llm_max_relationship_observations", 0),
            ("llm_max_relationship_observations", 1001),
            ("llm_max_normalized_facts_bytes", 999),
            ("llm_max_normalized_facts_bytes", 1_000_001),
            ("llm_max_input_bytes", 999),
            ("llm_max_input_bytes", 1_000_001),
        ],
    )
    def test_bounded_integer_settings_reject_invalid_values(
        self, field: str, value: object
    ) -> None:
        """Integer LLM settings enforce their documented bounds and types."""
        with pytest.raises(ValidationError):
            settings_from_config({field: value})

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("llm_timeout_seconds", 0),
            ("llm_timeout_seconds", -5),
            ("llm_timeout_seconds", float("nan")),
            ("llm_timeout_seconds", float("inf")),
            ("llm_timeout_seconds", True),
            ("llm_temperature", -0.1),
            ("llm_temperature", 2.1),
            ("llm_temperature", True),
        ],
    )
    def test_bounded_real_settings_reject_invalid_values(
        self, field: str, value: object
    ) -> None:
        """Real LLM settings reject non-finite, out-of-range, or boolean values."""
        with pytest.raises(ValidationError):
            settings_from_config({field: value})

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("llm_max_tokens", 0),
            ("llm_max_tokens", -1),
            ("llm_max_tokens", True),
        ],
    )
    def test_optional_max_tokens_rejects_invalid_values(
        self, field: str, value: object
    ) -> None:
        """The optional token cap must be a positive integer when set."""
        with pytest.raises(ValidationError):
            settings_from_config({field: value})
