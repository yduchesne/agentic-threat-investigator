# SPDX-License-Identifier: AGPL-3.0-only
"""PR 29A LLM-observability configuration tests (settings-level behavior)."""

from __future__ import annotations

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from agentic_threat_investigator.config import (
    LlmObservabilityBackend,
    load_config,
    settings_from_config,
)


class TestObservabilityDefaults:
    """Default observability configuration is safe and backend-neutral."""

    def test_master_switch_defaults_disabled(self) -> None:
        """Absent configuration leaves observability disabled (safe default)."""
        settings = settings_from_config({})
        assert settings.observability_enabled is False

    def test_backend_defaults_to_none(self) -> None:
        """Absent configuration selects the none backend."""
        settings = settings_from_config({})
        assert settings.llm_observability_backend is LlmObservabilityBackend.NONE

    def test_langfuse_secret_reference_defaults(self) -> None:
        """Langfuse settings default to non-blank reference names and a blank URL."""
        settings = settings_from_config({})
        assert settings.langfuse_public_key_secret == "ATI_LANGFUSE_PUBLIC_KEY"
        assert settings.langfuse_secret_key_secret == "ATI_LANGFUSE_SECRET_KEY"
        assert settings.langfuse_base_url == ""

    def test_profile_never_pins_the_backend(self) -> None:
        """The backend is an env-resolved operational selection, never a profile key."""
        config = load_config()
        assert "llm_observability_backend" not in config
        assert "observability_enabled" not in config


class TestBackendSelection:
    """Typed backend selection (CFG1-CFG4)."""

    def test_none_backend_valid_without_credentials(self) -> None:
        """backend=none is valid and requires no vendor configuration."""
        settings = settings_from_config({"llm_observability_backend": "none"})
        assert settings.llm_observability_backend is LlmObservabilityBackend.NONE

    def test_langsmith_backend_is_valid_typed_enum(self) -> None:
        """backend=langsmith parses to the typed enum value."""
        settings = settings_from_config({"llm_observability_backend": "langsmith"})
        assert settings.llm_observability_backend is LlmObservabilityBackend.LANGSMITH

    def test_langfuse_backend_is_valid_typed_enum(self) -> None:
        """backend=langfuse parses to the typed enum value."""
        settings = settings_from_config({"llm_observability_backend": "langfuse"})
        assert settings.llm_observability_backend is LlmObservabilityBackend.LANGFUSE

    @pytest.mark.parametrize("value", ["bogus", "", "   ", "LANGFUSE", "x"])
    def test_unknown_backend_fails_closed(self, value: str) -> None:
        """Unknown or blank backend values fail validation; no silent fallback."""
        with pytest.raises(ValidationError):
            settings_from_config({"llm_observability_backend": value})

    def test_env_override(self, monkeypatch: MonkeyPatch) -> None:
        """The backend is selectable through ATI_LLM_OBSERVABILITY_BACKEND."""
        monkeypatch.setenv("ATI_LLM_OBSERVABILITY_BACKEND", "langfuse")
        settings = settings_from_config({})
        assert settings.llm_observability_backend is LlmObservabilityBackend.LANGFUSE


class TestLangfuseValidation:
    """Langfuse URL and secret-reference validation (CFG8/CFG9)."""

    def test_blank_public_key_secret_rejected(self) -> None:
        """A blank public-key secret reference is rejected (CFG8)."""
        with pytest.raises(ValidationError, match="langfuse_public_key_secret"):
            settings_from_config({"langfuse_public_key_secret": "   "})

    def test_blank_secret_key_secret_rejected(self) -> None:
        """A blank secret-key reference is rejected (CFG8)."""
        with pytest.raises(ValidationError, match="langfuse_secret_key_secret"):
            settings_from_config({"langfuse_secret_key_secret": "   "})

    def test_valid_https_base_url_accepted(self) -> None:
        """An HTTPS Langfuse base URL without credentials is accepted."""
        settings = settings_from_config(
            {"langfuse_base_url": "https://cloud.langfuse.com"}
        )
        assert settings.langfuse_base_url == "https://cloud.langfuse.com"

    def test_base_url_with_credentials_rejected(self) -> None:
        """A base URL embedding credentials is rejected (CFG9)."""
        with pytest.raises(ValidationError, match="credentials"):
            settings_from_config(
                {"langfuse_base_url": "https://user:pass@cloud.langfuse.com"}
            )

    def test_non_http_scheme_rejected(self) -> None:
        """Only http/https schemes are accepted for the Langfuse base URL."""
        with pytest.raises(ValidationError, match="http or https"):
            settings_from_config({"langfuse_base_url": "ftp://cloud.langfuse.com"})
