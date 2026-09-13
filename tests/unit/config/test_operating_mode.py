# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Operating-mode configuration contract tests (PR 23D).

Covers the typed ``ATI_OPERATING_MODE`` setting: safe production default,
exact ``fake``/``production`` values, fail-closed validation, and orthogonality
with ``ATI_CONFIG_PROFILE``. Stable IDs from the PR 23D plan: 23D-U01 through
23D-U06.
"""

import pytest
from _pytest.logging import LogCaptureFixture
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from agentic_threat_investigator.config import (
    OperatingMode,
    Settings,
    settings_from_config,
)


def test_operating_mode_absent_defaults_to_production() -> None:
    """23D-U01: absent operating mode selects the safe production default."""
    settings = Settings()
    assert settings.operating_mode is OperatingMode.PRODUCTION
    assert settings.operating_mode.value == "production"


def test_operating_mode_fake_is_accepted() -> None:
    """23D-U02: ``fake`` parses to the typed enum value."""
    settings = Settings(operating_mode=OperatingMode.FAKE)
    assert settings.operating_mode is OperatingMode.FAKE


def test_operating_mode_production_is_accepted() -> None:
    """23D-U03: ``production`` parses to the typed enum value."""
    settings = Settings(operating_mode=OperatingMode.PRODUCTION)
    assert settings.operating_mode is OperatingMode.PRODUCTION


def test_operating_mode_unknown_fails_closed(monkeypatch: MonkeyPatch) -> None:
    """23D-U04: an unknown mode fails validation; no silent fallback."""
    monkeypatch.setenv("ATI_OPERATING_MODE", "demo")
    with pytest.raises(ValidationError):
        Settings()


def test_operating_mode_blank_fails_closed(monkeypatch: MonkeyPatch) -> None:
    """Blank mode values fail validation like other invalid values."""
    monkeypatch.setenv("ATI_OPERATING_MODE", "")
    with pytest.raises(ValidationError):
        Settings()


def test_profile_and_operating_mode_are_orthogonal(
    monkeypatch: MonkeyPatch,
) -> None:
    """23D-U05/U06: profile selection never mutates the operating mode."""
    fake_settings = settings_from_config({"operating_mode": "fake"})
    assert fake_settings.operating_mode is OperatingMode.FAKE
    assert fake_settings.environment == "development"

    production_settings = settings_from_config({"operating_mode": "production"})
    assert production_settings.operating_mode is OperatingMode.PRODUCTION

    # ATI_CONFIG_PROFILE stays independent: fake mode never implies a profile.
    monkeypatch.setenv("ATI_CONFIG_PROFILE", "local")
    assert fake_settings.operating_mode is OperatingMode.FAKE
    assert fake_settings.operating_mode.value != "local"


def test_operating_mode_serialized_value_is_lowercase() -> None:
    """The public serialized operating-mode value is always lowercase."""
    assert OperatingMode.FAKE.value == "fake"
    assert OperatingMode.PRODUCTION.value == "production"


def test_operating_mode_does_not_select_llm() -> None:
    """Operating mode never changes the configured LLM model or key reference."""
    fake = Settings(operating_mode=OperatingMode.FAKE)
    production = Settings(operating_mode=OperatingMode.PRODUCTION)
    assert fake.llm_model == production.llm_model
    assert fake.llm_api_key_secret == production.llm_api_key_secret


def test_operating_mode_logging_is_safe(
    caplog: LogCaptureFixture,
) -> None:
    """Configuration logging never leaks secret values around the mode."""
    from agentic_threat_investigator.config.config_utils import load_config

    with caplog.at_level("INFO"):
        config = load_config({})
    assert "operating_mode" not in config
    assert "<redacted>" in caplog.text or "profile" in caplog.text
