# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for typed configuration injection and caching."""

import pytest
from _pytest.logging import LogCaptureFixture
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from agentic_threat_investigator.config import (
    Settings,
    ensure_test_database_safe,
    get_settings,
    settings_from_config,
)


def test_profile_values_pin_fields_over_environment(
    monkeypatch: MonkeyPatch,
) -> None:
    """Constructor-injected profile values win over ATI environment values."""
    monkeypatch.setenv("ATI_LOG_LEVEL", "WARNING")
    assert settings_from_config({"log_level": "DEBUG"}).log_level == "DEBUG"


def test_unpinned_fields_remain_environment_injectable(
    monkeypatch: MonkeyPatch,
) -> None:
    """Fields absent from profiles still use the environment bridge."""
    monkeypatch.setenv("ATI_SESSION_COOKIE_SECURE", "true")
    assert settings_from_config({}).session_cookie_secure is True


def test_unknown_keys_are_ignored(caplog: LogCaptureFixture) -> None:
    """Forward-compatible profile keys are warned about and ignored."""
    settings = settings_from_config({"future_setting": 1})
    assert isinstance(settings, Settings)
    assert "unrecognized configuration keys" in caplog.text


def test_typed_validation_is_not_silenced() -> None:
    """Invalid profile values fail typed settings construction."""
    with pytest.raises(ValidationError):
        settings_from_config({"db_batch_size": "many"})


def test_get_settings_is_cached(monkeypatch: MonkeyPatch) -> None:
    """Bootstrap settings are loaded once per process cache lifetime."""
    get_settings.cache_clear()
    monkeypatch.setenv("ATI_CONFIG_PROFILE", "dev")
    first = get_settings()
    second = get_settings()
    assert first is second
    get_settings.cache_clear()


def test_test_database_guard() -> None:
    """The integration safety guard accepts only marked URLs."""
    ensure_test_database_safe("postgresql://host/ati-test")
    with pytest.raises(ValueError):
        ensure_test_database_safe("postgresql://host/ati")
