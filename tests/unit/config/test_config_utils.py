# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for configuration profile loading and safe logging."""

import logging
from collections.abc import Callable
from types import ModuleType
from typing import Any

import pytest

from agentic_threat_investigator.config.config_utils import (
    ConfigModuleError,
    ConfigProfileNotFoundError,
    _redact_config,
    load_config,
    override,
)


def module(name: str, config: object = None, *, expose: bool = True) -> ModuleType:
    """Build a synthetic profile module for loader tests."""
    result = ModuleType(name)
    if expose:
        result.CONFIG = config  # type: ignore[attr-defined]
    return result


def loader(
    default: dict[str, Any], profile: ModuleType | None = None
) -> Callable[[str], ModuleType]:
    """Build an import seam containing the default and optional profile."""
    modules = {
        "agentic_threat_investigator.config.config_default": module("default", default)
    }
    if profile is not None:
        modules[profile.__name__] = profile

    def import_module(name: str) -> ModuleType:
        try:
            return modules[name]
        except KeyError as exc:
            raise ModuleNotFoundError(name=name) from exc

    return import_module


@pytest.mark.parametrize(
    ("original", "replacement", "expected"),
    [
        ({}, {}, {}),
        ({"a": 1}, {"b": True}, {"a": 1, "b": True}),
        ({"a": 1}, {"a": 2}, {"a": 2}),
    ],
)
def test_override_cases(
    original: dict[str, Any], replacement: dict[str, Any], expected: dict[str, Any]
) -> None:
    """Override is a shallow, non-mutating merge."""
    original_copy = original.copy()
    replacement_copy = replacement.copy()
    assert override(original, replacement) == expected
    assert original == original_copy
    assert replacement == replacement_copy


def test_override_preserves_heterogeneous_values_and_replaces_nested() -> None:
    """Nested values are replaced rather than recursively merged."""
    original = {"nested": {"old": 1}, "float": 1.5}
    replacement = {"nested": {"new": 2}, "enabled": True}
    assert override(original, replacement) == {
        "nested": {"new": 2},
        "float": 1.5,
        "enabled": True,
    }


@pytest.mark.parametrize(
    "profile",
    ["../prod", "ati.other.module", "config-prod", "/dev/null", "Dev", "1dev"],
)
def test_invalid_profile_is_rejected_before_import(profile: str) -> None:
    """Profile values cannot become arbitrary import paths."""
    called = False

    def importing(_: str) -> ModuleType:
        nonlocal called
        called = True
        raise AssertionError("loader should not be called")

    with pytest.raises(ValueError, match="profile grammar"):
        load_config({"ATI_CONFIG_PROFILE": profile}, importing)
    assert not called


def test_default_blank_and_profile_merge() -> None:
    """Missing and blank profiles select default; valid profiles override it."""
    default = {"stable": 1, "nested": {"default": True}}
    assert load_config({}, loader(default)) == default
    assert load_config({"ATI_CONFIG_PROFILE": "   "}, loader(default)) == default
    profile_name = "agentic_threat_investigator.config.config_dev"
    profile = module(profile_name, {"nested": {"profile": True}, "new": 2})
    assert load_config({"ATI_CONFIG_PROFILE": "dev"}, loader(default, profile)) == {
        "stable": 1,
        "nested": {"profile": True},
        "new": 2,
    }


def test_missing_and_malformed_profiles() -> None:
    """Missing profiles and malformed modules fail explicitly."""
    with pytest.raises(ConfigProfileNotFoundError) as caught:
        load_config({"ATI_CONFIG_PROFILE": "nope"}, loader({}))
    assert isinstance(caught.value.__cause__, ModuleNotFoundError)

    profile_name = "agentic_threat_investigator.config.config_dev"
    for malformed in [
        module(profile_name, expose=False),
        module(profile_name, []),
        module(profile_name, {1: "bad"}),
    ]:
        with pytest.raises(ConfigModuleError):
            load_config({"ATI_CONFIG_PROFILE": "dev"}, loader({}, malformed))


def test_import_failure_propagates() -> None:
    """Failures from an existing module are not mislabeled as missing."""

    def importing(name: str) -> ModuleType:
        if name.endswith("config_default"):
            return module(name, {})
        raise RuntimeError("broken profile")

    with pytest.raises(RuntimeError, match="broken profile"):
        load_config({"ATI_CONFIG_PROFILE": "dev"}, importing)


def test_redaction_is_recursive_and_case_insensitive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """All sensitive values are redacted without changing the source."""
    config = {
        "DB_PASSWORD": "secret",
        "provider": {"Session_Secret": "x", "ok": 1},
        "items": [{"API_KEY": "y"}],
    }
    before = {
        "DB_PASSWORD": "secret",
        "provider": {"Session_Secret": "x", "ok": 1},
        "items": [{"API_KEY": "y"}],
    }
    redacted = _redact_config(config)
    assert redacted["DB_PASSWORD"] == "<redacted>"
    assert redacted["provider"]["Session_Secret"] == "<redacted>"
    assert redacted["items"][0]["API_KEY"] == "<redacted>"
    assert config == before
    with caplog.at_level(logging.INFO):
        load_config({}, loader(config))
    assert "secret" not in caplog.text
    assert "configuration.loaded" in caplog.text


def test_default_result_is_a_copy() -> None:
    """Mutating one load result does not mutate the profile module."""
    seam = loader({"value": 1})
    first = load_config({}, seam)
    first["value"] = 2
    assert load_config({}, seam)["value"] == 1
