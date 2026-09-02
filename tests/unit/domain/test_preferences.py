# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for user preferences."""

from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.preferences import UiTheme, UserPreferences


def test_preferences_default_to_darknite() -> None:
    """Preferences without an explicit theme use DARKNITE."""

    preferences = UserPreferences(user_id=uuid4())

    assert preferences.ui_theme == UiTheme.DARKNITE


def test_ui_theme_values_are_stable() -> None:
    """The three confirmed themes are the complete set."""

    assert {theme.value for theme in UiTheme} == {
        "darknite",
        "brightlight",
        "wargames",
    }


def test_preferences_accept_every_theme() -> None:
    """Any confirmed theme can be stored on preferences."""

    for theme in UiTheme:
        preferences = UserPreferences(user_id=uuid4(), ui_theme=theme)

        assert preferences.ui_theme is theme


def test_preferences_require_user_id() -> None:
    """Preferences are invalid without their owning user."""

    with pytest.raises(ValidationError):
        UserPreferences(ui_theme=UiTheme.WARGAMES)  # type: ignore[call-arg]


def test_preferences_reject_unknown_themes() -> None:
    """Unknown theme strings are rejected."""

    with pytest.raises(ValidationError):
        UserPreferences(user_id=uuid4(), ui_theme="neon")  # type: ignore[arg-type]
