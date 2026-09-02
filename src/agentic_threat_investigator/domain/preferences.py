# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Typed presentation preferences for one user.

Each User has exactly one :class:`UserPreferences` instance, and each instance
belongs to exactly one User. Persistence enforces this by using ``user_id`` as
both the ``user_preference`` table's primary key and a foreign key to the
User table; the preference row is created transactionally with its User so
application code does not need to interpret a missing row as a second
preference state.
"""

from enum import Enum
from uuid import UUID

from pydantic import BaseModel


class UiTheme(str, Enum):
    """Available UI presentation themes."""

    DARKNITE = "darknite"
    BRIGHTLIGHT = "brightlight"
    WARGAMES = "wargames"


class UserPreferences(BaseModel):
    """The typed, mutable collection of presentation preferences for one user.

    Updating preferences changes presentation only and has no effect on
    evidence, research, assessment, authorization, or investigation behavior.
    Preferences remain associated with a soft-deleted User for historical and
    restoration consistency; normal application queries exclude preferences
    whose User is deleted.
    """

    user_id: UUID
    ui_theme: UiTheme = UiTheme.DARKNITE
