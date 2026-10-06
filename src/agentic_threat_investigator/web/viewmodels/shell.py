# SPDX-License-Identifier: AGPL-3.0-only
"""Typed view models for the authenticated shell and login presentation.

These are immutable, presentation-only structures. They expose the safe
public identity (alias/role/display name) and never the session token,
credential, or any persistence identity beyond what the human UI requires.
Building them is a presentation concern; domain/application policy stays in
the services the routes call.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ShellViewModel:
    """Safe presentation data for the authenticated shell."""

    title: str
    username: str
    role: str
    display_name: str | None
    operating_mode: str
    render_id: str
    csrf_token: str
    htmx_enabled: bool = True


@dataclass(frozen=True, slots=True)
class LoginViewModel:
    """Safe presentation data for the unauthenticated login page."""

    title: str
    csrf_token: str
    error: str | None = None


def shell_view_model(
    *,
    username: str,
    role: str,
    display_name: str | None,
    operating_mode: str,
    render_id: str,
    csrf_token: str,
) -> ShellViewModel:
    """Build the immutable authenticated-shell view model."""
    return ShellViewModel(
        title="ATI",
        username=username,
        role=role,
        display_name=display_name,
        operating_mode=operating_mode,
        render_id=render_id,
        csrf_token=csrf_token,
    )


def login_view_model(*, csrf_token: str, error: str | None = None) -> LoginViewModel:
    """Build the immutable login view model."""
    return LoginViewModel(title="ATI", csrf_token=csrf_token, error=error)
