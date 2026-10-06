# SPDX-License-Identifier: AGPL-3.0-only
"""Shared HTTP cookie semantics for ATI's session/CSRF authority.

One session authority and one double-submit CSRF transport are shared by the
JSON ``api/`` and the server-rendered ``web/`` presentation adapters
(V07-01). This module is the single source of truth for cookie names and
security attributes so the two adapters cannot drift: the session cookie is
always HttpOnly + SameSite=Lax (+ Secure when configured), and the CSRF
cookie is always browser-readable because it is the double-submit proof.
"""

from __future__ import annotations

from starlette.responses import Response

from agentic_threat_investigator.api.auth_constants import COOKIE_NAME, CSRF_COOKIE
from agentic_threat_investigator.config import Settings


def set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    """Issue the HttpOnly session cookie with the configured security flags."""
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
        max_age=settings.session_absolute_expiry_seconds,
    )


def set_csrf_cookie(response: Response, settings: Settings, token: str) -> None:
    """Issue the browser-readable double-submit CSRF cookie."""
    response.set_cookie(
        CSRF_COOKIE,
        token,
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    """Expire both authentication cookies on the stable root path."""
    response.delete_cookie(COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
