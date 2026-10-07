# SPDX-License-Identifier: AGPL-3.0-only
"""Web-form CSRF and safe-redirect adapters over the shared security core.

This is not a second CSRF algorithm. Ordinary HTML forms cannot set the
API's ``X-CSRF-Token`` header, so the web adapter accepts the identical
double-submit proof from a hidden ``csrf_token`` form field and then calls
the one shared :func:`validate_csrf` implementation against the same exact
approved-origin collection. HTMX submissions carry the same proof.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from fastapi import Request
from starlette.responses import Response

from agentic_threat_investigator.api.auth_constants import (
    CSRF_COOKIE,
    CSRF_TOKEN_HEADER,
)
from agentic_threat_investigator.api.session_cookies import set_csrf_cookie
from agentic_threat_investigator.app.identity import CsrfError, validate_csrf
from agentic_threat_investigator.config import Settings

MAX_REDIRECT_LENGTH = 2048
"""Upper bound on an accepted ATI-local return path."""


def settings_from_request(request: Request) -> Settings:
    """Return the composed settings, or raise a bounded error if absent."""
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        from agentic_threat_investigator.web.errors import WebError

        raise WebError(503, "Service unavailable", "The service is unavailable.")
    return settings  # type: ignore[no-any-return]


def validate_web_csrf(request: Request, form_token: str | None) -> None:
    """Validate the shared double-submit proof for a web mutation.

    The proof may arrive as the hidden ``csrf_token`` form field or as the
    existing ``X-CSRF-Token`` header (HTMX may submit either). It is always
    compared against the ``ati_csrf`` cookie and the request Origin/Referer
    against the exact approved origin set.
    """
    settings = settings_from_request(request)
    proof = form_token or request.headers.get(CSRF_TOKEN_HEADER)
    validate_csrf(
        request.cookies.get(CSRF_COOKIE),
        proof,
        request.headers.get("origin"),
        request.headers.get("referer"),
        settings.csrf_allowed_origins,
    )


def issue_csrf_cookie(request: Request, response: Response) -> str:
    """Return the current CSRF proof, issuing a cookie when absent.

    A browser's first ``GET /login`` has no CSRF cookie yet; the form still
    needs a double-submit value. Issuing a fresh token here uses the same
    cookie semantics as the API. An existing cookie is never rotated by a
    safe GET.
    """
    settings = settings_from_request(request)
    existing = request.cookies.get(CSRF_COOKIE)
    if existing:
        return existing
    token = secrets.token_urlsafe(32)
    set_csrf_cookie(response, settings, token)
    return token


def safe_next_path(value: str | None, *, default: str = "/") -> str:
    """Return a safe ATI-local relative redirect target.

    Only same-origin server-relative paths are accepted. Absolute URLs,
    scheme-relative ``//host`` targets, and backslash tricks are rejected so
    a crafted return target can never become an open redirect.
    """
    if not value:
        return default
    candidate = value.strip()
    if not candidate or len(candidate) > MAX_REDIRECT_LENGTH:
        return default
    if not candidate.startswith("/") or candidate.startswith("//"):
        return default
    if "\\" in candidate or any(char in candidate for char in ("\r", "\n")):
        return default
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        return default
    return candidate


__all__ = [
    "CsrfError",
    "issue_csrf_cookie",
    "safe_next_path",
    "settings_from_request",
    "validate_web_csrf",
]
