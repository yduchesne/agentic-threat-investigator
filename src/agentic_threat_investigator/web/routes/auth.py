# SPDX-License-Identifier: AGPL-3.0-only
"""HTML authentication routes sharing ATI's one session authority.

Login calls the same :class:`AuthenticationService` as the JSON API and
issues the same session/CSRF cookie semantics. Logout validates a
form-compatible double-submit CSRF proof, revokes the same server-side
session, and expires both cookies. No JavaScript is required to sign in.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Request
from starlette.responses import RedirectResponse, Response

from agentic_threat_investigator.api.auth_constants import COOKIE_NAME, CSRF_COOKIE
from agentic_threat_investigator.api.session_cookies import (
    clear_auth_cookies,
    set_csrf_cookie,
    set_session_cookie,
)
from agentic_threat_investigator.app.identity import (
    AuthenticationError,
    CsrfError,
    RateLimitedError,
)
from agentic_threat_investigator.web.dependencies import (
    authentication_from_request,
    optional_web_user,
    templates_from_request,
)
from agentic_threat_investigator.web.errors import WebError
from agentic_threat_investigator.web.security import (
    safe_next_path,
    settings_from_request,
    validate_web_csrf,
)
from agentic_threat_investigator.web.viewmodels.shell import login_view_model

router = APIRouter(include_in_schema=False)

_INVALID_CREDENTIALS_MESSAGE = "Invalid username or password."
_RATE_LIMITED_MESSAGE = "Too many attempts. Please wait and try again."


async def _read_form(request: Request) -> dict[str, str]:
    """Extract bounded text form fields, or fail with a bounded 400.

    The web adapter deliberately does not rely on FastAPI ``Form``
    parameters: a non-form body or malformed body must map to a bounded HTML
    error, never a JSON validation envelope or a traceback.
    """
    content_type = request.headers.get("content-type", "")
    if not (
        content_type.startswith("application/x-www-form-urlencoded")
        or content_type.startswith("multipart/form-data")
    ):
        raise WebError(400, "Invalid request", "The form submission is malformed.")
    try:
        form = await request.form()
    except Exception as error:
        raise WebError(
            400, "Invalid request", "The form submission is malformed."
        ) from error
    fields: dict[str, str] = {}
    for name in ("username", "password", "csrf_token", "next"):
        value = form.get(name)
        fields[name] = value if isinstance(value, str) else ""
    return fields


def _render_login_error(
    request: Request, *, message: str, next_path: str, status_code: int
) -> Response:
    """Re-render the login page with a bounded error and no credential echo."""
    templates = templates_from_request(request)
    existing = request.cookies.get(CSRF_COOKIE)
    token = existing or secrets.token_urlsafe(32)
    response = templates.render(
        request,
        "auth/login.html",
        {
            "view": login_view_model(csrf_token=token, error=message),
            "next_path": next_path,
        },
    )
    response.status_code = status_code
    if existing is None:
        set_csrf_cookie(response, settings_from_request(request), token)
    return response


@router.get("/login")
async def login_form(request: Request) -> Response:
    """Render the login form, or redirect an already-authenticated actor."""
    next_path = safe_next_path(request.query_params.get("next"))
    user = await optional_web_user(request)
    if user is not None:
        return RedirectResponse(next_path, status_code=303)
    templates = templates_from_request(request)
    existing = request.cookies.get(CSRF_COOKIE)
    token = existing or secrets.token_urlsafe(32)
    response = templates.render(
        request,
        "auth/login.html",
        {"view": login_view_model(csrf_token=token), "next_path": next_path},
    )
    if existing is None:
        set_csrf_cookie(response, settings_from_request(request), token)
    return response


@router.post("/login")
async def login_submit(request: Request) -> Response:
    """Authenticate and issue the same session/CSRF cookies as the API."""
    form = await _read_form(request)
    next_path = safe_next_path(form["next"])
    try:
        validate_web_csrf(request, form["csrf_token"])
    except CsrfError as error:
        raise WebError(
            403, "Forbidden", "The request could not be verified."
        ) from error

    service = authentication_from_request(request)
    try:
        user, token = await service.login(
            form["username"],
            form["password"],
            client_address=request.client.host if request.client else None,
        )
    except RateLimitedError:
        return _render_login_error(
            request,
            message=_RATE_LIMITED_MESSAGE,
            next_path=next_path,
            status_code=429,
        )
    except AuthenticationError:
        return _render_login_error(
            request,
            message=_INVALID_CREDENTIALS_MESSAGE,
            next_path=next_path,
            status_code=401,
        )

    settings = settings_from_request(request)
    response = RedirectResponse(next_path, status_code=303)
    set_session_cookie(response, settings, token)
    set_csrf_cookie(response, settings, secrets.token_urlsafe(32))
    return response


@router.post("/logout")
async def logout(request: Request) -> Response:
    """Validate CSRF, revoke the session, expire cookies, and redirect home."""
    form = await _read_form(request)
    try:
        validate_web_csrf(request, form["csrf_token"])
    except CsrfError as error:
        raise WebError(
            403, "Forbidden", "The request could not be verified."
        ) from error

    service = authentication_from_request(request)
    session = request.cookies.get(COOKIE_NAME)
    if session:
        await service.logout(session)
    response = RedirectResponse("/login", status_code=303)
    clear_auth_cookies(response)
    return response
