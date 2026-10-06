# SPDX-License-Identifier: AGPL-3.0-only
"""Protected proof-shell routes for the server-rendered web adapter (V07-01).

These routes prove the architecture: they authenticate against the same
:class:`AuthenticationService`, resolve the same actor, build one typed view
model, and render either a complete document or an HTMX fragment from that
view model. No analyst workflow is migrated here.
"""

from __future__ import annotations

import secrets
from urllib.parse import quote

from fastapi import APIRouter, Request
from starlette.responses import RedirectResponse, Response

from agentic_threat_investigator.api.auth_constants import CSRF_COOKIE
from agentic_threat_investigator.api.session_cookies import set_csrf_cookie
from agentic_threat_investigator.domain.identity import User
from agentic_threat_investigator.web.dependencies import (
    optional_web_user,
    templates_from_request,
)
from agentic_threat_investigator.web.rendering import (
    HTMX_REDIRECT_HEADER,
    is_htmx_request,
)
from agentic_threat_investigator.web.security import settings_from_request
from agentic_threat_investigator.web.viewmodels.shell import (
    ShellViewModel,
    shell_view_model,
)

router = APIRouter(include_in_schema=False)


def login_redirect(request: Request, next_path: str) -> Response:
    """Redirect an unauthenticated request to the login page safely.

    An HTMX request receives an ``HX-Redirect`` response so htmx performs a
    full browser navigation instead of swapping a login document into a
    fragment target. This is representation only; the request was already
    treated as unauthenticated.
    """
    target = f"/login?next={quote(next_path, safe='/')}"
    if is_htmx_request(request):
        response = Response(status_code=204)
        response.headers[HTMX_REDIRECT_HEADER] = target
        return response
    return RedirectResponse(target, status_code=303)


def build_shell_view_model(request: Request, user: User) -> tuple[ShellViewModel, bool]:
    """Build the shell view model and report whether a CSRF cookie was absent.

    The authenticated shell embeds a CSRF-proofed logout form. A session
    created through the JSON API may legitimately lack the browser CSRF
    cookie; a safe GET issues one using the shared cookie semantics rather
    than rendering an unusable form.
    """
    settings = settings_from_request(request)
    existing = request.cookies.get(CSRF_COOKIE)
    token = existing or secrets.token_urlsafe(32)
    view = shell_view_model(
        username=user.username,
        role=user.role.value,
        display_name=user.display_name,
        operating_mode=settings.operating_mode.value,
        render_id=str(getattr(request.state, "request_id", "") or ""),
        csrf_token=token,
    )
    return view, existing is None


def _render_shell(
    request: Request, user: User, page_name: str, fragment_name: str
) -> Response:
    """Render the shell page or fragment from one shared view model."""
    view, issued_csrf = build_shell_view_model(request, user)
    response = templates_from_request(request).render_page_or_fragment(
        request, page_name, fragment_name, {"view": view}
    )
    if issued_csrf:
        set_csrf_cookie(response, settings_from_request(request), view.csrf_token)
    return response


@router.get("/")
async def home(request: Request) -> Response:
    """Render the protected authenticated shell (full document or fragment)."""
    user = await optional_web_user(request)
    if user is None:
        return login_redirect(request, "/")
    return _render_shell(request, user, "shell/page.html", "shell/_content.html")


@router.get("/partials/connection")
async def connection_status(request: Request) -> Response:
    """Return the harmless connection card as a fragment or full fallback.

    The ordinary-GET form is a complete document, so the enhanced anchor on
    the shell has a coherent no-JavaScript HTTP fallback.
    """
    user = await optional_web_user(request)
    if user is None:
        return login_redirect(request, "/partials/connection")
    return _render_shell(request, user, "shell/page.html", "shell/_connection.html")
