# SPDX-License-Identifier: AGPL-3.0-only
"""Web presentation dependencies resolved from ``request.app.state``.

The web adapter resolves the same in-process :class:`AuthenticationService`
and query services installed by the API composition. It never calls ATI's
REST API over HTTP to reach functionality already available in-process.
"""

from __future__ import annotations

from typing import cast

from fastapi import Request

from agentic_threat_investigator.api.auth_constants import COOKIE_NAME
from agentic_threat_investigator.app.identity import AuthenticationService
from agentic_threat_investigator.domain.identity import User
from agentic_threat_investigator.web.errors import WebError
from agentic_threat_investigator.web.rendering import WebTemplates


def authentication_from_request(request: Request) -> AuthenticationService:
    """Resolve the shared authentication service installed at bootstrap."""
    service = getattr(request.app.state, "authentication", None)
    if service is None:
        raise WebError(503, "Service unavailable", "Authentication is unavailable.")
    return cast(AuthenticationService, service)


def templates_from_request(request: Request) -> WebTemplates:
    """Resolve the installed Jinja template environment."""
    templates = getattr(request.app.state, "web_templates", None)
    if templates is None:
        raise WebError(503, "Service unavailable", "Web templates are unavailable.")
    return cast(WebTemplates, templates)


async def optional_web_user(request: Request) -> User | None:
    """Resolve the current actor, or ``None`` when unauthenticated.

    Absent, expired, revoked, and disabled sessions are intentionally
    indistinguishable: all resolve to ``None`` and the route maps that to a
    safe login redirect.
    """
    service = authentication_from_request(request)
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    user = await service.validate_session(token)
    if user is None:
        return None
    request.state.actor_id = str(user.id)
    return user
