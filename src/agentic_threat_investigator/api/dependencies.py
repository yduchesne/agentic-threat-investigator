# SPDX-License-Identifier: AGPL-3.0-only
"""Centralized API dependencies: authentication, authorization, CSRF, reads.

Dependencies resolve services from ``request.app.state`` so unit/route tests
inject fakes and the production application installs real compositions
without any route importing concrete persistence classes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Annotated, cast

from fastapi import Depends, Request

from agentic_threat_investigator.api.auth_constants import (
    COOKIE_NAME,
    CSRF_COOKIE,
    CSRF_TOKEN_HEADER,
)
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.app.identity import (
    AuthenticationService,
    CsrfError,
    validate_csrf,
)
from agentic_threat_investigator.app.query.services import QueryServiceBundle
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.domain.identity import User, UserRole


def _settings(request: Request) -> Settings:
    """Resolve the configured settings from the application state."""
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        raise ApiError(
            ApiErrorCode.DEPENDENCY_UNAVAILABLE,
            "Application settings are unavailable.",
            503,
        )
    return cast(Settings, settings)


def authentication_service(request: Request) -> AuthenticationService:
    """Resolve the authentication service installed by bootstrap."""
    service = getattr(request.app.state, "authentication", None)
    if service is None:
        raise ApiError(
            ApiErrorCode.DEPENDENCY_UNAVAILABLE,
            "Authentication is unavailable.",
            503,
        )
    return cast(AuthenticationService, service)


async def current_user(request: Request) -> User:
    """Resolve the authenticated actor from the session cookie.

    An absent, expired, revoked, or disabled session is indistinguishable at
    the public boundary: all map to ``401 authentication_required``.
    """
    service = authentication_service(request)
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise ApiError(
            ApiErrorCode.AUTHENTICATION_REQUIRED,
            "Authentication is required.",
            401,
        )
    user = await service.validate_session(token)
    if user is None:
        raise ApiError(
            ApiErrorCode.AUTHENTICATION_REQUIRED,
            "Authentication is required.",
            401,
        )
    request.state.actor_id = str(user.id)
    return user


def require_analyst(user: Annotated[User, Depends(current_user)]) -> User:
    """Require an ANALYST or ADMIN actor for analytical endpoints."""
    if user.role not in (UserRole.ANALYST, UserRole.ADMIN):
        raise ApiError(ApiErrorCode.FORBIDDEN, "Access is forbidden.", 403)
    return user


def csrf_protected(request: Request) -> None:
    """Require a valid double-submit CSRF proof for state-changing requests.

    The double-submit cookie token must equal the ``X-CSRF-Token`` request
    header, and the request Origin/Referer must match the configured public
    origin. SameSite=Lax/Strict cookies plus exact configured CORS origins
    are the preferred SPA policy; cross-origin mutations fail closed.
    """
    settings = _settings(request)
    cookie_token = request.cookies.get(CSRF_COOKIE)
    request_token = request.headers.get(CSRF_TOKEN_HEADER)
    try:
        validate_csrf(
            cookie_token,
            request_token,
            request.headers.get("origin"),
            request.headers.get("referer"),
            settings.public_base_url,
        )
    except CsrfError as error:
        raise ApiError(
            ApiErrorCode.FORBIDDEN, "CSRF validation failed.", 403
        ) from error


async def query_services(request: Request) -> AsyncIterator[QueryServiceBundle]:
    """Yield one read-session query bundle and close it after the request.

    Each request owns its own short-lived read session; sessions are never
    shared or cached across requests.
    """
    factory = getattr(request.app.state, "query_services_factory", None)
    if factory is None:
        raise ApiError(
            ApiErrorCode.DEPENDENCY_UNAVAILABLE,
            "Query services are unavailable.",
            503,
        )
    services = cast(Callable[[], QueryServiceBundle], factory)()
    try:
        yield services
    finally:
        await services.close()


def submission_service(request: Request) -> object:
    """Resolve the Investigation submission service installed by bootstrap."""
    service = getattr(request.app.state, "submission_service", None)
    if service is None:
        raise ApiError(
            ApiErrorCode.DEPENDENCY_UNAVAILABLE,
            "Investigation submission is unavailable.",
            503,
        )
    return service


CurrentUser = Annotated[User, Depends(current_user)]
AnalystUser = Annotated[User, Depends(require_analyst)]
QueryServices = Annotated[QueryServiceBundle, Depends(query_services)]
