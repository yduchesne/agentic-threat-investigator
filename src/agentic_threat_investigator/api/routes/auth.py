# SPDX-License-Identifier: AGPL-3.0-only
"""Public authentication routes: login, logout, me.

Login issues HttpOnly session and double-submit CSRF cookies; the raw
session token is never returned in JSON and only its SHA-256 digest is
persisted. Logout revokes the server-side session, expires both cookies,
and is idempotent. ``/me`` resolves the session to the public user DTO.
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from agentic_threat_investigator.api.auth_constants import (
    COOKIE_NAME,
    CSRF_COOKIE,
    CSRF_TOKEN_HEADER,
)
from agentic_threat_investigator.api.dependencies import (
    CurrentUser,
    authentication_service,
)
from agentic_threat_investigator.api.dto.auth import (
    AuthenticatedUserResponse,
    LoginRequest,
)
from agentic_threat_investigator.api.errors import (
    ApiError,
    ApiErrorCode,
    map_typed_error,
)
from agentic_threat_investigator.api.middleware import read_session_cookie
from agentic_threat_investigator.app.identity import (
    AuthenticationService,
    CsrfError,
    validate_csrf,
)
from agentic_threat_investigator.domain.identity import User

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _to_user_response(user: User) -> AuthenticatedUserResponse:
    """Map the authenticated user without exposing credential/session data."""
    return AuthenticatedUserResponse(id=user.id, alias=user.username, role=user.role)


@router.post(
    "/login",
    response_model=AuthenticatedUserResponse,
    status_code=status.HTTP_200_OK,
    operation_id="auth_login",
)
async def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    service: Annotated[AuthenticationService, Depends(authentication_service)],
) -> AuthenticatedUserResponse:
    """Authenticate and issue HttpOnly session and CSRF cookies."""
    try:
        user, token = await service.login(
            payload.username,
            payload.password.get_secret_value(),
            client_address=request.client.host if request.client else None,
        )
    except Exception as error:
        raise map_typed_error(error) from error
    settings = request.app.state.settings
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
        max_age=settings.session_absolute_expiry_seconds,
    )
    response.set_cookie(
        CSRF_COOKIE,
        secrets.token_urlsafe(32),
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    return _to_user_response(user)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="auth_logout",
)
async def logout(
    request: Request,
    response: Response,
    service: Annotated[AuthenticationService, Depends(authentication_service)],
) -> None:
    """Validate CSRF and revoke the current session, then expire cookies.

    An already-invalid logout is idempotent and still returns ``204``.
    """
    session = read_session_cookie(request)
    if session:
        settings = request.app.state.settings
        try:
            validate_csrf(
                request.cookies.get(CSRF_COOKIE),
                request.headers.get(CSRF_TOKEN_HEADER),
                request.headers.get("origin"),
                request.headers.get("referer"),
                settings.public_base_url,
            )
        except CsrfError as error:
            raise ApiError(
                ApiErrorCode.FORBIDDEN, "CSRF validation failed.", 403
            ) from error
        await service.logout(session)
    response.delete_cookie(COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


@router.get(
    "/me",
    response_model=AuthenticatedUserResponse,
    operation_id="auth_me",
)
async def me(user: CurrentUser) -> AuthenticatedUserResponse:
    """Return the public identity of the authenticated actor."""
    return _to_user_response(user)
