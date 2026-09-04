# SPDX-License-Identifier: AGPL-3.0-only
"""Contract-pinned local authentication endpoints."""

# The module-level dependency is replaced by application bootstrap.
# pylint: disable=global-statement,too-many-arguments,too-many-positional-arguments,broad-exception-caught
import secrets
from typing import Annotated

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field

from agentic_threat_investigator.app.identity import (
    AuthenticationError,
    AuthenticationService,
    CsrfError,
    validate_csrf,
)
from agentic_threat_investigator.config import get_settings
from agentic_threat_investigator.domain.audit import AuditAction, AuditOutcome
from agentic_threat_investigator.domain.identity import User

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
_authentication: AuthenticationService | None = None
COOKIE_NAME = "ati_session"
CSRF_COOKIE = "ati_csrf"


def configure_authentication(service: AuthenticationService) -> None:
    """Install the application service during process dependency construction."""
    global _authentication
    _authentication = service


def _service() -> AuthenticationService:
    """Return configured authentication or fail safely."""
    if _authentication is None:
        raise HTTPException(status_code=503, detail="authentication is unavailable")
    return _authentication


class LoginRequest(BaseModel):
    """Public login request DTO."""

    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class UserResponse(BaseModel):
    """Public authenticated-user DTO."""

    id: str
    username: str
    display_name: str | None
    role: str

    @classmethod
    def from_domain(cls, user: User) -> "UserResponse":
        """Convert a domain user without exposing credential/session data."""
        return cls(
            id=str(user.id),
            username=user.username,
            display_name=user.display_name,
            role=user.role.value,
        )


class LoginResponse(BaseModel):
    """Public login response DTO."""

    user: UserResponse


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    response: Response,
    service: Annotated[AuthenticationService, Depends(_service)],
) -> LoginResponse:
    """Authenticate and issue HttpOnly session and CSRF cookies."""
    try:
        user, token = await service.login(payload.username, payload.password)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=get_settings().session_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        secrets.token_urlsafe(32),
        httponly=False,
        secure=get_settings().session_cookie_secure,
        samesite="lax",
        path="/",
    )
    return LoginResponse(user=UserResponse.from_domain(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    service: Annotated[AuthenticationService, Depends(_service)],
    session: str | None = Cookie(default=None, alias=COOKIE_NAME),
    csrf: str | None = Cookie(default=None, alias=CSRF_COOKIE),
    x_csrf_token: str | None = Header(default=None),
) -> None:
    """Validate CSRF and revoke the current session."""
    if session:
        try:
            validate_csrf(
                csrf,
                x_csrf_token,
                request.headers.get("origin"),
                request.headers.get("referer"),
                str(request.base_url).rstrip("/"),
            )
        except CsrfError as exc:
            try:
                await service.audit.emit(
                    AuditAction.AUTH_CSRF_REJECTED, AuditOutcome.DENIED
                )
            except Exception:  # audit failure must not alter the security response
                pass
            raise HTTPException(
                status_code=403, detail="CSRF validation failed"
            ) from exc
        await service.logout(session)
    response.delete_cookie(COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


@router.get("/me", response_model=UserResponse)
async def me(
    service: Annotated[AuthenticationService, Depends(_service)],
    session: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> UserResponse:
    """Return the user represented by the current session."""
    if not session:
        raise HTTPException(status_code=401, detail="authentication required")
    user = await service.validate_session(session)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return UserResponse.from_domain(user)
