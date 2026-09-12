# SPDX-License-Identifier: AGPL-3.0-only
"""Request-ID, security-header, and structured-request-log middleware.

Every request receives a bounded request ID. A caller-supplied
``X-Request-ID`` is honored only when it matches a strict length/character
contract; otherwise a fresh ID is generated. The ID is returned in the
``X-Request-ID`` response header and included in every error envelope.

Security headers (``X-Content-Type-Options: nosniff`` and
``Cache-Control: no-store`` for API responses) are applied centrally.
Structured request logging emits request ID, method, route template, status,
duration, and authenticated actor ID only — never passwords, cookies,
session tokens, auth headers, idempotency keys, provider payloads, or SQL
parameters.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Awaitable, Callable
from typing import TypeGuard
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from agentic_threat_investigator.api.auth_constants import (
    COOKIE_NAME,
    REQUEST_ID_HEADER,
)

LOGGER = logging.getLogger(__name__)

REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
MAX_REQUEST_ID_LENGTH = 128

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}
"""Headers applied to every /api/v1 response.

``no-store`` is safe for the whole API surface because even authentication
responses carry session cookies that must never be cached by a shared
browser or intermediary.
"""


def accept_request_id(value: str | None) -> TypeGuard[str]:
    """Return whether a caller-supplied request ID matches the contract."""
    return bool(
        value
        and len(value) <= MAX_REQUEST_ID_LENGTH
        and REQUEST_ID_PATTERN.fullmatch(value)
    )


def new_request_id() -> str:
    """Generate a fresh bounded request ID (UUID hex)."""
    return uuid4().hex


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a bounded request ID and apply security headers and logging."""

    def __init__(
        self,
        application: object,
        *,
        log_requests: bool = True,
    ) -> None:
        """Bind the wrapped application and the logging preference."""
        super().__init__(application)  # type: ignore[arg-type]
        self._log_requests = log_requests

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Assign the request ID, run the route, and decorate the response."""
        supplied = request.headers.get(REQUEST_ID_HEADER)
        request_id = supplied if accept_request_id(supplied) else new_request_id()
        request.state.request_id = request_id
        started = time.monotonic()
        response = await call_next(request)
        duration_ms = (time.monotonic() - started) * 1000
        response.headers[REQUEST_ID_HEADER] = request_id
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if self._log_requests:
            self._log(request, response, duration_ms)
        return response

    @staticmethod
    def _log(request: Request, response: Response, duration_ms: float) -> None:
        """Emit the bounded structured request log line.

        The actor ID is read from ``request.state.actor_id`` which routes
        set after authentication; it is never derived from headers.
        """
        route = getattr(request.scope.get("route"), "path", None)
        actor_id = getattr(request.state, "actor_id", None)
        LOGGER.info(
            "api_request request_id=%s method=%s route=%s status=%s "
            "duration_ms=%.1f actor_id=%s",
            request.state.request_id,
            request.method,
            route or request.url.path,
            response.status_code,
            duration_ms,
            actor_id,
        )


def request_id(request: Request) -> str:
    """Return the bounded request ID assigned to this request."""
    return str(getattr(request.state, "request_id", "") or "")


def read_session_cookie(request: Request) -> str | None:
    """Return the raw session cookie value, if present."""
    return request.cookies.get(COOKIE_NAME)
