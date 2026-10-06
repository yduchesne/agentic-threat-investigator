# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded HTML error presentation for the server-rendered web adapter.

The JSON ``/api/v1`` boundary keeps its stable error envelopes unchanged:
every handler here delegates to the existing API handlers for API paths and
only renders HTML for non-API (web) paths. No handler leaks a traceback,
SQL text, provider payload, or secret.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import HTMLResponse, Response

from agentic_threat_investigator.api.auth_constants import API_PREFIX
from agentic_threat_investigator.api.errors import (
    http_exception_handler,
    unhandled_exception_handler,
)
from agentic_threat_investigator.web.rendering import WebTemplates

LOGGER = logging.getLogger(__name__)

_ERROR_COPY: dict[int, tuple[str, str]] = {
    400: ("Invalid request", "The request could not be processed."),
    401: ("Sign in required", "Please sign in to continue."),
    403: ("Forbidden", "You do not have access to this resource."),
    404: ("Page not found", "The page you requested does not exist."),
    405: ("Method not allowed", "That action is not supported here."),
    429: ("Too many requests", "Please wait a moment and try again."),
    500: ("Internal error", "An unexpected error occurred."),
    503: ("Service unavailable", "The service is temporarily unavailable."),
}


def is_api_path(path: str) -> bool:
    """Return whether a request path belongs to the JSON API boundary."""
    return path == API_PREFIX or path.startswith(f"{API_PREFIX}/")


def error_copy(status_code: int) -> tuple[str, str]:
    """Return the bounded title/message pair for an HTTP status."""
    return _ERROR_COPY.get(
        status_code, ("Request failed", "The request could not be completed.")
    )


class WebError(Exception):
    """A bounded HTML presentation error with an explicit status."""

    def __init__(self, status_code: int, title: str, message: str) -> None:
        """Bind the HTTP status and safe, bounded presentation strings."""
        super().__init__(message)
        self.status_code = status_code
        self.title = title
        self.message = message


def _plain_error(status_code: int, title: str, message: str) -> HTMLResponse:
    """Return a minimal escaped HTML error when templates are unavailable."""
    from html import escape

    body = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        f"<title>{status_code} {escape(title)}</title></head><body>"
        f"<h1>{status_code} {escape(title)}</h1><p>{escape(message)}</p>"
        "</body></html>"
    )
    return HTMLResponse(body, status_code=status_code)


def render_error(
    request: Request, status_code: int, title: str, message: str
) -> Response:
    """Render a bounded HTML error page using the installed templates."""
    templates = getattr(request.app.state, "web_templates", None)
    if templates is None:
        return _plain_error(status_code, title, message)
    response = cast(WebTemplates, templates).render(
        request,
        "errors/error.html",
        {
            "status_code": status_code,
            "error_title": title,
            "error_message": message,
        },
    )
    response.status_code = status_code
    return response


def install_web_error_handlers(application: FastAPI) -> None:
    """Install path-aware error handlers that keep API errors JSON.

    These registration order deliberately follows the API handler
    installation so web paths gain HTML presentation while ``/api/v1`` paths
    keep their existing stable JSON behavior through delegation.
    """

    async def web_error_handler(request: Request, exc: WebError) -> Response:
        """Render a typed :class:`WebError` as bounded HTML."""
        return render_error(request, exc.status_code, exc.title, exc.message)

    async def web_http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> Response:
        """Render HTML for web paths and delegate API paths to JSON."""
        if is_api_path(request.url.path):
            return await http_exception_handler(request, exc)
        title, message = error_copy(exc.status_code)
        return render_error(request, exc.status_code, title, message)

    async def web_unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> Response:
        """Render a bounded HTML 500 for web paths; never leak internals."""
        if is_api_path(request.url.path):
            return await unhandled_exception_handler(request, exc)
        LOGGER.exception(
            "unhandled web error method=%s path=%s", request.method, request.url.path
        )
        title, message = error_copy(500)
        return render_error(request, 500, title, message)

    application.add_exception_handler(WebError, cast(Any, web_error_handler))
    application.add_exception_handler(
        StarletteHTTPException, cast(Any, web_http_exception_handler)
    )
    application.add_exception_handler(
        Exception, cast(Any, web_unhandled_exception_handler)
    )
