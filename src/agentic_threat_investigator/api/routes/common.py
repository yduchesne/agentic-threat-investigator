# SPDX-License-Identifier: AGPL-3.0-only
"""Shared route helpers: page limits, request UUIDs, and safe query runs.

Routes stay thin: they build PR 23A query DTOs from validated HTTP
parameters and invoke query services; they never touch SQL or reimplement
query semantics.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar
from uuid import UUID

from fastapi import Request

from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.app.query.models import QueryPage
from agentic_threat_investigator.app.query.pagination import QueryCursorError
from agentic_threat_investigator.config import Settings

T = TypeVar("T")


def effective_page_limit(request: Request, limit: int | None) -> int:
    """Return the caller-supplied limit or the configured default.

    The ceiling itself is enforced by the PR 23A query services through
    :class:`QueryLimits`; this helper only supplies the default.
    """
    if limit is not None:
        return limit
    settings: Settings = request.app.state.settings
    return settings.query_default_page_size


def request_uuid(request: Request) -> UUID | None:
    """Return the bounded request ID as a UUID when it is one.

    Caller-supplied request IDs may be arbitrary bounded strings; only a
    valid UUID is carried into audit metadata.
    """
    value = getattr(request.state, "request_id", None)
    if not value:
        return None
    try:
        return UUID(str(value))
    except ValueError:
        return None


async def run_page_query(
    factory: Callable[[], Awaitable[QueryPage[T]]],
) -> QueryPage[T]:
    """Run one paginated query, mapping user-input failures to 400.

    Typed cursor errors are mapped centrally by the error handlers; only
    bounded user-input failures (invalid dates, limits, ranges) are
    translated here with their safe messages.
    """
    try:
        return await factory()
    except QueryCursorError:
        # Typed cursor errors (invalid_cursor, cursor_query_mismatch,
        # cursor_filter_mismatch) map centrally with their dedicated codes.
        raise
    except ValueError as error:
        raise ApiError(ApiErrorCode.INVALID_REQUEST, str(error), 400) from error
