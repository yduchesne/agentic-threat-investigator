# SPDX-License-Identifier: AGPL-3.0-only
"""Stable public API error envelope and typed exception mapping.

Every error response uses the stable envelope:

.. code-block:: json

    {"error": {"code": "...", "message": "...", "request_id": "..."}}

Codes are contract; messages may evolve. Python tracebacks, SQL text/errors,
SQLSTATEs, secrets, provider raw responses, LLM/provider internals, LangGraph
state, ORM metadata, and class names are never exposed.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException

from agentic_threat_investigator.app.investigation_submission import (
    DuplicateCanonicalIndicatorError,
    IdempotencyConflictError,
    IdempotencyKeyInvalidError,
    IdempotencyKeyRequiredError,
    SubmissionBoundsError,
)
from agentic_threat_investigator.app.persistence.repositories import (
    AssessmentCurrentReferenceConflictError,
    AssessmentDuplicateIdentityError,
    InvestigationDuplicateIdentityError,
    InvestigationJobDuplicateError,
    InvestigationNotFoundError,
    InvestigationVersionConflictError,
    ReportCurrentReferenceConflictError,
    ReportReferenceInvalidError,
    StaleReportInputError,
)
from agentic_threat_investigator.app.query.pagination import (
    CursorFilterMismatchError,
    CursorQueryMismatchError,
    InvalidCursorError,
)

LOGGER = logging.getLogger(__name__)


class ApiErrorCode(str, Enum):
    """Stable public error codes (contract values)."""

    NOT_FOUND = "not_found"
    INVALID_REQUEST = "invalid_request"
    VALIDATION_ERROR = "validation_error"
    AUTHENTICATION_REQUIRED = "authentication_required"
    INVALID_CREDENTIALS = "invalid_credentials"
    FORBIDDEN = "forbidden"
    RATE_LIMITED = "rate_limited"
    INVESTIGATION_NOT_FOUND = "investigation_not_found"
    EVIDENCE_NOT_FOUND = "evidence_not_found"
    RELATIONSHIP_NOT_FOUND = "relationship_not_found"
    RESEARCH_RESULT_NOT_FOUND = "research_result_not_found"
    ASSESSMENT_NOT_FOUND = "assessment_not_found"
    REPORT_NOT_FOUND = "report_not_found"
    INVALID_CURSOR = "invalid_cursor"
    CURSOR_QUERY_MISMATCH = "cursor_query_mismatch"
    CURSOR_FILTER_MISMATCH = "cursor_filter_mismatch"
    IDEMPOTENCY_KEY_REQUIRED = "idempotency_key_required"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    CONFLICT = "conflict"
    STALE_VERSION = "stale_version"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    INTERNAL_ERROR = "internal_error"


class ErrorDetail(BaseModel):
    """One stable error detail inside the public envelope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    message: str
    request_id: str


class ErrorResponse(BaseModel):
    """The stable public error envelope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    error: ErrorDetail


class ApiError(Exception):
    """A typed public API error with a stable code and HTTP status."""

    def __init__(
        self,
        code: ApiErrorCode | str,
        message: str,
        status_code: int,
        *,
        expose: bool = True,
    ) -> None:
        """Bind the stable code, safe message, and HTTP status."""
        super().__init__(message)
        self.code = code.value if isinstance(code, ApiErrorCode) else code
        self.message = message
        self.status_code = status_code
        self.expose = expose

    @classmethod
    def from_exception(cls, error: Exception) -> "ApiError":
        """Translate one typed application/persistence error centrally."""
        return map_typed_error(error)


def _request_id(request: Request) -> str:
    """Return the bounded request ID set by the request-ID middleware."""
    return str(getattr(request.state, "request_id", "") or "")


def error_envelope(
    request: Request, code: str, message: str, status_code: int
) -> JSONResponse:
    """Build a stable JSON error envelope for one request."""
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(
            error=ErrorDetail(
                code=code, message=message, request_id=_request_id(request)
            )
        ).model_dump(),
    )


async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    """Map a typed :class:`ApiError` to its stable envelope."""
    return error_envelope(request, exc.code, exc.message, exc.status_code)


async def validation_error_handler(
    request: Request, _exc: RequestValidationError
) -> JSONResponse:
    """Override FastAPI's default validation response with the ATI envelope.

    Only the generic bounded message is exposed; raw Pydantic internals and
    error class names never reach the client.
    """
    return error_envelope(
        request,
        ApiErrorCode.VALIDATION_ERROR.value,
        "Request validation failed.",
        422,
    )


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Map Starlette HTTP exceptions to the stable envelope.

    Authentication/authorization failures and unknown routes use stable
    codes; server-side dependency failures never leak internals.
    """
    status_code = exc.status_code
    if status_code == 401:
        code, message = (
            ApiErrorCode.AUTHENTICATION_REQUIRED.value,
            ("Authentication is required."),
        )
    elif status_code == 403:
        code, message = ApiErrorCode.FORBIDDEN.value, "Access is forbidden."
    elif status_code == 404:
        code, message = ApiErrorCode.NOT_FOUND.value, "The resource was not found."
    elif status_code == 405:
        code, message = (
            ApiErrorCode.INVALID_REQUEST.value,
            ("The HTTP method is not allowed for this resource."),
        )
    elif status_code == 429:
        code, message = (
            ApiErrorCode.RATE_LIMITED.value,
            ("Too many requests; try again later."),
        )
    else:
        code, message = (
            ApiErrorCode.INVALID_REQUEST.value,
            ("The request could not be processed."),
        )
    return error_envelope(request, code, message, status_code)


async def unhandled_exception_handler(
    request: Request, _exc: Exception
) -> JSONResponse:
    """Map typed errors centrally; return a safe generic 500 otherwise.

    Known application/persistence errors are translated to their stable
    envelopes; anything else logs the request context and returns the
    generic 500 without leaking internals.
    """
    mapped = map_typed_error(_exc)
    if mapped.status_code != 500:
        return error_envelope(request, mapped.code, mapped.message, mapped.status_code)
    LOGGER.exception(
        "unhandled API error request_id=%s method=%s path=%s",
        _request_id(request),
        request.method,
        request.url.path,
    )
    return error_envelope(
        request,
        ApiErrorCode.INTERNAL_ERROR.value,
        "An internal error occurred.",
        500,
    )


def map_typed_error(error: Exception) -> ApiError:
    """Map a typed application/persistence error to a stable public error.

    This is the single central translation table; routes never hand-map
    application errors to HTTP responses.
    """
    from agentic_threat_investigator.app.identity import (
        AuthenticationError,
        CsrfError,
        RateLimitedError,
    )

    if isinstance(error, ApiError):
        return error
    if isinstance(error, RateLimitedError):
        return ApiError(ApiErrorCode.RATE_LIMITED, "Too many login attempts.", 429)
    if isinstance(error, AuthenticationError):
        return ApiError(
            ApiErrorCode.INVALID_CREDENTIALS,
            "Invalid username or password.",
            401,
        )
    if isinstance(error, CsrfError):
        return ApiError(ApiErrorCode.FORBIDDEN, "CSRF validation failed.", 403)
    if isinstance(error, IdempotencyKeyRequiredError):
        return ApiError(
            ApiErrorCode.IDEMPOTENCY_KEY_REQUIRED,
            "Idempotency-Key is required for this operation.",
            400,
        )
    if isinstance(error, IdempotencyKeyInvalidError):
        return ApiError(
            ApiErrorCode.INVALID_REQUEST,
            "Idempotency-Key must be 1..128 visible ASCII characters.",
            400,
        )
    if isinstance(error, (SubmissionBoundsError, DuplicateCanonicalIndicatorError)):
        return ApiError(ApiErrorCode.INVALID_REQUEST, str(error), 400)
    if isinstance(error, IdempotencyConflictError):
        return ApiError(
            ApiErrorCode.IDEMPOTENCY_CONFLICT,
            "Idempotency-Key was already used for a different request.",
            409,
        )
    if isinstance(error, InvestigationNotFoundError):
        return ApiError(
            ApiErrorCode.INVESTIGATION_NOT_FOUND,
            "Investigation was not found.",
            404,
        )
    if isinstance(error, InvestigationVersionConflictError):
        return ApiError(
            ApiErrorCode.STALE_VERSION,
            "The resource changed since it was last read; refresh and retry.",
            409,
        )
    if isinstance(error, StaleReportInputError):
        return ApiError(
            ApiErrorCode.STALE_VERSION,
            "The report input is stale; regenerate from fresh inputs.",
            409,
        )
    if isinstance(
        error,
        (
            AssessmentCurrentReferenceConflictError,
            ReportCurrentReferenceConflictError,
            ReportReferenceInvalidError,
            InvestigationDuplicateIdentityError,
            InvestigationJobDuplicateError,
            AssessmentDuplicateIdentityError,
        ),
    ):
        return ApiError(
            ApiErrorCode.CONFLICT, "The resource already exists or is referenced.", 409
        )
    if isinstance(error, InvalidCursorError):
        return ApiError(
            ApiErrorCode.INVALID_CURSOR, "The cursor is malformed or unsupported.", 400
        )
    if isinstance(error, CursorQueryMismatchError):
        return ApiError(
            ApiErrorCode.CURSOR_QUERY_MISMATCH,
            "The cursor belongs to a different collection.",
            400,
        )
    if isinstance(error, CursorFilterMismatchError):
        return ApiError(
            ApiErrorCode.CURSOR_FILTER_MISMATCH,
            "The cursor does not match the supplied filters.",
            400,
        )
    # Unknown/unmapped errors: safe generic 500, no internals.
    LOGGER.warning("unmapped API error type=%s", type(error).__name__)
    return ApiError(
        ApiErrorCode.INTERNAL_ERROR,
        "An internal error occurred.",
        500,
        expose=False,
    )


def install_error_handlers(application: FastAPI) -> None:
    """Install the stable error handlers on a FastAPI application."""
    application.add_exception_handler(ApiError, cast(Any, api_error_handler))
    application.add_exception_handler(
        RequestValidationError, cast(Any, validation_error_handler)
    )
    application.add_exception_handler(
        StarletteHTTPException, cast(Any, http_exception_handler)
    )
    application.add_exception_handler(Exception, cast(Any, unhandled_exception_handler))
