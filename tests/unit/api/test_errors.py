# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23C stable error envelope tests (U16-U22)."""

from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentic_threat_investigator.api.errors import (
    ApiError,
    ApiErrorCode,
    install_error_handlers,
    map_typed_error,
)
from agentic_threat_investigator.app.identity import AuthenticationError
from agentic_threat_investigator.app.investigation_submission import (
    IdempotencyConflictError,
    IdempotencyKeyRequiredError,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    InvestigationVersionConflictError,
)
from agentic_threat_investigator.app.query.pagination import (
    CursorFilterMismatchError,
    CursorQueryMismatchError,
    InvalidCursorError,
)


def test_u16_typed_not_found_maps_to_stable_404_envelope() -> None:
    """InvestigationNotFound maps to the stable 404 envelope code."""
    error = map_typed_error(InvestigationNotFoundError("missing"))
    assert error.status_code == 404
    assert error.code == ApiErrorCode.INVESTIGATION_NOT_FOUND.value


def test_u17_invalid_cursor_maps_to_stable_400_envelope() -> None:
    """Malformed and mismatched cursors map to the stable 400 codes."""
    assert map_typed_error(InvalidCursorError("bad")).code == "invalid_cursor"
    assert (
        map_typed_error(CursorQueryMismatchError("bad")).code == "cursor_query_mismatch"
    )
    assert (
        map_typed_error(CursorFilterMismatchError("bad")).code
        == "cursor_filter_mismatch"
    )


def test_u18_stale_conflict_maps_to_stable_409_envelope() -> None:
    """Version conflicts map to the stable 409 stale_version code."""
    error = map_typed_error(InvestigationVersionConflictError(uuid4(), 2))
    assert error.status_code == 409
    assert error.code == ApiErrorCode.STALE_VERSION.value


def test_u19_unexpected_error_maps_to_generic_500_without_internals() -> None:
    """Unknown errors map to a safe generic 500; internals never escape."""
    error = map_typed_error(RuntimeError("connection pool exploded: dsn=secret"))
    assert error.status_code == 500
    assert error.code == ApiErrorCode.INTERNAL_ERROR.value
    assert "connection pool" not in error.message


def test_u20_fastapi_validation_uses_ati_envelope() -> None:
    """Request-validation failures return the ATI 422 envelope."""
    application = FastAPI()
    install_error_handlers(application)

    @application.get("/probe")
    async def probe(limit: int) -> dict[str, int]:
        """Probe route accepting one required integer."""
        return {"limit": limit}

    with TestClient(application) as client:
        response = client.get("/probe?limit=not-an-int")

    body = response.json()
    assert response.status_code == 422
    assert body["error"]["code"] == "validation_error"
    assert set(body["error"]) == {"code", "message", "request_id"}


def test_u21_valid_request_id_is_echoed() -> None:
    """A caller-supplied valid request ID is echoed in the response."""
    from agentic_threat_investigator.api.middleware import RequestContextMiddleware

    application = FastAPI()
    application.add_middleware(RequestContextMiddleware)
    install_error_handlers(application)

    @application.get("/probe")
    async def probe() -> dict[str, str]:
        """Probe route returning a fixed payload."""
        return {"ok": "yes"}

    with TestClient(application) as client:
        response = client.get("/probe", headers={"X-Request-ID": "caller-rid-123"})

    assert response.headers["X-Request-ID"] == "caller-rid-123"


def test_u22_invalid_request_id_is_replaced_safely() -> None:
    """An out-of-contract request ID is replaced with a fresh bounded ID."""
    from agentic_threat_investigator.api.middleware import RequestContextMiddleware

    application = FastAPI()
    application.add_middleware(RequestContextMiddleware)

    @application.get("/probe")
    async def probe() -> dict[str, str]:
        """Probe route returning a fixed payload."""
        return {"ok": "yes"}

    with TestClient(application) as client:
        response = client.get(
            "/probe", headers={"X-Request-ID": "evil<script>too-long-" + "x" * 500}
        )

    echoed = response.headers["X-Request-ID"]
    assert echoed != "evil<script>too-long-" + "x" * 500
    assert len(echoed) <= 128
    assert all(character.isalnum() or character in ".-_" for character in echoed)


def test_auth_errors_share_one_public_message() -> None:
    """Credential failures map to invalid_credentials with a fixed message."""
    error = map_typed_error(AuthenticationError("Invalid username or password."))
    assert error.status_code == 401
    assert error.code == ApiErrorCode.INVALID_CREDENTIALS.value


def test_idempotency_errors_map_to_stable_codes() -> None:
    """Idempotency failures map to the stable 400/409 codes."""
    required = map_typed_error(IdempotencyKeyRequiredError("key required"))
    assert required.status_code == 400
    assert required.code == ApiErrorCode.IDEMPOTENCY_KEY_REQUIRED.value
    conflict = map_typed_error(IdempotencyConflictError("conflict"))
    assert conflict.status_code == 409
    assert conflict.code == ApiErrorCode.IDEMPOTENCY_CONFLICT.value


def test_error_envelope_shape_is_stable() -> None:
    """The public envelope carries exactly code, message, request_id."""
    from agentic_threat_investigator.api.middleware import RequestContextMiddleware

    application = FastAPI()
    application.add_middleware(RequestContextMiddleware)
    install_error_handlers(application)

    @application.get("/boom")
    async def boom() -> None:
        """Route that always raises a typed API error."""
        raise ApiError(ApiErrorCode.CONFLICT, "Conflict happened.", 409)

    with TestClient(application) as client:
        response = client.get("/boom", headers={"X-Request-ID": "abc-123"})

    body = response.json()
    assert response.status_code == 409
    assert body == {
        "error": {
            "code": "conflict",
            "message": "Conflict happened.",
            "request_id": "abc-123",
        }
    }
