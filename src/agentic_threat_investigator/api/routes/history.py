# SPDX-License-Identifier: AGPL-3.0-only
"""Generic resource-history routes with public allowlist/redaction.

Identity remains ``object_type + object_id``; no ``natural_key`` exists.
Raw ``state``/``diff`` JSONB snapshots are never exposed: every record is
projected through the per-object-type public allowlist before crossing the
HTTP boundary, and non-allowlisted object types (credentials, sessions,
jobs, internal orchestration) fail closed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.common import PageResponse
from agentic_threat_investigator.api.dto.history import HistoryRecordResponse
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.api.history_redaction import (
    HistoryObjectTypeForbiddenError,
    redact_history_snapshot,
    require_public_history_object_type,
)
from agentic_threat_investigator.api.mappers import to_history_response
from agentic_threat_investigator.api.routes.common import (
    effective_page_limit,
    run_page_query,
)
from agentic_threat_investigator.app.query.history import (
    DomainHistoryListQuery,
    DomainObjectHistoryRecord,
    HistoryOperation,
    validate_object_version,
)

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/history",
    tags=["history"],
)


def _redacted(record: DomainObjectHistoryRecord) -> HistoryRecordResponse:
    """Project one history record through the public allowlist."""
    require_public_history_object_type(record.object_type)
    redacted = record.model_copy(
        update={
            "state": redact_history_snapshot(record.object_type, record.state),
            "diff": redact_history_snapshot(record.object_type, record.diff),
        }
    )
    return to_history_response(redacted)


@router.get(
    "",
    response_model=PageResponse[HistoryRecordResponse],
    operation_id="list_investigation_history",
)
async def list_investigation_history(
    investigation_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    object_type: str | None = None,
    operation: HistoryOperation | None = None,
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[HistoryRecordResponse]:
    """Browse history rows scoped to one Investigation.

    ``object_type`` is restricted to the public allowlist; any other type is
    rejected with ``400 invalid_request``.
    """
    if object_type is not None:
        try:
            require_public_history_object_type(object_type)
        except HistoryObjectTypeForbiddenError as error:
            raise ApiError(ApiErrorCode.INVALID_REQUEST, str(error), 400) from error
    page = await run_page_query(
        lambda: services.domain_history.list(
            DomainHistoryListQuery(
                investigation_id=investigation_id,
                object_type=object_type,
                operation=operation,
                occurred_from=occurred_from,
                occurred_to=occurred_to,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(_redacted(item) for item in page.items),
        next_cursor=page.next_cursor,
    )


@router.get(
    "/{object_type}/{object_id}",
    response_model=PageResponse[HistoryRecordResponse],
    operation_id="list_object_history",
)
async def list_object_history(
    investigation_id: UUID,
    object_type: str,
    object_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    operation: HistoryOperation | None = None,
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[HistoryRecordResponse]:
    """Browse the history of one Investigation-scoped object."""
    try:
        require_public_history_object_type(object_type)
    except HistoryObjectTypeForbiddenError as error:
        raise ApiError(ApiErrorCode.INVALID_REQUEST, str(error), 400) from error
    page = await run_page_query(
        lambda: services.domain_history.list(
            DomainHistoryListQuery(
                investigation_id=investigation_id,
                object_type=object_type,
                object_id=object_id,
                operation=operation,
                occurred_from=occurred_from,
                occurred_to=occurred_to,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(_redacted(item) for item in page.items),
        next_cursor=page.next_cursor,
    )


@router.get(
    "/{object_type}/{object_id}/{version}",
    response_model=HistoryRecordResponse,
    operation_id="get_object_history_version",
)
async def get_object_history_version(
    investigation_id: UUID,
    object_type: str,
    object_id: UUID,
    version: int,
    services: QueryServices,
    _user: AnalystUser,
) -> HistoryRecordResponse:
    """Return the exact history row of one object version.

    The row must belong to the path Investigation; cross-Investigation rows
    and non-allowlisted object types fail closed.
    """
    try:
        require_public_history_object_type(object_type)
        validate_object_version(object_type, version)
    except (HistoryObjectTypeForbiddenError, ValueError) as error:
        raise ApiError(ApiErrorCode.INVALID_REQUEST, str(error), 400) from error
    record = await services.domain_history.get_object_version(
        object_type=object_type, object_id=object_id, version=version
    )
    if record is None or record.investigation_id != investigation_id:
        raise ApiError(
            ApiErrorCode.NOT_FOUND,
            "History version was not found for this investigation.",
            404,
        )
    return _redacted(record)
