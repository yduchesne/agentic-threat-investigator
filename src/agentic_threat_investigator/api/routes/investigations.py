# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation creation, listing, and detail routes.

``POST /api/v1/investigations`` is asynchronous: the submission service
atomically persists the PENDING Investigation, its durable PostgreSQL job,
the mutation audit event, and the actor-scoped idempotency record, then the
route returns ``202 Accepted`` with a ``Location`` header. The request never
invokes ``InvestigationRunner`` and never uses FastAPI background tasks.
Listing and detail consume the PR 23A query contracts unchanged.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status

from agentic_threat_investigator.api.auth_constants import (
    IDEMPOTENCY_KEY_HEADER,
)
from agentic_threat_investigator.api.dependencies import (
    AnalystUser,
    QueryServices,
    csrf_protected,
    submission_service,
)
from agentic_threat_investigator.api.dto.common import PageResponse
from agentic_threat_investigator.api.dto.investigation import (
    CreateInvestigationRequest,
    CreateInvestigationResponse,
    InvestigationResponse,
)
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.api.mappers import (
    to_create_investigation_response,
    to_investigation_response,
)
from agentic_threat_investigator.api.routes.common import (
    effective_page_limit,
    request_uuid,
    run_page_query,
)
from agentic_threat_investigator.app.investigation_submission import (
    IndicatorInput,
    InvestigationSubmission,
    InvestigationSubmissionService,
)
from agentic_threat_investigator.app.query.investigations import (
    InvestigationListQuery,
)
from agentic_threat_investigator.domain.investigation import InvestigationStatus

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations"])


@router.post(
    "",
    response_model=CreateInvestigationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="create_investigation",
)
async def create_investigation(
    payload: CreateInvestigationRequest,
    request: Request,
    response: Response,
    user: AnalystUser,
    _csrf: Annotated[None, Depends(csrf_protected)],
    service: Annotated[InvestigationSubmissionService, Depends(submission_service)],
    idempotency_key: Annotated[str | None, Header(alias=IDEMPOTENCY_KEY_HEADER)] = None,
) -> CreateInvestigationResponse:
    """Persist a PENDING Investigation + durable job and return 202.

    ``Idempotency-Key`` is required and actor-scoped; equivalent replays
    return the same Investigation with consistent ``202`` semantics.
    """
    submission = InvestigationSubmission(
        indicators=[
            IndicatorInput(type=indicator.type, value=indicator.value)
            for indicator in payload.indicators
        ],
        objective=payload.objective,
    )
    try:
        state = await service.submit(
            submission,
            actor_id=user.id,
            idempotency_key=idempotency_key,
            request_id=request_uuid(request),
        )
    except Exception as error:
        raise ApiError.from_exception(error) from error
    response.headers["Location"] = f"/api/v1/investigations/{state.investigation_id}"
    return to_create_investigation_response(state)


@router.get(
    "",
    response_model=PageResponse[InvestigationResponse],
    operation_id="list_investigations",
)
async def list_investigations(
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    status_filter: Annotated[InvestigationStatus | None, Query(alias="status")] = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[InvestigationResponse]:
    """List visible Investigations using the PR 23A keyset contract.

    Filters map exactly: ``status``, ``created_from``/``created_to``
    (half-open UTC), ``limit``, and the opaque ``cursor``.
    """
    page = await run_page_query(
        lambda: services.investigations.list(
            InvestigationListQuery(
                status=status_filter,
                created_from=created_from,
                created_to=created_to,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(to_investigation_response(item) for item in page.items),
        next_cursor=page.next_cursor,
    )


@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
    operation_id="get_investigation",
)
async def get_investigation(
    investigation_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> InvestigationResponse:
    """Return one visible Investigation's stable public operational state."""
    investigation = await services.investigations.get(investigation_id)
    if investigation is None:
        raise ApiError(
            ApiErrorCode.INVESTIGATION_NOT_FOUND,
            "Investigation was not found.",
            404,
        )
    return to_investigation_response(investigation)
