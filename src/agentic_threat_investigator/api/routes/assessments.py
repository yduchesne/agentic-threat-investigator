# SPDX-License-Identifier: AGPL-3.0-only
"""Assessment version list, current, and detail routes.

The current Assessment is resolved through the Investigation's durable
``assessment_id`` pointer (never ``MAX(version)``); detail routes verify the
Assessment belongs to the path Investigation.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.assessment import AssessmentResponse
from agentic_threat_investigator.api.dto.common import PageResponse
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.api.mappers import to_assessment_response
from agentic_threat_investigator.api.routes.common import (
    effective_page_limit,
    run_page_query,
)
from agentic_threat_investigator.app.query.assessments import AssessmentListQuery

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/assessments",
    tags=["assessments"],
)


@router.get(
    "",
    response_model=PageResponse[AssessmentResponse],
    operation_id="list_assessments",
)
async def list_assessments(
    investigation_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[AssessmentResponse]:
    """List Assessment versions (``version DESC, id ASC``) for one Investigation."""
    page = await run_page_query(
        lambda: services.assessments.list(
            AssessmentListQuery(
                investigation_id=investigation_id,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(to_assessment_response(item) for item in page.items),
        next_cursor=page.next_cursor,
    )


@router.get(
    "/current",
    response_model=AssessmentResponse,
    operation_id="get_current_assessment",
)
async def get_current_assessment(
    investigation_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> AssessmentResponse:
    """Return the Investigation's current Assessment via its durable pointer."""
    assessment = await services.assessments.current(investigation_id)
    if assessment is None:
        raise ApiError(
            ApiErrorCode.ASSESSMENT_NOT_FOUND,
            "The investigation has no current assessment.",
            404,
        )
    return to_assessment_response(assessment)


@router.get(
    "/{assessment_id}",
    response_model=AssessmentResponse,
    operation_id="get_assessment",
)
async def get_assessment(
    investigation_id: UUID,
    assessment_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> AssessmentResponse:
    """Return one Assessment version bound to the path Investigation."""
    assessment = await services.assessments.get(investigation_id, assessment_id)
    if assessment is None:
        raise ApiError(
            ApiErrorCode.ASSESSMENT_NOT_FOUND,
            "Assessment was not found for this investigation.",
            404,
        )
    return to_assessment_response(assessment)
