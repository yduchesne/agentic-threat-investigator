# SPDX-License-Identifier: AGPL-3.0-only
"""Research collection and detail routes.

Structured claims and citation snapshots preserve claim->citation closure;
embedding/vector internals, prompts, and raw model responses are never
exposed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.common import PageResponse
from agentic_threat_investigator.api.dto.research import ResearchResultResponse
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.api.mappers import to_research_result_response
from agentic_threat_investigator.api.routes.common import (
    effective_page_limit,
    run_page_query,
)
from agentic_threat_investigator.app.query.research import ResearchResultListQuery

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/research",
    tags=["research"],
)


@router.get(
    "",
    response_model=PageResponse[ResearchResultResponse],
    operation_id="list_research_results",
)
async def list_research_results(
    investigation_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    subject_entity_id: UUID | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[ResearchResultResponse]:
    """List immutable ResearchResults of one Investigation (PR 23A contract)."""
    page = await run_page_query(
        lambda: services.research_results.list(
            ResearchResultListQuery(
                investigation_id=investigation_id,
                subject_entity_id=subject_entity_id,
                created_from=created_from,
                created_to=created_to,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(to_research_result_response(item) for item in page.items),
        next_cursor=page.next_cursor,
    )


@router.get(
    "/{research_result_id}",
    response_model=ResearchResultResponse,
    operation_id="get_research_result",
)
async def get_research_result(
    investigation_id: UUID,
    research_result_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> ResearchResultResponse:
    """Return one ResearchResult bound to the path Investigation."""
    result = await services.research_results.get(investigation_id, research_result_id)
    if result is None:
        raise ApiError(
            ApiErrorCode.RESEARCH_RESULT_NOT_FOUND,
            "Research result was not found for this investigation.",
            404,
        )
    return to_research_result_response(result)
