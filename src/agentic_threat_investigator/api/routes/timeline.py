# SPDX-License-Identifier: AGPL-3.0-only
"""Timeline route.

Exposes observable workflow events only in the PR 23A canonical
chronological order (``occurred_at ASC, sequence ASC``); hidden reasoning,
prompts, and LangGraph implementation details are never serialized.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.common import PageResponse
from agentic_threat_investigator.api.dto.timeline import TimelineEventResponse
from agentic_threat_investigator.api.mappers import to_timeline_event_response
from agentic_threat_investigator.api.routes.common import (
    effective_page_limit,
    run_page_query,
)
from agentic_threat_investigator.app.query.timeline import TimelineListQuery
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/timeline",
    tags=["timeline"],
)


@router.get(
    "",
    response_model=PageResponse[TimelineEventResponse],
    operation_id="list_timeline_events",
)
async def list_timeline_events(
    investigation_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    event_type: Annotated[
        InvestigationTimelineEventType | None, Query(alias="event_type")
    ] = None,
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[TimelineEventResponse]:
    """List observable timeline events in chronological order."""
    page = await run_page_query(
        lambda: services.timeline_events.list(
            TimelineListQuery(
                investigation_id=investigation_id,
                event_type=event_type,
                occurred_from=occurred_from,
                occurred_to=occurred_to,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(to_timeline_event_response(item) for item in page.items),
        next_cursor=page.next_cursor,
    )
