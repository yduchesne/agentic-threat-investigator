# SPDX-License-Identifier: AGPL-3.0-only
"""Report version list, current, detail, and deterministic Markdown routes.

The current report is resolved through the Investigation's durable
``report_id`` pointer (never ``MAX(version)``). GET never regenerates a
report and never invokes an LLM; the Markdown route calls PR 23B's pure
deterministic formatter only.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.common import PageResponse
from agentic_threat_investigator.api.dto.report import ReportResponse
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.api.mappers import to_report_response
from agentic_threat_investigator.api.routes.common import (
    effective_page_limit,
    run_page_query,
)
from agentic_threat_investigator.app.query.reports import ReportListQuery
from agentic_threat_investigator.app.report_writer.formatter import (
    format_investigation_report_markdown,
)
from agentic_threat_investigator.domain.report import InvestigationReport

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/reports",
    tags=["reports"],
)

MARKDOWN_MEDIA_TYPE = "text/markdown; charset=utf-8"


@router.get(
    "",
    response_model=PageResponse[ReportResponse],
    operation_id="list_reports",
)
async def list_reports(
    investigation_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[ReportResponse]:
    """List report versions (``version DESC, id ASC``) for one Investigation."""
    page = await run_page_query(
        lambda: services.reports.list(
            ReportListQuery(
                investigation_id=investigation_id,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(to_report_response(item) for item in page.items),
        next_cursor=page.next_cursor,
    )


@router.get(
    "/current",
    response_model=ReportResponse,
    operation_id="get_current_report",
)
async def get_current_report(
    investigation_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> ReportResponse:
    """Return the Investigation's current report via its durable pointer."""
    report = await services.reports.current(investigation_id)
    if report is None:
        raise ApiError(
            ApiErrorCode.REPORT_NOT_FOUND,
            "The investigation has no current report.",
            404,
        )
    return to_report_response(report)


@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    operation_id="get_report",
)
async def get_report(
    investigation_id: UUID,
    report_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> ReportResponse:
    """Return one report bound to the path Investigation."""
    report = await _bound_report(services, investigation_id, report_id)
    return to_report_response(report)


@router.get(
    "/{report_id}/markdown",
    response_model=None,
    operation_id="get_report_markdown",
)
async def get_report_markdown(
    investigation_id: UUID,
    report_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> Response:
    """Return the deterministic Markdown rendering of one persisted report.

    The pure PR 23B formatter renders the already-persisted structured
    report; no writer, LLM, or semantic transformation is involved.
    """
    report = await _bound_report(services, investigation_id, report_id)
    markdown = format_investigation_report_markdown(report)
    return Response(
        content=markdown,
        media_type="text/markdown",
        headers={"Content-Type": MARKDOWN_MEDIA_TYPE},
    )


async def _bound_report(
    services: QueryServices, investigation_id: UUID, report_id: UUID
) -> InvestigationReport:
    """Load one visible report and require its Investigation binding.

    A cross-Investigation report maps to ``404 report_not_found``; no
    resource enumeration is possible.
    """
    report = await services.reports.get(report_id)
    if report is None or report.investigation_id != investigation_id:
        raise ApiError(
            ApiErrorCode.REPORT_NOT_FOUND,
            "Report was not found for this investigation.",
            404,
        )
    return report
