# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence collection and detail routes.

Filters map exactly to the PR 23A evidence contract: ``source``,
``subject_entity_id``, ``type``, half-open ``retrieved_from``/``retrieved_to``,
``limit``, and the opaque ``cursor``. Raw provider payloads are never
exposed; detail routes verify the Evidence belongs to the path Investigation
and map cross-Investigation lookups to 404.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.common import PageResponse
from agentic_threat_investigator.api.dto.evidence import EvidenceResponse
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.api.mappers import to_evidence_response
from agentic_threat_investigator.api.routes.common import (
    effective_page_limit,
    run_page_query,
)
from agentic_threat_investigator.app.query.evidence import EvidenceListQuery
from agentic_threat_investigator.domain.evidence import EvidenceType

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/evidence",
    tags=["evidence"],
)


@router.get(
    "",
    response_model=PageResponse[EvidenceResponse],
    operation_id="list_evidence",
)
async def list_evidence(
    investigation_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    source: str | None = None,
    subject_entity_id: UUID | None = None,
    evidence_type: Annotated[EvidenceType | None, Query(alias="type")] = None,
    retrieved_from: datetime | None = None,
    retrieved_to: datetime | None = None,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[EvidenceResponse]:
    """List Evidence observations of one Investigation (PR 23A contract)."""
    page = await run_page_query(
        lambda: services.evidence.list(
            EvidenceListQuery(
                investigation_id=investigation_id,
                source=source,
                subject_entity_id=subject_entity_id,
                evidence_type=evidence_type,
                retrieved_from=retrieved_from,
                retrieved_to=retrieved_to,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(to_evidence_response(item) for item in page.items),
        next_cursor=page.next_cursor,
    )


@router.get(
    "/{evidence_id}",
    response_model=EvidenceResponse,
    operation_id="get_evidence",
)
async def get_evidence(
    investigation_id: UUID,
    evidence_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> EvidenceResponse:
    """Return one Evidence observation bound to the path Investigation.

    A cross-Investigation Evidence maps to ``404 evidence_not_found``; no
    resource enumeration is possible.
    """
    evidence = await services.evidence.get(investigation_id, evidence_id)
    if evidence is None:
        raise ApiError(
            ApiErrorCode.EVIDENCE_NOT_FOUND,
            "Evidence was not found for this investigation.",
            404,
        )
    return to_evidence_response(evidence)
