# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded Investigation-scoped support presentation route (PR 31F-5).

The frontend resolves the finite support-ID sets of one loaded
Report/Assessment through exactly one bounded batch request; per-support
HTTP GETs are never needed. Raw provider payloads are never returned, and
missing/cross-Investigation IDs are simply absent from the result so the
frontend renders the localized unavailable statement.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends

from agentic_threat_investigator.api.dependencies import (
    AnalystUser,
    QueryServices,
    csrf_protected,
)
from agentic_threat_investigator.api.dto.support import (
    SupportPresentationRequest,
    SupportPresentationResponse,
)
from agentic_threat_investigator.api.mappers import to_support_presentation_response
from agentic_threat_investigator.app.query.support_presentations import (
    SupportPresentationQuery,
)

support_presentations_router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/support-presentations",
    tags=["investigations"],
)


@support_presentations_router.post(
    "/resolve",
    response_model=SupportPresentationResponse,
    operation_id="resolve_support_presentations",
)
async def resolve_support_presentations(
    investigation_id: UUID,
    payload: SupportPresentationRequest,
    services: QueryServices,
    _user: AnalystUser,
    _csrf: Annotated[None, Depends(csrf_protected)],
) -> SupportPresentationResponse:
    """Resolve one bounded set of support IDs into presentation metadata.

    Investigation scope is mandatory: every requested ID resolves only
    through exact admission into the path Investigation, so
    cross-Investigation IDs fail closed (absent) and the raw provider
    payload never crosses the API boundary.
    """
    result = await services.support_presentations.resolve(
        SupportPresentationQuery(
            investigation_id=investigation_id,
            evidence_observation_ids=tuple(payload.evidence_observation_ids),
            relationship_observation_ids=tuple(payload.relationship_observation_ids),
        )
    )
    return to_support_presentation_response(result)
