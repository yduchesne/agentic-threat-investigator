# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation-scoped GEOINT read routes (PR 26D).

``GET /api/v1/investigations/{investigation_id}/geoint/*`` is the bounded
analyst-facing geographic read surface. Every route requires the path
Investigation and proves scope through exact Evidence provenance; detail
endpoints 404 when no qualifying data exists in the path Investigation and
never disclose cross-Investigation existence. Following the established
PR 23C collection convention, an unknown/not-visible Investigation or an
unused Location yields empty successful collections. No route mutates
state; the PR 26A-C mutation APIs remain untouched.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.common import PageResponse
from agentic_threat_investigator.api.dto.geoint import (
    GeointEntityLocationResponse,
    GeointLocationEntitiesResponse,
    GeointLocationObservationsResponse,
    GeointObservationDetailResponse,
    GeointObservationResponse,
    GeointSummaryResponse,
)
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.api.mappers import (
    to_geoint_entity_location_response,
    to_geoint_observation_detail_response,
    to_geoint_observation_response,
    to_geoint_summary_response,
)
from agentic_threat_investigator.api.routes.common import (
    effective_page_limit,
    run_page_query,
)
from agentic_threat_investigator.app.query.geoint import (
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointLocationEntityListQuery,
    GeointLocationObservationListQuery,
    GeointObservationQuery,
    GeointSummaryQuery,
)

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/geoint",
    tags=["geoint"],
)


@router.get(
    "/summary",
    response_model=GeointSummaryResponse,
    operation_id="get_investigation_geoint_summary",
)
async def get_investigation_geoint_summary(
    investigation_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> GeointSummaryResponse:
    """Return one bounded geographic summary of the Investigation.

    Counts are exact Investigation-scoped facts; ``top_locations`` carries
    at most the server-owned bound in deterministic order and is never a
    risk/concentration label.
    """
    summary = await services.geoint.summary(
        GeointSummaryQuery(investigation_id=investigation_id)
    )
    return to_geoint_summary_response(summary)


@router.get(
    "/entities/{entity_id}",
    response_model=GeointEntityLocationResponse,
    operation_id="get_investigation_geoint_entity",
)
async def get_investigation_geoint_entity(
    investigation_id: UUID,
    entity_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> GeointEntityLocationResponse:
    """Return one Entity's Investigation-relative current geographic context.

    ``current_observation`` is the newest qualifying observation within the
    path Investigation; a cross-scope Entity maps to 404 and never discloses
    existence in another Investigation.
    """
    entity = await services.geoint.get_entity(
        GeointEntityQuery(investigation_id=investigation_id, entity_id=entity_id)
    )
    if entity is None:
        raise ApiError(
            ApiErrorCode.GEOINT_ENTITY_NOT_FOUND,
            "The entity has no geographic observations in this investigation.",
            404,
        )
    return to_geoint_entity_location_response(entity)


@router.get(
    "/entities/{entity_id}/observations",
    response_model=PageResponse[GeointObservationResponse],
    operation_id="list_investigation_geoint_entity_observations",
)
async def list_investigation_geoint_entity_observations(
    investigation_id: UUID,
    entity_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[GeointObservationResponse]:
    """List the Entity's Investigation-scoped geographic observation history.

    Ordered newest-first under the exact PR 26A currentness ordering with
    opaque keyset cursors and the shared server page bounds.
    """
    page = await run_page_query(
        lambda: services.geoint.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_id,
                entity_id=entity_id,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(to_geoint_observation_response(item) for item in page.items),
        next_cursor=page.next_cursor,
    )


@router.get(
    "/locations/{location_id}/entities",
    response_model=GeointLocationEntitiesResponse[GeointEntityLocationResponse],
    operation_id="list_investigation_geoint_location_entities",
)
async def list_investigation_geoint_location_entities(
    investigation_id: UUID,
    location_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    include_contained: bool = False,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> GeointLocationEntitiesResponse[GeointEntityLocationResponse]:
    """List Entities observed at one canonical Location of the Investigation.

    ``include_contained=true`` additionally selects child canonical
    Locations spatially covered by the selected boundary (``ST_Covers``,
    boundary-inclusive); city Points and NULL boundaries never expand.
    Each Entity appears once using its latest qualifying observation.
    """
    page = await run_page_query(
        lambda: services.geoint.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=location_id,
                include_contained=include_contained,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return GeointLocationEntitiesResponse(
        items=tuple(to_geoint_entity_location_response(item) for item in page.items),
        next_cursor=page.next_cursor,
        containment_applied=page.containment_applied,
    )


@router.get(
    "/locations/{location_id}/observations",
    response_model=GeointLocationObservationsResponse[GeointObservationResponse],
    operation_id="list_investigation_geoint_location_observations",
)
async def list_investigation_geoint_location_observations(
    investigation_id: UUID,
    location_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    include_contained: bool = False,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> GeointLocationObservationsResponse[GeointObservationResponse]:
    """List geographic observations at one canonical Location of the Investigation.

    ``include_contained=true`` additionally selects child canonical
    Locations spatially covered by the selected boundary; city Points and
    NULL boundaries never expand. Every qualifying immutable observation is
    returned pageably with exact ``observation_id``/``evidence_id``.
    """
    page = await run_page_query(
        lambda: services.geoint.list_location_observations(
            GeointLocationObservationListQuery(
                investigation_id=investigation_id,
                location_id=location_id,
                include_contained=include_contained,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return GeointLocationObservationsResponse(
        items=tuple(to_geoint_observation_response(item) for item in page.items),
        next_cursor=page.next_cursor,
        containment_applied=page.containment_applied,
    )


@router.get(
    "/observations/{observation_id}",
    response_model=GeointObservationDetailResponse,
    operation_id="get_investigation_geoint_observation",
)
async def get_investigation_geoint_observation(
    investigation_id: UUID,
    observation_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> GeointObservationDetailResponse:
    """Return one exact geographic observation bound to the Investigation.

    The response carries the exact ``observation_id`` and ``evidence_id``;
    a cross-Investigation observation maps to 404 and never discloses
    existence elsewhere. Full Evidence drill-down remains
    ``GET /investigations/{I}/evidence/{evidence_id}``.
    """
    detail = await services.geoint.get_observation(
        GeointObservationQuery(
            investigation_id=investigation_id, observation_id=observation_id
        )
    )
    if detail is None:
        raise ApiError(
            ApiErrorCode.GEOINT_OBSERVATION_NOT_FOUND,
            "The geographic observation was not found in this investigation.",
            404,
        )
    return to_geoint_observation_detail_response(detail)
