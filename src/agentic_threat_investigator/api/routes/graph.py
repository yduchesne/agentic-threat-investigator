# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation-scoped graph neighborhood route (PR 31C).

The route is a thin authenticated read projection over the existing
:class:`GraphQueryService`: it builds exactly one
:class:`GraphNeighborhoodQuery` from validated path/query parameters, calls
``services.graph.neighborhood``, and maps the result to explicit public
DTOs. It never imports PostgreSQL, never issues SQL, never reconstructs
topology, never aggregates observations, and never infers visibility; a
``None`` result (missing, deleted, or not-visible focal Entity) maps to one
scoped 404 with a single stable code, and a visible isolated focal Entity
maps to 200 with a focal-only graph.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.graph import GraphNeighborhoodResponse
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.api.mappers import (
    to_graph_neighborhood_response,
)
from agentic_threat_investigator.api.routes.common import effective_page_limit
from agentic_threat_investigator.app.query.graph import GraphNeighborhoodQuery
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/graph",
    tags=["graph"],
)


@router.get(
    "/entities/{entity_id}/neighborhood",
    response_model=GraphNeighborhoodResponse,
    operation_id="get_graph_entity_neighborhood",
)
async def get_graph_entity_neighborhood(
    investigation_id: UUID,
    entity_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    direction: RelationshipDirection = RelationshipDirection.EITHER,
    relationship_type: Annotated[
        RelationshipType | None, Query(alias="relationship_type")
    ] = None,
    limit: int | None = None,
) -> GraphNeighborhoodResponse:
    """Return the bounded one-hop neighborhood of one focal Entity.

    ``direction`` defaults to ``either`` relative to the focal Entity;
    ``relationship_type`` filters the canonical Relationship URN; an omitted
    ``limit`` uses the configured default page size while the service-owned
    maximum is never clamped -- an oversized caller limit is a stable 400
    ``invalid_request``. Scoped absence (missing, soft-deleted, or
    not-visible focal Entity) maps to one 404 ``graph_entity_not_found``;
    every other graph result, including a visible isolated focal Entity,
    maps to 200.
    """
    try:
        result = await services.graph.neighborhood(
            GraphNeighborhoodQuery(
                investigation_id=investigation_id,
                entity_id=entity_id,
                direction=direction,
                relationship_type=relationship_type,
                limit=effective_page_limit(request, limit),
            )
        )
    except ValueError as error:
        raise ApiError(ApiErrorCode.INVALID_REQUEST, str(error), 400) from error
    if result is None:
        raise ApiError(
            ApiErrorCode.GRAPH_ENTITY_NOT_FOUND,
            "Graph entity was not found for this investigation.",
            404,
        )
    return to_graph_neighborhood_response(result)
