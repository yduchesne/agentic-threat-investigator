# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation-scoped graph route (PR 31C; PR 31G; PR 31H).

The route is a thin authenticated read projection over the existing
:class:`GraphQueryService`: it builds exactly one
:class:`GraphNeighborhoodQuery` (or, for the PR 31H traversal endpoint, one
:class:`GraphTraversalQuery`) from validated path/query parameters, calls the
corresponding service method, and maps the result to explicit public DTOs.
It never imports PostgreSQL, never issues SQL, never reconstructs
Topology, never aggregates observations, and never infers visibility; a
``None`` result (missing, deleted, or not-visible focal Entity) maps to one
scoped 404 with a single stable code, and a visible isolated focal Entity
maps to 200 with a focal-only graph. PR 31G adds the optional ``scope``
(``investigation`` default / ``known``), connected Entity type, exact
observation source and half-open observed-time filters; PR 31H adds the
bounded ``/traversal`` endpoint with an explicit 1..3 ``max_depth`` on top
of the identical filter vocabulary, reusing the same response model.
Defaults preserve current-main behavior.
"""

from __future__ import annotations

from datetime import datetime
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
from agentic_threat_investigator.app.query.graph import (
    DEFAULT_TRAVERSAL_MAX_DEPTH,
    GraphNeighborhoodQuery,
    GraphScope,
    GraphTraversalQuery,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/graph",
    tags=["graph"],
)


@router.get(
    "/entities/{entity_id}/traversal",
    response_model=GraphNeighborhoodResponse,
    operation_id="get_graph_entity_traversal",
)
async def get_graph_entity_traversal(
    investigation_id: UUID,
    entity_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    max_depth: Annotated[int | None, Query(alias="max_depth")] = None,
    direction: RelationshipDirection = RelationshipDirection.EITHER,
    relationship_type: Annotated[
        RelationshipType | None, Query(alias="relationship_type")
    ] = None,
    scope: Annotated[GraphScope | None, Query(alias="scope")] = None,
    entity_type: Annotated[EntityType | None, Query(alias="entity_type")] = None,
    source: Annotated[str | None, Query(alias="source")] = None,
    observed_from: Annotated[datetime | None, Query(alias="observed_from")] = None,
    observed_to: Annotated[datetime | None, Query(alias="observed_to")] = None,
    limit: int | None = None,
) -> GraphNeighborhoodResponse:
    """Return the bounded multi-hop traversal of one focal Entity.

    ``max_depth`` defaults to :data:`DEFAULT_TRAVERSAL_MAX_DEPTH` (2) and is
    hard-bounded to 1..3 (depth 1 equals the one-hop neighborhood; other
    values are a stable 400 ``invalid_request``). Every other parameter
    (``direction``, ``scope``, ``relationship_type``, ``entity_type``,
    ``source``, ``observed_from`` / ``observed_to``, ``limit``) keeps the
    exact PR 31G neighborhood meaning and is applied at every traversal
    frontier. The response reuses the canonical
    ``GraphNeighborhoodResponse`` vocabulary (nodes, edges, ``truncated``):
    no paths, arrays, SQL concepts, or second edge/node DTO are exposed.
    Scoped absence maps to the same 404 ``graph_entity_not_found`` as the
    one-hop read.
    """
    try:
        result = await services.graph.traverse(
            GraphTraversalQuery(
                investigation_id=investigation_id,
                entity_id=entity_id,
                max_depth=(
                    DEFAULT_TRAVERSAL_MAX_DEPTH if max_depth is None else max_depth
                ),
                scope=GraphScope.INVESTIGATION if scope is None else scope,
                direction=direction,
                relationship_type=relationship_type,
                entity_type=entity_type,
                source=source,
                observed_from=observed_from,
                observed_to=observed_to,
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
    scope: Annotated[GraphScope | None, Query(alias="scope")] = None,
    entity_type: Annotated[EntityType | None, Query(alias="entity_type")] = None,
    source: Annotated[str | None, Query(alias="source")] = None,
    observed_from: Annotated[datetime | None, Query(alias="observed_from")] = None,
    observed_to: Annotated[datetime | None, Query(alias="observed_to")] = None,
    limit: int | None = None,
) -> GraphNeighborhoodResponse:
    """Return the bounded one-hop neighborhood of one focal Entity.

    ``direction`` defaults to ``either`` relative to the focal Entity;
    ``relationship_type`` filters the canonical Relationship URN;
    ``scope`` selects ``investigation`` (default) or ``known`` topology;
    ``entity_type`` filters the connected/counterparty Entity type;
    ``source`` exact-matches ``RelationshipObservation.source``;
    ``observed_from`` / ``observed_to`` bound ``observed_at`` half-open;
    an omitted ``limit`` uses the configured default page size while the
    service-owned maximum is never clamped -- an oversized caller limit is
    a stable 400 ``invalid_request``. Scoped absence (missing, soft-deleted,
    or not-visible focal Entity) maps to one 404 ``graph_entity_not_found``;
    every other graph result, including a visible isolated focal Entity or
    an all-filters-filtered focal-only graph, maps to 200.
    """
    try:
        result = await services.graph.neighborhood(
            GraphNeighborhoodQuery(
                investigation_id=investigation_id,
                entity_id=entity_id,
                scope=GraphScope.INVESTIGATION if scope is None else scope,
                direction=direction,
                relationship_type=relationship_type,
                entity_type=entity_type,
                source=source,
                observed_from=observed_from,
                observed_to=observed_to,
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
