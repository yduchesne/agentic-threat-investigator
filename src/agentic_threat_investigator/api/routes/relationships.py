# SPDX-License-Identifier: AGPL-3.0-only
"""Relationship and RelationshipObservation routes.

Relationships expose distinct stable edges visible to one Investigation;
RelationshipObservations expose the immutable historical record directly
with the observed/retrieved time distinction preserved. Observations are
never routed through generic ``domain_object_history``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.common import PageResponse
from agentic_threat_investigator.api.dto.relationship import (
    RelationshipObservationResponse,
    RelationshipResponse,
)
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.api.mappers import (
    to_relationship_observation_response,
    to_relationship_response,
)
from agentic_threat_investigator.api.routes.common import (
    effective_page_limit,
    run_page_query,
)
from agentic_threat_investigator.app.query.relationships import (
    RelationshipListQuery,
    RelationshipObservationListQuery,
)
from agentic_threat_investigator.domain.relationships import RelationshipType

relationships_router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/relationships",
    tags=["relationships"],
)
observations_router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/relationship-observations",
    tags=["relationships"],
)


@relationships_router.get(
    "",
    response_model=PageResponse[RelationshipResponse],
    operation_id="list_relationships",
)
async def list_relationships(
    investigation_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    source_entity_id: UUID | None = None,
    target_entity_id: UUID | None = None,
    relationship_type: Annotated[
        RelationshipType | None, Query(alias="relationship_type")
    ] = None,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[RelationshipResponse]:
    """List distinct Relationships visible to one Investigation."""
    page = await run_page_query(
        lambda: services.relationships.list(
            RelationshipListQuery(
                investigation_id=investigation_id,
                source_entity_id=source_entity_id,
                target_entity_id=target_entity_id,
                relationship_type=relationship_type,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(to_relationship_response(item) for item in page.items),
        next_cursor=page.next_cursor,
    )


@relationships_router.get(
    "/{relationship_id}",
    response_model=RelationshipResponse,
    operation_id="get_relationship",
)
async def get_relationship(
    investigation_id: UUID,
    relationship_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> RelationshipResponse:
    """Return one Relationship visible to the path Investigation."""
    relationship = await services.relationships.get(investigation_id, relationship_id)
    if relationship is None:
        raise ApiError(
            ApiErrorCode.RELATIONSHIP_NOT_FOUND,
            "Relationship was not found for this investigation.",
            404,
        )
    return to_relationship_response(relationship)


@observations_router.get(
    "",
    response_model=PageResponse[RelationshipObservationResponse],
    operation_id="list_relationship_observations",
)
async def list_relationship_observations(
    investigation_id: UUID,
    request: Request,
    services: QueryServices,
    _user: AnalystUser,
    relationship_id: UUID | None = None,
    source: str | None = None,
    retrieved_from: datetime | None = None,
    retrieved_to: datetime | None = None,
    observed_from: datetime | None = None,
    observed_to: datetime | None = None,
    limit: int | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> PageResponse[RelationshipObservationResponse]:
    """List immutable RelationshipObservations of one Investigation.

    ``observed_at`` and ``retrieved_at`` remain independent half-open UTC
    filters; pagination follows the canonical ``retrieved_at DESC, id ASC``
    order with opaque cursors.
    """
    page = await run_page_query(
        lambda: services.relationship_observations.list(
            RelationshipObservationListQuery(
                investigation_id=investigation_id,
                relationship_id=relationship_id,
                source=source,
                retrieved_from=retrieved_from,
                retrieved_to=retrieved_to,
                observed_from=observed_from,
                observed_to=observed_to,
                limit=effective_page_limit(request, limit),
                cursor=cursor,
            )
        )
    )
    return PageResponse(
        items=tuple(to_relationship_observation_response(item) for item in page.items),
        next_cursor=page.next_cursor,
    )
