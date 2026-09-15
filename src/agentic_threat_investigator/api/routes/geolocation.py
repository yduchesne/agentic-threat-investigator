# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation geolocation projection route (PR 25A).

``GET /api/v1/investigations/{investigation_id}/geolocations`` returns one
bounded server-owned current geolocation context projection derived only
from persisted ``GEOLOCATION`` Evidence. The route performs no provider
lookup, opens no MMDB artifact, reads no ObjectStore location, and never
invokes orchestration or an LLM. Following the established PR 23C
collection convention, an unknown or not-visible Investigation yields an
empty successful collection, exactly like the Evidence/Timeline
collections.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter

from agentic_threat_investigator.api.dependencies import AnalystUser, QueryServices
from agentic_threat_investigator.api.dto.geolocation import (
    InvestigationGeolocationCollectionResponse,
)
from agentic_threat_investigator.api.mappers import to_geolocation_response

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/geolocations",
    tags=["geolocation"],
)


@router.get(
    "",
    response_model=InvestigationGeolocationCollectionResponse,
    operation_id="list_investigation_geolocations",
)
async def list_investigation_geolocations(
    investigation_id: UUID,
    services: QueryServices,
    _user: AnalystUser,
) -> InvestigationGeolocationCollectionResponse:
    """Return the bounded current geolocation projection of one Investigation.

    The projection contains at most one item per IP entity (the latest
    persisted ``GEOLOCATION`` Evidence by ``retrieved_at DESC, id ASC``),
    preserves the exact Evidence ID as provenance, and never exposes
    arbitrary facts or raw payloads.
    """
    result = await services.geolocations.list_for_investigation(investigation_id)
    return InvestigationGeolocationCollectionResponse(
        items=tuple(to_geolocation_response(item) for item in result.items),
        truncated=result.truncated,
    )
