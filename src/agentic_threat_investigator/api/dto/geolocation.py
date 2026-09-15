# SPDX-License-Identifier: AGPL-3.0-only
"""Public Investigation geolocation DTOs (PR 25A).

The geolocation contract exposes a bounded, Investigation-scoped current
geolocation context projection only: exact Evidence/Entity provenance,
typed geographic context, provider, precision, and timestamps. Arbitrary
normalized facts, raw provider payloads, artifact URIs, and filesystem
paths are never part of this surface. Geolocation remains approximate
network-address context and never implies physical attacker/device
location, maliciousness, or attribution.
"""

from __future__ import annotations

import math
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator

from agentic_threat_investigator.domain.geolocation import GeoPrecision


class InvestigationGeolocationResponse(BaseModel):
    """One current approximate geolocation context item for one IP entity.

    ``evidence_id`` is the exact persisted immutable Evidence observation
    that produced the item, so the frontend can navigate map point -> exact
    Evidence without any fuzzy lookup. Latitude and longitude are paired:
    either both are present or both are absent. Valid geographic context
    without map coordinates is retained with ``null`` coordinates.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: UUID
    entity_id: UUID
    ip_address: str
    country_code: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    precision: GeoPrecision
    provider: str
    observed_at: datetime | None
    retrieved_at: datetime

    @field_validator("latitude", "longitude")
    @classmethod
    def finite_coordinates(cls, value: float | None) -> float | None:
        """Reject non-finite coordinates across the public boundary."""
        if value is not None and not math.isfinite(value):
            raise ValueError("geolocation coordinates must be finite")
        return value


class InvestigationGeolocationCollectionResponse(BaseModel):
    """One bounded Investigation geolocation projection.

    No cursor is exposed: this is one coherent server-owned visualization
    dataset, never a pageable collection. ``truncated`` is true exactly
    when the projection exceeded the server-owned maximum.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[InvestigationGeolocationResponse, ...]
    truncated: bool
