# SPDX-License-Identifier: AGPL-3.0-only
"""Public Investigation GEOINT DTOs (PR 26D).

The GEOINT surface is bounded and Investigation-scoped: exact observation/
Evidence provenance, bounded Entity/Location display context, and the
centroid latitude/longitude pair only. Raw PostGIS geometry (EWKT/WKB),
boundary geometry, upstream metadata, and provider payloads never cross
this boundary. Geolocation semantics remain approximate context and never
imply threat relationships, risk, or attribution.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)

T = TypeVar("T")

_MIN_LATITUDE = -90.0
_MAX_LATITUDE = 90.0
_MIN_LONGITUDE = -180.0
_MAX_LONGITUDE = 180.0


class GeointLocationResponse(BaseModel):
    """One bounded canonical Location display reference.

    Centroid coordinates are exposed as the paired latitude/longitude only;
    no raw geometry or upstream metadata is ever included.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    location_id: UUID
    location_type: LocationType
    canonical_name: str
    country_code: str
    admin1_code: str | None
    admin2_code: str | None
    parent_location_id: UUID | None
    latitude: float | None
    longitude: float | None

    @field_validator("latitude", "longitude")
    @classmethod
    def finite_coordinates(cls, value: float | None) -> float | None:
        """Reject non-finite coordinates across the public boundary."""
        if value is not None and not math.isfinite(value):
            raise ValueError("geoint coordinates must be finite")
        return value

    @model_validator(mode="after")
    def coordinate_pair(self) -> "GeointLocationResponse":
        """Require the centroid coordinate pair to be complete and in range."""
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("geoint coordinates must be a complete pair")
        if self.latitude is not None and not (
            _MIN_LATITUDE <= self.latitude <= _MAX_LATITUDE
        ):
            raise ValueError("geoint latitude is out of range")
        if self.longitude is not None and not (
            _MIN_LONGITUDE <= self.longitude <= _MAX_LONGITUDE
        ):
            raise ValueError("geoint longitude is out of range")
        return self


class GeointObservationResponse(BaseModel):
    """One immutable geographic observation with exact provenance.

    ``observation_id`` and ``evidence_id`` are exact persisted identities:
    the observation -> Evidence drill-down route accepts ``evidence_id``
    unchanged.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: UUID
    entity_id: UUID
    location: GeointLocationResponse
    evidence_id: UUID
    precision: LocationPrecision
    resolution_method: str
    observed_at: datetime | None
    retrieved_at: datetime
    resolved_at: datetime


class GeointEntityLocationResponse(BaseModel):
    """One Entity's Investigation-relative current geographic context.

    ``current_observation`` is the newest qualifying observation within the
    path Investigation, never the global materialized ``EntityLocation``
    state (which may have been advanced by another Investigation).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    entity_type: EntityType
    entity_value: str
    display_name: str | None
    current_observation: GeointObservationResponse


class GeointObservationDetailResponse(BaseModel):
    """One exact geographic observation with bounded display context."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation: GeointObservationResponse
    entity_type: EntityType
    entity_value: str
    display_name: str | None


class GeointTopLocationResponse(BaseModel):
    """One exact observed Location group in the bounded summary.

    ``scoped_entity_count`` is an exact scoped fact, never a risk or
    concentration label.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    location: GeointLocationResponse
    scoped_entity_count: int


class GeointPrecisionCountsResponse(BaseModel):
    """Observation counts by the approved precision vocabulary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    country: int
    administrative_area: int
    city: int


class GeointSummaryResponse(BaseModel):
    """One bounded Investigation-scoped geographic summary (PR 26D)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_count_with_location: int
    observation_count: int
    location_count: int
    country_count: int
    administrative_area_count: int
    city_count: int
    precision_counts: GeointPrecisionCountsResponse
    top_locations: tuple[GeointTopLocationResponse, ...]
    truncated: bool


class GeointLocationEntitiesResponse(BaseModel, Generic[T]):
    """One bounded page of Location-scoped Entities.

    ``containment_applied`` is true exactly when the selection was performed
    with boundary containment; it is false for exact selections, city
    Points, and a NULL selected boundary geometry.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[T, ...]
    next_cursor: str | None = None
    containment_applied: bool


class GeointLocationObservationsResponse(BaseModel, Generic[T]):
    """One bounded page of Location-scoped observations.

    ``containment_applied`` is true exactly when the selection was performed
    with boundary containment; it is false for exact selections, city
    Points, and a NULL selected boundary geometry.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[T, ...]
    next_cursor: str | None = None
    containment_applied: bool
