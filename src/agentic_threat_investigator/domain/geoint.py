# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26A GEOINT domain contracts.

Location is canonical geographic/reference data, not an ATI Entity.
EntityLocationObservation is immutable append-only historical provenance that
explicitly preserves the exact Entity, Location, and supporting Evidence.
EntityLocation is the current materialized Entity-to-Location association and
is maintained exclusively by the database. GeoResolution is durable
operational geographic-enrichment work state, not geographic truth.

PR 26A is deliberately non-spatial: no PostGIS, no geometry/centroid fields,
and no geographic resolution logic.
"""

import re
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

_COUNTRY_CODE_RE = "^[A-Z]{2}$"
_ERROR_CODE_RE = "^[a-z][a-z0-9_]{0,63}$"
_NAME_MAX_LENGTH = 200
_CODE_MAX_LENGTH = 64
_METHOD_MAX_LENGTH = 200
_CLAIMED_BY_MAX_LENGTH = 200

_PRECISION_VOCABULARY = ("country", "administrative_area", "city")


class LocationType(str, Enum):
    """Classification of a canonical geographic reference object.

    The v0.1 vocabulary is deliberately bounded to country, administrative
    area, and city. ``LocationType`` classifies the canonical reference
    object; it is not a precision claim.
    """

    COUNTRY = "country"
    ADMINISTRATIVE_AREA = "administrative_area"
    CITY = "city"


class LocationPrecision(str, Enum):
    """Precision supported by a geographic observation or association.

    Although the initial vocabulary mirrors :class:`LocationType`, the
    semantics are distinct: ``LocationType`` classifies the canonical
    reference object while ``LocationPrecision`` records the precision
    supported by an observation/association. Canonicalization never infers a
    more precise value from a less precise one.
    """

    COUNTRY = "country"
    ADMINISTRATIVE_AREA = "administrative_area"
    CITY = "city"


class GeoResolutionStatus(str, Enum):
    """Operational state of durable geographic-enrichment work.

    PR 26A establishes the vocabulary only; the transition state machine
    beyond initial creation belongs to PR 26C.
    """

    PENDING = "pending"
    PROCESSING = "processing"
    RESOLVED = "resolved"
    UNRESOLVABLE = "unresolvable"
    FAILED = "failed"


def _normalize_text(value: str, label: str, max_length: int) -> str:
    """Trim a bounded nonblank textual field and reject failures closed."""
    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{label} must not be blank")
    if len(trimmed) > max_length:
        raise ValueError(f"{label} exceeds the maximum length of {max_length}")
    return trimmed


def _normalize_code(value: str, label: str) -> str:
    """Trim a bounded identifier code and reject blank/oversized values."""
    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{label} must not be blank")
    if len(trimmed) > _CODE_MAX_LENGTH:
        raise ValueError(f"{label} exceeds the maximum length of {_CODE_MAX_LENGTH}")
    return trimmed


def _require_aware_utc(value: datetime, label: str) -> datetime:
    """Require a timezone-aware timestamp and normalize it to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


class Location(BaseModel):
    """A canonical geographic/reference identity (country, area, or city).

    Location is not an ATI Entity and never participates in
    Relationship/RelationshipObservation records. Canonical identity is the
    deterministic tuple ``(type, country_code, admin1_code, admin2_code,
    canonical_name)`` with null components normalized by the database;
    ``parent_location_id`` is reference hierarchy and is not part of the
    identity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID | None = None
    type: LocationType
    name: str
    canonical_name: str
    country_code: str
    admin1_code: str | None = None
    admin2_code: str | None = None
    parent_location_id: UUID | None = None
    # Persistence-owned fields are exposed so repository writes can return
    # the authoritative revision without leaking ORM types.
    version: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_validator("name", "canonical_name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        """Require a nonblank name bounded to the documented maximum."""
        return _normalize_text(value, "location name", _NAME_MAX_LENGTH)

    @field_validator("country_code")
    @classmethod
    def _validate_country_code(cls, value: str) -> str:
        """Normalize a two-letter ISO-style country code deterministically.

        The layer validates the ``^[A-Z]{2}$`` shape only; PR 26A does not
        consult or download an external country registry.
        """
        normalized = value.strip().upper()
        if len(normalized) != 2 or not normalized.isalpha():
            raise ValueError("country_code must be two uppercase letters")
        return normalized

    @field_validator("admin1_code", "admin2_code")
    @classmethod
    def _validate_admin_code(cls, value: str | None) -> str | None:
        """Require a trimmed nonblank bounded administrative code when present."""
        return None if value is None else _normalize_code(value, "administrative code")

    @model_validator(mode="after")
    def _validate_type_shape(self) -> "Location":
        """Enforce the approved type-specific parent/admin code shape."""
        if self.type is LocationType.COUNTRY:
            if self.parent_location_id is not None:
                raise ValueError("country Location must not have a parent")
            if self.admin1_code is not None or self.admin2_code is not None:
                raise ValueError("country Location must not have admin codes")
        else:
            if self.parent_location_id is None:
                raise ValueError(
                    f"{self.type.value} Location requires a parent_location_id"
                )
            if self.admin1_code is None:
                raise ValueError(f"{self.type.value} Location requires an admin1_code")
        if self.id is not None and self.id == self.parent_location_id:
            raise ValueError("Location parent must not equal the Location itself")
        return self


class EntityLocationObservation(BaseModel):
    """An immutable historical geographic observation with exact provenance.

    One persisted row is one immutable historical observation. The exact
    ``entity_id``, ``location_id``, and ``evidence_id`` are stored explicitly;
    historical observations never derive their Location through mutable
    current ``EntityLocation`` state. There is no update, delete, or
    soft-delete path.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    entity_id: UUID
    location_id: UUID
    evidence_id: UUID
    precision: LocationPrecision
    observed_at: datetime | None = None
    retrieved_at: datetime
    resolved_at: datetime
    resolution_method: str
    version: int | None = None
    created_at: datetime | None = None

    @field_validator("observed_at", "retrieved_at", "resolved_at")
    @classmethod
    def _validate_utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware timestamps, normalized to UTC."""
        if value is None:
            return None
        return _require_aware_utc(value, "observation timestamp")

    @field_validator("resolution_method")
    @classmethod
    def _validate_method(cls, value: str) -> str:
        """Require a nonblank bounded machine-oriented resolution method."""
        return _normalize_text(value, "resolution_method", _METHOD_MAX_LENGTH)


class EntityLocation(BaseModel):
    """ATI's current materialized Entity-to-Location association.

    Exactly one current row exists per Entity in v0.1. Current state is
    database-maintained from observations; application code must not update
    it independently. ``latest_observation_id`` points at the observation
    that currently determines the materialized association.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    location_id: UUID
    precision: LocationPrecision
    latest_observation_id: UUID
    first_observed_at: datetime
    last_observed_at: datetime
    version: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_validator("first_observed_at", "last_observed_at")
    @classmethod
    def _validate_utc(cls, value: datetime) -> datetime:
        """Require timezone-aware timestamps, normalized to UTC."""
        return _require_aware_utc(value, "entity location timestamp")

    @model_validator(mode="after")
    def _validate_time_order(self) -> "EntityLocation":
        """Reject an inverted first/last observation window."""
        if self.first_observed_at > self.last_observed_at:
            raise ValueError("first_observed_at must not be after last_observed_at")
        return self


class GeoResolution(BaseModel):
    """Durable operational geographic-enrichment work for one Entity/Evidence pair.

    Pending/processing/failure state belongs here, never on Evidence or on
    EntityLocationObservation. PR 26A persists initial PENDING work and reads
    only; claim/lease/retry/completion semantics belong to PR 26C.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID | None = None
    entity_id: UUID
    evidence_id: UUID
    status: GeoResolutionStatus = GeoResolutionStatus.PENDING
    attempt_count: int = 0
    next_attempt_at: datetime | None = None
    claimed_by: str | None = None
    lease_expires_at: datetime | None = None
    resolved_location_id: UUID | None = None
    last_error_code: str | None = None
    version: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_validator("attempt_count")
    @classmethod
    def _validate_attempt_count(cls, value: int) -> int:
        """Reject negative attempt counts."""
        if value < 0:
            raise ValueError("attempt_count must not be negative")
        return value

    @field_validator("last_error_code")
    @classmethod
    def _validate_error_code(cls, value: str | None) -> str | None:
        """Require the bounded lowercase machine error-code grammar when present."""
        if value is None:
            return None
        if re.fullmatch(_ERROR_CODE_RE, value) is None:
            raise ValueError(
                "last_error_code must match ^[a-z][a-z0-9_]{0,63}$ when present"
            )
        return value

    @field_validator("claimed_by")
    @classmethod
    def _validate_claimed_by(cls, value: str | None) -> str | None:
        """Require a nonblank bounded claim identity when present."""
        return (
            None
            if value is None
            else _normalize_text(value, "claimed_by", _CLAIMED_BY_MAX_LENGTH)
        )

    @field_validator("next_attempt_at", "lease_expires_at")
    @classmethod
    def _validate_utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware timestamps, normalized to UTC."""
        if value is None:
            return None
        return _require_aware_utc(value, "geo resolution timestamp")


def location_identity_tuple(
    location: Location,
) -> tuple[str, str, str | None, str | None, str]:
    """Return the deterministic canonical identity tuple of a Location.

    The tuple ``(type, country_code, admin1_code, admin2_code,
    canonical_name)`` is the approved PR 26A canonical identity; the database
    enforces uniqueness with null components normalized. ``parent_location_id``
    is deliberately excluded.
    """
    return (
        location.type.value,
        location.country_code,
        location.admin1_code,
        location.admin2_code,
        location.canonical_name,
    )
