# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26 GEOINT domain contracts.

Location is canonical geographic/reference data, not an ATI Entity.
EntityLocationObservation is immutable append-only historical provenance that
explicitly preserves the exact Entity, Location, and supporting Evidence.
EntityLocation is the current materialized Entity-to-Location association and
is maintained exclusively by the database. GeoResolution is durable
operational geographic-enrichment work state, not geographic truth.

PR 26A delivered the non-spatial GEOINT foundation. PR 26B adds the
canonical reference/spatial surface: ``Location`` carries optional
PostGIS-compatible EWKT geometry (``SRID=4326;...``) and a representative
centroid/on-surface point, deterministic UUIDv5 canonical reference
identity, the bounded :class:`GeographicClaim` contract, and the explicit
:class:`CanonicalLocationResolution` result algebra. Spatial validation is
owned by the versioned SQL write function; the domain only bounds the text
representation so no PostGIS/SQLAlchemy object ever leaks into domain code.

PR 26A-2 manages EntityLocation version allocation; PR 26B does not touch
observation, current-state, or GeoResolution semantics.
"""

import math
import re
import unicodedata
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID, uuid5

from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationInfo,
    field_validator,
    model_validator,
)

_COUNTRY_CODE_RE = "^[A-Z]{2}$"
_ERROR_CODE_RE = "^[a-z][a-z0-9_]{0,63}$"
_NAME_MAX_LENGTH = 200
_CODE_MAX_LENGTH = 64
_METHOD_MAX_LENGTH = 200
_CLAIMED_BY_MAX_LENGTH = 200
_EWKT_MAX_LENGTH = 1_000_000

_PRECISION_VOCABULARY = ("country", "administrative_area", "city")

# Fixed namespace for canonical Location UUIDv5 identity (PR 26B). Generated
# once at authoring time; changing it would change every canonical reference
# identity, so it is an immutable contract.
ATI_LOCATION_NAMESPACE = UUID("d94572fc-fb6d-4626-ba99-b760fee02afd")

# Fixed namespace for deterministic resolution-produced observation identity
# (PR 26C). Generated once at authoring time; changing it would change every
# persisted observation identity, so it is an immutable contract.
ATI_OBSERVATION_NAMESPACE = UUID("8f61470b-3e21-4624-9c0f-24c285acba6c")


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


def _normalize_text_or_none(value: str | None, label: str) -> str | None:
    """Trim a bounded optional textual field and reject failures closed."""
    if value is None:
        return None
    return _normalize_text(value, label, _EWKT_MAX_LENGTH)


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
    identity. Spatial representation (``geometry``/``centroid``) is state
    attached to the canonical reference object, never part of its identity.
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
    # Reference/spatial state (PR 26B): PostGIS-compatible EWKT strings
    # (``SRID=4326;...``) or ``None`` when the canonical object has no
    # reference geometry. The database owns full geometric validity; the
    # domain only bounds the serialized text so no PostGIS object leaks.
    geometry: str | None = None
    centroid: str | None = None
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

    @field_validator("geometry", "centroid")
    @classmethod
    def _validate_spatial_text(
        cls, value: str | None, info: ValidationInfo
    ) -> str | None:
        """Bound the serialized EWKT text without parsing geometry.

        Spatial validity, SRID, type, emptiness, and coordinate bounds are
        enforced by the versioned reference write function; the domain only
        rejects blank and oversized serializations deterministically.
        """
        return _normalize_text_or_none(value, info.field_name or "spatial value")

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
    ``entity_id``, ``location_id``, and ``evidence_observation_id`` (the exact
    PR 28B EvidenceObservation) are stored explicitly; historical
    observations never derive their Location through mutable current
    ``EntityLocation`` state. There is no update, delete, or soft-delete path.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    entity_id: UUID
    location_id: UUID
    evidence_observation_id: UUID
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


def observation_uuid_for_resolution(resolution_id: UUID) -> UUID:
    """Return the deterministic observation identity for one successful work item.

    PR 26C resolution-produced ``EntityLocationObservation`` identities are
    UUIDv5 of the stable successful-work identity (``GeoResolution.id``)
    under the fixed :data:`ATI_OBSERVATION_NAMESPACE`. The identity therefore
    never changes across an uncertain-commit replay: the exact same
    successful completion always resolves to the same observation UUID, so
    replay can never duplicate an observation or fabricate a fresh random
    identity.
    """
    return uuid5(ATI_OBSERVATION_NAMESPACE, str(resolution_id))


class GeoResolution(BaseModel):
    """Durable work for one Entity/EvidenceObservation pair (PR 26A + PR 28B).

    Pending/processing/failure state belongs here, never on Evidence or on
    EntityLocationObservation. PR 26A persists initial PENDING work and reads
    only; claim/lease/retry/completion semantics belong to PR 26C. The pair
    binds the exact EvidenceObservation provenance (PR 28B).
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID | None = None
    entity_id: UUID
    evidence_observation_id: UUID
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


def normalize_reference_name(value: str) -> str:
    """Apply the deterministic reference-name normalization contract (PR 26B).

    - NFC Unicode normalization;
    - surrounding whitespace trimmed;
    - every Unicode whitespace run collapses to a single ASCII space;
    - case is preserved (matching aliases are case-folded only at
      claim-matching time, never inside the canonical name).

    The contract deliberately does not strip punctuation or diacritics and
    never fuzzes the canonical identity.
    """
    return " ".join(unicodedata.normalize("NFC", value).split())


def location_identity_key(
    *,
    location_type: LocationType,
    country_code: str,
    admin1_code: str | None,
    admin2_code: str | None,
    canonical_name: str,
) -> str:
    """Return the byte-deterministic serialization of the canonical identity.

    The exact serialization is the canonical identity tuple joined by the
    ASCII unit separator ``\\x1f`` with null admin codes serialized as the
    empty string:

    ``<type>\\x1f<country_code>\\x1f<admin1-or-empty>\\x1f<admin2-or-empty>\\x1f<canonical_name>``

    The unit separator cannot collide with the bounded validated fields and
    keeps the mapping injective over the identity tuple.
    """
    return "\x1f".join(
        (
            location_type.value,
            country_code,
            admin1_code or "",
            admin2_code or "",
            canonical_name,
        )
    )


def canonical_location_uuid(
    *,
    location_type: LocationType,
    country_code: str,
    admin1_code: str | None,
    admin2_code: str | None,
    canonical_name: str,
) -> UUID:
    """Derive the deterministic canonical Location UUIDv5 identity (PR 26B).

    The UUID is UUIDv5 of the canonical identity key under the fixed
    :data:`ATI_LOCATION_NAMESPACE`. It is independent of any external source
    identifier, so a clean database and an existing database resolve the same
    canonical Location identity to the same UUID, and geometry refreshes never
    change identity.
    """
    return uuid5(
        ATI_LOCATION_NAMESPACE,
        location_identity_key(
            location_type=location_type,
            country_code=country_code,
            admin1_code=admin1_code,
            admin2_code=admin2_code,
            canonical_name=canonical_name,
        ),
    )


class GeographicClaim(BaseModel):
    """A bounded frozen claim of only the geographic facts already observed.

    The field vocabulary mirrors the persisted ``GEOLOCATION`` Evidence facts
    (``country_code``, ``region`` -> ``administrative_area``, ``city``,
    ``latitude``, ``longitude``) plus the explicit administrative code, so PR
    26C consumes the same vocabulary without a parallel spelling.

    Validation rules:

    - latitude/longitude appear together, are finite, and stay within WGS84
      bounds (lon in [-180, 180], lat in [-90, 90]);
    - a supplied country code is two ASCII uppercase letters;
    - the claimed precision is exactly the precision of the most specific
      semantic field supplied: city fields demand ``city`` precision,
      administrative fields demand ``administrative_area`` precision, and a
      claim with no administrative/city field is a ``country`` claim.

    Coordinates are provider observation, never a precision claim: a
    coordinate pair does not upgrade the claim's semantic precision.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    country_code: str | None = None
    administrative_area: str | None = None
    administrative_area_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    precision: LocationPrecision

    @field_validator("country_code")
    @classmethod
    def _validate_country_code(cls, value: str | None) -> str | None:
        """Normalize and bound an optional two-letter country code."""
        if value is None:
            return None
        normalized = value.strip().upper()
        if len(normalized) != 2 or not normalized.isalpha():
            raise ValueError(
                "claim country_code must be two uppercase letters when supplied"
            )
        return normalized

    @field_validator("administrative_area", "city")
    @classmethod
    def _validate_geographic_name(cls, value: str | None) -> str | None:
        """Apply the deterministic name normalization contract when present."""
        if value is None:
            return None
        normalized = normalize_reference_name(value)
        if not normalized:
            raise ValueError("claim geographic name must not be blank")
        if len(normalized) > _NAME_MAX_LENGTH:
            raise ValueError(
                f"claim geographic name exceeds the maximum length of {_NAME_MAX_LENGTH}"
            )
        return normalized

    @field_validator("administrative_area_code")
    @classmethod
    def _validate_admin_code(cls, value: str | None) -> str | None:
        """Require a trimmed nonblank bounded administrative code when present."""
        if value is None:
            return None
        return _normalize_code(value, "claim administrative code")

    @field_validator("latitude", "longitude")
    @classmethod
    def _validate_finite(cls, value: float | None) -> float | None:
        """Reject non-finite coordinates while preserving ``None``."""
        if value is None:
            return None
        if not math.isfinite(value):
            raise ValueError("claim coordinates must be finite")
        return value

    @model_validator(mode="after")
    def _validate_claim_shape(self) -> "GeographicClaim":
        """Enforce coordinate pairing, WGS84 bounds, and precision support."""
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("claim latitude and longitude must be supplied together")
        if self.latitude is not None and not (-90.0 <= self.latitude <= 90.0):
            raise ValueError("claim latitude must be within [-90, 90]")
        if self.longitude is not None and not (-180.0 <= self.longitude <= 180.0):
            raise ValueError("claim longitude must be within [-180, 180]")
        if self.city is not None:
            if self.precision is not LocationPrecision.CITY:
                raise ValueError(
                    "claim city field requires city precision; coordinates and "
                    "labels never upgrade claim precision"
                )
        elif (
            self.administrative_area is not None
            or self.administrative_area_code is not None
        ):
            if self.precision is not LocationPrecision.ADMINISTRATIVE_AREA:
                raise ValueError(
                    "claim administrative field requires administrative_area "
                    "precision; coordinates and labels never upgrade claim precision"
                )
        elif self.precision is not LocationPrecision.COUNTRY:
            raise ValueError(
                "claim precision cannot exceed the semantic fields supplied"
            )
        return self


RESOLVED_REASON_CODES = frozenset(
    {"exact_semantic_match", "containment_disambiguation"}
)
"""Reason codes for :class:`CanonicalLocationResolution` RESOLVED outcomes."""

AMBIGUOUS_REASON_CODES = frozenset(
    {"multiple_candidates", "competing_boundary_coverage"}
)
"""Reason codes for :class:`CanonicalLocationResolution` AMBIGUOUS outcomes."""

UNRESOLVABLE_REASON_CODES = frozenset(
    {
        "missing_semantic_context",
        "missing_country_context",
        "unknown_country",
        "unknown_administrative_area",
        "unknown_city",
    }
)
"""Reason codes for :class:`CanonicalLocationResolution` UNRESOLVABLE outcomes."""


class CanonicalLocationResolutionStatus(str, Enum):
    """Deterministic canonical geography resolution outcome (PR 26B).

    Resolution outcomes are first-class results, never exceptions; malformed
    *input* remains an error raised by claim validation.
    """

    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    UNRESOLVABLE = "unresolvable"


class LocationCandidate(BaseModel):
    """One equally-valued canonical Location candidate and how it matched."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    location: Location
    matched_fields: tuple[str, ...] = ()


class CanonicalLocationResolution(BaseModel):
    """Bounded result algebra for claim -> canonical Location resolution.

    Invariants:

    - ``resolved``: exactly one canonical Location, exposed in both
      ``location`` and the single candidate;
    - ``ambiguous``: no selected Location and at least two deterministic
      candidates;
    - ``unresolvable``: no Location and no candidates, with a reason code.

    ``reason_code`` is drawn from the closed PR 26B vocabularies above.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: CanonicalLocationResolutionStatus
    location: Location | None = None
    candidates: tuple[LocationCandidate, ...] = ()
    reason_code: str | None = None

    @model_validator(mode="after")
    def _validate_result_shape(self) -> "CanonicalLocationResolution":
        """Enforce the documented invariant per outcome status."""
        if self.status is CanonicalLocationResolutionStatus.RESOLVED:
            if self.location is None:
                raise ValueError("resolved resolution requires a location")
            if len(self.candidates) != 1:
                raise ValueError("resolved resolution requires exactly one candidate")
            if self.candidates[0].location != self.location:
                raise ValueError("resolved resolution candidate must equal the result")
            if self.reason_code not in RESOLVED_REASON_CODES:
                raise ValueError(
                    f"reason_code must be one of {sorted(RESOLVED_REASON_CODES)}"
                )
        elif self.status is CanonicalLocationResolutionStatus.AMBIGUOUS:
            if self.location is not None:
                raise ValueError("ambiguous resolution must not select a location")
            if len(self.candidates) < 2:
                raise ValueError(
                    "ambiguous resolution requires at least two candidates"
                )
            if self.reason_code not in AMBIGUOUS_REASON_CODES:
                raise ValueError(
                    f"reason_code must be one of {sorted(AMBIGUOUS_REASON_CODES)}"
                )
        else:
            if self.location is not None:
                raise ValueError("unresolvable resolution must not select a location")
            if self.candidates:
                raise ValueError("unresolvable resolution must not carry candidates")
            if self.reason_code not in UNRESOLVABLE_REASON_CODES:
                raise ValueError(
                    f"reason_code must be one of {sorted(UNRESOLVABLE_REASON_CODES)}"
                )
        return self
