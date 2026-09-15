# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Source-neutral geographic reference corpus contracts (PR 26B).

Reference sources (GeoNames-style naming/hierarchy and Natural Earth-style
boundary geometry upstream) are parsed by source adapters into one
deterministic normalized record type, :class:`GeographicReferenceRecord`,
that the canonical reference ingestion service consumes. ``Location`` never
becomes a GeoNames/Natural-Earth-specific model, and external source record
identifiers never participate in ATI canonical identity.

A record's parent is expressed by the parent's own canonical identity, never
by a database row identifier, so canonical identity (and its deterministic
UUIDv5 derivation) is input-order independent and clean-vs-existing
database equivalent.
"""

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agentic_threat_investigator.domain.geoint import (
    LocationType,
    normalize_reference_name,
)

_NAME_MAX_LENGTH = 200
_CODE_MAX_LENGTH = 64
_EWKT_MAX_LENGTH = 1_000_000


class ReferenceParent(BaseModel):
    """The canonical identity of the reference parent of one record.

    ``location_type`` is the *reference* type of the parent object: countries
    have no parent, administrative areas have a country parent, and cities
    have an administrative-area parent.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    location_type: LocationType
    country_code: str
    admin1_code: str | None = None
    admin2_code: str | None = None
    canonical_name: str

    @field_validator("country_code")
    @classmethod
    def _validate_country_code(cls, value: str) -> str:
        """Normalize the parent's two-letter country code."""
        normalized = value.strip().upper()
        if len(normalized) != 2 or not normalized.isalpha():
            raise ValueError("parent country_code must be two uppercase letters")
        return normalized

    @field_validator("admin1_code", "admin2_code")
    @classmethod
    def _validate_admin_code(cls, value: str | None) -> str | None:
        """Require a trimmed nonblank bounded administrative code when present."""
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("parent administrative code must not be blank")
        if len(trimmed) > _CODE_MAX_LENGTH:
            raise ValueError(
                f"parent administrative code exceeds the maximum length of "
                f"{_CODE_MAX_LENGTH}"
            )
        return trimmed

    @field_validator("canonical_name")
    @classmethod
    def _validate_canonical_name(cls, value: str) -> str:
        """Apply the deterministic name normalization contract."""
        normalized = normalize_reference_name(value)
        if not normalized:
            raise ValueError("parent canonical_name must not be blank")
        if len(normalized) > _NAME_MAX_LENGTH:
            raise ValueError(
                f"parent canonical_name exceeds the maximum length of "
                f"{_NAME_MAX_LENGTH}"
            )
        return normalized


class GeographicReferenceRecord(BaseModel):
    """One normalized source-neutral canonical reference record.

    Validation enforces the approved parent rules deterministically:

    - ``country`` records have no parent and no admin codes;
    - ``administrative_area`` and ``city`` records require a parent and an
      ``admin1_code``;
    - exact authoritative geometry validation (validity, SRID 4326, type,
      emptiness, WGS84 bounds) is owned by the versioned SQL write function;
      the DTO only bounds the serialized EWKT text.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    location_type: LocationType
    name: str
    canonical_name: str
    country_code: str
    admin1_code: str | None = None
    admin2_code: str | None = None
    parent: ReferenceParent | None = None
    geometry: str | None = None
    centroid: str | None = None

    @field_validator("name", "canonical_name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        """Apply the deterministic name normalization contract."""
        normalized = normalize_reference_name(value)
        if not normalized:
            raise ValueError("reference record name must not be blank")
        if len(normalized) > _NAME_MAX_LENGTH:
            raise ValueError(
                f"reference record name exceeds the maximum length of {_NAME_MAX_LENGTH}"
            )
        return normalized

    @field_validator("country_code")
    @classmethod
    def _validate_country_code(cls, value: str) -> str:
        """Normalize the record's two-letter country code."""
        normalized = value.strip().upper()
        if len(normalized) != 2 or not normalized.isalpha():
            raise ValueError(
                "reference record country_code must be two uppercase letters"
            )
        return normalized

    @field_validator("admin1_code", "admin2_code")
    @classmethod
    def _validate_admin_code(cls, value: str | None) -> str | None:
        """Require a trimmed nonblank bounded administrative code when present."""
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("reference record administrative code must not be blank")
        if len(trimmed) > _CODE_MAX_LENGTH:
            raise ValueError(
                f"reference record administrative code exceeds the maximum "
                f"length of {_CODE_MAX_LENGTH}"
            )
        return trimmed

    @field_validator("geometry", "centroid")
    @classmethod
    def _validate_spatial_text(cls, value: str | None) -> str | None:
        """Bound the serialized EWKT text without parsing the geometry."""
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("reference record geometry must not be blank")
        if len(stripped) > _EWKT_MAX_LENGTH:
            raise ValueError(
                f"reference record geometry exceeds the maximum length of "
                f"{_EWKT_MAX_LENGTH}"
            )
        return stripped

    @model_validator(mode="after")
    def _validate_record_shape(self) -> "GeographicReferenceRecord":
        """Enforce the approved parent/admin shape rules fail-closed."""
        if self.location_type is LocationType.COUNTRY:
            if self.parent is not None:
                raise ValueError("country reference record must not have a parent")
            if self.admin1_code is not None or self.admin2_code is not None:
                raise ValueError("country reference record must not have admin codes")
        else:
            if self.parent is None:
                raise ValueError(
                    f"{self.location_type.value} reference record requires a parent"
                )
            if self.admin1_code is None:
                raise ValueError(
                    f"{self.location_type.value} reference record requires an "
                    f"admin1_code"
                )
        return self
