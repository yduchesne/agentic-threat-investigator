# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation-scoped GEOINT read contracts (PR 26D).

Every analyst GEOINT read is bounded and Investigation-scoped, and every
returned geographic observation remains traceable to its exact
``EntityLocationObservation`` and exact Evidence provenance. Investigation
scope is proved through the exact immutable Evidence chain
(``EntityLocationObservation.evidence_id -> Evidence.investigation_id``);
it is never inferred from shared Entity or Location identity.

The module owns the typed query inputs, the frozen read models, the pure
persisted-row mapping boundary, and the :class:`GeointQueryService` ABC.
It never performs mutations, arbitrary PostGIS expressions, or provider
lookups; the concrete PostgreSQL implementation lives in the query
infrastructure and executes purpose-built bounded SELECT statements only.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from agentic_threat_investigator.app.query.models import (
    QueryPage,
    normalize_utc,
)
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    filter_fingerprint,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)

DEFAULT_GEONT_SUMMARY_TOP_LOCATIONS = 10
"""Server-owned hard bound on summary ``top_locations`` groups.

The summary is one bounded analyst-facing dataset, not a pageable
collection; this bound is semantically distinct from page sizes. The
authoritative runtime value is injected from configuration when the query
bundle is composed.
"""

T = TypeVar("T")

_MIN_LATITUDE = -90.0
_MAX_LATITUDE = 90.0
_MIN_LONGITUDE = -180.0
_MAX_LONGITUDE = 180.0


class GeointReadError(RuntimeError):
    """Persisted GEOINT state violates the analyst read contract.

    Raised by the pure persisted-row mappers and translated centrally into
    a safe internal contract error; raw persisted values never reach the
    public boundary. Subclasses ``RuntimeError`` (not ``ValueError``) so the
    generic route ``ValueError`` -> 400 translation never mistakes corrupt
    database state for a user-input failure.
    """


def _require_enum(field_name: str, enum_type: type[object], value: object) -> object:
    """Convert one persisted vocabulary value, failing the read closed."""
    try:
        return enum_type(value)  # type: ignore[call-arg]
    except TypeError, ValueError:
        raise GeointReadError(
            f"persisted geoint {field_name} value is outside the approved vocabulary"
        ) from None


def _require_uuid(field_name: str, value: object) -> UUID:
    """Convert one persisted UUID identity, failing the read closed."""
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except TypeError, ValueError:
        raise GeointReadError(
            f"persisted geoint {field_name} is not a valid UUID"
        ) from None


def _optional_coordinate(value: object, label: str) -> float | None:
    """Convert one optional persisted coordinate, failing the read closed.

    Booleans, non-numeric values, non-finite values, and out-of-range values
    are contract failures and never coerced into coordinates.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GeointReadError(f"persisted geoint {label} must be a real number")
    coordinate = float(value)
    if not math.isfinite(coordinate):
        raise GeointReadError(f"persisted geoint {label} must be finite")
    if label == "latitude" and not _MIN_LATITUDE <= coordinate <= _MAX_LATITUDE:
        raise GeointReadError(f"persisted geoint {label} is out of range")
    if label == "longitude" and not _MIN_LONGITUDE <= coordinate <= _MAX_LONGITUDE:
        raise GeointReadError(f"persisted geoint {label} is out of range")
    return coordinate


def _require_str(field_name: str, value: object) -> str:
    """Require one persisted non-blank string, failing the read closed."""
    if not isinstance(value, str) or not value.strip():
        raise GeointReadError(f"persisted geoint {field_name} is missing or invalid")
    return value


def _optional_str(field_name: str, value: object) -> str | None:
    """Convert one optional persisted string, failing the read closed."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise GeointReadError(f"persisted geoint {field_name} must be a string")
    return value


def _require_datetime(field_name: str, value: object) -> datetime:
    """Require one persisted aware UTC datetime, failing the read closed."""
    if not isinstance(value, datetime):
        raise GeointReadError(f"persisted geoint {field_name} is missing or invalid")
    if value.tzinfo is None or value.utcoffset() is None:
        raise GeointReadError(f"persisted geoint {field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _optional_datetime(field_name: str, value: object) -> datetime | None:
    """Convert one optional persisted aware UTC datetime, failing the read closed."""
    if value is None:
        return None
    return _require_datetime(field_name, value)


# ---------------------------------------------------------------------------
# Typed query inputs
# ---------------------------------------------------------------------------


class GeointSummaryQuery(BaseModel):
    """Bounded Investigation-scoped geographic summary request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID


class GeointEntityQuery(BaseModel):
    """Bounded Investigation-scoped Entity geographic-context request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    entity_id: UUID


class GeointObservationQuery(BaseModel):
    """Bounded Investigation-scoped exact geographic observation request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    observation_id: UUID


class GeointEntityObservationListQuery(BaseModel):
    """Bounded pageable Entity geographic history request (PR 26D).

    Canonical order is the exact PR 26A currentness ordering
    (``COALESCE(observed_at, retrieved_at) DESC, observation id DESC``): the
    newest qualifying observation within the path Investigation is first,
    and the UUID tie-break direction matches the persisted reconciliation
    semantics with the greater pair winning.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    entity_id: UUID
    limit: int = Field(ge=1)
    cursor: str | None = None

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {"investigation_id": self.investigation_id, "entity_id": self.entity_id}
        )


class GeointLocationEntityListQuery(BaseModel):
    """Bounded pageable Location-to-Entity reverse lookup (PR 26D).

    ``include_contained=false`` (default) selects the exact canonical
    Location only; ``include_contained=true`` additionally selects child
    canonical Locations spatially covered by the selected Location boundary
    (country/admin representative geometry via boundary-inclusive
    ``ST_Covers``). A city Point never expands: contained behaves exactly as
    the exact-city selection with no invented radius. Each Entity appears
    once in deterministic ``(entity_type, canonical_value, entity_id)``
    order using its latest qualifying observation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    location_id: UUID
    include_contained: bool = False
    limit: int = Field(ge=1)
    cursor: str | None = None

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "investigation_id": self.investigation_id,
                "location_id": self.location_id,
                "include_contained": self.include_contained,
            }
        )


class GeointLocationObservationListQuery(BaseModel):
    """Bounded pageable Location-to-observation listing (PR 26D).

    The ordering and containment semantics mirror
    :class:`GeointLocationEntityListQuery`; the response exposes every
    qualifying immutable observation, never a deduplicated Entity set.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    location_id: UUID
    include_contained: bool = False
    limit: int = Field(ge=1)
    cursor: str | None = None

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "investigation_id": self.investigation_id,
                "location_id": self.location_id,
                "include_contained": self.include_contained,
            }
        )


# ---------------------------------------------------------------------------
# Read models
# ---------------------------------------------------------------------------


class GeointLocationRef(BaseModel):
    """Bounded display reference to one canonical Location (PR 26D).

    Exposes only approved reference fields and the centroid latitude/
    longitude pair when available; raw EWKT/WKB geometry, upstream metadata,
    and provider payloads are never part of the analyst read surface.
    Location is reference geography, never a threat Entity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    location_id: UUID
    location_type: LocationType
    canonical_name: str
    country_code: str
    admin1_code: str | None = None
    admin2_code: str | None = None
    parent_location_id: UUID | None = None
    latitude: float | None = None
    longitude: float | None = None

    @field_validator("canonical_name", "country_code")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        """Reject blank canonical names and country codes."""
        if not value.strip():
            raise ValueError("geoint location textual fields must not be blank")
        return value

    @model_validator(mode="after")
    def _validate_coordinates(self) -> "GeointLocationRef":
        """Require the centroid coordinate pair to be complete and in range."""
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("geoint location coordinates must be a complete pair")
        if self.latitude is not None and not math.isfinite(self.latitude):
            raise ValueError("geoint location latitude must be finite")
        if self.longitude is not None and not math.isfinite(self.longitude):
            raise ValueError("geoint location longitude must be finite")
        if self.latitude is not None and not (
            _MIN_LATITUDE <= self.latitude <= _MAX_LATITUDE
        ):
            raise ValueError("geoint location latitude is out of range")
        if self.longitude is not None and not (
            _MIN_LONGITUDE <= self.longitude <= _MAX_LONGITUDE
        ):
            raise ValueError("geoint location longitude is out of range")
        return self


class GeointObservationItem(BaseModel):
    """One immutable geographic observation with exact provenance.

    ``observation_id`` is the exact ``EntityLocationObservation`` identity
    and ``evidence_observation_id`` is the exact immutable
    EvidenceObservation that produced it (PR 28B); observation -> Evidence
    drill-down is exact through the existing Evidence detail contract.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: UUID
    entity_id: UUID
    location: GeointLocationRef
    evidence_observation_id: UUID
    precision: LocationPrecision
    resolution_method: str
    observed_at: datetime | None = None
    retrieved_at: datetime
    resolved_at: datetime

    @field_validator("observed_at", "retrieved_at", "resolved_at")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized timestamps."""
        return normalize_utc(value)

    @field_validator("resolution_method")
    @classmethod
    def _method_not_blank(cls, value: str) -> str:
        """Reject blank resolution-method identifiers."""
        if not value.strip():
            raise ValueError("geoint resolution_method must not be blank")
        return value


class GeointEntityLocationItem(BaseModel):
    """One Entity's Investigation-relative current geographic context.

    ``current_observation`` is the newest qualifying observation **within
    the path Investigation** under the exact PR 26A currentness ordering;
    it is explicitly not the global ``EntityLocation`` materialized state,
    which may have been advanced by another Investigation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    entity_type: EntityType
    entity_value: str
    display_name: str | None = None
    current_observation: GeointObservationItem

    @field_validator("entity_value")
    @classmethod
    def _value_not_blank(cls, value: str) -> str:
        """Reject blank canonical entity values."""
        if not value.strip():
            raise ValueError("geoint entity_value must not be blank")
        return value


class GeointObservationDetail(BaseModel):
    """One exact geographic observation with bounded display context.

    The immutable observation carries the exact ``evidence_id``; full
    Evidence drill-down remains the existing Evidence detail endpoint. Only
    bounded Entity display context and the exact Location reference are
    exposed; raw provider payloads and boundary geometry never are.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation: GeointObservationItem
    entity_type: EntityType
    entity_value: str
    display_name: str | None = None

    @field_validator("entity_value")
    @classmethod
    def _value_not_blank(cls, value: str) -> str:
        """Reject blank canonical entity values."""
        if not value.strip():
            raise ValueError("geoint entity_value must not be blank")
        return value


class GeointTopLocation(BaseModel):
    """One exact observed Location group in the bounded summary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    location: GeointLocationRef
    scoped_entity_count: int

    @model_validator(mode="after")
    def _validate_count(self) -> "GeointTopLocation":
        """Require a non-negative scoped entity count."""
        if self.scoped_entity_count < 0:
            raise ValueError("geoint top-location entity count must not be negative")
        return self


class GeointPrecisionCounts(BaseModel):
    """Observation counts by the approved precision vocabulary.

    The three keys are exact observation counts; a persisted precision
    outside the approved vocabulary fails the read closed instead of being
    silently dropped from a count.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    country: int = 0
    administrative_area: int = 0
    city: int = 0


class GeointSummary(BaseModel):
    """One bounded Investigation-scoped geographic summary (PR 26D).

    Counts are exact scoped facts, never risk/concentration/attribution
    labels: same/contained/near geography never implies a threat
    relationship. ``top_locations`` carries at most the configured server
    bound in deterministic ``scoped entity count DESC, canonical name ASC,
    Location UUID ASC`` order; ``truncated`` is true exactly when more
    groups existed beyond the bound.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_count_with_location: int
    observation_count: int
    location_count: int
    country_count: int
    administrative_area_count: int
    city_count: int
    precision_counts: GeointPrecisionCounts
    top_locations: tuple[GeointTopLocation, ...]
    truncated: bool

    @model_validator(mode="after")
    def _validate_counts(self) -> "GeointSummary":
        """Require the exact per-type and precision counts to be consistent."""
        if (
            self.country_count + self.administrative_area_count + self.city_count
            > self.location_count
        ):
            raise ValueError(
                "geoint summary per-type location counts exceed location_count"
            )
        total_precision = sum(
            (
                self.precision_counts.country,
                self.precision_counts.administrative_area,
                self.precision_counts.city,
            )
        )
        if total_precision != self.observation_count:
            raise ValueError(
                "geoint summary precision counts must equal observation_count"
            )
        if self.entity_count_with_location > self.observation_count:
            raise ValueError(
                "geoint summary entity count must not exceed observation_count"
            )
        return self


class GeointLocationPage(BaseModel, Generic[T]):
    """One bounded Location-scoped page with the containment indicator.

    Reuses the keyset page shape of :class:`QueryPage`; ``containment_applied``
    is ``true`` exactly when the selection was performed with boundary
    containment (``include_contained=true`` and a usable selected boundary
    geometry). It is ``false`` for exact selections, city Points, and a
    NULL selected boundary geometry (exact-only, never guessed).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[T, ...]
    next_cursor: str | None = None
    containment_applied: bool


# ---------------------------------------------------------------------------
# Cursor sort values
# ---------------------------------------------------------------------------


def effective_observation_time(
    observed_at: datetime | None, retrieved_at: datetime
) -> datetime:
    """Return the PR 26A effective observation time for currentness.

    ``COALESCE(observed_at, retrieved_at)`` normalized to UTC; the exact
    comparison semantics of the persisted reconcile path is
    ``(effective time, observation id)`` with the greater pair winning.
    """
    return (observed_at or retrieved_at).astimezone(UTC)


def observation_sort_values(
    observed_at: datetime | None, retrieved_at: datetime, observation_id: UUID
) -> tuple[str, str]:
    """Return canonical cursor sort values for one observation row."""
    return (
        effective_observation_time(observed_at, retrieved_at).isoformat(),
        str(observation_id),
    )


def parse_observation_cursor(
    envelope: CursorEnvelope, label: str
) -> tuple[datetime, UUID]:
    """Parse the typed continuation values of one observation cursor.

    ``label`` is the collection label used in safe error messages.
    """
    if len(envelope.sort_values) != 2:
        raise ValueError(f"{label} cursor requires effective time and id")
    effective_at = datetime.fromisoformat(envelope.sort_values[0])
    if effective_at.tzinfo is None or effective_at.utcoffset() is None:
        raise ValueError(f"{label} cursor timestamp must be timezone-aware")
    return effective_at.astimezone(UTC), UUID(envelope.sort_values[1])


def location_entity_sort_values(
    entity_type: EntityType, canonical_value: str, entity_id: UUID
) -> tuple[str, str, str]:
    """Return canonical Location-Entity cursor sort values for one row."""
    return entity_type.value, canonical_value, str(entity_id)


def parse_location_entity_cursor(
    envelope: CursorEnvelope,
) -> tuple[str, str, UUID]:
    """Parse the typed continuation values of a Location-Entity cursor."""
    if len(envelope.sort_values) != 3:
        raise ValueError("location entity cursor requires type, value, and id")
    entity_type_value, canonical_value, entity_id = envelope.sort_values
    try:
        EntityType(entity_type_value)
    except ValueError:
        raise ValueError(
            "location entity cursor entity type is outside the approved vocabulary"
        ) from None
    return entity_type_value, canonical_value, UUID(entity_id)


# ---------------------------------------------------------------------------
# Pure persisted-row mapping boundary
# ---------------------------------------------------------------------------


def _row_data(row: object) -> dict[str, Any]:
    """Return the string-keyed mapping of one persisted row projection.

    Accepts SQLAlchemy ``Row``/``RowMapping`` objects and plain mappings so
    the pure mappers never couple to a driver row type.
    """
    source = getattr(row, "_mapping", row)
    if isinstance(source, Mapping):
        return dict(source)
    if isinstance(row, Mapping):
        return dict(row)
    return {}


def geoint_location_ref_from_row(row: object) -> GeointLocationRef:
    """Map one persisted Location projection onto the bounded reference.

    Row access goes through string-key lookups so the mapper accepts the
    driver mapping of every purpose-built GEOINT statement without coupling
    to SQLAlchemy row types. Malformed persisted values fail the read
    closed with :class:`GeointReadError`.
    """
    data = _row_data(row)
    latitude = _optional_coordinate(data.get("latitude"), "latitude")
    longitude = _optional_coordinate(data.get("longitude"), "longitude")
    if (latitude is None) != (longitude is None):
        raise GeointReadError("persisted geoint centroid must be a complete pair")
    try:
        return GeointLocationRef(
            location_id=_require_uuid("location_id", data.get("location_id")),
            location_type=_require_enum(  # type: ignore[arg-type]
                "location_type", LocationType, data.get("location_type")
            ),
            canonical_name=_require_str("canonical_name", data.get("canonical_name")),
            country_code=_require_str("country_code", data.get("country_code")),
            admin1_code=_optional_str("admin1_code", data.get("admin1_code")),
            admin2_code=_optional_str("admin2_code", data.get("admin2_code")),
            parent_location_id=(
                None
                if data.get("parent_location_id") is None
                else _require_uuid("parent_location_id", data.get("parent_location_id"))
            ),
            latitude=latitude,
            longitude=longitude,
        )
    except (ValidationError, TypeError) as error:
        raise GeointReadError(
            "persisted geoint location reference is malformed"
        ) from error


def geoint_observation_item_from_row(row: object) -> GeointObservationItem:
    """Map one persisted observation+Location projection onto the read item.

    The exact ``observation_id`` and ``evidence_id`` are always preserved;
    unknown persisted columns are ignored rather than leaked.
    """
    data = _row_data(row)
    try:
        return GeointObservationItem(
            observation_id=_require_uuid("observation_id", data.get("observation_id")),
            entity_id=_require_uuid("entity_id", data.get("entity_id")),
            location=geoint_location_ref_from_row(row),
            evidence_observation_id=_require_uuid(
                "evidence_observation_id", data.get("evidence_observation_id")
            ),
            precision=_require_enum(  # type: ignore[arg-type]
                "precision", LocationPrecision, data.get("precision")
            ),
            resolution_method=_require_str(
                "resolution_method", data.get("resolution_method")
            ),
            observed_at=_optional_datetime("observed_at", data.get("observed_at")),
            retrieved_at=_require_datetime("retrieved_at", data.get("retrieved_at")),
            resolved_at=_require_datetime("resolved_at", data.get("resolved_at")),
        )
    except (ValidationError, TypeError) as error:
        raise GeointReadError("persisted geoint observation is malformed") from error


def geoint_entity_location_item_from_row(row: object) -> GeointEntityLocationItem:
    """Map one persisted Entity+observation projection onto the read item."""
    data = _row_data(row)
    try:
        return GeointEntityLocationItem(
            entity_id=_require_uuid("entity_id", data.get("entity_id")),
            entity_type=_require_enum(  # type: ignore[arg-type]
                "entity_type", EntityType, data.get("entity_type")
            ),
            entity_value=_require_str("canonical_value", data.get("canonical_value")),
            display_name=_optional_str("display_name", data.get("display_name")),
            current_observation=geoint_observation_item_from_row(row),
        )
    except (ValidationError, TypeError) as error:
        raise GeointReadError(
            "persisted geoint entity location item is malformed"
        ) from error


def geoint_observation_detail_from_row(row: object) -> GeointObservationDetail:
    """Map one persisted observation detail projection onto the read model."""
    data = _row_data(row)
    try:
        return GeointObservationDetail(
            observation=geoint_observation_item_from_row(row),
            entity_type=_require_enum(  # type: ignore[arg-type]
                "entity_type", EntityType, data.get("entity_type")
            ),
            entity_value=_require_str("canonical_value", data.get("canonical_value")),
            display_name=_optional_str("display_name", data.get("display_name")),
        )
    except (ValidationError, TypeError) as error:
        raise GeointReadError(
            "persisted geoint observation detail is malformed"
        ) from error


# ---------------------------------------------------------------------------
# Service boundary
# ---------------------------------------------------------------------------


class GeointQueryService(ABC):
    """Analyst-facing Investigation-scoped GEOINT read contract (PR 26D).

    Every read requires the path Investigation and proves scope through the
    exact Evidence chain; there is no global GEOINT browse contract in
    v0.1. Implementations are strictly read-only (SELECT only, no commit).
    """

    @abstractmethod
    async def summary(self, query: GeointSummaryQuery) -> GeointSummary:
        """Return one bounded geographic summary of the Investigation."""

    @abstractmethod
    async def get_entity(
        self, query: GeointEntityQuery
    ) -> GeointEntityLocationItem | None:
        """Return one Entity's Investigation-relative current context, if any.

        A cross-scope/missing Entity fails closed by returning ``None`` so
        the HTTP layer can map it to a 404 without enumerating resources.
        """

    @abstractmethod
    async def list_entity_observations(
        self, query: GeointEntityObservationListQuery
    ) -> QueryPage[GeointObservationItem]:
        """Return one bounded page of the Entity's scoped observation history.

        Ordering is the exact PR 26A currentness ordering with the greater
        ``(COALESCE(observed_at, retrieved_at), observation id)`` pair first.
        """

    @abstractmethod
    async def list_location_entities(
        self, query: GeointLocationEntityListQuery
    ) -> GeointLocationPage[GeointEntityLocationItem]:
        """Return one bounded page of Entities observed at the Location scope.

        Each Entity appears once using its latest qualifying observation
        under deterministic ``(entity_type, canonical_value, entity_id)``
        order.
        """

    @abstractmethod
    async def list_location_observations(
        self, query: GeointLocationObservationListQuery
    ) -> GeointLocationPage[GeointObservationItem]:
        """Return one bounded page of observations at the Location scope."""

    @abstractmethod
    async def get_observation(
        self, query: GeointObservationQuery
    ) -> GeointObservationDetail | None:
        """Return one observation bound to the Investigation, if any.

        Proves ``observation.id``, exact Evidence provenance, and the path
        Investigation scope; a cross-scope lookup fails closed with ``None``.
        """
