# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation-scoped geolocation read projection (PR 25A).

The Map dataset is a deterministic, bounded, Investigation-scoped read
projection derived exclusively from already-persisted immutable
``GEOLOCATION`` Evidence joined to its canonical IP entity. This module owns
the typed read models and the pure persisted-facts mapping boundary; it
never performs provider lookups, opens MMDB artifacts, executes
orchestration, consults an LLM, or reads any other source.
"""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agentic_threat_investigator.app.query.models import normalize_utc
from agentic_threat_investigator.domain.geolocation import GeoPrecision

DEFAULT_MAX_MAP_GEOLOCATION_ITEMS = 500
"""Initial server-owned hard bound for one geolocation projection.

The map dataset is returned as one coherent bounded visualization set; this
bound is semantically separate from pageable collection sizes. The
authoritative runtime value is injected from configuration when the query
bundle is composed.
"""

_MIN_LATITUDE = -90.0
_MAX_LATITUDE = 90.0
_MIN_LONGITUDE = -180.0
_MAX_LONGITUDE = 180.0

_COUNTRY_CODE = re.compile(r"[A-Z]{2}")
"""Exact grammar of the persisted normalized country-code vocabulary.

The existing DB-IP City Lite producer normalizes country codes to exactly
two uppercase ASCII letters; the read projection validates that persisted
representation and fails closed on anything else.
"""


class GeolocationFactsError(ValueError):
    """Persisted ``GEOLOCATION`` facts violate the read projection contract.

    Raised by the pure facts mapper and translated centrally into a safe
    internal contract error; raw fact values never reach the public
    boundary.
    """


class InvestigationGeolocationItem(BaseModel):
    """One current persisted geolocation context item for one IP entity.

    ``evidence_id`` is the exact immutable Evidence observation that produced
    this projection: the latest ``GEOLOCATION`` Evidence for the entity by
    (``retrieved_at DESC, id ASC``). Country/region/city and the paired
    latitude/longitude are approximate network-address context only; they
    never identify the physical location of an attacker or device and carry
    no maliciousness or attribution semantics.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: UUID
    entity_id: UUID
    ip_address: str
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    precision: GeoPrecision
    provider: str
    observed_at: datetime | None = None
    retrieved_at: datetime

    @field_validator("observed_at", "retrieved_at")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized timestamps."""
        return normalize_utc(value)

    @field_validator("ip_address", "provider")
    @classmethod
    def not_blank(cls, value: str) -> str:
        """Reject blank canonical IP identities and provider identifiers."""
        if not value.strip():
            raise ValueError("geolocation string fields must not be blank")
        return value

    @model_validator(mode="after")
    def coordinate_pair(self) -> "InvestigationGeolocationItem":
        """Require the coordinate pair to be complete, finite, and in range.

        A partial pair (one coordinate present) fails closed: a map point
        must never plot a single coordinate. Both coordinates may validly be
        absent; valid geographic context without map coordinates is retained.
        """
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("geolocation coordinates must be a complete pair")
        if self.latitude is not None:
            if not math.isfinite(self.latitude):
                raise ValueError("geolocation latitude must be finite")
            if not _MIN_LATITUDE <= self.latitude <= _MAX_LATITUDE:
                raise ValueError("geolocation latitude is out of range")
        if self.longitude is not None:
            if not math.isfinite(self.longitude):
                raise ValueError("geolocation longitude must be finite")
            if not _MIN_LONGITUDE <= self.longitude <= _MAX_LONGITUDE:
                raise ValueError("geolocation longitude is out of range")
        return self


class InvestigationGeolocationResult(BaseModel):
    """One bounded Investigation geolocation projection.

    ``items`` carries at most the configured server-owned maximum current
    geolocation context items in the canonical deterministic order
    (``ip_address ASC, entity_id ASC``); ``truncated`` is true exactly when
    the projection exceeded the bound. No cursor is exposed: this is one
    coherent visualization dataset, never a pageable collection.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[InvestigationGeolocationItem, ...]
    truncated: bool


class InvestigationGeolocationQueryService(ABC):
    """Analyst-facing investigation geolocation read contract (PR 25A).

    The Investigation scope is mandatory; there is no global geolocation
    browse contract in v0.1.
    """

    @abstractmethod
    async def list_for_investigation(
        self, investigation_id: UUID
    ) -> InvestigationGeolocationResult:
        """Return the bounded current geolocation projection for one Investigation.

        The projection is derived only from persisted ``GEOLOCATION``
        Evidence of the Investigation; exactly one latest observation is
        selected per IP entity with the exact persisted Evidence ID retained
        as provenance.
        """


def _require_string(facts: Mapping[str, Any], key: str) -> str:
    """Return one required non-blank string fact or fail the read contract."""
    value = facts.get(key)
    if not isinstance(value, str) or not value.strip():
        raise GeolocationFactsError(
            f"persisted geolocation fact {key!r} is missing or invalid"
        )
    return value.strip()


def _optional_string(facts: Mapping[str, Any], key: str) -> str | None:
    """Return an optional non-blank string fact, or ``None`` when absent.

    A present but non-string or blank value is a persistence contract
    failure, never a silent repair.
    """
    if key not in facts or facts[key] is None:
        return None
    value = facts[key]
    if not isinstance(value, str) or not value.strip():
        raise GeolocationFactsError(f"persisted geolocation fact {key!r} is invalid")
    return value.strip()


def _optional_coordinate(facts: Mapping[str, Any], key: str) -> float | None:
    """Return an optional finite real coordinate, or ``None`` when absent.

    Booleans, non-numeric values, and non-finite values (NaN, infinity) are
    contract failures; arbitrary strings are never coerced into coordinates.
    """
    if key not in facts or facts[key] is None:
        return None
    value = facts[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GeolocationFactsError(
            f"persisted geolocation fact {key!r} must be a real number"
        )
    coordinate = float(value)
    if not math.isfinite(coordinate):
        raise GeolocationFactsError(
            f"persisted geolocation fact {key!r} must be finite"
        )
    return coordinate


def geolocation_item_from_persisted_facts(
    *,
    evidence_id: UUID,
    entity_id: UUID,
    ip_address: str,
    facts: Mapping[str, Any] | None,
    observed_at: datetime | None,
    retrieved_at: datetime,
) -> InvestigationGeolocationItem:
    """Map one persisted ``GEOLOCATION`` Evidence onto the typed read item.

    Only the approved normalized facts are consumed; unknown extra facts are
    ignored rather than leaked. Malformed persisted data raises
    :class:`GeolocationFactsError` instead of being silently dropped or
    reinterpreted: silently dropping corrupt rows would make the map
    incomplete without telling the analyst and could hide a
    persistence/normalization defect.
    """
    if facts is None:
        raise GeolocationFactsError("persisted geolocation facts are missing")

    provider = _require_string(facts, "provider")
    precision_value = _require_string(facts, "precision")
    try:
        precision = GeoPrecision(precision_value)
    except ValueError:
        raise GeolocationFactsError(
            "persisted geolocation precision is outside the approved vocabulary"
        ) from None

    country_code = _optional_string(facts, "country_code")
    if country_code is not None and not _COUNTRY_CODE.fullmatch(country_code):
        raise GeolocationFactsError(
            "persisted geolocation country code is not two ASCII letters"
        )
    region = _optional_string(facts, "region")
    city = _optional_string(facts, "city")

    latitude = _optional_coordinate(facts, "latitude")
    longitude = _optional_coordinate(facts, "longitude")
    if (latitude is None) != (longitude is None):
        raise GeolocationFactsError(
            "persisted geolocation coordinates must be a complete pair"
        )

    return InvestigationGeolocationItem(
        evidence_id=evidence_id,
        entity_id=entity_id,
        ip_address=ip_address,
        country_code=country_code,
        region=region,
        city=city,
        latitude=latitude,
        longitude=longitude,
        precision=precision,
        provider=provider,
        observed_at=observed_at,
        retrieved_at=retrieved_at,
    )
