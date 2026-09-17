# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Exact GEOLOCATION LegacyEvidence -> geographic claim extraction (PR 26C).

The worker seam converts one immutable ``GEOLOCATION`` LegacyEvidence observation
into the bounded :class:`GeographicClaim` consumed by PR 26C's
:class:`LocationResolver`. The conversion is pure: no external I/O, no
Location creation, no persistence. Only the already-observed facts
(``country_code``, ``region``/``administrative_area``,
``administrative_area_code``, ``city``, ``latitude``, ``longitude``) are
mapped, and the claim's precision never exceeds the semantic detail the
source actually supplied (coordinates never upgrade precision).

Malformed or unsupported payloads fail closed with a typed bounded error:

- non-``GEOLOCATION`` LegacyEvidence raises :class:`GeoEvidenceTypeError`;
- payloads with no geographic facts, non-finite/out-of-range coordinates,
  or a precision vocabulary the claim contract rejects raise
  :class:`InvalidGeographicClaimError`.
"""

from __future__ import annotations

import math
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from agentic_threat_investigator.app.persistence.repositories import (
    GeoEvidenceTypeError,
    InvalidGeographicClaimError,
)
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.geoint import (
    GeographicClaim,
    LocationPrecision,
)
from agentic_threat_investigator.domain.legacy_evidence import LegacyEvidence

# Persisted facts precision vocabulary (mirrors the DB-IP City Lite
# normalization output consumed by the PR 25A projection): the claim keeps
# the source's precision only when the source declared one; otherwise the
# minimal precision supported by the supplied semantic fields is derived.
_PRECISION_FROM_FACT = {
    "country": LocationPrecision.COUNTRY,
    "region": LocationPrecision.ADMINISTRATIVE_AREA,
    "city": LocationPrecision.CITY,
}

_FACT_COUNTRY_CODE = "country_code"
_FACT_REGION = "region"
_FACT_ADMINISTRATIVE_AREA = "administrative_area"
_FACT_ADMINISTRATIVE_AREA_CODE = "administrative_area_code"
_FACT_CITY = "city"
_FACT_LATITUDE = "latitude"
_FACT_LONGITUDE = "longitude"
_FACT_PRECISION = "precision"


def _optional_string(facts: dict[str, Any], key: str) -> str | None:
    """Return a non-blank optional string fact, or ``None`` when absent.

    A present but non-string or blank value is a contract failure, never a
    silent repair.
    """
    if key not in facts or facts[key] is None:
        return None
    value = facts[key]
    if not isinstance(value, str) or not value.strip():
        raise InvalidGeographicClaimError(
            f"persisted geolocation fact {key!r} must be a non-blank string"
        )
    return value


def _optional_coordinate(facts: dict[str, Any], key: str) -> float | None:
    """Return an optional finite real coordinate, or ``None`` when absent.

    Booleans, non-numeric values, and non-finite values are contract
    failures; arbitrary strings are never coerced into coordinates.
    """
    if key not in facts or facts[key] is None:
        return None
    value = facts[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidGeographicClaimError(
            f"persisted geolocation fact {key!r} must be a real number"
        )
    coordinate = float(value)
    if not math.isfinite(coordinate):
        raise InvalidGeographicClaimError(
            f"persisted geolocation fact {key!r} must be finite"
        )
    return coordinate


def _derived_precision(facts: dict[str, Any]) -> LocationPrecision:
    """Return the minimal precision supported by the supplied semantic fields.

    A city fact supports city precision, an administrative fact supports
    administrative-area precision, and a claim with none of them is a
    country-precision claim (coordinates never upgrade precision).
    """
    if _optional_string(facts, _FACT_CITY) is not None:
        return LocationPrecision.CITY
    if (
        _optional_string(facts, _FACT_REGION) is not None
        or _optional_string(facts, _FACT_ADMINISTRATIVE_AREA) is not None
        or _optional_string(facts, _FACT_ADMINISTRATIVE_AREA_CODE) is not None
    ):
        return LocationPrecision.ADMINISTRATIVE_AREA
    return LocationPrecision.COUNTRY


def geographic_claim_from_evidence(evidence: LegacyEvidence) -> GeographicClaim:
    """Build the bounded claim from the exact GEOLOCATION LegacyEvidence facts.

    Requires ``GEOLOCATION`` LegacyEvidence; maps only the existing
    country/admin/admin-code/city/lat/lon facts and preserves the source's
    semantic precision (a declared source precision is kept, otherwise the
    minimal supported precision is derived). The :class:`GeographicClaim`
    validator is the final authority: any vocabulary mismatch fails closed
    as :class:`InvalidGeographicClaimError`.
    """
    if evidence.type is not EvidenceType.GEOLOCATION:
        raise GeoEvidenceTypeError(evidence.id or UUID(int=0))

    facts = evidence.facts
    country_code = _optional_string(facts, _FACT_COUNTRY_CODE)
    region = _optional_string(facts, _FACT_REGION)
    administrative_area = _optional_string(facts, _FACT_ADMINISTRATIVE_AREA)
    administrative_area_code = _optional_string(facts, _FACT_ADMINISTRATIVE_AREA_CODE)
    city = _optional_string(facts, _FACT_CITY)
    latitude = _optional_coordinate(facts, _FACT_LATITUDE)
    longitude = _optional_coordinate(facts, _FACT_LONGITUDE)

    semantic_fields = (
        country_code,
        region,
        administrative_area,
        administrative_area_code,
        city,
        latitude,
        longitude,
    )
    if all(field is None for field in semantic_fields):
        raise InvalidGeographicClaimError(
            "persisted geolocation evidence carries no geographic facts"
        )

    precision_fact = facts.get(_FACT_PRECISION)
    if precision_fact is None:
        precision = None
    elif not isinstance(precision_fact, str):
        raise InvalidGeographicClaimError(
            "persisted geolocation fact 'precision' must be a string"
        )
    else:
        normalized_precision = precision_fact.strip().lower()
        if not normalized_precision:
            raise InvalidGeographicClaimError(
                "persisted geolocation fact 'precision' must not be blank"
            )
        if normalized_precision == "unknown":
            # The source declares no supported precision; the minimal
            # precision supported by the supplied semantic fields is derived.
            precision = None
        else:
            precision = _PRECISION_FROM_FACT.get(normalized_precision)
            if precision is None:
                raise InvalidGeographicClaimError(
                    "persisted geolocation fact 'precision' uses an "
                    "unsupported vocabulary"
                )
    if precision is None:
        precision = _derived_precision(facts)

    try:
        return GeographicClaim(
            country_code=country_code,
            administrative_area=administrative_area or region,
            administrative_area_code=administrative_area_code,
            city=city,
            latitude=latitude,
            longitude=longitude,
            precision=precision,
        )
    except ValidationError as error:
        raise InvalidGeographicClaimError(str(error)) from error
