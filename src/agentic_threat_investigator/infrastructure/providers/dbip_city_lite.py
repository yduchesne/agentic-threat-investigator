# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""DB-IP City Lite provider for local file-backed IP geolocation.

Reads an already-present DB-IP IP to City Lite MMDB artifact through the
existing ObjectStore artifact boundary and normalizes it into approximate
``GeoLocation`` context and immutable ``GEOLOCATION`` evidence. This is a
local evidence source, not an HTTP provider: it never downloads data, never
calls the DB-IP API, holds no credentials, and never persists, creates
relationships, assesses maliciousness, or decides pivots. Geolocation is
approximate context only and never identifies the physical location of an
attacker or device.
"""

from __future__ import annotations

import io
import math
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import maxminddb

from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderError,
    ProviderErrorCode,
    ProviderResult,
    normalize_retrieval_timestamp,
    validate_investigation_entity,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.geolocation import GeoLocation, GeoPrecision
from agentic_threat_investigator.domain.identifiers import SourceId

_MAX_NAME_LENGTH = 200
"""Bound for English city/region display names."""

_COUNTRY_CODE = re.compile(r"[A-Za-z]{2}")
"""Exact grammar for a raw two-ASCII-letter country code."""

_LAT_MIN = -90.0
_LAT_MAX = 90.0
_LON_MIN = -180.0
_LON_MAX = 180.0


class MmdbOpenError(RuntimeError):
    """Raised when the City Lite MMDB artifact cannot be opened as a reader."""


class MmdbLookupError(RuntimeError):
    """Raised when an MMDB lookup fails because the database is unreadable."""


class CityLiteDatabase(ABC):
    """Read-only MMDB lookup boundary used by the DB-IP provider.

    This infrastructure-local client abstraction keeps third-party reader
    types and exceptions out of the provider contract. Implementations must
    return a mapping-like record for a matched IP or ``None`` for a miss,
    and raise :class:`MmdbLookupError` when the database cannot be read.
    """

    @abstractmethod
    def lookup(self, ip: str) -> Mapping[str, Any] | None:
        """Return the raw record for one canonical IP, or ``None`` on miss."""

    @abstractmethod
    def close(self) -> None:
        """Release the owned reader exactly once; safe to call repeatedly."""


_EXPECTED_DATABASE_TYPE = "DBIP-City-Lite"
"""Verified ``database_type`` metadata of the official DB-IP City Lite MMDB."""


class CityLiteRecordError(ValueError):
    """Raised when a matched City Lite record is malformed."""


class CityLiteMmdb(CityLiteDatabase):
    """Long-lived read-only adapter over one opened local MMDB artifact.

    Constructed once at composition time from already-resolved artifact
    bytes; it never downloads or writes. The underlying reader is opened in
    file-descriptor mode from an in-memory copy, so no host artifact path
    leaks into provider behavior or evidence.
    """

    def __init__(self, payload: bytes) -> None:
        """Open one read-only reader over the artifact bytes."""
        try:
            self._reader: maxminddb.Reader | None = maxminddb.open_database(
                io.BytesIO(payload), mode=maxminddb.MODE_FD
            )
        except Exception as exc:
            raise MmdbOpenError("unreadable City Lite MMDB artifact") from exc
        # Product-identity check: only the verified DB-IP City Lite edition
        # may serve evidence under this provider identity. A different valid
        # MMDB (ASN, country, GeoLite, unrelated) must fail composition.
        if self._reader.metadata().database_type != _EXPECTED_DATABASE_TYPE:
            self._reader.close()
            self._reader = None
            self._closed = True
            raise MmdbOpenError(
                "City Lite MMDB artifact has the wrong database product type"
            )
        self._closed = False

    def lookup(self, ip: str) -> Mapping[str, Any] | None:
        """Return the raw record for one canonical IP, or ``None`` on miss."""
        if self._closed or self._reader is None:
            raise MmdbLookupError("City Lite MMDB reader is closed")
        try:
            record = self._reader.get(ip)
        except Exception as exc:
            raise MmdbLookupError("City Lite MMDB lookup failed") from exc
        if record is None:
            return None
        if not isinstance(record, dict):
            raise CityLiteRecordError("City Lite MMDB record is not a JSON object")
        return record

    def close(self) -> None:
        """Release the owned reader exactly once; safe to call repeatedly."""
        if self._closed:
            return
        self._closed = True
        if self._reader is not None:
            self._reader.close()


def _require_member(record: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    """Return a required mapping member, treating absent keys as absent data."""
    if key not in record:
        return None
    value = record[key]
    if not isinstance(value, dict):
        raise CityLiteRecordError(f"City Lite record member {key} must be an object")
    return value


def _english_name(names: Mapping[str, Any], label: str) -> str | None:
    """Extract the strict bounded English name, or ``None`` when absent."""
    if "en" not in names:
        return None
    value = names["en"]
    if not isinstance(value, str):
        raise CityLiteRecordError(f"City Lite {label} English name must be a string")
    stripped = value.strip()
    if not stripped:
        raise CityLiteRecordError(f"City Lite {label} English name must not be blank")
    if len(stripped) > _MAX_NAME_LENGTH:
        raise CityLiteRecordError(f"City Lite {label} English name exceeds bound")
    return stripped


def _country_code(country: Mapping[str, Any] | None) -> str | None:
    """Extract and normalize the strict two-letter country code.

    The raw value must be exactly two ASCII letters before normalization, so
    Unicode case-expanding characters cannot masquerade as a valid code.
    """
    if country is None or "iso_code" not in country:
        return None
    value = country["iso_code"]
    if not isinstance(value, str):
        raise CityLiteRecordError("City Lite country code must be a string")
    if not _COUNTRY_CODE.fullmatch(value):
        raise CityLiteRecordError("City Lite country code must be two ASCII letters")
    return value.upper()


def _coordinate(location: Mapping[str, Any], key: str) -> float | None:
    """Extract one strict finite coordinate, or ``None`` when absent."""
    if key not in location:
        return None
    value = location[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CityLiteRecordError(f"City Lite {key} must be a real number")
    coordinate = float(value)
    if not math.isfinite(coordinate):
        raise CityLiteRecordError(f"City Lite {key} must be finite")
    return coordinate


def _coordinates(record: Mapping[str, Any]) -> tuple[float, float] | None:
    """Extract the strict coordinate pair, enforcing the all-or-none rule."""
    location = _require_member(record, "location")
    if location is None:
        return None
    latitude = _coordinate(location, "latitude")
    longitude = _coordinate(location, "longitude")
    if (latitude is None) != (longitude is None):
        raise CityLiteRecordError("City Lite coordinates must be a complete pair")
    if latitude is None or longitude is None:
        return None
    if not _LAT_MIN <= latitude <= _LAT_MAX or not _LON_MIN <= longitude <= _LON_MAX:
        raise CityLiteRecordError("City Lite coordinates are out of range")
    return (latitude, longitude)


def _region(record: Mapping[str, Any]) -> str | None:
    """Extract the deterministic first-subdivision English name."""
    if "subdivisions" not in record:
        return None
    subdivisions = record["subdivisions"]
    if not isinstance(subdivisions, list):
        raise CityLiteRecordError("City Lite subdivisions must be a list")
    if not subdivisions:
        return None
    first = subdivisions[0]
    if not isinstance(first, dict):
        raise CityLiteRecordError("City Lite subdivision entries must be objects")
    if "names" not in first:
        return None
    names = first["names"]
    if not isinstance(names, dict):
        raise CityLiteRecordError("City Lite subdivision names must be an object")
    return _english_name(names, "region")


def normalize_city_lite_record(record: object) -> GeoLocation | None:
    """Strictly validate and normalize one raw City Lite record.

    Returns the canonical :class:`GeoLocation` for the record, or ``None``
    when the record exists but carries no usable approved data at all, which
    the source contract defines as a documented lookup miss.
    """
    if not isinstance(record, dict):
        raise CityLiteRecordError("City Lite record must be a JSON object")
    country = _country_code(_require_member(record, "country"))
    city = None
    city_member = _require_member(record, "city")
    if city_member is not None:
        names = _require_member(city_member, "names")
        if names is not None:
            city = _english_name(names, "city")
    region = _region(record)
    coordinates = _coordinates(record)

    if country is not None and city is not None:
        precision = GeoPrecision.CITY
    elif country is not None and region is not None:
        precision = GeoPrecision.REGION
    elif country is not None:
        precision = GeoPrecision.COUNTRY
    else:
        precision = GeoPrecision.UNKNOWN

    if country is None and region is None and city is None and coordinates is None:
        return None
    return GeoLocation(
        country_code=country,
        region=region,
        city=city,
        latitude=None if coordinates is None else coordinates[0],
        longitude=None if coordinates is None else coordinates[1],
        provider=SourceId.DBIP_CITY_LITE.value,
        precision=precision,
    )


class DbIpCityLiteProvider(EvidenceProvider):
    """Local DB-IP City Lite geolocation provider for IP-address entities."""

    def __init__(
        self, database: CityLiteDatabase, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        """Initialize the provider over one opened local MMDB reader.

        The database reader is owned by the caller and closed at composition
        teardown. The UTC wall clock is used only for evidence
        ``retrieved_at`` timestamps; tests may inject a deterministic
        replacement.
        """
        self._database = database
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def id(self) -> str:
        """Return the stable ``urn:ati:source:dbip_city_lite`` identifier."""
        return SourceId.DBIP_CITY_LITE.value

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to IP-address entities only."""
        return entity.type == EntityType.IP_ADDRESS

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Normalize one local geolocation observation for an IP entity.

        Unsupported or uncanonicalizable entities are rejected before any
        lookup; a miss is a valid empty result, never a benign assessment.
        """
        canonical_ip, rejection = validate_investigation_entity(self, entity)
        if canonical_ip is None:
            assert rejection is not None
            return rejection
        retrieved_at = normalize_retrieval_timestamp(self._clock)

        try:
            record = self._database.lookup(canonical_ip)
        except CityLiteRecordError:
            return self._error(
                ProviderErrorCode.INVALID_RESPONSE,
                "City Lite matched record is malformed",
                False,
            )
        except MmdbLookupError:
            return self._error(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                "City Lite MMDB artifact is unreadable",
                True,
            )

        geolocation = None
        if record is not None:
            try:
                geolocation = normalize_city_lite_record(record)
            except CityLiteRecordError as exc:
                return self._error(ProviderErrorCode.INVALID_RESPONSE, str(exc), False)
        if geolocation is None:
            # A miss and a record without usable data are valid empty
            # results; neither is a benign assessment.
            return ProviderResult(provider=self.id)

        evidence = Evidence(
            investigation_id=investigation_id,
            type=EvidenceType.GEOLOCATION,
            subject=EvidenceEntityRef(
                id=entity.id, type=entity.type, value=canonical_ip
            ),
            source=self.id,
            source_url=None,
            observed_at=None,
            retrieved_at=retrieved_at,
            facts=geolocation.model_dump(mode="json"),
            raw_payload=None,
        )
        return ProviderResult(provider=self.id, evidence=(evidence,))

    def _error(
        self, code: ProviderErrorCode, message: str, retryable: bool
    ) -> ProviderResult:
        """Build one typed provider failure attributed to this provider."""
        error = ProviderError(
            provider=self.id, code=code, message=message, retryable=retryable
        )
        return ProviderResult(provider=self.id, errors=(error,))
