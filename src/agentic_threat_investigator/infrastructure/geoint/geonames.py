# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic GeoNames reference-source adapter (PR 26B-2).

Parses the documented supported GeoNames dump files into normalized source
records consumed by :class:`GeographyCorpusBuilder`:

- ``countryInfo.txt`` (19-column TSV, ``#`` comment lines): ISO/ISO3 codes,
  English country name, geoname id;
- ``admin1CodesASCII.txt`` (4-column TSV): ``<ISO>.<code>`` admin code,
  English first-order name, ASCII name, geoname id;
- one supported cities file such as ``cities1000.txt`` (19-column TSV
  matching the main GeoNames ``geoname`` table layout): geoname id, name,
  coordinates, country code, admin1 code, population.

The adapter extracts only the canonical-geography fields ATI needs; it never
writes PostgreSQL and never downloads anything. Malformed or unsupported
record shapes fail closed with :class:`GeonamesSourceError`; coordinates are
validated to be finite WGS84 values at parse time.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

_COUNTRY_FIELDS = 19
_ADMIN1_FIELDS = 4
_CITY_FIELDS = 19

# countryInfo.txt column indexes (documented GeoNames schema).
_COUNTRY_ISO = 0
_COUNTRY_NAME = 4
_COUNTRY_GEONAME_ID = 16

# admin1CodesASCII.txt column indexes.
_ADMIN1_CODE = 0
_ADMIN1_NAME = 1
_ADMIN1_GEONAME_ID = 3

# cities1000.txt column indexes (the supported-file subset of the GeoNames
# main ``geoname`` table layout).
_CITY_GEONAME_ID = 0
_CITY_NAME = 1
_CITY_LATITUDE = 4
_CITY_LONGITUDE = 5
_CITY_COUNTRY = 8
_CITY_ADMIN1 = 10
_CITY_POPULATION = 14


class GeonamesSourceError(ValueError):
    """Raised when a GeoNames file violates the documented supported format.

    The message identifies the artifact and line; it never embeds full
    record payloads.
    """


def _required_cell(
    cells: list[str], column: int, *, path: str, line_number: int, label: str
) -> str:
    """Return one nonblank tab-separated cell or fail closed."""
    value = cells[column].strip()
    if not value:
        raise GeonamesSourceError(f"{path}:{line_number}: {label} must not be blank")
    return value


def _optional_int(value: str, *, path: str, line_number: int, label: str) -> int | None:
    """Parse an optional integer cell, rejecting junk deterministically."""
    stripped = value.strip()
    if not stripped:
        return None
    return _parse_int(stripped, path=path, line_number=line_number, label=label)


def _parse_int(value: str, *, path: str, line_number: int, label: str) -> int:
    """Parse a required integer cell or fail closed."""
    try:
        return int(value)
    except ValueError as error:
        raise GeonamesSourceError(
            f"{path}:{line_number}: {label} must be an integer"
        ) from error


def _parse_float(value: str, *, path: str, line_number: int, label: str) -> float:
    """Parse a required finite WGS84 decimal coordinate or fail closed."""
    try:
        parsed = float(value)
    except ValueError as error:
        raise GeonamesSourceError(
            f"{path}:{line_number}: {label} must be a decimal number"
        ) from error
    if not math.isfinite(parsed):
        raise GeonamesSourceError(f"{path}:{line_number}: {label} must be finite")
    if label == "latitude" and not -90.0 <= parsed <= 90.0:
        raise GeonamesSourceError(
            f"{path}:{line_number}: latitude is outside WGS84 bounds"
        )
    if label == "longitude" and not -180.0 <= parsed <= 180.0:
        raise GeonamesSourceError(
            f"{path}:{line_number}: longitude is outside WGS84 bounds"
        )
    return parsed


def _split_row(
    raw_line: str, *, path: str, line_number: int, expected: int
) -> list[str]:
    """Split one named-format row and enforce the exact column count."""
    cells = raw_line.rstrip("\n").split("\t")
    if len(cells) != expected:
        raise GeonamesSourceError(
            f"{path}:{line_number}: expected {expected} tab-separated fields "
            f"(got {len(cells)})"
        )
    return cells


def _meaningful_lines(content: str) -> list[tuple[int, str]]:
    """Return (line_number, line) pairs skipping comments and blank lines."""
    return [
        (number, line)
        for number, line in enumerate(content.splitlines(), start=1)
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _read(path: Path) -> str:
    """Read one local artifact file, translating I/O errors fail-closed."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise GeonamesSourceError(
            f"cannot read GeoNames artifact {path}: {error}"
        ) from error


@dataclass(frozen=True)
class GeonamesCountryRecord:
    """One normalized GeoNames country row (supported countryInfo.txt)."""

    iso_code: str
    name: str
    geoname_id: int | None


@dataclass(frozen=True)
class GeonamesAdmin1Record:
    """One normalized GeoNames first-order administrative record."""

    country_code: str
    code: str
    name: str
    geoname_id: int | None


@dataclass(frozen=True)
class GeonamesCityRecord:
    """One normalized GeoNames city row (supported cities file)."""

    geoname_id: int
    name: str
    country_code: str
    admin1_code: str | None
    latitude: float
    longitude: float
    population: int


class GeoNamesReferenceSource:
    """Parse the documented supported GeoNames dump files deterministically.

    The adapter produces normalized source records only; joining,
    geometry attachment, hierarchy construction, and corpus emission belong
    to :class:`GeographyCorpusBuilder`.
    """

    def parse_countries(self, path: Path) -> list[GeonamesCountryRecord]:
        """Parse countryInfo.txt into normalized country records."""
        lines = _meaningful_lines(_read(path))
        records: list[GeonamesCountryRecord] = []
        for line_number, raw_line in lines:
            cells = _split_row(
                raw_line,
                path=str(path),
                line_number=line_number,
                expected=_COUNTRY_FIELDS,
            )
            iso_code = _required_cell(
                cells,
                _COUNTRY_ISO,
                path=str(path),
                line_number=line_number,
                label="ISO code",
            ).upper()
            if len(iso_code) != 2 or not iso_code.isalpha():
                raise GeonamesSourceError(
                    f"{path}:{line_number}: ISO code must be two letters"
                )
            name = _required_cell(
                cells,
                _COUNTRY_NAME,
                path=str(path),
                line_number=line_number,
                label="country name",
            )
            geoname_id = _optional_int(
                cells[_COUNTRY_GEONAME_ID],
                path=str(path),
                line_number=line_number,
                label="geoname id",
            )
            records.append(
                GeonamesCountryRecord(
                    iso_code=iso_code, name=name, geoname_id=geoname_id
                )
            )
        return records

    def parse_admin1(self, path: Path) -> list[GeonamesAdmin1Record]:
        """Parse admin1CodesASCII.txt into normalized admin1 records."""
        lines = _meaningful_lines(_read(path))
        records: list[GeonamesAdmin1Record] = []
        for line_number, raw_line in lines:
            cells = _split_row(
                raw_line,
                path=str(path),
                line_number=line_number,
                expected=_ADMIN1_FIELDS,
            )
            code = _required_cell(
                cells,
                _ADMIN1_CODE,
                path=str(path),
                line_number=line_number,
                label="admin1 code",
            )
            parts = code.split(".")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                raise GeonamesSourceError(
                    f"{path}:{line_number}: admin1 code must have the form CC.SUB"
                )
            country_code = parts[0].upper()
            if len(country_code) != 2 or not country_code.isalpha():
                raise GeonamesSourceError(
                    f"{path}:{line_number}: admin1 country code must be two letters"
                )
            name = _required_cell(
                cells,
                _ADMIN1_NAME,
                path=str(path),
                line_number=line_number,
                label="admin1 name",
            )
            geoname_id = _optional_int(
                cells[_ADMIN1_GEONAME_ID],
                path=str(path),
                line_number=line_number,
                label="geoname id",
            )
            records.append(
                GeonamesAdmin1Record(
                    country_code=country_code,
                    code=parts[1],
                    name=name,
                    geoname_id=geoname_id,
                )
            )
        return records

    def parse_cities(self, path: Path) -> list[GeonamesCityRecord]:
        """Parse a supported GeoNames cities file (e.g. cities1000.txt).

        Only the documented 19-column ``geoname``-style row layout is
        accepted; any other record shape fails closed and can never silently
        become a canonical Location.
        """
        lines = _meaningful_lines(_read(path))
        records: list[GeonamesCityRecord] = []
        for line_number, raw_line in lines:
            cells = _split_row(
                raw_line, path=str(path), line_number=line_number, expected=_CITY_FIELDS
            )
            geoname_id = _parse_int(
                cells[_CITY_GEONAME_ID],
                path=str(path),
                line_number=line_number,
                label="geoname id",
            )
            name = _required_cell(
                cells,
                _CITY_NAME,
                path=str(path),
                line_number=line_number,
                label="city name",
            )
            latitude = _parse_float(
                cells[_CITY_LATITUDE],
                path=str(path),
                line_number=line_number,
                label="latitude",
            )
            longitude = _parse_float(
                cells[_CITY_LONGITUDE],
                path=str(path),
                line_number=line_number,
                label="longitude",
            )
            country_code = _required_cell(
                cells,
                _CITY_COUNTRY,
                path=str(path),
                line_number=line_number,
                label="country code",
            ).upper()
            if len(country_code) != 2 or not country_code.isalpha():
                raise GeonamesSourceError(
                    f"{path}:{line_number}: country code must be two letters"
                )
            admin1_code = cells[_CITY_ADMIN1].strip() or None
            population = _parse_int(
                cells[_CITY_POPULATION],
                path=str(path),
                line_number=line_number,
                label="population",
            )
            records.append(
                GeonamesCityRecord(
                    geoname_id=geoname_id,
                    name=name,
                    country_code=country_code,
                    admin1_code=admin1_code,
                    latitude=latitude,
                    longitude=longitude,
                    population=population,
                )
            )
        return records
