# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic ATI Geography Corpus builder (PR 26B-2).

Joins normalized GeoNames records (naming/hierarchy/coordinates) with
normalized Natural Earth records (boundary geometry) into the documented
source-neutral ATI Geography Corpus consumed by ``ati-geography-import``.
The corpus remains the stable interchange boundary: this module only writes
corpus records, it never writes PostgreSQL.

Determinism contract:

- identical source inputs and options produce identical output bytes (no
  timestamps, random values, or absolute paths in the artifact);
- records are emitted parent-before-child in the fixed class order
  country, administrative_area, city, each class sorted by stable canonical
  keys, never by source iteration or filesystem order;
- joins use deterministic identifiers (ISO country codes; country + admin
  subdivision codes), with the bounded fallback of exact normalized-name
  equality within one country and the version-controlled
  :data:`ADMIN1_CODE_EXCEPTIONS` mapping for reviewed mismatches; global
  fuzzy matching is never used;
- unmatched Natural Earth objects are reported and skipped, never converted
  into guessed canonical identities; a valid GeoNames record without
  Natural Earth geometry keeps null geometry where the corpus permits it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from agentic_threat_investigator.app.geoint.canonicalization import (
    canonical_geometry_ewkt,
)
from agentic_threat_investigator.domain.geo_reference import (
    GeographicReferenceRecord,
    ReferenceParent,
)
from agentic_threat_investigator.domain.geoint import (
    LocationType,
    normalize_reference_name,
)
from agentic_threat_investigator.infrastructure.geoint.geonames import (
    GeonamesAdmin1Record,
    GeonamesCityRecord,
    GeonamesCountryRecord,
)
from agentic_threat_investigator.infrastructure.geoint.natural_earth import (
    NaturalEarthAdmin1Record,
    NaturalEarthCountryRecord,
    format_coordinate,
)

# Reviewed exception mappings for administrative joins (PR 26B-2, section
# 7.3). Key: (GeoNames country code, GeoNames admin1 code); value: the
# Natural Earth subdivision code (``iso_3166_2`` tail) that carries the
# matching boundary. Entries are added only after explicit review against
# the pinned upstream dataset versions; the v0.1 table carries the
# fixture-verified example exercised by the checked-in fixtures, so the
# mechanism is documented, version-controlled, and tested (G26B2-BLD03).
# Unknown mismatches are never guessed: they surface as reported unmatched
# objects.
ADMIN1_CODE_EXCEPTIONS: dict[tuple[str, str], str] = {
    ("DE", "BER"): "BE",  # GeoNames DE.BER (Berlin) <-> Natural Earth DE-BE
}


class CorpusBuildError(ValueError):
    """Raised when a corpus cannot be built from the supplied source records.

    Fail-closed conditions include duplicate source identifiers, invalid
    build options, and malformed geometry that would otherwise create an
    invalid canonical record.
    """


def _normalized(value: str, *, label: str) -> str:
    """Apply the deterministic reference-name normalization contract."""
    normalized = normalize_reference_name(value)
    if not normalized:
        raise CorpusBuildError(f"{label} must not be blank")
    return normalized


def _point_ewkt(latitude: float, longitude: float) -> str:
    """Return the canonical city-point EWKT for one GeoNames coordinate pair."""
    return (
        f"SRID=4326;POINT({format_coordinate(longitude)} {format_coordinate(latitude)})"
    )


@dataclass(frozen=True)
class UnmatchedSourceReport:
    """One Natural Earth object that could not be deterministically joined.

    The identifier carries enough upstream attribute information (names and
    codes) for an operator to diagnose the source file; ``reason`` is one of
    ``no_usable_iso_code``, ``no_boundary_data``,
    ``no_matching_geonames_country``, or ``no_matching_geonames_admin``.
    """

    source: str
    kind: str
    identifier: str
    reason: str


@dataclass(frozen=True)
class RejectedCityReport:
    """One GeoNames city that was rejected rather than created.

    ``reason`` is one of ``unknown_country``, ``missing_admin1``,
    ``orphan_admin``, or ``duplicate_canonical_identity``.
    """

    name: str
    country_code: str
    admin1_code: str | None
    reason: str


@dataclass(frozen=True)
class AmbiguousMatchReport:
    """One join deliberately left unresolved rather than guessed.

    ``reason`` is ``multiple_natural_earth_features_for_code`` or
    ``multiple_natural_earth_features``.
    """

    kind: str
    identifier: str
    reason: str


@dataclass(frozen=True)
class GeographyCorpusBuildReport:
    """Bounded outcome summary for one deterministic corpus build."""

    countries: int
    administrative_areas: int
    cities: int
    polygon_geometries: int
    records_without_geometry: int
    unmatched: tuple[UnmatchedSourceReport, ...]
    rejected_cities: tuple[RejectedCityReport, ...]
    ambiguous: tuple[AmbiguousMatchReport, ...]


@dataclass(frozen=True)
class GeographyCorpusBuildResult:
    """One deterministic corpus build: ordered records plus the summary."""

    records: tuple[GeographicReferenceRecord, ...]
    report: GeographyCorpusBuildReport


class GeographyCorpusBuilder:
    """Deterministically derive the ATI Geography Corpus from source records.

    The builder is the deterministic derivation path between the upstream
    source adapters and the existing ``ati-geography-import`` corpus
    consumer. It never writes PostgreSQL and never downloads source files.
    """

    def __init__(
        self, admin1_exceptions: Mapping[tuple[str, str], str] | None = None
    ) -> None:
        """Bind the reviewed admin-code exception mapping.

        When ``admin1_exceptions`` is ``None`` the version-controlled
        :data:`ADMIN1_CODE_EXCEPTIONS` table applies.
        """
        self._exceptions = (
            dict(ADMIN1_CODE_EXCEPTIONS)
            if admin1_exceptions is None
            else dict(admin1_exceptions)
        )

    def build(
        self,
        *,
        countries: Sequence[GeonamesCountryRecord],
        admin1: Sequence[GeonamesAdmin1Record],
        cities: Sequence[GeonamesCityRecord],
        natural_earth_countries: Sequence[NaturalEarthCountryRecord] = (),
        natural_earth_admin1: Sequence[NaturalEarthAdmin1Record] = (),
        min_population: int | None = None,
        country_filter: frozenset[str] = frozenset(),
    ) -> GeographyCorpusBuildResult:
        """Build the deterministic corpus from normalized source records.

        ``country_filter`` selects a subset of countries and their complete
        child hierarchy; ``min_population`` drops cities below the bound.
        Raises :class:`CorpusBuildError` fail-closed for invalid options or
        malformed geometry.
        """
        if min_population is not None and min_population < 0:
            raise CorpusBuildError("min_population must not be negative")
        for code in country_filter:
            if len(code) != 2 or not code.isalpha():
                raise CorpusBuildError(
                    f"country filter code {code!r} must be two letters"
                )
        selected = self._countries_by_code(countries)
        known_countries = set(selected)
        selected_countries = {
            code for code in selected if not country_filter or code in country_filter
        }
        if country_filter and not selected_countries:
            raise CorpusBuildError(
                "country filter selected no GeoNames countries "
                f"(available: {', '.join(sorted(selected))})"
            )

        unmatched: list[UnmatchedSourceReport] = []
        rejected_cities: list[RejectedCityReport] = []
        ambiguous: list[AmbiguousMatchReport] = []

        country_geometry, country_conflicts = self._join_country_geometry(
            natural_earth_countries,
            known_countries=known_countries,
            unmatched=unmatched,
            ambiguous=ambiguous,
        )
        admins_by_code = self._admins_by_code(admin1)
        admin_geometry = self._join_admin_geometry(
            natural_earth_admin1,
            admins_by_code,
            known_countries=known_countries,
            selected_countries=selected_countries,
            unmatched=unmatched,
            ambiguous=ambiguous,
        )

        records: list[GeographicReferenceRecord] = self._country_records(
            selected, selected_countries, country_geometry, country_conflicts
        )
        admin_records, admin_by_key = self._admin_records(
            selected, selected_countries, admins_by_code, admin_geometry
        )
        city_records = self._city_records(
            cities,
            known=known_countries,
            selected=selected_countries,
            admins=admin_by_key,
            min_population=min_population,
            rejected=rejected_cities,
        )
        records.extend(admin_records)
        records.extend(city_records)
        return GeographyCorpusBuildResult(
            records=tuple(records),
            report=self._report(records, unmatched, rejected_cities, ambiguous),
        )

    def _report(
        self,
        records: Sequence[GeographicReferenceRecord],
        unmatched: Sequence[UnmatchedSourceReport],
        rejected_cities: Sequence[RejectedCityReport],
        ambiguous: Sequence[AmbiguousMatchReport],
    ) -> GeographyCorpusBuildReport:
        """Compile the bounded build summary from emitted records."""
        countries = administrative_areas = cities = polygon = without = 0
        for record in records:
            if record.location_type is LocationType.COUNTRY:
                countries += 1
            elif record.location_type is LocationType.ADMINISTRATIVE_AREA:
                administrative_areas += 1
            else:
                cities += 1
            if record.geometry is None:
                without += 1
            elif record.location_type is not LocationType.CITY:
                polygon += 1
        return GeographyCorpusBuildReport(
            countries=countries,
            administrative_areas=administrative_areas,
            cities=cities,
            polygon_geometries=polygon,
            records_without_geometry=without,
            unmatched=tuple(unmatched),
            rejected_cities=tuple(rejected_cities),
            ambiguous=tuple(ambiguous),
        )

    @staticmethod
    def _countries_by_code(
        countries: Sequence[GeonamesCountryRecord],
    ) -> dict[str, GeonamesCountryRecord]:
        """Index GeoNames countries by ISO code, rejecting duplicates."""
        indexed: dict[str, GeonamesCountryRecord] = {}
        for country in countries:
            if country.iso_code in indexed:
                raise CorpusBuildError(
                    f"duplicate GeoNames country code {country.iso_code}"
                )
            indexed[country.iso_code] = country
        if not indexed:
            raise CorpusBuildError("GeoNames country input is empty")
        return indexed

    @staticmethod
    def _admins_by_code(
        admin1: Sequence[GeonamesAdmin1Record],
    ) -> dict[tuple[str, str], GeonamesAdmin1Record]:
        """Index GeoNames admin1 records by (country, code)."""
        indexed: dict[tuple[str, str], GeonamesAdmin1Record] = {}
        for admin in admin1:
            key = (admin.country_code, admin.code)
            if key in indexed:
                raise CorpusBuildError(
                    f"duplicate GeoNames admin1 code {admin.country_code}.{admin.code}"
                )
            indexed[key] = admin
        return indexed

    def _join_country_geometry(
        self,
        natural_earth_countries: Sequence[NaturalEarthCountryRecord],
        *,
        known_countries: set[str],
        unmatched: list[UnmatchedSourceReport],
        ambiguous: list[AmbiguousMatchReport],
    ) -> tuple[dict[str, str], set[str]]:
        """Attach Natural Earth country geometry by deterministic ISO code."""
        geometry: dict[str, str] = {}
        conflicts: set[str] = set()
        for record in natural_earth_countries:
            identifier = _country_identifier(record)
            if record.iso_code is None:
                unmatched.append(
                    UnmatchedSourceReport(
                        source="natural_earth",
                        kind="country",
                        identifier=identifier,
                        reason="no_usable_iso_code",
                    )
                )
            elif record.iso_code not in known_countries:
                unmatched.append(
                    UnmatchedSourceReport(
                        source="natural_earth",
                        kind="country",
                        identifier=identifier,
                        reason="no_matching_geonames_country",
                    )
                )
            elif record.geometry is None:
                unmatched.append(
                    UnmatchedSourceReport(
                        source="natural_earth",
                        kind="country",
                        identifier=identifier,
                        reason="no_boundary_data",
                    )
                )
            elif record.iso_code in geometry or record.iso_code in conflicts:
                conflicts.add(record.iso_code)
                ambiguous.append(
                    AmbiguousMatchReport(
                        kind="country",
                        identifier=identifier,
                        reason="multiple_natural_earth_features_for_code",
                    )
                )
            else:
                geometry[record.iso_code] = record.geometry
        return geometry, conflicts

    def _join_admin_geometry(
        self,
        natural_earth_admin1: Sequence[NaturalEarthAdmin1Record],
        admins_by_code: Mapping[tuple[str, str], GeonamesAdmin1Record],
        *,
        known_countries: set[str],
        selected_countries: set[str],
        unmatched: list[UnmatchedSourceReport],
        ambiguous: list[AmbiguousMatchReport],
    ) -> dict[tuple[str, str], str]:
        """Attach Natural Earth admin1 geometry with deterministic joins.

        Two deterministic passes, never fuzzy:

        1. GeoNames-first: for every GeoNames admin of a selected country,
           resolve the Natural Earth subdivision via the reviewed exception
           mapping or the direct subdivision-code match and attach the
           boundary when exactly one feature carries it.
        2. Natural Earth-side fallback: remaining features try exact
           normalized-name equality within their country; a feature with no
           deterministic match (or more than one) is reported, never
           guessed. Features whose country is known but not selected by the
           explicit operator country filter are intentionally skipped.
        """
        indexed: dict[tuple[str, str], str] = {}
        indexed_conflicts: set[tuple[str, str]] = set()
        for record in natural_earth_admin1:
            identifier = _admin_identifier(record)
            if record.country_code is None:
                unmatched.append(
                    UnmatchedSourceReport(
                        source="natural_earth",
                        kind="administrative_area",
                        identifier=identifier,
                        reason="no_usable_iso_code",
                    )
                )
                continue
            if record.country_code not in known_countries:
                unmatched.append(
                    UnmatchedSourceReport(
                        source="natural_earth",
                        kind="administrative_area",
                        identifier=identifier,
                        reason="no_matching_geonames_country",
                    )
                )
                continue
            if record.country_code not in selected_countries:
                continue
            if record.geometry is None:
                unmatched.append(
                    UnmatchedSourceReport(
                        source="natural_earth",
                        kind="administrative_area",
                        identifier=identifier,
                        reason="no_boundary_data",
                    )
                )
                continue
            if record.subdivision_code is None:
                continue
            key = (record.country_code, record.subdivision_code)
            if key in indexed or key in indexed_conflicts:
                indexed_conflicts.add(key)
                ambiguous.append(
                    AmbiguousMatchReport(
                        kind="administrative_area",
                        identifier=identifier,
                        reason="multiple_natural_earth_features",
                    )
                )
                continue
            indexed[key] = record.geometry

        geometry: dict[tuple[str, str], str] = {}
        consumed: set[tuple[str, str]] = set()
        for geonames_key, admin in admins_by_code.items():
            if admin.country_code not in selected_countries:
                continue
            ne_subdivision = self._exceptions.get(
                (admin.country_code, admin.code), admin.code
            )
            ne_key = (admin.country_code, ne_subdivision)
            if ne_key in indexed_conflicts:
                continue
            if ne_key not in indexed:
                continue
            if ne_key in consumed:
                ambiguous.append(
                    AmbiguousMatchReport(
                        kind="administrative_area",
                        identifier=_admin_identifier_geonames(admin),
                        reason="multiple_natural_earth_features",
                    )
                )
                continue
            geometry[geonames_key] = indexed[ne_key]
            consumed.add(ne_key)

        for record in natural_earth_admin1:
            if record.country_code is None:
                continue
            if record.country_code not in known_countries:
                continue
            if record.country_code not in selected_countries:
                continue
            if record.geometry is None:
                continue
            fallback_ne_key = (
                None
                if record.subdivision_code is None
                else (record.country_code, record.subdivision_code)
            )
            if fallback_ne_key is not None and (
                fallback_ne_key in indexed_conflicts or fallback_ne_key in consumed
            ):
                continue
            matched_key = self._name_match(record, admins_by_code, ambiguous=ambiguous)
            if matched_key is None:
                unmatched.append(
                    UnmatchedSourceReport(
                        source="natural_earth",
                        kind="administrative_area",
                        identifier=_admin_identifier(record),
                        reason="no_matching_geonames_admin",
                    )
                )
                continue
            if matched_key in geometry:
                ambiguous.append(
                    AmbiguousMatchReport(
                        kind="administrative_area",
                        identifier=_admin_identifier(record),
                        reason="multiple_natural_earth_features",
                    )
                )
                continue
            geometry[matched_key] = record.geometry
        return geometry

    @staticmethod
    def _name_match(
        record: NaturalEarthAdmin1Record,
        admins_by_code: Mapping[tuple[str, str], GeonamesAdmin1Record],
        *,
        ambiguous: list[AmbiguousMatchReport],
    ) -> tuple[str, str] | None:
        """Return the exactly-one GeoNames admin whose normalized name matches.

        Returns ``None`` when the feature carries no name, matches no
        GeoNames admin, or matches more than one (which is reported as
        ambiguous, never guessed).
        """
        assert record.country_code is not None
        if record.name is None:
            return None
        name = _normalized(record.name, label="Natural Earth admin name")
        matches = [
            key
            for key, admin in admins_by_code.items()
            if admin.country_code == record.country_code
            and _normalized(admin.name, label="GeoNames admin name") == name
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            ambiguous.append(
                AmbiguousMatchReport(
                    kind="administrative_area",
                    identifier=_admin_identifier(record),
                    reason="multiple_natural_earth_features",
                )
            )
        return None

    def _country_records(
        self,
        selected: Mapping[str, GeonamesCountryRecord],
        selected_countries: set[str],
        country_geometry: Mapping[str, str],
        country_conflicts: set[str],
    ) -> list[GeographicReferenceRecord]:
        """Build sorted country records with attached geometry when resolved."""
        records: list[GeographicReferenceRecord] = []
        for iso_code in sorted(selected_countries):
            country = selected[iso_code]
            canonical_name = _normalized(country.name, label="country name")
            geometry = (
                None
                if iso_code in country_conflicts
                else country_geometry.get(iso_code)
            )
            records.append(
                GeographicReferenceRecord(
                    location_type=LocationType.COUNTRY,
                    name=canonical_name,
                    canonical_name=canonical_name,
                    country_code=iso_code,
                    geometry=self._validated_geometry(
                        geometry, location_type=LocationType.COUNTRY
                    ),
                )
            )
        return records

    def _admin_records(
        self,
        selected: Mapping[str, GeonamesCountryRecord],
        selected_countries: set[str],
        admins_by_code: Mapping[tuple[str, str], GeonamesAdmin1Record],
        admin_geometry: Mapping[tuple[str, str], str],
    ) -> tuple[
        list[GeographicReferenceRecord], dict[tuple[str, str], GeonamesAdmin1Record]
    ]:
        """Build sorted admin records and the index used by city records."""
        records: list[GeographicReferenceRecord] = []
        by_key: dict[tuple[str, str], GeonamesAdmin1Record] = {}
        for key in sorted(admins_by_code):
            admin = admins_by_code[key]
            if admin.country_code not in selected_countries:
                continue
            country = selected[admin.country_code]
            canonical_name = _normalized(admin.name, label="admin1 name")
            records.append(
                GeographicReferenceRecord(
                    location_type=LocationType.ADMINISTRATIVE_AREA,
                    name=canonical_name,
                    canonical_name=canonical_name,
                    country_code=admin.country_code,
                    admin1_code=admin.code,
                    parent=ReferenceParent(
                        location_type=LocationType.COUNTRY,
                        country_code=admin.country_code,
                        canonical_name=_normalized(country.name, label="country name"),
                    ),
                    geometry=self._validated_geometry(
                        admin_geometry.get(key),
                        location_type=LocationType.ADMINISTRATIVE_AREA,
                    ),
                )
            )
            by_key[key] = admin
        return records, by_key

    def _city_records(
        self,
        cities: Sequence[GeonamesCityRecord],
        *,
        known: set[str],
        selected: set[str],
        admins: Mapping[tuple[str, str], GeonamesAdmin1Record],
        min_population: int | None,
        rejected: list[RejectedCityReport],
    ) -> list[GeographicReferenceRecord]:
        """Build sorted city records, rejecting orphans and duplicates.

        Cities of countries that are known but not selected by the explicit
        operator country filter are intentionally skipped; cities of entirely
        unknown countries are rejected.
        """
        if min_population is not None:
            cities = [city for city in cities if city.population >= min_population]
        sorted_cities = sorted(cities, key=_city_sort_key)
        records: list[GeographicReferenceRecord] = []
        seen: set[tuple[str, str, str]] = set()
        for city in sorted_cities:
            if city.country_code not in known:
                rejected.append(
                    RejectedCityReport(
                        name=city.name,
                        country_code=city.country_code,
                        admin1_code=city.admin1_code,
                        reason="unknown_country",
                    )
                )
                continue
            if city.country_code not in selected:
                continue
            if city.admin1_code is None or not city.admin1_code:
                rejected.append(
                    RejectedCityReport(
                        name=city.name,
                        country_code=city.country_code,
                        admin1_code=city.admin1_code,
                        reason="missing_admin1",
                    )
                )
                continue
            admin = admins.get((city.country_code, city.admin1_code))
            if admin is None:
                rejected.append(
                    RejectedCityReport(
                        name=city.name,
                        country_code=city.country_code,
                        admin1_code=city.admin1_code,
                        reason="orphan_admin",
                    )
                )
                continue
            canonical_name = _normalized(city.name, label="city name")
            identity_key = (city.country_code, city.admin1_code, canonical_name)
            if identity_key in seen:
                rejected.append(
                    RejectedCityReport(
                        name=city.name,
                        country_code=city.country_code,
                        admin1_code=city.admin1_code,
                        reason="duplicate_canonical_identity",
                    )
                )
                continue
            seen.add(identity_key)
            point = _point_ewkt(city.latitude, city.longitude)
            records.append(
                GeographicReferenceRecord(
                    location_type=LocationType.CITY,
                    name=canonical_name,
                    canonical_name=canonical_name,
                    country_code=city.country_code,
                    admin1_code=city.admin1_code,
                    parent=ReferenceParent(
                        location_type=LocationType.ADMINISTRATIVE_AREA,
                        country_code=city.country_code,
                        admin1_code=city.admin1_code,
                        canonical_name=_normalized(admin.name, label="admin1 name"),
                    ),
                    geometry=self._validated_geometry(
                        point, location_type=LocationType.CITY
                    ),
                    centroid=point,
                )
            )
        return records

    @staticmethod
    def _validated_geometry(
        geometry: str | None, *, location_type: LocationType
    ) -> str | None:
        """Validate one geometry against the canonical import contract.

        Uses the same canonical EWKT validation the ingestion service
        applies, so a built corpus is importable by construction; malformed
        geometry fails the build instead of being silently accepted.
        """
        if geometry is None:
            return None
        return canonical_geometry_ewkt(geometry, location_type=location_type)


def _city_sort_key(city: GeonamesCityRecord) -> tuple[str, str, str, str]:
    """Return the deterministic city ordering key (geoname id tie-breaker)."""
    return (
        city.country_code,
        city.admin1_code or "",
        _normalized(city.name, label="city name"),
        str(city.geoname_id),
    )


def _country_identifier(record: NaturalEarthCountryRecord) -> str:
    """Return a diagnostic identifier for one Natural Earth country feature."""
    return f"{record.name or '<unnamed>'} ({record.iso_code or 'no code'})"


def _admin_identifier(record: NaturalEarthAdmin1Record) -> str:
    """Return a diagnostic identifier for one Natural Earth admin feature."""
    code = record.subdivision_code or record.adm1_code or "no subdivision code"
    return (
        f"{record.name or '<unnamed>'} ({record.country_code or 'no country'}:{code})"
    )


def _admin_identifier_geonames(admin: GeonamesAdmin1Record) -> str:
    """Return a diagnostic identifier for one GeoNames admin1 record."""
    return f"{admin.name} ({admin.country_code}.{admin.code})"


def _corpus_line(record: GeographicReferenceRecord) -> str:
    """Serialize one corpus record deterministically in the documented schema."""
    return record.model_dump_json(exclude_none=True)


def serialize_corpus(records: Sequence[GeographicReferenceRecord]) -> str:
    """Serialize corpus records into the deterministic NDJSON artifact.

    The output carries the static format header and one compact JSON object
    per line with the documented record field order; ``None`` fields are
    omitted exactly like the checked-in PR 26B fixtures. No timestamps,
    random values, or absolute source paths are ever emitted.
    """
    header = (
        "# ATI Geography Corpus v1 -- deterministic build (PR 26B-2).\n"
        "# Geometry is operator-derived from documented upstream sources; see docs/DATA_SOURCES.md."
    )
    lines = [header]
    lines.extend(_corpus_line(record) for record in records)
    return "\n".join(lines) + "\n"
