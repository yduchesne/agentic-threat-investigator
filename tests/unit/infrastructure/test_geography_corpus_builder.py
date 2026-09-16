# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B-2 ATI Geography Corpus builder tests (G26B2-BLD01..14).

The builder deterministically joins normalized GeoNames records with
Natural Earth geometry into the documented source-neutral ATI Geography
Corpus NDJSON consumed by ``ati-geography-import``. Fixtures under
``tests/fixtures/geoint/`` are synthetic but conform exactly to the
production source contracts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentic_threat_investigator.app.geoint.canonicalization import (
    canonical_geometry_ewkt,
)
from agentic_threat_investigator.domain.geo_reference import GeographicReferenceRecord
from agentic_threat_investigator.domain.geoint import LocationType
from agentic_threat_investigator.infrastructure.geoint.geography_corpus_builder import (
    ADMIN1_CODE_EXCEPTIONS,
    CorpusBuildError,
    GeographyCorpusBuilder,
    GeographyCorpusBuildResult,
    serialize_corpus,
)
from agentic_threat_investigator.infrastructure.geoint.geonames import (
    GeonamesAdmin1Record,
    GeonamesCityRecord,
    GeonamesCountryRecord,
    GeoNamesReferenceSource,
)
from agentic_threat_investigator.infrastructure.geoint.natural_earth import (
    NaturalEarthAdmin1Record,
    NaturalEarthCountryRecord,
    NaturalEarthReferenceSource,
)
from agentic_threat_investigator.infrastructure.sources.geography import (
    JsonlGeographyCorpus,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "geoint"
GEONAMES = FIXTURES / "geonames"
NATURAL_EARTH = FIXTURES / "natural_earth"

SPEC_COUNTRY = GeonamesCountryRecord(
    iso_code="US", name="United States", geoname_id=6252001
)
SPEC_COUNTRY_2 = GeonamesCountryRecord(iso_code="CA", name="Canada", geoname_id=6251999)
SPEC_ADMIN = GeonamesAdmin1Record(
    country_code="US", code="WA", name="Washington", geoname_id=1
)
SPEC_ADMIN_2 = GeonamesAdmin1Record(
    country_code="US", code="OR", name="Oregon", geoname_id=2
)
SPEC_CITY = GeonamesCityRecord(
    geoname_id=10,
    name="Seattle",
    country_code="US",
    admin1_code="WA",
    latitude=47.60621,
    longitude=-122.33207,
    population=737015,
)


def _ne_country(
    iso_code: str | None, name: str, geometry: str | None = None
) -> NaturalEarthCountryRecord:
    return NaturalEarthCountryRecord(
        iso_code=iso_code, name=name, geometry=geometry, source_id="ne-test"
    )


def _ne_admin(
    country_code: str | None,
    subdivision_code: str | None,
    name: str,
    geometry: str = "SRID=4326;POLYGON((-125 45,-116 45,-116 49.5,-125 49.5,-125 45))",
) -> NaturalEarthAdmin1Record:
    return NaturalEarthAdmin1Record(
        country_code=country_code,
        subdivision_code=subdivision_code,
        name=name,
        geometry=geometry,
        source_id="ne-test",
        adm1_code=None,
        postal=None,
    )


def _fixture_builder(
    *, min_population: int | None = None, country_filter: frozenset[str] = frozenset()
) -> GeographyCorpusBuildResult:
    """Build the corpus from the checked-in real-format fixtures."""
    geonames = GeoNamesReferenceSource()
    natural_earth = NaturalEarthReferenceSource()
    return GeographyCorpusBuilder().build(
        countries=geonames.parse_countries(GEONAMES / "countryInfo.txt"),
        admin1=geonames.parse_admin1(GEONAMES / "admin1CodesASCII.txt"),
        cities=geonames.parse_cities(GEONAMES / "cities1000.txt"),
        natural_earth_countries=natural_earth.parse_countries(
            NATURAL_EARTH / "ne_countries.geojson"
        ),
        natural_earth_admin1=natural_earth.parse_admin1(
            NATURAL_EARTH / "ne_admin1.geojson"
        ),
        min_population=min_population,
        country_filter=country_filter,
    )


def _types(result: GeographyCorpusBuildResult) -> list[str]:
    """Return the emitted record types in output order."""
    return [record.location_type.value for record in result.records]


def test_bld01_country_joins_by_stable_code() -> None:
    """G26B2-BLD01 countries join Natural Earth geometry by ISO code."""
    country_geometry = (
        "SRID=4326;POLYGON((-125 45,-116 45,-116 49.5,-125 49.5,-125 45))"
    )
    result = GeographyCorpusBuilder().build(
        countries=[SPEC_COUNTRY, SPEC_COUNTRY_2],
        admin1=[],
        cities=[],
        natural_earth_countries=[
            _ne_country("US", "United States", geometry=country_geometry),
            _ne_country("ZZ", "Unknown-Land", geometry=country_geometry),
        ],
    )
    by_code = {record.country_code: record for record in result.records}
    assert by_code["US"].geometry == country_geometry
    assert by_code["CA"].geometry is None
    assert "ZZ" not in by_code  # unmatched Natural Earth country: no canonical record


def test_bld02_admin_joins_deterministically_within_country() -> None:
    """G26B2-BLD02 admin geometry joins by (country, subdivision) code."""
    result = GeographyCorpusBuilder().build(
        countries=[SPEC_COUNTRY],
        admin1=[SPEC_ADMIN, SPEC_ADMIN_2],
        cities=[],
        natural_earth_admin1=[
            _ne_admin("US", "WA", "Washington"),
            _ne_admin("US", "OR", "Oregon"),
        ],
    )
    by_code = {record.admin1_code: record for record in result.records}
    assert by_code["WA"].geometry is not None
    assert by_code["OR"].geometry is not None


def test_bld03_exception_mapping_resolves_known_mismatch() -> None:
    """G26B2-BLD03 a reviewed exception resolves a known code mismatch."""
    assert ADMIN1_CODE_EXCEPTIONS[("DE", "BER")] == "BE"
    result = GeographyCorpusBuilder().build(
        countries=[GeonamesCountryRecord(iso_code="DE", name="Germany", geoname_id=1)],
        admin1=[
            GeonamesAdmin1Record(
                country_code="DE", code="BER", name="Berlin", geoname_id=2
            )
        ],
        cities=[],
        natural_earth_admin1=[
            _ne_admin("DE", "BE", "Berlin City"),  # name and code both differ
        ],
    )
    by_type = {
        (record.location_type, record.admin1_code): record for record in result.records
    }
    assert by_type[(LocationType.ADMINISTRATIVE_AREA, "BER")].geometry is not None
    assert result.report.unmatched == ()


def test_bld04_ambiguous_admin_match_reported_never_guessed() -> None:
    """G26B2-BLD04 an ambiguous name fallback is reported, never guessed."""
    result = GeographyCorpusBuilder().build(
        countries=[GeonamesCountryRecord(iso_code="TT", name="Testland", geoname_id=1)],
        admin1=[
            GeonamesAdmin1Record(
                country_code="TT", code="T1", name="Same District", geoname_id=2
            ),
            GeonamesAdmin1Record(
                country_code="TT", code="T2", name="Same District", geoname_id=3
            ),
        ],
        cities=[],
        natural_earth_admin1=[_ne_admin("TT", None, "Same District")],
    )
    assert all(record.geometry is None for record in result.records)
    assert any(
        entry.reason == "multiple_natural_earth_features"
        for entry in result.report.ambiguous
    )


def test_bld05_unmatched_natural_earth_cannot_create_canonical_record() -> None:
    """G26B2-BLD05 unmatched Natural Earth objects are reported and skipped."""
    result = _fixture_builder()
    reported = {entry.identifier for entry in result.report.unmatched}
    assert "Xenovia (XE)" in reported
    assert "Fallbackia (XY)" in reported
    assert "Nope District (ZZ:NOPE)" in reported
    codes = [record.country_code for record in result.records]
    assert "XE" not in codes and "XY" not in codes
    assert not any(record.canonical_name == "Xenovia" for record in result.records)


def test_bld06_geonames_without_polygon_emits_null_geometry() -> None:
    """G26B2-BLD06 a valid GeoNames record without geometry keeps null state."""
    result = _fixture_builder()
    edge_land = next(
        record for record in result.records if record.canonical_name == "EdgeLand"
    )
    assert edge_land.location_type is LocationType.COUNTRY
    assert edge_land.geometry is None
    texas = next(
        record
        for record in result.records
        if record.canonical_name == "Texas"
        and record.location_type is LocationType.ADMINISTRATIVE_AREA
    )
    assert texas.geometry is None  # no Natural Earth TX feature in the fixture
    assert result.report.records_without_geometry > 0


def test_bld07_parent_before_child_output() -> None:
    """G26B2-BLD07 output is ordered country, administrative_area, city."""
    result = _fixture_builder()
    assert _types(result) == [
        "country",
        "country",
        "country",
        "country",
        "administrative_area",
        "administrative_area",
        "administrative_area",
        "administrative_area",
        "administrative_area",
        "administrative_area",
        "city",
        "city",
        "city",
        "city",
    ]
    countries = [
        r.canonical_name
        for r in result.records
        if r.location_type is LocationType.COUNTRY
    ]
    assert countries == ["Canada", "Germany", "United States", "EdgeLand"]


def test_bld08_identical_inputs_produce_identical_bytes() -> None:
    """G26B2-BLD08 identical inputs produce byte-identical output."""
    first = serialize_corpus(_fixture_builder().records)
    second = serialize_corpus(_fixture_builder().records)
    assert first == second


def test_bld09_input_ordering_does_not_affect_output() -> None:
    """G26B2-BLD09 source iteration order never changes the output bytes."""
    geonames = GeoNamesReferenceSource()
    natural_earth = NaturalEarthReferenceSource()
    countries = geonames.parse_countries(GEONAMES / "countryInfo.txt")
    admin1 = geonames.parse_admin1(GEONAMES / "admin1CodesASCII.txt")
    cities = geonames.parse_cities(GEONAMES / "cities1000.txt")
    ne_countries = natural_earth.parse_countries(NATURAL_EARTH / "ne_countries.geojson")
    ne_admin1 = natural_earth.parse_admin1(NATURAL_EARTH / "ne_admin1.geojson")
    baseline = GeographyCorpusBuilder().build(
        countries=countries,
        admin1=admin1,
        cities=cities,
        natural_earth_countries=ne_countries,
        natural_earth_admin1=ne_admin1,
    )
    shuffled = GeographyCorpusBuilder().build(
        countries=list(reversed(list(countries))),
        admin1=sorted(admin1, key=lambda record: record.geoname_id or 0, reverse=True),
        cities=list(reversed(list(cities))),
        natural_earth_countries=list(reversed(list(ne_countries))),
        natural_earth_admin1=list(reversed(list(ne_admin1))),
    )
    assert serialize_corpus(shuffled.records) == serialize_corpus(baseline.records)


def test_bld10_no_timestamps_random_values_in_output() -> None:
    """G26B2-BLD10 the artifact carries no timestamps or random values."""
    artifact = serialize_corpus(_fixture_builder().records)
    assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", artifact) is None
    assert (
        re.search(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            artifact,
            re.IGNORECASE,
        )
        is None
    )
    assert "now(" not in artifact.lower()
    assert re.search(r"\b20\d{2}-\d{2}-\d{2}\b", artifact) is None
    assert artifact.startswith("# ATI Geography Corpus v1")


def test_bld11_output_conforms_to_pr26b_corpus_schema() -> None:
    """G26B2-BLD11 output round-trips through the production corpus parser."""
    result = _fixture_builder()
    artifact = serialize_corpus(result.records)
    reparsed = JsonlGeographyCorpus().read(artifact, source="built")
    assert reparsed == list(result.records)
    for record in reparsed:
        assert record.location_type in {
            LocationType.COUNTRY,
            LocationType.ADMINISTRATIVE_AREA,
            LocationType.CITY,
        }


def test_bld12_city_coordinates_never_become_polygons() -> None:
    """G26B2-BLD12 city coordinates stay canonical points, never polygons."""
    result = GeographyCorpusBuilder().build(
        countries=[SPEC_COUNTRY],
        admin1=[SPEC_ADMIN],
        cities=[SPEC_CITY],
    )
    city = next(
        record for record in result.records if record.location_type is LocationType.CITY
    )
    assert city.geometry == "SRID=4326;POINT(-122.33207 47.60621)"
    assert city.centroid == city.geometry


def test_bld13_orphan_city_rejected_and_reported() -> None:
    """G26B2-BLD13 an orphan city is rejected and reported, never created."""
    result = _fixture_builder()
    assert any(
        rejection.name == "Orphanville" and rejection.reason == "orphan_admin"
        for rejection in result.report.rejected_cities
    )
    assert all(
        not (
            record.location_type is LocationType.CITY
            and record.canonical_name == "Orphanville"
        )
        for record in result.records
    )


def test_bld14_geometry_stays_wgs84_srid_4326() -> None:
    """G26B2-BLD14 all geometry is SRID-4326 EWKT within WGS84 bounds."""
    for record in _fixture_builder().records:
        if record.geometry is None:
            continue
        assert record.geometry.startswith("SRID=4326;")
        canonical = canonical_geometry_ewkt(
            record.geometry, location_type=record.location_type
        )
        assert canonical == record.geometry


def test_min_population_filters_cities() -> None:
    """G26B2 the explicit population bound filters cities, not hierarchy."""
    result = _fixture_builder(min_population=1_000_000)
    names = [
        record.canonical_name
        for record in result.records
        if record.location_type is LocationType.CITY
    ]
    assert names == ["Berlin", "Dallas"]  # Seattle/Vancouver drop below the bound


def test_country_filter_selects_complete_hierarchy() -> None:
    """G26B2 the explicit country filter keeps whole child hierarchies."""
    result = _fixture_builder(country_filter=frozenset({"US", "ZZ"}))
    codes = {record.country_code for record in result.records}
    assert codes == {"US", "ZZ"}
    assert result.report.countries == 2
    assert result.report.administrative_areas == 4
    assert result.report.cities == 2
    # Cities/admins of filtered-out countries are skipped, not rejected.
    assert not any(
        rejection.reason == "unknown_country"
        for rejection in result.report.rejected_cities
    )


def test_invalid_options_fail_closed() -> None:
    """G26B2 invalid filters and duplicate source codes fail closed."""
    with pytest.raises(CorpusBuildError):
        _fixture_builder(min_population=-1)
    with pytest.raises(CorpusBuildError):
        _fixture_builder(country_filter=frozenset({"USA"}))
    with pytest.raises(CorpusBuildError):
        _fixture_builder(country_filter=frozenset({"XX"}))
    with pytest.raises(CorpusBuildError):
        GeographyCorpusBuilder().build(
            countries=[SPEC_COUNTRY, SPEC_COUNTRY],
            admin1=[],
            cities=[],
        )
    with pytest.raises(CorpusBuildError):
        GeographyCorpusBuilder().build(
            countries=[SPEC_COUNTRY],
            admin1=[SPEC_ADMIN, SPEC_ADMIN],
            cities=[],
        )


def test_serialized_output_is_line_delimited_json() -> None:
    """G26B2 the artifact is one compact JSON object per line."""
    artifact = serialize_corpus(_fixture_builder().records)
    data_lines = [line for line in artifact.splitlines() if not line.startswith("#")]
    assert data_lines
    for line in data_lines:
        payload = json.loads(line)
        assert isinstance(payload, dict)
        assert "location_type" in payload


def test_corpus_records_have_documented_shape() -> None:
    """G26B2 every record satisfies the PR 26B hierarchy shape rules."""
    result = _fixture_builder()
    for record in result.records:
        assert isinstance(record, GeographicReferenceRecord)
        if record.location_type is LocationType.COUNTRY:
            assert record.parent is None
            assert record.admin1_code is None
        else:
            assert record.parent is not None
            assert record.admin1_code is not None
            assert record.parent.country_code == record.country_code
