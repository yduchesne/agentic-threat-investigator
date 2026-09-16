# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B-2 GeoNames reference-source adapter tests (G26B2-SRC01..07).

The supported inputs are the documented GeoNames dump files in their exact
upstream layouts: countryInfo.txt (19 columns), admin1CodesASCII.txt (4
columns), and a supported cities file such as cities1000.txt (19 columns
matching the main geonames table). The checked-in fixtures
(``tests/fixtures/geoint/geonames/``) are synthetic but conform exactly to
the production input contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentic_threat_investigator.infrastructure.geoint.geonames import (
    GeoNamesReferenceSource,
    GeonamesSourceError,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "geoint" / "geonames"
SOURCE = GeoNamesReferenceSource()

CITY_ROW = (
    "5809844\tSeattle\tSeattle\tSeattle\t47.60621\t-122.33207\tP\tPPLA\tUS\t\tWA"
    "\t\t\t\t737015\t56\t56\tAmerica/Los_Angeles\t2011-06-22"
)


def _artifact(tmp_path: Path, filename: str, *rows: str) -> Path:
    """Write inline rows into one supported-format artifact under tmp_path."""
    path = tmp_path / filename
    path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return path


def test_src01_supported_country_parses() -> None:
    """G26B2-SRC01 the fixture countryInfo.txt parses deterministically."""
    records = SOURCE.parse_countries(FIXTURES / "countryInfo.txt")
    by_code = {record.iso_code: record for record in records}
    assert set(by_code) == {"US", "CA", "DE", "ZZ"}
    assert by_code["US"].name == "United States"
    assert by_code["US"].geoname_id == 6252001
    # Adapters preserve deterministic artifact order; sorting is the
    # builder's responsibility (G26B2-BLD07/BLD09).
    assert [record.iso_code for record in records] == ["US", "CA", "DE", "ZZ"]


def test_src02_supported_admin1_parses() -> None:
    """G26B2-SRC02 the fixture admin1CodesASCII.txt parses deterministically."""
    records = SOURCE.parse_admin1(FIXTURES / "admin1CodesASCII.txt")
    by_key = {(record.country_code, record.code): record for record in records}
    assert by_key[("US", "WA")].name == "Washington"
    assert by_key[("US", "WA")].geoname_id == 1128279
    assert by_key[("DE", "BER")].name == "Berlin"
    assert [(record.country_code, record.code) for record in records] == [
        ("US", "WA"),
        ("US", "TX"),
        ("CA", "BC"),
        ("DE", "BER"),
        ("ZZ", "ALPHA"),
        ("ZZ", "BETA"),
    ]


def test_src03_supported_city_parses() -> None:
    """G26B2-SRC03 the fixture cities1000.txt parses deterministically."""
    records = SOURCE.parse_cities(FIXTURES / "cities1000.txt")
    seattle = next(record for record in records if record.geoname_id == 5809844)
    assert seattle.name == "Seattle"
    assert seattle.country_code == "US"
    assert seattle.admin1_code == "WA"
    assert seattle.latitude == pytest.approx(47.60621)
    assert seattle.longitude == pytest.approx(-122.33207)
    assert seattle.population == 737015


@pytest.mark.parametrize(
    ("latitude", "longitude"),
    [
        ("abc", "-122.33207"),
        ("47.60621", "xyz"),
        ("91.0", "-122.33207"),
        ("-91.0", "-122.33207"),
        ("47.60621", "181.0"),
        ("47.60621", "-181.0"),
        ("NaN", "5.0"),
        ("5.0", "inf"),
    ],
)
def test_src04_malformed_coordinates_fail_deterministically(
    tmp_path: Path, latitude: str, longitude: str
) -> None:
    """G26B2-SRC04 malformed/non-finite/out-of-bounds coordinates fail closed."""
    row = (
        "5809844\tSeattle\tSeattle\tSeattle\t"
        f"{latitude}\t{longitude}"
        "\tP\tPPLA\tUS\t\tWA\t\t\t\t737015\t56\t56\tAmerica/Los_Angeles\t2011-06-22"
    )
    with pytest.raises(GeonamesSourceError):
        SOURCE.parse_cities(_artifact(tmp_path, "cities_inline.txt", row))


def test_src05_invalid_admin_code_shape_fails(tmp_path: Path) -> None:
    """G26B2-SRC05 a malformed admin reference cannot parse silently."""
    with pytest.raises(GeonamesSourceError):
        SOURCE.parse_admin1(
            _artifact(tmp_path, "admin1_bad.txt", "WA\tWashington\tWashington\t1128279")
        )


def test_src05b_invalid_country_code_shape_fails(tmp_path: Path) -> None:
    """G26B2-SRC05 a non-two-letter city country reference fails closed."""
    row = (
        "5809844\tSeattle\tSeattle\tSeattle\t47.60621\t-122.33207\tP\tPPLA\tUSA"
        "\t\tWA\t\t\t\t737015\t56\t56\tAmerica/Los_Angeles\t2011-06-22"
    )
    with pytest.raises(GeonamesSourceError):
        SOURCE.parse_cities(_artifact(tmp_path, "cities_bad_country.txt", row))


def test_src05c_invalid_country_cell_fails(tmp_path: Path) -> None:
    """G26B2-SRC05 a blank required country/admin cell fails closed."""
    blank_name = "US\tUSA\t840\tUS\t\tWashington\t9826675\t331002651\tNA\t.us\tUSD\tDollar\t1\t#####-####\t^(\\d{5})$\ten-US\t6252001\tCA\tUS"
    with pytest.raises(GeonamesSourceError):
        SOURCE.parse_countries(
            _artifact(tmp_path, "country_blank_name.txt", blank_name)
        )
    with pytest.raises(GeonamesSourceError):
        SOURCE.parse_cities(
            _artifact(
                tmp_path,
                "cities_blank.tx",
                "5809844\t\tSeattle\tSeattle\t47.60621\t-122.33207\tP\tPPLA\tUS"
                "\t\tWA\t\t\t\t737015\t56\t56\tAmerica/Los_Angeles\t2011-06-22",
            )
        )


def test_src06_unicode_diacritics_parse_and_normalize(tmp_path: Path) -> None:
    """G26B2-SRC06 diacritics parse and stay NFC-normalizable, never mangled."""
    composed = (
        "2838591\tMünchen\tMunich\tMünchen\t48.13743\t11.57549\tP\tPPLA\tDE"
        "\t\tBERE\t\t\t\t1471508\t519\t519\tEurope/Berlin\t2024-09-05"
    )
    decompozed = (
        "2838591\tM\u0308unchen\tMunich\tM\u0308unchen\t48.13743\t11.57549\tP\tPPLA\tDE"
        "\t\tBERE\t\t\t\t1471508\t519\t519\tEurope/Berlin\t2024-09-05"
    )
    # The adapter preserves the source spelling; NFC composition is the
    # corpus naming contract applied by the builder (see G26B2-BLD tests).
    assert (
        SOURCE.parse_cities(_artifact(tmp_path, "cities_muenchen.txt", composed))[
            0
        ].name
        == "München"
    )
    assert (
        SOURCE.parse_cities(_artifact(tmp_path, "cities_muenchen_nfd.txt", decompozed))[
            0
        ].name
        == "M\u0308unchen"
    )


def test_src07_unsupported_record_shape_cannot_create_location(tmp_path: Path) -> None:
    """G26B2-SRC07 wrong column counts are rejected, never silently accepted."""
    truncated = (
        "5809844\tSeattle\tSeattle\tSeattle\t47.60621\t-122.33207\tP\tPPLA\tUS"
        "\t\tWA\t\t\t\t737015\t56\t56\tAmerica/Los_Angeles"
    )
    assert len(truncated.split("\t")) == 18
    with pytest.raises(GeonamesSourceError):
        SOURCE.parse_cities(_artifact(tmp_path, "cities_truncated.txt", truncated))
    with pytest.raises(GeonamesSourceError):
        SOURCE.parse_countries(_artifact(tmp_path, "country_truncated.txt", "US\tUSA"))
    with pytest.raises(GeonamesSourceError):
        SOURCE.parse_admin1(
            _artifact(tmp_path, "admin1_truncated.txt", "US.WA\tWashington\tWashington")
        )
