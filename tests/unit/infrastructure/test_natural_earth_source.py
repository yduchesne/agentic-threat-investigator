# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B-2 Natural Earth reference-source adapter tests (G26B2-SRC08..12).

The supported inputs are explicitly versioned Natural Earth GeoJSON feature
collections in the ``ne_10m_admin_0_countries`` / ``ne_10m_admin_1_states_
provinces`` schema (``iso_a2``/``iso_a2_eh``/``iso_a2_wb`` country codes,
``iso_3166_2`` admin subdivision). The checked-in fixtures are synthetic
but conform exactly to the production GeoJSON input contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_threat_investigator.infrastructure.geoint.natural_earth import (
    NaturalEarthReferenceSource,
    NaturalEarthSourceError,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "geoint" / "natural_earth"
SOURCE = NaturalEarthReferenceSource()


def _collection(tmp_path: Path, *features: dict[str, object]) -> Path:
    """Write inline GeoJSON features into one supported-format artifact."""
    payload = {
        "type": "FeatureCollection",
        "features": [{"type": "Feature", **feature} for feature in features],
    }
    path = tmp_path / "inline.geojson"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _polygon(*positions: list[float]) -> dict[str, object]:
    """Build one GeoJSON polygon geometry with the given closed ring."""
    return {
        "type": "Polygon",
        "coordinates": [[list(position) for position in positions]],
    }


_COUNTRY_RING = [
    [-125.0, 25.0],
    [-65.0, 25.0],
    [-65.0, 49.5],
    [-125.0, 49.5],
    [-125.0, 25.0],
]
_ADMIN_RING = [
    [-125.0, 45.0],
    [-116.0, 45.0],
    [-116.0, 49.5],
    [-125.0, 49.5],
    [-125.0, 45.0],
]


def test_src08_country_polygon_parses(tmp_path: Path) -> None:
    """G26B2-SRC08 a country Polygon parses to canonical Polygon EWKT."""
    path = _collection(
        tmp_path,
        {
            "properties": {
                "iso_a2": "CA",
                "iso_a2_eh": "CA",
                "iso_a2_wb": "CA",
                "name": "Canada",
            },
            "geometry": _polygon(*_COUNTRY_RING),
        },
    )
    records = SOURCE.parse_countries(path)
    assert len(records) == 1
    record = records[0]
    assert record.iso_code == "CA"
    assert record.name == "Canada"
    assert record.geometry == (
        "SRID=4326;POLYGON((-125 25, -65 25, -65 49.5, -125 49.5, -125 25))"
    )


def test_src09_country_multipolygon_parses(tmp_path: Path) -> None:
    """G26B2-SRC09 a country MultiPolygon parses to canonical EWKT."""
    path = _collection(
        tmp_path,
        {
            "properties": {
                "iso_a2": "US",
                "iso_a2_eh": "US",
                "iso_a2_wb": "US",
                "name": "United States",
            },
            "geometry": {
                "type": "MultiPolygon",
                "coordinates": [
                    [[list(position) for position in _COUNTRY_RING]],
                    [
                        [
                            [-170.0, 55.0],
                            [-130.0, 55.0],
                            [-130.0, 72.0],
                            [-170.0, 72.0],
                            [-170.0, 55.0],
                        ]
                    ],
                ],
            },
        },
    )
    records = SOURCE.parse_countries(path)
    assert records[0].geometry is not None
    assert records[0].geometry.startswith("SRID=4326;MULTIPOLYGON(")
    assert "((" in records[0].geometry  # at least two polygon rings


def test_src10_admin_polygon_parses(tmp_path: Path) -> None:
    """G26B2-SRC10 an admin-1 Polygon parses with its subdivision code."""
    path = _collection(
        tmp_path,
        {
            "properties": {
                "iso_a2": "US",
                "iso_3166_2": "US-WA",
                "name": "Washington",
                "adm1_code": "USA-0001",
                "postal": "WA",
            },
            "geometry": _polygon(*_ADMIN_RING),
        },
    )
    records = SOURCE.parse_admin1(path)
    assert len(records) == 1
    record = records[0]
    assert record.country_code == "US"
    assert record.subdivision_code == "WA"
    assert record.adm1_code == "USA-0001"
    assert record.geometry == (
        "SRID=4326;POLYGON((-125 45, -116 45, -116 49.5, -125 49.5, -125 45))"
    )


@pytest.mark.parametrize(
    "geometry",
    [
        {"type": "Point", "coordinates": [-122.0, 47.6]},
        {"type": "LineString", "coordinates": [[-125.0, 45.0], [-116.0, 49.5]]},
        {"type": "Polygon", "coordinates": [[]]},
        {"type": "Polygon", "coordinates": [[[-125.0, 45.0], [-116.0, 45.0]]]},
        {
            "type": "Polygon",
            "coordinates": [
                [
                    [-125.0, 45.0],
                    [-116.0, 45.0],
                    [-116.0, 49.5],
                    [-125.0, 49.5],
                    [0.0, 0.0],
                ]
            ],
        },
    ],
)
def test_src11_invalid_non_polygonal_geometry_rejected(
    tmp_path: Path, geometry: dict[str, object]
) -> None:
    """G26B2-SRC11 non-polygonal/empty/unclosed geometry fails closed."""
    path = _collection(
        tmp_path,
        {
            "properties": {
                "iso_a2": "CA",
                "iso_a2_eh": "CA",
                "iso_a2_wb": "CA",
                "name": "Canada",
            },
            "geometry": geometry,
        },
    )
    for parse in (SOURCE.parse_countries, SOURCE.parse_admin1):
        with pytest.raises(NaturalEarthSourceError):
            parse(path)


def test_src12_country_identifiers_normalize_deterministically(
    tmp_path: Path,
) -> None:
    """G26B2-SRC12 ISO identifiers normalize deterministically.

    The primary ``iso_a2`` wins when usable; otherwise the Eurostat
    (``iso_a2_eh``) and World Bank (``iso_a2_wb``) fallbacks apply in
    order; a feature with no usable code keeps ``None`` and is reported by
    the builder, never guessed.
    """
    path = _collection(
        tmp_path,
        {
            "properties": {
                "iso_a2": "us",
                "iso_a2_eh": "US",
                "iso_a2_wb": "US",
                "name": "lower",
            },
            "geometry": _polygon(*_COUNTRY_RING),
        },
        {
            "properties": {
                "iso_a2": "-99",
                "iso_a2_eh": "XY",
                "iso_a2_wb": "XY",
                "name": "eh",
            },
            "geometry": _polygon(*_COUNTRY_RING),
        },
        {
            "properties": {
                "iso_a2": "-99",
                "iso_a2_eh": "-99",
                "iso_a2_wb": "YY",
                "name": "wb",
            },
            "geometry": _polygon(*_COUNTRY_RING),
        },
        {
            "properties": {
                "iso_a2": "-99",
                "iso_a2_eh": "-99",
                "iso_a2_wb": "-99",
                "name": "none",
            },
            "geometry": _polygon(*_COUNTRY_RING),
        },
    )
    codes = [record.iso_code for record in SOURCE.parse_countries(path)]
    assert codes == ["US", "XY", "YY", None]
