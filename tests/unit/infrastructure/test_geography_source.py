# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B ATI Geography Corpus NDJSON source reader unit tests.

The corpus format is the documented deterministic intermediate representation
operators derive from the upstream reference sources; this parser is the
production parser the checked-in fixtures exercise (see
tests/fixtures/geoint/).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentic_threat_investigator.domain.geoint import LocationType
from agentic_threat_investigator.infrastructure.sources.geography import (
    JsonlGeographyCorpus,
    ReferenceCorpusError,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "geoint"


def test_parses_small_corpus_with_hierarchy() -> None:
    """The small fixture parses into the deterministic reference records."""
    records = JsonlGeographyCorpus().read_path(FIXTURES / "corpus_small.jsonl")
    types = [record.location_type for record in records]
    assert types.count(LocationType.COUNTRY) == 2
    assert types.count(LocationType.ADMINISTRATIVE_AREA) == 3
    assert types.count(LocationType.CITY) == 6
    seattle = next(record for record in records if record.canonical_name == "Seattle")
    assert seattle.parent is not None
    assert seattle.parent.location_type is LocationType.ADMINISTRATIVE_AREA
    assert seattle.geometry == "SRID=4326;POINT(-122.3321 47.6062)"
    auburn = next(record for record in records if record.canonical_name == "Auburn")
    assert auburn.geometry is None  # coordinate-less record stays spatial-free


def test_parses_synthetic_edge_corpus_with_parents() -> None:
    """The synthetic edge fixture parses with overlapping parent polygons."""
    records = JsonlGeographyCorpus().read_path(FIXTURES / "corpus_synthetic_edge.jsonl")
    assert len(records) == 5
    springfields = [r for r in records if r.canonical_name == "Springfield"]
    assert {r.admin1_code for r in springfields} == {"ALPHA", "BETA"}
    alpha = next(r for r in records if r.admin1_code == "ALPHA")
    assert alpha.geometry is not None
    assert "0 10" in alpha.geometry  # overlap strip


def test_comments_and_blank_lines_are_ignored() -> None:
    """Blank lines and comment lines are structurally insignificant."""
    corpus = (
        "# header comment\n"
        "\n"
        '{"location_type": "country", "name": "X", "canonical_name": "X", "country_code": "XX"}\n'
        "# trailing comment\n"
    )
    records = JsonlGeographyCorpus().read(corpus, source="inline")
    assert len(records) == 1
    assert records[0].country_code == "XX"


def test_malformed_json_fails_closed() -> None:
    """Malformed JSON reports the artifact and line without partial records."""
    with pytest.raises(ReferenceCorpusError, match=r"inline:3"):
        JsonlGeographyCorpus().read(
            '{"location_type": "country", "name": "X", "canonical_name": "X", '
            '"country_code": "XX"}\n'
            "# comment\n"
            "{not-json\n",
            source="inline",
        )


def test_unknown_fields_fail_closed() -> None:
    """Unknown corpus fields are rejected rather than silently ignored."""
    with pytest.raises(ReferenceCorpusError, match="unknown fields"):
        JsonlGeographyCorpus().read(
            '{"location_type": "country", "name": "X", "canonical_name": "X", '
            '"country_code": "XX", "source_id": "gn:123"}\n'
        )


def test_unknown_location_type_fails_closed() -> None:
    """An unsupported reference type is rejected at parse time."""
    with pytest.raises(ReferenceCorpusError, match="location_type"):
        JsonlGeographyCorpus().read(
            '{"location_type": "continent", "name": "X", "canonical_name": "X", '
            '"country_code": "XX"}\n'
        )


def test_invalid_record_values_fail_closed() -> None:
    """Invalid DTO values (bad country code, missing parent) fail closed."""
    with pytest.raises(ReferenceCorpusError, match="country_code"):
        JsonlGeographyCorpus().read(
            '{"location_type": "country", "name": "X", "canonical_name": "X", '
            '"country_code": "USA"}\n'
        )
    with pytest.raises(ReferenceCorpusError, match="parent"):
        JsonlGeographyCorpus().read(
            '{"location_type": "city", "name": "X", "canonical_name": "X", '
            '"country_code": "US", "admin1_code": "WA"}\n'
        )


def test_directory_reading_is_deterministic() -> None:
    """Directory reading processes artifacts in sorted name order."""
    records = JsonlGeographyCorpus().read_directory(FIXTURES)
    assert len(records) == 16


def test_missing_artifact_fails_closed() -> None:
    """A missing artifact path fails closed with the artifact identity."""
    with pytest.raises(ReferenceCorpusError, match="cannot read"):
        JsonlGeographyCorpus().read_path(FIXTURES / "does_not_exist.jsonl")
