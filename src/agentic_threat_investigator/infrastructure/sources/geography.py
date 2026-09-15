# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic canonical geography corpus source (PR 26B).

Reads the *ATI Geography Corpus* NDJSON format: one JSON object per line
describing one canonical reference record. The format is the documented
deterministic intermediate representation that operators derive from the
upstream reference sources (GeoNames-style naming/hierarchy/coordinates and
Natural Earth-style boundary geometry -- see docs/DATA_SOURCES.md). Only
this local corpus parser is installed in PR 26B; migrations never download
reference data, and reference import is explicit operator action.

Corpus syntax:

- one JSON object per line (blank lines and ``#`` comment lines ignored);
- record fields match :class:`GeographicReferenceRecord` with ``type`` in
  ``country``/``administrative_area``/``city`` and an optional ``parent``
  object carrying the parent's own canonical identity;
- ``geometry``/``centroid`` are EWKT strings (``SRID=4326;...``) or absent;
- malformed JSON, unknown fields, or invalid values fail closed with
  :class:`ReferenceCorpusError`, never silently skipped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agentic_threat_investigator.domain.geo_reference import (
    GeographicReferenceRecord,
    ReferenceParent,
)
from agentic_threat_investigator.domain.geoint import LocationType

_PARENT_FIELDS = {
    "location_type",
    "country_code",
    "admin1_code",
    "admin2_code",
    "canonical_name",
}
_RECORD_FIELDS = {
    "location_type",
    "name",
    "canonical_name",
    "country_code",
    "admin1_code",
    "admin2_code",
    "parent",
    "geometry",
    "centroid",
}

_TYPE_NAMES = {member.value: member for member in LocationType}


class ReferenceCorpusError(ValueError):
    """Raised when a reference corpus file violates the documented format.

    The message identifies the artifact and line; it never embeds record
    payloads.
    """


def _location_type(value: Any, *, path: str) -> LocationType:
    """Map a corpus ``location_type`` value fail-closed."""
    if not isinstance(value, str) or value not in _TYPE_NAMES:
        raise ReferenceCorpusError(
            f"{path}: location_type must be one of country, administrative_area, city"
        )
    return _TYPE_NAMES[value]


def _parent(raw: Any, *, path: str) -> ReferenceParent | None:
    """Map an optional corpus parent object fail-closed."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ReferenceCorpusError(f"{path}.parent must be an object")
    unknown = set(raw) - _PARENT_FIELDS
    if unknown:
        raise ReferenceCorpusError(
            f"{path}.parent has unknown fields: {sorted(unknown)}"
        )
    try:
        return ReferenceParent(
            location_type=_location_type(raw["location_type"], path=f"{path}.parent"),
            country_code=raw["country_code"],
            admin1_code=raw.get("admin1_code"),
            admin2_code=raw.get("admin2_code"),
            canonical_name=raw["canonical_name"],
        )
    except (KeyError, TypeError) as error:
        raise ReferenceCorpusError(
            f"{path}.parent is missing required fields"
        ) from error


def _record(raw: dict[str, Any], *, path: str) -> GeographicReferenceRecord:
    """Map one validated corpus object onto the reference record DTO."""
    try:
        return GeographicReferenceRecord(
            location_type=_location_type(raw["location_type"], path=path),
            name=raw["name"],
            canonical_name=raw["canonical_name"],
            country_code=raw["country_code"],
            admin1_code=raw.get("admin1_code"),
            admin2_code=raw.get("admin2_code"),
            parent=_parent(raw.get("parent"), path=path),
            geometry=raw.get("geometry"),
            centroid=raw.get("centroid"),
        )
    except KeyError as error:
        raise ReferenceCorpusError(
            f"{path}: missing required field {error.args[0]}"
        ) from error
    except ValidationError as error:
        raise ReferenceCorpusError(f"{path}: {error}") from error


class JsonlGeographyCorpus:
    """Reads the documented ATI Geography Corpus NDJSON format."""

    def read(
        self, content: str, *, source: str = "<corpus>"
    ) -> list[GeographicReferenceRecord]:
        """Parse one corpus document into deterministic reference records."""
        records: list[GeographicReferenceRecord] = []
        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as error:
                raise ReferenceCorpusError(
                    f"{source}:{line_number}: invalid JSON ({error.msg})"
                ) from error
            if not isinstance(payload, dict):
                raise ReferenceCorpusError(
                    f"{source}:{line_number}: each corpus line must be a JSON object"
                )
            unknown = set(payload) - _RECORD_FIELDS
            if unknown:
                raise ReferenceCorpusError(
                    f"{source}:{line_number}: unknown fields {sorted(unknown)}"
                )
            records.append(_record(payload, path=f"{source}:{line_number}"))
        return records

    def read_path(self, path: Path) -> list[GeographicReferenceRecord]:
        """Parse one corpus artifact file fail-closed."""
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as error:
            raise ReferenceCorpusError(
                f"cannot read corpus artifact {path}: {error}"
            ) from error
        return self.read(content, source=str(path))

    def read_paths(self, paths: list[Path]) -> list[GeographicReferenceRecord]:
        """Parse one or more artifacts, preserving their given order."""
        records: list[GeographicReferenceRecord] = []
        for path in paths:
            records.extend(self.read_path(path))
        return records

    def read_directory(self, directory: Path) -> list[GeographicReferenceRecord]:
        """Parse every ``*.jsonl`` artifact in one directory deterministically."""
        artifacts = sorted(directory.glob("*.jsonl"))
        return self.read_paths(artifacts)
