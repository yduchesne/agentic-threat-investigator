# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33D source-neutral relationship vocabulary tests (M33D-D01..D07).

The four PR 33D RelationshipType URNs (USES, TARGETS, ATTRIBUTED_TO,
CONTROLS) must exist with exact wire values, all pre-existing relationship
URNs must remain byte-identical, the API/OpenAPI and frontend exhaustive
registries must represent all four, and the STIX converter/extractor
profiles must reference the exact URNs. PostgreSQL persistence stores the
relationship-type URN as free text (no database enum/allowlist), so no
migration is introduced; the real-DB slice exercises the new URNs through
the authoritative stored functions (M33D-V02).
"""

from __future__ import annotations

import json
from pathlib import Path

from agentic_threat_investigator.domain.relationships import RelationshipType

_REPO_ROOT = Path(__file__).resolve().parents[3]

_EXISTING_URNS = frozenset(
    {
        "urn:ati:relationship:dns:resolves_to",
        "urn:ati:relationship:dns:cname_of",
        "urn:ati:relationship:dns:uses_name_server",
        "urn:ati:relationship:dns:uses_mail_server",
        "urn:ati:relationship:network:belongs_to",
        "urn:ati:relationship:routing:announced_by",
        "urn:ati:relationship:registration:registered_to",
        "urn:ati:relationship:organization:operated_by",
        "urn:ati:relationship:threat:associated_with",
        "urn:ati:relationship:attack:uses_technique",
        "urn:ati:relationship:vulnerability:exploits",
    }
)
"""The exact pre-PR-33D relationship URN set; none may change identity."""

_NEW_URNS = {
    RelationshipType.USES: "urn:ati:relationship:threat:uses",
    RelationshipType.TARGETS: "urn:ati:relationship:threat:targets",
    RelationshipType.ATTRIBUTED_TO: "urn:ati:relationship:threat:attributed_to",
    RelationshipType.CONTROLS: "urn:ati:relationship:threat:controls",
}


def test_m33d_d01_uses_wire_value() -> None:
    """M33D-D01: USES has the exact source-neutral URN."""
    assert RelationshipType.USES.value == "urn:ati:relationship:threat:uses"
    assert RelationshipType.USES.value in _NEW_URNS.values()


def test_m33d_d02_targets_wire_value() -> None:
    """M33D-D02: TARGETS has the exact source-neutral URN."""
    assert RelationshipType.TARGETS.value == "urn:ati:relationship:threat:targets"


def test_m33d_d03_attributed_to_wire_value() -> None:
    """M33D-D03: ATTRIBUTED_TO has the exact source-neutral URN."""
    assert (
        RelationshipType.ATTRIBUTED_TO.value
        == "urn:ati:relationship:threat:attributed_to"
    )


def test_m33d_d04_controls_wire_value() -> None:
    """M33D-D04: CONTROLS has the exact source-neutral URN."""
    assert RelationshipType.CONTROLS.value == "urn:ati:relationship:threat:controls"


def test_m33d_d05_existing_urns_unchanged() -> None:
    """M33D-D05: every pre-existing relationship URN stays byte-identical."""
    all_urns = {item.value for item in RelationshipType}
    assert all_urns >= _EXISTING_URNS
    assert len(all_urns) == len(_EXISTING_URNS) + 4


def test_m33d_d06_persistence_accepts_free_text_urn() -> None:
    """M33D-D06: the URNs are opaque text for the generic persistence path.

    PostgreSQL persists ``relationship_type_urn`` as free text (no database
    enum/allowlist/CHECK on these values); the new URNs therefore need no
    migration. This unit proxy proves the enum round-trips as a plain value
    and parses back; the real stored-function path is covered by M33D-V02.
    """
    for urn in _NEW_URNS.values():
        assert RelationshipType(urn).value == urn


def test_m33d_d07_registries_represent_all_four() -> None:
    """M33D-D07: API/OpenAPI and frontend registries list all four URNs."""
    openapi = json.loads(
        (_REPO_ROOT / "tests/fixtures/openapi_v1.json").read_text(encoding="utf-8")
    )
    enum_values = set(openapi["components"]["schemas"]["RelationshipType"]["enum"])
    assert all(urn in enum_values for urn in _NEW_URNS.values())
    labels = (_REPO_ROOT / "frontend/src/relationships/labels.ts").read_text(
        encoding="utf-8"
    )
    assert all(urn in labels for urn in _NEW_URNS.values())
    locale = (_REPO_ROOT / "frontend/src/i18n/locales/en/relationships.json").read_text(
        encoding="utf-8"
    )
    assert "types.uses" in locale
    assert "types.targets" in locale
    assert "types.attributedTo" in locale
    assert "types.controls" in locale
