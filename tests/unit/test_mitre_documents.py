# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for MITRE ATT&CK narrative document construction."""

from datetime import UTC, datetime

import pytest

from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.infrastructure.sources.mitre_attack_documents import (
    MitreAttackDocumentBuilder,
)


def _record(**overrides: object) -> SourceRecord:
    values: dict[str, object] = {
        "source_id": "urn:ati:source:mitre_attack",
        "source_record_id": "attack-pattern--one",
        "record_type": "attack_technique",
        "normalization_version": 1,
        "published_at": datetime(2026, 1, 1, tzinfo=UTC),
        "retrieved_at": datetime(2026, 1, 2, tzinfo=UTC),
        "canonical_payload": {
            "attack_id": "T1001",
            "name": "Example technique",
            "description": "A synthetic long description.",
            "url": "https://attack.mitre.org/techniques/T1001",
            "platforms": ["Linux", "Windows"],
            "tactics": ["command-and-control"],
            "is_subtechnique": False,
            "revoked": False,
            "deprecated": False,
        },
    }
    values.update(overrides)
    return SourceRecord.model_validate(values)


def test_builder_renders_normalized_sections_in_fixed_order() -> None:
    """The builder emits stable sections and carries source provenance."""
    builder = MitreAttackDocumentBuilder()
    first = builder.build(_record())
    second = builder.build(_record())
    assert first == second
    assert first.title == "Example technique"
    assert first.metadata["attack_id"] == "T1001"
    assert first.content.index("## Overview") < first.content.index("## Details")
    assert first.content.index("## Details") < first.content.index("## Context")
    assert first.content.index("## Context") < first.content.index("## References")
    assert "raw_payload" not in first.content


@pytest.mark.parametrize(
    "overrides",
    [
        {"source_id": "urn:ati:source:other"},
        {"record_type": "attack_relationship"},
    ],
)
def test_builder_rejects_unsupported_records(overrides: dict[str, object]) -> None:
    """The infrastructure builder enforces its source and type contract."""
    with pytest.raises(ValueError):
        MitreAttackDocumentBuilder().build(_record(**overrides))
