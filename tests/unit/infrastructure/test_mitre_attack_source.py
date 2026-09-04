# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for MITRE ATT&CK STIX normalization and batching."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest

from agentic_threat_investigator.app.sources import (
    CHECKPOINTING,
    ArtifactReference,
    ObjectStore,
)
from agentic_threat_investigator.infrastructure.sources.mitre_attack import (
    NORMALIZATION_VERSION,
    RECORD_TYPE_GROUP,
    RECORD_TYPE_RELATIONSHIP,
    RECORD_TYPE_SOFTWARE,
    RECORD_TYPE_TECHNIQUE,
    MitreAttackBatchSource,
    MitreAttackFormatError,
    normalize_stix_objects,
)


class MemoryObjectStore(ObjectStore):  # pylint: disable=too-few-public-methods
    """Return one deterministic in-memory artifact."""

    def __init__(self, content: bytes) -> None:
        self.content = content

    async def read(self, uri: str) -> bytes:
        """Return the configured artifact bytes without external I/O."""
        assert uri
        return self.content


def _bundle() -> dict[str, Any]:
    """Return the Appendix A synthetic STIX bundle verbatim."""
    return {
        "type": "bundle",
        "id": "bundle--5c9d3f10-4a5e-4f8b-9a4f-1c1b1e0a0001",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--a934d7f9-1f15-4d3f-b7a1-2a7f0a1b1c01",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2024-06-01T00:00:00.000Z",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages to gain access to "
                "victim systems.",
                "revoked": False,
                "x_mitre_deprecated": False,
                "x_mitre_is_subtechnique": False,
                "x_mitre_attack_id": "T1566",
                "x_mitre_platforms": ["Linux", "Windows"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--0b7df85b-76f2-4f1a-8b6c-04e5d0f1a0d2",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2024-06-01T00:00:00.000Z",
                "name": "Spearphishing Attachment",
                "description": "Adversaries may send emails with malicious attachments.",
                "revoked": False,
                "x_mitre_deprecated": False,
                "x_mitre_is_subtechnique": True,
                "x_mitre_attack_id": "T1566.001",
                "x_mitre_platforms": ["Windows"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "malware",
                "id": "malware--4b6a9f2c-3d1e-4a8b-9c0d-5e6f7a8b9c0e",
                "created": "2017-05-31T00:00:00.000Z",
                "modified": "2023-10-01T00:00:00.000Z",
                "name": "Mimikatz",
                "description": "Mimikatz is a utility that extracts plaintext passwords, "
                "hash values, and Kerberos tickets.",
                "revoked": False,
                "x_mitre_deprecated": False,
                "x_mitre_attack_id": "S0002",
                "x_mitre_platforms": ["Windows"],
            },
            {
                "type": "tool",
                "id": "tool--4f1c3a8b-9d2e-4c6f-8a0b-1d2e3f4a5b6c",
                "created": "2017-05-31T00:00:00.000Z",
                "modified": "2023-10-01T00:00:00.000Z",
                "name": "PsExec",
                "description": "PsExec is a command-line tool for executing processes on "
                "remote systems.",
                "revoked": False,
                "x_mitre_deprecated": False,
                "x_mitre_attack_id": "S0029",
                "x_mitre_platforms": ["Windows"],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--bef3c5c5-6b7d-4a1c-8b9c-2d3e4f5a6b7c",
                "created": "2016-01-01T00:00:00.000Z",
                "modified": "2024-03-01T00:00:00.000Z",
                "name": "APT28",
                "description": "APT28 is a threat group attributed to Russia's "
                "intelligence services.",
                "aliases": ["Sofacy", "Fancy Bear", "APT28"],
                "revoked": False,
                "x_mitre_deprecated": False,
                "x_mitre_attack_id": "G0007",
            },
            {
                "type": "relationship",
                "id": "relationship--1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2024-06-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--bef3c5c5-6b7d-4a1c-8b9c-2d3e4f5a6b7c",
                "target_ref": "attack-pattern--a934d7f9-1f15-4d3f-b7a1-2a7f0a1b1c01",
                "description": "APT28 uses spearphishing to gain initial access.",
            },
            {
                "type": "relationship",
                "id": "relationship--2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2024-06-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "malware--4b6a9f2c-3d1e-4a8b-9c0d-5e6f7a8b9c0e",
                "target_ref": "attack-pattern--0b7df85b-76f2-4f1a-8b6c-04e5d0f1a0d2",
                "description": "Mimikatz uses spearphishing attachments for delivery.",
            },
            {
                "type": "relationship",
                "id": "relationship--3c4d5e6f-7a8b-4c9d-0e1f-2a3b4c5d6e7f",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2024-06-01T00:00:00.000Z",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--0b7df85b-76f2-4f1a-8b6c-04e5d0f1a0d2",
                "target_ref": "attack-pattern--a934d7f9-1f15-4d3f-b7a1-2a7f0a1b1c01",
                "description": "Spearphishing Attachment is a sub-technique of "
                "Phishing.",
            },
            {
                "type": "relationship",
                "id": "relationship--4d5e6f7a-8b9c-4d0e-1f2a-3b4c5d6e7f8a",
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2024-06-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--bef3c5c5-6b7d-4a1c-8b9c-2d3e4f5a6b7c",
                "target_ref": "malware--4b6a9f2c-3d1e-4a8b-9c0d-5e6f7a8b9c0e",
                "description": "APT28 uses Mimikatz.",
            },
            {
                "type": "identity",
                "id": "identity--c2ab6c9e-4f6a-4b3e-9a1d-8e2f3a4b5c6d",
                "name": "The MITRE Corporation",
            },
            {
                "type": "marking-definition",
                "id": "marking-definition--f2ab5c8e-3d4a-4e6f-8b0c-9d1e2f3a4b5c",
                "definition_type": "tlp",
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5e",
                "name": "Initial Access",
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--5e6f7a8b-9c0d-4e1f-2a3b-4c5d6e7f8a9b",
                "name": "Phishing Filter",
            },
        ],
    }


def _artifact() -> ArtifactReference:
    """Return a deterministic MITRE ATT&CK artifact reference."""
    return ArtifactReference(
        source_id="urn:ati:source:mitre_attack",
        uri="file:///datasets/mitre-attack/enterprise-attack.json",
        retrieved_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def _records() -> list[Any]:
    """Normalize the reference fixture for concise assertions."""
    return normalize_stix_objects(_bundle()["objects"], _artifact().retrieved_at)


def test_normalizes_techniques_with_provenance() -> None:
    """Normalize technique fields, tactics, platforms, identity, and provenance."""
    record = _records()[0]
    assert record.record_type == RECORD_TYPE_TECHNIQUE
    assert record.source_id == "urn:ati:source:mitre_attack"
    assert record.source_record_id.startswith("attack-pattern--")
    assert record.normalization_version == NORMALIZATION_VERSION
    assert record.observed_at is None
    assert record.published_at == datetime(2024, 6, 1, tzinfo=UTC)
    assert record.retrieved_at == _artifact().retrieved_at
    assert record.metadata == {"stix_type": "attack-pattern", "attack_id": "T1566"}
    assert record.canonical_payload == {
        "attack_id": "T1566",
        "name": "Phishing",
        "description": (
            "Adversaries may send phishing messages to gain access to victim systems."
        ),
        "url": "https://attack.mitre.org/techniques/T1566",
        "is_subtechnique": False,
        "tactics": ("initial-access",),
        "platforms": ("Linux", "Windows"),
        "revoked": False,
        "deprecated": False,
    }
    assert record.model_dump(mode="json")["raw_payload"] == _bundle()["objects"][0]
    subtechnique = _records()[1]
    assert subtechnique.canonical_payload["is_subtechnique"] is True
    assert subtechnique.canonical_payload["url"].endswith("/T1566/001")


def test_normalizes_malware_tool_and_group() -> None:
    """Normalize both software kinds and groups with sorted aliases."""
    records = _records()
    assert records[2].record_type == RECORD_TYPE_SOFTWARE
    assert records[2].canonical_payload["software_kind"] == "malware"
    assert records[3].record_type == RECORD_TYPE_SOFTWARE
    assert records[3].canonical_payload["software_kind"] == "tool"
    assert records[4].record_type == RECORD_TYPE_GROUP
    assert records[4].canonical_payload["aliases"] == (
        "APT28",
        "Fancy Bear",
        "Sofacy",
    )


def test_normalizes_relationships_and_resolves_endpoints() -> None:
    """Map relationship URNs and resolve endpoint ATT&CK fields from the bundle."""
    relationships = _records()[5:]
    assert all(
        record.record_type == RECORD_TYPE_RELATIONSHIP for record in relationships
    )
    first = relationships[0].canonical_payload
    assert first == {
        "relationship_urn": "urn:ati:relationship:attack:uses_technique",
        "stix_relationship_type": "uses",
        "source_stix_id": _bundle()["objects"][4]["id"],
        "source_stix_type": "intrusion-set",
        "source_attack_id": "G0007",
        "source_name": "APT28",
        "target_stix_id": _bundle()["objects"][0]["id"],
        "target_stix_type": "attack-pattern",
        "target_attack_id": "T1566",
        "target_name": "Phishing",
    }
    assert (
        relationships[1]
        .canonical_payload["relationship_urn"]
        .endswith(":uses_technique")
    )
    assert (
        relationships[2]
        .canonical_payload["relationship_urn"]
        .endswith(":associated_with")
    )
    assert (
        relationships[3]
        .canonical_payload["relationship_urn"]
        .endswith(":associated_with")
    )


def test_relationship_allows_unresolvable_endpoint() -> None:
    """Retain raw STIX endpoint IDs while unresolved endpoint fields remain null."""
    bundle = _bundle()
    relationship = bundle["objects"][5]
    relationship["target_ref"] = "attack-pattern--ffffffff-ffff-4fff-8fff-ffffffffffff"
    record = normalize_stix_objects(bundle["objects"], _artifact().retrieved_at)[5]
    payload = record.canonical_payload
    assert payload["target_stix_id"] == relationship["target_ref"]
    assert payload["target_stix_type"] is None
    assert payload["target_attack_id"] is None
    assert payload["target_name"] is None


def test_skips_metadata_out_of_scope_and_unknown_types() -> None:
    """Ignore the documented skip list and forward-compatible unknown types."""
    objects = [
        {"type": object_type, "id": f"{object_type}--valid"}
        for object_type in (
            "identity",
            "future-stix-type",
            "marking-definition",
            "x-mitre-tactic",
            "x-mitre-matrix",
            "course-of-action",
        )
    ]
    assert not normalize_stix_objects(objects, _artifact().retrieved_at)


def test_carries_revoked_and_deprecated_flags() -> None:
    """Retain revoked and deprecated ATT&CK objects as historical records."""
    bundle = _bundle()
    bundle["objects"][0]["revoked"] = True
    bundle["objects"][0]["x_mitre_deprecated"] = True
    payload = normalize_stix_objects(bundle["objects"], _artifact().retrieved_at)[
        0
    ].canonical_payload
    assert payload["revoked"] is True
    assert payload["deprecated"] is True


@pytest.mark.parametrize(
    "objects",
    [
        ["not-an-object"],
        [{"type": "identity"}],
        [{"id": "identity--one"}],
    ],
)
def test_rejects_malformed_stix_objects(objects: list[Any]) -> None:
    """Reject every malformed object even when its type would otherwise be skipped."""
    with pytest.raises(MitreAttackFormatError):
        normalize_stix_objects(objects, _artifact().retrieved_at)


@pytest.mark.parametrize(
    ("object_index", "attack_id"),
    [(0, "T123"), (2, "M0002"), (3, "S29"), (4, "G007")],
)
def test_rejects_missing_or_invalid_attack_ids(
    object_index: int, attack_id: str
) -> None:
    """Validate type-specific ATT&CK identifiers on every entity type."""
    bundle = _bundle()
    bundle["objects"][object_index]["x_mitre_attack_id"] = attack_id
    with pytest.raises(MitreAttackFormatError, match="invalid ATT&CK ID"):
        normalize_stix_objects(bundle["objects"], _artifact().retrieved_at)
    bundle["objects"][object_index].pop("x_mitre_attack_id")
    with pytest.raises(MitreAttackFormatError, match="x_mitre_attack_id"):
        normalize_stix_objects(bundle["objects"], _artifact().retrieved_at)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"type": "not-a-bundle", "objects": []},
        {"type": "bundle"},
        {"type": "bundle", "objects": {}},
    ],
)
@pytest.mark.asyncio
async def test_source_rejects_malformed_bundle_envelopes(payload: Any) -> None:
    """Reject invalid top-level JSON shapes and STIX envelopes."""
    source = MitreAttackBatchSource(MemoryObjectStore(json.dumps(payload).encode()))
    with pytest.raises(MitreAttackFormatError):
        _result = [batch async for batch in source.batches(_artifact())]


@pytest.mark.parametrize("content", [b"not-json", b"\xff", b"\xff\xfe{\x00}\x00"])
@pytest.mark.asyncio
async def test_source_rejects_invalid_utf8_json(content: bytes) -> None:
    """Require artifact content to be valid UTF-8 JSON."""
    source = MitreAttackBatchSource(MemoryObjectStore(content))
    with pytest.raises(MitreAttackFormatError):
        _result = [batch async for batch in source.batches(_artifact())]


@pytest.mark.asyncio
async def test_emits_bounded_ordered_batches_and_resumes() -> None:
    """Emit bundle-order records with cumulative checkpoints and exact resume."""
    content = json.dumps(_bundle()).encode()
    source = MitreAttackBatchSource(MemoryObjectStore(content), batch_size=4)
    batches = [batch async for batch in source.batches(_artifact())]
    assert [len(batch.records) for batch in batches] == [4, 4, 1]
    assert [batch.checkpoint for batch in batches] == ["index:4", "index:8", "index:9"]
    assert [batch.complete for batch in batches] == [False, False, True]
    assert [
        record.source_record_id for batch in batches for record in batch.records
    ] == [record.source_record_id for record in _records()]

    resumed = [
        batch async for batch in source.batches(_artifact(), checkpoint="index:4")
    ]
    assert [len(batch.records) for batch in resumed] == [4, 1]
    assert resumed[0].records[0].source_record_id == _records()[4].source_record_id


@pytest.mark.parametrize("checkpoint", ["", "4", "index:-1", "index:ten", "index:10"])
@pytest.mark.asyncio
async def test_rejects_invalid_checkpoints(checkpoint: str) -> None:
    """Reject unknown, malformed, negative, and out-of-range checkpoints."""
    source = MitreAttackBatchSource(MemoryObjectStore(json.dumps(_bundle()).encode()))
    with pytest.raises(ValueError, match="checkpoint"):
        _result = [
            batch async for batch in source.batches(_artifact(), checkpoint=checkpoint)
        ]


def test_content_hash_is_semantic_and_retrieval_independent() -> None:
    """Keep hashes stable across retrievals and change them with payload semantics."""
    bundle = _bundle()
    first = normalize_stix_objects(bundle["objects"], datetime(2025, 1, 1, tzinfo=UTC))
    second = normalize_stix_objects(
        deepcopy(bundle["objects"]), datetime(2025, 2, 1, tzinfo=UTC)
    )
    changed_bundle = deepcopy(bundle)
    changed_bundle["objects"][0]["description"] = "Materially changed."
    changed = normalize_stix_objects(
        changed_bundle["objects"], datetime(2025, 1, 1, tzinfo=UTC)
    )
    assert [record.content_hash for record in first] == [
        record.content_hash for record in second
    ]
    assert first[0].content_hash != changed[0].content_hash
    assert first[1].content_hash == changed[1].content_hash


def test_source_contract_and_constructor_validation() -> None:
    """Advertise the stable source contract and reject invalid batch bounds."""
    source = MitreAttackBatchSource(MemoryObjectStore(b"{}"))
    assert source.source_id == "urn:ati:source:mitre_attack"
    assert source.normalization_version == 1
    assert source.capabilities == frozenset({CHECKPOINTING})
    with pytest.raises(ValueError, match="positive"):
        MitreAttackBatchSource(MemoryObjectStore(b"{}"), batch_size=0)


@pytest.mark.asyncio
async def test_source_rejects_empty_result_and_mismatched_artifact() -> None:
    """Reject bundles without records and artifacts owned by another source."""
    empty = {"type": "bundle", "objects": [{"type": "identity", "id": "id--1"}]}
    source = MitreAttackBatchSource(MemoryObjectStore(json.dumps(empty).encode()))
    with pytest.raises(MitreAttackFormatError, match="no ingestible"):
        _result = [batch async for batch in source.batches(_artifact())]

    artifact = ArtifactReference(
        source_id="other",
        uri="file:///datasets/other/input.json",
        retrieved_at=datetime(2025, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="source_id"):
        _result = [batch async for batch in source.batches(artifact)]
