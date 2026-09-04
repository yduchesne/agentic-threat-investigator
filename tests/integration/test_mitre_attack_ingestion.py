# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL integration tests for MITRE ATT&CK ingestion."""

# The reference fixture intentionally matches the unit fixture prescribed by the PR plan.
# pylint: disable=duplicate-code

import json
from collections.abc import AsyncIterator, Callable
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.ingestion import IngestionService
from agentic_threat_investigator.app.sources import (
    ArtifactReference,
    BatchSource,
    SourceBatch,
)
from agentic_threat_investigator.infrastructure.object_store import (
    FileSystemObjectStore,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.sources.mitre_attack import (
    MitreAttackBatchSource,
)


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


def _new_technique() -> dict[str, Any]:
    """Return one deterministic technique for update-path testing."""
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--11900000-0000-4000-8000-000000000000",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2025-01-01T00:00:00.000Z",
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries may exploit an internet-facing host.",
        "revoked": False,
        "x_mitre_deprecated": False,
        "x_mitre_is_subtechnique": False,
        "x_mitre_attack_id": "T1190",
        "x_mitre_platforms": ["Linux", "Windows"],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
        ],
    }


def _artifact(uri: str) -> ArtifactReference:
    """Build a deterministic MITRE ATT&CK artifact reference."""
    return ArtifactReference(
        source_id="urn:ati:source:mitre_attack",
        uri=uri,
        retrieved_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


async def _write_bundle(
    store: FileSystemObjectStore, path: Path, bundle: dict[str, Any]
) -> ArtifactReference:
    """Write a synthetic artifact through ObjectStore and return its reference."""
    uri = path.as_uri()
    await store.write(uri, json.dumps(bundle).encode("utf-8"))
    return _artifact(uri)


class _InterruptAfterFirstBatch(BatchSource):  # pylint: disable=too-few-public-methods
    """Delegate one batch and then emulate an artifact-processing interruption."""

    source_id = "urn:ati:source:mitre_attack"
    normalization_version = 1
    capabilities = MitreAttackBatchSource.capabilities

    def __init__(self, delegate: MitreAttackBatchSource) -> None:
        self._delegate = delegate

    def batches(
        self, artifact: ArtifactReference, checkpoint: str | None = None
    ) -> AsyncIterator[SourceBatch]:
        """Yield exactly one real batch before raising a deterministic error."""

        async def generate() -> AsyncIterator[SourceBatch]:
            iterator = self._delegate.batches(artifact, checkpoint)
            yield await anext(iterator)
            raise RuntimeError("synthetic interruption")

        return generate()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_full_ingestion_persists_records_and_provenance(
    uow_factory: Callable[[], PostgresUnitOfWork], tmp_path: Path
) -> None:
    """Persist every normalized record with durable identity and provenance."""
    store = FileSystemObjectStore(tmp_path)
    artifact = await _write_bundle(
        store, tmp_path / "enterprise-attack.json", _bundle()
    )
    summary = await IngestionService(uow_factory, batch_size=4).ingest(
        MitreAttackBatchSource(store, batch_size=4), artifact
    )

    assert (summary.inserted, summary.updated, summary.unchanged) == (9, 0, 0)
    assert summary.complete is True
    assert summary.checkpoint == "index:9"
    async with uow_factory() as uow:
        record = await uow.source_records.get_by_identity(
            "urn:ati:source:mitre_attack",
            "attack-pattern--a934d7f9-1f15-4d3f-b7a1-2a7f0a1b1c01",
        )
        assert uow.session is not None
        history_count = await uow.session.scalar(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = 'source_record'"
            )
        )
    assert record is not None
    assert record.source_id == artifact.source_id
    assert record.published_at == datetime(2024, 6, 1, tzinfo=UTC)
    assert record.retrieved_at == artifact.retrieved_at
    assert len(record.content_hash) == 64
    assert record.raw_payload is not None
    assert history_count == 9


@pytest.mark.asyncio
@pytest.mark.integration
async def test_completed_noop_and_restart_are_idempotent(
    uow_factory: Callable[[], PostgresUnitOfWork], tmp_path: Path
) -> None:
    """No-op completed artifacts and classify explicit restart records unchanged."""
    store = FileSystemObjectStore(tmp_path)
    artifact = await _write_bundle(
        store, tmp_path / "enterprise-attack.json", _bundle()
    )
    source = MitreAttackBatchSource(store, batch_size=4)
    service = IngestionService(uow_factory, batch_size=4)
    await service.ingest(source, artifact)

    completed = await service.ingest(source, artifact)
    assert (completed.inserted, completed.updated, completed.unchanged) == (0, 0, 0)
    assert completed.complete is True
    restarted = await service.ingest(source, artifact, restart=True)
    assert (restarted.inserted, restarted.updated, restarted.unchanged) == (0, 0, 9)
    async with uow_factory() as uow:
        assert uow.session is not None
        history_count = await uow.session.scalar(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = 'source_record'"
            )
        )
    assert history_count == 9


@pytest.mark.asyncio
@pytest.mark.integration
async def test_updated_bundle_changes_only_material_records(
    uow_factory: Callable[[], PostgresUnitOfWork], tmp_path: Path
) -> None:
    """Insert one new record, update one changed record, and retain all others."""
    store = FileSystemObjectStore(tmp_path)
    service = IngestionService(uow_factory, batch_size=4)
    source = MitreAttackBatchSource(store, batch_size=4)
    original = await _write_bundle(store, tmp_path / "original.json", _bundle())
    await service.ingest(source, original)

    updated_bundle = deepcopy(_bundle())
    updated_bundle["objects"][0]["description"] = "Materially revised description."
    updated_bundle["objects"].append(_new_technique())
    updated_artifact = await _write_bundle(
        store, tmp_path / "updated.json", updated_bundle
    )
    summary = await service.ingest(source, updated_artifact)

    assert (summary.inserted, summary.updated, summary.unchanged) == (1, 1, 8)
    async with uow_factory() as uow:
        assert uow.session is not None
        history_count = await uow.session.scalar(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = 'source_record'"
            )
        )
    assert history_count == 11


@pytest.mark.asyncio
@pytest.mark.integration
async def test_checkpoint_resumes_after_interruption(
    uow_factory: Callable[[], PostgresUnitOfWork], tmp_path: Path
) -> None:
    """Commit partial progress and resume remaining records with the real source."""
    store = FileSystemObjectStore(tmp_path)
    artifact = await _write_bundle(
        store, tmp_path / "enterprise-attack.json", _bundle()
    )
    real_source = MitreAttackBatchSource(store, batch_size=3)
    service = IngestionService(uow_factory, batch_size=3)

    with pytest.raises(RuntimeError, match="synthetic interruption"):
        await service.ingest(_InterruptAfterFirstBatch(real_source), artifact)
    async with uow_factory() as uow:
        checkpoint = await uow.ingestion_checkpoints.get(
            real_source.source_id, artifact.uri, real_source.normalization_version
        )
    assert checkpoint is not None
    assert checkpoint.checkpoint == "index:3"
    assert checkpoint.complete is False

    resumed = await service.ingest(real_source, artifact)
    assert (resumed.inserted, resumed.updated, resumed.unchanged) == (6, 0, 0)
    assert resumed.checkpoint == "index:9"
    assert resumed.complete is True
