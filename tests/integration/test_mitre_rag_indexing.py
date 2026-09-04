# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end integration test for MITRE ingestion and RAG indexing."""

import json
from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from agentic_threat_investigator.app.document_indexing import (
    DocumentIndexingService,
    TokenBoundedChunker,
)
from agentic_threat_investigator.app.ingestion import IngestionService
from agentic_threat_investigator.app.sources import ArtifactReference, ObjectStore
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.sources.mitre_attack import (
    MitreAttackBatchSource,
)
from agentic_threat_investigator.infrastructure.sources.mitre_attack_documents import (
    MitreAttackDocumentBuilder,
)


class _MemoryStore(ObjectStore):  # pylint: disable=too-few-public-methods
    """Serve one synthetic pre-existing artifact without network access."""

    def __init__(self, content: bytes) -> None:
        self._content = content

    async def read(self, uri: str) -> bytes:
        """Return the synthetic artifact bytes."""
        assert uri == "file:///datasets/mitre/synthetic.json"
        return self._content


def _artifact_bytes() -> bytes:
    """Return a minimal ATI-authored synthetic ATT&CK bundle."""
    return json.dumps(
        {
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000001",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--00000000-0000-4000-8000-000000000002",
                    "created": "2026-01-01T00:00:00Z",
                    "modified": "2026-01-02T00:00:00Z",
                    "name": "Synthetic technique",
                    "description": "A deterministic integration fixture.",
                    "x_mitre_attack_id": "T1001",
                    "x_mitre_platforms": ["Linux"],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "command-and-control",
                        }
                    ],
                    "revoked": False,
                    "x_mitre_deprecated": False,
                    "x_mitre_is_subtechnique": False,
                }
            ],
        }
    ).encode()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_mitre_ingestion_to_document_chunks_is_idempotent(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Changed source IDs load and index; an unchanged rerun is a full no-op."""
    artifact = ArtifactReference(
        "urn:ati:source:mitre_attack",
        "file:///datasets/mitre/synthetic.json",
        datetime(2026, 1, 3, tzinfo=UTC),
    )
    source = MitreAttackBatchSource(_MemoryStore(_artifact_bytes()), batch_size=10)
    ingestion = IngestionService(uow_factory, batch_size=10)
    first = await ingestion.ingest(source, artifact)
    assert len(first.changed) == 1

    async with uow_factory() as uow:
        records = [
            await uow.source_records.get_by_id(result.record_id)
            for result in first.changed
        ]
    indexing = DocumentIndexingService(
        uow_factory,
        MitreAttackDocumentBuilder(),
        TokenBoundedChunker(400, 800),
        HashingEmbeddingClient(),
        batch_size=10,
        embedding_batch_size=4,
    )
    indexed = await indexing.index([record for record in records if record is not None])
    assert indexed.documents_inserted == 1
    assert indexed.chunks_replaced >= 1

    second = await ingestion.ingest(source, artifact)
    assert not second.changed
    noop = await indexing.index([])
    assert noop.documents_inserted == 0 and noop.chunks_replaced == 0

    async with uow_factory() as uow:
        document = await uow.documents.get_by_identity(
            "urn:ati:source:mitre_attack",
            "attack-pattern--00000000-0000-4000-8000-000000000002",
        )
        assert document is not None and document.id is not None
        chunks = await uow.document_chunks.list_by_document(document.id)
    assert chunks and len(chunks[0].embedding) == 1536
