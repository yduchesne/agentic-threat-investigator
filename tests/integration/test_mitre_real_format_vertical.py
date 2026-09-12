# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical PR 22A real-format MITRE ATT&CK vertical slice.

Proves the complete production ingestion -> document construction ->
embedding/indexing -> PostgreSQL/pgvector retrieval path against a
deterministic local STIX 2.1 fixture that conforms exactly to the
``MitreAttackBatchSource`` input contract. The only fake boundary is the
deterministic embedding representation; the production source parser,
document builder, indexing service, repositories, and retriever are all
exercised.
"""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from agentic_threat_investigator.app.document_indexing import (
    DocumentIndexingService,
    TokenBoundedChunker,
)
from agentic_threat_investigator.app.embeddings import EmbeddedText, EmbeddingClient
from agentic_threat_investigator.app.ingestion import IngestionService
from agentic_threat_investigator.app.sources import ArtifactReference
from agentic_threat_investigator.domain.documents import (
    DocumentChunk,
    EmbeddingModelInfo,
)
from agentic_threat_investigator.domain.research import ResearchQuery
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.object_store import (
    FileSystemObjectStore,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)
from agentic_threat_investigator.infrastructure.sources.mitre_attack import (
    MitreAttackBatchSource,
)
from agentic_threat_investigator.infrastructure.sources.mitre_attack_documents import (
    MitreAttackDocumentBuilder,
)

FIXTURE = Path("tests/fixtures/mitre_attack/enterprise_attack_small.json")
RETRIEVED_AT = datetime(2026, 1, 15, tzinfo=UTC)

# One distinctive technique whose description words are unique to it; the
# deterministic hashing representation ranks it first for the query below.
TECHNIQUE_RECORD_ID = "attack-pattern--8a8e9e5e-2b4c-4d6e-8f0a-112233445566"
DISTINCTIVE_QUERY = "obfuscate command-and-control traffic conceal exfiltrated data"


class _VariantEmbeddingClient(EmbeddingClient):
    """Deterministic hashing representation under a different embedding identity.

    The vectors differ from ``HashingEmbeddingClient`` (a salt is prepended
    to every word) and the identity is distinct, which proves controlled
    re-embedding and identity-filtered retrieval without external I/O.
    """

    def __init__(self, dimension: int = 1536) -> None:
        self._dimension = dimension
        self._info = EmbeddingModelInfo(
            provider="hashing-variant",
            model="ati-variant-v1",
            model_version=2,
            dimension=dimension,
        )

    @property
    def model_info(self) -> EmbeddingModelInfo:
        """Return the variant embedding identity."""
        return self._info

    async def embed_texts(self, texts: Sequence[str]) -> list[EmbeddedText]:
        """Hash salted words into normalized vectors deterministically."""
        base = HashingEmbeddingClient(self._dimension)
        results = await base.embed_texts(["salt:" + text for text in texts])
        return [EmbeddedText(result.text_ordinal, result.vector) for result in results]


def _document_records(records: Sequence[SourceRecord]) -> list[SourceRecord]:
    """Return only the persisted records the MITRE document builder supports.

    The production builder renders attack_technique/attack_software/attack_group
    records; relationship records persist as source records but do not become
    narrative documents.
    """
    builder = MitreAttackDocumentBuilder()
    return [
        record
        for record in records
        if record.record_type in builder.document_record_types
    ]


async def _ingest_fixture(
    uow_factory: Callable[[], PostgresUnitOfWork], store_root: Path
) -> tuple[FileSystemObjectStore, ArtifactReference, list[SourceRecord]]:
    """Write the fixture into the production filesystem store and ingest it."""
    store = FileSystemObjectStore(store_root)
    uri = f"file://{store_root / 'datasets/mitre/enterprise_attack_small.json'}"
    await store.write(uri, FIXTURE.read_bytes())
    artifact = ArtifactReference("urn:ati:source:mitre_attack", uri, RETRIEVED_AT)
    ingestion = IngestionService(uow_factory, batch_size=20)
    first = await ingestion.ingest(
        MitreAttackBatchSource(store, batch_size=20), artifact
    )
    # technique, malware, tool, group, relationship; identity/marking/tactic skipped.
    assert first.inserted == 5
    async with uow_factory() as uow:
        records = [
            record
            for result in first.changed
            if (record := await uow.source_records.get_by_id(result.record_id))
            is not None
        ]
    assert len(records) == 5
    return store, artifact, _document_records(records)


def _indexing_service(
    uow_factory: Callable[[], PostgresUnitOfWork],
    embedding_client: EmbeddingClient,
) -> DocumentIndexingService:
    """Build the production indexing service with an injected embedding client."""
    return DocumentIndexingService(
        uow_factory,
        MitreAttackDocumentBuilder(),
        TokenBoundedChunker(400, 800),
        embedding_client,
        batch_size=20,
        embedding_batch_size=4,
    )


async def _documents_with_chunks(
    uow_factory: Callable[[], PostgresUnitOfWork], records: Sequence[SourceRecord]
) -> dict[str, tuple[UUID, list[DocumentChunk]]]:
    """Return per-record document IDs and their ordered current chunks."""
    loaded: dict[str, tuple[UUID, list[DocumentChunk]]] = {}
    async with uow_factory() as uow:
        for record in records:
            document = await uow.documents.get_by_identity(
                record.source_id, record.source_record_id
            )
            if document is None or document.id is None:
                continue
            loaded[record.source_record_id] = (
                document.id,
                await uow.document_chunks.list_by_document(document.id),
            )
    return loaded


@pytest.mark.asyncio
@pytest.mark.integration
async def test_canonical_mitre_real_format_vertical_slice(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """Real-format ingestion -> builder -> indexing -> pgvector round trip."""
    store, artifact, records = await _ingest_fixture(uow_factory, tmp_path)

    # A second ingestion through the production checkpoint seam is idempotent.
    second = await IngestionService(uow_factory, batch_size=20).ingest(
        MitreAttackBatchSource(store, batch_size=20), artifact
    )
    assert (second.inserted, second.updated, second.unchanged) == (0, 0, 0)
    assert second.complete is True

    indexing = _indexing_service(uow_factory, HashingEmbeddingClient())
    indexed = await indexing.index(records)
    assert indexed.documents_inserted == 4  # technique + software x2 + group
    assert indexed.documents_updated == 0
    assert indexed.chunks_replaced >= 4

    loaded = await _documents_with_chunks(uow_factory, records)
    assert set(loaded) >= {
        TECHNIQUE_RECORD_ID,
        "malware--3c4d5e6f-7a8b-4c9d-0e1f-2a3b4c5d6e7f",
        "tool--5e6f7a8b-9c0d-4e1f-2a3b-4c5d6e7f8a9b",
        "intrusion-set--7a8b9c0d-1e2f-4a3b-5c6d-7e8f9a0b1c2d",
    }
    all_citations: list[UUID] = []
    for document_id, chunks in loaded.values():
        assert chunks, "every persisted document must have indexed chunks"
        assert any(chunk.document_id == document_id for chunk in chunks)
        for chunk in chunks:
            assert chunk.citation_id is not None
            assert chunk.id is not None
            assert chunk.embedding_provider == "hashing"
            assert chunk.embedding_model == "ati-hashing-v1"
            assert chunk.embedding_model_version == 1
            assert chunk.embedding_dimension == 1536
            assert len(chunk.embedding) == 1536
            all_citations.append(chunk.citation_id)
    assert len(set(all_citations)) == len(all_citations)

    technique_document_id = loaded[TECHNIQUE_RECORD_ID][0]
    technique_citations = {
        chunk.citation_id for chunk in loaded[TECHNIQUE_RECORD_ID][1]
    }

    results = await PgVectorResearchRetriever(
        session_factory, HashingEmbeddingClient()
    ).retrieve(
        ResearchQuery(
            investigation_id=UUID("00000000-0000-4000-8000-000000000001"),
            query=DISTINCTIVE_QUERY,
            max_results=3,
        )
    )
    assert results
    top = results[0]
    assert top.document_id == technique_document_id
    assert top.source_record_id == TECHNIQUE_RECORD_ID
    assert top.document_type == "attack_technique"
    assert top.chunk_sequence >= 1
    assert top.citation_id in technique_citations
    assert top.metadata["document_type"] == "attack_technique"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_canonical_same_model_rerun_is_idempotent(
    uow_factory: Callable[[], PostgresUnitOfWork],
    tmp_path: Path,
) -> None:
    """I6: identical embedding identity rerun is a true no-op."""
    _store, _artifact, records = await _ingest_fixture(uow_factory, tmp_path)
    indexing = _indexing_service(uow_factory, HashingEmbeddingClient())
    first = await indexing.index(records)
    assert first.documents_inserted == 4

    second = await indexing.index(records)
    assert (second.documents_unchanged, second.chunks_replaced) == (4, 0)

    loaded = await _documents_with_chunks(uow_factory, records)
    all_citations = [
        chunk.citation_id for _, chunks in loaded.values() for chunk in chunks
    ]
    assert len(set(all_citations)) == len(all_citations)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_canonical_embedding_identity_migration(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """I7: re-indexing under a new embedding identity keeps citations stable."""
    _store, _artifact, records = await _ingest_fixture(uow_factory, tmp_path)
    indexing = _indexing_service(uow_factory, HashingEmbeddingClient())
    first = await indexing.index(records)
    assert first.documents_inserted == 4
    before = await _documents_with_chunks(uow_factory, records)
    original_set = {
        chunk.citation_id for _, chunks in before.values() for chunk in chunks
    }

    migrated = await _indexing_service(uow_factory, _VariantEmbeddingClient()).index(
        records
    )
    assert (migrated.documents_unchanged, migrated.chunks_replaced) == (
        4,
        len(original_set),
    )

    after = await _documents_with_chunks(uow_factory, records)
    migrated_set = {
        chunk.citation_id for _, chunks in after.values() for chunk in chunks
    }
    assert migrated_set == original_set
    for record_id, (document_id, chunks) in after.items():
        assert document_id == before[record_id][0]
        for chunk in chunks:
            assert chunk.embedding_provider == "hashing-variant"
            assert chunk.embedding_model == "ati-variant-v1"
            assert chunk.embedding_model_version == 2

    investigation_id = UUID("00000000-0000-4000-8000-000000000002")
    stale = await PgVectorResearchRetriever(
        session_factory, HashingEmbeddingClient()
    ).retrieve(
        ResearchQuery(
            investigation_id=investigation_id,
            query=DISTINCTIVE_QUERY,
            max_results=3,
        )
    )
    assert stale == []
    current = await PgVectorResearchRetriever(
        session_factory, _VariantEmbeddingClient()
    ).retrieve(
        ResearchQuery(
            investigation_id=investigation_id,
            query=DISTINCTIVE_QUERY,
            max_results=3,
        )
    )
    assert current
    assert current[0].citation_id in original_set
