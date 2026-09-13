# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit idempotent fake-data bootstrap (PR 23D).

The bootstrap is the only path that initializes fake batch data. It is never
invoked by API startup, worker startup, module import, or application
lifespan hooks: local fake deployments orchestrate it once before normal
API/worker use, and ``ATI_OPERATING_MODE=production`` never runs it.

Each packaged batch fixture is materialized into the datasets object store
and ingested through the existing production ``BatchSource`` /
``IngestionService`` persistence path, which owns checkpoint/idempotency
semantics: a completed artifact is a no-op on subsequent runs, so re-running
the bootstrap never creates semantic duplicates. Changed records may be
indexed into the research corpus so fake-mode Research/RAG has useful
context; the configured embedding path (deterministic hashing by default)
is used, never a fake-specific representation.

The bootstrap never invokes live Evidence providers or the LLM.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from agentic_threat_investigator.app.document_indexing import (
    DocumentBuilder,
    DocumentIndexingService,
    TokenBoundedChunker,
)
from agentic_threat_investigator.app.embeddings import EmbeddingClient
from agentic_threat_investigator.app.ingestion import IngestionService
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.sources import ArtifactReference, BatchSource
from agentic_threat_investigator.config.settings import OperatingMode, Settings
from agentic_threat_investigator.infrastructure.embeddings import (
    HashingEmbeddingClient,
    build_openai_embedding_client,
)
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeWorldCatalog,
)
from agentic_threat_investigator.infrastructure.object_store import (
    FileSystemObjectStore,
)
from agentic_threat_investigator.infrastructure.sources.mitre_attack import (
    MitreAttackBatchSource,
)


class FakeDataBootstrapError(RuntimeError):
    """Raised when the fake-data bootstrap cannot complete.

    The message is a fixed safe string that never embeds fixture payloads,
    artifact paths, or configuration values.
    """


@dataclass(frozen=True)
class FakeBatchIngestionSummary:
    """Deterministic aggregate of one fake batch fixture bootstrap."""

    source_id: str
    artifact_uri: str
    inserted: int
    updated: int
    unchanged: int
    complete: bool
    checkpoint: str | None
    documents_indexed: int


@dataclass(frozen=True)
class FakeBootstrapSummary:
    """Aggregate of every fake batch fixture bootstrap."""

    fixtures: tuple[FakeBatchIngestionSummary, ...] = ()

    @property
    def total_records_changed(self) -> int:
        """Return the total inserted+updated records across fixtures."""
        return sum(fixture.inserted + fixture.updated for fixture in self.fixtures)


class FakeDataBootstrap:
    """One-shot idempotent fake batch-data bootstrap over production paths."""

    def __init__(
        self,
        *,
        settings: Settings,
        uow_factory: Callable[[], UnitOfWork],
        catalog: FakeWorldCatalog | None = None,
        object_store: FileSystemObjectStore | None = None,
        embedding_client: EmbeddingClient | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the settings, transaction factory, and optional seams.

        The operating mode is verified at run time, not construction, so the
        bootstrap object can be built and then rejected by mode safely.
        """
        self._settings = settings
        self._uow_factory = uow_factory
        self._catalog = catalog
        self._object_store = object_store
        self._embedding_client = embedding_client
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )

    async def run(self) -> FakeBootstrapSummary:
        """Load, validate, and ingest every fake batch fixture idempotently.

        Raises :class:`FakeDataBootstrapError` on any fixture, parser, or
        persistence failure; a successfully completed prior bootstrap is a
        full no-op. External I/O (artifact reads/writes) stays outside
        database transactions, mirroring production ingestion semantics.
        """
        if self._settings.operating_mode is not OperatingMode.FAKE:
            raise FakeDataBootstrapError(
                "fake-data bootstrap requires ATI_OPERATING_MODE=fake"
            )
        catalog = (
            self._catalog
            if self._catalog is not None
            else FakeWorldCatalog.load_packaged()
        )
        store = (
            self._object_store
            if self._object_store is not None
            else FileSystemObjectStore(self._settings.datasets_dir)
        )
        embedding = (
            self._embedding_client
            if self._embedding_client is not None
            else self._compose_embedding_client()
        )
        summaries: list[FakeBatchIngestionSummary] = []
        for artifact_binding in catalog.batch_artifacts():
            summary = await self._bootstrap_one(
                artifact_binding, store, catalog, embedding
            )
            summaries.append(summary)
        return FakeBootstrapSummary(fixtures=tuple(summaries))

    def _compose_embedding_client(self) -> EmbeddingClient:
        """Compose the configured embedding client (deterministic by default)."""
        embedding_settings = self._settings.embedding
        if embedding_settings.provider == "hashing":
            return HashingEmbeddingClient(embedding_settings.dimension)
        if embedding_settings.provider != "openai":
            raise FakeDataBootstrapError(
                "unsupported fake bootstrap embedding provider"
            )
        from agentic_threat_investigator.app.secrets import EnvVarSecretsResolver

        api_key = EnvVarSecretsResolver().require(embedding_settings.api_key_secret)
        return build_openai_embedding_client(
            model=embedding_settings.model,
            model_version=embedding_settings.model_version,
            dimension=embedding_settings.dimension,
            api_key=api_key,
            timeout_seconds=embedding_settings.timeout_seconds,
        )

    async def _bootstrap_one(
        self,
        artifact_binding: object,
        store: FileSystemObjectStore,
        catalog: FakeWorldCatalog,
        embedding: EmbeddingClient,
    ) -> FakeBatchIngestionSummary:
        """Bootstrap one packaged batch fixture through production paths."""
        from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
            FakeBatchArtifactData,
        )

        if not isinstance(artifact_binding, FakeBatchArtifactData):
            raise FakeDataBootstrapError("invalid fake batch artifact binding")
        content = catalog.load_batch_artifact_bytes(artifact_binding.package_path)
        uri = self._artifact_uri(artifact_binding.dataset_path)
        await store.write(uri, content)
        retrieved_at = self._clock()
        artifact = ArtifactReference(
            source_id=artifact_binding.source_id,
            uri=uri,
            retrieved_at=retrieved_at,
            content_hash=hashlib.sha256(content).hexdigest(),
        )
        source = self._source_for(artifact_binding.source_id, store)
        ingestion = IngestionService(
            self._uow_factory, batch_size=self._settings.db_batch_size
        )
        summary = await ingestion.ingest(source, artifact)
        documents_indexed = 0
        if summary.changed:
            builder = self._document_builder_for(artifact_binding.source_id)
            records = []
            for result in summary.changed:
                async with self._uow_factory() as uow:
                    record = await uow.source_records.get_by_id(result.record_id)
                if (
                    record is not None
                    and record.record_type in builder.document_record_types
                ):
                    records.append(record)
            if records:
                indexing = DocumentIndexingService(
                    self._uow_factory,
                    builder=builder,
                    chunker=TokenBoundedChunker(
                        self._settings.rag_chunk_target_tokens,
                        self._settings.rag_chunk_max_tokens,
                    ),
                    embedding_client=embedding,
                    batch_size=self._settings.db_batch_size,
                    embedding_batch_size=self._settings.embedding_batch_size,
                )
                indexed = await indexing.index(records)
                documents_indexed = indexed.documents_inserted
        return FakeBatchIngestionSummary(
            source_id=artifact_binding.source_id,
            artifact_uri=uri,
            inserted=summary.inserted,
            updated=summary.updated,
            unchanged=summary.unchanged,
            complete=summary.complete,
            checkpoint=summary.checkpoint,
            documents_indexed=documents_indexed,
        )

    def _artifact_uri(self, dataset_path: str) -> str:
        """Build the canonical file URI below the datasets root."""
        datasets_root = Path(self._settings.datasets_dir)
        resolved = datasets_root / dataset_path
        try:
            relative = resolved.resolve().relative_to(datasets_root.resolve())
        except ValueError as exc:
            raise FakeDataBootstrapError(
                "fake artifact path escapes the datasets root"
            ) from exc
        if ".." in relative.parts:
            raise FakeDataBootstrapError("fake artifact path must not traverse")
        return resolved.as_uri()

    @staticmethod
    def _source_for(source_id: str, store: FileSystemObjectStore) -> BatchSource:
        """Return the existing production BatchSource for a fixture source."""
        if source_id == "urn:ati:source:mitre_attack":
            return MitreAttackBatchSource(store, batch_size=100)
        raise FakeDataBootstrapError("unsupported fake batch source")

    @staticmethod
    def _document_builder_for(source_id: str) -> DocumentBuilder:
        """Return the production document builder for a fixture source."""
        from agentic_threat_investigator.infrastructure.sources.mitre_attack_documents import (
            MitreAttackDocumentBuilder,
        )

        if source_id == "urn:ati:source:mitre_attack":
            return MitreAttackDocumentBuilder()
        raise FakeDataBootstrapError("unsupported fake batch source")


async def run_fake_data_bootstrap(
    *,
    settings: Settings,
    uow_factory: Callable[[], UnitOfWork],
) -> FakeBootstrapSummary:
    """Run the one-shot fake-data bootstrap over the composed transaction path.

    This narrow helper exists so the CLI and tests share the same entry
    point without constructing engines themselves.
    """
    bootstrap = FakeDataBootstrap(settings=settings, uow_factory=uow_factory)
    return await bootstrap.run()
