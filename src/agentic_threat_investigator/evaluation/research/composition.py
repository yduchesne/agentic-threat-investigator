# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Research world composition (production retriever/agent/persistence).

Repository-owned helpers that bind the **production** Research runtime to the
PR 30 target/dispatch layers:

- :class:`RecordingResearchRetriever` observes the exact ordered chunks the
  production retriever supplies to the Research Agent (never a second probe
  retrieval);
- :func:`load_epistemic_snapshot` captures promotion-sensitive identity sets
  immediately before/after an isolated research interval;
- :func:`seed_research_anchors` persists the run-scoped Investigation and
  subject Entity a synthesis execution needs;
- :func:`bootstrap_research_corpus` ingests and indexes the repository-owned
  MITRE ATT&CK fixture world through the production ingestion/indexing
  services (deterministic hashing embeddings; no live web).

No evaluator, LLM, or LangSmith behavior is implemented here.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid5

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.document_indexing import (
    DocumentIndexingService,
    TokenBoundedChunker,
)
from agentic_threat_investigator.app.embeddings import EmbeddingClient
from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.ingestion import IngestionService
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.research import ResearchRetriever
from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
from agentic_threat_investigator.app.research_persistence import (
    ResearchResultPersistenceService,
)
from agentic_threat_investigator.app.sources import ArtifactReference
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.research import (
    ResearchQuery,
    RetrievedChunk,
)
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.evaluation.research.models import (
    ResearchEpistemicSnapshot,
    ResearchRetrievalScenario,
    ResearchSynthesisScenario,
)
from agentic_threat_investigator.infrastructure.embeddings import (
    HashingEmbeddingClient,
)
from agentic_threat_investigator.infrastructure.object_store import (
    FileSystemObjectStore,
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

_RETRIEVED_AT = datetime(2026, 1, 15, tzinfo=UTC)
"""Fixed timestamp of the repository-owned research corpus ingestion."""

_CORPUS_NAMESPACE = UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
"""Stable namespace for run-scoped research anchor identities."""

REPOSITORY_RESEARCH_FIXTURES: dict[str, Path] = {
    "mitre-attack-small": Path(
        "tests/fixtures/mitre_attack/enterprise_attack_small.json"
    ),
    "mitre-attack-contradiction": Path(
        "tests/fixtures/mitre_attack/enterprise_contradiction_small.json"
    ),
    "mitre-attack-hostile": Path(
        "tests/fixtures/mitre_attack/enterprise_attack_hostile_small.json"
    ),
}
"""Repository-owned fixture corpus files keyed by scenario fixture name."""


class RecordingResearchRetriever(ResearchRetriever):
    """Observation wrapper delegating exactly to the production retriever.

    Every call is forwarded unchanged to the wrapped retriever and its
    returned values are recorded in order. Nothing is altered or filtered:
    the wrapper exists so evaluation can prove the exact chunks supplied to
    the model were the chunks the production retrieval returned.
    """

    def __init__(self, inner: ResearchRetriever) -> None:
        """Bind the production retriever and an empty call log."""
        self._inner = inner
        self.calls: list[list[RetrievedChunk]] = []

    async def retrieve(self, query: ResearchQuery) -> list[RetrievedChunk]:
        """Delegate to the production retriever and record the response."""
        chunks = await self._inner.retrieve(query)
        self.calls.append(list(chunks))
        return chunks

    @property
    def supplied_citation_ids(self) -> tuple[UUID, ...]:
        """Return the recorded citation IDs of the most recent retrieval."""
        if not self.calls:
            return ()
        return tuple(chunk.citation_id for chunk in self.calls[-1])


def research_query(
    *,
    investigation_id: UUID,
    query: str,
    source_ids: tuple[str, ...],
    document_types: tuple[str, ...],
    max_results: int,
) -> ResearchQuery:
    """Build one bounded production retrieval query from scenario fields."""
    return ResearchQuery(
        investigation_id=investigation_id,
        query=query,
        source_ids=list(source_ids),
        document_types=list(document_types),
        max_results=max_results,
    )


def retrieval_query(
    scenario: ResearchRetrievalScenario, *, investigation_id: UUID
) -> ResearchQuery:
    """Map one retrieval scenario onto the production retrieval query."""
    return research_query(
        investigation_id=investigation_id,
        query=scenario.query,
        source_ids=scenario.source_ids,
        document_types=scenario.document_types,
        max_results=scenario.max_results,
    )


def synthesis_query(
    scenario: ResearchSynthesisScenario, *, investigation_id: UUID
) -> ResearchQuery:
    """Map one synthesis scenario onto the production retrieval query."""
    return research_query(
        investigation_id=investigation_id,
        query=scenario.query,
        source_ids=scenario.source_ids,
        document_types=scenario.document_types,
        max_results=scenario.max_results,
    )


def scenario_anchor_ids(
    *, case_id: str, version: int, execution_id: UUID
) -> tuple[UUID, UUID]:
    """Return deterministic run-scoped (investigation, subject) anchor ids.

    The execution identity makes repeated runs isolated while keeping one
    case execution deterministic and never colliding with other cases.
    """
    namespace = uuid5(_CORPUS_NAMESPACE, f"{case_id}@v{version}:{execution_id}")
    return uuid5(namespace, "investigation"), uuid5(namespace, "subject")


async def seed_research_anchors(
    uow_factory: Callable[[], UnitOfWork],
    *,
    investigation_id: UUID,
    subject_entity_id: UUID,
) -> None:
    """Persist the run-scoped Investigation and subject Entity once."""
    async with uow_factory() as uow:
        await uow.entities.upsert(
            # Anchor-unique canonical value: ``example.test`` would be reused
            # under an earlier execution's identity by the canonical upsert,
            # breaking the run-scoped anchor invariant.
            Entity(
                id=subject_entity_id,
                type=EntityType.DOMAIN,
                value=f"anchor-{subject_entity_id}",
            )
        )
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[subject_entity_id],
                objective="Explain the contextual research question.",
                budget=default_investigation_budget(),
                started_at=_RETRIEVED_AT,
            )
        )


async def load_epistemic_snapshot(
    uow_factory: Callable[[], UnitOfWork], investigation_id: UUID
) -> ResearchEpistemicSnapshot:
    """Capture promotion-sensitive identities through one short UnitOfWork."""
    async with uow_factory() as uow:
        evidence = await uow.evidence.list_for_investigation(
            investigation_id, limit=1000
        )
        observations = await uow.relationship_observations.list_for_investigation(
            investigation_id, limit=1000
        )
        assessments = await uow.assessments.list_for_investigation(
            investigation_id, limit=1000
        )
    evidence_ids = tuple(sorted(item.id for item in evidence if item.id is not None))
    observation_ids = tuple(sorted(item.id for item in observations))
    assessment_ids = tuple(
        sorted(
            (item.id, item.version or -1) for item in assessments if item.id is not None
        )
    )
    return ResearchEpistemicSnapshot(
        evidence_ids=evidence_ids,
        relationship_observation_ids=observation_ids,
        assessment_identities=assessment_ids,
    )


@dataclass(frozen=True)
class ResearchWorld:
    """One production-composed Research world bound to the injection seams."""

    agent: ResearchAgent
    """The production Research Agent (LLM boundary supplied by the caller)."""

    retriever: RecordingResearchRetriever
    """The observing wrapper proving exact supplied citations."""

    session_factory: async_sessionmaker[AsyncSession]
    """The session factory the retriever and agent share."""


def build_research_world(
    *,
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    embedding_client: EmbeddingClient,
    llm_client: object,
    max_structured_output_attempts: int = 2,
) -> ResearchWorld:
    """Build the production Research Agent behind an observing retriever.

    ``llm_client`` is any :class:`LlmClient` implementation (real model or a
    deterministic fake at the model boundary); no evaluation-specific agent
    or LLM abstraction exists.
    """
    recording = RecordingResearchRetriever(
        PgVectorResearchRetriever(session_factory, embedding_client)
    )
    agent = ResearchAgent(
        retriever=recording,
        llm_client=llm_client,  # type: ignore[arg-type]
        result_persistence=ResearchResultPersistenceService(uow_factory),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=max_structured_output_attempts,
    )
    return ResearchWorld(
        agent=agent,
        retriever=recording,
        session_factory=session_factory,
    )


async def bootstrap_research_corpus(
    uow_factory: Callable[[], UnitOfWork],
    *,
    data_dir: Path,
    fixture_files: Sequence[Path],
    batch_size: int = 20,
) -> int:
    """Ingest and index repository-owned research fixtures idempotently.

    Returns the number of documents indexed. Uses production ingestion/
    indexing services with the deterministic hashing embedding path; no
    external corpus is ever downloaded. Removing/editing an upstream fixture
    is a deterministic corpus change, never a live fetch.
    """
    store = FileSystemObjectStore(data_dir)
    indexed_documents = 0
    for index, fixture_path in enumerate(fixture_files):
        uri = f"file://{data_dir.resolve() / f'datasets/mitre/{index}.json'}"
        await store.write(uri, fixture_path.read_bytes())
        artifact = ArtifactReference(
            source_id="urn:ati:source:mitre_attack",
            uri=uri,
            retrieved_at=_RETRIEVED_AT,
        )
        ingestion = IngestionService(uow_factory, batch_size=batch_size)
        result = await ingestion.ingest(
            MitreAttackBatchSource(store, batch_size=batch_size), artifact
        )
        records = await _document_records(uow_factory, result.changed)
        await _index_records(uow_factory, records, batch_size=batch_size)
        indexed_documents += len(records)
    return indexed_documents


async def _document_records(
    uow_factory: Callable[[], UnitOfWork], changed: Sequence[object]
) -> list[SourceRecord]:
    """Return the persisted records the MITRE document builder supports."""
    builder = MitreAttackDocumentBuilder()
    records: list[SourceRecord] = []
    async with uow_factory() as uow:
        for result_item in changed:
            record_id = getattr(result_item, "record_id", None)
            if not isinstance(record_id, UUID):
                continue
            record = await uow.source_records.get_by_id(record_id)
            if (
                record is not None
                and record.record_type in builder.document_record_types
            ):
                records.append(record)
    return records


async def _index_records(
    uow_factory: Callable[[], UnitOfWork],
    records: Sequence[SourceRecord],
    *,
    batch_size: int,
) -> None:
    """Index persisted records through the production indexing service."""
    indexing = DocumentIndexingService(
        uow_factory,
        MitreAttackDocumentBuilder(),
        TokenBoundedChunker(400, 800),
        HashingEmbeddingClient(),
        batch_size=batch_size,
        embedding_batch_size=4,
    )
    await indexing.index(records)
