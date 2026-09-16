# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic bounded research retrieval regression (corrective PR).

The production ``PgVectorResearchRetriever`` orders by vector distance first
and the stable unique chunk identity second, so equal-distance rows have a
total order and bounded top-N membership cannot vary across otherwise
identical executions. These slices make the tie *intentional* (three chunks
rendered from identical indexed text always share one embedding vector) and
pin the contractual behavior through the production persistence/indexing/
pgvector path:

* RDET-01 — distinct distances preserve ranking (the tie-break never
  reorders a closer chunk behind a tied group).
* RDET-02 — equal-distance chunks follow the stable unique chunk key.
* RDET-03 — a tie crossing the ``LIMIT`` boundary has deterministic top-N
  membership.
* RDET-04 — repeated identical retrieval returns identical ordered IDs.
* RDET-05 — filters retain the deterministic ordering inside the eligible
  set.

No embedding algorithm, distance metric, ``max_results``, schema, or
citation-validation behavior is changed here.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.domain.research import (
    ResearchQuery,
    RetrievedChunk,
)
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)
from tests.integration.test_research_agent import _index, _ingest_fixture

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

TIE_FIXTURE = Path("tests/fixtures/mitre_attack/enterprise_attack_tie_small.json")
# The three tied records render byte-identical documents (same name,
# description, attack id, URL, and platform/flags), so their chunks share one
# embedding vector and therefore one exact vector distance for any query.
TIED_RECORDS = {
    "attack-pattern--1a2b3c4d-1001-4001-8001-000000000001",
    "attack-pattern--1a2b3c4d-1001-4001-8001-000000000002",
    "attack-pattern--1a2b3c4d-1001-4001-8001-000000000003",
}
DISTINCTIVE_RECORD = "attack-pattern--1a2b3c4d-1001-4001-8001-000000000004"
PARTIAL_RECORD = "attack-pattern--1a2b3c4d-1001-4001-8001-000000000005"
SOFTWARE_RECORD = "tool--5e6f7a8b-9c0d-4e1f-2a3b-4c5d6e7f8a9c"

QUERY_DISTINCTIVE = "obfuscate command-and-control traffic conceal exfiltrated data"
QUERY_TIED = "synthetic software tool credential access fixture text"


async def _indexed_tie_corpus(
    uow_factory: Callable[[], PostgresUnitOfWork], tmp_path: Path
) -> None:
    """Ingest and index the intentional-tie fixture through production paths."""
    records = await _ingest_fixture(uow_factory, tmp_path, fixture=TIE_FIXTURE)
    await _index(records, uow_factory)


async def _retrieve(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    query: str,
    max_results: int = 100,
    document_types: tuple[str, ...] | None = None,
) -> list[RetrievedChunk]:
    """Execute one bounded production pgvector retrieval."""
    retriever = PgVectorResearchRetriever(session_factory, HashingEmbeddingClient())
    return await retriever.retrieve(
        ResearchQuery(
            investigation_id=uuid4(),
            query=query,
            document_types=list(document_types) if document_types else [],
            max_results=max_results,
        )
    )


def _tied_chunks(chunks: list[RetrievedChunk]) -> list[RetrievedChunk]:
    """Return the chunk IDs of the intentional tie group in retrieval order."""
    return [chunk for chunk in chunks if chunk.source_record_id in TIED_RECORDS]


def _tied_ids_sorted_by_unique_key(chunks: list[RetrievedChunk]) -> list[UUID]:
    """Return the stable unique-key ascending order of the tie group."""
    return [chunk.chunk_id for chunk in sorted(chunks, key=lambda item: item.chunk_id)]


async def test_rdet01_distinct_distances_preserve_ranking(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RDET-01: vector distance stays primary when distances differ."""
    await _indexed_tie_corpus(uow_factory, tmp_path)
    chunks = await _retrieve(session_factory, query=QUERY_DISTINCTIVE)
    assert len(chunks) == 6
    # The distinctive record resolves all query words; the partial record a
    # strict subset; every remaining chunk is orthogonal (distance 1.0).
    assert chunks[0].source_record_id == DISTINCTIVE_RECORD
    assert chunks[1].source_record_id == PARTIAL_RECORD
    scores = [chunk.similarity_score for chunk in chunks[:3]]
    first, second, third = scores
    assert first is not None and second is not None and third is not None
    assert first > second > third, scores
    # The secondary key is irrelevant across unequal distances: even though
    # the tie group's chunk IDs are arbitrary, no tied chunk may precede a
    # strictly closer chunk.
    assert {chunk.source_record_id for chunk in chunks[2:]} == (
        TIED_RECORDS | {SOFTWARE_RECORD}
    )


async def test_rdet02_equal_distance_stable_order(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RDET-02: exact ties follow the stable unique chunk key."""
    await _indexed_tie_corpus(uow_factory, tmp_path)
    chunks = await _retrieve(session_factory, query=QUERY_TIED, max_results=3)
    tied = _tied_chunks(chunks)
    assert len(tied) == 3
    assert all(
        tied[index].similarity_score == tied[0].similarity_score
        for index in range(1, len(tied))
    ), "the tie must be exact"
    assert [chunk.chunk_id for chunk in tied] == _tied_ids_sorted_by_unique_key(tied)


async def test_rdet03_tie_crossing_limit_is_deterministic(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RDET-03: a tie crossing LIMIT yields deterministic top-N membership."""
    await _indexed_tie_corpus(uow_factory, tmp_path)
    # max_results + 1 = 3 tied rows compete for 2 slots: the two chunks with
    # the lowest stable unique key must be selected, and the third excluded.
    chunks = await _retrieve(session_factory, query=QUERY_TIED, max_results=2)
    assert len(chunks) == 2
    tied = _tied_chunks(chunks)
    assert len(tied) == 2
    expected = _tied_ids_sorted_by_unique_key(tied)[:2]
    assert [chunk.chunk_id for chunk in tied] == expected
    all_tied = {
        chunk.chunk_id
        for chunk in await _retrieve(session_factory, query=QUERY_TIED)
        if chunk.source_record_id in TIED_RECORDS
    }
    excluded = sorted(all_tied - set(expected))
    assert len(excluded) == 1
    # The excluded chunk is the highest stable unique key in the tie group.
    assert excluded[0] == sorted(all_tied)[-1]


async def test_rdet04_repeated_retrieval_is_identical(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RDET-04: repeated identical queries return identical ordered IDs."""
    await _indexed_tie_corpus(uow_factory, tmp_path)
    first = await _retrieve(session_factory, query=QUERY_TIED, max_results=3)
    first_ids = tuple(chunk.chunk_id for chunk in first)
    for _ in range(5):
        again = await _retrieve(session_factory, query=QUERY_TIED, max_results=3)
        assert tuple(chunk.chunk_id for chunk in again) == first_ids
    first_wide = await _retrieve(
        session_factory, query=QUERY_DISTINCTIVE, max_results=6
    )
    first_wide_ids = tuple(chunk.chunk_id for chunk in first_wide)
    assert len(first_wide_ids) == 6
    for _ in range(5):
        again = await _retrieve(session_factory, query=QUERY_DISTINCTIVE, max_results=6)
        assert tuple(chunk.chunk_id for chunk in again) == first_wide_ids


async def test_rdet05_filters_retain_deterministic_order(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RDET-05: filtered eligible sets keep the deterministic ordering."""
    await _indexed_tie_corpus(uow_factory, tmp_path)
    techniques = await _retrieve(
        session_factory,
        query=QUERY_TIED,
        max_results=3,
        document_types=("attack_technique",),
    )
    tied = _tied_chunks(techniques)
    assert len(techniques) == 3 and len(tied) == 3
    assert [chunk.chunk_id for chunk in tied] == _tied_ids_sorted_by_unique_key(tied)
    software = await _retrieve(
        session_factory,
        query=QUERY_TIED,
        max_results=100,
        document_types=("attack_software",),
    )
    assert [chunk.source_record_id for chunk in software] == [SOFTWARE_RECORD]
    # Same distinctive query, technique filter: identical order as unfiltered
    # minus the excluded software chunk, tie group still id-ascending.
    filtered = await _retrieve(
        session_factory,
        query=QUERY_DISTINCTIVE,
        max_results=5,
        document_types=("attack_technique",),
    )
    assert [chunk.source_record_id for chunk in filtered] == [
        DISTINCTIVE_RECORD,
        PARTIAL_RECORD,
        *[
            chunk.source_record_id
            for chunk in sorted(
                (chunk for chunk in filtered if chunk.source_record_id in TIED_RECORDS),
                key=lambda item: item.chunk_id,
            )
        ],
    ]
    assert all(chunk.source_record_id != SOFTWARE_RECORD for chunk in filtered)
