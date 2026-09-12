# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical PR 22D real-format retrieval evaluation slice (22D-I01).

Layer-2 retrieval evaluation: the repository-owned retrieval scenarios run
against the complete production path — real-format MITRE ATT&CK STIX
fixture, production parser/document builder, ``DocumentIndexingService``,
real PostgreSQL/pgvector, and ``PgVectorResearchRetriever`` — and the
deterministic ``ResearchRetrievalEvaluator`` consumes the ordered response.
One scenario declares a deliberately failing expectation to prove that a
structurally successful retrieval can fail the baseline.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.domain.research import ResearchQuery, RetrievedChunk
from agentic_threat_investigator.evaluation.research import (
    ResearchRetrievalEvaluator,
    ResearchRetrievalFailureCode,
    ResearchRetrievalScenario,
    load_retrieval_scenarios_directory,
)
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)
from tests.integration.test_research_agent import FIXTURE, _index, _ingest_fixture

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_CORPUS = Path(__file__).parents[2] / "evals/scenarios/research/retrieval"


async def _indexed_corpus(
    uow_factory: Callable[[], PostgresUnitOfWork],
    tmp_path: Path,
) -> None:
    """Ingest and index the real-format ATT&CK fixture."""
    records = await _ingest_fixture(uow_factory, tmp_path, fixture=FIXTURE)
    await _index(records, uow_factory)


async def _retrieve(
    session_factory: async_sessionmaker[AsyncSession],
    scenario: ResearchRetrievalScenario,
) -> list[RetrievedChunk]:
    """Run the production pgvector retriever for one scenario."""
    retriever = PgVectorResearchRetriever(session_factory, HashingEmbeddingClient())
    return await retriever.retrieve(
        ResearchQuery(
            investigation_id=uuid4(),
            query=scenario.query,
            source_ids=list(scenario.source_ids),
            document_types=list(scenario.document_types),
            max_results=scenario.max_results,
        )
    )


async def test_i01_real_format_retrieval_evaluation_passes(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """22D-I01: every passing real-format scenario evaluates green."""
    await _indexed_corpus(uow_factory, tmp_path)
    evaluator = ResearchRetrievalEvaluator()
    scenarios = load_retrieval_scenarios_directory(_CORPUS)
    passing = [
        item for item in scenarios if item.id != "real-mitre-forbidden-technique"
    ]
    assert len(passing) == 4
    for scenario in passing:
        chunks = await _retrieve(session_factory, scenario)
        result = evaluator.evaluate(scenario=scenario, chunks=chunks)
        assert result.passed, (scenario.id, result.failures, result.metrics)

    by_id = {scenario.id: scenario for scenario in scenarios}
    technique = by_id["real-mitre-technique-relevant"]
    technique_chunks = await _retrieve(session_factory, technique)
    result = evaluator.evaluate(scenario=technique, chunks=technique_chunks)
    assert result.metrics.recall_at_k == pytest.approx(1.0)
    assert result.metrics.mrr == pytest.approx(1.0)
    assert result.metrics.expected_source_rank == 1
    assert result.metrics.precision_at_k == pytest.approx(1 / 3)

    software = by_id["real-mitre-software-filter"]
    software_chunks = await _retrieve(session_factory, software)
    result = evaluator.evaluate(scenario=software, chunks=software_chunks)
    assert result.metrics.recall_at_k == pytest.approx(1.0)
    assert result.metrics.precision_at_k == pytest.approx(1.0)
    assert result.metrics.mrr == pytest.approx(1.0)
    assert len(software_chunks) == 2

    gap = by_id["real-mitre-retrieval-gap"]
    gap_chunks = await _retrieve(session_factory, gap)
    result = evaluator.evaluate(scenario=gap, chunks=gap_chunks)
    assert result.passed, result.failures
    assert result.metrics.recall_at_k == pytest.approx(1.0)
    assert result.metrics.precision_at_k == pytest.approx(1.0)
    assert result.metrics.mrr is None


async def test_i01b_deliberately_failing_expectation_fails_baseline(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """A structurally successful retrieval can fail the evaluation baseline."""
    await _indexed_corpus(uow_factory, tmp_path)
    scenario = next(
        item
        for item in load_retrieval_scenarios_directory(_CORPUS)
        if item.id == "real-mitre-forbidden-technique"
    )
    chunks = await _retrieve(session_factory, scenario)
    assert chunks, "the retrieval itself is structurally successful"
    result = ResearchRetrievalEvaluator().evaluate(scenario=scenario, chunks=chunks)
    assert not result.passed
    assert result.failures == (ResearchRetrievalFailureCode.FORBIDDEN_RECORD_RETRIEVED,)
