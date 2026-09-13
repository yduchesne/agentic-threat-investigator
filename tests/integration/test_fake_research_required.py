# SPDX-License-Identifier: AGPL-3.0-only
"""F04 research-required integration test (PR 23D).

The researchable attack-technique root ``T1566.001`` drives the coordinator
research lifecycle: no live provider supports ATTACK_TECHNIQUE, so the
investigation reaches ``REQUEST_RESEARCH``, the real Research Agent executes
against the indexed MITRE corpus, and a contextual ``ResearchResult`` is
persisted — with useful (claim-carrying) material that stays epistemically
separate from Evidence (no Evidence rows are ever created).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.config import OperatingMode, Settings
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.research import ResearchQuery
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
)
from agentic_threat_investigator.infrastructure.bootstrap import FakeDataBootstrap
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)
from tests.integration.fake_runtime_helpers import build_fake_mode_runner

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

F04_TECHNIQUE = "T1566.001"
F04_OBJECTIVE = "assess the spearphishing attachment technique context"
CLOCK = datetime(2026, 6, 1, tzinfo=UTC)


async def _index_mitre_corpus(
    uow_factory: Callable[[], UnitOfWork], tmp_path: Path
) -> None:
    """Ingest and index the packaged MITRE fixture through the real bootstrap."""
    settings = Settings(operating_mode=OperatingMode.FAKE, data_dir=tmp_path)
    bootstrap = FakeDataBootstrap(settings=settings, uow_factory=uow_factory)
    summary = await bootstrap.run()
    assert summary.fixtures
    assert summary.total_records_changed >= 1


async def test_f04_research_required_executes_real_research_path(
    uow_factory: Callable[[], Any],
    session_factory: Any,
    tmp_path: Path,
) -> None:
    """The coordinator research lifecycle persists contextual research only."""
    await _index_mitre_corpus(uow_factory, tmp_path)

    investigation_id = uuid4()
    root_id = uuid4()
    async with uow_factory() as uow:
        written = await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.ATTACK_TECHNIQUE, value=F04_TECHNIQUE)
        )
        durable_root_id = written.id if written.id is not None else root_id
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.API,
                root_entity_ids=[durable_root_id],
                objective=F04_OBJECTIVE,
                budget=default_investigation_budget(),
                started_at=CLOCK,
                created_at=CLOCK,
            )
        )
        await uow.commit()

    # Deterministically derive the chunks the real retriever will present to
    # the model, then script a claim citing the first chunk's citation id.
    retriever = PgVectorResearchRetriever(session_factory, HashingEmbeddingClient(1536))
    query = ResearchQuery(
        investigation_id=investigation_id,
        query=(
            f"Provide contextual threat-research information about "
            f'attack_technique "{F04_TECHNIQUE}" that is relevant to this '
            f"investigation objective: {F04_OBJECTIVE}"
        ),
        entity_ids=[],
        source_ids=[],
        document_types=[],
        max_results=8,
    )
    chunks = tuple(await retriever.retrieve(query))
    assert chunks

    runner, llm = build_fake_mode_runner(uow_factory, session_factory, clock=CLOCK)
    llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="Spearphishing attachments are a documented delivery "
                    "technique in the ATT&CK corpus.",
                    citation_ids=(chunks[0].citation_id,),
                ),
            ),
        )
    )
    terminal = await runner.run(investigation_id)
    assert terminal.status is InvestigationStatus.COMPLETED

    async with uow_factory() as uow:
        results = await uow.research_results.list_by_investigation(investigation_id)
        evidence = await uow.evidence.list_for_investigation(
            investigation_id, limit=100
        )
    assert len(results) == 1
    assert results[0].claims
    assert results[0].claims[0].citation_ids
    # Research remains Research: no Evidence row was created for the root.
    assert evidence == []


async def test_f04_unknown_technique_has_deterministic_bounded_research(
    uow_factory: Callable[[], Any],
    session_factory: Any,
    tmp_path: Path,
) -> None:
    """A technique outside the corpus still persists a bounded research result."""
    del tmp_path
    investigation_id = uuid4()
    root_id = uuid4()
    async with uow_factory() as uow:
        written = await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.ATTACK_TECHNIQUE, value="T9999")
        )
        durable_root_id = written.id if written.id is not None else root_id
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.API,
                root_entity_ids=[durable_root_id],
                objective="assess an uncatalogued technique",
                budget=default_investigation_budget(),
                started_at=CLOCK,
                created_at=CLOCK,
            )
        )
        await uow.commit()
    runner, llm = build_fake_mode_runner(uow_factory, session_factory, clock=CLOCK)
    llm.set_default(ResearchAgentDecision(claims=()))
    terminal = await runner.run(investigation_id)
    assert terminal.status is InvestigationStatus.COMPLETED
    async with uow_factory() as uow:
        results = await uow.research_results.list_by_investigation(investigation_id)
    assert len(results) == 1
