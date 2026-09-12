# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the production Research Agent composition seam (PR 22B)."""

from typing import cast

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.embeddings import EmbeddingClient
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)
from agentic_threat_investigator.infrastructure.research_agent_composition import (
    build_research_agent,
)
from tests.support.llm_fixtures import FakeLlmClient


def _session_factory() -> async_sessionmaker[AsyncSession]:
    """Return a static-typed session factory without binding a real engine."""
    return cast(async_sessionmaker[AsyncSession], object())


def _empty_uow_factory() -> UnitOfWork:
    """Satisfy the composition signature with an unusable boundary."""

    raise AssertionError("composition must not open a UnitOfWork")


def test_composition_wires_the_production_research_agent() -> None:
    """The factory assembles real retriever + persistence/accounting seams."""
    agent = build_research_agent(
        uow_factory=_empty_uow_factory,
        session_factory=_session_factory(),
        embedding_client=cast(EmbeddingClient, object()),
        llm_client=FakeLlmClient(),
        max_structured_output_attempts=2,
    )

    assert isinstance(agent, ResearchAgent)
    assert isinstance(agent._retriever, PgVectorResearchRetriever)


def test_composition_forwards_attempt_bounds() -> None:
    """The bounded attempt policy forwards through the composition seam."""
    for invalid in (0, 3):
        with pytest.raises(ValueError, match="1..2"):
            build_research_agent(
                uow_factory=_empty_uow_factory,
                session_factory=_session_factory(),
                embedding_client=cast(EmbeddingClient, object()),
                llm_client=FakeLlmClient(),
                max_structured_output_attempts=invalid,
            )
