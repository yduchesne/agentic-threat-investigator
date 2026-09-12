# SPDX-License-Identifier: AGPL-3.0-only
"""Production composition seam for the standalone Research Agent (PR 22B).

Wires the existing production research pieces into one :class:`ResearchAgent`:

```text
PgVectorResearchRetriever      (real pgvector retrieval adapter)
ResearchResultPersistenceService (existing PR 22A persistence seam)
LlmAccountingService           (existing Investigation-wide budget)
+ injected LlmClient
        -> ResearchAgent
```

PR 22B deliberately does NOT add the Research Agent to the Coordinator/LangGraph
production graph; this narrow factory exists so PR 22C can obtain a fully
wired service object without knowing pgvector, prompt, model-provider, or
research-repository details.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.embeddings import EmbeddingClient
from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.llm import LlmClient
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
from agentic_threat_investigator.app.research_persistence import (
    ResearchResultPersistenceService,
)
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)


def build_research_agent(
    *,
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    embedding_client: EmbeddingClient,
    llm_client: LlmClient,
    max_structured_output_attempts: int = 2,
) -> ResearchAgent:
    """Assemble a fully wired ResearchAgent from its production seams.

    ``uow_factory`` supplies both the short result-persistence transaction and
    the short durable LLM-budget reservation; ``session_factory`` and
    ``embedding_client`` drive the real pgvector retriever; ``llm_client`` is
    the existing injected structured-output client. No global state is
    created and no reading of environment/configuration happens here.
    """
    retriever = PgVectorResearchRetriever(session_factory, embedding_client)
    return ResearchAgent(
        retriever=retriever,
        llm_client=llm_client,
        result_persistence=ResearchResultPersistenceService(uow_factory),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=max_structured_output_attempts,
    )
