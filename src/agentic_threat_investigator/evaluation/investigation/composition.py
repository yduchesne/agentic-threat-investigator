# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30F narrow evaluation composition seam (end-to-end Investigation target).

Wires the existing production investigation pieces into the evaluation
target without creating any benchmark-only architecture:

```text
production EvidenceAnalyst (existing loader/persistence/accounting seams)
production Research Agent (existing research-agent composition, hashing embeddings)
production LocalInvestigationRunner (production Coordinator graph/policy)
production ReportWriter (existing report-writer composition)
+ one shared CountingLlmClient over the injected LlmClient
```

The shared counting decorator observes the exact current-execution model
call count through the same ``LlmClient`` seam the analyst, Research Agent,
and Report Writer use; it never alters prompts, outputs, retries, or
exceptions. No database transaction ever spans a model call here: every
composed service already keeps its own short transactions.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst import (
    EvidenceAnalyst,
    EvidenceAnalystInputLoader,
    LlmAccountingService,
)
from agentic_threat_investigator.app.llm import LlmClient
from agentic_threat_investigator.app.orchestration.research import (
    ResearchAgentResearchExecutor,
)
from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.app.report_writer.writer import ReportWriter
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.evaluation.report_writer.composition import (
    CountingLlmClient,
)
from agentic_threat_investigator.infrastructure.embeddings import (
    HashingEmbeddingClient,
)
from agentic_threat_investigator.infrastructure.report_writer_composition import (
    build_report_writer,
)
from agentic_threat_investigator.infrastructure.research_agent_composition import (
    build_research_agent,
)


@dataclass(frozen=True)
class InvestigationWorld:
    """One production-composed end-to-end investigation world."""

    runner: LocalInvestigationRunner
    """The production runner bound to the fixture provider registry."""

    analyst: EvidenceAnalyst
    """The production Evidence Analyst (counting client at the model boundary)."""

    research_agent: object
    """The production Research Agent (counting client at the model boundary)."""

    report_writer: ReportWriter
    """The production Report Writer (counting client at the model boundary)."""

    counting: CountingLlmClient
    """The exact per-execution model-call counter shared by every boundary."""


def compose_investigation_world(
    *,
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    llm_client: LlmClient,
    provider_registry: Mapping[SourceId, EvidenceProvider],
    batch_size: int = 100,
    max_structured_output_attempts: int = 2,
    clock: Callable[[], datetime] | None = None,
    recursion_limit: int = 120,
) -> InvestigationWorld:
    """Compose the production investigation world over one injected client.

    The analyst, Research Agent, runner, and Report Writer are exactly the
    production implementations; the only shared boundary is the counting
    decorator over the injected ``LlmClient``. ``clock`` defaults to UTC now
    (tests inject a fixed clock); the recursion bound mirrors the measured
    canonical multi-hop fake-world trajectory (120).
    """
    counting = CountingLlmClient(llm_client)
    analyst = EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(uow_factory),
        llm_client=counting,
        assessment_persistence=AssessmentPersistenceService(
            uow_factory, batch_size=batch_size
        ),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=max_structured_output_attempts,
    )
    research_agent = build_research_agent(
        uow_factory=uow_factory,
        session_factory=session_factory,
        embedding_client=HashingEmbeddingClient(),
        llm_client=counting,
        max_structured_output_attempts=max_structured_output_attempts,
    )
    runner = LocalInvestigationRunner(
        uow_factory=uow_factory,
        provider_registry=provider_registry,
        analysis_executor_factory=lambda bound: EvidenceAnalystAnalysisExecutor(
            analyst, bound_investigation_id=bound
        ),
        research_executor_factory=lambda bound: ResearchAgentResearchExecutor(
            research_agent, bound_investigation_id=bound
        ),
        clock=clock if clock is not None else (lambda: datetime.now(UTC)),
        recursion_limit=recursion_limit,
    )
    report_writer = build_report_writer(
        uow_factory=uow_factory,
        llm_client=counting,
        batch_size=batch_size,
        max_structured_output_attempts=max_structured_output_attempts,
    )
    return InvestigationWorld(
        runner=runner,
        analyst=analyst,
        research_agent=research_agent,
        report_writer=report_writer,
        counting=counting,
    )
