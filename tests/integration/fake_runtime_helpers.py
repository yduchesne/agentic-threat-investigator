# SPDX-License-Identifier: AGPL-3.0-only
"""Shared helpers for the PR 23D fake-mode PostgreSQL integration tests.

Composes the production investigation path over real PostgreSQL with the
packaged deterministic fake intelligence sources and ``FakeLlmClient`` at
the model boundary only. Everything else — provider planning, the provider
executor, the coordinator graph, the runner, extraction, persistence, the
Research Agent, and the worker — is the real production implementation.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.evidence_analyst.analyst import EvidenceAnalyst
from agentic_threat_investigator.app.evidence_analyst.loader import (
    EvidenceAnalystInputLoader,
)
from agentic_threat_investigator.app.investigation_worker import (
    InvestigationJobWorker,
)
from agentic_threat_investigator.app.orchestration.research import (
    ResearchAgentResearchExecutor,
)
from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.config import OperatingMode, Settings
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeWorldCatalog,
)
from agentic_threat_investigator.infrastructure.intelligence_composition import (
    build_fake_intelligence_sources,
)
from agentic_threat_investigator.infrastructure.research_agent_composition import (
    build_research_agent,
)
from tests.support.llm_fixtures import FakeLlmClient

FIXED_TS = datetime(2026, 6, 1, tzinfo=UTC)
"""Shared deterministic retrieval clock for fake-mode integration tests."""


def build_fake_mode_runner(
    uow_factory: Callable[[], Any],
    session_factory: Any,
    *,
    clock: datetime = FIXED_TS,
    catalog: FakeWorldCatalog | None = None,
    recursion_limit: int = 120,
) -> tuple[LocalInvestigationRunner, FakeLlmClient]:
    """Compose the production runner over fake sources and FakeLlmClient.

    Returns the runner and the scripted LLM client so tests can enqueue
    deterministic analysis/research decisions before invoking the worker.
    The recursion limit is deliberately generous: multi-pivot scenarios
    traverse more graph nodes than the canonical two-provider trajectory
    whose measured value (40) is the runner default.
    """
    llm = FakeLlmClient()
    analyst = EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(uow_factory),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            uow_factory, batch_size=100
        ),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=2,
    )
    research_agent = build_research_agent(
        uow_factory=uow_factory,
        session_factory=session_factory,
        embedding_client=HashingEmbeddingClient(1536),
        llm_client=llm,
        max_structured_output_attempts=2,
    )
    sources = build_fake_intelligence_sources(
        Settings(operating_mode=OperatingMode.FAKE),
        catalog=catalog or FakeWorldCatalog.load_packaged(),
        clock=lambda: clock,
    )
    runner = LocalInvestigationRunner(
        uow_factory=uow_factory,
        provider_registry=sources.provider_registry,
        analysis_executor_factory=lambda bound: EvidenceAnalystAnalysisExecutor(
            analyst, bound_investigation_id=bound
        ),
        research_executor_factory=lambda bound: ResearchAgentResearchExecutor(
            research_agent, bound_investigation_id=bound
        ),
        clock=lambda: clock,
        recursion_limit=recursion_limit,
    )
    return runner, llm


def build_fake_mode_worker(
    uow_factory: Callable[[], Any],
    session_factory: Any,
    *,
    clock: datetime = FIXED_TS,
) -> tuple[InvestigationJobWorker, FakeLlmClient]:
    """Compose a durable worker over the fake-mode runner and FakeLlmClient."""
    runner, llm = build_fake_mode_runner(uow_factory, session_factory, clock=clock)
    worker = InvestigationJobWorker(
        uow_factory=uow_factory, runner=runner, clock=lambda: clock
    )
    return worker, llm


def analysis_decision(
    *,
    verdict: str = "suspicious",
    confidence: str = "medium",
    disposition: str = "needs_more_evidence",
    summary: str = "synthetic deterministic analysis",
) -> Any:
    """Build one scripted EvidenceAnalystDecision for the FakeLlmClient."""
    from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
    from agentic_threat_investigator.domain.assessment import (
        AssessmentConfidence,
        Verdict,
    )
    from agentic_threat_investigator.domain.investigation import AnalysisDisposition

    return EvidenceAnalystDecision(
        verdict=Verdict(verdict),
        confidence=AssessmentConfidence(confidence),
        summary=summary,
        disposition=AnalysisDisposition(disposition),
    )
