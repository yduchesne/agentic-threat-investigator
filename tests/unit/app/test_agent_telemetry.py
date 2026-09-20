# SPDX-License-Identifier: AGPL-3.0-only
"""Agent/report LLM-observation tests (PR 29B, A1..A5).

Proves that every agent uses the common observed ``LlmClient`` so each
actual model attempt produces exactly one OTel ``ati.llm.invoke`` span and
one selected backend observation: empty ResearchAgent retrieval has zero
model calls, a normal synthesis has one, and a bounded repair has exactly
two; the Evidence Analyst and the Report Writer use the same common seam.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from opentelemetry.sdk.metrics.export import Metric

from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.llm_observability import (
    LlmObservability,
    LlmObservation,
    ObservedLlmClient,
)
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.llm_fixtures import FakeLlmClient
from tests.support.otel import histogram_count, metrics_by_name
from tests.support.report_writer_unit import ReportWriterUnitWorld
from tests.unit.app.research_agent.test_agent import (
    FakeResearchRetriever,
    ResearchWorld,
    _AccountingInvestigationRepository,
    _AccountingUow,
    _claim,
    _decision,
    _PersistenceUow,
    _ResearchResults,
)
from tests.unit.app.test_evidence_analyst import (
    AnalysisWorld,
    FakeAccountingInvestigationRepository,
    FakeAccountingUnitOfWork,
    FakeAssessmentRepository,
    FakeAuditRepository,
    FakeInvestigationRepository,
    FakeLoader,
    FakePersistenceUnitOfWork,
)
from tests.unit.app.test_report_writer import (
    FakeAccounting,
)
from tests.unit.app.test_report_writer import (
    FakeLoader as ReportFakeLoader,
)
from tests.unit.app.test_report_writer import (
    FakePersistence as ReportFakePersistence,
)


class _RecordingObservability(LlmObservability):
    """Deterministic backend double recording observation lifecycles."""

    def __init__(self) -> None:
        """Start with no observations."""
        self.observations: list[LlmObservation] = []

    @contextmanager
    def observe(self, observation: LlmObservation) -> Iterator[None]:
        """Record the observation and yield."""
        self.observations.append(observation)
        yield


def _observed(
    fake_llm: FakeLlmClient, backend: _RecordingObservability
) -> ObservedLlmClient:
    """Wrap a fake delegate with the common observing client."""
    return ObservedLlmClient(
        fake_llm,
        backend,
        model_provider="openai",
        model_name="gpt-4o-mini",
    )


def _recorded(telemetry: SimpleNamespace) -> dict[str, Metric]:
    """Return recorded metrics indexed by name."""
    return metrics_by_name(telemetry.reader)


def _spans(telemetry: SimpleNamespace) -> list[object]:
    """Return finished span names from the in-memory exporter."""
    return [span.name for span in telemetry.exporter.get_finished_spans()]


class TestResearchAgentObservations:
    """A1..A3: agent span + exact model-attempt observations."""

    @pytest.mark.asyncio
    async def test_a1_normal_synthesis_one_agent_one_llm(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Normal synthesis: one agent span and one LLM observation (A1)."""
        from agentic_threat_investigator.app.evidence_analyst.accounting import (
            LlmAccountingService,
        )
        from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
        from agentic_threat_investigator.app.research_persistence import (
            ResearchResultPersistenceService,
        )

        world = ResearchWorld()
        backend = _RecordingObservability()
        fake_llm = FakeLlmClient()
        fake_llm.set_default(
            _decision(_claim("Statement X is described.", world.chunk_a.citation_id))
        )
        retriever = FakeResearchRetriever([world.chunk_a])
        store = _ResearchResults()
        persistence_uow = _PersistenceUow(
            store, {world.investigation_id}, {world.subject_entity_id}
        )
        accounting_uow = _AccountingUow(world.investigation)
        accounting_uow.investigations = _AccountingInvestigationRepository(
            world.investigation
        )
        agent = ResearchAgent(
            retriever=retriever,
            llm_client=_observed(fake_llm, backend),
            result_persistence=ResearchResultPersistenceService(
                lambda: persistence_uow
            ),
            llm_accounting=LlmAccountingService(lambda: accounting_uow),
            max_structured_output_attempts=2,
        )
        result = await agent.research(world.request())
        assert len(result.claims) == 1
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.agent.invoke") == 1
        assert spans.count("ati.llm.invoke") == 1
        assert len(backend.observations) == 1
        recorded = _recorded(in_memory_persistence_telemetry)
        assert histogram_count(recorded[DurationMetrics.AGENT_INVOKE]) == 1
        assert Metrics.LLM_INVOKE_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_a2_empty_retrieval_zero_llm(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Empty retrieval: one agent span and zero LLM observations (A2)."""
        from agentic_threat_investigator.app.evidence_analyst.accounting import (
            LlmAccountingService,
        )
        from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
        from agentic_threat_investigator.app.research_persistence import (
            ResearchResultPersistenceService,
        )

        world = ResearchWorld()
        backend = _RecordingObservability()
        fake_llm = FakeLlmClient()
        retriever = FakeResearchRetriever([])
        store = _ResearchResults()
        persistence_uow = _PersistenceUow(
            store, {world.investigation_id}, {world.subject_entity_id}
        )
        accounting_uow = _AccountingUow(world.investigation)
        accounting_uow.investigations = _AccountingInvestigationRepository(
            world.investigation
        )
        agent = ResearchAgent(
            retriever=retriever,
            llm_client=_observed(fake_llm, backend),
            result_persistence=ResearchResultPersistenceService(
                lambda: persistence_uow
            ),
            llm_accounting=LlmAccountingService(lambda: accounting_uow),
            max_structured_output_attempts=2,
        )
        result = await agent.research(world.request())
        assert result.claims == () and result.citations == ()
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.agent.invoke") == 1
        assert spans.count("ati.llm.invoke") == 0
        assert backend.observations == []
        recorded = _recorded(in_memory_persistence_telemetry)
        assert DurationMetrics.LLM_INVOKE not in recorded

    @pytest.mark.asyncio
    async def test_a3_one_repair_two_llm_observations(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """One bounded repair: one agent span and two LLM observations (A3)."""
        from agentic_threat_investigator.app.evidence_analyst.accounting import (
            LlmAccountingService,
        )
        from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
        from agentic_threat_investigator.app.research_persistence import (
            ResearchResultPersistenceService,
        )

        world = ResearchWorld()
        backend = _RecordingObservability()
        fake_llm = FakeLlmClient()
        fake_llm.enqueue(
            LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True)
        )
        fake_llm.set_default(
            _decision(_claim("Statement X is described.", world.chunk_a.citation_id))
        )
        retriever = FakeResearchRetriever([world.chunk_a])
        store = _ResearchResults()
        persistence_uow = _PersistenceUow(
            store, {world.investigation_id}, {world.subject_entity_id}
        )
        accounting_uow = _AccountingUow(world.investigation)
        accounting_uow.investigations = _AccountingInvestigationRepository(
            world.investigation
        )
        agent = ResearchAgent(
            retriever=retriever,
            llm_client=_observed(fake_llm, backend),
            result_persistence=ResearchResultPersistenceService(
                lambda: persistence_uow
            ),
            llm_accounting=LlmAccountingService(lambda: accounting_uow),
            max_structured_output_attempts=2,
        )
        result = await agent.research(world.request())
        assert len(result.claims) == 1
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.agent.invoke") == 1
        assert spans.count("ati.llm.invoke") == 2
        assert len(backend.observations) == 2


class TestAnalystAndReportCommonLlm:
    """A4..A5: analyst and report writer use the common observed client."""

    @pytest.mark.asyncio
    async def test_a4_analyst_uses_common_llm(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """The Evidence Analyst routes model attempts through the common seam (A4)."""
        from agentic_threat_investigator.app.assessment_persistence import (
            AssessmentPersistenceService,
        )
        from agentic_threat_investigator.app.evidence_analyst.accounting import (
            LlmAccountingService,
        )
        from agentic_threat_investigator.app.evidence_analyst.analyst import (
            EvidenceAnalyst,
        )

        world = AnalysisWorld()
        backend = _RecordingObservability()
        fake_llm = FakeLlmClient()
        fake_llm.set_default(world.decision(evidence_support=True))
        persistence_uow = FakePersistenceUnitOfWork(
            world=world,
            assessments=FakeAssessmentRepository(),
            audit_events=FakeAuditRepository(),
            investigations=FakeInvestigationRepository(world.investigation),
        )
        accounting_uow = FakeAccountingUnitOfWork(world.investigation)
        accounting_uow.investigations = FakeAccountingInvestigationRepository(
            world.investigation
        )
        analyst = EvidenceAnalyst(
            input_loader=FakeLoader(world.analyst_input()),
            llm_client=_observed(fake_llm, backend),
            assessment_persistence=AssessmentPersistenceService(
                lambda: persistence_uow, batch_size=100
            ),
            llm_accounting=LlmAccountingService(lambda: accounting_uow),
            max_structured_output_attempts=2,
        )
        persisted = await analyst.analyze(world.investigation_id)
        assert persisted.investigation_id == world.investigation_id
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.agent.invoke") == 1
        assert spans.count("ati.llm.invoke") == 1
        assert len(backend.observations) == 1
        assert backend.observations[0].model_name == "gpt-4o-mini"

    @pytest.mark.asyncio
    async def test_a5_report_writer_uses_common_llm(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """The Report Writer emits a report span plus one common LLM span (A5)."""
        from agentic_threat_investigator.app.report_writer.writer import ReportWriter

        world = ReportWriterUnitWorld()
        backend = _RecordingObservability()
        fake_llm = FakeLlmClient()
        fake_llm.set_default(world.output())
        loader = ReportFakeLoader(world.input())
        writer = ReportWriter(
            input_loader=loader,
            llm_client=_observed(fake_llm, backend),
            report_persistence=ReportFakePersistence(),
            llm_accounting=FakeAccounting(),
            max_structured_output_attempts=2,
        )
        report = await writer.write(world.investigation_id)
        assert report.verdict.value == "malicious"
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.report.generate") == 1
        assert spans.count("ati.llm.invoke") == 1
        assert len(backend.observations) == 1
        recorded = _recorded(in_memory_persistence_telemetry)
        assert histogram_count(recorded[DurationMetrics.REPORT_GENERATE]) == 1
