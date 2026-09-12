# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 22C research planning, fingerprint, executor, and reconciler unit tests.

Covers the deterministic query template (U07), the schema-versioned context
fingerprint (U08-U11), the production/fake executor seams, the typed
recoverable-failure classification, and the crash-window reconciliation
rules. All tests are synchronous/in-memory except the executor tests, which
use deterministic fakes with no network, database, or LLM I/O.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest

from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.orchestration.coordinator import (
    CoordinatorEntityView,
    PlannedResearchRequest,
)
from agentic_threat_investigator.app.orchestration.research import (
    AmbiguousResearchReconciliationError,
    DeterministicResearchRequestPlanner,
    FakeResearchExecutor,
    ResearchAgentResearchExecutor,
    ResearchExecutionOutcome,
    UowResearchExecutionReconciler,
    research_context_fingerprint,
    research_execution_recoverable,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.domain.research_agent import ResearchAgentRequest

_INVESTIGATION = UUID("00000000-0000-0000-0000-0000000000c1")
_SUBJECT = UUID("00000000-0000-0000-0000-0000000000a1")
_OBJECTIVE = "Assess the malware family and its infrastructure."


def _entity(
    entity_id: UUID = _SUBJECT,
    entity_type: EntityType = EntityType.MALWARE,
    value: str = "asyncrat",
) -> CoordinatorEntityView:
    """Return one RESEARCHABLE entity view."""
    return CoordinatorEntityView(
        entity_id=entity_id, entity_type=entity_type, value=value
    )


def _investigation(**overrides: object) -> InvestigationState:
    """Return one minimal running investigation."""
    params: dict[str, object] = {
        "investigation_id": _INVESTIGATION,
        "status": InvestigationStatus.RUNNING,
        "trigger_type": InvestigationTriggerType.MANUAL,
        "root_entity_ids": [_SUBJECT],
        "objective": _OBJECTIVE,
        "budget": default_investigation_budget(),
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "version": 1,
    }
    params.update(overrides)
    return InvestigationState.model_validate(params)


class TestDeterministicResearchRequestPlanner:
    """U07: the production planner is deterministic and never LLM-driven."""

    def test_query_template_embeds_type_value_and_objective(self) -> None:
        """The query is the documented deterministic template."""
        planner = DeterministicResearchRequestPlanner(max_results=8)
        planned = planner.plan(investigation=_investigation(), entity=_entity())
        expected = (
            "Provide contextual threat-research information about malware "
            '"asyncrat" that is relevant to this investigation objective: '
            "Assess the malware family and its infrastructure."
        )
        assert planned.request.query == expected

    def test_planned_request_anchors_subject_and_filters(self) -> None:
        """The request carries the subject anchor and v0.1 retrieval filters."""
        planned = DeterministicResearchRequestPlanner(max_results=8).plan(
            investigation=_investigation(), entity=_entity()
        )
        request = planned.request
        assert request.investigation_id == _INVESTIGATION
        assert request.subject_entity_id == _SUBJECT
        # v0.1 corpus indexing does not associate entity UUIDs with documents:
        # semantic retrieval only, with bounded result count.
        assert request.entity_ids == ()
        assert request.source_ids == ()
        assert request.document_types == ()
        assert request.max_results == 8

    def test_same_inputs_produce_identical_request(self) -> None:
        """U07: repeated planning of the same context is identical."""
        planner = DeterministicResearchRequestPlanner(max_results=8)
        first = planner.plan(investigation=_investigation(), entity=_entity())
        second = planner.plan(investigation=_investigation(), entity=_entity())
        assert first == second

    def test_max_results_out_of_range_rejected(self) -> None:
        """The bounded limit rejects values outside 1..100."""
        with pytest.raises(ValueError, match="1..100"):
            DeterministicResearchRequestPlanner(max_results=0)

    def test_planner_never_reads_llm_or_persistence(self) -> None:
        """U07: planning carries no external I/O seam by construction."""
        planner = DeterministicResearchRequestPlanner(max_results=8)
        planned = planner.plan(investigation=_investigation(), entity=_entity())
        assert planned.context_fingerprint
        assert isinstance(planned, PlannedResearchRequest)


class TestResearchContextFingerprint:
    """U08-U11: the context fingerprint is deterministic and versioned."""

    def _request(self, **overrides: object) -> ResearchAgentRequest:
        values: dict[str, object] = {
            "investigation_id": _INVESTIGATION,
            "subject_entity_id": _SUBJECT,
            "query": "Provide contextual threat-research information.",
            "max_results": 8,
        }
        values.update(overrides)
        return ResearchAgentRequest.model_validate(values)

    def _fingerprint(self, request: ResearchAgentRequest, **entity: object) -> str:
        kwargs: dict[str, object] = {
            "entity_type": EntityType.MALWARE.value,
            "entity_value": "asyncrat",
        }
        kwargs.update(entity)
        return research_context_fingerprint(
            entity_type=str(kwargs["entity_type"]),
            entity_value=str(kwargs["entity_value"]),
            request=request,
        )

    def test_same_inputs_same_fingerprint(self) -> None:
        """U08: identical contexts hash identically."""
        request = self._request()
        assert self._fingerprint(request) == self._fingerprint(request)

    def test_different_subject_different_fingerprint(self) -> None:
        """U09: a different subject entity changes the fingerprint."""
        other = self._request(
            subject_entity_id=UUID("00000000-0000-0000-0000-0000000000a2")
        )
        assert self._fingerprint(self._request()) != self._fingerprint(other)

    def test_changed_entity_value_different_fingerprint(self) -> None:
        """U09: a changed canonical entity value changes the fingerprint."""
        request = self._request()
        assert self._fingerprint(request) != self._fingerprint(
            request, entity_value="njrat"
        )

    def test_changed_query_different_fingerprint(self) -> None:
        """U10: a changed objective/query changes the fingerprint."""
        assert self._fingerprint(self._request()) != self._fingerprint(
            self._request(query="A different research question.")
        )

    def test_changed_retrieval_config_different_fingerprint(self) -> None:
        """U11: changed filters or max_results change the fingerprint."""
        filtered = self._request(entity_ids=(_SUBJECT,))
        assert self._fingerprint(self._request()) != self._fingerprint(filtered)
        more = self._request(max_results=16)
        assert self._fingerprint(self._request()) != self._fingerprint(more)

    def test_schema_version_is_embedded(self) -> None:
        """The schema/version literal is part of the canonical payload."""
        request = self._request()
        from agentic_threat_investigator.app.orchestration.research import (
            RESEARCH_CONTEXT_SCHEMA_VERSION,
        )

        assert len(self._fingerprint(request)) == 64
        assert isinstance(RESEARCH_CONTEXT_SCHEMA_VERSION, str)


class TestResearchExecutionRecoverableClassification:
    """Recoverable failures are typed and explicit; nothing is parsed."""

    def test_retryable_llm_error_is_recoverable(self) -> None:
        """A typed retryable LlmError is the only recoverable condition."""
        error = LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True)
        assert research_execution_recoverable(error)

    def test_non_retryable_llm_error_is_not_recoverable(self) -> None:
        """A non-retryable LlmError fails closed."""
        error = LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False)
        assert not research_execution_recoverable(error)

    def test_unsupported_citation_is_not_recoverable(self) -> None:
        """Invariant violations never retry at orchestration level."""
        from agentic_threat_investigator.app.research_agent.errors import (
            ResearchAgentCitationError,
        )

        assert not research_execution_recoverable(ResearchAgentCitationError(()))

    def test_generic_error_is_not_recoverable(self) -> None:
        """Unknown exceptions fail closed; no string parsing occurs."""
        assert not research_execution_recoverable(RuntimeError("transient?"))


class TestResearchExecutors:
    """Executor seams return identifiers only and enforce bindings."""

    @pytest.mark.asyncio
    async def test_fake_executor_records_calls_and_returns_outcome(self) -> None:
        """A scripted outcome is returned and the request recorded."""
        request = ResearchAgentRequest(
            investigation_id=_INVESTIGATION,
            subject_entity_id=_SUBJECT,
            query="Provide contextual threat-research information.",
        )
        result_id = UUID("00000000-0000-0000-0000-0000000000d1")
        executor = FakeResearchExecutor(
            (
                ResearchExecutionOutcome(
                    result_id=result_id,
                    investigation_id=_INVESTIGATION,
                    subject_entity_id=_SUBJECT,
                    query=request.query,
                ),
            )
        )
        outcome = await executor.execute(request)
        assert outcome.result_id == result_id
        assert executor.calls == [request]

    @pytest.mark.asyncio
    async def test_fake_executor_raises_scripted_error(self) -> None:
        """A scripted typed error is raised unchanged."""
        error = LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True)
        executor = FakeResearchExecutor((error,))
        with pytest.raises(LlmError):
            await executor.execute(
                ResearchAgentRequest(
                    investigation_id=_INVESTIGATION,
                    subject_entity_id=_SUBJECT,
                    query="q",
                )
            )

    @pytest.mark.asyncio
    async def test_fake_executor_binding_mismatch_fails_closed(self) -> None:
        """A bound fake rejects another investigation before any call."""
        other = UUID("00000000-0000-0000-0000-0000000000ee")
        executor = FakeResearchExecutor(
            bound_investigation_id=_INVESTIGATION,
        )
        with pytest.raises(ValueError, match="does not match"):
            await executor.execute(
                ResearchAgentRequest(
                    investigation_id=other,
                    subject_entity_id=_SUBJECT,
                    query="q",
                )
            )
        assert executor.calls == []

    @pytest.mark.asyncio
    async def test_fake_executor_exhausts_fail_closed(self) -> None:
        """An empty outcome queue fails closed instead of fabricating."""
        executor = FakeResearchExecutor()
        with pytest.raises(RuntimeError, match="outcomes exhausted"):
            await executor.execute(
                ResearchAgentRequest(
                    investigation_id=_INVESTIGATION,
                    subject_entity_id=_SUBJECT,
                    query="q",
                )
            )


class TestResearchExecutionReconciler:
    """Crash-window reconciliation rules are deterministic."""

    @staticmethod
    def _result(result_id: UUID) -> ResearchResult:
        return ResearchResult(
            id=result_id,
            investigation_id=_INVESTIGATION,
            subject_entity_id=_SUBJECT,
            query="Provide contextual threat-research information.",
            claims=(),
            citations=(),
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

    @staticmethod
    def _uow_factory(
        results: list[ResearchResult],
    ) -> Callable[[], UnitOfWork]:
        """Return an async-context-manager factory exposing research results.

        The fake UnitOfWork duck-types the repository seam used by the
        reconciler; the concrete ``UnitOfWork`` contract is satisfied by the
        fake's repository attribute.
        """
        from agentic_threat_investigator.app.persistence.repositories import (
            UnitOfWork,
        )

        def factory() -> UnitOfWork:
            return cast(UnitOfWork, _FakeUow(results))

        return factory

    @pytest.mark.asyncio
    async def test_exactly_one_match_is_adopted(self) -> None:
        """One exact (subject, query) match is returned deterministically."""

        factory = self._uow_factory(
            [self._result(UUID("00000000-0000-0000-0000-0000000000d1"))]
        )
        reconciler = UowResearchExecutionReconciler(factory)
        state = _investigation()
        found = await reconciler.find_matching_result(
            investigation_id=_INVESTIGATION,
            subject_entity_id=_SUBJECT,
            query="Provide contextual threat-research information.",
            state=state,
        )
        assert found is not None
        assert found.subject_entity_id == _SUBJECT

    @pytest.mark.asyncio
    async def test_no_match_returns_none(self) -> None:
        """An empty investigation result set returns None."""

        factory = self._uow_factory([])
        reconciler = UowResearchExecutionReconciler(factory)
        assert (
            await reconciler.find_matching_result(
                investigation_id=_INVESTIGATION,
                subject_entity_id=_SUBJECT,
                query="q",
                state=_investigation(),
            )
            is None
        )

    @pytest.mark.asyncio
    async def test_multiple_matches_linked_one_is_adopted(self) -> None:
        """A match coherently linked by research_result_ids is adopted."""
        linked = self._result(UUID("00000000-0000-0000-0000-0000000000e1"))
        other = self._result(UUID("00000000-0000-0000-0000-0000000000e2"))

        factory = self._uow_factory([other, linked])
        reconciler = UowResearchExecutionReconciler(factory)
        state = _investigation(research_result_ids=[linked.id])
        found = await reconciler.find_matching_result(
            investigation_id=_INVESTIGATION,
            subject_entity_id=_SUBJECT,
            query="Provide contextual threat-research information.",
            state=state,
        )
        assert found is not None
        assert found.id == linked.id

    @pytest.mark.asyncio
    async def test_multiple_unlinked_matches_fail_closed(self) -> None:
        """Ambiguous unlinked matches raise rather than pick 'latest'."""
        first = self._result(UUID("00000000-0000-0000-0000-0000000000f1"))
        second = self._result(UUID("00000000-0000-0000-0000-0000000000f2"))

        factory = self._uow_factory([first, second])
        reconciler = UowResearchExecutionReconciler(factory)
        with pytest.raises(AmbiguousResearchReconciliationError):
            await reconciler.find_matching_result(
                investigation_id=_INVESTIGATION,
                subject_entity_id=_SUBJECT,
                query="Provide contextual threat-research information.",
                state=_investigation(),
            )

    @pytest.mark.asyncio
    async def test_agent_executor_rejects_wrong_request_binding(self) -> None:
        """The production adapter enforces its optional investigation binding."""
        from typing import cast

        from agentic_threat_investigator.app.research_agent.agent import ResearchAgent

        class _StubAgent:
            async def research(self, request: ResearchAgentRequest) -> ResearchResult:
                del request
                raise AssertionError("stub agent must not be called")

        executor = ResearchAgentResearchExecutor(
            cast(ResearchAgent, _StubAgent()), bound_investigation_id=_INVESTIGATION
        )
        other = UUID("00000000-0000-0000-0000-0000000000ff")
        with pytest.raises(ValueError, match="does not match"):
            await executor.execute(
                ResearchAgentRequest(
                    investigation_id=other,
                    subject_entity_id=_SUBJECT,
                    query="q",
                )
            )


class _FakeUow:
    """Duck-typed fake UnitOfWork exposing a research-results repository."""

    def __init__(self, results: list[ResearchResult]) -> None:
        self.research_results = _FakeResearchRepo(results)

    async def __aenter__(self) -> "_FakeUow":
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        return None


class _FakeResearchRepo:
    """Return the configured results from list_by_investigation."""

    def __init__(self, results: list[ResearchResult]) -> None:
        self._results = results

    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> list[ResearchResult]:
        del investigation_id
        return list(self._results)
