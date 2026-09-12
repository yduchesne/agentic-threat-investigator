# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 22C orchestration research planning and execution seams.

This module owns the narrow deterministic request-planning seam, the
research-context fingerprint, and the execution boundary between the
coordinator graph and the PR 22B Research Agent:

- :class:`PlannedResearchRequest` is the pure policy output that carries the
  exact ``ResearchAgentRequest`` plus its stable context fingerprint;
- :class:`ResearchRequestPlanner` and :class:`DeterministicResearchRequestPlanner`
  construct one bounded contextual question deterministically (never with an
  LLM) and fingerprint it;
- :class:`ResearchExecutor` / :class:`ResearchExecutionOutcome` is the
  orchestration-facing execution boundary returning authoritative identifiers
  only — no claims, chunks, or citations cross into Coordinator policy;
- :class:`ResearchExecutionReconciler` resolves an already-persisted matching
  ``ResearchResult`` so a crash between result persistence and completion
  recording never blindly repeats the model call.

The module deliberately does not import ``CoordinatorPolicy`` internals at
runtime: the planner ABC references the pure policy entity view only through
lazy annotations so no import cycle exists between this seam and the pure
policy module.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.app.llm import LlmError
from agentic_threat_investigator.app.orchestration.coordinator import (
    CoordinatorEntityView,
    PlannedResearchRequest,
    ResearchRequestPlanner,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.domain.research_agent import ResearchAgentRequest

RESEARCH_CONTEXT_SCHEMA_VERSION = "ati-research-context-v1"
"""Stable research-context schema/version literal.

Included in every fingerprint so future query/filter semantics can
intentionally invalidate old deduplication state by bumping the version.
"""

RESEARCH_QUERY_TEMPLATE = (
    'Provide contextual threat-research information about {entity_type} "{value}" '
    "that is relevant to this investigation objective: {objective}"
)
"""The one stable deterministic query template (PR 22C).

The template embeds the persisted entity type/value and the investigation
objective only; it never includes hidden state, prior model output, or
retrieved content. Changing the template intentionally changes every
fingerprint, invalidating old deduplication state.
"""


def research_context_fingerprint(
    *,
    entity_type: str,
    entity_value: str,
    request: ResearchAgentRequest,
) -> str:
    """Return the deterministic SHA-256 fingerprint of one research context.

    The canonical serialization has an explicit field order and schema/version
    literal and includes every input that changes the planned request
    semantics: the Investigation/subject anchors, the entity type/value, the
    exact query, the retrieval filter configuration, and ``max_results``.
    Incidental object repr formatting, timestamps, UUID randomness, LLM
    output, and retrieved chunk identities are never part of the fingerprint.
    """
    canonical = json.dumps(
        {
            "schema_version": RESEARCH_CONTEXT_SCHEMA_VERSION,
            "investigation_id": str(request.investigation_id),
            "subject_entity_id": str(request.subject_entity_id),
            "entity_type": entity_type,
            "entity_value": entity_value,
            "query": request.query,
            "entity_ids": [str(item) for item in request.entity_ids],
            "source_ids": list(request.source_ids),
            "document_types": list(request.document_types),
            "max_results": request.max_results,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DeterministicResearchRequestPlanner(ResearchRequestPlanner):
    """Production v0.1 planner constructing one bounded contextual question.

    Retrieval filters use ``entity_ids=()`` in v0.1 because the current
    corpus indexing does not associate investigation entity UUIDs with
    documents (the pgvector retriever filters on source/document type only);
    semantic query retrieval against the narrative corpus remains the whole
    of the retrieval context. ``max_results`` is a bounded default.
    """

    def __init__(self, max_results: int = 8) -> None:
        """Bind the bounded retrieval result limit (1..100)."""
        if not 1 <= max_results <= 100:
            raise ValueError("research max_results must be in the range 1..100")
        self._max_results = max_results

    def plan(
        self,
        *,
        investigation: InvestigationState,
        entity: CoordinatorEntityView,
    ) -> PlannedResearchRequest:
        """Build one request from the persisted type/value and objective.

        The query embeds the canonical entity value and the investigation
        objective only; the subject anchor, the retrieval filters, and the
        bounded limit are carried explicitly on the request so the persisted
        execution state preserves the exact planned context.
        """
        query = RESEARCH_QUERY_TEMPLATE.format(
            entity_type=entity.entity_type.value,
            value=entity.value,
            objective=investigation.objective,
        )
        request = ResearchAgentRequest(
            investigation_id=investigation.investigation_id,
            subject_entity_id=entity.entity_id,
            query=query,
            entity_ids=(),
            source_ids=(),
            document_types=(),
            max_results=self._max_results,
        )
        fingerprint = research_context_fingerprint(
            entity_type=entity.entity_type.value,
            entity_value=entity.value,
            request=request,
        )
        return PlannedResearchRequest(request=request, context_fingerprint=fingerprint)


class ResearchExecutionOutcome(BaseModel):
    """Minimal authoritative result identity returned by an executor.

    Contains operational identifiers only: no claims, citations, chunks,
    similarity scores, or research content cross into Coordinator policy.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    result_id: UUID
    investigation_id: UUID
    subject_entity_id: UUID
    query: str


class ResearchExecutor(ABC):
    """Execution boundary for the PR 22B Research Agent.

    The executor runs outside any orchestration transaction and returns only
    information about already-persisted research. It never decides whether
    research should run, which entity to research, or whether a pivot should
    occur.
    """

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the investigation binding, or ``None`` for unbound executors."""
        return None

    @abstractmethod
    async def execute(self, request: ResearchAgentRequest) -> ResearchExecutionOutcome:
        """Execute one authorized research request and return its outcome.

        The outcome's result must already be durably persisted by the
        Research Agent; recoverable failures raise typed errors that
        orchestration may retry within its bounded attempt policy.
        """


class ResearchAgentResearchExecutor(ResearchExecutor):
    """Production adapter around the already-delivered PR 22B Research Agent.

    Delegates the whole bounded execution (retrieval, LLM accounting,
    structured-output repair, citation validation, immutable result
    persistence) to the agent and returns only the authoritative identifiers
    needed by orchestration. No claims/citations are exposed to policy.
    """

    def __init__(
        self,
        research_agent: ResearchAgent,
        *,
        bound_investigation_id: UUID | None = None,
    ) -> None:
        """Bind the Research Agent and optional investigation identity."""
        self._research_agent = research_agent
        self._bound_investigation_id = bound_investigation_id

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the configured investigation binding, if any."""
        return self._bound_investigation_id

    async def execute(self, request: ResearchAgentRequest) -> ResearchExecutionOutcome:
        """Run one research execution and return its authoritative identity."""
        if (
            self._bound_investigation_id is not None
            and request.investigation_id != self._bound_investigation_id
        ):
            raise ValueError(
                "research executor investigation does not match the requested "
                "investigation"
            )
        result = await self._research_agent.research(request)
        return ResearchExecutionOutcome(
            result_id=result.id,
            investigation_id=result.investigation_id,
            subject_entity_id=result.subject_entity_id,
            query=result.query,
        )


class FakeResearchExecutor(ResearchExecutor):
    """Deterministic scripted research executor used by unit tests.

    Records every call, returns queued outcomes in order (or raises queued
    typed errors), and optionally enforces an investigation binding. It never
    fakes retrieval or persistence; canonical integration trajectories use
    the real Research Agent path with ``FakeLlmClient`` only at the model
    boundary.
    """

    def __init__(
        self,
        outcomes: Sequence[ResearchExecutionOutcome | BaseException] = (),
        *,
        bound_investigation_id: UUID | None = None,
    ) -> None:
        """Bind the queued outcomes, optional identity, and call recording."""
        self._outcomes = list(outcomes)
        self.calls: list[ResearchAgentRequest] = []
        self._bound_investigation_id = bound_investigation_id

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the configured binding when set."""
        return self._bound_investigation_id

    async def execute(self, request: ResearchAgentRequest) -> ResearchExecutionOutcome:
        """Return the next queued outcome/error, failing closed when empty."""
        if (
            self._bound_investigation_id is not None
            and request.investigation_id != self._bound_investigation_id
        ):
            raise ValueError(
                "research executor investigation does not match the requested "
                "investigation"
            )
        self.calls.append(request)
        if not self._outcomes:
            raise RuntimeError("fake research outcomes exhausted")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome.investigation_id != request.investigation_id:
            raise ValueError(
                "fake research outcome investigation does not match the request"
            )
        if outcome.subject_entity_id != request.subject_entity_id:
            raise ValueError("fake research outcome subject does not match the request")
        if outcome.query != request.query:
            raise ValueError("fake research outcome query does not match the request")
        return outcome


class AmbiguousResearchReconciliationError(RuntimeError):
    """Multiple matching ResearchResults exist with no authoritative link.

    The graph fails closed rather than arbitrarily picking "latest": the
    only deterministic adoption is an exactly-one match or a match already
    linked coherently by ``research_result_ids``.
    """


class ResearchExecutionReconciler(ABC):
    """Resolve an already-persisted result for a crash-window context."""

    @abstractmethod
    async def find_matching_result(
        self,
        *,
        investigation_id: UUID,
        subject_entity_id: UUID,
        query: str,
        state: InvestigationState,
    ) -> ResearchResult | None:
        """Return exactly one adoptable matching result, or ``None``.

        Matching is authoritative on ``(subject_entity_id, query)``; the
        context fingerprint is implied by the deterministic planner. Raises
        :class:`AmbiguousResearchReconciliationError` when multiple distinct
        matches exist and none is coherently linked by ``research_result_ids``.
        """


class UowResearchExecutionReconciler(ResearchExecutionReconciler):
    """List persisted results through one short read-only UnitOfWork."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork]) -> None:
        """Bind the reconciler to a UnitOfWork factory."""
        self._uow_factory = uow_factory

    async def find_matching_result(
        self,
        *,
        investigation_id: UUID,
        subject_entity_id: UUID,
        query: str,
        state: InvestigationState,
    ) -> ResearchResult | None:
        """Return one deterministically adoptable matching result or ``None``.

        The transaction is closed before the result is returned. A single
        exact match is adopted; when several distinct matches exist, only a
        match already linked by ``research_result_ids`` is adopted and any
        other arrangement fails closed as ambiguous orchestration state.
        """
        async with self._uow_factory() as uow:
            results = await uow.research_results.list_by_investigation(investigation_id)
        matches = [
            result
            for result in results
            if result.subject_entity_id == subject_entity_id and result.query == query
        ]
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]
        linked_ids = set(state.research_result_ids)
        referenced = [result for result in matches if result.id in linked_ids]
        if len(referenced) == 1:
            return referenced[0]
        raise AmbiguousResearchReconciliationError()


def research_execution_recoverable(error: BaseException) -> bool:
    """Return True only for typed, explicitly retryable execution failures.

    Orchestration retries are limited to a typed ``LlmError`` that carries
    the documented retryable flag. Everything else — unsupported citations,
    retrieval contract violations, reference mismatches, persistence
    failures, binding mismatches, malformed output after bounded repair — is
    non-recoverable and must fail closed. Classification never parses
    exception strings.
    """
    return isinstance(error, LlmError) and error.retryable
