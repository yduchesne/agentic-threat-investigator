# SPDX-License-Identifier: AGPL-3.0-only
"""The standalone structured Threat Research / Context Agent (PR 22B).

Execution path:

```text
ResearchAgentRequest
 -> ResearchQuery (pure mapping)
 -> ResearchRetriever (one bounded pass; its transaction closes inside)
 -> deterministic prompt
 -> LlmAccountingService.reserve_call (short durable reservation)
 -> LlmClient.generate_structured
 -> deterministic citation-membership validation
 -> ResearchResult (application stamps IDs, clock, anchors)
 -> ResearchResultPersistenceService (one short atomic transaction)
```

Retrieval and LLM work never run inside a long PostgreSQL transaction. An
empty retrieval deterministically persists a zero-claim/zero-citation result
without spending a model call. The model may cite only stable ``citation_id``
values from the exact chunks rendered into its prompt; a schema-valid claim
that cites anything else fails closed before any persistence. The agent
allocates durable identities and timestamps itself and never creates
Evidence, Relationships, Assessments, verdicts, or pivot authority.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.llm import LlmClient, LlmError, LlmErrorCode
from agentic_threat_investigator.app.research import (
    ResearchRetrievalError,
    ResearchRetriever,
)
from agentic_threat_investigator.app.research_agent.errors import (
    ResearchAgentCitationError,
)
from agentic_threat_investigator.app.research_agent.prompts import (
    OPERATION_RESEARCH_SYNTHESIS,
    build_research_agent_prompts,
)
from agentic_threat_investigator.app.research_persistence import (
    ResearchResultPersistenceService,
)
from agentic_threat_investigator.domain.research import (
    ResearchClaim,
    ResearchQuery,
    ResearchResult,
    RetrievedChunk,
    research_citation_from_retrieved_chunk,
)
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentDecision,
    ResearchAgentRequest,
)


def research_query_from_request(request: ResearchAgentRequest) -> ResearchQuery:
    """Map one execution request onto the existing bounded retrieval query.

    The mapping is pure and deterministic: filters carry over without
    reordering, ``max_results`` stays within the shared 1..100 bound, and
    ``subject_entity_id`` is deliberately not a retrieval concern.
    """
    return ResearchQuery(
        investigation_id=request.investigation_id,
        query=request.query,
        entity_ids=list(request.entity_ids),
        source_ids=list(request.source_ids),
        document_types=list(request.document_types),
        max_results=request.max_results,
    )


class ResearchAgent:
    """Run one bounded, provenance-backed contextual research execution.

    ``max_structured_output_attempts`` bounds the explicit schema-repair
    policy: one initial attempt plus at most ``max_attempts - 1`` repairs,
    each a separately accounted model invocation. ``clock`` and ``id_factory``
    are narrow seams for deterministic unit tests; production uses UTC now and
    ``uuid4``.
    """

    def __init__(
        self,
        *,
        retriever: ResearchRetriever,
        llm_client: LlmClient,
        result_persistence: ResearchResultPersistenceService,
        llm_accounting: LlmAccountingService,
        max_structured_output_attempts: int = 2,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], UUID] | None = None,
    ) -> None:
        """Bind the retriever, LLM client, persistence, and accounting seams.

        ``max_structured_output_attempts`` is hard-limited to the approved
        range 1..2 (one initial attempt plus at most one schema repair), even
        when the agent is constructed directly without ``Settings``.
        """
        if not 1 <= max_structured_output_attempts <= 2:
            raise ValueError("max_structured_output_attempts must be in the range 1..2")
        self._retriever = retriever
        self._llm_client = llm_client
        self._result_persistence = result_persistence
        self._llm_accounting = llm_accounting
        self._max_structured_output_attempts = max_structured_output_attempts
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._id_factory = id_factory if id_factory is not None else uuid4

    async def research(self, request: ResearchAgentRequest) -> ResearchResult:
        """Retrieve once, synthesize once, validate, and persist one result.

        One execution performs at most one retrieval pass and at most one
        bounded structured-output sequence. An empty retrieval short-circuits
        to a persisted zero-claim/zero-citation result without any model
        invocation; a schema-valid decision whose claims cite chunks that were
        not supplied fails closed before any persistence; a durable result is
        returned only after its single short persistence transaction commits.
        """
        query = research_query_from_request(request)
        chunks = tuple(await self._retriever.retrieve(query))
        _validate_unique_citation_identities(chunks)

        if not chunks:
            return await self._persist_empty_result(request)

        decision = await self._generate_decision(request, chunks)
        result = self._build_result(request, chunks, decision)
        await self._result_persistence.persist(result)
        return result

    async def _generate_decision(
        self,
        request: ResearchAgentRequest,
        chunks: Sequence[RetrievedChunk],
    ) -> ResearchAgentDecision:
        """Run bounded, accounted structured-output attempts.

        Each attempt first builds its deterministic prompt, then durably
        reserves exactly one LLM call, then invokes the model once. A
        prompt-construction failure consumes no budget and no model call is
        attempted; the Investigation version returned by one reservation
        chains into the next, so a repair attempt is separately counted.
        """
        latest_version: int | None = None
        for attempt in range(1, self._max_structured_output_attempts + 1):
            system_prompt, user_prompt = build_research_agent_prompts(
                request, chunks, repair=attempt > 1
            )
            latest_version = await self._llm_accounting.reserve_call(
                request.investigation_id, expected_version=latest_version
            )
            try:
                decision = await self._llm_client.generate_structured(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=ResearchAgentDecision,
                    operation_name=OPERATION_RESEARCH_SYNTHESIS,
                )
            except asyncio.CancelledError:
                # Cooperative cancellation propagates unchanged; the handler
                # only prevents the LlmError mapping below from catching it.
                raise
            except LlmError as error:
                # Repair only a retryable invalid-structured-output error with
                # an attempt budget remaining; a non-retryable invalid output
                # (or any other category) fails conservative.
                if (
                    error.code is LlmErrorCode.INVALID_STRUCTURED_OUTPUT
                    and error.retryable
                    and attempt < self._max_structured_output_attempts
                ):
                    continue
                raise
            return decision
        raise LlmError(  # pragma: no cover - the loop always returns or raises
            LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False
        )

    async def _persist_empty_result(
        self, request: ResearchAgentRequest
    ) -> ResearchResult:
        """Persist the deterministic no-context result without a model call.

        Zero claims and zero citations are a first-class domain outcome; no
        LLM attempt is spent rediscovering the structural fact that no
        context was retrieved. The result still passes through the real
        persistence seam, so invalid Investigation/subject references fail
        normally.
        """
        result = ResearchResult(
            id=self._id_factory(),
            investigation_id=request.investigation_id,
            subject_entity_id=request.subject_entity_id,
            query=request.query,
            claims=(),
            citations=(),
            created_at=self._clock(),
        )
        await self._result_persistence.persist(result)
        return result

    def _build_result(
        self,
        request: ResearchAgentRequest,
        chunks: Sequence[RetrievedChunk],
        decision: ResearchAgentDecision,
    ) -> ResearchResult:
        """Validate citation membership and stamp every authoritative field.

        The model returns semantic content only; the application owns the
        result/claim UUIDs, the UTC clock, the investigation/subject anchors,
        and the durable citation snapshots. Only chunks actually cited by
        accepted claims become citations, in deterministic first-use order.
        """
        chunks_by_citation_id = {chunk.citation_id: chunk for chunk in chunks}
        unsupported = _unsupported_citation_ids(
            decision, frozenset(chunks_by_citation_id)
        )
        if unsupported:
            raise ResearchAgentCitationError(unsupported)

        claims: list[ResearchClaim] = []
        used: dict[UUID, RetrievedChunk] = {}
        for claim in decision.claims:
            for citation_id in claim.citation_ids:
                chunk = chunks_by_citation_id[citation_id]
                if citation_id not in used:
                    used[citation_id] = chunk
            claims.append(
                ResearchClaim(
                    id=self._id_factory(),
                    text=claim.text,
                    citation_ids=claim.citation_ids,
                )
            )
        citations = tuple(
            research_citation_from_retrieved_chunk(used[citation_id])
            for citation_id in used
        )
        return ResearchResult(
            id=self._id_factory(),
            investigation_id=request.investigation_id,
            subject_entity_id=request.subject_entity_id,
            query=request.query,
            claims=tuple(claims),
            citations=citations,
            created_at=self._clock(),
        )


def _validate_unique_citation_identities(chunks: Sequence[RetrievedChunk]) -> None:
    """Fail closed when one retrieval response repeats a stable citation ID.

    Duplicate ``citation_id`` values would make snapshot selection ambiguous
    and must not normally occur; treating the response as contract-invalid
    avoids silently choosing one chunk over another.
    """
    citation_ids = [chunk.citation_id for chunk in chunks]
    if len(set(citation_ids)) != len(citation_ids):
        raise ResearchRetrievalError(
            "research retriever returned duplicate citation identities"
        )


def _unsupported_citation_ids(
    decision: ResearchAgentDecision, allowed: frozenset[UUID]
) -> tuple[UUID, ...]:
    """Return the deterministic first-use list of unsupported claim citations.

    A citation that merely exists somewhere in the corpus but was not supplied
    to this model invocation is rejected identically to an unknown one.
    """
    unsupported: list[UUID] = []
    seen: set[UUID] = set()
    for claim in decision.claims:
        for citation_id in claim.citation_ids:
            if citation_id not in allowed and citation_id not in seen:
                seen.add(citation_id)
                unsupported.append(citation_id)
    return tuple(unsupported)
