# SPDX-License-Identifier: AGPL-3.0-only
"""The Evidence Analyst application execution service.

Execution path (PR 20B):

```text
EvidenceAnalystInputLoader (read-only UnitOfWork, then closed)
 -> deterministic prompt
 -> LlmClient.generate_structured(...)
 -> EvidenceAnalystDecision  (semantic output only)
 -> Assessment (application stamps investigation_id and analyzed_evidence_ids)
 -> AssessmentPersistenceService (PR 20A validation/persistence seam)
 -> persisted Assessment + Investigation assessment pointer
```

LLM calls happen strictly outside database transactions. Every actual model
invocation is durably reserved against the Investigation LLM budget before
the call; structured-output repair is explicit and bounded. A no-evidence
Investigation short-circuits to a deterministic INCONCLUSIVE Assessment with
no model call.
"""

# The analyze signature mirrors the confirmed PR 20B contract: one explicit
# argument per correlation/concurrency dimension (actor, request, expected
# version).
# pylint: disable=too-many-arguments

from __future__ import annotations

import asyncio
from uuid import UUID

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.evidence_analyst.loader import (
    EvidenceAnalystInputLoader,
)
from agentic_threat_investigator.app.evidence_analyst.prompts import (
    OPERATION_EVIDENCE_ANALYSIS,
    build_evidence_analyst_prompts,
)
from agentic_threat_investigator.app.llm import LlmClient, LlmError, LlmErrorCode
from agentic_threat_investigator.domain.analyst import (
    EvidenceAnalystDecision,
    EvidenceAnalystInput,
)
from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    Verdict,
)

_NO_EVIDENCE_SUMMARY = "No evidence was available for analysis."
_NO_EVIDENCE_LIMITATION = "No evidence was available for this investigation."


class EvidenceAnalyst:  # pylint: disable=too-few-public-methods
    """Run one Evidence Analyst execution for an Investigation.

    ``max_structured_output_attempts`` bounds the explicit schema-repair
    policy: one initial attempt plus at most ``max_attempts - 1`` repairs,
    each a separately counted model invocation.
    """

    def __init__(
        self,
        *,
        input_loader: EvidenceAnalystInputLoader,
        llm_client: LlmClient,
        assessment_persistence: AssessmentPersistenceService,
        llm_accounting: LlmAccountingService,
        max_structured_output_attempts: int = 2,
    ) -> None:
        """Bind the loader, LLM client, persistence seam, and accounting.

        ``max_structured_output_attempts`` is hard-limited to the approved
        range 1..2 (one initial attempt plus at most one schema repair), even
        when the service is constructed directly without ``Settings``.
        """
        if not 1 <= max_structured_output_attempts <= 2:
            raise ValueError("max_structured_output_attempts must be in the range 1..2")
        self._input_loader = input_loader
        self._llm_client = llm_client
        self._assessment_persistence = assessment_persistence
        self._llm_accounting = llm_accounting
        self._max_structured_output_attempts = max_structured_output_attempts

    async def analyze(
        self,
        investigation_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_investigation_version: int | None = None,
    ) -> Assessment:
        """Load, analyze, construct, and persist one Assessment.

        An exhausted LLM budget, exhausted structured-output attempts, LLM
        timeout/provider failure, invalid support references, or a stale
        Investigation version fail without producing any partial Assessment.
        """
        analyst_input = await self._input_loader.load(investigation_id)
        if not analyst_input.evidence:
            return await self._persist_no_evidence(
                analyst_input,
                actor_id=actor_id,
                request_id=request_id,
                expected_investigation_version=expected_investigation_version,
            )

        decision, latest_version = await self._generate_decision(
            analyst_input,
            investigation_id,
            expected_version=expected_investigation_version,
        )
        return await self._persist_decision(
            analyst_input,
            decision,
            latest_version=latest_version,
            actor_id=actor_id,
            request_id=request_id,
        )

    async def _generate_decision(
        self,
        analyst_input: EvidenceAnalystInput,
        investigation_id: UUID,
        *,
        expected_version: int | None,
    ) -> tuple[EvidenceAnalystDecision, int]:
        """Run bounded, accounted structured-output attempts.

        Each attempt first builds its deterministic prompt, then durably
        reserves exactly one LLM call, then invokes the model once. A
        prompt-construction failure consumes no budget and no model call is
        attempted; the returned version chains through the attempts and into
        the final persistence guard.
        """
        latest_version: int | None = expected_version
        for attempt in range(1, self._max_structured_output_attempts + 1):
            # Build this attempt's deterministic prompt BEFORE durably
            # reserving its model invocation: a prompt-construction failure is
            # a local application/input-rendering defect that must consume no
            # LLM budget and never reach the model boundary. A reservation is
            # written only immediately before entering the LlmClient, so a
            # failed repair-prompt build can never reserve a nonexistent
            # repair call while the prior real attempt stays accounted.
            system_prompt, user_prompt = build_evidence_analyst_prompts(
                analyst_input, repair=attempt > 1
            )
            latest_version = await self._llm_accounting.reserve_call(
                investigation_id, expected_version=latest_version
            )
            try:
                decision = await self._llm_client.generate_structured(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=EvidenceAnalystDecision,
                    operation_name=OPERATION_EVIDENCE_ANALYSIS,
                )
            except asyncio.CancelledError:  # pylint: disable=try-except-raise
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
            return decision, latest_version
        raise LlmError(  # pragma: no cover - the loop always returns or raises
            LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False
        )

    async def _persist_decision(
        self,
        analyst_input: EvidenceAnalystInput,
        decision: EvidenceAnalystDecision,
        *,
        latest_version: int,
        actor_id: UUID | None,
        request_id: UUID | None,
    ) -> Assessment:
        """Stamp authoritative IDs and persist once through the PR 20A seam."""
        assessment = Assessment(
            investigation_id=analyst_input.investigation_id,
            analyzed_evidence_ids=tuple(
                item.evidence_id for item in analyst_input.evidence
            ),
            verdict=decision.verdict,
            confidence=decision.confidence,
            summary=decision.summary,
            findings=decision.findings,
            limitations=decision.limitations,
            unresolved_questions=decision.unresolved_questions,
            recommended_next_steps=decision.recommended_next_steps,
        )
        return await self._assessment_persistence.persist_assessment(
            assessment,
            actor_id=actor_id,
            request_id=request_id,
            expected_investigation_version=latest_version,
        )

    async def _persist_no_evidence(
        self,
        analyst_input: EvidenceAnalystInput,
        *,
        actor_id: UUID | None,
        request_id: UUID | None,
        expected_investigation_version: int | None,
    ) -> Assessment:
        """Persist the deterministic no-evidence INCONCLUSIVE Assessment.

        No model call is spent to rediscover a structural fact already encoded
        in the domain, and the caller's expected Investigation version still
        guards this persistence.
        """
        assessment = Assessment(
            investigation_id=analyst_input.investigation_id,
            verdict=Verdict.INCONCLUSIVE,
            confidence=AssessmentConfidence.LOW,
            summary=_NO_EVIDENCE_SUMMARY,
            analyzed_evidence_ids=(),
            limitations=(_NO_EVIDENCE_LIMITATION,),
        )
        return await self._assessment_persistence.persist_assessment(
            assessment,
            actor_id=actor_id,
            request_id=request_id,
            expected_investigation_version=expected_investigation_version,
        )
