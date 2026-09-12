# SPDX-License-Identifier: AGPL-3.0-only
"""The Report Writer application execution service (PR 23B).

Execution path:

```text
ReportWriterInputLoader (read-only UnitOfWork, then closed)
 -> deterministic prompt
 -> LlmAccountingService.reserve_call (short durable reservation)
 -> LlmClient.generate_structured
 -> ReportWriterOutput (semantic output only)
 -> build_investigation_report (application stamping)
 -> ReportProvenanceValidator (deterministic closure)
 -> InvestigationReportPersistenceService (one short atomic transaction)
 -> persisted InvestigationReport + Investigation report pointer
```

LLM calls happen strictly outside database transactions. Every actual model
invocation is durably reserved against the Investigation LLM budget before
the call; structured-output repair is explicit and bounded to at most one
repair. No report row, history, or pointer update exists until provenance
validation and the atomic persistence transaction succeed.

The Report Writer does not collect Evidence, perform RAG retrieval, change
investigation policy, determine the analytical verdict, or create new
threat-intelligence facts. The current persisted Assessment remains the sole
authority for verdict and confidence, which are application-stamped into the
final report and never authored by the model.
"""

from __future__ import annotations

import asyncio
from uuid import UUID

from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.llm import LlmClient, LlmError, LlmErrorCode
from agentic_threat_investigator.app.report_writer.input_loader import (
    ReportWriterInputLoader,
)
from agentic_threat_investigator.app.report_writer.persistence import (
    InvestigationReportPersistenceService,
)
from agentic_threat_investigator.app.report_writer.prompts import (
    OPERATION_REPORT_WRITING,
    build_report_writer_prompts,
)
from agentic_threat_investigator.app.report_writer.validator import (
    ReportProvenanceValidator,
    build_investigation_report,
)
from agentic_threat_investigator.domain.report import (
    InvestigationReport,
    ReportWriterInput,
    ReportWriterOutput,
)


class ReportWriter:
    """Run one structured Report Writer execution for an Investigation.

    ``max_structured_output_attempts`` bounds the explicit schema-repair
    policy: one initial attempt plus at most ``max_attempts - 1`` repairs,
    each a separately counted model invocation.
    """

    def __init__(
        self,
        *,
        input_loader: ReportWriterInputLoader,
        llm_client: LlmClient,
        report_persistence: InvestigationReportPersistenceService,
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
        self._report_persistence = report_persistence
        self._llm_accounting = llm_accounting
        self._max_structured_output_attempts = max_structured_output_attempts

    async def write(
        self,
        investigation_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_investigation_version: int | None = None,
    ) -> InvestigationReport:
        """Write one new report version for the Investigation.

        The input snapshot is materialized in a short read-only transaction
        (failing with a typed error when the Investigation has no current
        Assessment — no LLM call is spent), then bounded structured output is
        generated under durable LLM accounting with at most one schema
        repair, the authoritative report is assembled and provenance
        validated, and one short atomic transaction persists the report and
        advances the Investigation ``report_id`` pointer.

        Every explicit call to ``write`` creates a new report version;
        unchanged source input is never silently reused.
        """
        report_input = await self._input_loader.load(investigation_id)
        output, latest_version = await self._generate_output(
            report_input,
            investigation_id,
            expected_version=expected_investigation_version,
        )
        report = build_investigation_report(report_input, output)
        ReportProvenanceValidator().validate(report, report_input)
        return await self._report_persistence.persist(
            report,
            actor_id=actor_id,
            request_id=request_id,
            expected_investigation_version=latest_version,
        )

    async def _generate_output(
        self,
        report_input: ReportWriterInput,
        investigation_id: UUID,
        *,
        expected_version: int | None,
    ) -> tuple[ReportWriterOutput, int]:
        """Run bounded, accounted structured-output attempts.

        Each attempt first builds its deterministic prompt, then durably
        reserves exactly one LLM call, then invokes the model once. A
        prompt-construction failure consumes no budget and no model call is
        attempted; the returned version chains through the attempts so a
        repair attempt is separately counted.
        """
        latest_version: int | None = expected_version
        for attempt in range(1, self._max_structured_output_attempts + 1):
            system_prompt, user_prompt = build_report_writer_prompts(
                report_input, repair=attempt > 1
            )
            latest_version = await self._llm_accounting.reserve_call(
                investigation_id, expected_version=latest_version
            )
            try:
                output = await self._llm_client.generate_structured(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=ReportWriterOutput,
                    operation_name=OPERATION_REPORT_WRITING,
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
            self._latest_version = latest_version
            return output, latest_version
        raise LlmError(  # pragma: no cover - the loop always returns or raises
            LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False
        )
