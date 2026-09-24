# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30E narrow evaluation composition seam (Report Writer target).

Wires the existing production Report Writer pieces into the evaluation
target without creating any benchmark-only writer:

```text
ReportWriterInputLoader          (read-only input materialization)
InvestigationReportPersistenceService (existing atomic report persistence)
LlmAccountingService             (existing Investigation-wide budget)
+ injected LlmClient
        -> ReportWriter
```

The counting decorator (:class:`CountingLlmClient`) observes the exact
current-execution model-attempt count through the same ``LlmClient`` seam the
production writer uses; it never alters prompts, outputs, retries, or
exceptions. No database transaction ever spans a model call here: the
composition only binds services that already keep their own short
transactions (input load, accounting reservation, and report persistence).
"""

from __future__ import annotations

from collections.abc import Callable

from agentic_threat_investigator.app.llm import LlmClient, ResponseT
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.report_writer.writer import ReportWriter
from agentic_threat_investigator.infrastructure.report_writer_composition import (
    build_report_writer,
)


class CountingLlmClient(LlmClient):
    """Transparent counting decorator over the real ``LlmClient`` boundary.

    Counts every actual model invocation for the current execution without
    changing prompts, response models, retry/repair behavior, or exception
    propagation. ``calls`` is an exact current-execution count; it is never
    inferred from telemetry or LangSmith.
    """

    def __init__(self, delegate: LlmClient) -> None:
        """Bind the production client and initialize the exact call count."""
        self._delegate = delegate
        self.calls = 0

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Record one attempt and delegate unchanged (errors propagate as-is)."""
        self.calls += 1
        return await self._delegate.generate_structured(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            operation_name=operation_name,
        )


def compose_report_writer_target(
    *,
    uow_factory: Callable[[], UnitOfWork],
    llm_client: LlmClient,
    batch_size: int = 100,
    max_structured_output_attempts: int = 2,
) -> tuple[ReportWriter, CountingLlmClient]:
    """Compose the production Report Writer over an injected ``LlmClient``.

    Returns the writer and its exact per-execution counting client. The
    writer is built through the existing ``infrastructure.report_writer_composition``
    seam, so input loading, accounting, provenance validation, and atomic
    report persistence are exactly the production implementations.
    """
    counting = CountingLlmClient(llm_client)
    writer = build_report_writer(
        uow_factory=uow_factory,
        llm_client=counting,
        batch_size=batch_size,
        max_structured_output_attempts=max_structured_output_attempts,
    )
    return writer, counting


def default_writer_factory(
    *,
    uow_factory: Callable[[], UnitOfWork],
    batch_size: int = 100,
    max_structured_output_attempts: int = 2,
) -> Callable[[LlmClient], ReportWriter]:
    """Return a factory that builds one fresh production Report Writer.

    The factory consumes the counting-wrapped ``LlmClient`` (already observed
    by the executor) and builds exactly the production writer through the
    infrastructure seam.
    """

    def build(llm_client: LlmClient) -> ReportWriter:
        """Build one fresh production Report Writer bound to the client."""
        return build_report_writer(
            uow_factory=uow_factory,
            llm_client=llm_client,
            batch_size=batch_size,
            max_structured_output_attempts=max_structured_output_attempts,
        )

    return build


__all__ = [
    "CountingLlmClient",
    "compose_report_writer_target",
    "default_writer_factory",
]
