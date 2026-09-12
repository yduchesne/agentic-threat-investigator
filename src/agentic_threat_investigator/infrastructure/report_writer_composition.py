# SPDX-License-Identifier: AGPL-3.0-only
"""Production composition seam for the standalone Report Writer (PR 23B).

Wires the existing production report pieces into one :class:`ReportWriter`:

```text
ReportWriterInputLoader          (read-only input materialization)
InvestigationReportPersistenceService (existing atomic report persistence)
LlmAccountingService             (existing Investigation-wide budget)
+ injected LlmClient
        -> ReportWriter
```

PR 23B deliberately does NOT add the Report Writer to the Coordinator/LangGraph
production graph; this narrow factory exists so a future bootstrap (or PR 23C
orchestration) can obtain a fully wired service object without knowing input
loading, prompt, model-provider, or report-repository details.
"""

from __future__ import annotations

from collections.abc import Callable

from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.llm import LlmClient
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.report_writer.input_loader import (
    ReportWriterInputLoader,
)
from agentic_threat_investigator.app.report_writer.persistence import (
    InvestigationReportPersistenceService,
)
from agentic_threat_investigator.app.report_writer.writer import ReportWriter


def build_report_writer(
    *,
    uow_factory: Callable[[], UnitOfWork],
    llm_client: LlmClient,
    batch_size: int = 100,
    max_findings: int = 50,
    max_evidence: int = 100,
    max_relationship_observations: int = 200,
    max_research_results: int = 20,
    max_research_claims: int = 100,
    max_input_bytes: int = 262_144,
    max_structured_output_attempts: int = 2,
) -> ReportWriter:
    """Assemble a fully wired ReportWriter from its production seams.

    ``uow_factory`` supplies both the short input-materialization read scope
    and the short report-persistence transaction; ``llm_client`` is the
    existing injected structured-output client. No global state is created
    and no reading of environment/configuration happens here.
    """
    return ReportWriter(
        input_loader=ReportWriterInputLoader(
            uow_factory,
            max_findings=max_findings,
            max_evidence=max_evidence,
            max_relationship_observations=max_relationship_observations,
            max_research_results=max_research_results,
            max_research_claims=max_research_claims,
            max_serialized_input_bytes=max_input_bytes,
        ),
        llm_client=llm_client,
        report_persistence=InvestigationReportPersistenceService(
            uow_factory, batch_size=batch_size
        ),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=max_structured_output_attempts,
    )
