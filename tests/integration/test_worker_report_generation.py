# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Worker-level Report generation wiring (PR 24B deterministic E2E boundary).

Composes the exact worker seam the ``ati-worker`` entrypoint now wires: the
production runner over the packaged fake world, the durable job worker, and
the production Report Writer sharing one :class:`DeterministicLlmClient`
model boundary. Over real PostgreSQL and the canonical F02 malicious
multi-source scenario the worker must reach a terminal Investigation with a
current Assessment AND a persisted current Report that the HTTP read path
returns with executive summary, findings, and support references.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

import pytest

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
from agentic_threat_investigator.cli import _write_missing_current_report
from agentic_threat_investigator.config import OperatingMode, Settings
from agentic_threat_investigator.domain.assessment import Verdict
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeWorldCatalog,
)
from agentic_threat_investigator.infrastructure.intelligence_composition import (
    build_fake_intelligence_sources,
)
from agentic_threat_investigator.infrastructure.llm.deterministic import (
    DeterministicLlmClient,
)
from agentic_threat_investigator.infrastructure.report_writer_composition import (
    build_report_writer,
)
from agentic_threat_investigator.infrastructure.research_agent_composition import (
    build_research_agent,
)
from tests.integration.api_helpers import (
    api_client,
    api_settings,
    csrf_headers,
    seed_user,
)
from tests.integration.fake_runtime_helpers import FIXED_TS

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

F02_ROOT_DOMAIN = "update-package.test"
F02_OBJECTIVE = "assess the update-package delivery domain"


def _fake_api_settings() -> Any:
    """Return API settings with the fake operating mode selected."""
    return api_settings().model_copy(update={"operating_mode": OperatingMode.FAKE})


async def test_f02_worker_writes_current_report(
    session_factory: Any, uow_factory: Callable[[], Any]
) -> None:
    """F02 -> durable job -> worker -> terminal -> Report -> HTTP reads."""
    await seed_user(session_factory)

    # HTTP creation returns 202 with a persisted PENDING Investigation.
    with api_client(_fake_api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        response = client.post(
            "/api/v1/investigations",
            json={
                "indicators": [{"type": "domain", "value": F02_ROOT_DOMAIN}],
                "objective": F02_OBJECTIVE,
            },
            headers={"Idempotency-Key": "f02-report-wiring-1", **csrf_headers(client)},
        )
        assert response.status_code == 202
        investigation_id = UUID(response.json()["id"])

    # The durable worker claims the job and advances the confirmed
    # PENDING -> RUNNING lifecycle itself before invoking the runner.

    # Worker composition mirrors `ati-worker`: production runner + report
    # writer sharing one deterministic offline model boundary.
    llm = DeterministicLlmClient()
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
        catalog=FakeWorldCatalog.load_packaged(),
        clock=lambda: FIXED_TS,
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
        clock=lambda: FIXED_TS,
        recursion_limit=120,
    )
    worker = InvestigationJobWorker(
        uow_factory=uow_factory, runner=runner, clock=lambda: FIXED_TS
    )
    report_writer = build_report_writer(uow_factory=uow_factory, llm_client=llm)

    executed = await worker.claim_and_run_once()
    assert executed == investigation_id

    # The worker post-step writes the current Report for the terminal
    # Investigation.
    await _write_missing_current_report(investigation_id, uow_factory, report_writer)

    with api_client(_fake_api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        detail = client.get(f"/api/v1/investigations/{investigation_id}")
        current = client.get(
            f"/api/v1/investigations/{investigation_id}/assessments/current"
        )
        report = client.get(
            f"/api/v1/investigations/{investigation_id}/reports/current"
        )
        markdown = client.get(
            f"/api/v1/investigations/{investigation_id}/reports/"
            f"{report.json()['id']}/markdown"
        )

    assert detail.status_code == 200
    assert detail.json()["status"] == "completed"
    assert detail.json()["report_id"] is not None

    assert current.status_code == 200
    assert current.json()["verdict"] == Verdict.MALICIOUS.value
    assert current.json()["confidence"] == "high"
    assert current.json()["findings"]

    assert report.status_code == 200
    report_body = report.json()
    assert report_body["verdict"] == Verdict.MALICIOUS.value
    assert report_body["confidence"] == "high"
    assert report_body["title"] == "ATI deterministic investigation report"
    assert report_body["executive_summary"]
    assert report_body["findings"]
    for finding in report_body["findings"]:
        assert finding["support"]
        for support in finding["support"]:
            assert support["kind"] in {"evidence", "relationship_observation"}
    assert report_body["research_context"] == []

    # Deterministic Markdown renders the persisted report without an LLM.
    assert markdown.status_code == 200
    assert "ATI deterministic investigation report" in markdown.text
