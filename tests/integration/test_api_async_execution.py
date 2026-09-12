# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical asynchronous vertical slice (PR 23C Phase 11).

Proves the complete boundary over real PostgreSQL through production seams:

1. POST /api/v1/auth/login
2. POST /api/v1/investigations with Idempotency-Key
3. HTTP returns 202 after durable persistence (Investigation PENDING + job)
4. production worker claim path runs (durable job claim)
5. worker invokes InvestigationRunner
6. deterministic orchestration runs against synthetic providers/FakeLlmClient
7. Investigation reaches a terminal state
8. GET investigation / timeline / evidence / assessment / report

The API half proves the HTTP request never executes LangGraph; the worker
half proves the exact persisted Investigation is executable through
``InvestigationRunner``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
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
from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderResult,
)
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationStatus,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.integration.api_helpers import (
    api_client,
    api_settings,
    create_payload,
    csrf_headers,
    seed_user,
)
from tests.support.llm_fixtures import FakeLlmClient

_FIXED_TS = datetime(2026, 1, 1, tzinfo=UTC)


class _ScriptedDnsProvider(EvidenceProvider):
    """Deterministic provider returning one DNS Evidence observation.

    The provider exercises the production provider-execution path: the
    coordinator plans the work, the executor persists the Evidence and
    updates the Investigation's operational evidence list, then the analysis
    node runs against real persistence.
    """

    def __init__(self) -> None:
        """Bind an empty call log."""
        self.calls: list[tuple[UUID, Entity]] = []

    @property
    def id(self) -> str:
        """Return the stable Google DNS source URN."""
        return SourceId.GOOGLE_PUBLIC_DNS.value

    def supports(self, entity: Entity) -> bool:
        """Support DOMAIN entities only."""
        return entity.type is EntityType.DOMAIN

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Return one normalized A-record observation for the domain."""
        self.calls.append((investigation_id, entity))
        assert entity.id is not None
        evidence = Evidence(
            investigation_id=investigation_id,
            type=EvidenceType.DNS,
            subject=EntityRef(id=entity.id, type=entity.type, value=entity.value),
            source=SourceId.GOOGLE_PUBLIC_DNS.value,
            retrieved_at=_FIXED_TS,
            facts={
                "query_name": entity.value,
                "query_type": "A",
                "status": 0,
                "flags": {"rd": True, "ra": True},
                "answers": [
                    {
                        "name": entity.value,
                        "record_type": "A",
                        "ttl": 300,
                        "value": "192.0.2.42",
                    }
                ],
            },
        )
        return ProviderResult(
            provider=SourceId.GOOGLE_PUBLIC_DNS.value,
            evidence=(evidence,),
        )


def _analyst_for(session_factory: Any, llm: FakeLlmClient) -> EvidenceAnalyst:
    """Build a real Evidence Analyst wired to real persistence services."""
    return EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(
            lambda: PostgresUnitOfWork(session_factory)
        ),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            lambda: PostgresUnitOfWork(session_factory),
            batch_size=100,
        ),
        llm_accounting=LlmAccountingService(
            lambda: PostgresUnitOfWork(session_factory)
        ),
        max_structured_output_attempts=2,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_async_vertical_slice(
    session_factory: Any, uow_factory: Callable[[], PostgresUnitOfWork]
) -> None:
    """POST -> durable job -> worker -> InvestigationRunner -> GET."""
    await seed_user(session_factory)

    # 1-3. HTTP creation returns 202 with a persisted PENDING Investigation.
    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        response = client.post(
            "/api/v1/investigations",
            json=create_payload(),
            headers={"Idempotency-Key": "slice-1", **csrf_headers(client)},
        )
        assert response.status_code == 202
        investigation_id = UUID(response.json()["id"])
        assert response.json()["status"] == "pending"

        # 4. The durable job exists and is pending; the runner has not run.
        async with uow_factory() as uow:
            job = await uow.investigation_jobs.get_by_investigation(investigation_id)
            assert job is not None
            assert job.status.value == "pending"
            # The API request must not have executed the Investigation.
            durable = await uow.investigations.get_by_id(investigation_id)
            assert durable is not None
            assert durable.status is InvestigationStatus.PENDING
            # Move the PENDING Investigation to RUNNING so the runner can
            # execute it (the confirmed lifecycle: pending -> running).
            assert durable.version is not None
            await uow.investigations.update_status(
                investigation_id,
                InvestigationStatus.RUNNING,
                expected_version=durable.version,
            )

    # 5-6. Production worker claim path: claim the durable job, invoke the
    # production runner against deterministic external fakes (synthetic
    # provider registry, FakeLlmClient-backed real Evidence Analyst).
    llm = FakeLlmClient()
    llm.set_default(
        __import__(
            "agentic_threat_investigator.domain.analyst",
            fromlist=["EvidenceAnalystDecision"],
        ).EvidenceAnalystDecision(
            verdict=Verdict.SUSPICIOUS,
            confidence=AssessmentConfidence.MEDIUM,
            summary="synthetic sufficient analysis",
            disposition=__import__(
                "agentic_threat_investigator.domain.investigation",
                fromlist=["AnalysisDisposition"],
            ).AnalysisDisposition.SUFFICIENT,
        )
    )
    analyst = _analyst_for(session_factory, llm)
    provider = _ScriptedDnsProvider()
    runner = LocalInvestigationRunner(
        uow_factory=uow_factory,
        provider_registry={SourceId.GOOGLE_PUBLIC_DNS: provider},
        analysis_executor_factory=lambda bound: EvidenceAnalystAnalysisExecutor(
            analyst, bound_investigation_id=bound
        ),
        clock=lambda: _FIXED_TS,
        recursion_limit=40,
    )
    worker = InvestigationJobWorker(
        uow_factory=uow_factory, runner=runner, clock=lambda: _FIXED_TS
    )

    executed = await worker.claim_and_run_once()
    assert executed == investigation_id

    # 7. The Investigation reached a terminal state durably.
    async with uow_factory() as uow:
        terminal = await uow.investigations.get_by_id(investigation_id)
        assert terminal is not None
        assert terminal.status in (
            InvestigationStatus.COMPLETED,
            InvestigationStatus.PARTIAL,
        )
        assert terminal.completed_at is not None
        completed_job = await uow.investigation_jobs.get_by_investigation(
            investigation_id
        )
        assert completed_job is not None
        assert completed_job.status.value == "succeeded"

    # 8. HTTP reads resolve the persisted terminal state.
    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        detail = client.get(f"/api/v1/investigations/{investigation_id}")
        timeline = client.get(f"/api/v1/investigations/{investigation_id}/timeline")
        evidence = client.get(f"/api/v1/investigations/{investigation_id}/evidence")
        assessments = client.get(
            f"/api/v1/investigations/{investigation_id}/assessments"
        )
        reports = client.get(f"/api/v1/investigations/{investigation_id}/reports")

    assert detail.status_code == 200
    assert detail.json()["status"] in ("completed", "partial")
    assert detail.json()["version"] > 1
    assert timeline.status_code == 200
    event_types = {item["type"] for item in timeline.json()["items"]}
    # Observable terminal workflow events are present; hidden reasoning is
    # never part of the public timeline.
    assert InvestigationTimelineEventType.INVESTIGATION_STOPPED.value in event_types
    assert InvestigationTimelineEventType.ASSESSMENT_REQUESTED.value in event_types
    assert evidence.status_code == 200
    assert assessments.status_code == 200
    assert len(assessments.json()["items"]) >= 1
    # Reports are generated by a separate writer step (PR 24 scope); the
    # version list endpoint still serves its contract.
    assert reports.status_code == 200
