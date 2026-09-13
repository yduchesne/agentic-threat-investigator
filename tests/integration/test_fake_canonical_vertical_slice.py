# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical fake-mode HTTP -> durable job -> worker -> HTTP vertical slice.

Runs the primary F02 malicious multi-source scenario through the exact
backend environment PR 24 will consume, over real PostgreSQL:

```text
HTTP client -> login -> POST /api/v1/investigations (Idempotency-Key)
  -> durable investigation_job -> InvestigationJobWorker
  -> LocalInvestigationRunner -> production coordinator graph
  -> RegistryProviderWorkPlanner -> LocalTaskDispatcher
  -> ProviderWorkExecutor -> fake EvidenceProvider implementations
  -> real extraction/persistence -> real research path
  -> FakeLlmClient at the LLM boundary -> real Assessment persistence
  -> terminal Investigation -> HTTP GET reads
```

Assertions follow PR 23D plan section 9 (canonical slice) and the F02
demo-readiness acceptance rules.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.config import OperatingMode
from agentic_threat_investigator.domain.assessment import Verdict
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationStatus,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeWorldCatalog,
)
from tests.integration.api_helpers import (
    api_client,
    api_settings,
    csrf_headers,
    seed_user,
)
from tests.integration.fake_runtime_helpers import (
    FIXED_TS,
    analysis_decision,
    build_fake_mode_worker,
)


def _fake_api_settings() -> Any:
    """Return API settings with the fake operating mode selected."""
    return api_settings().model_copy(update={"operating_mode": OperatingMode.FAKE})


pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

F02_ROOT_DOMAIN = "update-package.test"
F02_MALWARE = "malware.badloader_v2"
F02_SHARED_ASN = "AS64500"
F02_SHARED_PREFIX = "203.0.113.0/24"


async def _move_to_running(
    uow_factory: Callable[[], Any], investigation_id: UUID
) -> None:
    """Advance the PENDING Investigation to RUNNING (confirmed lifecycle)."""
    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(investigation_id)
        assert durable is not None
        assert durable.version is not None
        await uow.investigations.update_status(
            investigation_id,
            InvestigationStatus.RUNNING,
            expected_version=durable.version,
        )


def _enqueue_f02_decisions(llm: Any) -> None:
    """Script the deterministic F02 analyst trajectory.

    Three needs-more-evidence rounds drive three bounded pivots — the
    resolved IP (multi-hop prefix discovery), the CNAME target, and the
    benign-looking MX neighbor (dead-end) — and the final round is a
    sufficient malicious verdict. The research path uses the empty corpus:
    it persists a zero-claim result without any LLM call.
    """
    llm.enqueue(
        analysis_decision(disposition="needs_more_evidence", summary="first round")
    )
    llm.enqueue(
        analysis_decision(disposition="needs_more_evidence", summary="second round")
    )
    llm.enqueue(
        analysis_decision(disposition="needs_more_evidence", summary="third round")
    )
    llm.set_default(
        analysis_decision(
            verdict="malicious",
            confidence="high",
            disposition="sufficient",
            summary="correlated multi-source evidence is sufficient",
        )
    )


async def test_f02_canonical_fake_mode_vertical_slice(
    session_factory: Any, uow_factory: Callable[[], Any]
) -> None:
    """F02 through HTTP -> durable job -> worker -> runner -> HTTP reads."""
    await seed_user(session_factory)

    # 1-3. HTTP creation returns 202 with a persisted PENDING Investigation.
    with api_client(_fake_api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        response = client.post(
            "/api/v1/investigations",
            json={
                "indicators": [{"type": "domain", "value": F02_ROOT_DOMAIN}],
                "objective": "assess the update-package delivery domain",
            },
            headers={"Idempotency-Key": "f02-slice-1", **csrf_headers(client)},
        )
        assert response.status_code == 202
        investigation_id = UUID(response.json()["id"])
        assert response.json()["status"] == "pending"

        # 4. Exactly one durable logical job exists; the runner has not run.
        async with uow_factory() as uow:
            job = await uow.investigation_jobs.get_by_investigation(investigation_id)
            assert job is not None
            assert job.status.value == "pending"
            durable = await uow.investigations.get_by_id(investigation_id)
            assert durable is not None
            assert durable.status is InvestigationStatus.PENDING

    await _move_to_running(uow_factory, investigation_id)

    # 5-6. Worker claims and executes the durable job against the fake
    # intelligence sources; FakeLlmClient is the only faked boundary.
    worker, llm = build_fake_mode_worker(uow_factory, session_factory, clock=FIXED_TS)
    _enqueue_f02_decisions(llm)
    executed = await worker.claim_and_run_once()
    assert executed == investigation_id

    # 7. Terminal durable state and succeeded job.
    async with uow_factory() as uow:
        terminal = await uow.investigations.get_by_id(investigation_id)
        assert terminal is not None
        assert terminal.status is InvestigationStatus.COMPLETED
        assert terminal.completed_at is not None
        completed_job = await uow.investigation_jobs.get_by_investigation(
            investigation_id
        )
        assert completed_job is not None
        assert completed_job.status.value == "succeeded"

    # 8. FakeLlmClient received only bounded evidence-analysis calls.
    assert llm.calls
    for call in llm.calls:
        assert call.operation_name == "urn:ati:llm:evidence_analysis"

    # 9-14. HTTP reads resolve the persisted analyst artifacts.
    with api_client(_fake_api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        detail = client.get(f"/api/v1/investigations/{investigation_id}")
        timeline = client.get(
            f"/api/v1/investigations/{investigation_id}/timeline", params={"limit": 200}
        )
        evidence = client.get(f"/api/v1/investigations/{investigation_id}/evidence")
        relationships = client.get(
            f"/api/v1/investigations/{investigation_id}/relationships"
        )
        observations = client.get(
            f"/api/v1/investigations/{investigation_id}/relationship-observations"
        )
        research = client.get(f"/api/v1/investigations/{investigation_id}/research")
        assessments = client.get(
            f"/api/v1/investigations/{investigation_id}/assessments"
        )
        current = client.get(
            f"/api/v1/investigations/{investigation_id}/assessments/current"
        )
        reports = client.get(f"/api/v1/investigations/{investigation_id}/reports")
        runtime = client.get("/api/v1/runtime")

    assert detail.status_code == 200
    assert detail.json()["status"] == "completed"
    assert detail.json()["version"] > 1

    assert timeline.status_code == 200
    event_types = {item["type"] for item in timeline.json()["items"]}
    assert InvestigationTimelineEventType.INVESTIGATION_STOPPED.value in event_types
    assert InvestigationTimelineEventType.ASSESSMENT_REQUESTED.value in event_types
    assert InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED.value in event_types
    assert InvestigationTimelineEventType.RESEARCH_REQUESTED.value in event_types

    # Evidence: a deterministic mixture of signal, inconclusive, and ambient.
    assert evidence.status_code == 200
    evidence_items = evidence.json()["items"]
    sources = {item["source"] for item in evidence_items}
    assert "urn:ati:source:google_public_dns" in sources
    assert "urn:ati:source:threatfox" in sources
    assert "urn:ati:source:rdap" in sources
    assert "urn:ati:source:abuseipdb" in sources
    # Ambient/noise evidence (marketing TXT) coexists with signal evidence.
    assert any("newsletter" in str(item["facts"]) for item in evidence_items)
    # No raw provider payload or synthetic marker ever reaches the API.
    for item in evidence_items:
        assert "raw_payload" not in item
        assert "synthetic_world" not in str(item)
        assert item["source_url"] is None

    # Relationships: stable identities plus shared infrastructure.
    assert relationships.status_code == 200
    relationship_items = relationships.json()["items"]
    relationship_types = {item["type"] for item in relationship_items}
    assert "urn:ati:relationship:dns:resolves_to" in relationship_types
    assert "urn:ati:relationship:dns:cname_of" in relationship_types
    assert "urn:ati:relationship:threat:associated_with" in relationship_types
    assert "urn:ati:relationship:dns:uses_mail_server" in relationship_types
    assert "urn:ati:relationship:dns:uses_name_server" in relationship_types
    assert "urn:ati:relationship:network:belongs_to" in relationship_types

    # RelationshipObservations preserve observed_at separately from retrieved_at.
    assert observations.status_code == 200
    observation_items = observations.json()["items"]
    assert observation_items
    for item in observation_items:
        assert item["observed_at"] is not None
        assert item["observed_at"] != item["retrieved_at"]

    # Research remains Research, never Evidence.
    assert research.status_code == 200
    research_items = research.json()["items"]
    assert research_items
    evidence_ids = {item["id"] for item in evidence_items}
    research_ids = {item["id"] for item in research_items}
    assert not (evidence_ids & research_ids)

    # Assessment is current through the durable pointer.
    assert assessments.status_code == 200
    assert current.status_code == 200
    current_assessment = current.json()
    assert current_assessment["verdict"] == Verdict.MALICIOUS.value
    assert current_assessment["confidence"] == "high"
    assert current_assessment["version"] >= 1
    assessment_ids = {item["id"] for item in assessments.json()["items"]}
    assert current_assessment["id"] in assessment_ids

    # Report list endpoint remains available without invoking an LLM.
    assert reports.status_code == 200

    # Runtime metadata reports fake and nothing else.
    assert runtime.status_code == 200
    assert runtime.json() == {"operating_mode": "fake"}

    # 17. HTTP responses expose no raw provider payload or secrets.
    for response in (detail, evidence, relationships, observations, current):
        assert "secret" not in str(response.json()).lower()
        assert "api_key" not in str(response.json()).lower()
        assert "password" not in str(response.json()).lower()

    # 18. Repeated idempotent POST returns the same Investigation.
    with api_client(_fake_api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        replay = client.post(
            "/api/v1/investigations",
            json={
                "indicators": [{"type": "domain", "value": F02_ROOT_DOMAIN}],
                "objective": "assess the update-package delivery domain",
            },
            headers={"Idempotency-Key": "f02-slice-1", **csrf_headers(client)},
        )
    assert replay.status_code == 202
    assert UUID(replay.json()["id"]) == investigation_id


async def test_f02_shared_world_contains_signal_and_noise(
    session_factory: Any, uow_factory: Callable[[], Any]
) -> None:
    """F02 world data supports a multi-hop path and shared infrastructure.

    Direct catalog lookups prove the scenario-defining signal, the
    relevant-but-inconclusive shared infrastructure, the benign/dead-end
    branches, and the later-hop world data (23D-I14..I17).
    """
    del session_factory
    catalog = FakeWorldCatalog.load_packaged()
    root = catalog.provider_response(
        "urn:ati:source:threatfox",
        EntityType.DOMAIN,
        F02_ROOT_DOMAIN,
        FIXED_TS,
    )
    assert root.observations
    assert root.observations[0].facts["matches"][0]["malware"] == F02_MALWARE

    # Second-hop world data: the ASN resolves deterministically.
    asn = catalog.provider_response(
        "urn:ati:source:rdap", EntityType.ASN, F02_SHARED_ASN, FIXED_TS
    )
    assert asn.observations

    # Benign/dead-end pivot: mail-01.test has no malicious signal.
    dead_end = catalog.provider_response(
        "urn:ati:source:threatfox", EntityType.DOMAIN, "mail-01.test", FIXED_TS
    )
    assert dead_end.observations == ()
    assert dead_end.error is None

    # Explicit no-result provider (23D-I08-style): threatfox on the benign IP.
    no_result = catalog.provider_response(
        "urn:ati:source:threatfox", EntityType.IP_ADDRESS, "203.0.113.10", FIXED_TS
    )
    assert no_result.observations == ()
    assert no_result.error is None

    # Shared prefix spans benign and suspicious hosts without labeling.
    shared = catalog.provider_response(
        "urn:ati:source:rdap", EntityType.IP_ADDRESS, "203.0.113.81", FIXED_TS
    )
    assert shared.observations
    assert shared.observations[0].facts["cidr0_cidrs"][0] == {
        "prefix": "203.0.113.0",
        "length": 24,
    }
    benign = catalog.provider_response(
        "urn:ati:source:rdap", EntityType.IP_ADDRESS, "203.0.113.10", FIXED_TS
    )
    assert (
        benign.observations[0].facts["cidr0_cidrs"][0]
        == shared.observations[0].facts["cidr0_cidrs"][0]
    )
