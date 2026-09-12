# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL API subresource integration tests (23C-I06..I10).

Seeds a complete Investigation (Evidence, Relationships, Observations,
ResearchResults, Assessments, Reports, Timeline) through the production
repositories, then exercises the HTTP collection/detail routes through the
real PR 23A/23B services. Proves cursor survival, raw-payload exclusion,
durable current pointers, history redaction, and deterministic Markdown.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.domain.relationships import RelationshipType
from agentic_threat_investigator.domain.report import InvestigationReport
from agentic_threat_investigator.domain.research import ResearchResult
from tests.integration.api_helpers import (
    api_client,
    api_settings,
    seed_user,
)
from tests.support.query_fixtures import (
    evidence_factory,
    seed_entity,
    seed_investigation,
    seed_observation,
    seed_relationship,
)

FIXED = datetime(2026, 1, 1, tzinfo=UTC)


def _assessment(investigation_id: UUID) -> Assessment:
    """Build one structurally valid INCONCLUSIVE Assessment version."""
    return Assessment(
        investigation_id=investigation_id,
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="synthetic inconclusive assessment",
        analyzed_evidence_ids=(),
    )


def _report(
    investigation_id: UUID, assessment_id: UUID, title: str
) -> InvestigationReport:
    """Build one structurally valid report version."""
    return InvestigationReport(
        investigation_id=investigation_id,
        assessment_id=assessment_id,
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        title=title,
    )


async def _version(uow: Any, investigation_id: UUID) -> int:
    """Return the authoritative persisted version of one Investigation."""
    state = await uow.investigations.get_by_id(investigation_id)
    assert state is not None and state.version is not None
    return int(state.version)


async def _seed_complete_investigation(uow: Any) -> UUID:
    """Seed one Investigation with every analytical subresource."""
    investigation_id = await seed_investigation(uow)
    domain_entity = await seed_entity(uow, value="example.com")
    ip_entity = await seed_entity(
        uow, entity_type=EntityType.IP_ADDRESS, value="192.0.2.1"
    )

    evidence = await uow.evidence.insert(
        evidence_factory(investigation_id, domain_entity, retrieved_at=FIXED)
    )
    later_evidence = await uow.evidence.insert(
        evidence_factory(
            investigation_id,
            domain_entity,
            source="urn:ati:source:rdap",
            evidence_type=EvidenceType.REGISTRATION,
            retrieved_at=datetime(2026, 1, 2, tzinfo=UTC),
        )
    )
    assert evidence.id is not None and later_evidence.id is not None

    relationship = await seed_relationship(
        uow,
        source_entity_id=domain_entity,
        target_entity_id=ip_entity,
        relationship_type=RelationshipType.RESOLVES_TO,
    )
    await seed_observation(
        uow,
        investigation_id=investigation_id,
        relationship=relationship,
        evidence=evidence,
        retrieved_at=FIXED,
        observed_at=FIXED,
    )

    await uow.research_results.add(
        ResearchResult(
            id=uuid4(),
            investigation_id=investigation_id,
            subject_entity_id=domain_entity,
            query="example.com context",
            created_at=FIXED,
        )
    )

    first_assessment = await uow.assessments.insert(_assessment(investigation_id))
    await uow.investigations.update_assessment_reference(
        investigation_id,
        first_assessment.id,
        expected_version=await _version(uow, investigation_id),
    )
    await uow.investigation_reports.append(
        _report(investigation_id, first_assessment.id, "First report")
    )
    await uow.investigation_reports.append(
        _report(investigation_id, first_assessment.id, "Second report")
    )

    await uow.timeline_events.append(
        InvestigationTimelineEvent(
            id=uuid4(),
            investigation_id=investigation_id,
            type=InvestigationTimelineEventType.INVESTIGATION_STARTED,
            occurred_at=FIXED,
        )
    )
    return investigation_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i06_read_collections_with_cursor_survival(
    uow_factory: Any, session_factory: Any
) -> None:
    """Every collection route serves pages and cursors survive HTTP."""
    async with uow_factory() as uow:
        investigation_id = await _seed_complete_investigation(uow)
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        evidence = client.get(
            f"/api/v1/investigations/{investigation_id}/evidence?limit=1"
        )
        assert evidence.status_code == 200
        page = evidence.json()
        assert len(page["items"]) == 1
        next_cursor = page["next_cursor"]
        assert next_cursor
        continued = client.get(
            f"/api/v1/investigations/{investigation_id}/evidence",
            params={"limit": 1, "cursor": next_cursor},
        )
        assert continued.status_code == 200
        assert len(continued.json()["items"]) == 1

        for path, _tag in (
            ("relationships", "relationships"),
            ("relationship-observations", "relationship_observations"),
            ("research", "research_results"),
            ("assessments", "assessments"),
            ("reports", "reports"),
            ("timeline", "timeline_events"),
        ):
            response = client.get(f"/api/v1/investigations/{investigation_id}/{path}")
            assert response.status_code == 200, path
            body = response.json()
            assert "items" in body
            assert "next_cursor" in body

        detail = client.get(f"/api/v1/investigations/{investigation_id}/relationships")
        assert detail.status_code == 200
        relationship_id = detail.json()["items"][0]["id"]
        one = client.get(
            f"/api/v1/investigations/{investigation_id}/relationships/{relationship_id}"
        )
        assert one.status_code == 200
        assert one.json()["id"] == relationship_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i07_no_raw_evidence_payload(
    uow_factory: Any, session_factory: Any
) -> None:
    """Seeded raw provider payloads never cross the HTTP boundary."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity = await seed_entity(uow, value="example.com")
        evidence = await uow.evidence.insert(
            evidence_with_raw_payload(investigation_id, entity)
        )
        assert evidence.id is not None
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        listed = client.get(f"/api/v1/investigations/{investigation_id}/evidence")
        detail = client.get(
            f"/api/v1/investigations/{investigation_id}/evidence/{evidence.id}"
        )

    assert listed.status_code == 200
    assert detail.status_code == 200
    assert "raw_payload" not in listed.text
    assert "raw_payload" not in detail.text
    assert "http_response" not in detail.text
    # The normalized facts remain available.
    assert detail.json()["facts"]["answers"]


def evidence_with_raw_payload(investigation_id: UUID, entity_id: UUID) -> object:
    """Build one evidence observation carrying a raw provider payload."""
    return evidence_factory(
        investigation_id,
        entity_id,
        source="urn:ati:source:google_public_dns",
        evidence_type=EvidenceType.DNS,
    ).model_copy(
        update={"raw_payload": {"http_response": {"status": 200, "body": "secret"}}}
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i08_current_pointers_follow_durable_pointers(
    uow_factory: Any, session_factory: Any
) -> None:
    """Current Assessment/Report follow durable pointers, never MAX(version)."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        first = await uow.assessments.insert(_assessment(investigation_id))
        second = await uow.assessments.insert(_assessment(investigation_id))
        assert first.version is not None and second.version is not None
        assert second.version > first.version
        # Point the Investigation at the OLDER assessment version.
        await uow.investigations.update_assessment_reference(
            investigation_id,
            first.id,
            expected_version=await _version(uow, investigation_id),
        )
        first_report = await uow.investigation_reports.append(
            _report(investigation_id, first.id, "Pointer report")
        )
        second_report = await uow.investigation_reports.append(
            _report(investigation_id, first.id, "Newer pointer report")
        )
        assert first_report.version is not None and second_report.version is not None
        assert second_report.version > first_report.version
        # Point the Investigation at the OLDER report version.
        await uow.investigations.update_report_reference(
            investigation_id,
            first_report.id,
            expected_version=await _version(uow, investigation_id),
        )
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        current_assessment = client.get(
            f"/api/v1/investigations/{investigation_id}/assessments/current"
        )
        current_report = client.get(
            f"/api/v1/investigations/{investigation_id}/reports/current"
        )

    assert current_assessment.status_code == 200
    assert current_assessment.json()["id"] == str(first.id)
    assert current_report.status_code == 200
    assert current_report.json()["id"] == str(first_report.id)
    assert current_report.json()["title"] == "Pointer report"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i09_history_redaction(uow_factory: Any, session_factory: Any) -> None:
    """History responses remove internal operational fields."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        assessment = await uow.assessments.insert(_assessment(investigation_id))
        await uow.investigations.update_assessment_reference(
            investigation_id,
            assessment.id,
            expected_version=await _version(uow, investigation_id),
        )
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        history = client.get(f"/api/v1/investigations/{investigation_id}/history")

    assert history.status_code == 200
    items = history.json()["items"]
    assert items
    assert {item["object_type"] for item in items} <= {
        "investigation",
        "assessment",
    }
    for item in items:
        # Private operational JSONB is never exposed for any object type.
        assert "operational_state" not in item["state"]
        assert "pending_provider_work" not in item["state"]
        assert "traversal" not in item["state"]
        assert "budget" not in item["state"] or item["object_type"] == "investigation"

    # Non-allowlisted object types fail closed.
    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        forbidden = client.get(
            f"/api/v1/investigations/{investigation_id}/history/session/{uuid4()}"
        )
    assert forbidden.status_code == 400
    assert forbidden.json()["error"]["code"] == "invalid_request"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i10_deterministic_markdown(
    uow_factory: Any, session_factory: Any
) -> None:
    """GET the same persisted report Markdown twice: byte-identical."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        assessment = await uow.assessments.insert(_assessment(investigation_id))
        await uow.investigations.update_assessment_reference(
            investigation_id,
            assessment.id,
            expected_version=await _version(uow, investigation_id),
        )
        report = await uow.investigation_reports.append(
            _report(investigation_id, assessment.id, "Deterministic report")
        )
        await uow.investigations.update_report_reference(
            investigation_id,
            report.id,
            expected_version=await _version(uow, investigation_id),
        )
        assert report.id is not None
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        first = client.get(
            f"/api/v1/investigations/{investigation_id}/reports/{report.id}/markdown"
        )
        second = client.get(
            f"/api/v1/investigations/{investigation_id}/reports/{report.id}/markdown"
        )

    assert first.status_code == 200
    assert first.headers["content-type"].startswith("text/markdown")
    assert first.content == second.content
    assert "# Deterministic report" in first.text
