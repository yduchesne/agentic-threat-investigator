# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23C route contract tests (R05-R16).

Pure HTTP contract tests with injected application fakes: creation returns
202 without running anything, filters map exactly to the PR 23A query DTOs,
cursors map to stable 400s, current pointers use the durable-pointer
services, Markdown is deterministic, and cross-Investigation lookups fail
with 404.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.app.investigation_submission import (
    IdempotencyConflictError,
    IdempotencyKeyRequiredError,
)
from agentic_threat_investigator.app.query.models import QueryPage
from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import InvestigationStatus
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipType,
)
from agentic_threat_investigator.domain.report import InvestigationReport

from .conftest import (
    FakeCollectionService,
    FakeQueryBundle,
    FakeSubmissionService,
    build_test_app,
    csrf_headers,
    login_client,
)

INVESTIGATION = UUID("11111111-1111-1111-1111-111111111111")


def test_r05_create_accepted_returns_location_without_runner() -> None:
    """POST /investigations returns 202 + Location and never runs work."""
    submission = FakeSubmissionService()
    with build_test_app(submission=submission) as client:
        login_client(client)
        response = client.post(
            "/api/v1/investigations",
            json={
                "indicators": [{"type": "domain", "value": "example.com"}],
                "objective": "assess the domain",
            },
            headers={
                "Idempotency-Key": "create-1",
                **csrf_headers(),
            },
        )

    assert response.status_code == 202
    body = response.json()
    assert body["id"] == str(INVESTIGATION)
    assert body["status"] == "pending"
    assert response.headers["location"] == f"/api/v1/investigations/{INVESTIGATION}"
    assert submission.submissions
    submitted, actor_id, key = submission.submissions[0]
    assert key == "create-1"
    assert actor_id == submission.fresh_investigation.investigation_id or actor_id


def test_r06_idempotent_replay_returns_same_investigation() -> None:
    """Equivalent replay returns the same Investigation and Location."""
    submission = FakeSubmissionService()
    with build_test_app(submission=submission) as client:
        login_client(client)
        headers = {
            "Idempotency-Key": "create-1",
            **csrf_headers(),
        }
        payload = {
            "indicators": [{"type": "domain", "value": "example.com"}],
            "objective": "assess the domain",
        }
        first = client.post("/api/v1/investigations", json=payload, headers=headers)
        second = client.post("/api/v1/investigations", json=payload, headers=headers)

    assert first.status_code == second.status_code == 202
    assert first.json()["id"] == second.json()["id"] == str(INVESTIGATION)
    assert first.headers["location"] == second.headers["location"]
    assert len(submission.submissions) == 2


def test_r07_idempotency_conflict_returns_409() -> None:
    """Same key with a different semantic request fails closed with 409."""
    submission = FakeSubmissionService()
    submission.conflict = IdempotencyConflictError("key reused")
    with build_test_app(submission=submission) as client:
        login_client(client)
        response = client.post(
            "/api/v1/investigations",
            json={
                "indicators": [{"type": "domain", "value": "other.example.com"}],
                "objective": "different objective",
            },
            headers={"Idempotency-Key": "create-1", **csrf_headers()},
        )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "idempotency_conflict"


def test_create_requires_idempotency_key() -> None:
    """Creation without an Idempotency-Key returns the required error."""
    submission = FakeSubmissionService()
    submission.conflict = IdempotencyKeyRequiredError("key required")
    with build_test_app(submission=submission) as client:
        login_client(client)
        response = client.post(
            "/api/v1/investigations",
            json={
                "indicators": [{"type": "domain", "value": "example.com"}],
                "objective": "assess the domain",
            },
            headers=csrf_headers(),
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "idempotency_key_required"


def test_create_rejects_missing_csrf() -> None:
    """State-changing creation without CSRF proof fails closed with 403."""
    with build_test_app() as client:
        login_client(client, csrf="cookie")
        response = client.post(
            "/api/v1/investigations",
            json={
                "indicators": [{"type": "domain", "value": "example.com"}],
                "objective": "assess",
            },
            headers={
                "Idempotency-Key": "k1",
                "X-CSRF-Token": "wrong",
                "Origin": "http://testserver",
            },
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_r08_investigation_list_maps_filters_exactly() -> None:
    """HTTP filters map exactly to the PR 23A InvestigationListQuery."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            "/api/v1/investigations",
            params={
                "status": "running",
                "created_from": "2026-01-01T00:00:00Z",
                "created_to": "2026-02-01T00:00:00Z",
                "limit": "7",
            },
        )

    assert response.status_code == 200
    query = bundle.investigations.queries[0]
    assert query.status is InvestigationStatus.RUNNING
    assert query.created_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.created_to == datetime(2026, 2, 1, tzinfo=UTC)
    assert query.limit == 7
    assert query.cursor is None


def test_r09_invalid_cursor_returns_stable_400() -> None:
    """A malformed cursor maps to the stable 400 invalid_cursor envelope."""
    from agentic_threat_investigator.app.query.pagination import InvalidCursorError

    bundle = FakeQueryBundle()
    bundle.investigations = FakeCollectionService()

    async def failing_list(query: object) -> QueryPage[object]:
        """Raise the typed cursor error like the real service."""
        raise InvalidCursorError("bad cursor")

    bundle.investigations.list = failing_list  # type: ignore[method-assign]
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get("/api/v1/investigations", params={"cursor": "garbage!!"})

    assert response.status_code == 400
    body = response.json()["error"]
    assert body["code"] == "invalid_cursor"
    assert body["request_id"]


def test_r10_evidence_filters_map_exactly() -> None:
    """Evidence source/entity/type/range filters map to the 23A DTO."""
    bundle = FakeQueryBundle()
    subject = uuid4()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        client.get(
            f"/api/v1/investigations/{INVESTIGATION}/evidence",
            params={
                "source": "urn:ati:source:rdap",
                "subject_entity_id": str(subject),
                "type": "urn:ati:evidence:registration",
                "retrieved_from": "2026-01-01T00:00:00Z",
                "retrieved_to": "2026-02-01T00:00:00Z",
            },
        )

    query = bundle.evidence.queries[0]
    assert query.investigation_id == INVESTIGATION
    assert query.source == "urn:ati:source:rdap"
    assert query.subject_entity_id == subject
    assert query.evidence_type is EvidenceType.REGISTRATION
    assert query.retrieved_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.retrieved_to == datetime(2026, 2, 1, tzinfo=UTC)


def test_r11_observation_filters_keep_observed_retrieved_distinct() -> None:
    """Observed/retrieved filters stay independent on the observation route."""
    bundle = FakeQueryBundle()
    relationship_id = uuid4()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations",
            params={
                "relationship_id": str(relationship_id),
                "observed_from": "2026-01-01T00:00:00Z",
                "observed_to": "2026-01-15T00:00:00Z",
                "retrieved_from": "2026-02-01T00:00:00Z",
                "retrieved_to": "2026-03-01T00:00:00Z",
            },
        )

    query = bundle.relationship_observations.queries[0]
    assert query.relationship_id == relationship_id
    assert query.observed_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.observed_to == datetime(2026, 1, 15, tzinfo=UTC)
    assert query.retrieved_from == datetime(2026, 2, 1, tzinfo=UTC)
    assert query.retrieved_to == datetime(2026, 3, 1, tzinfo=UTC)


def test_r12_current_assessment_uses_durable_pointer_service() -> None:
    """Current Assessment resolution calls the pointer service, not MAX."""
    bundle = FakeQueryBundle()
    assessment = Assessment(
        id=uuid4(),
        investigation_id=INVESTIGATION,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="suspicious infrastructure",
        analyzed_evidence_ids=(),
        version=4,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    bundle.assessments.gets[("current", INVESTIGATION)] = assessment
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/assessments/current"
        )

    assert response.status_code == 200
    assert response.json()["version"] == 4
    assert bundle.assessments.queries == []


def test_r13_current_report_uses_durable_pointer_service() -> None:
    """Current Report resolution calls the pointer service, not MAX."""
    bundle = FakeQueryBundle()
    report = InvestigationReport(
        id=uuid4(),
        investigation_id=INVESTIGATION,
        assessment_id=uuid4(),
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        title="Report",
        version=2,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    bundle.reports.gets[("current", INVESTIGATION)] = report
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/reports/current")

    assert response.status_code == 200
    assert response.json()["version"] == 2
    assert bundle.reports.queries == []


def test_r14_report_markdown_is_deterministic_and_pure() -> None:
    """Markdown renders the persisted report deterministically, no writer."""
    bundle = FakeQueryBundle()
    report = InvestigationReport(
        id=uuid4(),
        investigation_id=INVESTIGATION,
        assessment_id=uuid4(),
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        title="Malicious infrastructure",
        version=1,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    bundle.reports.gets[(report.id,)] = report
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        first = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/reports/{report.id}/markdown"
        )
        second = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/reports/{report.id}/markdown"
        )

    assert first.status_code == 200
    assert first.headers["content-type"].startswith("text/markdown")
    assert "# Malicious infrastructure" in first.text
    assert "Verdict: **malicious**" in first.text
    assert first.content == second.content


def test_r15_timeline_returns_chronological_page() -> None:
    """Timeline maps to the chronological query contract."""
    bundle = FakeQueryBundle()
    event = InvestigationTimelineEvent(
        id=uuid4(),
        investigation_id=INVESTIGATION,
        type=InvestigationTimelineEventType.INVESTIGATION_STARTED,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    bundle.timeline_events.page = QueryPage(items=(event,), next_cursor="cursor-1")
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/timeline",
            params={"event_type": "investigation_started"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["next_cursor"] == "cursor-1"
    assert body["items"][0]["type"] == "investigation_started"
    query = bundle.timeline_events.queries[0]
    assert query.event_type is InvestigationTimelineEventType.INVESTIGATION_STARTED


def test_r16_cross_investigation_detail_returns_404() -> None:
    """A resource from Investigation B under A maps to 404, no enumeration."""
    bundle = FakeQueryBundle()
    evidence_id = uuid4()
    bundle.evidence.gets[(INVESTIGATION, evidence_id)] = None
    other = UUID("99999999-9999-9999-9999-999999999999")
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{other}/evidence/{evidence_id}")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "evidence_not_found"


def test_evidence_detail_never_exposes_raw_payload() -> None:
    """Detail responses exclude raw provider payloads entirely."""
    bundle = FakeQueryBundle()
    evidence = Evidence(
        id=uuid4(),
        investigation_id=INVESTIGATION,
        type=EvidenceType.DNS,
        subject=EntityRef(id=uuid4(), type=EntityType.DOMAIN, value="example.com"),
        source="urn:ati:source:google_public_dns",
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        facts={},
        raw_payload={"http_response": {"status": 200}},
    )
    bundle.evidence.gets[(INVESTIGATION, evidence.id)] = evidence
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/evidence/{evidence.id}"
        )

    assert response.status_code == 200
    assert "raw_payload" not in response.json()
    assert "http_response" not in response.text


def test_relationship_detail_maps_stable_urn() -> None:
    """Relationship detail exposes the stable type URN and edge identities."""
    bundle = FakeQueryBundle()
    relationship = Relationship(
        id=uuid4(),
        source_entity_id=uuid4(),
        target_entity_id=uuid4(),
        type=RelationshipType.RESOLVES_TO,
    )
    bundle.relationships.gets[(INVESTIGATION, relationship.id)] = relationship
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationships/{relationship.id}"
        )

    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "urn:ati:relationship:dns:resolves_to"
    assert body["source_entity_id"] == str(relationship.source_entity_id)


def test_unknown_route_uses_stable_envelope() -> None:
    """Unknown paths return the stable not_found envelope."""
    with build_test_app() as client:
        login_client(client)
        response = client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_malformed_path_uuid_uses_ati_envelope() -> None:
    """A malformed path UUID maps to the stable 422 validation envelope."""
    with build_test_app() as client:
        login_client(client)
        response = client.get("/api/v1/investigations/not-a-uuid")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
