# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31F-5: bounded Investigation-scoped support presentation route tests.

The route resolves one finite support-ID set through the abstract bundle
and never exposes raw provider payloads. Duplicate IDs resolve once (the
postgres service deduplicates through the bounded set query; the route
forwards the request unchanged), oversized batches fail closed, and the
investigation scope is always forwarded to the service boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.api.mappers import to_support_presentation_response
from agentic_threat_investigator.app.query.support_presentations import (
    MAX_SUPPORT_IDS_PER_KIND,
    EvidenceSupportPresentation,
    RelationshipObservationSupportPresentation,
    SupportPresentationResult,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType

from .conftest import (
    FakeQueryBundle,
    build_test_app,
    csrf_headers,
    login_client,
)

INVESTIGATION = "11111111-1111-1111-1111-111111111111"
EVIDENCE_ID = "33333333-3333-4333-8333-333333333333"
OBSERVATION_ID = "44444444-4444-4444-8444-444444444444"
RELATIONSHIP_ID = "55555555-5555-4555-8555-555555555555"
SOURCE_ENTITY_ID = "22222222-2222-4222-8222-222222222222"
TARGET_ENTITY_ID = "66666666-6666-4666-8666-666666666666"


def _result() -> SupportPresentationResult:
    """One deterministic resolved support presentation result."""
    return SupportPresentationResult(
        evidence=(
            EvidenceSupportPresentation(
                evidence_observation_id=UUID(EVIDENCE_ID),
                evidence_type=EvidenceType.DNS,
                source="urn:ati:source:google_public_dns",
                subject_entity_id=UUID(SOURCE_ENTITY_ID),
                subject_entity_type=EntityType.DOMAIN,
                subject_entity_value="update-package.test",
            ),
        ),
        relationship_observations=(
            RelationshipObservationSupportPresentation(
                relationship_observation_id=UUID(OBSERVATION_ID),
                relationship_id=UUID(RELATIONSHIP_ID),
                relationship_type=RelationshipType.RESOLVES_TO,
                source_entity_id=UUID(SOURCE_ENTITY_ID),
                source_entity_type=EntityType.DOMAIN,
                source_entity_value="update-package.test",
                target_entity_id=UUID(TARGET_ENTITY_ID),
                target_entity_type=EntityType.MALWARE,
                target_entity_value="malware.badloader_v2",
                observed_at=datetime(2026, 6, 1, 9, 0, 0, tzinfo=UTC),
            ),
        ),
    )


def test_support_resolution_returns_semantic_presentation_only() -> None:
    """The response is presentation metadata; raw payload fields never appear."""
    bundle = FakeQueryBundle()
    bundle.support_presentations.result = _result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.post(
            f"/api/v1/investigations/{INVESTIGATION}/support-presentations/resolve",
            headers=csrf_headers(),
            json={
                "evidence_observation_ids": [EVIDENCE_ID],
                "relationship_observation_ids": [OBSERVATION_ID],
            },
        )

    assert response.status_code == 200
    body = response.json()
    evidence = body["evidence"][0]
    assert evidence["evidence_observation_id"] == EVIDENCE_ID
    assert evidence["evidence_type"] == "urn:ati:evidence:dns"
    assert evidence["source"] == "urn:ati:source:google_public_dns"
    assert evidence["subject_entity_value"] == "update-package.test"
    assert evidence["subject_entity_type"] == "domain"
    assert "facts" not in evidence
    assert "raw_payload" not in response.text
    edge = body["relationship_observations"][0]
    assert edge["relationship_observation_id"] == OBSERVATION_ID
    assert edge["relationship_type"] == "urn:ati:relationship:dns:resolves_to"
    assert edge["source_entity_value"] == "update-package.test"
    assert edge["target_entity_value"] == "malware.badloader_v2"
    assert edge["observed_at"] == "2026-06-01T09:00:00Z"
    assert "source_url" not in edge


def test_support_resolution_forwards_investigation_scope() -> None:
    """The route always binds the path Investigation to the resolution."""
    bundle = FakeQueryBundle()
    bundle.support_presentations.result = _result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.post(
            f"/api/v1/investigations/{INVESTIGATION}/support-presentations/resolve",
            headers=csrf_headers(),
            json={
                "evidence_observation_ids": [EVIDENCE_ID, EVIDENCE_ID],
                "relationship_observation_ids": [],
            },
        )

    assert response.status_code == 200
    query = bundle.support_presentations.queries[-1]
    assert str(query.investigation_id) == INVESTIGATION
    assert query.evidence_observation_ids == (UUID(EVIDENCE_ID), UUID(EVIDENCE_ID))


def test_support_resolution_requires_csrf() -> None:
    """Mutating batch resolution is CSRF-protected like every unsafe route."""
    bundle = FakeQueryBundle()
    bundle.support_presentations.result = _result()
    with build_test_app(bundle=bundle) as client:
        client.cookies.set("ati_session", "session-token")
        response = client.post(
            f"/api/v1/investigations/{INVESTIGATION}/support-presentations/resolve",
            json={"evidence_observation_ids": [EVIDENCE_ID]},
        )

    assert response.status_code == 403


def test_support_resolution_rejects_oversized_batch() -> None:
    """Batches above the per-kind bound fail closed instead of degrading."""
    bundle = FakeQueryBundle()
    bundle.support_presentations.result = _result()
    oversized = [str(uuid4()) for _ in range(MAX_SUPPORT_IDS_PER_KIND + 1)]
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.post(
            f"/api/v1/investigations/{INVESTIGATION}/support-presentations/resolve",
            headers=csrf_headers(),
            json={"evidence_observation_ids": oversized},
        )

    assert response.status_code == 422
    assert bundle.support_presentations.queries == []


def test_support_resolution_empty_request_is_valid() -> None:
    """An empty request resolves to an empty presentation result."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.post(
            f"/api/v1/investigations/{INVESTIGATION}/support-presentations/resolve",
            headers=csrf_headers(),
            json={},
        )

    assert response.status_code == 200
    assert response.json() == {
        "evidence": [],
        "relationship_observations": [],
    }


def test_support_mapper_is_an_allowlist_projection() -> None:
    """The mapper copies only allowlisted presentation fields."""
    response = to_support_presentation_response(_result())
    assert response.evidence[0].subject_entity_value == "update-package.test"
    assert response.relationship_observations[0].target_entity_type == "malware"
    assert response.relationship_observations[0].observed_at is not None
