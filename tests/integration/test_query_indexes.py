# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A query-plan/index eligibility tests (23A-P01..P12, 23A-I03).

Every representative statement mirrors the exact shape of the production
query contract it backs. Tests assert that the intended index appears in the
PostgreSQL plan (index scan or bitmap index scan), never exact costs,
cardinalities, or wall-clock latencies.

``SET LOCAL enable_seqscan = off`` is used only inside these plan-eligibility
assertions so tiny fixture sizes cannot make a sequential scan rational; no
production session setting disables sequential scans.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.domain.relationships import RelationshipType
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.query_fixtures import (
    FIXED_TIME,
    evidence_factory,
    seed_entity,
    seed_investigation,
    seed_observation,
    seed_relationship,
)


def _index_names(node: object, found: set[str]) -> None:
    """Collect every index name present in an EXPLAIN plan tree."""
    if isinstance(node, Mapping):
        name = node.get("Index Name")
        if isinstance(name, str):
            found.add(name)
        for value in node.values():
            _index_names(value, found)
    elif isinstance(node, list):
        for item in node:
            _index_names(item, found)


async def _plan_indexes(
    uow: PostgresUnitOfWork,
    statement: str,
    params: Mapping[str, object],
) -> set[str]:
    """Return the set of indexes PostgreSQL chose for one representative query."""
    assert uow.session is not None
    await uow.session.execute(text("SET LOCAL enable_seqscan = off"))
    result = await uow.session.execute(
        text("EXPLAIN (FORMAT JSON) " + statement), dict(params)
    )
    payload = result.scalar_one()
    if isinstance(payload, str):
        payload = json.loads(payload)
    found: set[str] = set()
    _index_names(payload, found)
    return found


async def _assert_uses_index(
    uow: PostgresUnitOfWork,
    statement: str,
    params: Mapping[str, object],
    index: str,
) -> None:
    """Assert the representative query plan can use the intended index."""
    found = await _plan_indexes(uow, statement, params)
    assert index in found, f"expected {index} in plan, found {sorted(found)}"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p01_investigation_status_time_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Investigation status+time listing uses the status/time index."""
    async with uow_factory() as uow:
        await seed_investigation(uow)
        assert uow.session is not None
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.investigation "
            "WHERE status = :status AND deleted_at IS NULL "
            "ORDER BY created_at DESC, id ASC LIMIT 50",
            {"status": "running"},
            "investigation_active_status_created_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p02_evidence_investigation_retrieved_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Investigation Evidence listing uses the existing listing index."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(uow)
        await uow.evidence.insert(evidence_factory(investigation_id, entity_id))
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.evidence "
            "WHERE investigation_id = :investigation_id "
            "ORDER BY retrieved_at DESC, id ASC LIMIT 50",
            {"investigation_id": investigation_id},
            "evidence_investigation_listing_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p03_evidence_source_listing_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Investigation+source Evidence listing uses the source composite."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(uow)
        await uow.evidence.insert(evidence_factory(investigation_id, entity_id))
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.evidence "
            "WHERE investigation_id = :investigation_id AND source = :source "
            "ORDER BY retrieved_at DESC, id ASC LIMIT 50",
            {
                "investigation_id": investigation_id,
                "source": "urn:ati:source:google_public_dns",
            },
            "evidence_investigation_source_listing_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p04_relationship_target_adjacency_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Target-side adjacency pivots use the reverse adjacency index."""
    async with uow_factory() as uow:
        shared_source = await seed_entity(uow, value="example.com")
        target_a = await seed_entity(uow, value="192.0.2.1")
        target_b = await seed_entity(uow, value="192.0.2.2")
        other_source = await seed_entity(uow, value="other.example.net")
        await seed_relationship(
            uow, source_entity_id=shared_source, target_entity_id=target_a
        )
        await seed_relationship(
            uow,
            source_entity_id=shared_source,
            target_entity_id=target_b,
            relationship_type=RelationshipType.CNAME_OF,
        )
        await seed_relationship(
            uow, source_entity_id=other_source, target_entity_id=target_a
        )
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.relationship "
            "WHERE target_entity_id = :target_entity_id "
            "AND relationship_type_urn = :relationship_type "
            "AND deleted_at IS NULL",
            {
                "target_entity_id": target_a,
                "relationship_type": RelationshipType.RESOLVES_TO.value,
            },
            "relationship_target_adjacency_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i03_relationship_adjacency_functional(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Shared-source and shared-target adjacency lookups return the edges."""
    async with uow_factory() as uow:
        shared_source = await seed_entity(uow, value="example.com")
        target_a = await seed_entity(uow, value="192.0.2.1")
        target_b = await seed_entity(uow, value="192.0.2.2")
        other_source = await seed_entity(uow, value="other.example.net")
        to_a = await seed_relationship(
            uow, source_entity_id=shared_source, target_entity_id=target_a
        )
        to_b = await seed_relationship(
            uow,
            source_entity_id=shared_source,
            target_entity_id=target_b,
            relationship_type=RelationshipType.CNAME_OF,
        )
        from_other = await seed_relationship(
            uow,
            source_entity_id=other_source,
            target_entity_id=target_a,
            relationship_type=RelationshipType.REGISTERED_TO,
        )
        deleted = await seed_relationship(
            uow, source_entity_id=target_a, target_entity_id=target_b
        )
        await uow.relationships.soft_delete(deleted.id)

        session = uow.session
        assert session is not None

        async def _ids(statement: str, params: dict[str, object]) -> list[object]:
            rows = await session.execute(text(statement), params)
            return [row[0] for row in rows.fetchall()]

        source_rows = await _ids(
            "SELECT id FROM ati.relationship "
            "WHERE source_entity_id = :source AND deleted_at IS NULL "
            "ORDER BY id",
            {"source": shared_source},
        )
        assert source_rows == sorted([to_a.id, to_b.id])
        target_rows = await _ids(
            "SELECT id FROM ati.relationship "
            "WHERE target_entity_id = :target AND deleted_at IS NULL "
            "ORDER BY id",
            {"target": target_a},
        )
        assert target_rows == sorted([to_a.id, from_other.id])
        # Type-filtered target adjacency, matching the indexed shape.
        typed = await _ids(
            "SELECT id FROM ati.relationship "
            "WHERE target_entity_id = :target "
            "AND relationship_type_urn = :relationship_type "
            "AND deleted_at IS NULL ORDER BY id",
            {
                "target": target_a,
                "relationship_type": RelationshipType.RESOLVES_TO.value,
            },
        )
        assert typed == [to_a.id]
        # A soft-deleted edge is never returned by either adjacency direction.
        assert deleted.id not in source_rows and deleted.id not in target_rows


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p05_observation_relationship_retrieved_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Relationship observation by relationship/retrieved uses its index."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        evidence = await uow.evidence.insert(evidence_factory(investigation_id, source))
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence=evidence,
        )
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.relationship_observation "
            "WHERE relationship_id = :relationship_id "
            "ORDER BY retrieved_at DESC, id ASC LIMIT 50",
            {"relationship_id": edge.id},
            "relationship_observation_relationship_retrieved_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p06_observation_relationship_observed_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Relationship observation by relationship/observed range uses its index."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        evidence = await uow.evidence.insert(evidence_factory(investigation_id, source))
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence=evidence,
            observed_at=FIXED_TIME,
        )
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.relationship_observation "
            "WHERE relationship_id = :relationship_id "
            "AND observed_at >= :observed_from AND observed_at < :observed_to "
            "ORDER BY observed_at DESC, id ASC LIMIT 50",
            {
                "relationship_id": edge.id,
                "observed_from": FIXED_TIME - timedelta(days=1),
                "observed_to": FIXED_TIME + timedelta(days=1),
            },
            "relationship_observation_relationship_observed_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p07_research_subject_time_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Research by investigation+subject uses the subject/time index."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        subject = await seed_entity(uow, value="malware-a")
        await uow.research_results.add(_research_result(investigation_id, subject))
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.research_result "
            "WHERE investigation_id = :investigation_id "
            "AND subject_entity_id = :subject_entity_id "
            "ORDER BY created_at DESC, id ASC LIMIT 50",
            {"investigation_id": investigation_id, "subject_entity_id": subject},
            "research_result_investigation_subject_created_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p08_assessment_version_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Assessment version listing uses the investigation/version index."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await uow.assessments.insert(_assessment(investigation_id))
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.assessment "
            "WHERE investigation_id = :investigation_id AND deleted_at IS NULL "
            "ORDER BY version DESC, id ASC LIMIT 50",
            {"investigation_id": investigation_id},
            "assessment_investigation_version_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p09_timeline_occurred_sequence_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Timeline chronological listing uses the occurred/sequence index."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await uow.timeline_events.append(_timeline_event(investigation_id))
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.investigation_timeline_event "
            "WHERE investigation_id = :investigation_id "
            "ORDER BY occurred_at, sequence LIMIT 50",
            {"investigation_id": investigation_id},
            "investigation_timeline_event_chronological_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p10_history_object_occurred_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """One object's history browses through the object/time index."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.domain_object_history "
            "WHERE object_type = :object_type AND object_id = :object_id "
            "ORDER BY occurred_at DESC, id ASC LIMIT 50",
            {"object_type": "investigation", "object_id": investigation_id},
            "domain_history_object_occurred_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p11_history_type_occurred_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Type-scoped history browses through the type/time index."""
    async with uow_factory() as uow:
        await seed_investigation(uow)
        # The type+time-range shape is the documented type/time browse path;
        # the range makes the type/time index clearly preferable to the
        # object/time index (whose occurred_at column follows object_id).
        now = datetime.now(UTC)
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.domain_object_history "
            "WHERE object_type = :object_type "
            "AND occurred_at >= :occurred_from AND occurred_at < :occurred_to "
            "ORDER BY occurred_at DESC, id ASC LIMIT 50",
            {
                "object_type": "investigation",
                "occurred_from": now - timedelta(days=1),
                "occurred_to": now + timedelta(days=1),
            },
            "domain_history_type_occurred_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p12_history_investigation_occurred_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Investigation-scoped history browses through the partial index."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await _assert_uses_index(
            uow,
            "SELECT id FROM ati.domain_object_history "
            "WHERE investigation_id = :investigation_id "
            "ORDER BY occurred_at DESC, id ASC LIMIT 50",
            {"investigation_id": investigation_id},
            "domain_history_investigation_occurred_idx",
        )


def _research_result(investigation_id: UUID, subject_entity_id: UUID) -> ResearchResult:
    """Build one deterministic immutable research result."""
    return ResearchResult(
        id=uuid4(),
        investigation_id=investigation_id,
        subject_entity_id=subject_entity_id,
        query="context for the subject",
        created_at=FIXED_TIME,
    )


def _assessment(investigation_id: UUID) -> Assessment:
    """Build one structurally valid INCONCLUSIVE Assessment version."""
    return Assessment(
        investigation_id=investigation_id,
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="synthetic inconclusive assessment",
        analyzed_evidence_ids=(),
    )


def _timeline_event(investigation_id: UUID) -> InvestigationTimelineEvent:
    """Build one deterministic investigation_started timeline event."""
    return InvestigationTimelineEvent(
        id=uuid4(),
        investigation_id=investigation_id,
        type=InvestigationTimelineEventType.INVESTIGATION_STARTED,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
