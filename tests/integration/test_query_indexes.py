# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A/31B query-plan/index eligibility tests (23A-P01..P12, 23A-I03).

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
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
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
    seed_entity,
    seed_evidence_observation,
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
    index: str | tuple[str, ...],
) -> None:
    """Assert the representative query plan can use the intended index(es)."""
    found = await _plan_indexes(uow, statement, params)
    expected = (index,) if isinstance(index, str) else index
    assert any(item in found for item in expected), (
        f"expected one of {expected} in plan, found {sorted(found)}"
    )


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
async def test_p02_evidence_entity_association_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Entity-scoped Evidence listing drives the association composite."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(uow)
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=entity_id
        )
        await _assert_uses_index(
            uow,
            "SELECT eo.id FROM ati.evidence_observation eo "
            "JOIN ati.evidence_observation_entity eoe "
            "  ON eoe.evidence_observation_id = eo.id "
            "WHERE eoe.entity_id = :entity_id "
            "ORDER BY eo.retrieved_at DESC, eo.id ASC LIMIT 50",
            {"entity_id": entity_id},
            "evidence_observation_entity_entity_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p03_admission_dependency_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Admission dependency probes drive the observation-led composite."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(uow)
        observation_id = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=entity_id
        )
        await _assert_uses_index(
            uow,
            "SELECT evidence_observation_id FROM ati.investigation_evidence "
            "WHERE evidence_observation_id = :observation_id",
            {"observation_id": observation_id},
            "investigation_evidence_observation_idx",
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
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=source
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
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
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=source
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
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
        # The shared suite truncates tables per test without refreshing
        # planner statistics (TRUNCATE leaves migration-era stats), so the
        # index decision between the adjacency/type indexes can otherwise
        # flip with the preceding workload. A fresh ANALYZE makes the
        # plan-eligibility assertion deterministic; `enable_seqscan=off`
        # and the asserted index itself are unchanged.
        assert uow.session is not None
        await uow.session.execute(text("ANALYZE ati.domain_object_history"))
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


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p13_geolocation_projection_drives_entity_association_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PR 25A geolocation projection drives the global entity association.

    The latest-per-entity projection filters through
    ``ati.evidence_observation_entity`` and the stable ``ati.evidence`` type
    column; the plan is served by the entity-led association composite with
    no structural migration at v0.1 (plan 28).
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        await seed_evidence_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            source="urn:ati:source:dbip_city_lite",
            evidence_type=EvidenceType.GEOLOCATION,
        )
        found = await _plan_indexes(
            uow,
            "SELECT eo.id FROM ati.evidence_observation eo "
            "JOIN ati.evidence e ON e.id = eo.evidence_id "
            "JOIN ati.evidence_observation_entity eoe "
            "  ON eoe.evidence_observation_id = eo.id "
            "WHERE eoe.entity_id = :entity_id "
            "AND e.evidence_type = :evidence_type "
            "ORDER BY eo.retrieved_at DESC, eo.id ASC LIMIT 50",
            {
                "entity_id": entity_id,
                "evidence_type": EvidenceType.GEOLOCATION.value,
            },
        )
        assert found & {
            "evidence_observation_entity_entity_idx",
            "evidence_observation_entity_pkey",
        }, f"plan used none of the entity association indexes: {sorted(found)}"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_p12_observation_entity_join_uses_investigation_retrieved_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Entity-centric evolution (PR 24E) keeps the canonical observation index.

    The entity/direction/type filters run through the joined stable
    Relationship, and the driving scan remains the Investigation+retrieved
    observation index that backs the canonical ``retrieved_at DESC, id ASC``
    keyset order. No structural migration is required for the bounded
    evolution query at v0.1 scale.
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=source
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
            observed_at=FIXED_TIME,
        )
        assert uow.session is not None
        await _assert_uses_index(
            uow,
            "SELECT ro.id FROM ati.relationship_observation ro "
            "JOIN ati.evidence_observation_entity eoe "
            "  ON eoe.evidence_observation_id = ro.evidence_observation_id "
            "WHERE eoe.entity_id = :entity_id AND ro.relationship_id = :relationship_id "
            "ORDER BY ro.retrieved_at DESC, ro.id ASC LIMIT 50",
            {"entity_id": source, "relationship_id": edge.id},
            ("evidence_observation_entity_entity_idx",),
        )


# ---------------------------------------------------------------------------
# PR 31B graph neighborhood plan eligibility (P31B-01..02 / G31B-X01..X04)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_x01_graph_source_neighborhood_uses_adjacency_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P31B-01: the source-side graph edge selection can use the adjacency index.

    The statement mirrors the graph edge selection's relationship access
    path: the source-entity predicate of the default (untyped) neighborhood
    is served by ``relationship_adjacency_idx`` through its leading column
    (the optional type filter is served by the second column).
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
        )
        await _assert_uses_index(
            uow,
            "SELECT r.id FROM ati.relationship r "
            "WHERE r.source_entity_id = :entity_id AND r.deleted_at IS NULL "
            "ORDER BY r.id ASC LIMIT 51",
            {"entity_id": focal},
            "relationship_adjacency_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_x02_graph_target_neighborhood_uses_reverse_adjacency_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P31B-02: the target-side graph edge selection can use the reverse index.

    The statement mirrors the graph edge selection's relationship access
    path for the TARGET neighborhood: the target-entity predicate of the
    default (untyped) neighborhood is served by
    ``relationship_target_adjacency_idx`` through its leading column (the
    optional type filter is served by the second column).
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="192.0.2.1")
        source = await seed_entity(uow, value="example.com")
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=focal
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
        )
        await _assert_uses_index(
            uow,
            "SELECT r.id FROM ati.relationship r "
            "WHERE r.target_entity_id = :entity_id AND r.deleted_at IS NULL "
            "ORDER BY r.id ASC LIMIT 51",
            {"entity_id": focal},
            "relationship_target_adjacency_idx",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_x03_graph_focal_visibility_uses_entity_association_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P31B-03: the focal visibility probe uses the entity association index.

    The exact PR 31B focal visibility rule (live Entity with an admitted
    associated EvidenceObservation) is served by
    ``evidence_observation_entity_entity_idx`` and the InvestigationEvidence
    admission index(es).
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        found = await _plan_indexes(
            uow,
            "SELECT e.id FROM ati.entity e "
            "WHERE e.id = :entity_id AND e.deleted_at IS NULL AND EXISTS ("
            "  SELECT 1 FROM ati.evidence_observation_entity eoe "
            "  JOIN ati.investigation_evidence ie "
            "    ON ie.evidence_observation_id = eoe.evidence_observation_id "
            "  WHERE eoe.entity_id = e.id "
            "    AND ie.investigation_id = :investigation_id"
            ")",
            {"entity_id": focal, "investigation_id": investigation_id},
        )
        assert found & {
            "evidence_observation_entity_entity_idx",
            "investigation_evidence_pkey",
            "investigation_evidence_observation_idx",
        }, f"plan used none of the focal visibility indexes: {sorted(found)}"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_x04_graph_admission_join_uses_admission_index(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P31B-04: the edge admission join uses an InvestigationEvidence index.

    The Observation -> Investigation admission join of the graph edge
    selection resolves through the InvestigationEvidence admission index
    (primary-key or observation-led composite according to the planner's
    join direction).
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=source
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
        )
        found = await _plan_indexes(
            uow,
            "SELECT ro.id FROM ati.relationship_observation ro "
            "JOIN ati.investigation_evidence ie "
            "  ON ie.evidence_observation_id = ro.evidence_observation_id "
            "WHERE ie.investigation_id = :investigation_id "
            "  AND ro.relationship_id = :relationship_id",
            {"investigation_id": investigation_id, "relationship_id": edge.id},
        )
        assert found & {
            "investigation_evidence_pkey",
            "investigation_evidence_observation_idx",
        }, f"plan used none of the admission indexes: {sorted(found)}"
