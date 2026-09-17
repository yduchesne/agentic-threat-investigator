# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26C async geographic-resolution lifecycle matrices on real PostgreSQL.

G26C-P01..P43 matrix: claim/lease semantics, attempt/backoff bookkeeping,
stale-worker protection, atomic resolved completion with replay
idempotency, unresolvable/failure transitions, EXPLAIN/index eligibility,
and extension/API coexistence. Vertical slices then run the production
worker flow against the real PostgreSQL + PostGIS stack: multi-worker
disjoint claims, crash/recovery with lease expiry, and retry/exhaustion
with a fake LocationResolver only.

Timestamps are controlled deterministically through direct SQL (forcing
``lease_expires_at``/``next_attempt_at`` into the past) instead of
sleep-based waits; no sleep-heavy tests.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.geoint.worker import (
    AMBIGUITY_ERROR_CODE,
    CANONICAL_GEOGRAPHY_METHOD,
    GeoResolutionWorker,
    GeoResolutionWorkerConfig,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EntityLocationObservationDuplicateError,
    GeoEntityNotFoundError,
    GeoEvidenceNotFoundError,
    GeoEvidenceSubjectMismatchError,
    GeoEvidenceTypeError,
    GeoLocationNotFoundError,
    GeoResolutionClaimantMismatchError,
    GeoResolutionInvalidTransitionError,
    GeoResolutionLeaseExpiredError,
    GeoResolutionNotFoundError,
    GeoResolutionTerminalReplayConflictError,
    GeoResolutionVersionConflictError,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    EntityLocationObservation,
    GeographicClaim,
    GeoResolution,
    GeoResolutionStatus,
    Location,
    LocationPrecision,
    LocationType,
    observation_uuid_for_resolution,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.legacy_evidence import EntityRef, LegacyEvidence
from agentic_threat_investigator.infrastructure.persistence.postgresql.canonical_geography_resolver import (
    PostgresCanonicalGeographyResolver,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

pytestmark = pytest.mark.integration

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_RESOLVED_AT = _RETRIEVED_AT + timedelta(minutes=1)
_EPOCH = datetime(2020, 1, 1, tzinfo=UTC)
# A genuinely far-future timestamp for "not yet due"/"unexpired" fixtures.
_FUTURE = datetime(2029, 1, 1, tzinfo=UTC)

# Deterministic two-letter country codes for seeding many independent work
# pairs without canonical collisions.
_COUNTRY_CODES = (
    "US",
    "CA",
    "MX",
    "BR",
    "AR",
    "DE",
    "FR",
    "IT",
    "ES",
    "NL",
    "GR",
    "PL",
    "SE",
    "NO",
    "FI",
    "DK",
    "AT",
    "CH",
    "BE",
    "PT",
)


def location_factory(country_code: str) -> Location:
    """Build one canonical country Location fixture."""
    return Location(
        type=LocationType.COUNTRY,
        name=country_code,
        canonical_name=country_code,
        country_code=country_code,
    )


async def seed_geolocation_work(
    uow: PostgresUnitOfWork,
    *,
    country_code: str = "US",
    precision: str = "country",
    evidence_type: EvidenceType = EvidenceType.GEOLOCATION,
    create_resolution: bool = True,
) -> tuple[UUID, UUID, UUID | None]:
    """Create investigation, entity, GEOLOCATION LegacyEvidence, and PENDING work.

    Returns ``(entity_id, evidence_id, resolution_id)``; ``resolution_id``
    is ``None`` when ``create_resolution`` is False.
    """
    investigation_id = uuid4()
    await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[uuid4()],
            objective="Assess the indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
        )
    )
    entity = await uow.entities.upsert(
        Entity(
            type=EntityType.IP_ADDRESS,
            value=str(ipaddress.IPv4Address(uuid4().int & 0xFFFFFFFF)),
        )
    )
    assert entity.id is not None
    evidence = await uow.evidence.insert(
        LegacyEvidence(
            investigation_id=investigation_id,
            type=evidence_type,
            subject=EntityRef(
                id=entity.id, type=EntityType.IP_ADDRESS, value="203.0.113.7"
            ),
            source="urn:ati:source:test",
            retrieved_at=_RETRIEVED_AT,
            facts={"country_code": country_code, "precision": precision},
        )
    )
    assert evidence.id is not None
    if not create_resolution:
        return entity.id, evidence.id, None
    resolution = await uow.geo_resolutions.create_pending(
        GeoResolution(entity_id=entity.id, evidence_id=evidence.id)
    )
    assert resolution.id is not None
    return entity.id, evidence.id, resolution.id


async def claim(
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    claimed_by: str,
    limit: int = 20,
    lease_seconds: int = 300,
    max_attempts: int = 3,
) -> list[GeoResolution]:
    """Claim a bounded batch in ONE committed UnitOfWork."""
    async with uow_factory() as uow:
        return await uow.geo_resolutions.claim_batch(
            claimed_by=claimed_by,
            limit=limit,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
        )


async def state_of(
    uow_factory: Callable[[], PostgresUnitOfWork], resolution_id: UUID
) -> GeoResolution | None:
    """Return the authoritative work state in a fresh UoW."""
    async with uow_factory() as uow:
        return await uow.geo_resolutions.get_by_id(resolution_id)


async def observation_count(
    integration_engine: AsyncEngine,
) -> int:
    """Count every immutable observation row."""
    return await table_count(integration_engine, "entity_location_observation")


async def table_count(integration_engine: AsyncEngine, table: str) -> int:
    """Count every row of one application table."""
    async with integration_engine.begin() as connection:
        result = await connection.execute(text(f"SELECT count(*) FROM ati.{table}"))
        return int(result.scalar_one())


async def direct_insert_resolution(
    integration_engine: AsyncEngine,
    *,
    entity_id: UUID,
    evidence_id: UUID,
    status: str = "pending",
    attempt_count: int = 0,
    next_attempt_at: datetime | None = None,
    claimed_by: str | None = None,
    lease_expires_at: datetime | None = None,
    resolved_location_id: UUID | None = None,
    last_error_code: str | None = None,
) -> UUID:
    """Insert a GeoResolution row directly (test-only fixture control)."""
    resolution_id = uuid4()
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO ati.geo_resolution ("
                "id, entity_id, evidence_id, status, attempt_count,"
                "next_attempt_at, claimed_by, lease_expires_at,"
                "resolved_location_id, last_error_code, version) "
                "VALUES (:id, :entity_id, :evidence_id, :status,"
                ":attempt_count, :next_attempt_at, :claimed_by,"
                ":lease_expires_at, :resolved_location_id,"
                ":last_error_code, 1)"
            ),
            {
                "id": resolution_id,
                "entity_id": entity_id,
                "evidence_id": evidence_id,
                "status": status,
                "attempt_count": attempt_count,
                "next_attempt_at": next_attempt_at,
                "claimed_by": claimed_by,
                "lease_expires_at": lease_expires_at,
                "resolved_location_id": resolved_location_id,
                "last_error_code": last_error_code,
            },
        )
    return resolution_id


async def force_lease_expiry(
    integration_engine: AsyncEngine, resolution_id: UUID
) -> None:
    """Force an expired lease deterministically (test timestamp control)."""
    await _update_timestamp(
        integration_engine,
        "SET lease_expires_at = now() - interval '1 second'",
        resolution_id,
    )


async def force_due(integration_engine: AsyncEngine, resolution_id: UUID) -> None:
    """Force a retry-scheduled row due now (test timestamp control)."""
    await _update_timestamp(
        integration_engine,
        "SET next_attempt_at = now() - interval '1 second'",
        resolution_id,
    )


async def _update_timestamp(
    integration_engine: AsyncEngine, assignment: str, resolution_id: UUID
) -> None:
    """Apply one timestamp assignment to one work row (test control)."""
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(f"UPDATE ati.geo_resolution {assignment} WHERE id = :resolution_id"),
            {"resolution_id": resolution_id},
        )


class ClaimedResolution(GeoResolution):
    """A claim result whose authoritative identity fields are non-null.

    The stored claim function always returns complete rows; this narrow read
    model lets callers use ``id``/``version``/``claimed_by`` without
    re-narrowing optionals (purely a test-side convenience).
    """

    id: UUID
    version: int
    claimed_by: str


async def _claim_single(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
    resolution_id: UUID,
    *,
    claimed_by: str,
    max_attempts: int = 10,
) -> ClaimedResolution:
    """Claim exactly one eligible row under a fresh identity."""
    state = await state_of(uow_factory, resolution_id)
    if state is not None and state.status is GeoResolutionStatus.PROCESSING:
        # A live PROCESSING row must first have its lease expired before a
        # reclaim can compete for it (deterministic timestamp control).
        await force_lease_expiry(integration_engine, resolution_id)
    claimed = await claim(
        uow_factory, claimed_by=claimed_by, limit=20, max_attempts=max_attempts
    )
    matches = [row for row in claimed if row.id == resolution_id]
    assert len(matches) == 1
    row = matches[0]
    assert row.id is not None
    assert row.version is not None
    assert row.claimed_by is not None
    return ClaimedResolution(**row.model_dump())


def observation_for(
    *,
    resolution_id: UUID,
    entity_id: UUID,
    location_id: UUID,
    evidence_id: UUID,
    precision: LocationPrecision = LocationPrecision.COUNTRY,
    observed_at: datetime | None = None,
    retrieved_at: datetime = _RETRIEVED_AT,
    resolved_at: datetime = _RESOLVED_AT,
) -> EntityLocationObservation:
    """Build the deterministic observation for one successful completion."""
    return EntityLocationObservation(
        id=observation_uuid_for_resolution(resolution_id),
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
        precision=precision,
        observed_at=observed_at,
        retrieved_at=retrieved_at,
        resolved_at=resolved_at,
        resolution_method=CANONICAL_GEOGRAPHY_METHOD,
    )


async def complete_resolved_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    resolution: GeoResolution,
    observation: EntityLocationObservation,
) -> GeoResolution:
    """Complete one claimed resolution through a committed UnitOfWork."""
    assert resolution.id is not None and resolution.version is not None
    async with uow_factory() as uow:
        return await uow.geo_resolutions.complete_resolved(
            resolution.id,
            resolution.version,
            resolution.claimed_by or "",
            observation,
        )


async def _seed_resolvable(
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    country_code: str = "US",
) -> tuple[UUID, UUID, UUID, UUID]:
    """Seed work plus one canonical Location; returns all identities."""
    async with uow_factory() as uow:
        entity_id, evidence_id, resolution_id = await seed_geolocation_work(
            uow, country_code=country_code
        )
        assert resolution_id is not None
        persisted = await uow.locations.upsert(location_factory(country_code))
        assert persisted.id is not None
        return entity_id, evidence_id, resolution_id, persisted.id


# ---------------------------------------------------------------------------
# G26C-P01..P12 claim matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p01_eligible_pending_is_claimed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26C-P01 an eligible PENDING row transitions to PROCESSING on claim."""
    async with uow_factory() as uow:
        _, _, resolution_id = await seed_geolocation_work(uow, country_code="US")
    assert resolution_id is not None
    claimed = await claim(uow_factory, claimed_by="worker-a")
    assert [row.id for row in claimed] == [resolution_id]
    row = claimed[0]
    assert row.status is GeoResolutionStatus.PROCESSING
    assert row.claimed_by == "worker-a"
    assert row.lease_expires_at is not None
    assert row.attempt_count == 1
    assert row.version is not None
    assert row.next_attempt_at is None


@pytest.mark.asyncio
async def test_p02_future_scheduled_pending_is_not_claimed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P02 future next_attempt_at work is never claimed early."""
    async with uow_factory() as uow:
        _, _, resolution_id = await seed_geolocation_work(uow, country_code="US")
        assert resolution_id is not None
        other_entity, other_evidence, _ = await seed_geolocation_work(
            uow, country_code="CA", create_resolution=False
        )
    await direct_insert_resolution(
        integration_engine,
        entity_id=other_entity,
        evidence_id=other_evidence,
        status="pending",
        next_attempt_at=_FUTURE,
    )
    claimed = await claim(uow_factory, claimed_by="worker-a")
    assert [row.id for row in claimed] == [resolution_id]


@pytest.mark.asyncio
async def test_p03_unexpired_processing_is_not_claimed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P03 unexpired PROCESSING work is never double-claimed."""
    async with uow_factory() as uow:
        _, _, resolution_id = await seed_geolocation_work(uow, country_code="US")
        assert resolution_id is not None
        other_entity, other_evidence, _ = await seed_geolocation_work(
            uow, country_code="CA", create_resolution=False
        )
    await direct_insert_resolution(
        integration_engine,
        entity_id=other_entity,
        evidence_id=other_evidence,
        status="processing",
        attempt_count=1,
        claimed_by="worker-x",
        lease_expires_at=_FUTURE,
    )
    claimed = await claim(uow_factory, claimed_by="worker-a")
    assert [row.id for row in claimed] == [resolution_id]


@pytest.mark.asyncio
async def test_p04_expired_processing_is_reclaimed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P04 expired PROCESSING work is reclaimed under a fresh claim."""
    async with uow_factory() as uow:
        _, _, resolution_id = await seed_geolocation_work(uow, country_code="US")
        assert resolution_id is not None
        other_entity, other_evidence, _ = await seed_geolocation_work(
            uow, country_code="CA", create_resolution=False
        )
    expired_id = await direct_insert_resolution(
        integration_engine,
        entity_id=other_entity,
        evidence_id=other_evidence,
        status="processing",
        attempt_count=1,
        claimed_by="worker-x",
        lease_expires_at=_EPOCH,
    )
    claimed = await claim(uow_factory, claimed_by="worker-a")
    claimed_ids = [row.id for row in claimed]
    assert {expired_id, resolution_id} == set(claimed_ids)
    assert expired_id in claimed_ids
    row = next(row for row in claimed if row.id == expired_id)
    assert row.claimed_by == "worker-a"
    assert row.attempt_count == 2
    assert row.lease_expires_at is not None


@pytest.mark.asyncio
async def test_p05_terminal_rows_are_never_claimed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P05 terminal statuses are never claimed."""
    async with uow_factory() as uow:
        for country in _COUNTRY_CODES[:3]:
            await seed_geolocation_work(uow, country_code=country)
        # Three additional pairs (no resolution) host the terminal rows:
        # a terminal row can never share a pair with a live PENDING row.
        terminal_pairs: list[tuple[UUID, UUID]] = []
        for country in _COUNTRY_CODES[3:6]:
            entity_id, evidence_id, _ = await seed_geolocation_work(
                uow, country_code=country, create_resolution=False
            )
            terminal_pairs.append((entity_id, evidence_id))
        resolved_location = await uow.locations.upsert(location_factory("ZZ"))
        assert resolved_location.id is not None
    terminal_ids: list[UUID] = []
    async with integration_engine.begin() as connection:
        for index, status in enumerate(("resolved", "unresolvable", "failed")):
            row_id = uuid4()
            terminal_ids.append(row_id)
            pair_entity, pair_evidence = terminal_pairs[index]
            await connection.execute(
                text(
                    "INSERT INTO ati.geo_resolution ("
                    "id, entity_id, evidence_id, status, attempt_count, "
                    "resolved_location_id, last_error_code, version) "
                    "VALUES (:id, :entity_id, :evidence_id, :status, 1, "
                    ":loc, :code, 1)"
                ),
                {
                    "id": row_id,
                    "entity_id": pair_entity,
                    "evidence_id": pair_evidence,
                    "status": status,
                    "loc": resolved_location.id if status == "resolved" else None,
                    "code": "x" if status != "resolved" else None,
                },
            )
    claimed = await claim(uow_factory, claimed_by="worker-a", limit=100)
    claimed_ids = {row.id for row in claimed}
    assert not claimed_ids & set(terminal_ids)
    assert len(claimed) == 3


@pytest.mark.asyncio
async def test_p06_claim_limit_is_bounded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26C-P06 a claim returns at most N eligible rows."""
    async with uow_factory() as uow:
        for index in range(7):
            await seed_geolocation_work(uow, country_code=_COUNTRY_CODES[index])
    claimed = await claim(uow_factory, claimed_by="worker-a", limit=3)
    assert len(claimed) == 3


@pytest.mark.asyncio
async def test_p07_claim_order_is_deterministic(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26C-P07 claims follow deterministic (eligibility, created, id) order."""
    async with uow_factory() as uow:
        for country in _COUNTRY_CODES[1:4]:
            await seed_geolocation_work(uow, country_code=country)
    claimed = await claim(uow_factory, claimed_by="worker-a", limit=10)
    assert len(claimed) == 3
    created_order = [row.created_at for row in claimed if row.created_at is not None]
    assert created_order == sorted(created_order)
    # Rows created in one transaction share created_at; id is the final
    # deterministic tie-breaker, matching the documented ordering.
    ids = [row.id for row in claimed]
    if created_order[0] == created_order[-1]:
        assert ids == sorted(ids, key=lambda value: str(value))


@pytest.mark.asyncio
async def test_p08_two_workers_claim_disjoint_batches(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26C-P08 concurrent workers claim disjoint bounded batches."""
    async with uow_factory() as uow:
        ids: set[UUID] = set()
        for country in _COUNTRY_CODES[4:12]:
            _, _, resolution_id = await seed_geolocation_work(uow, country_code=country)
            assert resolution_id is not None
            ids.add(resolution_id)

    async def worker_take(name: str) -> list[UUID | None]:
        return [row.id for row in await claim(uow_factory, claimed_by=name, limit=100)]

    first, second = await asyncio.gather(
        worker_take("worker-a"), worker_take("worker-b")
    )
    assert len(first) + len(second) == len(ids)
    assert not set(first) & set(second)


@pytest.mark.asyncio
async def test_p09_claim_increments_attempt_exactly_once(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P09 each claim increments attempt_count exactly once."""
    async with uow_factory() as uow:
        _, _, resolution_id = await seed_geolocation_work(uow, country_code="US")
    assert resolution_id is not None
    first = (await claim(uow_factory, claimed_by="worker-a"))[0]
    assert first.attempt_count == 1
    await force_lease_expiry(integration_engine, resolution_id)
    second = (await claim(uow_factory, claimed_by="worker-b"))[0]
    assert second.attempt_count == 2


@pytest.mark.asyncio
async def test_p10_claim_allocates_a_fresh_db_version(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P10 every claim allocates a fresh database-issued version."""
    async with uow_factory() as uow:
        _, _, resolution_id = await seed_geolocation_work(uow, country_code="US")
    assert resolution_id is not None
    async with integration_engine.begin() as connection:
        before = (
            await connection.execute(
                text("SELECT version FROM ati.geo_resolution WHERE id = :id"),
                {"id": resolution_id},
            )
        ).scalar_one()
    claimed = (await claim(uow_factory, claimed_by="worker-a"))[0]
    assert claimed.version is not None
    assert claimed.version > int(before)


@pytest.mark.asyncio
async def test_p11_expired_at_max_attempts_fails_not_reclaimed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P11 expired PROCESSING work at the budget becomes FAILED."""
    async with uow_factory() as uow:
        entity_id, evidence_id, _ = await seed_geolocation_work(
            uow, country_code="US", create_resolution=False
        )
    exhausted_id = await direct_insert_resolution(
        integration_engine,
        entity_id=entity_id,
        evidence_id=evidence_id,
        status="processing",
        attempt_count=3,
        claimed_by="worker-x",
        lease_expires_at=_EPOCH,
    )
    claimed = await claim(uow_factory, claimed_by="worker-a", max_attempts=3)
    # The expired-at-max row is NOT claimed...
    assert all(row.id != exhausted_id for row in claimed)
    # ...and is now terminally FAILED with no next attempt.
    async with integration_engine.begin() as connection:
        row = (
            await connection.execute(
                text(
                    "SELECT status, attempt_count, last_error_code, "
                    "next_attempt_at FROM ati.geo_resolution WHERE id = :id"
                ),
                {"id": exhausted_id},
            )
        ).first()
    assert row is not None
    status, attempts, code, next_at = row[0], int(row[1]), row[2], row[3]
    assert status == "failed"
    assert attempts == 3
    assert code == "attempts_exhausted"
    assert next_at is None


@pytest.mark.asyncio
async def test_p12_claim_rollback_preserves_previous_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26C-P12 a rolled-back claim leaves the prior durable state intact."""
    async with uow_factory() as uow:
        _, _, resolution_id = await seed_geolocation_work(uow, country_code="US")
    assert resolution_id is not None
    try:
        async with uow_factory() as uow:
            await uow.geo_resolutions.claim_batch(
                claimed_by="worker-a", limit=5, lease_seconds=300, max_attempts=3
            )
            raise RuntimeError("injected failure")
    except RuntimeError:
        pass
    state = await state_of(uow_factory, resolution_id)
    assert state is not None
    assert state.status is GeoResolutionStatus.PENDING
    assert state.claimed_by is None
    assert state.attempt_count == 0


# ---------------------------------------------------------------------------
# G26C-P13..P18 stale-claim matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p13_correct_owner_version_lease_accepted(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P13 correct owner/version/live lease is accepted and completes."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    completed = await complete_resolved_observation(uow_factory, claimed, observation)
    assert completed.status is GeoResolutionStatus.RESOLVED
    assert completed.resolved_location_id == location_id
    assert completed.claimed_by is None
    assert completed.lease_expires_at is None
    assert await observation_count(integration_engine) == 1
    assert await table_count(integration_engine, "entity_location") == 1


@pytest.mark.asyncio
async def test_p14_wrong_owner_is_a_typed_conflict(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P14 a wrong claimant is rejected with no mutation."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoResolutionClaimantMismatchError):
        async with uow_factory() as uow:
            await uow.geo_resolutions.complete_resolved(
                resolution_id,
                claimed.version,
                "worker-b",
                observation,
            )
    assert await observation_count(integration_engine) == 0
    state = await state_of(uow_factory, resolution_id)
    assert state is not None and state.status is GeoResolutionStatus.PROCESSING


@pytest.mark.asyncio
async def test_p15_stale_version_is_a_typed_conflict(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P15 a stale expected version is rejected with no mutation."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoResolutionVersionConflictError):
        async with uow_factory() as uow:
            await uow.geo_resolutions.complete_resolved(
                resolution_id,
                (claimed.version or 0) - 1,
                "worker-a",
                observation,
            )
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p16_expired_lease_is_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P16 a completed mutation with an expired lease is rejected."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    await force_lease_expiry(integration_engine, resolution_id)
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoResolutionLeaseExpiredError):
        async with uow_factory() as uow:
            await uow.geo_resolutions.complete_resolved(
                resolution_id,
                claimed.version,
                "worker-a",
                observation,
            )
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p17_stale_worker_after_reclaim_is_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P17 A expires, B reclaims, A's completion is rejected."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    worker_a = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    # A's lease expires; B reclaims with attempt +1 under a fresh version.
    worker_b = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-b"
    )
    assert worker_b.attempt_count == worker_a.attempt_count + 1
    assert worker_b.version != worker_a.version
    observation_a = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    # A completes with its (now stale) version: rejected, no mutation.
    with pytest.raises(GeoResolutionVersionConflictError):
        async with uow_factory() as uow:
            await uow.geo_resolutions.complete_resolved(
                resolution_id,
                worker_a.version,
                "worker-a",
                observation_a,
            )
    assert await observation_count(integration_engine) == 0
    # B remains authoritative.
    state = await state_of(uow_factory, resolution_id)
    assert state is not None
    assert state.claimed_by == "worker-b"
    assert state.version == worker_b.version


@pytest.mark.asyncio
async def test_p18_reclaim_owner_completes(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P18 B (the authoritative owner) completes successfully."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    worker_b = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-b"
    )
    observation_b = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    completed = await complete_resolved_observation(
        uow_factory, worker_b, observation_b
    )
    assert completed.status is GeoResolutionStatus.RESOLVED
    assert completed.resolved_location_id == location_id
    assert await observation_count(integration_engine) == 1


# ---------------------------------------------------------------------------
# G26C-P19..P30 resolved-completion matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p19_valid_success_is_atomic(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P19 success atomically appends observation + current state."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    completed = await complete_resolved_observation(uow_factory, claimed, observation)
    assert completed.status is GeoResolutionStatus.RESOLVED
    async with uow_factory() as uow:
        obs_rows = await uow.entity_location_observations.list_for_entity(entity_id)
        current = await uow.entity_locations.get_by_entity_id(entity_id)
    assert len(obs_rows) == 1
    assert obs_rows[0].id == observation.id
    assert obs_rows[0].evidence_id == evidence_id
    assert obs_rows[0].location_id == location_id
    assert obs_rows[0].observed_at is None
    assert obs_rows[0].retrieved_at == _RETRIEVED_AT
    assert obs_rows[0].resolved_at == _RESOLVED_AT
    assert current is not None
    assert current.location_id == location_id
    assert current.latest_observation_id == observation.id
    assert current.first_observed_at == _RETRIEVED_AT


@pytest.mark.asyncio
async def test_p20_missing_entity_is_a_full_rollback(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P20 a soft-deleted Entity fails the completion with no mutation."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    async with uow_factory() as uow:
        await uow.entities.soft_delete(entity_id, actor_id=uuid4())
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoEntityNotFoundError):
        await complete_resolved_observation(uow_factory, claimed, observation)
    assert await observation_count(integration_engine) == 0
    assert await table_count(integration_engine, "entity_location") == 0


@pytest.mark.asyncio
async def test_p21_missing_evidence_is_a_full_rollback(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P21 missing LegacyEvidence fails the completion with no mutation."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    async with integration_engine.begin() as connection:
        # LegacyEvidence is immutable and FK-referenced by the work row; simulate a
        # missing LegacyEvidence row by disabling FK enforcement in this session.
        await connection.execute(text("SET session_replication_role = replica"))
        await connection.execute(
            text("DELETE FROM ati.evidence WHERE id = :id"),
            {"id": evidence_id},
        )
        await connection.execute(text("SET session_replication_role = origin"))
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoEvidenceNotFoundError):
        await complete_resolved_observation(uow_factory, claimed, observation)
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p22_wrong_evidence_type_is_a_full_rollback(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P22 non-GEOLOCATION LegacyEvidence fails the completion."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    # The work was created against valid GEOLOCATION LegacyEvidence; corrupt the
    # LegacyEvidence type after creation to force the database-authoritative guard.
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE ati.evidence SET evidence_type = 'urn:ati:evidence:dns' "
                "WHERE id = :id"
            ),
            {"id": evidence_id},
        )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoEvidenceTypeError):
        await complete_resolved_observation(uow_factory, claimed, observation)
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p23_subject_mismatch_is_a_full_rollback(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P23 a subject mismatch between LegacyEvidence and work is rejected."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    async with uow_factory() as uow:
        other_entity = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value=f"other-{uuid4().hex[:8]}.com")
        )
        assert other_entity.id is not None
        other = other_entity.id
    async with integration_engine.begin() as connection:
        await connection.execute(
            text("UPDATE ati.evidence SET subject_entity_id = :other WHERE id = :id"),
            {"other": other, "id": evidence_id},
        )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoEvidenceSubjectMismatchError):
        await complete_resolved_observation(uow_factory, claimed, observation)
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p24_missing_location_is_a_full_rollback(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P24 a missing canonical Location fails the completion."""
    entity_id, evidence_id, resolution_id, _location_id = await _seed_resolvable(
        uow_factory
    )
    ghost_location = uuid4()
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=ghost_location,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoLocationNotFoundError):
        await complete_resolved_observation(uow_factory, claimed, observation)
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p25_exact_replay_does_not_duplicate(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P25 an exact replay of the same success is a no-op, no duplicate."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    completed = await complete_resolved_observation(uow_factory, claimed, observation)
    assert completed.status is GeoResolutionStatus.RESOLVED
    # Uncertain-commit replay: identical inputs, deterministic identity.
    replayed = await complete_resolved_observation(uow_factory, claimed, observation)
    assert replayed.status is GeoResolutionStatus.RESOLVED
    assert replayed.version == completed.version
    assert await observation_count(integration_engine) == 1
    assert await table_count(integration_engine, "entity_location") == 1


@pytest.mark.asyncio
async def test_p26_conflicting_replay_is_a_typed_conflict(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P26 a replay to a different Location is a typed conflict."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    await complete_resolved_observation(uow_factory, claimed, observation)
    async with uow_factory() as uow:
        other = await uow.locations.upsert(location_factory("CA"))
        assert other.id is not None
        other_location_id = other.id
    conflicting = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=other_location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoResolutionTerminalReplayConflictError):
        await complete_resolved_observation(uow_factory, claimed, conflicting)
    assert await observation_count(integration_engine) == 1


@pytest.mark.asyncio
async def test_p27_existing_current_state_is_reconciled(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P27 completion preserves the PR 26A reconciliation semantics."""
    entity_id, evidence_id, resolution_id, us_location = await _seed_resolvable(
        uow_factory
    )
    async with uow_factory() as uow:
        ca = await uow.locations.upsert(location_factory("CA"))
        assert ca.id is not None
        previous_retrieved = _RETRIEVED_AT - timedelta(hours=2)
        first_obs = observation_for(
            resolution_id=uuid4(),
            entity_id=entity_id,
            location_id=us_location,
            evidence_id=evidence_id,
            retrieved_at=previous_retrieved,
            resolved_at=previous_retrieved,
        )
        await uow.entity_location_observations.append(first_obs)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=ca.id,
        evidence_id=evidence_id,
    )
    await complete_resolved_observation(uow_factory, claimed, observation)
    async with uow_factory() as uow:
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        obs_rows = await uow.entity_location_observations.list_for_entity(entity_id)
    assert current is not None
    # The newer retrieval wins current state; earliest first_observed_at stays.
    assert current.location_id == ca.id
    assert current.latest_observation_id == observation.id
    assert current.first_observed_at == previous_retrieved
    assert len(obs_rows) == 2


@pytest.mark.asyncio
async def test_p28_earlier_observed_at_keeps_first_observed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P28 an earlier observed_at preserves first-observed semantics."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
        observed_at=_EPOCH,
    )
    await complete_resolved_observation(uow_factory, claimed, observation)
    async with uow_factory() as uow:
        current = await uow.entity_locations.get_by_entity_id(entity_id)
    assert current is not None
    # COALESCE(observed_at, retrieved_at) = observed_at for the effective time.
    assert current.first_observed_at == _EPOCH
    assert current.last_observed_at == _EPOCH


@pytest.mark.asyncio
async def test_p29_newer_observation_advances_current_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P29 a newer observation advances latest/current semantics."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    older_at = _RETRIEVED_AT - timedelta(days=2)
    async with uow_factory() as uow:
        older_obs = observation_for(
            resolution_id=uuid4(),
            entity_id=entity_id,
            location_id=location_id,
            evidence_id=evidence_id,
            retrieved_at=older_at,
            resolved_at=older_at,
        )
        await uow.entity_location_observations.append(older_obs)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    await complete_resolved_observation(uow_factory, claimed, observation)
    async with uow_factory() as uow:
        current = await uow.entity_locations.get_by_entity_id(entity_id)
    assert current is not None
    assert current.latest_observation_id == observation.id
    assert current.last_observed_at == _RETRIEVED_AT
    assert current.first_observed_at == older_at


@pytest.mark.asyncio
async def test_p30_injected_rollback_after_append_commits_nothing(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P30 a failed completion transaction commits nothing."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    try:
        async with uow_factory() as uow:
            await uow.geo_resolutions.complete_resolved(
                resolution_id,
                claimed.version,
                "worker-a",
                observation,
            )
            raise RuntimeError("injected post-append failure")
    except RuntimeError:
        pass
    assert await observation_count(integration_engine) == 0
    assert await table_count(integration_engine, "entity_location") == 0
    state = await state_of(uow_factory, resolution_id)
    assert state is not None and state.status is GeoResolutionStatus.PROCESSING


@pytest.mark.asyncio
async def test_p30b_completion_of_unknown_resolution_is_not_found(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A completion against an unknown work identity is a typed not-found."""
    ghost = uuid4()
    observation = observation_for(
        resolution_id=ghost,
        entity_id=uuid4(),
        location_id=uuid4(),
        evidence_id=uuid4(),
    )
    with pytest.raises(GeoResolutionNotFoundError):
        async with uow_factory() as uow:
            await uow.geo_resolutions.complete_resolved(
                ghost, 1, "worker-a", observation
            )


@pytest.mark.asyncio
async def test_p30c_completion_of_pending_row_is_an_invalid_transition(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """A completion against a never-claimed PENDING row is invalid."""
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    state = await state_of(uow_factory, resolution_id)
    assert state is not None and state.status is GeoResolutionStatus.PENDING
    assert state.version is not None
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoResolutionInvalidTransitionError):
        async with uow_factory() as uow:
            await uow.geo_resolutions.complete_resolved(
                resolution_id,
                state.version,
                "worker-a",
                observation,
            )
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p30d_deterministic_identity_bound_elsewhere_is_a_duplicate(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """A deterministic observation identity bound to a different tuple rejects.

    The database refrains from silently adopting an observation whose
    deterministic identity was already claimed by a different tuple.
    """
    entity_id, evidence_id, resolution_id, location_id = await _seed_resolvable(
        uow_factory
    )
    async with uow_factory() as uow:
        ca = await uow.locations.upsert(location_factory("CA"))
        assert ca.id is not None
        squat_location = ca.id
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    # Squat the deterministic observation identity with a DIFFERENT existing
    # Location: the completion must refuse to adopt it silently.
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO ati.entity_location_observation ("
                'id, entity_id, location_id, evidence_id, "precision", '
                "retrieved_at, resolved_at, resolution_method, version) "
                "VALUES (:id, :entity_id, :location_id, :evidence_id, "
                "'country', now(), now(), 'x', 1)"
            ),
            {
                "id": observation_uuid_for_resolution(resolution_id),
                "entity_id": entity_id,
                "location_id": squat_location,
                "evidence_id": evidence_id,
            },
        )
    observation = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(EntityLocationObservationDuplicateError):
        await complete_resolved_observation(uow_factory, claimed, observation)


# ---------------------------------------------------------------------------
# G26C-P31..P38 failure/unresolvable matrix
# ---------------------------------------------------------------------------


async def _record_failure(
    uow_factory: Callable[[], PostgresUnitOfWork],
    resolution: GeoResolution,
    *,
    error_code: str,
    retryable: bool,
    claimed_by: str | None = None,
    expected_version: int | None = None,
    max_attempts: int = 3,
    retry_base_seconds: float = 60.0,
    retry_max_seconds: float = 3600.0,
) -> GeoResolution:
    """Record one failure transition in a committed UnitOfWork."""
    assert resolution.id is not None
    if expected_version is None:
        assert resolution.version is not None
        expected_version = resolution.version
    async with uow_factory() as uow:
        return await uow.geo_resolutions.record_failure(
            resolution.id,
            expected_version,
            claimed_by if claimed_by is not None else (resolution.claimed_by or ""),
            error_code,
            retryable=retryable,
            retry_base_seconds=retry_base_seconds,
            retry_max_seconds=retry_max_seconds,
            max_attempts=max_attempts,
        )


@pytest.mark.asyncio
async def test_p31_unresolvable_is_terminal_without_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P31 unresolvable is terminal with no observation or state change."""
    entity_id, evidence_id, resolution_id, _ = await _seed_resolvable(uow_factory)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    async with uow_factory() as uow:
        completed = await uow.geo_resolutions.complete_unresolvable(
            resolution_id=resolution_id,
            expected_version=claimed.version,
            claimed_by="worker-a",
            error_code="unknown_city",
        )
    assert completed.status is GeoResolutionStatus.UNRESOLVABLE
    assert completed.resolved_location_id is None
    assert completed.last_error_code == "unknown_city"
    assert completed.claimed_by is None and completed.lease_expires_at is None
    assert completed.next_attempt_at is None
    assert await observation_count(integration_engine) == 0
    assert await table_count(integration_engine, "entity_location") == 0


@pytest.mark.asyncio
async def test_p32_ambiguity_is_terminal_and_never_guessed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P32 ambiguity maps to terminal unresolvable with its code."""
    entity_id, evidence_id, resolution_id, _ = await _seed_resolvable(uow_factory)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    async with uow_factory() as uow:
        completed = await uow.geo_resolutions.complete_unresolvable(
            resolution_id=resolution_id,
            expected_version=claimed.version,
            claimed_by="worker-a",
            error_code=AMBIGUITY_ERROR_CODE,
        )
    assert completed.status is GeoResolutionStatus.UNRESOLVABLE
    assert completed.last_error_code == AMBIGUITY_ERROR_CODE
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p33_retryable_failure_is_scheduled_with_backoff(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P33 a retryable failure returns to PENDING with a schedule."""
    _, _, resolution_id, _ = await _seed_resolvable(uow_factory)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    outcome = await _record_failure(
        uow_factory,
        claimed,
        error_code="resolver_error",
        retryable=True,
        max_attempts=4,
        retry_base_seconds=60.0,
        retry_max_seconds=3600.0,
    )
    assert outcome.status is GeoResolutionStatus.PENDING
    assert outcome.attempt_count == 1
    assert outcome.claimed_by is None and outcome.lease_expires_at is None
    assert outcome.next_attempt_at is not None
    # Attempt 1 -> base delay (60s), no jitter: the schedule is inside the
    # deterministic window around DB now.
    delay = (outcome.next_attempt_at - datetime.now(UTC)).total_seconds()
    assert 50.0 <= delay <= 180.0


@pytest.mark.asyncio
async def test_p34_retry_clears_the_lease(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P34 the retry transition clears claimant/lease state."""
    _, _, resolution_id, _ = await _seed_resolvable(uow_factory)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    outcome = await _record_failure(
        uow_factory, claimed, error_code="resolver_error", retryable=True
    )
    assert outcome.claimed_by is None
    assert outcome.lease_expires_at is None
    state = await state_of(uow_factory, resolution_id)
    assert (
        state is not None
        and state.claimed_by is None
        and state.lease_expires_at is None
    )


@pytest.mark.asyncio
async def test_p35_terminal_error_is_failed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P35 a non-retryable failure terminates as FAILED."""
    _, _, resolution_id, _ = await _seed_resolvable(uow_factory)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    outcome = await _record_failure(
        uow_factory, claimed, error_code="malformed_evidence", retryable=False
    )
    assert outcome.status is GeoResolutionStatus.FAILED
    assert outcome.last_error_code == "malformed_evidence"
    assert outcome.next_attempt_at is None
    assert outcome.claimed_by is None and outcome.lease_expires_at is None


@pytest.mark.asyncio
async def test_p36_terminal_failure_mutates_no_geographic_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P36 terminal transitions never create observations/current state."""
    _, _, resolution_id, _ = await _seed_resolvable(uow_factory)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    await _record_failure(
        uow_factory,
        claimed,
        error_code="resolver_error",
        retryable=True,
        max_attempts=1,
    )
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p37_stale_failure_request_is_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P37 a stale failure request (wrong owner) is rejected."""
    _, _, resolution_id, _ = await _seed_resolvable(uow_factory)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    with pytest.raises(GeoResolutionClaimantMismatchError):
        await _record_failure(
            uow_factory,
            claimed,
            error_code="resolver_error",
            retryable=True,
            claimed_by="worker-b",
        )


@pytest.mark.asyncio
async def test_p38_failure_rollback_retains_processing(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P38 a rolled-back failure transition keeps PROCESSING state."""
    _, _, resolution_id, _ = await _seed_resolvable(uow_factory)
    claimed = await _claim_single(
        uow_factory, integration_engine, resolution_id, claimed_by="worker-a"
    )
    try:
        async with uow_factory() as uow:
            await uow.geo_resolutions.record_failure(
                resolution_id,
                claimed.version,
                "worker-a",
                "resolver_error",
                retryable=True,
                retry_base_seconds=60.0,
                retry_max_seconds=3600.0,
                max_attempts=3,
            )
            raise RuntimeError("injected failure")
    except RuntimeError:
        pass
    state = await state_of(uow_factory, resolution_id)
    assert state is not None and state.status is GeoResolutionStatus.PROCESSING
    assert state.claimed_by == "worker-a"


# ---------------------------------------------------------------------------
# G26C-P39..P43 migration/index matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p39_claim_explain_uses_the_intended_index(
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P39 the claim predicate is proven index-eligible with EXPLAIN."""
    statements = {
        "pending": (
            "SELECT * FROM ati.geo_resolution gr "
            "WHERE gr.status = 'pending' "
            "AND (gr.next_attempt_at IS NULL OR gr.next_attempt_at <= now()) "
            "ORDER BY COALESCE(gr.next_attempt_at, gr.created_at), "
            "gr.created_at, gr.id LIMIT 10 FOR UPDATE SKIP LOCKED"
        ),
        "processing": (
            "SELECT * FROM ati.geo_resolution gr "
            "WHERE gr.status = 'processing' AND gr.lease_expires_at <= now() "
            "ORDER BY gr.lease_expires_at, gr.created_at, gr.id "
            "LIMIT 10 FOR UPDATE SKIP LOCKED"
        ),
    }
    async with integration_engine.begin() as connection:
        await connection.execute(text("SET enable_seqscan = off"))
        for label, statement in statements.items():
            rows = (await connection.execute(text("EXPLAIN " + statement))).all()
            # PostgreSQL 18's TEXT plan format returns one row per plan line.
            plan = "\n".join(str(row[0]) for row in rows)
            index_name = (
                "geo_resolution_pending_claim_idx"
                if label == "pending"
                else "geo_resolution_processing_claim_idx"
            )
            assert index_name in plan, f"{label} plan misses {index_name}: {plan}"
            assert "Seq Scan" not in plan, f"{label} plan seq-scans: {plan}"


@pytest.mark.asyncio
async def test_p42_pgvector_and_postgis_coexist_and_v0024_is_installed(
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P42 pgvector + PostGIS coexist and the v0024 API is installed."""
    async with integration_engine.begin() as connection:
        extensions = {
            row[0]
            for row in (
                await connection.execute(
                    text(
                        "SELECT extname FROM pg_extension "
                        "WHERE extname IN ('vector', 'postgis')"
                    )
                )
            ).all()
        }
        assert {"vector", "postgis"} <= extensions
        functions = {
            row[0]
            for row in (
                await connection.execute(
                    text(
                        "SELECT proname FROM pg_proc "
                        "WHERE proname IN ('claim_geo_resolutions',"
                        "'complete_geo_resolution_resolved',"
                        "'complete_geo_resolution_unresolvable',"
                        "'record_geo_resolution_failure')"
                    )
                )
            ).all()
        }
        assert functions == {
            "claim_geo_resolutions",
            "complete_geo_resolution_resolved",
            "complete_geo_resolution_unresolvable",
            "record_geo_resolution_failure",
        }


@pytest.mark.asyncio
async def test_p43_prior_sql_apis_remain_unchanged(
    integration_engine: AsyncEngine,
) -> None:
    """G26C-P43 the v0021/v0022/v0023 SQL APIs remain installed."""
    async with integration_engine.begin() as connection:
        functions = {
            row[0]
            for row in (
                (await connection.execute(text("SELECT proname FROM pg_proc"))).all()
            )
        }
    for name in (
        "upsert_location",
        "append_entity_location_observation",
        "create_geo_resolution",
        "upsert_reference_location",
        "reference_geometry_parse",
        "reference_centroid_parse",
    ):
        assert name in functions


# ---------------------------------------------------------------------------
# Vertical slices (production worker against real PostgreSQL/PostGIS)
# ---------------------------------------------------------------------------


class _SessionBoundResolver(LocationResolver):
    """LocationResolver adapter with one short read session per resolve."""

    def __init__(self, session_factory: async_sessionmaker[Any]) -> None:
        """Bind the read-session factory."""
        self._session_factory = session_factory

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Resolve through the real PostGIS canonical resolver."""
        async with self._session_factory() as session:
            return await PostgresCanonicalGeographyResolver(session).resolve(claim)


class _ScriptedResolver(LocationResolver):
    """Deterministic resolver: fail the first N attempts, then resolve."""

    def __init__(
        self, session_factory: async_sessionmaker[Any], *, fail_attempts: int = 0
    ) -> None:
        """Bind the read-session factory and the failure plan."""
        self._session_factory = session_factory
        self.fail_attempts = fail_attempts
        self.attempts = 0

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Fail the first N attempts, then resolve through the real resolver."""
        self.attempts += 1
        if self.attempts <= self.fail_attempts:
            raise RuntimeError("scripted transient failure")
        async with self._session_factory() as session:
            return await PostgresCanonicalGeographyResolver(session).resolve(claim)


def _worker_instance(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    *,
    worker_id: str,
    resolver: LocationResolver,
    max_attempts: int = 3,
    batch_size: int = 10,
) -> GeoResolutionWorker:
    """Compose one production-style worker instance."""
    return GeoResolutionWorker(
        uow_factory=uow_factory,
        resolver=resolver,
        config=GeoResolutionWorkerConfig(
            enabled=True,
            worker_id=worker_id,
            batch_size=batch_size,
            lease_seconds=300,
            poll_interval_seconds=1.0,
            max_attempts=max_attempts,
            retry_base_seconds=60.0,
            retry_max_seconds=3600.0,
        ),
    )


@pytest.mark.asyncio
async def test_vs_multi_worker_disjoint_and_single_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    integration_engine: AsyncEngine,
) -> None:
    """Multi-worker slice: disjoint claims, one observation per work item."""
    async with uow_factory() as uow:
        work: list[tuple[UUID, UUID, UUID]] = []
        for country in _COUNTRY_CODES[:8]:
            entity_id, evidence_id, resolution_id = await seed_geolocation_work(
                uow, country_code=country
            )
            assert resolution_id is not None
            persisted = await uow.locations.upsert(location_factory(country))
            assert persisted.id is not None
            work.append((entity_id, evidence_id, resolution_id))
    worker_a = _worker_instance(
        uow_factory,
        session_factory,
        worker_id="worker-a",
        resolver=_ScriptedResolver(session_factory),
    )
    worker_b = _worker_instance(
        uow_factory,
        session_factory,
        worker_id="worker-b",
        resolver=_ScriptedResolver(session_factory),
    )

    first, second = await asyncio.gather(worker_a.run_once(), worker_b.run_once())
    assert first + second == len(work)
    async with uow_factory() as uow:
        states = [await uow.geo_resolutions.get_by_id(rid) for _, _, rid in work]
        observations: dict[UUID, int] = {}
        for entity_id, _evidence_id, _rid in work:
            rows = await uow.entity_location_observations.list_for_entity(
                entity_id, limit=1000
            )
            observations[entity_id] = len(rows)
    assert all(
        state is not None and state.status is GeoResolutionStatus.RESOLVED
        for state in states
    )
    assert all(count == 1 for count in observations.values())
    assert await table_count(integration_engine, "entity_location") == len(work)


@pytest.mark.asyncio
async def test_vs_crash_recovery(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    integration_engine: AsyncEngine,
) -> None:
    """Crash/recovery slice: A claims and dies, B reclaims and completes."""
    async with uow_factory() as uow:
        entity_id, evidence_id, resolution_id = await seed_geolocation_work(
            uow, country_code="US"
        )
        assert resolution_id is not None
        persisted = await uow.locations.upsert(location_factory("US"))
        assert persisted.id is not None
        location_id = persisted.id
    # Worker A claims and COMMITS, then is simulated as crashing mid-work:
    # no completion is ever persisted for A.
    claimed_a = await claim(uow_factory, claimed_by="worker-a")
    assert len(claimed_a) == 1
    attempt_after_a = claimed_a[0].attempt_count
    version_after_a = claimed_a[0].version
    # A's lease expires deterministically.
    await force_lease_expiry(integration_engine, resolution_id)
    # Worker B reclaims (attempt +1) — A's stale completion is rejected.
    claimed_b = await claim(uow_factory, claimed_by="worker-b")
    assert len(claimed_b) == 1
    assert claimed_b[0].attempt_count == attempt_after_a + 1
    observation_a = observation_for(
        resolution_id=resolution_id,
        entity_id=entity_id,
        location_id=location_id,
        evidence_id=evidence_id,
    )
    with pytest.raises(GeoResolutionVersionConflictError):
        await complete_resolved_observation(uow_factory, claimed_a[0], observation_a)
    # B resolves and completes atomically.
    worker_b = _worker_instance(
        uow_factory,
        session_factory,
        worker_id="worker-b",
        resolver=_SessionBoundResolver(session_factory),
    )
    processed = await worker_b.run_once()
    assert processed == 0  # B already holds the claim; no eligible work remains.
    await complete_resolved_observation(uow_factory, claimed_b[0], observation_a)
    async with uow_factory() as uow:
        state = await uow.geo_resolutions.get_by_id(resolution_id)
        obs_rows = await uow.entity_location_observations.list_for_entity(
            entity_id, limit=1000
        )
        current = await uow.entity_locations.get_by_entity_id(entity_id)
    assert state is not None
    assert state.status is GeoResolutionStatus.RESOLVED
    assert state.attempt_count == attempt_after_a + 1
    assert state.version != version_after_a
    # Exactly one observation from B; A never created one.
    assert len(obs_rows) == 1
    assert obs_rows[0].location_id == location_id
    assert current is not None and current.location_id == location_id


@pytest.mark.asyncio
async def test_vs_retry_exhaustion_then_success(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    integration_engine: AsyncEngine,
) -> None:
    """Retry/exhaustion slice: transient failures are bounded and recoverable."""
    async with uow_factory() as uow:
        entity_id, evidence_id, resolution_id = await seed_geolocation_work(
            uow, country_code="US"
        )
        assert resolution_id is not None
        persisted = await uow.locations.upsert(location_factory("US"))
        assert persisted.id is not None
    # The resolver fails the first two attempts, then resolves.
    resolver = _ScriptedResolver(session_factory, fail_attempts=2)
    worker = _worker_instance(
        uow_factory,
        session_factory,
        worker_id="worker-a",
        resolver=resolver,
        max_attempts=4,
    )
    # Round 1: claim + fail -> PENDING with a backoff schedule.
    assert await worker.run_once() == 1
    state = await state_of(uow_factory, resolution_id)
    assert state is not None
    assert state.status is GeoResolutionStatus.PENDING
    assert state.attempt_count == 1
    assert state.next_attempt_at is not None
    # No early claim before the schedule.
    assert await claim(uow_factory, claimed_by="worker-a") == []
    # Force the schedule due; round 2 fails again (attempt 2).
    await force_due(integration_engine, resolution_id)
    assert await worker.run_once() == 1
    state = await state_of(uow_factory, resolution_id)
    assert state is not None
    assert state.attempt_count == 2
    assert state.status is GeoResolutionStatus.PENDING
    # Force the schedule due; round 3 succeeds atomically.
    await force_due(integration_engine, resolution_id)
    assert await worker.run_once() == 1
    state = await state_of(uow_factory, resolution_id)
    assert state is not None
    assert state.status is GeoResolutionStatus.RESOLVED
    assert state.attempt_count == 3
    async with uow_factory() as uow:
        obs_rows = await uow.entity_location_observations.list_for_entity(
            entity_id, limit=1000
        )
    # Failures created no observation; the successful attempt created one.
    assert len(obs_rows) == 1


@pytest.mark.asyncio
async def test_vs_retry_exhaustion_terminates(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    integration_engine: AsyncEngine,
) -> None:
    """Exhaustion slice: a persistently failing item terminates FAILED."""
    async with uow_factory() as uow:
        _, _, resolution_id = await seed_geolocation_work(uow, country_code="US")
        assert resolution_id is not None
        persisted = await uow.locations.upsert(location_factory("US"))
        assert persisted.id is not None
    resolver = _ScriptedResolver(session_factory, fail_attempts=1000)
    worker = _worker_instance(
        uow_factory,
        session_factory,
        worker_id="worker-a",
        resolver=resolver,
        max_attempts=2,
    )
    for round_index in range(2):
        assert await worker.run_once() == 1
        # A schedule exists only while PENDING work remains; the final
        # failing round terminates FAILED with no schedule at all.
        if round_index < 1:
            await force_due(integration_engine, resolution_id)
    state = await state_of(uow_factory, resolution_id)
    assert state is not None
    assert state.status is GeoResolutionStatus.FAILED
    assert state.attempt_count == 2
    assert state.next_attempt_at is None
    assert await observation_count(integration_engine) == 0


@pytest.mark.asyncio
async def test_p44_production_composition_no_work_and_wiring(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26C-P44 the production compose path wires and idles on an empty queue.

    Exercises the exact ``_compose_geo_worker`` entry point used by
    ``ati-geo-resolver``: worker-id generation, bounded batch/lease/retry
    settings, UoW factory, and a no-op iteration when no work is due.
    """
    from agentic_threat_investigator.cli import _compose_geo_worker
    from agentic_threat_investigator.config import Settings

    settings = Settings(
        geo_resolver_enabled=True,
        geo_resolver_worker_id="",
        geo_resolver_batch_size=17,
        geo_resolver_lease_seconds=120,
        geo_resolver_poll_interval_seconds=0.1,
        geo_resolver_max_attempts=5,
        geo_resolver_retry_base_seconds=7.0,
        geo_resolver_retry_max_seconds=700.0,
    )
    worker = _compose_geo_worker(settings, session_factory, uow_factory)
    # Auto-generated bounded worker identity, per-process unique.
    assert worker._config.worker_id.startswith("geo-resolver-")
    assert len(worker._config.worker_id) <= 200
    assert worker._config.batch_size == 17
    assert worker._config.lease_seconds == 120
    assert worker._config.max_attempts == 5
    assert worker._config.retry_base_seconds == 7.0
    # Empty queue: one iteration performs no work and persists nothing.
    assert await worker.run_once() == 0
