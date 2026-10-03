# SPDX-License-Identifier: AGPL-3.0-only
"""PR L-2 worker-level concurrency vertical slices on real PostgreSQL.

L2-P01: one bounded concurrent ``GeoResolutionWorker`` pass completes
multiple independently resolvable GEOLOCATION work items through the real
claim/evidence/canonical-resolver/completion stored-function path, creating
exactly one observation per item with exact provenance and authoritative
terminal state.

L2-P02: deterministic overlap at the worker boundary with real persistence
behind the resolver gate: two item pipelines reach the canonical resolver
concurrently when ``max_concurrency=2`` while the caller holds no
UnitOfWork across the gate, and releasing the gate persists both normally.

L2-P03/P04 regressions (disjoint multi-worker claims, stale/version/lease
conflicts) are re-run by the existing lifecycle suite unchanged.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from types import TracebackType
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.geoint.worker import (
    GeoResolutionWorker,
    GeoResolutionWorkerConfig,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
    GeoResolutionStatus,
    observation_uuid_for_resolution,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.canonical_geography_resolver import (
    PostgresCanonicalGeographyResolver,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.integration.test_geo_resolution_lifecycle import (
    location_factory,
    seed_geolocation_work,
    table_count,
)

pytestmark = pytest.mark.integration

_COUNTRY_CODES = ("US", "CA", "MX")


class _TrackingUnitOfWork:
    """Real PostgresUnitOfWork wrapper counting open caller transactions.

    Test infrastructure only: it counts opens/closes and delegates every
    repository attribute to the real unit of work; persistence behavior is
    never faked.
    """

    def __init__(
        self, inner: PostgresUnitOfWork, tracker: "_TrackingUowFactory"
    ) -> None:
        """Bind the real UoW and the shared activity counter."""
        self._inner = inner
        self._tracker = tracker

    async def __aenter__(self) -> "_TrackingUnitOfWork":
        """Register the open transaction and enter the real UoW."""
        self._tracker.active += 1
        self._tracker.peak = max(self._tracker.peak, self._tracker.active)
        await self._inner.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the real UoW and unregister the transaction."""
        try:
            return await self._inner.__aexit__(exc_type, exc, traceback)
        finally:
            self._tracker.active -= 1

    def __getattr__(self, name: str) -> Any:
        """Delegate repository access to the real UnitOfWork."""
        return getattr(self._inner, name)


class _TrackingUowFactory:
    """Callable factory returning tracked real UnitOfWorks."""

    def __init__(self, inner: Callable[[], PostgresUnitOfWork]) -> None:
        """Bind the real factory and initialize the activity counters."""
        self._inner = inner
        self.active = 0
        self.peak = 0

    def __call__(self) -> _TrackingUnitOfWork:
        """Create a fresh tracked unit of work per worker call."""
        return _TrackingUnitOfWork(self._inner(), self)


class _BarrierSessionBoundResolver(LocationResolver):
    """Production resolver path holding a deterministic entry barrier only.

    Each resolve records concurrent activity, waits for the shared gate (so
    tests can park an arbitrary number of real item pipelines at the resolver
    boundary), then delegates to the real canonical geography resolver with
    a fresh session per call. Timing/control only: persistence and the
    canonical resolver remain real.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[Any],
        tracker: _TrackingUowFactory,
        *,
        gate_at: int,
    ) -> None:
        """Bind the session factory, UoW tracker, and barrier size."""
        self._session_factory = session_factory
        self._tracker = tracker
        self._gate_at = gate_at
        self.gate = asyncio.Event()
        self.entries = 0
        self.active = 0
        self.reached = asyncio.Event()

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Wait for the barrier, then resolve through the real canonical path."""
        self.entries += 1
        self.active += 1
        if self.entries >= self._gate_at:
            self.reached.set()
        try:
            await self.gate.wait()
            async with self._session_factory() as session:
                return await PostgresCanonicalGeographyResolver(session).resolve(claim)
        finally:
            self.active -= 1


def _worker_instance(
    uow_factory: Callable[[], Any],
    session_factory: async_sessionmaker[Any],
    *,
    worker_id: str,
    resolver: LocationResolver,
    max_concurrency: int,
    batch_size: int = 10,
) -> GeoResolutionWorker:
    """Compose one production-style worker with the L-2 concurrency policy."""
    return GeoResolutionWorker(
        uow_factory=uow_factory,
        resolver=resolver,
        config=GeoResolutionWorkerConfig(
            enabled=True,
            worker_id=worker_id,
            batch_size=batch_size,
            lease_seconds=300,
            poll_interval_seconds=1.0,
            max_attempts=3,
            retry_base_seconds=60.0,
            retry_max_seconds=3600.0,
            max_concurrency=max_concurrency,
        ),
    )


@pytest.mark.asyncio
async def test_l2_p01_concurrent_real_worker_lifecycle(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    integration_engine: AsyncEngine,
) -> None:
    """L2-P01: concurrent real completion creates exactly one result per item."""
    async with uow_factory() as uow:
        work: list[tuple[UUID, UUID, UUID]] = []
        for country in _COUNTRY_CODES:
            entity_id, evidence_id, resolution_id = await seed_geolocation_work(
                uow, country_code=country
            )
            assert resolution_id is not None
            persisted = await uow.locations.upsert(location_factory(country))
            assert persisted.id is not None
            work.append((entity_id, evidence_id, resolution_id))

    class _SessionBoundResolver(LocationResolver):
        """Production-style resolver: one short read session per call."""

        def __init__(self, factory: async_sessionmaker[Any]) -> None:
            self._factory = factory

        async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
            async with self._factory() as session:
                return await PostgresCanonicalGeographyResolver(session).resolve(claim)

    worker = _worker_instance(
        uow_factory,
        session_factory,
        worker_id="worker-l2-p01",
        resolver=_SessionBoundResolver(session_factory),
        max_concurrency=2,
    )
    processed = await worker.run_once()
    assert processed == len(work)
    async with uow_factory() as uow:
        states = [await uow.geo_resolutions.get_by_id(rid) for _, _, rid in work]
        observations = {}
        for entity_id, _evidence_id, _rid in work:
            rows = await uow.entity_location_observations.list_for_entity(
                entity_id, limit=1000
            )
            observations[entity_id] = rows
    # Every intended row reached the durable terminal state.
    assert all(
        state is not None and state.status is GeoResolutionStatus.RESOLVED
        for state in states
    )
    # Each completion carries exact provenance and exists exactly once.
    for (entity_id, evidence_id, resolution_id), state in zip(
        work, states, strict=True
    ):
        assert state is not None
        rows = observations[entity_id]
        assert len(rows) == 1
        assert rows[0].id == observation_uuid_for_resolution(resolution_id)
        assert rows[0].entity_id == entity_id
        assert rows[0].evidence_observation_id == evidence_id
    # No duplicate current-state rows are created and nothing stays pending.
    assert await table_count(integration_engine, "entity_location_observation") == len(
        work
    )
    assert await table_count(integration_engine, "entity_location") == len(work)
    for state in states:
        assert state is not None
        assert state.lease_expires_at is None
        assert state.attempt_count >= 1


@pytest.mark.asyncio
async def test_l2_p02_deterministic_overlap_at_worker_boundary(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    integration_engine: AsyncEngine,
) -> None:
    """L2-P02: two real pipelines overlap at the resolver with no caller UoW."""
    async with uow_factory() as uow:
        work: list[tuple[UUID, UUID, UUID]] = []
        for country in _COUNTRY_CODES:
            entity_id, evidence_id, resolution_id = await seed_geolocation_work(
                uow, country_code=country
            )
            assert resolution_id is not None
            persisted = await uow.locations.upsert(location_factory(country))
            assert persisted.id is not None
            work.append((entity_id, evidence_id, resolution_id))
    tracker = _TrackingUowFactory(uow_factory)
    resolver = _BarrierSessionBoundResolver(session_factory, tracker, gate_at=2)
    worker = _worker_instance(
        tracker,
        session_factory,
        worker_id="worker-l2-p02",
        resolver=resolver,
        max_concurrency=2,
    )
    task = asyncio.create_task(worker.run_once())
    await resolver.reached.wait()
    # Two item pipelines are parked at the real resolver boundary at once,
    # and no caller UnitOfWork is held across the gate.
    assert resolver.entries == 2
    assert resolver.active == 2
    assert tracker.active == 0
    # Releasing the gate lets both continue and persist through the real
    # completion stored functions.
    resolver.gate.set()
    processed = await task
    assert processed == len(work)
    assert resolver.entries == 3
    async with uow_factory() as uow:
        states = [await uow.geo_resolutions.get_by_id(rid) for _, _, rid in work]
        observeds = {}
        for entity_id, _evidence_id, _rid in work:
            rows = await uow.entity_location_observations.list_for_entity(
                entity_id, limit=1000
            )
            observeds[entity_id] = rows
    assert all(
        state is not None and state.status is GeoResolutionStatus.RESOLVED
        for state in states
    )
    assert all(len(rows) == 1 for rows in observeds.values())
    assert await table_count(integration_engine, "entity_location_observation") == len(
        work
    )
    assert tracker.active == 0


@pytest.mark.asyncio
async def test_l2_p03_disjoint_multi_worker_claims_stay_disjoint(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[Any],
    integration_engine: AsyncEngine,
) -> None:
    """L2-P03: two workers retain disjoint claim batches under concurrency."""
    async with uow_factory() as uow:
        work: list[tuple[UUID, UUID, UUID]] = []
        for country in ("US", "CA", "MX", "BR"):
            entity_id, evidence_id, resolution_id = await seed_geolocation_work(
                uow, country_code=country
            )
            assert resolution_id is not None
            persisted = await uow.locations.upsert(location_factory(country))
            assert persisted.id is not None
            work.append((entity_id, evidence_id, resolution_id))

    class _SessionBound(LocationResolver):
        def __init__(self, factory: async_sessionmaker[Any]) -> None:
            self._factory = factory

        async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
            async with self._factory() as session:
                return await PostgresCanonicalGeographyResolver(session).resolve(claim)

    worker_a = _worker_instance(
        uow_factory,
        session_factory,
        worker_id="worker-l2-p03-a",
        resolver=_SessionBound(session_factory),
        max_concurrency=2,
    )
    worker_b = _worker_instance(
        uow_factory,
        session_factory,
        worker_id="worker-l2-p03-b",
        resolver=_SessionBound(session_factory),
        max_concurrency=2,
    )
    first, second = await asyncio.gather(worker_a.run_once(), worker_b.run_once())
    assert first + second == len(work)
    async with uow_factory() as uow:
        states = [await uow.geo_resolutions.get_by_id(rid) for _, _, rid in work]
    assert all(
        state is not None and state.status is GeoResolutionStatus.RESOLVED
        for state in states
    )
    assert await table_count(integration_engine, "entity_location_observation") == len(
        work
    )
