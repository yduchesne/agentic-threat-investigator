# SPDX-License-Identifier: AGPL-3.0-only
"""G26C-W matrix: GeoResolutionWorker orchestration with fake boundaries.

Proves the one-iteration worker flow contract: short committed claim, short
evidence load, resolution OUTSIDE any UnitOfWork, and a NEW short UnitOfWork
per completion — with the LocationResolver as the only fake resolution
boundary. No real database is involved; persistence boundaries are recorded.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.geoint.resolution import (
    LocationResolver,
    ambiguous_result,
    resolved_result,
    unresolvable_result,
)
from agentic_threat_investigator.app.geoint.worker import (
    AMBIGUITY_ERROR_CODE,
    CANONICAL_GEOGRAPHY_METHOD,
    FAILURE_EVIDENCE_TYPE,
    FAILURE_MISSING_EVIDENCE,
    FAILURE_RESOLVER,
    GeoResolutionWorker,
    GeoResolutionWorkerConfig,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    EntityLocationObservation,
    GeographicClaim,
    GeoResolution,
    GeoResolutionStatus,
    Location,
    LocationCandidate,
    LocationPrecision,
    LocationType,
    observation_uuid_for_resolution,
)

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def worker_config(
    *,
    worker_id: str = "worker-unit",
    max_attempts: int = 3,
    retry_base_seconds: float = 60.0,
    retry_max_seconds: float = 3600.0,
    batch_size: int = 10,
) -> GeoResolutionWorkerConfig:
    """Return a valid bounded worker policy fixture."""
    return GeoResolutionWorkerConfig(
        enabled=True,
        worker_id=worker_id,
        batch_size=batch_size,
        lease_seconds=300,
        poll_interval_seconds=1.0,
        max_attempts=max_attempts,
        retry_base_seconds=retry_base_seconds,
        retry_max_seconds=retry_max_seconds,
    )


def location_factory(location_id: UUID | None = None) -> Location:
    """Return one canonical Location fixture."""
    return Location(
        id=location_id or uuid4(),
        type=LocationType.COUNTRY,
        name="Testonia",
        canonical_name="Testonia",
        country_code="ZZ",
    )


def unresolved_result() -> CanonicalLocationResolution:
    """Return a deterministic UNRESOLVABLE canonical outcome."""
    return unresolvable_result("unknown_city")


def ambiguous_outcome() -> CanonicalLocationResolution:
    """Return a deterministic AMBIGUOUS canonical outcome."""
    marker = location_factory()
    return ambiguous_result(
        (
            LocationCandidate(location=marker, matched_fields=()),
            LocationCandidate(location=location_factory(), matched_fields=()),
        ),
        reason_code="multiple_candidates",
    )


def geolocation_evidence(
    *,
    evidence_id: UUID | None = None,
    facts: dict[str, object] | None = None,
    type_: EvidenceType = EvidenceType.GEOLOCATION,
) -> Evidence:
    """Return one deterministic GEOLOCATION Evidence fixture."""
    return Evidence(
        id=evidence_id or uuid4(),
        investigation_id=uuid4(),
        type=type_,
        subject=EntityRef(id=uuid4(), type=EntityType.IP_ADDRESS, value="203.0.113.7"),
        source="urn:ati:source:test",
        retrieved_at=RETRIEVED_AT,
        facts=facts if facts is not None else {"country_code": "ZZ"},
    )


class FakeUnitOfWork:
    """Transactional boundary fake that records open/close and routes repos."""

    def __init__(self, factory: "FakeUnitOfWorkFactory") -> None:
        """Bind the shared fake state and registry."""
        self.factory = factory
        self.active = False

    async def __aenter__(self) -> "FakeUnitOfWork":
        """Register the opened UoW on the shared factory."""
        self.active = True
        self.factory.active_uows += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the UoW and record commit/rollback decisions."""
        del exc, traceback
        self.active = False
        self.factory.active_uows -= 1
        self.factory.closed_uows.append("commit" if exc_type is None else "rollback")

    @property
    def geo_resolutions(self) -> "FakeGeoResolutionsRepository":
        """Return the shared geo resolution repository fake."""
        return self.factory.geo_resolutions

    @property
    def evidence(self) -> "FakeEvidenceRepository":
        """Return the shared evidence repository fake."""
        return self.factory.evidence


class FakeGeoResolutionsRepository:
    """In-memory GeoResolution lifecycle repository with call recording."""

    def __init__(self, factory: "FakeUnitOfWorkFactory") -> None:
        """Bind the shared factory and initialize the call log."""
        self.factory = factory
        self.claimed: list[GeoResolution] = []
        self.resolved: list[EntityLocationObservation] = []
        self.unresolvable: list[tuple[UUID, str]] = []
        self.failures: list[dict[str, Any]] = []
        self.completion_failure: type[Exception] | None = None
        self.failure_persistence_failure: type[Exception] | None = None

    async def claim_batch(
        self, *, claimed_by: str, limit: int, lease_seconds: int, max_attempts: int
    ) -> list[GeoResolution]:
        """Return the configured claimed batch once."""
        assert self.factory.active_uows == 1
        return list(self.claimed)

    async def complete_resolved(
        self,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        observation: EntityLocationObservation,
    ) -> GeoResolution:
        """Record an atomic resolved completion invocation."""
        assert self.factory.active_uows == 1
        self.resolved.append(observation)
        if self.completion_failure is not None:
            raise self.completion_failure()
        return GeoResolution(
            id=resolution_id,
            entity_id=observation.entity_id,
            evidence_id=observation.evidence_id,
            status=GeoResolutionStatus.RESOLVED,
            attempt_count=1,
            claimed_by=None,
            lease_expires_at=None,
            resolved_location_id=observation.location_id,
            version=expected_version + 1,
        )

    async def complete_unresolvable(
        self,
        *,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        error_code: str,
    ) -> GeoResolution:
        """Record a terminal unresolvable completion invocation."""
        assert self.factory.active_uows == 1
        self.unresolvable.append((resolution_id, error_code))
        return GeoResolution(
            id=resolution_id,
            entity_id=uuid4(),
            evidence_id=uuid4(),
            status=GeoResolutionStatus.UNRESOLVABLE,
            attempt_count=1,
            last_error_code=error_code,
            version=expected_version + 1,
        )

    async def record_failure(
        self,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        error_code: str,
        *,
        retryable: bool,
        retry_base_seconds: float,
        retry_max_seconds: float,
        max_attempts: int,
    ) -> GeoResolution:
        """Record a failure transition (or simulate persistence failure)."""
        assert self.factory.active_uows == 1
        self.failures.append(
            {
                "resolution_id": resolution_id,
                "expected_version": expected_version,
                "claimed_by": claimed_by,
                "error_code": error_code,
                "retryable": retryable,
                "retry_base_seconds": retry_base_seconds,
                "retry_max_seconds": retry_max_seconds,
                "max_attempts": max_attempts,
            }
        )
        if self.failure_persistence_failure is not None:
            raise self.failure_persistence_failure()
        return GeoResolution(
            id=resolution_id,
            entity_id=uuid4(),
            evidence_id=uuid4(),
            status=GeoResolutionStatus.PENDING,
            attempt_count=1,
            next_attempt_at=FIXED_NOW,
            last_error_code=error_code,
            version=expected_version + 1,
        )


class FakeEvidenceRepository:
    """In-memory immutable Evidence repository."""

    def __init__(self, evidence_rows: list[Evidence]) -> None:
        """Index the bound Evidence rows by identity."""
        self.rows = {row.id: row for row in evidence_rows}

    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        """Return the bound Evidence row, if any."""
        return self.rows.get(evidence_id)


class FakeUnitOfWorkFactory:
    """Build fakes and expose the shared registry + UoW activity."""

    def __init__(
        self,
        evidence_rows: list[Evidence],
        claimed: list[GeoResolution],
    ) -> None:
        """Bind the evidence index and the claimed batch."""
        self.evidence = FakeEvidenceRepository(evidence_rows)
        self.geo_resolutions = FakeGeoResolutionsRepository(self)
        self.geo_resolutions.claimed = claimed
        self.active_uows = 0
        self.closed_uows: list[str] = []
        self.resolver_saw_active_uow: list[bool] = []

    def __call__(self) -> FakeUnitOfWork:
        """Create a fresh transactional fake per worker call."""
        return FakeUnitOfWork(self)

    async def run_resolver_with_tracking(
        self, outcome: CanonicalLocationResolution
    ) -> CanonicalLocationResolution:
        """Record whether a UoW was open during resolver execution."""
        self.resolver_saw_active_uow.append(self.active_uows != 0)
        await asyncio.sleep(0)
        return outcome


class FakeResolver(LocationResolver):
    """Scripted LocationResolver with optional failure injection."""

    def __init__(
        self,
        factory: FakeUnitOfWorkFactory,
        outcome: CanonicalLocationResolution,
    ) -> None:
        """Bind the tracking factory and the fixed outcome."""
        self.factory = factory
        self.outcome = outcome
        self.error: BaseException | None = None

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Record UoW activity, then raise or return the scripted outcome."""
        self.factory.resolver_saw_active_uow.append(self.factory.active_uows != 0)
        if self.error is not None:
            raise self.error
        return self.outcome


def claimed_resolution(
    *,
    resolution_id: UUID | None = None,
    entity_id: UUID | None = None,
    evidence_id: UUID | None = None,
    version: int = 7,
) -> GeoResolution:
    """Return one claimed (PROCESSING) GeoResolution fixture."""
    return GeoResolution(
        id=resolution_id or uuid4(),
        entity_id=entity_id or uuid4(),
        evidence_id=evidence_id or uuid4(),
        status=GeoResolutionStatus.PROCESSING,
        attempt_count=2,
        claimed_by="worker-unit",
        lease_expires_at=FIXED_NOW,
        version=version,
    )


async def run_worker(
    factory: FakeUnitOfWorkFactory,
    resolver: FakeResolver,
    *,
    config: GeoResolutionWorkerConfig | None = None,
) -> int:
    """Run one worker iteration against the fakes."""
    worker = GeoResolutionWorker(
        uow_factory=cast(Callable[[], UnitOfWork], factory),
        resolver=resolver,
        config=config or worker_config(),
        clock=lambda: FIXED_NOW,
    )
    return await worker.run_once()


def test_g26c_w08_empty_batch_no_work() -> None:
    """G26C-W08 an empty claim batch performs no resolution work."""

    async def scenario() -> None:
        factory = FakeUnitOfWorkFactory([], [])
        resolver = FakeResolver(factory, unresolved_result())
        processed = await run_worker(factory, resolver)
        assert processed == 0
        assert factory.resolver_saw_active_uow == []
        assert factory.geo_resolutions.resolved == []
        assert factory.geo_resolutions.failures == []

    asyncio.run(scenario())


def test_g26c_w01_resolved_completion() -> None:
    """G26C-W01 a resolved outcome persists an exact-provenance observation."""

    async def scenario() -> None:
        evidence = geolocation_evidence(facts={"country_code": "ZZ"})
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        outcome = resolved_result(
            location_factory(), reason_code="exact_semantic_match", matched_fields=()
        )
        factory = FakeUnitOfWorkFactory([evidence], [res])
        resolver = FakeResolver(factory, outcome)
        processed = await run_worker(factory, resolver)
        assert processed == 1
        assert resolver.factory.resolver_saw_active_uow == [False]
        assert factory.closed_uows == ["commit", "commit", "commit"]
        assert len(factory.geo_resolutions.resolved) == 1
        obs = factory.geo_resolutions.resolved[0]
        assert isinstance(obs, EntityLocationObservation)
        assert res.id is not None
        assert obs.id == observation_uuid_for_resolution(res.id)
        assert obs.entity_id == res.entity_id
        assert obs.evidence_id == res.evidence_id
        assert obs.location_id == outcome.location.id  # type: ignore[union-attr]
        assert obs.precision is LocationPrecision.COUNTRY
        assert obs.observed_at is None
        assert obs.retrieved_at == RETRIEVED_AT
        assert obs.resolved_at == FIXED_NOW
        assert obs.resolution_method == CANONICAL_GEOGRAPHY_METHOD

    asyncio.run(scenario())


def test_g26c_w02_unresolvable_completion() -> None:
    """G26C-W02 an unresolvable outcome terminates work with the reason code."""

    async def scenario() -> None:
        evidence = geolocation_evidence(facts={"country_code": "ZZ"})
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        factory = FakeUnitOfWorkFactory([evidence], [res])
        resolver = FakeResolver(factory, unresolved_result())
        processed = await run_worker(factory, resolver)
        assert processed == 1
        assert factory.geo_resolutions.resolved == []
        assert factory.geo_resolutions.failures == []
        assert factory.geo_resolutions.unresolvable == [(res.id, "unknown_city")]

    asyncio.run(scenario())


def test_g26c_w03_ambiguous_is_unresolvable_and_never_guessed() -> None:
    """G26C-W03 ambiguity maps to terminal unresolvable with the stable code."""

    async def scenario() -> None:
        evidence = geolocation_evidence(facts={"country_code": "ZZ"})
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        factory = FakeUnitOfWorkFactory([evidence], [res])
        resolver = FakeResolver(factory, ambiguous_outcome())
        processed = await run_worker(factory, resolver)
        assert processed == 1
        assert factory.geo_resolutions.resolved == []
        assert factory.geo_resolutions.unresolvable == [(res.id, AMBIGUITY_ERROR_CODE)]

    asyncio.run(scenario())


def test_g26c_w04_malformed_evidence_is_terminal_failed() -> None:
    """G26C-W04 malformed Evidence persists a terminal non-retryable failure."""

    async def scenario() -> None:
        # A non-GEOLOCATION Evidence row fails the type guard.
        evidence = geolocation_evidence(type_=EvidenceType.DNS)
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        factory = FakeUnitOfWorkFactory([evidence], [res])
        resolver = FakeResolver(factory, unresolved_result())
        processed = await run_worker(factory, resolver)
        assert processed == 1
        assert factory.geo_resolutions.resolved == []
        assert factory.geo_resolutions.failures[-1]["error_code"] == (
            FAILURE_EVIDENCE_TYPE
        )
        assert factory.geo_resolutions.failures[-1]["retryable"] is False

    asyncio.run(scenario())


def test_g26c_w04b_missing_evidence_is_terminal_failed() -> None:
    """G26C-W04/missing a missing Evidence row is a terminal failure."""

    async def scenario() -> None:
        res = claimed_resolution()
        factory = FakeUnitOfWorkFactory([], [res])
        resolver = FakeResolver(factory, unresolved_result())
        processed = await run_worker(factory, resolver)
        assert processed == 1
        failure = factory.geo_resolutions.failures[-1]
        assert failure["error_code"] == FAILURE_MISSING_EVIDENCE
        assert failure["retryable"] is False

    asyncio.run(scenario())


def test_g26c_w05_retryable_failure_uses_bounded_backoff_config() -> None:
    """G26C-W05 a transient resolver error schedules a bounded retry."""

    async def scenario() -> None:
        evidence = geolocation_evidence(facts={"country_code": "ZZ"})
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        factory = FakeUnitOfWorkFactory([evidence], [res])
        resolver = FakeResolver(factory, unresolved_result())
        resolver.error = RuntimeError("boom")
        processed = await run_worker(factory, resolver, config=worker_config())
        assert processed == 1
        failure = factory.geo_resolutions.failures[-1]
        assert failure["error_code"] == FAILURE_RESOLVER
        assert failure["retryable"] is True
        assert failure["retry_base_seconds"] == 60.0
        assert failure["retry_max_seconds"] == 3600.0
        assert failure["max_attempts"] == 3

    asyncio.run(scenario())


def test_g26c_w06_retryable_failure_at_max_attempts_uses_terminal_budget() -> None:
    """G26C-W06 at the max attempt the worker passes the budget to the DB."""

    async def scenario() -> None:
        evidence = geolocation_evidence(facts={"country_code": "ZZ"})
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        # The worker always asks for a bounded retry; the database is the
        # final authority that transitions an exhausted budget to FAILED.
        factory = FakeUnitOfWorkFactory([evidence], [res])
        resolver = FakeResolver(factory, unresolved_result())
        resolver.error = RuntimeError("boom")
        processed = await run_worker(
            factory, resolver, config=worker_config(max_attempts=2)
        )
        assert processed == 1
        failure = factory.geo_resolutions.failures[-1]
        assert failure["retryable"] is True
        assert failure["max_attempts"] == 2

    asyncio.run(scenario())


def test_g26c_w07_cancellation_propagates_without_failure_persistence() -> None:
    """G26C-W07 asyncio.CancelledError propagates and persists no transition."""

    async def scenario() -> None:
        evidence = geolocation_evidence(facts={"country_code": "ZZ"})
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        factory = FakeUnitOfWorkFactory([evidence], [res])
        resolver = FakeResolver(factory, unresolved_result())
        resolver.error = asyncio.CancelledError()
        worker = GeoResolutionWorker(
            uow_factory=cast(Callable[[], UnitOfWork], factory),
            resolver=resolver,
            config=worker_config(),
            clock=lambda: FIXED_NOW,
        )
        with pytest.raises(asyncio.CancelledError):
            await worker.run_once()
        assert factory.geo_resolutions.failures == []
        assert factory.geo_resolutions.resolved == []
        assert factory.geo_resolutions.unresolvable == []

    asyncio.run(scenario())


def test_g26c_w09_resolver_runs_with_no_claim_uow_open() -> None:
    """G26C-W09 resolver execution never overlaps a claim UnitOfWork."""

    async def scenario() -> None:
        evidence = geolocation_evidence(facts={"country_code": "ZZ"})
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        factory = FakeUnitOfWorkFactory([evidence], [res])
        resolver = FakeResolver(factory, unresolved_result())
        await run_worker(factory, resolver)
        # The resolver recorded one observation per resolve call.
        assert factory.resolver_saw_active_uow == [False]
        # Claim, evidence load, and completion each opened exactly one UoW.
        assert factory.closed_uows == ["commit", "commit", "commit"]

    asyncio.run(scenario())


def test_g26c_w10_completion_opens_a_new_short_uow() -> None:
    """G26C-W10 completion runs inside its own fresh UnitOfWork."""

    async def scenario() -> None:
        evidence = geolocation_evidence(facts={"country_code": "ZZ"})
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        outcome = resolved_result(
            location_factory(), reason_code="exact_semantic_match", matched_fields=()
        )
        factory = FakeUnitOfWorkFactory([evidence], [res])
        resolver = FakeResolver(factory, outcome)
        await run_worker(factory, resolver)
        # The fake repositories assert exactly one UoW is active per call;
        # the closed log proves claim + load + completion are separate UoWs.
        assert factory.closed_uows == ["commit", "commit", "commit"]
        assert len(factory.geo_resolutions.resolved) == 1
        assert factory.active_uows == 0

    asyncio.run(scenario())


def test_g26c_w11_failure_persistence_failure_relies_on_lease_recovery() -> None:
    """G26C-W11 a rejected failure transition never terminates the iteration."""

    async def scenario() -> None:
        evidence = geolocation_evidence(type_=EvidenceType.DNS)
        res = claimed_resolution(evidence_id=evidence.id, entity_id=evidence.subject.id)
        factory = FakeUnitOfWorkFactory([evidence], [res])
        factory.geo_resolutions.failure_persistence_failure = RuntimeError
        resolver = FakeResolver(factory, unresolved_result())
        # One item failure must not raise: the lease expires and the row is
        # reclaimed; the worker continues with the rest of the batch.
        processed = await run_worker(factory, resolver)
        assert processed == 1
        assert factory.geo_resolutions.resolved == []

    asyncio.run(scenario())


def test_g26c_w_unit_factory_type_hints() -> None:
    """The fake factories satisfy the worker's structural contract."""

    async def scenario() -> None:
        factory = FakeUnitOfWorkFactory([], [])
        worker = GeoResolutionWorker(
            uow_factory=cast(Callable[[], UnitOfWork], factory),
            resolver=FakeResolver(factory, unresolved_result()),
            config=worker_config(),
        )
        assert worker.run_once is not None

    asyncio.run(scenario())
