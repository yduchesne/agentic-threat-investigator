# SPDX-License-Identifier: AGPL-3.0-only
"""PR L-2 matrix (L2-W01..W15): bounded concurrent GEO item execution.

Deterministic ``asyncio.Event``/counter tests prove the worker-level
concurrency bound and lifecycle invariants with no wall-clock timing:

- L2-W01  empty batch creates no item work;
- L2-W02  concurrency=1 keeps item pipelines strictly sequential;
- L2-W03  concurrency=2 admits genuine resolver overlap;
- L2-W04  a task waiting for admission holds no UnitOfWork;
- L2-W05  resolver entries never see a caller UoW under overlap;
- L2-W06  mixed outcomes persist independently and never suppress each other;
- L2-W07  a normal resolver failure never cancels siblings;
- L2-W08  an unexpected ``_process_one`` escape is isolated (log only);
- L2-W09  parent cancellation propagates and settles outstanding children;
- L2-W10  the permit is released after an expected item failure;
- L2-W11  the permit is released after an unexpected isolated escape;
- L2-W12  claimed identity (id/version/owner) stays item-specific;
- L2-W13  out-of-order completion never cross-wires observations;
- L2-W14  a batch larger than the concurrency bound fully drains;
- L2-W15  max_concurrency greater than batch size is legal.

The gated resolvers below own only timing/control: all persistence and
lifecycle behavior remains the shared fake UnitOfWork/repository boundaries.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import cast
from uuid import UUID

from _pytest.logging import LogCaptureFixture

from agentic_threat_investigator.app.geoint.resolution import (
    LocationResolver,
    ambiguous_result,
    resolved_result,
    unresolvable_result,
)
from agentic_threat_investigator.app.geoint.worker import (
    AMBIGUITY_ERROR_CODE,
    FAILURE_RESOLVER,
    GeoResolutionWorker,
    GeoResolutionWorkerConfig,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
    GeoResolution,
    LocationCandidate,
    observation_uuid_for_resolution,
)
from tests.unit.app.geoint.test_geo_resolution_worker import (
    RETRIEVED_AT,
    FakeResolver,
    FakeUnitOfWorkFactory,
    claimed_resolution,
    geolocation_evidence,
    location_factory,
    worker_config,
)


def _outcome(country_code: str) -> CanonicalLocationResolution:
    """Return one RESOLVED outcome with a deterministic location."""
    return resolved_result(
        location_factory(location_id=UUID(int=len(country_code))),
        reason_code="exact_semantic_match",
        matched_fields=("country_code",),
    )


async def _drain(rounds: int = 8) -> None:
    """Yield control repeatedly so scheduled tasks can progress.

    ``asyncio.sleep(0)`` is an event-loop yield, never wall-clock timing;
    it lets concurrent tasks reach their next event without asserting on
    elapsed time.
    """
    for _ in range(rounds):
        await asyncio.sleep(0)


async def _wait_until(predicate: Callable[[], bool]) -> None:
    """Yield until ``predicate`` holds, bounded by an assertion failure."""
    for _ in range(1000):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition never became true")


async def _wait_entry_count(resolver: "_GatedResolver", target: int) -> None:
    """Wait until the gated resolver has admitted ``target`` calls."""
    resolver.expect_entries(target)
    await resolver.entry_reached.wait()


class _GatedResolver(FakeResolver):
    """Resolver with deterministic entry counters and a shared release gate.

    Each invocation records UoW activity, increments the active/peak
    counters before the first await, and — while ``block`` is enabled —
    waits for the shared ``release`` event so tests can hold an arbitrary
    number of item pipelines at the resolution boundary.
    """

    def __init__(
        self,
        factory: FakeUnitOfWorkFactory,
        outcome: CanonicalLocationResolution,
        *,
        block: bool = True,
    ) -> None:
        """Bind the tracking factory, outcome, and gate policy."""
        super().__init__(factory, outcome)
        self.block = block
        self.release = asyncio.Event()
        self.entries = 0
        self.active = 0
        self.peak_active = 0
        self.entry_reached = asyncio.Event()
        self._entry_target: int | None = None

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Record UoW activity, count concurrent entries, then gate/return."""
        del claim
        self.factory.resolver_saw_active_uow.append(self.factory.active_uows != 0)
        self.active += 1
        self.entries += 1
        self.peak_active = max(self.peak_active, self.active)
        if self._entry_target is not None and self.entries >= self._entry_target:
            self.entry_reached.set()
        try:
            await asyncio.sleep(0)
            if self.block:
                await self.release.wait()
            if self.error is not None:
                raise self.error
            return self.outcome
        finally:
            self.active -= 1

    def expect_entries(self, count: int) -> None:
        """Arm the entry-count event for the next target."""
        self._entry_target = count
        self.entry_reached.clear()


class _ScriptedByCountryResolver(FakeResolver):
    """Resolver with per-claim (country code) outcomes and failure plan."""

    def __init__(
        self,
        factory: FakeUnitOfWorkFactory,
        outcomes: dict[str, CanonicalLocationResolution],
        *,
        fail_countries: frozenset[str] = frozenset(),
    ) -> None:
        """Bind per-country outcomes and the transient-failure set."""
        super().__init__(factory, unresolvable_result("unknown_city"))
        self.outcomes = outcomes
        self.fail_countries = fail_countries

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Record UoW activity, then fail transiently or return the outcome."""
        self.factory.resolver_saw_active_uow.append(self.factory.active_uows != 0)
        await asyncio.sleep(0)
        code = claim.country_code or ""
        if code in self.fail_countries:
            raise RuntimeError("scripted transient resolver failure")
        return self.outcomes[code]


class _KeyedGateResolver(FakeResolver):
    """Resolver releasing each blocked claim independently by country code."""

    def __init__(
        self,
        factory: FakeUnitOfWorkFactory,
        outcome: CanonicalLocationResolution,
        *,
        countries: tuple[str, ...],
    ) -> None:
        """Bind the outcome and one release gate per claimed country code."""
        super().__init__(factory, outcome)
        self.gates: dict[str, asyncio.Event] = {
            code: asyncio.Event() for code in countries
        }
        self.entries: list[str] = []
        self.all_blocked = asyncio.Event()
        self._expected = 0

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Block until the claim's own gate is released."""
        self.factory.resolver_saw_active_uow.append(self.factory.active_uows != 0)
        code = claim.country_code or ""
        self.entries.append(code)
        if self._expected and len(self.entries) >= self._expected:
            self.all_blocked.set()
        await self.gates[code].wait()
        await asyncio.sleep(0)
        return self.outcome

    def wait_for_all(self, count: int) -> None:
        """Arm the all-blocked event for exactly ``count`` entries."""
        self._expected = count
        self.all_blocked.clear()


class _EscapingWorker(GeoResolutionWorker):
    """Narrow worker whose ``_process_one`` escapes once for one item.

    Used only to inject an unexpected exception at the item boundary; no
    production repository, resolver, or persistence behavior is touched.
    """

    def __init__(
        self,
        *,
        escape_id: UUID,
        uow_factory: Callable[[], UnitOfWork],
        resolver: LocationResolver,
        config: GeoResolutionWorkerConfig,
    ) -> None:
        """Bind the escape target before delegating to the base constructor."""
        self._escape_id = escape_id
        super().__init__(uow_factory=uow_factory, resolver=resolver, config=config)

    async def _process_one(self, resolution: GeoResolution) -> None:
        """Raise an unexpected escape for the target row, else delegate."""
        if resolution.id == self._escape_id:
            raise RuntimeError(
                "unexpected invoked escape (raw detail must not be persisted)"
            )
        return await super()._process_one(resolution)


def _make_worker(
    factory: FakeUnitOfWorkFactory,
    resolver: LocationResolver,
    *,
    max_concurrency: int,
    batch_size: int = 10,
) -> GeoResolutionWorker:
    """Compose one worker over the fakes with the L-2 concurrency policy."""
    return GeoResolutionWorker(
        uow_factory=cast(Callable[[], UnitOfWork], factory),
        resolver=resolver,
        config=worker_config(batch_size=batch_size, max_concurrency=max_concurrency),
    )


def test_l2_w01_empty_batch_creates_no_item_work() -> None:
    """L2-W01 an empty claim performs no resolution/UoW/persistence work."""

    async def scenario() -> None:
        factory = FakeUnitOfWorkFactory([], [])
        resolver = _GatedResolver(factory, _outcome("US"))
        worker = _make_worker(factory, resolver, max_concurrency=4)
        processed = await worker.run_once()
        assert processed == 0
        assert resolver.entries == 0
        assert factory.geo_resolutions.resolved == []
        assert factory.geo_resolutions.unresolvable == []
        assert factory.geo_resolutions.failures == []
        assert factory.closed_uows == ["commit"]  # claim UoW only

    asyncio.run(scenario())


def test_l2_w02_concurrency_one_is_sequential() -> None:
    """L2-W02 concurrency=1 serializes pipelines; all items still complete."""

    async def scenario() -> None:
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1]
            for code in ("US", "CA", "MX")
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _GatedResolver(factory, _outcome("US"))
        worker = _make_worker(factory, resolver, max_concurrency=1)
        task = asyncio.create_task(worker.run_once())
        await _wait_entry_count(resolver, 1)
        # The first item is blocked inside resolution; with a bound of one,
        # no second pipeline may enter concurrently.
        await _drain()
        assert resolver.entries == 1
        assert resolver.active == 1
        assert resolver.peak_active == 1
        # Releasing the gate lets the remaining items drain one at a time.
        resolver.release.set()
        processed = await task
        assert processed == 3
        assert resolver.peak_active == 1
        assert resolver.active == 0
        assert sorted(obs.id for obs in factory.geo_resolutions.resolved) == sorted(
            observation_uuid_for_resolution(res.id)
            for res in resolutions
            if res.id is not None
        )

    asyncio.run(scenario())


def test_l2_w03_concurrency_two_admits_overlap() -> None:
    """L2-W03 concurrency=2 admits genuine resolver overlap; third waits."""

    async def scenario() -> None:
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1]
            for code in ("US", "CA", "MX")
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _GatedResolver(factory, _outcome("US"))
        worker = _make_worker(factory, resolver, max_concurrency=2)
        task = asyncio.create_task(worker.run_once())
        await _wait_entry_count(resolver, 2)
        await _drain()
        # Two resolvers are genuinely active at once (overlap proven) and the
        # third item has not entered until a permit is released.
        assert resolver.entries == 2
        assert resolver.active == 2
        assert resolver.peak_active == 2
        resolver.release.set()
        processed = await task
        assert processed == 3
        assert resolver.peak_active == 2
        assert len(factory.geo_resolutions.resolved) == 3

    asyncio.run(scenario())


def test_l2_w04_waiting_item_holds_no_uow() -> None:
    """L2-W04 tasks waiting for admission have opened no UnitOfWork."""

    async def scenario() -> None:
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1]
            for code in ("US", "CA", "MX")
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _GatedResolver(factory, _outcome("US"))
        worker = _make_worker(factory, resolver, max_concurrency=1)
        task = asyncio.create_task(worker.run_once())
        await _wait_entry_count(resolver, 1)
        await _drain()
        # The first item is blocked inside resolution (its load UoW is
        # already closed) and no waiting item has opened any UoW: the permit
        # is acquired before _process_one begins. A misplaced semaphore
        # inside evidence loading would have opened a UoW here.
        assert resolver.entries == 1
        assert factory.active_uows == 0
        resolver.release.set()
        processed = await task
        assert processed == 3
        assert factory.active_uows == 0

    asyncio.run(scenario())


def test_l2_w05_resolver_sees_no_caller_uow_under_overlap() -> None:
    """L2-W05 concurrent resolver entries never overlap a caller UoW."""

    async def scenario() -> None:
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1]
            for code in ("US", "CA")
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _GatedResolver(factory, _outcome("US"))
        worker = _make_worker(factory, resolver, max_concurrency=2)
        task = asyncio.create_task(worker.run_once())
        await _wait_entry_count(resolver, 2)
        assert resolver.active == 2
        assert factory.resolver_saw_active_uow == [False, False]
        resolver.release.set()
        await task

    asyncio.run(scenario())


def test_l2_w06_mixed_outcomes_persist_independently() -> None:
    """L2-W06 resolved/unresolvable/ambiguous/failure coexist in one batch."""

    async def scenario() -> None:
        codes = ("US", "CA", "MX", "BR")
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1] for code in codes
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        outcomes = {
            "US": _outcome("US"),
            "CA": unresolvable_result("unknown_city"),
            "MX": ambiguous_result(
                (
                    LocationCandidate(location=location_factory(), matched_fields=()),
                    LocationCandidate(location=location_factory(), matched_fields=()),
                ),
                reason_code="multiple_candidates",
            ),
            "BR": _outcome("BR"),
        }
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _ScriptedByCountryResolver(
            factory, outcomes, fail_countries=frozenset({"BR"})
        )
        worker = _make_worker(factory, resolver, max_concurrency=4)
        processed = await worker.run_once()
        assert processed == 4
        # Exactly one RESOLVED outcome for the US item.
        assert len(factory.geo_resolutions.resolved) == 1
        assert resolutions[0].id is not None
        assert factory.geo_resolutions.resolved[
            0
        ].id == observation_uuid_for_resolution(resolutions[0].id)
        # Unresolvable + ambiguous both map to terminal UNRESOLVABLE.
        by_resolution = dict(factory.geo_resolutions.unresolvable)
        assert resolutions[1].id is not None and resolutions[2].id is not None
        assert set(by_resolution) == {resolutions[1].id, resolutions[2].id}
        assert by_resolution[resolutions[1].id] == "unknown_city"
        assert by_resolution[resolutions[2].id] == AMBIGUITY_ERROR_CODE
        # The retryable resolver failure is bounded and independent.
        assert len(factory.geo_resolutions.failures) == 1
        failure = factory.geo_resolutions.failures[0]
        assert failure["resolution_id"] == resolutions[3].id
        assert failure["error_code"] == FAILURE_RESOLVER
        assert failure["retryable"] is True

    asyncio.run(scenario())


def test_l2_w07_normal_resolver_failure_does_not_cancel_siblings() -> None:
    """L2-W07 one FAILURE_RESOLVER path leaves sibling outcomes intact."""

    async def scenario() -> None:
        codes = ("US", "CA", "MX")
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1] for code in codes
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        outcomes = {"US": _outcome("US"), "CA": _outcome("CA"), "MX": _outcome("MX")}
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _ScriptedByCountryResolver(
            factory, outcomes, fail_countries=frozenset({"MX"})
        )
        worker = _make_worker(factory, resolver, max_concurrency=3)
        processed = await worker.run_once()
        assert processed == 3
        assert len(factory.geo_resolutions.failures) == 1
        assert factory.geo_resolutions.failures[0]["error_code"] == FAILURE_RESOLVER
        assert resolutions[0].id is not None and resolutions[1].id is not None
        assert {obs.id for obs in factory.geo_resolutions.resolved} == {
            observation_uuid_for_resolution(resolutions[0].id),
            observation_uuid_for_resolution(resolutions[1].id),
        }

    asyncio.run(scenario())


def test_l2_w08_unexpected_process_one_escape_is_isolated(
    caplog: LogCaptureFixture,
) -> None:
    """L2-W08 an escaping item is logged only; siblings continue."""

    async def scenario() -> None:
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1]
            for code in ("US", "CA")
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        assert resolutions[0].id is not None
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _GatedResolver(factory, _outcome("US"), block=False)
        worker = _EscapingWorker(
            escape_id=resolutions[0].id,
            uow_factory=cast(Callable[[], UnitOfWork], factory),
            resolver=resolver,
            config=worker_config(max_concurrency=1),
        )
        processed = await worker.run_once()
        # The escaped item persisted nothing; the sibling completed.
        assert processed == 2
        assert len(factory.geo_resolutions.resolved) == 1
        assert factory.geo_resolutions.failures == []
        assert factory.geo_resolutions.unresolvable == []
        # The isolation boundary logged a bounded reason without raw text.
        matches = [
            record
            for record in caplog.records
            if record.name == "agentic_threat_investigator.app.geoint.worker"
            and "geo resolution item failed unexpectedly" in record.getMessage()
        ]
        assert matches
        message = matches[-1].getMessage()
        assert str(resolutions[0].id) in message
        assert "RuntimeError" in message
        assert "unexpected invoked escape" not in message

    asyncio.run(scenario())


def test_l2_w09_parent_cancellation_propagates_and_settles_children() -> None:
    """L2-W09 cancelling run_once settles active and waiting children."""

    async def scenario() -> None:
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1]
            for code in ("US", "CA", "MX")
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _GatedResolver(factory, _outcome("US"))
        worker = _make_worker(factory, resolver, max_concurrency=2)
        task = asyncio.create_task(worker.run_once())
        await _wait_entry_count(resolver, 2)
        # Two active pipelines are blocked in resolution; the third waits
        # for a permit. Cancel the iteration from the parent.
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("run_once must propagate CancelledError")
        await _drain()
        # No further item entered the resolver or any UoW after settle.
        assert resolver.entries == 2
        assert resolver.active == 0
        assert factory.active_uows == 0
        assert factory.geo_resolutions.resolved == []
        assert factory.geo_resolutions.unresolvable == []
        assert factory.geo_resolutions.failures == []

    asyncio.run(scenario())


def test_l2_w10_permit_released_after_expected_failure() -> None:
    """L2-W10 an expected item failure releases the permit for the next item."""

    async def scenario() -> None:
        codes = ("US", "CA")
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1] for code in codes
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        outcomes = {"US": _outcome("US"), "CA": _outcome("CA")}
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _ScriptedByCountryResolver(
            factory, outcomes, fail_countries=frozenset({"US"})
        )
        worker = _make_worker(factory, resolver, max_concurrency=1)
        processed = await worker.run_once()
        assert processed == 2
        assert len(factory.geo_resolutions.failures) == 1
        assert factory.geo_resolutions.failures[0]["resolution_id"] == resolutions[0].id
        assert len(factory.geo_resolutions.resolved) == 1
        assert resolutions[1].id is not None
        assert factory.geo_resolutions.resolved[
            0
        ].id == observation_uuid_for_resolution(resolutions[1].id)

    asyncio.run(scenario())


def test_l2_w11_permit_released_after_unexpected_escape() -> None:
    """L2-W11 an unexpected escaped item releases the permit for the next."""

    async def scenario() -> None:
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1]
            for code in ("US", "CA")
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        assert resolutions[0].id is not None
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _GatedResolver(factory, _outcome("US"), block=False)
        worker = _EscapingWorker(
            escape_id=resolutions[0].id,
            uow_factory=cast(Callable[[], UnitOfWork], factory),
            resolver=resolver,
            config=worker_config(max_concurrency=1),
        )
        processed = await worker.run_once()
        assert processed == 2
        assert len(factory.geo_resolutions.resolved) == 1
        assert resolutions[1].id is not None
        assert factory.geo_resolutions.resolved[
            0
        ].id == observation_uuid_for_resolution(resolutions[1].id)

    asyncio.run(scenario())


def test_l2_w12_claimed_identity_remains_item_specific() -> None:
    """L2-W12 every completion/failure keeps its exact claimed identity."""

    async def scenario() -> None:
        codes = ("US", "CA", "MX")
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1] for code in codes
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id, version=version)
            for obs, version in zip(evidence, (7, 8, 9), strict=True)
        ]
        outcomes = {"US": _outcome("US"), "CA": _outcome("CA"), "MX": _outcome("MX")}
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _ScriptedByCountryResolver(
            factory, outcomes, fail_countries=frozenset({"MX"})
        )
        worker = _make_worker(factory, resolver, max_concurrency=3)
        processed = await worker.run_once()
        assert processed == 3
        # The failure kept the exact id/version/owner of its own row.
        failure = factory.geo_resolutions.failures[0]
        assert failure["resolution_id"] == resolutions[2].id
        assert failure["expected_version"] == 9
        assert failure["claimed_by"] == "worker-unit"
        # Resolved outcomes kept their own row identity.
        by_obs_id = {obs.id: obs for obs in factory.geo_resolutions.resolved}
        for res in resolutions[:2]:
            assert res.id is not None
            obs = by_obs_id[observation_uuid_for_resolution(res.id)]
            assert obs.entity_id == res.entity_id
            assert obs.evidence_observation_id == res.evidence_observation_id

    asyncio.run(scenario())


def test_l2_w13_out_of_order_completion_never_cross_wires() -> None:
    """L2-W13 reversed completion order preserves exact per-item provenance."""

    async def scenario() -> None:
        codes = ("US", "CA", "MX")
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1] for code in codes
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        outcome = _outcome("US")
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _KeyedGateResolver(factory, outcome, countries=codes)
        worker = _make_worker(factory, resolver, max_concurrency=3)
        task = asyncio.create_task(worker.run_once())
        resolver.wait_for_all(3)
        await resolver.all_blocked.wait()
        assert sorted(resolver.entries) == sorted(codes)
        # Complete in reverse claim order: MX, then CA, then US.
        resolver.gates["MX"].set()
        await _wait_until(lambda: len(factory.geo_resolutions.resolved) == 1)
        resolver.gates["CA"].set()
        await _wait_until(lambda: len(factory.geo_resolutions.resolved) == 2)
        resolver.gates["US"].set()
        processed = await task
        assert processed == 3
        completed = factory.geo_resolutions.resolved
        # Completion order is exactly the reverse of claim order.
        assert resolutions[0].id is not None
        assert resolutions[1].id is not None
        assert resolutions[2].id is not None
        assert [obs.id for obs in completed] == [
            observation_uuid_for_resolution(resolutions[2].id),
            observation_uuid_for_resolution(resolutions[1].id),
            observation_uuid_for_resolution(resolutions[0].id),
        ]
        # Each observation stays bound to its own resolution's provenance.
        by_obs_id = {obs.id: obs for obs in completed}
        for res in resolutions:
            assert res.id is not None
            obs = by_obs_id[observation_uuid_for_resolution(res.id)]
            assert obs.entity_id == res.entity_id
            assert obs.evidence_observation_id == res.evidence_observation_id
            assert obs.retrieved_at == RETRIEVED_AT

    asyncio.run(scenario())


def test_l2_w14_batch_larger_than_concurrency_fully_drains() -> None:
    """L2-W14 with batch 7 and concurrency 3, all work settles bounded."""

    async def scenario() -> None:
        codes = ("US", "CA", "MX", "BR", "AR", "DE", "FR")
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1] for code in codes
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _GatedResolver(factory, _outcome("US"))
        worker = _make_worker(factory, resolver, max_concurrency=3, batch_size=7)
        task = asyncio.create_task(worker.run_once())
        # First admitted wave reaches full bound.
        await _wait_entry_count(resolver, 3)
        assert resolver.entries == 3
        assert resolver.peak_active == 3
        await _drain()
        assert resolver.entries == 3
        # Release the bound; the rest drains without ever exceeding it.
        resolver.release.set()
        processed = await task
        assert processed == 7
        assert resolver.entries == 7
        assert resolver.peak_active == 3
        assert len(factory.geo_resolutions.resolved) == 7

    asyncio.run(scenario())


def test_l2_w15_max_concurrency_greater_than_batch_is_legal() -> None:
    """L2-W15 concurrency above batch size runs without error."""

    async def scenario() -> None:
        codes = ("US", "CA", "MX")
        evidence = [
            geolocation_evidence(facts={"country_code": code})[1] for code in codes
        ]
        resolutions = [
            claimed_resolution(evidence_observation_id=obs.id) for obs in evidence
        ]
        factory = FakeUnitOfWorkFactory(evidence, resolutions)
        resolver = _GatedResolver(factory, _outcome("US"), block=False)
        worker = _make_worker(factory, resolver, max_concurrency=8, batch_size=2)
        processed = await worker.run_once()
        assert processed == 3
        assert len(factory.geo_resolutions.resolved) == 3

    asyncio.run(scenario())
