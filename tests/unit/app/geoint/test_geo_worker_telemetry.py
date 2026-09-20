# SPDX-License-Identifier: AGPL-3.0-only
"""GeoResolutionWorker telemetry tests (PR 29B, G1..G5).

Proves the batch-level ``ati.geo.resolve`` span/duration and the per-item
resolved/unresolvable/failed counters, with no invented work, unchanged
retry/status semantics, and cancellation propagation.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest
from opentelemetry.sdk.metrics.export import Metric

from agentic_threat_investigator.app.geoint.resolution import resolved_result
from agentic_threat_investigator.app.geoint.worker import GeoResolutionWorker
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
)
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.otel import (
    counter_value,
    histogram_count,
    metrics_by_name,
)
from tests.unit.app.geoint.test_geo_resolution_worker import (
    FakeResolver,
    FakeUnitOfWorkFactory,
    claimed_resolution,
    geolocation_evidence,
    location_factory,
    run_worker,
    unresolved_result,
    worker_config,
)


def _recorded(telemetry: SimpleNamespace) -> dict[str, Metric]:
    """Return recorded metrics indexed by name."""
    return metrics_by_name(telemetry.reader)


class TestGeoTelemetry:
    """G1..G5: resolution outcomes are observable with exact counts."""

    @pytest.mark.asyncio
    async def test_g1_resolved_counts_resolved(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A RESOLVED completion counts one resolved and one span (G1)."""
        stable, observation = geolocation_evidence(facts={"country_code": "ZZ"})
        resolution = claimed_resolution(
            evidence_observation_id=observation.id, entity_id=uuid4()
        )
        factory = FakeUnitOfWorkFactory(
            [observation], [resolution], stable={stable.id: stable}
        )
        resolver = FakeResolver(
            factory,
            resolved_result(
                location_factory(location_id=uuid4()),
                reason_code="exact_semantic_match",
                matched_fields=(),
            ),
        )
        processed = await run_worker(factory, resolver)
        assert processed == 1
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.GEO_RESOLVED]) == 1
        assert Metrics.GEO_UNRESOLVABLE not in recorded
        assert Metrics.GEO_FAILED not in recorded
        duration = recorded[DurationMetrics.GEO_RESOLVE]
        assert histogram_count(duration) == 1

    @pytest.mark.asyncio
    async def test_g2_unresolvable_counts_terminal(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A terminal UNRESOLVABLE outcome counts unresolvable (G2)."""
        stable, observation = geolocation_evidence(facts={"country_code": "ZZ"})
        resolution = claimed_resolution(
            evidence_observation_id=observation.id, entity_id=uuid4()
        )
        factory = FakeUnitOfWorkFactory(
            [observation], [resolution], stable={stable.id: stable}
        )
        resolver = FakeResolver(factory, unresolved_result())
        processed = await run_worker(factory, resolver)
        assert processed == 1
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.GEO_UNRESOLVABLE]) == 1
        assert Metrics.GEO_RESOLVED not in recorded

    @pytest.mark.asyncio
    async def test_g3_retryable_failure_counts_failed(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A retryable resolver failure records a failed outcome (G3)."""
        stable, observation = geolocation_evidence(facts={"country_code": "ZZ"})
        resolution = claimed_resolution(
            evidence_observation_id=observation.id, entity_id=uuid4()
        )
        factory = FakeUnitOfWorkFactory(
            [observation], [resolution], stable={stable.id: stable}
        )
        resolver = FakeResolver(factory, unresolved_result())
        resolver.error = RuntimeError("resolver boom")
        processed = await run_worker(factory, resolver)
        assert processed == 1
        assert factory.geo_resolutions.failures[-1]["retryable"] is True
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.GEO_FAILED]) == 1
        assert Metrics.GEO_RESOLVED not in recorded
        assert Metrics.GEO_UNRESOLVABLE not in recorded

    @pytest.mark.asyncio
    async def test_g4_no_work_invents_nothing(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """An empty claim emits a worker span but no item outcomes (G4)."""
        factory = FakeUnitOfWorkFactory([], [])
        resolver = FakeResolver(factory, unresolved_result())
        processed = await run_worker(factory, resolver)
        assert processed == 0
        recorded = _recorded(in_memory_persistence_telemetry)
        assert Metrics.GEO_RESOLVED not in recorded
        assert Metrics.GEO_UNRESOLVABLE not in recorded
        assert Metrics.GEO_FAILED not in recorded
        duration = recorded[DurationMetrics.GEO_RESOLVE]
        assert histogram_count(duration) == 1

    @pytest.mark.asyncio
    async def test_g5_cancellation_propagates(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Cancellation propagates unchanged with no telemetry (G5)."""

        class _CancelResolver(FakeResolver):
            """A resolver whose resolve cancels."""

            async def resolve(
                self, claim: GeographicClaim
            ) -> CanonicalLocationResolution:
                del claim
                raise asyncio.CancelledError()

        stable, observation = geolocation_evidence(facts={"country_code": "ZZ"})
        resolution = claimed_resolution(
            evidence_observation_id=observation.id, entity_id=uuid4()
        )
        factory = FakeUnitOfWorkFactory(
            [observation], [resolution], stable={stable.id: stable}
        )
        resolver = _CancelResolver(factory, unresolved_result())
        worker = GeoResolutionWorker(
            uow_factory=cast(Callable[[], UnitOfWork], factory),
            resolver=resolver,
            config=worker_config(),
        )
        with pytest.raises(asyncio.CancelledError):
            await worker.run_once()
        recorded = _recorded(in_memory_persistence_telemetry)
        assert Metrics.GEO_FAILED not in recorded
        assert DurationMetrics.GEO_RESOLVE not in recorded
