# SPDX-License-Identifier: AGPL-3.0-only
"""Provider work-item telemetry tests (PR 29B, PW1..PW5).

Proves the ``ati.provider.execute`` span/duration and bounded failure
counter at the logical provider work boundary: one logical work item per
span regardless of internal HTTP retries, FAILED outcomes follow the
existing typed semantics, exceptions map to bounded failures, partial
durable commits keep their IDs, and cancellation propagates.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import UUID

import pytest
from opentelemetry.sdk.metrics.export import Metric

from agentic_threat_investigator.app.orchestration.provider_executor import (
    ERROR_PROVIDER_ERROR,
    ERROR_PROVIDER_NOT_CONFIGURED,
)
from agentic_threat_investigator.app.providers import (
    ProviderError,
    ProviderErrorCode,
    ProviderResult,
)
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.investigation import ProviderExecutionStatus
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.otel import (
    counter_value,
    data_point_attributes,
    histogram_count,
    metrics_by_name,
)
from tests.support.provider_executor_fixtures import (
    FIRST_OBSERVATION_ID,
    THREATFOX_SOURCE,
    FakeEvidenceProvider,
    FakePersistenceService,
    FakeTimelineSink,
    build_executor,
    domain_entity,
    global_converted_evidence,
    persisted_result,
    threatfox_work_item,
)


def _recorded(telemetry: SimpleNamespace) -> dict[str, Metric]:
    """Return recorded metrics indexed by name."""
    return metrics_by_name(telemetry.reader)


def _spans(telemetry: SimpleNamespace) -> list[object]:
    """Return finished span names from the in-memory exporter."""
    return [span.name for span in telemetry.exporter.get_finished_spans()]


class TestProviderWorkTelemetry:
    """PW1..PW5: one logical provider work item is observable."""

    @pytest.mark.asyncio
    async def test_pw1_success_one_logical_work_span(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A succeeded work item emits one provider-work span (PW1)."""
        from agentic_threat_investigator.app.providers import ProviderResult

        provider = FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE))
        timeline = FakeTimelineSink()
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status is ProviderExecutionStatus.SUCCEEDED
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.provider.execute") == 1
        recorded = _recorded(in_memory_persistence_telemetry)
        duration = recorded[DurationMetrics.PROVIDER_EXECUTE]
        assert histogram_count(duration) == 1
        attrs = data_point_attributes(duration)
        assert attrs["ati.provider"] == "urn:ati:source:threatfox"
        assert attrs["ati.outcome"] == "success"
        assert Metrics.PROVIDER_WORK_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_pw2_mixed_result_keeps_outcome_semantics(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A mixed provider result follows the existing outcome semantics (PW2)."""
        from uuid import uuid4

        from agentic_threat_investigator.app.providers import (
            ProviderResult,
        )

        converted = global_converted_evidence(evidence_id=uuid4())
        persistence = FakePersistenceService([persisted_result(converted)])
        first_error = ProviderError(
            provider=THREATFOX_SOURCE,
            code=ProviderErrorCode.TIMEOUT,
            message="A query timed out for the indicator",
            retryable=True,
        )
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=THREATFOX_SOURCE,
                evidence=(converted,),
                errors=(first_error,),
            )
        )
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, timeline=timeline
        )
        outcome = await executor.execute(threatfox_work_item())
        # Mixed evidence + error with a committed observation stays SUCCEEDED
        # per PR 19B and keeps the first error code.
        assert outcome.status is ProviderExecutionStatus.SUCCEEDED
        assert outcome.error is not None and outcome.error.code == "timeout"
        recorded = _recorded(in_memory_persistence_telemetry)
        duration = recorded[DurationMetrics.PROVIDER_EXECUTE]
        assert data_point_attributes(duration)["ati.outcome"] == "success"
        assert Metrics.PROVIDER_WORK_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_pw3_failed_outcome_counts_bounded_failure(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A FAILED outcome counts one bounded failure with the provider label (PW3)."""
        executor = build_executor(None, None)
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status is ProviderExecutionStatus.FAILED
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PROVIDER_NOT_CONFIGURED
        recorded = _recorded(in_memory_persistence_telemetry)
        failures = recorded[Metrics.PROVIDER_WORK_FAILURES]
        assert counter_value(failures) == 1
        assert data_point_attributes(failures)["ati.provider"] == (
            "urn:ati:source:threatfox"
        )
        duration = recorded[DurationMetrics.PROVIDER_EXECUTE]
        assert data_point_attributes(duration)["ati.outcome"] == "error"

    @pytest.mark.asyncio
    async def test_pw5_cancellation_propagates_unchanged(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Cancellation propagates unchanged with no telemetry (PW5)."""

        class _CancelProvider(FakeEvidenceProvider):
            """A provider whose investigate cancels."""

            def __init__(self) -> None:
                """Build without a scripted result."""
                super().__init__()

            async def investigate(
                self, investigation_id: UUID, entity: Entity
            ) -> ProviderResult:
                del investigation_id, entity
                raise asyncio.CancelledError()

        executor = build_executor(_CancelProvider(), domain_entity())
        with pytest.raises(asyncio.CancelledError):
            await executor.execute(threatfox_work_item())
        recorded = _recorded(in_memory_persistence_telemetry)
        assert Metrics.PROVIDER_WORK_FAILURES not in recorded
        assert DurationMetrics.PROVIDER_EXECUTE not in recorded

    @pytest.mark.asyncio
    async def test_pw3b_exception_maps_to_bounded_failure(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A provider exception becomes a bounded failure outcome (PW3)."""

        class _BoomProvider(FakeEvidenceProvider):
            """A provider that raises an unexpected exception."""

            def __init__(self) -> None:
                """Build without a scripted result."""
                super().__init__()

            async def investigate(
                self, investigation_id: UUID, entity: Entity
            ) -> ProviderResult:
                del investigation_id, entity
                raise RuntimeError("boom")

        executor = build_executor(_BoomProvider(), domain_entity())
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status is ProviderExecutionStatus.FAILED
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PROVIDER_ERROR
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.PROVIDER_WORK_FAILURES]) == 1

    @pytest.mark.asyncio
    async def test_pw4_partial_commit_then_failure_keeps_ids(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Partial durable commits stay durable when a later step fails (PW4)."""
        from uuid import uuid4

        from agentic_threat_investigator.app.orchestration.provider_executor import (
            ERROR_PERSISTENCE_ERROR,
        )
        from agentic_threat_investigator.app.provider_observation_persistence import (
            ProviderObservationPersistenceResult,
        )
        from agentic_threat_investigator.app.providers import ProviderResult

        first = global_converted_evidence(evidence_id=uuid4())
        second = global_converted_evidence(evidence_id=uuid4())
        persistence = FakePersistenceService()
        calls = {"count": 0}

        async def persist(
            converted: object,
            invocation_entity: object,
            extraction: object,
            *,
            investigation_id: UUID,
            actor_id: UUID | None = None,
            request_id: UUID | None = None,
        ) -> ProviderObservationPersistenceResult:
            del converted, invocation_entity, extraction, investigation_id
            del actor_id, request_id
            calls["count"] += 1
            if calls["count"] == 1:
                return persisted_result(first, observation_id=FIRST_OBSERVATION_ID)
            raise RuntimeError("later persistence failure")

        persistence.persist = persist  # type: ignore[method-assign]
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, evidence=(first, second))
        )
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, timeline=timeline
        )
        outcome = await executor.execute(threatfox_work_item())
        # The committed observation ID is retained in the failed outcome and
        # the failure counter fires once.
        assert outcome.status is ProviderExecutionStatus.FAILED
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PERSISTENCE_ERROR
        assert outcome.evidence_ids == (FIRST_OBSERVATION_ID,)
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.PROVIDER_WORK_FAILURES]) == 1
        duration = recorded[DurationMetrics.PROVIDER_EXECUTE]
        assert data_point_attributes(duration)["ati.outcome"] == "error"
