# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 19B real provider work executor (PR 28B global model).

Normal executor-success scenarios drive the real executor with global
``ConvertedEvidence`` from the migrated ThreatFox semantic source; the
unmigrated Google DNS provider remains ``LEGACY_NOT_SEMANTICALLY_MODELED``
and its ``LegacyEvidence`` output fails closed before global persistence
(see the regressions module).
"""

# The executor test harness intentionally composes comparable deterministic
# scenarios; duplicate-code-style duplication is not checked by the enabled
# Ruff rules, so the comparable structure is accepted per repository
# convention.

import asyncio
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionError,
    EvidenceExtractionView,
    ExtractionErrorReason,
    ExtractionResult,
)
from agentic_threat_investigator.app.orchestration.executor import (
    InvestigationBoundWorkExecutor,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ERROR_EXTRACTION_ERROR,
    ERROR_PERSISTENCE_ERROR,
    ERROR_PROVIDER_ERROR,
    ERROR_PROVIDER_NOT_CONFIGURED,
    ERROR_TARGET_NOT_FOUND,
    ERROR_TIMELINE_ERROR,
    ERROR_UNSUPPORTED_INDICATOR,
)
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceResult,
)
from agentic_threat_investigator.app.providers import (
    ProviderError,
    ProviderErrorCode,
    ProviderResult,
)
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import ConvertedEvidence
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from tests.support.provider_executor_fixtures import (
    DOMAIN_ENTITY_ID,
    FIRST_OBSERVATION_ID,
    FIXED_TS,
    INVESTIGATION_ID,
    THREATFOX_SOURCE,
    FakeEvidenceProvider,
    FakePersistenceService,
    FakeTimelineSink,
    build_executor,
    domain_entity,
    global_converted_evidence,
    persisted_result,
    provider_calls_recorded,
    provider_error,
    threatfox_work_item,
)


class TestProviderResolution:
    """Target and provider resolution before any provider invocation."""

    @pytest.mark.asyncio
    async def test_missing_provider_fails_without_timeline_start(self) -> None:
        """An unknown source yields a failed outcome and no started event."""
        timeline = FakeTimelineSink()
        executor = build_executor(None, domain_entity(), timeline=timeline)
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PROVIDER_NOT_CONFIGURED
        assert provider_calls_recorded(timeline) == []

    @pytest.mark.asyncio
    async def test_missing_target_never_calls_provider(self) -> None:
        """A missing target yields target_not_found without provider invocation."""
        provider = FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE))
        timeline = FakeTimelineSink()
        executor = build_executor(provider, None, timeline=timeline)
        outcome = await executor.execute(threatfox_work_item())
        assert not provider.investigate_calls
        assert outcome.error is not None
        assert outcome.error.code == ERROR_TARGET_NOT_FOUND
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED
        ]

    @pytest.mark.asyncio
    async def test_soft_deleted_target_never_calls_provider(self) -> None:
        """A soft-deleted target is indistinguishable from a missing one."""
        provider = FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE))
        deleted = domain_entity().model_copy(update={"deleted_at": FIXED_TS})
        executor = build_executor(provider, deleted)
        outcome = await executor.execute(threatfox_work_item())
        assert not provider.investigate_calls
        assert outcome.error is not None
        assert outcome.error.code == ERROR_TARGET_NOT_FOUND

    @pytest.mark.asyncio
    async def test_unsupported_target_never_calls_provider(self) -> None:
        """An unsupported target yields unsupported_indicator without HTTP."""
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE),
            supports_target=False,
        )
        executor = build_executor(provider, domain_entity())
        outcome = await executor.execute(threatfox_work_item())
        assert not provider.investigate_calls
        assert outcome.error is not None
        assert outcome.error.code == ERROR_UNSUPPORTED_INDICATOR

    @pytest.mark.asyncio
    async def test_supported_provider_called_once_with_target(self) -> None:
        """A supported provider is invoked exactly once with the loaded entity."""
        provider = FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE))
        executor = build_executor(provider, domain_entity())
        await executor.execute(threatfox_work_item())
        assert len(provider.investigate_calls) == 1
        investigation_id, entity = provider.investigate_calls[0]
        assert investigation_id == INVESTIGATION_ID
        assert entity == domain_entity()


class TestProviderResultProcessing:
    """Deterministic handling of provider results."""

    @pytest.mark.asyncio
    async def test_empty_success_yields_succeeded_without_ids(self) -> None:
        """A valid miss is a success with no inferred assessment or IDs."""
        provider = FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE))
        timeline = FakeTimelineSink()
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status.name == "SUCCEEDED"
        assert outcome.evidence_ids == ()
        assert outcome.discovered_entity_ids == ()
        assert outcome.error is None
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
        ]
        assert timeline.events[-1].error_code is None

    @pytest.mark.asyncio
    async def test_errors_only_fails_without_persistence(self) -> None:
        """Errors without evidence fail the work and never persist anything."""
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, errors=(provider_error(),))
        )
        persistence = FakePersistenceService()
        executor = build_executor(provider, domain_entity(), persistence=persistence)
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == "invalid_response"
        assert outcome.error.recoverable is False
        assert not persistence.calls

    @pytest.mark.asyncio
    async def test_provider_invocation_failure_fails_work(self) -> None:
        """An unexpected provider exception maps to provider_error."""
        provider = FakeEvidenceProvider(None, raises=RuntimeError("boom"))
        executor = build_executor(provider, domain_entity())
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PROVIDER_ERROR

    @pytest.mark.asyncio
    async def test_cancellation_propagates(self) -> None:
        """asyncio.CancelledError is never swallowed as a provider failure."""
        provider = FakeEvidenceProvider(None, raises=asyncio.CancelledError())
        timeline = FakeTimelineSink()
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        with pytest.raises(asyncio.CancelledError):
            await executor.execute(threatfox_work_item())
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED
        ]

    @pytest.mark.asyncio
    async def test_mixed_converted_plus_errors_succeeds_retaining_first_error(
        self,
    ) -> None:
        """A mixed partial result succeeds and keeps the first error.

        One global ConvertedEvidence plus one typed provider error commits
        the ConvertedEvidence, returns SUCCEEDED, retains only the first
        provider error (stable code and retryability, never its free-form
        message), and exposes the retained code on the
        PROVIDER_WORK_COMPLETED timeline event. The committed outcome ID is
        the exact EvidenceObservation identity.
        """
        converted = global_converted_evidence(evidence_id=uuid4())
        persistence = FakePersistenceService([persisted_result(converted)])
        first_error = ProviderError(
            provider=THREATFOX_SOURCE,
            code=ProviderErrorCode.TIMEOUT,
            message="A query timed out for the indicator",
            retryable=True,
        )
        second_error = ProviderError(
            provider=THREATFOX_SOURCE,
            code=ProviderErrorCode.INVALID_RESPONSE,
            message="secondary query returned a malformed payload",
            retryable=False,
        )
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=THREATFOX_SOURCE,
                evidence=(converted,),
                errors=(first_error, second_error),
            )
        )
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, timeline=timeline
        )
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status.name == "SUCCEEDED"
        # Exactly one ConvertedEvidence is processed and persisted, in
        # provider-return order.
        assert len(persistence.calls) == 1
        assert persistence.calls[0][0].evidence.id == converted.evidence.id
        assert persistence.calls[0][0].evidence.source == converted.evidence.source
        # Only the first provider error is retained, by code and retryability.
        assert outcome.error is not None
        assert outcome.error.code == "timeout"
        assert outcome.error.recoverable is True
        assert "timed out" not in outcome.error.message
        assert "malformed" not in outcome.error.message
        assert len(outcome.evidence_ids) == 1
        # The timeline accurately exposes the partial result: the retained
        # code travels on the PROVIDER_WORK_COMPLETED event.
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            InvestigationTimelineEventType.EVIDENCE_PERSISTED,
            InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
        ]
        assert timeline.events[-1].error_code == "timeout"

    @pytest.mark.asyncio
    async def test_provider_error_retryable_is_preserved(self) -> None:
        """Provider retryability flows into the typed outcome error."""
        retryable = ProviderError(
            provider=THREATFOX_SOURCE,
            code=ProviderErrorCode.TIMEOUT,
            message="timeout",
            retryable=True,
        )
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, errors=(retryable,))
        )
        executor = build_executor(provider, domain_entity())
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.error is not None
        assert outcome.error.recoverable is True


class TestExtractionPersistenceSequencing:
    """Extraction and persistence sequencing invariants."""

    @pytest.mark.asyncio
    async def test_extraction_called_once_per_evidence_in_order(self) -> None:
        """Extraction runs once per ConvertedEvidence, in provider-return order."""
        first = global_converted_evidence()
        second = global_converted_evidence()
        order: list[str] = []

        def extractor(
            evidence_extraction_view: EvidenceExtractionView,
        ) -> ExtractionResult:
            order.append(evidence_extraction_view.evidence.source)
            return ExtractionResult()

        persistence = FakePersistenceService(
            [
                persisted_result(first, observation_id=uuid4()),
                persisted_result(second, observation_id=uuid4()),
            ]
        )
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, evidence=(first, second))
        )
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, extractor=extractor
        )
        outcome = await executor.execute(threatfox_work_item())
        assert len(persistence.calls) == 2
        assert order == [THREATFOX_SOURCE, THREATFOX_SOURCE]
        assert outcome.status.name == "SUCCEEDED"

    @pytest.mark.asyncio
    async def test_extraction_happens_before_persistence(self) -> None:
        """Each ConvertedEvidence is extracted before it is persisted."""
        seen: list[str] = []
        converted = global_converted_evidence()

        def extractor(_view: EvidenceExtractionView) -> ExtractionResult:
            seen.append("extract")
            return ExtractionResult()

        class RecordingPersistence(FakePersistenceService):
            async def persist(
                self,
                converted: ConvertedEvidence,
                invocation_entity: Entity,
                extraction: ExtractionResult,
                **kwargs: Any,
            ) -> ProviderObservationPersistenceResult:
                seen.append("persist")
                return await super().persist(
                    converted, invocation_entity, extraction, **kwargs
                )

        persistence = RecordingPersistence([persisted_result(converted)])
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, evidence=(converted,))
        )
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, extractor=extractor
        )
        await executor.execute(threatfox_work_item())
        assert seen == ["extract", "persist"]

    @pytest.mark.asyncio
    async def test_extraction_failure_prevents_persistence(self) -> None:
        """An extraction failure discards that ConvertedEvidence and fails the work item."""

        def failing_extractor(_view: EvidenceExtractionView) -> ExtractionResult:
            raise EvidenceExtractionError(
                THREATFOX_SOURCE,
                ExtractionErrorReason.MALFORMED_FACTS,
                "malformed ThreatFox facts",
            )

        persistence = FakePersistenceService()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=THREATFOX_SOURCE,
                evidence=(global_converted_evidence(),),
            )
        )
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            extractor=failing_extractor,
            timeline=timeline,
        )
        outcome = await executor.execute(threatfox_work_item())
        assert not persistence.calls
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_EXTRACTION_ERROR
        assert InvestigationTimelineEventType.PROVIDER_WORK_FAILED in [
            event.type for event in timeline.events
        ]

    @pytest.mark.asyncio
    async def test_persistence_failure_returns_failed_outcome(self) -> None:
        """A PR 18C failure fails the work item with persistence_error."""
        converted = global_converted_evidence()
        persistence = FakePersistenceService(raises=RuntimeError("db failure"))
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, evidence=(converted,))
        )
        executor = build_executor(provider, domain_entity(), persistence=persistence)
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PERSISTENCE_ERROR

    @pytest.mark.asyncio
    async def test_prior_committed_observation_retained_after_later_failure(
        self,
    ) -> None:
        """Already committed observation IDs remain represented when later work fails."""
        first = global_converted_evidence()
        second = global_converted_evidence()
        persistence = FakePersistenceService()

        calls = {"count": 0}

        async def persist(
            converted: ConvertedEvidence,
            invocation_entity: Entity,
            extraction: ExtractionResult,
            *,
            investigation_id: UUID,
            actor_id: UUID | None = None,
            request_id: UUID | None = None,
        ) -> ProviderObservationPersistenceResult:
            calls["count"] += 1
            if calls["count"] == 1:
                return persisted_result(first, observation_id=FIRST_OBSERVATION_ID)
            raise RuntimeError("later persistence failure")

        persistence.persist = persist  # type: ignore[method-assign]
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, evidence=(first, second))
        )
        executor = build_executor(provider, domain_entity(), persistence=persistence)
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PERSISTENCE_ERROR
        assert len(outcome.evidence_ids) == 1
        assert isinstance(outcome.evidence_ids[0], UUID)
        # Committed identity is the exact observation ID, never the stable
        # Evidence ID (the fake reports the fixed first observation).
        assert outcome.evidence_ids[0] == FIRST_OBSERVATION_ID

    @pytest.mark.asyncio
    async def test_provider_call_outside_uow_persists_after_return(self) -> None:
        """Provider I/O completes before persistence is invoked at all."""
        events: list[str] = []

        class OrderedProvider(FakeEvidenceProvider):
            async def investigate(
                self, investigation_id: UUID, entity: Entity
            ) -> ProviderResult:
                events.append("provider")
                return await super().investigate(investigation_id, entity)

        class OrderedPersistence(FakePersistenceService):
            async def persist(
                self,
                converted: ConvertedEvidence,
                invocation_entity: Entity,
                extraction: ExtractionResult,
                **kwargs: object,
            ) -> ProviderObservationPersistenceResult:
                events.append("persist")
                return persisted_result(converted)

        converted = global_converted_evidence()
        provider = OrderedProvider(
            ProviderResult(provider=THREATFOX_SOURCE, evidence=(converted,))
        )
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=OrderedPersistence([persisted_result(converted)]),
        )
        await executor.execute(threatfox_work_item())
        assert events == ["provider", "persist"]


class TestOutcomeBookkeepingHelpers:
    """Operational outcome identifier assembly."""

    @pytest.mark.asyncio
    async def test_discovered_ids_exclude_target_entity(self) -> None:
        """The investigated target is never reported as discovered."""
        converted = global_converted_evidence()
        persistence = FakePersistenceService(
            [
                persisted_result(
                    converted,
                    observation_id=uuid4(),
                    entity_ids=(DOMAIN_ENTITY_ID, uuid4()),
                )
            ]
        )
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, evidence=(converted,))
        )
        executor = build_executor(provider, domain_entity(), persistence=persistence)
        outcome = await executor.execute(threatfox_work_item())
        assert len(outcome.discovered_entity_ids) == 1


class TestTimelineSemantics:
    """Timeline event ordering and failure semantics."""

    @pytest.mark.asyncio
    async def test_started_event_precedes_provider_invocation(self) -> None:
        """The started event is appended before the provider call executes."""
        order: list[str] = []

        class OrderedSink(FakeTimelineSink):
            async def append(self, event: Any) -> None:
                order.append(f"timeline:{event.type.value}")
                await super().append(event)

        class OrderedProvider(FakeEvidenceProvider):
            async def investigate(
                self, investigation_id: UUID, entity: Entity
            ) -> ProviderResult:
                order.append("provider")
                return await super().investigate(investigation_id, entity)

        provider = OrderedProvider(ProviderResult(provider=THREATFOX_SOURCE))
        executor = build_executor(provider, domain_entity(), timeline=OrderedSink())
        await executor.execute(threatfox_work_item())
        assert order == [
            "timeline:provider_work_started",
            "provider",
            "timeline:provider_work_completed",
        ]

    @pytest.mark.asyncio
    async def test_evidence_persisted_only_after_persistence_success(self) -> None:
        """EVIDENCE_PERSISTED is emitted only after PR 18C commits."""
        converted = global_converted_evidence()
        persistence = FakePersistenceService([persisted_result(converted)])
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, evidence=(converted,))
        )
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, timeline=timeline
        )
        await executor.execute(threatfox_work_item())
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            InvestigationTimelineEventType.EVIDENCE_PERSISTED,
            InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
        ]

    @pytest.mark.asyncio
    async def test_failed_event_carries_only_safe_fields(self) -> None:
        """Failure events carry a bounded error code and identifiers only."""
        provider = FakeEvidenceProvider(None, raises=RuntimeError("sensitive"))
        timeline = FakeTimelineSink()
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        await executor.execute(threatfox_work_item())
        failed = timeline.events[-1]
        assert failed.type is InvestigationTimelineEventType.PROVIDER_WORK_FAILED
        assert failed.error_code == ERROR_PROVIDER_ERROR
        dumped = failed.model_dump()
        assert "sensitive" not in str(dumped)
        assert all(
            field_name in dumped
            for field_name in (
                "id",
                "investigation_id",
                "type",
                "occurred_at",
                "provider",
                "target_entity_id",
                "error_code",
            )
        )

    @pytest.mark.asyncio
    async def test_timeline_failure_fails_work_without_rollback(self) -> None:
        """A timeline append failure surfaces timeline_error with committed IDs."""
        converted = global_converted_evidence()
        persistence = FakePersistenceService([persisted_result(converted)])
        provider = FakeEvidenceProvider(
            ProviderResult(provider=THREATFOX_SOURCE, evidence=(converted,))
        )
        timeline = FakeTimelineSink(
            fail_on=InvestigationTimelineEventType.EVIDENCE_PERSISTED
        )
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, timeline=timeline
        )
        outcome = await executor.execute(threatfox_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_TIMELINE_ERROR
        # Committed domain data is preserved in the outcome.
        assert len(outcome.evidence_ids) == 1

    @pytest.mark.asyncio
    async def test_started_timeline_failure_prevents_provider_call(self) -> None:
        """A failed started append fails the work before any provider I/O."""
        provider = FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE))
        timeline = FakeTimelineSink(
            fail_on=InvestigationTimelineEventType.PROVIDER_WORK_STARTED
        )
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        outcome = await executor.execute(threatfox_work_item())
        assert not provider.investigate_calls
        assert outcome.error is not None
        assert outcome.error.code == ERROR_TIMELINE_ERROR

    @pytest.mark.asyncio
    async def test_timeline_events_use_injected_clock(self) -> None:
        """Every event carries the deterministic context timestamp."""
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE))
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        await executor.execute(threatfox_work_item())
        assert all(event.occurred_at == FIXED_TS for event in timeline.events)


class TestExecutorInvestigationBinding:
    """ProviderWorkExecutor exposes its bound investigation identity."""

    def test_executor_is_investigation_bound(self) -> None:
        """ProviderWorkExecutor implements InvestigationBoundWorkExecutor."""
        executor = build_executor(
            FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE)),
            domain_entity(),
        )
        assert isinstance(executor, InvestigationBoundWorkExecutor)

    def test_bound_investigation_id_matches_context(self) -> None:
        """The bound ID equals the exact ProviderExecutionContext ID."""
        executor = build_executor(
            FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE)),
            domain_entity(),
        )
        assert executor.bound_investigation_id == INVESTIGATION_ID

    def test_bound_investigation_id_has_no_mutation_path(self) -> None:
        """No setter or mutation path can change the bound ID."""
        executor = build_executor(
            FakeEvidenceProvider(ProviderResult(provider=THREATFOX_SOURCE)),
            domain_entity(),
        )
        with pytest.raises(AttributeError):
            executor.bound_investigation_id = uuid4()  # type: ignore[misc]
        assert executor.bound_investigation_id == INVESTIGATION_ID
