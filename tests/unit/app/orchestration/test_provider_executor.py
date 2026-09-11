# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 19B real provider work executor."""

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
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from tests.support.provider_executor_fixtures import (
    DOMAIN_ENTITY_ID,
    FIXED_TS,
    INVESTIGATION_ID,
    FakeEvidenceProvider,
    FakePersistenceService,
    FakeTimelineSink,
    build_executor,
    dns_evidence,
    dns_work_item,
    domain_entity,
    persisted_result,
    provider_calls_recorded,
    provider_error,
)


class TestProviderResolution:
    """Target and provider resolution before any provider invocation."""

    @pytest.mark.asyncio
    async def test_missing_provider_fails_without_timeline_start(self) -> None:
        """An unknown source yields a failed outcome and no started event."""
        timeline = FakeTimelineSink()
        executor = build_executor(None, domain_entity(), timeline=timeline)
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PROVIDER_NOT_CONFIGURED
        assert provider_calls_recorded(timeline) == []

    @pytest.mark.asyncio
    async def test_missing_target_never_calls_provider(self) -> None:
        """A missing target yields target_not_found without provider invocation."""
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        timeline = FakeTimelineSink()
        executor = build_executor(provider, None, timeline=timeline)
        outcome = await executor.execute(dns_work_item())
        assert not provider.investigate_calls
        assert outcome.error is not None
        assert outcome.error.code == ERROR_TARGET_NOT_FOUND
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED
        ]

    @pytest.mark.asyncio
    async def test_soft_deleted_target_never_calls_provider(self) -> None:
        """A soft-deleted target is indistinguishable from a missing one."""
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        deleted = domain_entity().model_copy(update={"deleted_at": FIXED_TS})
        executor = build_executor(provider, deleted)
        outcome = await executor.execute(dns_work_item())
        assert not provider.investigate_calls
        assert outcome.error is not None
        assert outcome.error.code == ERROR_TARGET_NOT_FOUND

    @pytest.mark.asyncio
    async def test_unsupported_target_never_calls_provider(self) -> None:
        """An unsupported target yields unsupported_indicator without HTTP."""
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value),
            supports_target=False,
        )
        executor = build_executor(provider, domain_entity())
        outcome = await executor.execute(dns_work_item())
        assert not provider.investigate_calls
        assert outcome.error is not None
        assert outcome.error.code == ERROR_UNSUPPORTED_INDICATOR

    @pytest.mark.asyncio
    async def test_supported_provider_called_once_with_target(self) -> None:
        """A supported provider is invoked exactly once with the loaded entity."""
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        executor = build_executor(provider, domain_entity())
        await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        investigation_id, entity = provider.investigate_calls[0]
        assert investigation_id == INVESTIGATION_ID
        assert entity == domain_entity()


class TestProviderResultProcessing:
    """Deterministic handling of provider results."""

    @pytest.mark.asyncio
    async def test_empty_success_yields_succeeded_without_ids(self) -> None:
        """A valid miss is a success with no inferred assessment or IDs."""
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        timeline = FakeTimelineSink()
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        outcome = await executor.execute(dns_work_item())
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
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, errors=(provider_error(),)
            )
        )
        persistence = FakePersistenceService()
        executor = build_executor(provider, domain_entity(), persistence=persistence)
        outcome = await executor.execute(dns_work_item())
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
        outcome = await executor.execute(dns_work_item())
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
            await executor.execute(dns_work_item())
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED
        ]

    @pytest.mark.asyncio
    async def test_mixed_evidence_plus_rr_errors_succeeds_retaining_first_error(
        self,
    ) -> None:
        """A Google-DNS-shaped partial result succeeds and keeps the first error.

        One DNS Evidence plus one typed RR-query error commits the Evidence,
        returns SUCCEEDED, retains only the first provider error (stable code
        and retryability, never its free-form message), and exposes the
        retained code on the PROVIDER_WORK_COMPLETED timeline event.
        """
        evidence = dns_evidence(evidence_id=uuid4())
        persistence = FakePersistenceService([persisted_result(evidence)])
        first_error = ProviderError(
            provider=SourceId.GOOGLE_PUBLIC_DNS.value,
            code=ProviderErrorCode.TIMEOUT,
            message="A query timed out for the RR type",
            retryable=True,
        )
        second_error = ProviderError(
            provider=SourceId.GOOGLE_PUBLIC_DNS.value,
            code=ProviderErrorCode.INVALID_RESPONSE,
            message="AAAA query returned a malformed payload",
            retryable=False,
        )
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(evidence,),
                errors=(first_error, second_error),
            )
        )
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, timeline=timeline
        )
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "SUCCEEDED"
        # Exactly one Evidence is processed and persisted, in provider-return
        # order, carrying the assigned identity.
        assert len(persistence.calls) == 1
        assert persistence.calls[0][0].id == evidence.id
        assert persistence.calls[0][0].source == evidence.source
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
            provider=SourceId.GOOGLE_PUBLIC_DNS.value,
            code=ProviderErrorCode.TIMEOUT,
            message="timeout",
            retryable=True,
        )
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, errors=(retryable,)
            )
        )
        executor = build_executor(provider, domain_entity())
        outcome = await executor.execute(dns_work_item())
        assert outcome.error is not None
        assert outcome.error.recoverable is True


class TestExtractionPersistenceSequencing:
    """Extraction and persistence sequencing invariants."""

    @pytest.mark.asyncio
    async def test_extraction_called_once_per_evidence_in_order(self) -> None:
        """Extraction runs once per Evidence, in provider-return order."""
        first = dns_evidence()
        second = dns_evidence()
        order: list[str] = []

        def extractor(evidence: Evidence) -> ExtractionResult:
            order.append(evidence.facts["query_name"])
            return ExtractionResult()

        persistence = FakePersistenceService(
            [persisted_result(first), persisted_result(second)]
        )
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(first, second),
            )
        )
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, extractor=extractor
        )
        outcome = await executor.execute(dns_work_item())
        assert len(persistence.calls) == 2
        assert order == ["malicious.test", "malicious.test"]
        assert outcome.status.name == "SUCCEEDED"

    @pytest.mark.asyncio
    async def test_extraction_happens_before_persistence(self) -> None:
        """Each Evidence is extracted before it is persisted."""
        seen: list[str] = []
        evidence = dns_evidence()

        def extractor(_evidence: Evidence) -> ExtractionResult:
            seen.append("extract")
            return ExtractionResult()

        class RecordingPersistence(FakePersistenceService):
            async def persist(
                self,
                evidence: Evidence,
                extraction: ExtractionResult,
                **kwargs: Any,
            ) -> ProviderObservationPersistenceResult:
                seen.append("persist")
                return await super().persist(evidence, extraction, **kwargs)

        persistence = RecordingPersistence([persisted_result(evidence)])
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, extractor=extractor
        )
        await executor.execute(dns_work_item())
        assert seen == ["extract", "persist"]

    @pytest.mark.asyncio
    async def test_extraction_failure_prevents_persistence(self) -> None:
        """An extraction failure discards that Evidence and fails the work item."""

        def failing_extractor(_evidence: Evidence) -> ExtractionResult:
            raise EvidenceExtractionError(
                SourceId.GOOGLE_PUBLIC_DNS.value,
                ExtractionErrorReason.MALFORMED_FACTS,
                "malformed DNS facts",
            )

        persistence = FakePersistenceService()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(dns_evidence(),),
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
        outcome = await executor.execute(dns_work_item())
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
        evidence = dns_evidence()
        persistence = FakePersistenceService(raises=RuntimeError("db failure"))
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        executor = build_executor(provider, domain_entity(), persistence=persistence)
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PERSISTENCE_ERROR

    @pytest.mark.asyncio
    async def test_prior_committed_evidence_retained_after_later_failure(self) -> None:
        """Already committed Evidence IDs remain represented when later work fails."""
        first = dns_evidence()
        second = dns_evidence()
        persistence = FakePersistenceService()

        calls = {"count": 0}

        async def persist(
            evidence: Evidence,
            extraction: ExtractionResult,
            *,
            actor_id: UUID | None = None,
            request_id: UUID | None = None,
        ) -> ProviderObservationPersistenceResult:
            calls["count"] += 1
            if calls["count"] == 1:
                return persisted_result(first)
            raise RuntimeError("later persistence failure")

        persistence.persist = persist  # type: ignore[method-assign]
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(first, second)
            )
        )
        executor = build_executor(provider, domain_entity(), persistence=persistence)
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PERSISTENCE_ERROR
        assert len(outcome.evidence_ids) == 1
        assert isinstance(outcome.evidence_ids[0], UUID)
        assert outcome.evidence_ids[0] not in (first.id, second.id)

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
                evidence: Evidence,
                extraction: ExtractionResult,
                **kwargs: object,
            ) -> ProviderObservationPersistenceResult:
                events.append("persist")
                return persisted_result(evidence)

        evidence = dns_evidence()
        provider = OrderedProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=OrderedPersistence([persisted_result(evidence)]),
        )
        await executor.execute(dns_work_item())
        assert events == ["provider", "persist"]


class TestOutcomeBookkeepingHelpers:
    """Operational outcome identifier assembly."""

    @pytest.mark.asyncio
    async def test_discovered_ids_exclude_target_entity(self) -> None:
        """The investigated target is never reported as discovered."""
        evidence = dns_evidence()
        persistence = FakePersistenceService(
            [persisted_result(evidence, entity_ids=(DOMAIN_ENTITY_ID, uuid4()))]
        )
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        executor = build_executor(provider, domain_entity(), persistence=persistence)
        outcome = await executor.execute(dns_work_item())
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

        provider = OrderedProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        executor = build_executor(provider, domain_entity(), timeline=OrderedSink())
        await executor.execute(dns_work_item())
        assert order == [
            "timeline:provider_work_started",
            "provider",
            "timeline:provider_work_completed",
        ]

    @pytest.mark.asyncio
    async def test_evidence_persisted_only_after_persistence_success(self) -> None:
        """EVIDENCE_PERSISTED is emitted only after PR 18C commits."""
        evidence = dns_evidence()
        persistence = FakePersistenceService([persisted_result(evidence)])
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, timeline=timeline
        )
        await executor.execute(dns_work_item())
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
        await executor.execute(dns_work_item())
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
        evidence = dns_evidence()
        persistence = FakePersistenceService([persisted_result(evidence)])
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        timeline = FakeTimelineSink(
            fail_on=InvestigationTimelineEventType.EVIDENCE_PERSISTED
        )
        executor = build_executor(
            provider, domain_entity(), persistence=persistence, timeline=timeline
        )
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_TIMELINE_ERROR
        # Committed domain data is preserved in the outcome.
        assert len(outcome.evidence_ids) == 1

    @pytest.mark.asyncio
    async def test_started_timeline_failure_prevents_provider_call(self) -> None:
        """A failed started append fails the work before any provider I/O."""
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        timeline = FakeTimelineSink(
            fail_on=InvestigationTimelineEventType.PROVIDER_WORK_STARTED
        )
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        outcome = await executor.execute(dns_work_item())
        assert not provider.investigate_calls
        assert outcome.error is not None
        assert outcome.error.code == ERROR_TIMELINE_ERROR

    @pytest.mark.asyncio
    async def test_timeline_events_use_injected_clock(self) -> None:
        """Every event carries the deterministic context timestamp."""
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        await executor.execute(dns_work_item())
        assert all(event.occurred_at == FIXED_TS for event in timeline.events)


class TestExecutorInvestigationBinding:
    """ProviderWorkExecutor exposes its bound investigation identity."""

    def test_executor_is_investigation_bound(self) -> None:
        """ProviderWorkExecutor implements InvestigationBoundWorkExecutor."""
        executor = build_executor(
            FakeEvidenceProvider(
                ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
            ),
            domain_entity(),
        )
        assert isinstance(executor, InvestigationBoundWorkExecutor)

    def test_bound_investigation_id_matches_context(self) -> None:
        """The bound ID equals the exact ProviderExecutionContext ID."""
        executor = build_executor(
            FakeEvidenceProvider(
                ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
            ),
            domain_entity(),
        )
        assert executor.bound_investigation_id == INVESTIGATION_ID

    def test_bound_investigation_id_has_no_mutation_path(self) -> None:
        """No setter or mutation path can change the bound ID."""
        executor = build_executor(
            FakeEvidenceProvider(
                ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
            ),
            domain_entity(),
        )
        with pytest.raises(AttributeError):
            executor.bound_investigation_id = uuid4()  # type: ignore[misc]
        assert executor.bound_investigation_id == INVESTIGATION_ID
