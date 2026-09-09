# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for the PR 19B provider-work executor HIGH fixes.

Covers provider-output binding (HIGH-2), retention of all committed
operational IDs when later Evidence processing fails (HIGH-3), bounded
secret-free failure logging (HIGH-4), exact/canonical authoritative target
binding (fixes 02), and canonical first-seen aggregate ID lists (fixes 04).
Shared deterministic fakes and builders live in
``tests/support.provider_executor_fixtures``; these tests drive the real
executor through them and never import from the other executor test module.
"""

# pylint: disable=redefined-outer-name,protected-access,too-few-public-methods,unused-argument,missing-class-docstring,missing-function-docstring

import logging
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionError,
    ExtractionErrorReason,
    ExtractionResult,
)
from agentic_threat_investigator.app.orchestration.models import (
    enqueue_provider_work,
    record_provider_outcome,
    select_provider_work,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ERROR_EXTRACTION_ERROR,
    ERROR_PERSISTENCE_ERROR,
    ERROR_PROVIDER_BINDING,
    ERROR_TIMELINE_ERROR,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    LOGGER as EXECUTOR_LOGGER,
)
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceResult,
)
from agentic_threat_investigator.app.providers import ProviderResult
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EntityRef, Evidence
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import ProviderExecutionOutcome
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from tests.support.orchestration_fixtures import scenario_investigation_state
from tests.support.provider_executor_fixtures import (
    DISCOVERED_ONE,
    DOMAIN_ENTITY_ID,
    EVIDENCE_ONE,
    FOREIGN_INVESTIGATION_ID,
    IP_VALUE,
    RELATIONSHIP_ONE,
    SECOND_EVIDENCE,
    FakeEvidenceProvider,
    FakePersistenceService,
    FakeTimelineSink,
    build_executor,
    committed_first_observation,
    dns_evidence,
    dns_work_item,
    domain_entity,
    persisted_result,
)


def _assert_binding_failure(
    outcome: ProviderExecutionOutcome, timeline: FakeTimelineSink
) -> None:
    """Assert one deterministic binding failure with no commit events."""
    assert outcome.status.name == "FAILED"
    assert outcome.error is not None
    assert outcome.error.code == ERROR_PROVIDER_BINDING
    event_types = [event.type for event in timeline.events]
    assert InvestigationTimelineEventType.EVIDENCE_PERSISTED not in event_types
    assert InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED not in event_types


class TestProviderOutputBinding:
    """Provider output is bound to the selected work, target, and investigation."""

    @pytest.mark.asyncio
    async def test_registry_key_provider_id_mismatch_never_invokes_provider(
        self,
    ) -> None:
        """A provider registered under a foreign key identity fails before invocation."""
        misbound = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value),
            provider_id=SourceId.RDAP.value,
        )
        timeline = FakeTimelineSink()
        executor = build_executor(misbound, domain_entity(), timeline=timeline)
        outcome = await executor.execute(dns_work_item())
        assert not misbound.investigate_calls
        _assert_binding_failure(outcome, timeline)
        # Only the safe failure event is emitted; the work never started.
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED
        ]

    @pytest.mark.asyncio
    async def test_result_provider_mismatch_fails_after_invocation(self) -> None:
        """A result declaring a foreign provider never processes its tuple."""
        provider = FakeEvidenceProvider(ProviderResult(provider=SourceId.RDAP.value))
        timeline = FakeTimelineSink()
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        _assert_binding_failure(outcome, timeline)
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
        ]

    @pytest.mark.asyncio
    async def test_evidence_investigation_mismatch_fails_before_persistence(
        self,
    ) -> None:
        """Evidence for a foreign investigation is never extracted or persisted."""
        evidence = dns_evidence(evidence_id=EVIDENCE_ONE).model_copy(
            update={"investigation_id": FOREIGN_INVESTIGATION_ID}
        )
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)

    @pytest.mark.asyncio
    async def test_evidence_subject_type_mismatch_fails_before_persistence(
        self,
    ) -> None:
        """Evidence whose subject type differs from the target is rejected."""
        evidence = dns_evidence(evidence_id=EVIDENCE_ONE).model_copy(
            update={
                "subject": EntityRef(
                    id=DOMAIN_ENTITY_ID,
                    type=EntityType.IP_ADDRESS,
                    value=IP_VALUE,
                )
            }
        )
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)

    @pytest.mark.asyncio
    async def test_evidence_subject_value_mismatch_fails_before_persistence(
        self,
    ) -> None:
        """Evidence whose subject value differs from the target is rejected."""
        evidence = dns_evidence(evidence_id=EVIDENCE_ONE).model_copy(
            update={
                "subject": EntityRef(
                    id=DOMAIN_ENTITY_ID,
                    type=EntityType.DOMAIN,
                    value="other.example",
                )
            }
        )
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)

    @pytest.mark.asyncio
    async def test_evidence_subject_id_conflict_fails_before_persistence(
        self,
    ) -> None:
        """Evidence carrying a conflicting subject identifier is rejected."""
        evidence = dns_evidence(evidence_id=EVIDENCE_ONE).model_copy(
            update={
                "subject": EntityRef(
                    id=uuid4(),
                    type=EntityType.DOMAIN,
                    value="malicious.test",
                )
            }
        )
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)

    @pytest.mark.asyncio
    async def test_second_invalid_evidence_prevents_first_commit(self) -> None:
        """One invalid item in the tuple invalidates the whole returned result."""
        first = dns_evidence(evidence_id=EVIDENCE_ONE)
        second = dns_evidence(evidence_id=SECOND_EVIDENCE).model_copy(
            update={"investigation_id": FOREIGN_INVESTIGATION_ID}
        )
        extracted: list[UUID] = []

        def extractor(_evidence: Evidence) -> ExtractionResult:
            extracted.append(_evidence.id or UUID(int=0))
            return ExtractionResult()

        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(first, second),
            )
        )
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            extractor=extractor,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        # Zero extraction and zero persistence for the entire result tuple.
        assert not extracted
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)

    @pytest.mark.asyncio
    async def test_noncanonical_equivalent_subject_fails_closed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A canonical-equivalent subject that is not already canonical is rejected."""
        marker = "MALICIOUS.TEST."
        evidence = dns_evidence(evidence_id=EVIDENCE_ONE).model_copy(
            update={
                "subject": EntityRef(
                    id=DOMAIN_ENTITY_ID,
                    type=EntityType.DOMAIN,
                    value=marker,
                )
            }
        )
        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            timeline=timeline,
        )
        with caplog.at_level(logging.ERROR, logger=EXECUTOR_LOGGER.name):
            outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
        ]
        # The noncanonical spelling appears nowhere: not in logs, the outcome
        # error, or the persisted timeline representation.
        assert outcome.error is not None
        assert marker not in caplog.text
        assert marker not in outcome.error.message
        assert marker not in str([event.model_dump() for event in timeline.events])

    @pytest.mark.asyncio
    async def test_malformed_subject_canonicalization_never_escapes(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A subject that makes canonicalize() raise fails closed, never crashing."""
        marker = "SUPER-SECRET-SUBJECT-VALUE-91"
        target = Entity(
            id=DOMAIN_ENTITY_ID,
            type=EntityType.URL,
            value="https://evil.example/",
        )
        evidence = dns_evidence(evidence_id=EVIDENCE_ONE).model_copy(
            update={
                "subject": EntityRef(
                    id=DOMAIN_ENTITY_ID,
                    type=EntityType.URL,
                    value=marker,
                )
            }
        )
        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        executor = build_executor(
            provider,
            target,
            persistence=persistence,
            timeline=timeline,
        )
        with caplog.at_level(logging.ERROR, logger=EXECUTOR_LOGGER.name):
            outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)
        assert outcome.error is not None
        assert marker not in caplog.text
        assert marker not in outcome.error.message
        assert marker not in str([event.model_dump() for event in timeline.events])

    @pytest.mark.asyncio
    async def test_reader_wrong_entity_id_never_invokes_provider(self) -> None:
        """A reader returning another Entity ID fails before any provider call."""
        wrong_entity = domain_entity().model_copy(update={"id": uuid4()})
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        timeline = FakeTimelineSink()
        executor = build_executor(provider, wrong_entity, timeline=timeline)
        outcome = await executor.execute(dns_work_item())
        assert not provider.investigate_calls
        _assert_binding_failure(outcome, timeline)
        # The target check precedes the started event and provider invocation.
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED
        ]

    @pytest.mark.asyncio
    async def test_reader_entity_without_id_never_invokes_provider(self) -> None:
        """An ID-less reader result fails closed before any provider call."""
        no_id = domain_entity().model_copy(update={"id": None})
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        timeline = FakeTimelineSink()
        executor = build_executor(provider, no_id, timeline=timeline)
        outcome = await executor.execute(dns_work_item())
        assert not provider.investigate_calls
        _assert_binding_failure(outcome, timeline)
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED
        ]

    @pytest.mark.asyncio
    async def test_noncanonical_target_from_reader_rejected_before_provider(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A reader target whose value is not already canonical fails closed."""
        marker = "MALICIOUS.TEST."
        noncanonical = Entity(id=DOMAIN_ENTITY_ID, type=EntityType.DOMAIN, value=marker)
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        timeline = FakeTimelineSink()
        executor = build_executor(provider, noncanonical, timeline=timeline)
        with caplog.at_level(logging.ERROR, logger=EXECUTOR_LOGGER.name):
            outcome = await executor.execute(dns_work_item())
        assert not provider.investigate_calls
        _assert_binding_failure(outcome, timeline)
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED
        ]
        assert outcome.error is not None
        assert marker not in caplog.text
        assert marker not in outcome.error.message
        assert marker not in str([event.model_dump() for event in timeline.events])

    @pytest.mark.asyncio
    async def test_valid_subject_without_optional_id_is_accepted(self) -> None:
        """A canonical exact subject without an optional identifier remains valid."""
        evidence = dns_evidence(evidence_id=EVIDENCE_ONE).model_copy(
            update={
                "subject": EntityRef(type=EntityType.DOMAIN, value="malicious.test")
            }
        )
        persistence = FakePersistenceService([persisted_result(evidence)])
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "SUCCEEDED"
        assert len(outcome.evidence_ids) == 1
        assert outcome.error is None
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            InvestigationTimelineEventType.EVIDENCE_PERSISTED,
            InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
        ]


class TestMalformedBindingStopsBeforeExtraction:
    """Malformed/noncanonical output never reaches extraction or persistence."""

    @pytest.mark.asyncio
    async def test_noncanonical_subject_never_extracts_or_persists(self) -> None:
        """A noncanonical subject fails with zero extraction and PR 18C calls."""
        evidence = dns_evidence(evidence_id=EVIDENCE_ONE).model_copy(
            update={
                "subject": EntityRef(
                    id=DOMAIN_ENTITY_ID,
                    type=EntityType.DOMAIN,
                    value="MALICIOUS.TEST.",
                )
            }
        )
        extracted: list[UUID] = []

        def extractor(_evidence: Evidence) -> ExtractionResult:
            extracted.append(_evidence.id or UUID(int=0))
            return ExtractionResult()

        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            extractor=extractor,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        assert not extracted
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)

    @pytest.mark.asyncio
    async def test_malformed_subject_never_extracts_or_persists(self) -> None:
        """A subject that makes canonicalize() raise never reaches extraction."""
        target = Entity(
            id=DOMAIN_ENTITY_ID,
            type=EntityType.URL,
            value="https://evil.example/",
        )
        evidence = dns_evidence(evidence_id=EVIDENCE_ONE).model_copy(
            update={
                "subject": EntityRef(
                    id=DOMAIN_ENTITY_ID,
                    type=EntityType.URL,
                    value="SUPER-SECRET-SUBJECT-VALUE-91",
                )
            }
        )
        extracted: list[UUID] = []

        def extractor(_evidence: Evidence) -> ExtractionResult:
            extracted.append(_evidence.id or UUID(int=0))
            return ExtractionResult()

        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        executor = build_executor(
            provider,
            target,
            persistence=persistence,
            extractor=extractor,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        assert not extracted
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)

    @pytest.mark.asyncio
    async def test_second_invalid_evidence_never_extracts_first(self) -> None:
        """A tuple with one invalid item extracts and persists neither item."""
        first = dns_evidence(evidence_id=EVIDENCE_ONE)
        second = dns_evidence(evidence_id=SECOND_EVIDENCE).model_copy(
            update={
                "subject": EntityRef(
                    id=DOMAIN_ENTITY_ID,
                    type=EntityType.DOMAIN,
                    value="MALICIOUS.TEST.",
                )
            }
        )
        extracted: list[UUID] = []

        def extractor(_evidence: Evidence) -> ExtractionResult:
            extracted.append(_evidence.id or UUID(int=0))
            return ExtractionResult()

        persistence = FakePersistenceService()
        timeline = FakeTimelineSink()
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(first, second),
            )
        )
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            extractor=extractor,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert len(provider.investigate_calls) == 1
        assert not extracted
        assert not persistence.calls
        _assert_binding_failure(outcome, timeline)


class TestCommittedIdsRetainedOnFailure:
    """Failed work outcomes retain every ID committed before the failure."""

    @pytest.mark.asyncio
    async def test_second_evidence_extraction_failure_retains_committed_ids(
        self,
    ) -> None:
        """Extraction failure on Evidence 2 keeps all Evidence 1 committed IDs."""
        first = dns_evidence(evidence_id=EVIDENCE_ONE)
        second = dns_evidence(evidence_id=SECOND_EVIDENCE)
        persistence = FakePersistenceService(
            [committed_first_observation(first), persisted_result(second)]
        )
        calls = {"count": 0}

        def extractor(_evidence: Evidence) -> ExtractionResult:
            calls["count"] += 1
            if calls["count"] == 2:
                raise EvidenceExtractionError(
                    SourceId.GOOGLE_PUBLIC_DNS.value,
                    ExtractionErrorReason.MALFORMED_FACTS,
                    "malformed DNS facts",
                )
            return ExtractionResult()

        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(first, second),
            )
        )
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            extractor=extractor,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_EXTRACTION_ERROR
        assert outcome.evidence_ids == (EVIDENCE_ONE,)
        assert outcome.discovered_entity_ids == (DISCOVERED_ONE,)
        assert outcome.relationship_ids == (RELATIONSHIP_ONE,)
        assert len(persistence.calls) == 1
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            InvestigationTimelineEventType.EVIDENCE_PERSISTED,
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
        ]
        self._assert_bookkeeping_merges(outcome)

    @pytest.mark.asyncio
    async def test_second_evidence_persistence_failure_retains_committed_ids(
        self,
    ) -> None:
        """Persistence failure on Evidence 2 keeps all Evidence 1 committed IDs."""
        first = dns_evidence(evidence_id=EVIDENCE_ONE)
        second = dns_evidence(evidence_id=SECOND_EVIDENCE)
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
                return committed_first_observation(evidence)
            raise RuntimeError("later persistence failure")

        persistence.persist = persist  # type: ignore[method-assign]
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(first, second),
            )
        )
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_PERSISTENCE_ERROR
        assert outcome.evidence_ids == (EVIDENCE_ONE,)
        assert outcome.discovered_entity_ids == (DISCOVERED_ONE,)
        assert outcome.relationship_ids == (RELATIONSHIP_ONE,)
        assert [event.type for event in timeline.events] == [
            InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            InvestigationTimelineEventType.EVIDENCE_PERSISTED,
            InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
        ]
        self._assert_bookkeeping_merges(outcome)

    def _assert_bookkeeping_merges(self, outcome: ProviderExecutionOutcome) -> None:
        """Prove the failed outcome merges cleanly through PR 19A bookkeeping."""
        state = enqueue_provider_work(scenario_investigation_state(), [dns_work_item()])
        recorded = record_provider_outcome(select_provider_work(state), outcome)
        assert list(recorded.evidence_ids) == [EVIDENCE_ONE]
        assert list(recorded.discovered_entity_ids) == [DISCOVERED_ONE]
        assert list(recorded.relationship_ids) == [RELATIONSHIP_ONE]
        assert outcome.error is not None
        assert recorded.errors == [outcome.error]
        assert recorded.budget.provider_calls_used == 1
        assert dns_work_item() in recorded.completed_provider_work
        assert dns_work_item() not in recorded.pending_provider_work
        assert recorded.current_provider_work is None

    @pytest.mark.asyncio
    async def test_timeline_failure_preserves_all_committed_ids(self) -> None:
        """Committed IDs survive when the failure event itself cannot append."""
        first = dns_evidence(evidence_id=EVIDENCE_ONE)
        second = dns_evidence(evidence_id=SECOND_EVIDENCE)
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
                return committed_first_observation(evidence)
            raise RuntimeError("later persistence failure")

        persistence.persist = persist  # type: ignore[method-assign]
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(first, second),
            )
        )
        timeline = FakeTimelineSink(
            fail_on=InvestigationTimelineEventType.PROVIDER_WORK_FAILED
        )
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_TIMELINE_ERROR
        assert outcome.evidence_ids == (EVIDENCE_ONE,)
        assert outcome.discovered_entity_ids == (DISCOVERED_ONE,)
        assert outcome.relationship_ids == (RELATIONSHIP_ONE,)


class TestCanonicalAggregateIdLists:
    """Aggregate outcome/timeline ID lists are canonical first-seen summaries."""

    @pytest.mark.asyncio
    async def test_repeated_identity_appears_once_at_first_position(self) -> None:
        """A repeated Entity/Relationship across Evidence commits stays first-seen."""
        first = dns_evidence(evidence_id=EVIDENCE_ONE)
        second = dns_evidence(evidence_id=SECOND_EVIDENCE)
        # Both observations commit the same discovered Entity and Relationship
        # under different Evidence IDs, as stable PR 18C identities reuse.
        persistence = FakePersistenceService(
            [
                persisted_result(
                    first,
                    entity_ids=(DISCOVERED_ONE,),
                    relationship_ids=(RELATIONSHIP_ONE,),
                ),
                persisted_result(
                    second,
                    entity_ids=(DISCOVERED_ONE,),
                    relationship_ids=(RELATIONSHIP_ONE,),
                ),
            ]
        )
        order: list[UUID] = []

        def extractor(evidence: Evidence) -> ExtractionResult:
            order.append(evidence.id or UUID(int=0))
            return ExtractionResult()

        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(first, second),
            )
        )
        timeline = FakeTimelineSink()
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            extractor=extractor,
            timeline=timeline,
        )
        outcome = await executor.execute(dns_work_item())
        assert order == [EVIDENCE_ONE, SECOND_EVIDENCE]
        assert len(persistence.calls) == 2
        # Both Evidence IDs are persisted once each, in provider-return order.
        assert outcome.evidence_ids == (EVIDENCE_ONE, SECOND_EVIDENCE)
        # The repeated Entity and Relationship IDs occur once, at first position.
        assert outcome.discovered_entity_ids == (DISCOVERED_ONE,)
        assert outcome.relationship_ids == (RELATIONSHIP_ONE,)
        completed = timeline.events[-1]
        assert completed.type is InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED
        assert completed.evidence_ids == (EVIDENCE_ONE, SECOND_EVIDENCE)
        assert completed.entity_ids == (DISCOVERED_ONE,)
        assert completed.relationship_ids == (RELATIONSHIP_ONE,)

    @pytest.mark.asyncio
    async def test_failed_partial_outcome_keeps_canonical_accumulated_lists(
        self,
    ) -> None:
        """A later failure keeps the same first-seen canonical accumulated lists."""
        first = dns_evidence(evidence_id=EVIDENCE_ONE)
        second = dns_evidence(evidence_id=SECOND_EVIDENCE)
        persistence = FakePersistenceService(
            [
                persisted_result(
                    first,
                    entity_ids=(DISCOVERED_ONE,),
                    relationship_ids=(RELATIONSHIP_ONE,),
                ),
                persisted_result(second),
            ]
        )
        calls = {"count": 0}

        def extractor(_evidence: Evidence) -> ExtractionResult:
            calls["count"] += 1
            if calls["count"] == 2:
                raise EvidenceExtractionError(
                    SourceId.GOOGLE_PUBLIC_DNS.value,
                    ExtractionErrorReason.MALFORMED_FACTS,
                    "malformed DNS facts",
                )
            return ExtractionResult()

        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                evidence=(first, second),
            )
        )
        executor = build_executor(
            provider,
            domain_entity(),
            persistence=persistence,
            extractor=extractor,
        )
        outcome = await executor.execute(dns_work_item())
        assert outcome.status.name == "FAILED"
        assert outcome.error is not None
        assert outcome.error.code == ERROR_EXTRACTION_ERROR
        assert outcome.evidence_ids == (EVIDENCE_ONE,)
        assert outcome.discovered_entity_ids == (DISCOVERED_ONE,)
        assert outcome.relationship_ids == (RELATIONSHIP_ONE,)


class TestBoundedFailureLogging:
    """Caught exceptions never leak text or tracebacks through logs."""

    @pytest.mark.asyncio
    async def test_provider_exception_logs_no_exception_details(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An unexpected provider exception logs a bounded summary only."""
        marker = "SUPER-SECRET-MARKER-4381"
        provider = FakeEvidenceProvider(
            None, raises=RuntimeError(f"connection failed {marker}")
        )
        executor = build_executor(provider, domain_entity())
        with caplog.at_level(logging.ERROR, logger=EXECUTOR_LOGGER.name):
            outcome = await executor.execute(dns_work_item())
        assert outcome.error is not None
        assert outcome.error.code == "provider_error"
        assert marker not in caplog.text
        assert "provider work failure" in caplog.text
        assert "provider_error" in caplog.text

    @pytest.mark.asyncio
    async def test_persistence_exception_logs_no_exception_details(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A persistence exception logs a bounded summary without its message."""
        marker = "SUPER-SECRET-MARKER-8347"
        evidence = dns_evidence()
        persistence = FakePersistenceService(raises=RuntimeError(f"db failed {marker}"))
        provider = FakeEvidenceProvider(
            ProviderResult(
                provider=SourceId.GOOGLE_PUBLIC_DNS.value, evidence=(evidence,)
            )
        )
        executor = build_executor(provider, domain_entity(), persistence=persistence)
        with caplog.at_level(logging.ERROR, logger=EXECUTOR_LOGGER.name):
            outcome = await executor.execute(dns_work_item())
        assert outcome.error is not None
        assert outcome.error.code == "persistence_error"
        assert marker not in caplog.text
        assert "provider work failure" in caplog.text
        assert "persistence_error" in caplog.text

    @pytest.mark.asyncio
    async def test_timeline_exception_logs_no_exception_details(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A timeline append exception logs a bounded summary only."""
        marker = "SUPER-SECRET-MARKER-5930"
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        timeline = FakeTimelineSink(
            fail_on=InvestigationTimelineEventType.PROVIDER_WORK_STARTED
        )
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        with caplog.at_level(logging.ERROR, logger=EXECUTOR_LOGGER.name):
            outcome = await executor.execute(dns_work_item())
        assert outcome.error is not None
        assert outcome.error.code == "timeline_error"
        assert marker not in caplog.text
        assert "provider work failure" in caplog.text
        assert "timeline_error" in caplog.text

    @pytest.mark.asyncio
    async def test_timeline_exception_with_secret_message_is_fully_redacted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An injected timeline exception carrying a secret marker never leaks it.

        The adversarial variant injects the real exception (not a generic
        RuntimeError) so its message actually contains the synthetic secret.
        Every log record must be marker-free, carry no ``exc_info``, and keep
        the stable ``timeline_error`` category.
        """
        marker = "SUPER-SECRET-MARKER-9999"
        provider = FakeEvidenceProvider(
            ProviderResult(provider=SourceId.GOOGLE_PUBLIC_DNS.value)
        )
        timeline = FakeTimelineSink(
            fail_on=InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
            fail_exc=RuntimeError(f"timeline backend failed {marker}"),
        )
        executor = build_executor(provider, domain_entity(), timeline=timeline)
        with caplog.at_level(logging.ERROR, logger=EXECUTOR_LOGGER.name):
            outcome = await executor.execute(dns_work_item())
        assert outcome.error is not None
        assert outcome.error.code == "timeline_error"
        assert marker not in caplog.text
        assert "provider work failure" in caplog.text
        assert "timeline_error" in caplog.text
        assert all(marker not in record.getMessage() for record in caplog.records)
        assert all(record.exc_info is None for record in caplog.records)
        assert all(marker not in record.message for record in caplog.records)
