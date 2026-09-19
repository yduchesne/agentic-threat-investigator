# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 28F-2 datasource Evidence producer unit-test matrix.

Stable matrix IDs F2-M01..M10 (message construction), F2-L01..L11 (producer
lifecycle; F2-L12..L15 are recorder/domain-level and live in
``test_datasource_execution_recorder.py`` / ``test_datasource_log.py``),
F2-P01..P07 (publisher interaction), and F2-S01..S06 (scope). The tests run
the real PR 27C ``ThreatFoxDatasource`` (real ``ProviderHttpClient`` over a
deterministic local ``httpx.MockTransport`` — only the external Internet
endpoint is faked), the real PR 27D converter/registry, the real PR 28C
``evidence_message_from_converted`` builder, the real PR 28D
``InMemoryEvidenceLog.publisher()`` as the injected ``EvidencePublisher``,
and the PR 27B recorder over an in-memory UnitOfWork fake. No database,
broker, or network is involved; no Evidence is ever persisted by the
producer path.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self
from uuid import UUID

import httpx
import pytest

import agentic_threat_investigator.app.datasource_evidence_producer as producer_module
from agentic_threat_investigator.app.datasource_evidence_producer import (
    DatasourceEvidenceProducer,
    DatasourceProducerOutcome,
    DatasourceProducerResult,
)
from agentic_threat_investigator.app.datasource_semantics import (
    SemanticAcquisitionResult,
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    ConversionError,
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
    UnknownSemanticFormatError,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceConsumerId,
    EvidencePublisher,
    EvidencePublishError,
    EvidencePublishResult,
    InMemoryEvidenceLog,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    EvidenceMessageValidationError,
    decode_evidence_message,
    encode_evidence_message,
    evidence_message_id,
)
from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceExecutionEventType,
    DatasourceId,
    DatasourceLogEvent,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox import (
    ThreatFoxDatasource,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    ThreatFoxToEvidenceConverter,
    build_threatfox_conversion_registry,
    build_threatfox_match_facts,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from tests.support.provider_http import no_op_sleep, zero_jitter
from tests.support.threatfox_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    FIXED_KEY,
    asyncrat_domain_record,
    threatfox_search_response,
)

pytestmark = pytest.mark.unit

_OCCURRED_AT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"
_EXECUTION_ID = UUID("22222222-3333-4444-5555-666666666666")
_ENTITY_ID = UUID("11111111-2222-3333-4444-555555555555")

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)
_DOMAIN_ENTITY = Entity(
    id=_ENTITY_ID, type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN
)


class _State:
    """Shared producer-test state: durable events and transaction probes."""

    def __init__(self) -> None:
        """Start with an empty durable log and no open transaction."""
        self.events: list[DatasourceLogEvent] = []
        self.pending_append: DatasourceLogEvent | None = None
        self.commits = 0
        self.rollbacks = 0
        self.active = 0
        self.fail_on_event_type: DatasourceExecutionEventType | None = None

    @property
    def types(self) -> list[str]:
        """Return the durable event types in append order."""
        return [event.event_type.value for event in self.events]


class _Logs:
    """In-memory append-only datasource-log fake with deterministic failure."""

    def __init__(self, state: _State) -> None:
        """Bind to the shared test state."""
        self.state = state

    async def append(self, event: DatasourceLogEvent) -> None:
        """Record the pending append, or fail when a lifecycle fault is armed."""
        if self.state.fail_on_event_type is event.event_type:
            raise RuntimeError("injected datasource-log append failure")
        self.state.pending_append = event

    def commit(self) -> None:
        """Apply the pending append to the durable in-memory log."""
        if self.state.pending_append is not None:
            self.state.events.append(self.state.pending_append)
            self.state.pending_append = None


class _Uow(UnitOfWork):
    """Deterministic in-memory UnitOfWork fake with transaction probes."""

    def __init__(self, state: _State) -> None:
        """Bind the fake UoW to the shared state."""
        self.state = state
        self._logs = _Logs(state)
        self.datasource_logs = self._logs  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        """Assert no transaction is already open, then open one."""
        assert self.state.active == 0
        self.state.active += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit on success and roll back when the block raised."""
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()
        self.state.active -= 1

    async def commit(self) -> None:
        """Support the test commit behavior."""
        self._logs.commit()
        self.state.commits += 1

    async def rollback(self) -> None:
        """Support the test rollback behavior."""
        self.state.pending_append = None
        self.state.rollbacks += 1


def _uow_factory(state: _State) -> Callable[[], UnitOfWork]:
    """Return a UoW factory bound to the shared probe state."""
    return lambda: _Uow(state)


def _json_response(payload: object, *, status: int = 200) -> httpx.Response:
    """Build one deterministic JSON response."""
    return httpx.Response(
        status,
        content=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def _client(handler: Callable[[httpx.Request], Any]) -> httpx.AsyncClient:
    """Build a real ``httpx`` mock-transport client for the local fixture."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _datasource(
    client: httpx.AsyncClient, *, clock: Callable[[], datetime] | None = None
) -> ThreatFoxDatasource:
    """Build the real acquirer over the real bounded HTTP client."""
    return ThreatFoxDatasource(
        ProviderHttpClient(
            client=client,
            policy=ProviderHttpPolicy(max_retries=0, base_delay_seconds=0.01),
            sleep=no_op_sleep,
            jitter_fn=zero_jitter,
        ),
        auth_key=FIXED_KEY,
        clock=clock,
    )


def _semantic_context(
    definition: DatasourceDefinition = _DEFINITION,
) -> SemanticSourceContext:
    """Build the fixed cross-cutting semantic context of the fixture."""
    return SemanticSourceContext.from_definition(
        definition,
        retrieved_at=_OCCURRED_AT,
        source_reference=_ENDPOINT,
    )


def _threatfox_records(*ids: str) -> tuple[ThreatFoxRecord, ...]:
    """Build validated ThreatFoxRecord objects from the synthetic fixture."""
    return tuple(
        ThreatFoxRecord.model_validate(asyncrat_domain_record(id=record_id))
        for record_id in ids
    )


def _one_converted(record: ThreatFoxRecord) -> ConvertedEvidence:
    """Build one ConvertedEvidence exactly like the production converter.

    Mirrors ``ThreatFoxToEvidenceConverter`` output so message construction
    tests can drive deterministic 0..N flattening without the HTTP stack.
    """
    semantic = _semantic_context()
    return ConvertedEvidence(
        evidence=Evidence(
            id=evidence_id_for_source_record(
                SemanticFormatId.THREATFOX, SourceId.THREATFOX, record.id
            ),
            type=EvidenceType.THREAT_INTELLIGENCE,
            source=SourceId.THREATFOX.value,
            source_record_id=record.id,
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=evidence_id_for_source_record(
                SemanticFormatId.THREATFOX, SourceId.THREATFOX, record.id
            ),
            source_url=semantic.source_reference,
            observed_at=(
                record.last_seen if record.last_seen is not None else record.first_seen
            ),
            retrieved_at=semantic.retrieved_at,
            facts={"matches": [build_threatfox_match_facts(record)]},
            raw_payload=None,
        ),
    )


class _FixedCountConverter(ToEvidenceConverter[ThreatFoxRecord]):
    """Test-only converter emitting a fixed count of ConvertedEvidence per record."""

    def __init__(self, count: int) -> None:
        """Pin the per-record output count."""
        self._count = count

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Claim the ThreatFox semantic format."""
        return SemanticFormatId.THREATFOX

    def convert(
        self,
        source: ThreatFoxRecord,
        context: EvidenceConversionContext,
    ) -> tuple[ConvertedEvidence, ...]:
        """Emit ``count`` distinct ConvertedEvidence per record in return order.

        Each output derives its source-record identity from the source ID
        plus a decimal offset so the ThreatFox ID grammar stays valid.
        """
        return tuple(
            _one_converted(source.model_copy(update={"id": f"{source.id}{offset}"}))
            for offset in range(self._count)
        )


class _FakeAcquirer:
    """Test-only deterministic SemanticAcquirer for message-construction tests."""

    def __init__(
        self,
        handler: Callable[
            [],
            SemanticAcquisitionResult[ThreatFoxRecord]
            | Awaitable[SemanticAcquisitionResult[ThreatFoxRecord]],
        ],
        *,
        supports_value: bool = True,
    ) -> None:
        """Bind the handler and the deterministic support value."""
        self._handler = handler
        self._supports = supports_value

    def supports(self, entity: Entity) -> bool:
        """Return the deterministic applicability flag."""
        return self._supports

    async def acquire(
        self,
        *,
        definition: DatasourceDefinition,
        entity: Entity,
        recorder: object,
    ) -> SemanticAcquisitionResult[ThreatFoxRecord]:
        """Return the handler's result (awaited when it is a coroutine)."""
        outcome = self._handler()
        if inspect.isawaitable(outcome):
            outcome = await outcome
        return outcome


class _ProbePublisher(EvidencePublisher):
    """Test-only publisher counting calls and recording fault injections."""

    def __init__(self, *, fail: bool = False, cancelled: bool = False) -> None:
        """Start with no calls and an optional one-shot fault."""
        self.calls: list[Sequence[EvidenceMessage]] = []
        self._fail = fail
        self._cancelled = cancelled

    async def publish(
        self, messages: Sequence[EvidenceMessage]
    ) -> EvidencePublishResult:
        """Record the ordered input, then return or inject the armed fault."""
        self.calls.append(messages)
        if self._cancelled:
            raise asyncio.CancelledError
        if self._fail:
            raise RuntimeError("injected publish failure")
        return EvidencePublishResult(records=())


def _producer(
    state: _State,
    publisher: EvidencePublisher,
    *,
    acquirer: Any,
    registry: ToEvidenceConverterRegistry | None = None,
    execution_id: UUID | None = None,
) -> DatasourceEvidenceProducer[ThreatFoxRecord]:
    """Build one producer over the injected publisher and probe state."""
    return DatasourceEvidenceProducer(
        definition=_DEFINITION,
        acquirer=acquirer,
        registry=registry or build_threatfox_conversion_registry(),
        publisher=publisher,
        uow_factory=_uow_factory(state),
        clock=lambda: _OCCURRED_AT,
        execution_id=execution_id,
    )


async def _poll_messages(log: InMemoryEvidenceLog) -> tuple[EvidenceMessage, ...]:
    """Return every published message of one log in position order."""
    consumer = log.consumer(EvidenceConsumerId("producer-test"))
    batch = await consumer.poll(500)
    return tuple(record.message for record in batch.records)


class TestMessageConstruction:
    """F2-M01..M10: deterministic message construction over flattened output."""

    @pytest.mark.asyncio
    async def test_m01_one_object_one_message_sequence_zero(self) -> None:
        """F2-M01: one converted item becomes one message at sequence 0."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        outcome = await producer.produce(_DOMAIN_ENTITY)
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert outcome.published_count == 1
        assert outcome.execution_id is not None
        (message,) = await _poll_messages(log)
        assert message.sequence == 0
        assert message.source_record_id == "864201"

    @pytest.mark.asyncio
    async def test_m02_two_objects_sequences_in_source_order(self) -> None:
        """F2-M02: two objects yield sequences 0,1 preserving source order."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(),
            objects=_threatfox_records("864201", "864299"),
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        await producer.produce(_DOMAIN_ENTITY)
        messages = await _poll_messages(log)
        assert [message.sequence for message in messages] == [0, 1]
        assert [message.source_record_id for message in messages] == [
            "864201",
            "864299",
        ]

    @pytest.mark.asyncio
    async def test_m03_one_object_multiple_converter_order(self) -> None:
        """F2-M03: one object -> many contiguous items in converter return order."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        registry = ToEvidenceConverterRegistry(
            converters=(_FixedCountConverter(count=3),)
        )
        producer = _producer(
            state,
            log.publisher(),
            acquirer=_FakeAcquirer(lambda: result),
            registry=registry,
        )
        await producer.produce(_DOMAIN_ENTITY)
        messages = await _poll_messages(log)
        assert [message.sequence for message in messages] == [0, 1, 2]
        assert [message.source_record_id for message in messages] == [
            "8642010",
            "8642011",
            "8642012",
        ]

    @pytest.mark.asyncio
    async def test_m04_mixed_zero_one_many_contiguous_flat_sequence(self) -> None:
        """F2-M04: mixed per-object counts flatten to one contiguous sequence.

        One object yields 0 items (omitted), then one yields 1 and one
        yields 2; the flattened sequence stays contiguous 0,1,2 over the
        surviving items in source-object order.
        """

        class _MixedConverter(ToEvidenceConverter[ThreatFoxRecord]):
            @property
            def semantic_format(self) -> SemanticFormatId:
                return SemanticFormatId.THREATFOX

            def convert(
                self,
                source: ThreatFoxRecord,
                context: EvidenceConversionContext,
            ) -> tuple[ConvertedEvidence, ...]:
                counts = {"864900": 0, "864901": 1, "864902": 2}
                return tuple(
                    _one_converted(
                        source.model_copy(update={"id": f"{source.id}{offset}"})
                    )
                    for offset in range(counts[source.id])
                )

        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(),
            objects=_threatfox_records("864900", "864901", "864902"),
        )
        registry = ToEvidenceConverterRegistry(converters=(_MixedConverter(),))
        producer = _producer(
            state,
            log.publisher(),
            acquirer=_FakeAcquirer(lambda: result),
            registry=registry,
        )
        await producer.produce(_DOMAIN_ENTITY)
        messages = await _poll_messages(log)
        assert [message.sequence for message in messages] == [0, 1, 2]
        assert [message.source_record_id for message in messages] == [
            "8649010",
            "8649020",
            "8649021",
        ]

    @pytest.mark.asyncio
    async def test_m05_zero_converted_empty_publish_tuple(self) -> None:
        """F2-M05: zero converted output publishes the empty tuple and completes."""
        state = _State()
        log = InMemoryEvidenceLog()
        result: SemanticAcquisitionResult[ThreatFoxRecord] = SemanticAcquisitionResult(
            context=_semantic_context(), objects=()
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        outcome = await producer.produce(_DOMAIN_ENTITY)
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert outcome.published_count == 0
        assert await _poll_messages(log) == ()
        assert state.types == ["started", "converted", "published", "completed"]

    @pytest.mark.asyncio
    async def test_m06_message_identity_is_pr28c_deterministic(self) -> None:
        """F2-M06: message_id is the PR 28C deterministic UUIDv5 value."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state,
            log.publisher(),
            acquirer=_FakeAcquirer(lambda: result),
            execution_id=_EXECUTION_ID,
        )
        await producer.produce(_DOMAIN_ENTITY)
        (message,) = await _poll_messages(log)
        assert message.datasource_execution_id == _EXECUTION_ID
        assert message.message_id == evidence_message_id(
            _EXECUTION_ID, 0, message.evidence_id
        )

    @pytest.mark.asyncio
    async def test_m07_exact_recorder_execution_id_in_all_messages(self) -> None:
        """F2-M07: every message carries the exact recorder execution ID."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(),
            objects=_threatfox_records("864201", "864299"),
        )
        producer = _producer(
            state,
            log.publisher(),
            acquirer=_FakeAcquirer(lambda: result),
            execution_id=_EXECUTION_ID,
        )
        outcome = await producer.produce(_DOMAIN_ENTITY)
        assert outcome.execution_id == _EXECUTION_ID
        messages = await _poll_messages(log)
        assert messages
        assert all(
            message.datasource_execution_id == _EXECUTION_ID for message in messages
        )

    @pytest.mark.asyncio
    async def test_m08_provenance_matches_semantic_context(self) -> None:
        """F2-M08: messages carry the exact semantic-source provenance."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        await producer.produce(_DOMAIN_ENTITY)
        (message,) = await _poll_messages(log)
        assert message.datasource_id == _DEFINITION.datasource_id
        assert message.source_id is SourceId.THREATFOX
        assert message.semantic_format is SemanticFormatId.THREATFOX
        assert message.source_url == _ENDPOINT
        assert message.retrieved_at == _OCCURRED_AT
        assert message.evidence_type is EvidenceType.THREAT_INTELLIGENCE

    @pytest.mark.asyncio
    async def test_m09_builder_failure_no_publish_failed(self) -> None:
        """F2-M09: a message-construction violation publishes nothing and FAILED.

        An observation whose source_url differs from the semantic reference
        fails the PR 28C builder; the producer records
        FAILED(message_construction_failed), publishes nothing, and the log
        stays empty.
        """
        state = _State()
        log = InMemoryEvidenceLog()
        record = _threatfox_records("864201")[0]
        semantic = _semantic_context()
        evidence_id = evidence_id_for_source_record(
            SemanticFormatId.THREATFOX, SourceId.THREATFOX, record.id
        )
        mismatched = ConvertedEvidence(
            evidence=Evidence(
                id=evidence_id,
                type=EvidenceType.THREAT_INTELLIGENCE,
                source=SourceId.THREATFOX.value,
                source_record_id=record.id,
            ),
            observation=EvidenceObservationCandidate(
                evidence_id=evidence_id,
                source_url="https://other.example/api",
                observed_at=record.first_seen,
                retrieved_at=semantic.retrieved_at,
                facts={"matches": [build_threatfox_match_facts(record)]},
                raw_payload=None,
            ),
        )

        class _BadConverter(ToEvidenceConverter[ThreatFoxRecord]):
            @property
            def semantic_format(self) -> SemanticFormatId:
                return SemanticFormatId.THREATFOX

            def convert(
                self,
                source: ThreatFoxRecord,
                context: EvidenceConversionContext,
            ) -> tuple[ConvertedEvidence, ...]:
                return (mismatched,)

        registry = ToEvidenceConverterRegistry(converters=(_BadConverter(),))
        result = SemanticAcquisitionResult(context=semantic, objects=(record,))
        producer = _producer(
            state,
            log.publisher(),
            acquirer=_FakeAcquirer(lambda: result),
            registry=registry,
        )
        with pytest.raises(EvidenceMessageValidationError):
            await producer.produce(_DOMAIN_ENTITY)
        assert await _poll_messages(log) == ()
        assert state.types == ["started", "converted", "failed"]
        assert state.events[-1].error_code == "message_construction_failed"

    @pytest.mark.asyncio
    async def test_m10_same_execution_id_same_fixture_identical_messages(self) -> None:
        """F2-M10: identical injected execution ID + fixture yields identical messages."""
        state_a = _State()
        state_b = _State()
        log_a = InMemoryEvidenceLog()
        log_b = InMemoryEvidenceLog()

        def result() -> SemanticAcquisitionResult[ThreatFoxRecord]:
            return SemanticAcquisitionResult(
                context=_semantic_context(),
                objects=_threatfox_records("864201", "864299"),
            )

        producer_a = _producer(
            state_a,
            log_a.publisher(),
            acquirer=_FakeAcquirer(result),
            execution_id=_EXECUTION_ID,
        )
        producer_b = _producer(
            state_b,
            log_b.publisher(),
            acquirer=_FakeAcquirer(result),
            execution_id=_EXECUTION_ID,
        )
        await producer_a.produce(_DOMAIN_ENTITY)
        await producer_b.produce(_DOMAIN_ENTITY)
        first = await _poll_messages(log_a)
        second = await _poll_messages(log_b)
        assert first == second
        assert [message.sequence for message in first] == [0, 1]


class TestLifecycle:
    """F2-L01..L11: producer lifecycle through the real ThreatFox HTTP stack."""

    async def _run_live(
        self,
        state: _State,
        log: InMemoryEvidenceLog,
        payload: object,
        *,
        status: int = 200,
        registry: ToEvidenceConverterRegistry | None = None,
    ) -> DatasourceProducerResult:
        """Run one production-stack produce against one static fixture."""
        async with _client(lambda _: _json_response(payload, status=status)) as client:
            producer = _producer(
                state,
                log.publisher(),
                acquirer=_datasource(client, clock=lambda: _OCCURRED_AT),
                registry=registry,
            )
            return await producer.produce(_DOMAIN_ENTITY)

    @pytest.mark.asyncio
    async def test_l01_normal_lifecycle(self) -> None:
        """F2-L01: STARTED, ACQUIRED, DECODED, CONVERTED(1), PUBLISHED(1), COMPLETED."""
        state = _State()
        log = InMemoryEvidenceLog()
        outcome = await self._run_live(
            state,
            log,
            threatfox_search_response(asyncrat_domain_record()),
        )
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert outcome.published_count == 1
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "published",
            "completed",
        ]
        assert state.events[3].item_count == 1
        assert state.events[4].item_count == 1
        assert all(event.error_code is None for event in state.events)
        (message,) = await _poll_messages(log)
        assert message.sequence == 0
        assert message.datasource_execution_id == outcome.execution_id

    @pytest.mark.asyncio
    async def test_l02_zero_output_lifecycle(self) -> None:
        """F2-L02: CONVERTED(0), PUBLISHED(0), COMPLETED on a valid no-result."""
        state = _State()
        log = InMemoryEvidenceLog()
        outcome = await self._run_live(state, log, {"query_status": "no_result"})
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert outcome.published_count == 0
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "published",
            "completed",
        ]
        assert state.events[3].item_count == 0
        assert state.events[4].item_count == 0
        assert await _poll_messages(log) == ()

    @pytest.mark.asyncio
    async def test_l03_acquisition_failure_no_publish(self) -> None:
        """F2-L03: a typed HTTP failure records FAILED and publishes nothing."""
        state = _State()
        log = InMemoryEvidenceLog()
        outcome = await self._run_live(state, log, {}, status=500)
        assert outcome.outcome is DatasourceProducerOutcome.FAILED
        assert outcome.published_count == 0
        assert outcome.error_code == "provider_unavailable"
        assert state.types == ["started", "failed"]
        assert state.events[-1].error_code == "provider_unavailable"
        assert await _poll_messages(log) == ()

    @pytest.mark.asyncio
    async def test_l04_decode_semantic_failure_bounded_failed(self) -> None:
        """F2-L04: a decode/semantic stage failure is a bounded FAILED, no publish."""
        state = _State()
        log = InMemoryEvidenceLog()
        outcome = await self._run_live(state, log, {"query_status": "ratelimited"})
        assert outcome.outcome is DatasourceProducerOutcome.FAILED
        assert outcome.error_code == "rate_limited"
        assert state.types == ["started", "acquired", "failed"]
        assert state.events[-1].error_code == "rate_limited"
        assert await _poll_messages(log) == ()

    @pytest.mark.asyncio
    async def test_l05_conversion_failure(self) -> None:
        """F2-L05: a conversion violation records FAILED(conversion_failed)."""

        class _FailingConverter(ToEvidenceConverter[Any]):
            @property
            def semantic_format(self) -> SemanticFormatId:
                return SemanticFormatId.THREATFOX

            def convert(
                self,
                source: Any,
                context: EvidenceConversionContext,
            ) -> tuple[Any, ...]:
                raise ConversionError("deterministic local conversion failure")

        state = _State()
        log = InMemoryEvidenceLog()
        failing = ToEvidenceConverterRegistry(converters=(_FailingConverter(),))
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            producer = _producer(
                state,
                log.publisher(),
                acquirer=_datasource(client, clock=lambda: _OCCURRED_AT),
                registry=failing,
            )
            with pytest.raises(ConversionError):
                await producer.produce(_DOMAIN_ENTITY)
        assert state.types == ["started", "acquired", "decoded", "failed"]
        assert state.events[-1].error_code == "conversion_failed"
        assert "converted" not in state.types
        assert await _poll_messages(log) == ()

    @pytest.mark.asyncio
    async def test_l06_message_failure(self) -> None:
        """F2-L06: a message-construction failure records the bounded code.

        The real converter emits a candidate whose source_url conflicts with
        the semantic reference (a PR 28A/28C provenance violation), so the
        builder fails deterministically; the lifecycle records
        FAILED(message_construction_failed) and the log stays empty.
        """

        class _MismatchingConverter(ThreatFoxToEvidenceConverter):
            def convert(
                self,
                source: ThreatFoxRecord,
                context: EvidenceConversionContext,
            ) -> tuple[ConvertedEvidence, ...]:
                converted = super().convert(source, context)
                evidence_id = converted[0].evidence.id
                return (
                    ConvertedEvidence(
                        evidence=converted[0].evidence,
                        observation=EvidenceObservationCandidate(
                            evidence_id=evidence_id,
                            source_url="https://other.example/api",
                            observed_at=converted[0].observation.observed_at,
                            retrieved_at=converted[0].observation.retrieved_at,
                            facts=converted[0].observation.facts,
                            raw_payload=converted[0].observation.raw_payload,
                        ),
                    ),
                )

        state = _State()
        log = InMemoryEvidenceLog()
        mismatching = ToEvidenceConverterRegistry(converters=(_MismatchingConverter(),))
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            producer = _producer(
                state,
                log.publisher(),
                acquirer=_datasource(client, clock=lambda: _OCCURRED_AT),
                registry=mismatching,
            )
            with pytest.raises(EvidenceMessageValidationError):
                await producer.produce(_DOMAIN_ENTITY)
        assert state.types == ["started", "acquired", "decoded", "converted", "failed"]
        assert state.events[-1].error_code == "message_construction_failed"
        assert await _poll_messages(log) == ()

    @pytest.mark.asyncio
    async def test_l07_publisher_failure(self) -> None:
        """F2-L07: a publish failure records FAILED(publication_failed)."""
        state = _State()
        log = InMemoryEvidenceLog()
        log.fail_next_publish()
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            producer = _producer(
                state,
                log.publisher(),
                acquirer=_datasource(client, clock=lambda: _OCCURRED_AT),
            )
            with pytest.raises(EvidencePublishError):
                await producer.produce(_DOMAIN_ENTITY)
        assert state.types == ["started", "acquired", "decoded", "converted", "failed"]
        assert state.events[-1].error_code == "publication_failed"
        assert "published" not in state.types
        assert "completed" not in state.types
        assert await _poll_messages(log) == ()

    @pytest.mark.asyncio
    async def test_l08_acquisition_cancellation_propagates(self) -> None:
        """F2-L08: cancellation during acquisition records CANCELLED and propagates."""
        state = _State()
        log = InMemoryEvidenceLog()

        async def cancelled() -> SemanticAcquisitionResult[ThreatFoxRecord]:
            raise asyncio.CancelledError

        producer = _producer(state, log.publisher(), acquirer=_FakeAcquirer(cancelled))
        with pytest.raises(asyncio.CancelledError):
            await producer.produce(_DOMAIN_ENTITY)
        assert state.types == ["started", "cancelled"]
        assert "failed" not in state.types
        assert "completed" not in state.types
        assert await _poll_messages(log) == ()

    @pytest.mark.asyncio
    async def test_l09_publication_cancellation_propagates(self) -> None:
        """F2-L09: cancellation at the publisher boundary records CANCELLED."""
        state = _State()
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            producer = _producer(
                state,
                _ProbePublisher(cancelled=True),
                acquirer=_datasource(client, clock=lambda: _OCCURRED_AT),
            )
            with pytest.raises(asyncio.CancelledError):
                await producer.produce(_DOMAIN_ENTITY)
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "cancelled",
        ]
        assert "failed" not in state.types
        assert "published" not in state.types
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_l10_publish_success_published_append_failure(self) -> None:
        """F2-L10: PUBLISHED-append failure after publish never republishes.

        The message is already durable in the log while the lifecycle lacks
        PUBLISHED; the producer propagates the lifecycle persistence failure
        without republishing, without COMPLETED, and never relabels it
        ``publication_failed``.
        """
        state = _State()
        log = InMemoryEvidenceLog()
        state.fail_on_event_type = DatasourceExecutionEventType.PUBLISHED
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            producer = _producer(
                state,
                log.publisher(),
                acquirer=_datasource(client, clock=lambda: _OCCURRED_AT),
            )
            with pytest.raises(
                RuntimeError, match="injected datasource-log append failure"
            ):
                await producer.produce(_DOMAIN_ENTITY)
        assert state.types == ["started", "acquired", "decoded", "converted"]
        assert "published" not in state.types
        assert "completed" not in state.types
        assert "failed" not in state.types
        assert len(await _poll_messages(log)) == 1

    @pytest.mark.asyncio
    async def test_l11_published_success_completed_append_failure(self) -> None:
        """F2-L11: COMPLETED-append failure after PUBLISHED never republishes.

        Publication is already known successful (PUBLISHED is durable), so the
        failed COMPLETED append propagates and the message is not republished.
        """
        state = _State()
        log = InMemoryEvidenceLog()
        state.fail_on_event_type = DatasourceExecutionEventType.COMPLETED
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            producer = _producer(
                state,
                log.publisher(),
                acquirer=_datasource(client, clock=lambda: _OCCURRED_AT),
            )
            with pytest.raises(
                RuntimeError, match="injected datasource-log append failure"
            ):
                await producer.produce(_DOMAIN_ENTITY)
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "published",
        ]
        assert state.events[-1].item_count == 1
        assert "completed" not in state.types
        assert "failed" not in state.types
        assert len(await _poll_messages(log)) == 1


class TestPublisherInteraction:
    """F2-P01..P07: exactly one ordered publish through the EvidencePublisher ABC."""

    @pytest.mark.asyncio
    async def test_p01_exactly_one_publish_call(self) -> None:
        """F2-P01: N messages reach the publisher in exactly one publish call."""
        state = _State()
        probe = _ProbePublisher()
        result = SemanticAcquisitionResult(
            context=_semantic_context(),
            objects=_threatfox_records("864201", "864299", "864300"),
        )
        producer = _producer(state, probe, acquirer=_FakeAcquirer(lambda: result))
        await producer.produce(_DOMAIN_ENTITY)
        assert len(probe.calls) == 1
        assert len(probe.calls[0]) == 3

    @pytest.mark.asyncio
    async def test_p02_publish_input_is_ordered(self) -> None:
        """F2-P02: the single publish receives messages in flattened order M0..MN."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(),
            objects=_threatfox_records("864201", "864299"),
        )
        producer = _producer(
            state,
            log.publisher(),
            acquirer=_FakeAcquirer(lambda: result),
            execution_id=_EXECUTION_ID,
        )
        await producer.produce(_DOMAIN_ENTITY)
        messages = await _poll_messages(log)
        assert [message.sequence for message in messages] == [0, 1]
        assert [message.source_record_id for message in messages] == [
            "864201",
            "864299",
        ]
        assert [message.message_id for message in messages] == [
            evidence_message_id(_EXECUTION_ID, 0, messages[0].evidence_id),
            evidence_message_id(_EXECUTION_ID, 1, messages[1].evidence_id),
        ]

    @pytest.mark.asyncio
    async def test_p03_zero_one_empty_publish_no_op(self) -> None:
        """F2-P03: zero output triggers one empty publish call (a no-op)."""
        state = _State()
        log = InMemoryEvidenceLog()
        probe = _ProbePublisher()
        result: SemanticAcquisitionResult[ThreatFoxRecord] = SemanticAcquisitionResult(
            context=_semantic_context(), objects=()
        )
        producer = _producer(state, probe, acquirer=_FakeAcquirer(lambda: result))
        await producer.produce(_DOMAIN_ENTITY)
        assert len(probe.calls) == 1
        assert probe.calls[0] == ()
        assert await _poll_messages(log) == ()

    @pytest.mark.asyncio
    async def test_p04_failure_no_retry(self) -> None:
        """F2-P04: a publish failure is never retried by the producer."""
        state = _State()
        probe = _ProbePublisher(fail=True)
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(state, probe, acquirer=_FakeAcquirer(lambda: result))
        with pytest.raises(RuntimeError, match="injected publish failure"):
            await producer.produce(_DOMAIN_ENTITY)
        assert len(probe.calls) == 1
        assert state.types == ["started", "converted", "failed"]
        assert state.events[-1].error_code == "publication_failed"

    @pytest.mark.asyncio
    async def test_p05_failure_no_direct_persistence_fallback(self) -> None:
        """F2-P05: a publish failure never falls back to direct persistence."""
        state = _State()
        log = InMemoryEvidenceLog()
        log.fail_next_publish()
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            producer = _producer(
                state,
                log.publisher(),
                acquirer=_datasource(client, clock=lambda: _OCCURRED_AT),
            )
            with pytest.raises(EvidencePublishError):
                await producer.produce(_DOMAIN_ENTITY)
        assert await _poll_messages(log) == ()
        assert state.types == ["started", "acquired", "decoded", "converted", "failed"]
        assert state.events[-1].error_code == "publication_failed"

    @pytest.mark.asyncio
    async def test_p06_success_published_count_equals_message_count(self) -> None:
        """F2-P06: PUBLISHED count equals the published message count."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(),
            objects=_threatfox_records("864201", "864299"),
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        outcome = await producer.produce(_DOMAIN_ENTITY)
        published = state.events[state.types.index("published")]
        assert published.item_count == 2
        assert outcome.published_count == 2
        assert len(await _poll_messages(log)) == 2

    @pytest.mark.asyncio
    async def test_p07_publisher_abc_only(self) -> None:
        """F2-P07: the producer depends on the EvidencePublisher ABC only."""
        log = InMemoryEvidenceLog()
        publisher = log.publisher()
        assert isinstance(publisher, EvidencePublisher)
        # The producer module never references the concrete in-memory log,
        # a consumer, direct observation persistence, or the Investigation
        # executor.
        source = inspect.getsource(producer_module)
        assert "InMemoryEvidenceLog" not in source
        assert "EvidenceConsumer" not in source
        assert "ProviderObservationPersistenceService" not in source
        assert "ProviderWorkExecutor" not in source


class TestScope:
    """F2-S01..S06: PR 28F-2 scope boundaries."""

    @pytest.mark.asyncio
    async def test_s01_reference_corpus_not_published_as_evidence(self) -> None:
        """F2-S01: MITRE/reference corpus never flows through the Evidence log.

        The ThreatFox registry owns only the ThreatFox semantic format; a
        STIX semantic-format lookup fails closed, and the producer module
        never references reference-corpus concepts.
        """
        registry = build_threatfox_conversion_registry()
        assert registry.get(SemanticFormatId.THREATFOX) is not None
        with pytest.raises(UnknownSemanticFormatError):
            registry.get(SemanticFormatId.STIX_21)
        source = inspect.getsource(producer_module)
        assert "MITRE" not in source
        assert "SourceRecord" not in source

    @pytest.mark.asyncio
    async def test_s02_no_observation_persistence_service(self) -> None:
        """F2-S02: the producer path never executes direct Evidence persistence."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        outcome = await producer.produce(_DOMAIN_ENTITY)
        # Only the lifecycle log and the Evidence log write; the producer
        # keeps no observation-persistence dependency.
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert state.fail_on_event_type is None
        source = inspect.getsource(producer_module)
        assert "ProviderObservationPersistenceService" not in source

    @pytest.mark.asyncio
    async def test_s03_no_investigation_identity_in_message(self) -> None:
        """F2-S03: a produced message carries no Investigation identity."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        await producer.produce(_DOMAIN_ENTITY)
        (message,) = await _poll_messages(log)
        for field in ("investigation_id", "investigation", "subject", "pivot"):
            assert not hasattr(message, field)
        assert "investigation" not in EvidenceMessage.model_fields

    @pytest.mark.asyncio
    async def test_s04_no_broker_topology_in_message(self) -> None:
        """F2-S04: a produced message carries no broker topology."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        await producer.produce(_DOMAIN_ENTITY)
        (message,) = await _poll_messages(log)
        for field in ("topic", "partition", "offset", "group_id", "broker"):
            assert not hasattr(message, field)
            assert field not in EvidenceMessage.model_fields

    @pytest.mark.asyncio
    async def test_s05_no_consumer_or_database_wait(self) -> None:
        """F2-S05: the producer never waits on a consumer or the database."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        outcome = await producer.produce(_DOMAIN_ENTITY)
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert outcome.published_count == 1
        source = inspect.getsource(producer_module)
        assert "poll(" not in source
        assert "postgres" not in source.lower()
        assert "evidence_consumer" not in source

    @pytest.mark.asyncio
    async def test_s06_json_codec_unchanged(self) -> None:
        """F2-S06: the PR 28F-1 canonical stdlib JSON codec path is unchanged.

        Messages produced by the producer round-trip through the PR 28C
        canonical codec byte-identically; the producer module performs no
        orjson integration.
        """
        state = _State()
        log = InMemoryEvidenceLog()
        result = SemanticAcquisitionResult(
            context=_semantic_context(), objects=_threatfox_records("864201")
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeAcquirer(lambda: result)
        )
        await producer.produce(_DOMAIN_ENTITY)
        (message,) = await _poll_messages(log)
        payload = encode_evidence_message(message)
        assert decode_evidence_message(payload) == message
        assert payload == encode_evidence_message(message)
        source = inspect.getsource(producer_module)
        assert "orjson" not in source
