# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 32D collection datasource Evidence producer unit-test matrix.

Stable matrix IDs M32D-P01..P16 cover the source-neutral collection
producer seam. They run the real PR 32A MISP parser over deterministic
ATI-authored MISP fixtures, the real PR 32B `build_misp_conversion_registry`
converter registry (selected purely by `SemanticFormatId.MISP`), the real
PR 28C `evidence_message_from_converted` builder, the real PR 28D
`InMemoryEvidenceLog.publisher()` as the injected `EvidencePublisher`, and
the PR 27B recorder over an in-memory UnitOfWork fake. One test runs the
real `MispDatasource` over a deterministic `httpx.MockTransport` to prove
the real acquisitions honors the collection contract and holds no
UnitOfWork across HTTP. No database, broker, or network is involved; no
Evidence is ever persisted by the producer path.
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
    CollectionDatasourceEvidenceProducer,
    DatasourceEvidenceProducer,
    DatasourceProducerOutcome,
)
from agentic_threat_investigator.app.datasource_provider import (
    CollectionSemanticAcquirer,
)
from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    DatasourceStageError,
    SemanticAcquisitionResult,
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceConsumerId,
    EvidencePublishResult,
    InMemoryEvidenceLog,
)
from agentic_threat_investigator.app.evidence_message import EvidenceMessage
from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceExecutionEventType,
    DatasourceId,
    DatasourceLogEvent,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.evidence import ConvertedEvidence
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.misp import MispDatasource
from agentic_threat_investigator.infrastructure.datasources.misp_evidence import (
    build_misp_conversion_registry,
)
from agentic_threat_investigator.infrastructure.datasources.misp_semantics import (
    MispSemanticRecord,
    parse_misp_event,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from tests.support.misp_fixtures import (
    ATTRIBUTE_UUID,
    DOMAIN_VALUE,
    FIXED_KEY,
    IPV4_VALUE,
    IPV6_VALUE,
    MISP_REST_SEARCH_ENDPOINT,
    UNSUPPORTED_ATTRIBUTE_TYPE,
    misp_attribute,
    misp_rest_event,
    misp_rest_search,
)
from tests.support.provider_http import no_op_sleep, zero_jitter

pytestmark = pytest.mark.unit

_OCCURRED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)
_EXECUTION_ID = UUID("33333333-4444-5555-6666-777777777777")

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("misp-live"),
    source_id=SourceId.MISP,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.MISP,
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
        self.active_at_http: list[int] = []
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
        """Apply the pending append and count the commit."""
        self._logs.commit()
        self.state.commits += 1

    async def rollback(self) -> None:
        """Drop the pending append and count the rollback."""
        self.state.pending_append = None
        self.state.rollbacks += 1


def _uow_factory(state: _State) -> Callable[[], UnitOfWork]:
    """Return a UoW factory bound to the shared probe state."""
    return lambda: _Uow(state)


def _semantic_context() -> SemanticSourceContext:
    """Build the fixed cross-cutting MISP semantic context of the fixture."""
    return SemanticSourceContext.from_definition(
        _DEFINITION,
        retrieved_at=_OCCURRED_AT,
        source_reference=MISP_REST_SEARCH_ENDPOINT,
    )


def _misp_result(
    *,
    attributes: tuple[dict[str, Any], ...] = (),
    objects: tuple[dict[str, Any], ...] = (),
) -> SemanticAcquisitionResult[MispSemanticRecord]:
    """Parse one synthetic MISP Event through the real parser into records."""
    payload = misp_rest_search(misp_rest_event(attributes=attributes, objects=objects))
    records: list[MispSemanticRecord] = []
    for envelope in payload["response"]:
        semantic = parse_misp_event(envelope)
        assert semantic.error is None
        records.extend(semantic.records)
    return SemanticAcquisitionResult(
        context=_semantic_context(),
        objects=tuple(records),
    )


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


class _FakeCollectionAcquirer:
    """Test-only deterministic CollectionSemanticAcquirer."""

    def __init__(
        self,
        handler: Callable[
            [],
            SemanticAcquisitionResult[MispSemanticRecord]
            | Awaitable[SemanticAcquisitionResult[MispSemanticRecord]],
        ],
    ) -> None:
        """Bind the handler."""
        self._handler = handler

    async def acquire(
        self,
        *,
        definition: DatasourceDefinition,
        recorder: object,
    ) -> SemanticAcquisitionResult[MispSemanticRecord]:
        """Return the handler's result (awaited when it is a coroutine)."""
        outcome = self._handler()
        if inspect.isawaitable(outcome):
            outcome = await outcome
        return outcome


class _ProbePublisher:
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
    publisher: Any,
    *,
    acquirer: Any,
    registry: ToEvidenceConverterRegistry | None = None,
    execution_id: UUID | None = None,
) -> CollectionDatasourceEvidenceProducer[MispSemanticRecord]:
    """Build one collection producer over the injected seams and probe state."""
    return CollectionDatasourceEvidenceProducer(
        definition=_DEFINITION,
        acquirer=acquirer,
        registry=registry or build_misp_conversion_registry(),
        publisher=publisher,
        uow_factory=_uow_factory(state),
        clock=lambda: _OCCURRED_AT,
        execution_id=execution_id,
    )


async def _poll_messages(log: InMemoryEvidenceLog) -> tuple[EvidenceMessage, ...]:
    """Return every published message of one log in position order."""
    consumer = log.consumer(EvidenceConsumerId("collection-producer-test"))
    batch = await consumer.poll(500)
    return tuple(record.message for record in batch.records)


class TestCollectionProducerLifecycle:
    """M32D-P01..P05: success, zero conversion, and acquisition failures."""

    @pytest.mark.asyncio
    async def test_p01_one_converted_object_publishes_and_completes(self) -> None:
        """M32D-P01: one converted object -> CONVERTED(1), one publish, COMPLETED."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = _misp_result(
            attributes=(misp_attribute(type_="domain", value=DOMAIN_VALUE),)
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeCollectionAcquirer(lambda: result)
        )
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert outcome.published_count == 1
        assert outcome.execution_id is not None
        # The deterministic fake acquirer appends no ACQUIRED/DECODED events;
        # the full real-datasource lifecycle is asserted in P14.
        assert state.types == [
            "started",
            "converted",
            "published",
            "completed",
        ]
        converted_event = next(
            event
            for event in state.events
            if event.event_type is DatasourceExecutionEventType.CONVERTED
        )
        assert converted_event.item_count == 1
        (message,) = await _poll_messages(log)
        assert message.sequence == 0
        assert message.source_record_id == ATTRIBUTE_UUID
        assert message.semantic_format is SemanticFormatId.MISP
        assert message.source_id is SourceId.MISP

    @pytest.mark.asyncio
    async def test_p02_multiple_objects_deterministic_sequence(self) -> None:
        """M32D-P02: multiple objects keep deterministic source order/sequence."""
        state = _State()
        log = InMemoryEvidenceLog()
        first_uuid = ATTRIBUTE_UUID
        second_uuid = "77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b42"
        result = _misp_result(
            attributes=(
                misp_attribute(type_="domain", value=DOMAIN_VALUE, uuid=first_uuid),
                misp_attribute(type_="ip-src", value=IPV4_VALUE, uuid=second_uuid),
            )
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeCollectionAcquirer(lambda: result)
        )
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert outcome.published_count == 2
        messages = await _poll_messages(log)
        assert [message.sequence for message in messages] == [0, 1]
        assert [message.source_record_id for message in messages] == [
            first_uuid,
            second_uuid,
        ]

    @pytest.mark.asyncio
    async def test_p03_zero_conversion_publishes_empty_tuple(self) -> None:
        """M32D-P03: unsupported-only input -> publish(()), PUBLISHED(0), COMPLETED."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = _misp_result(
            attributes=(
                misp_attribute(
                    type_=UNSUPPORTED_ATTRIBUTE_TYPE,
                    value="a" * 64,
                    uuid=ATTRIBUTE_UUID,
                ),
            )
        )
        publisher = log.publisher()
        producer = _producer(
            state, publisher, acquirer=_FakeCollectionAcquirer(lambda: result)
        )
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert outcome.published_count == 0
        assert state.types[-3:] == ["converted", "published", "completed"]
        messages = await _poll_messages(log)
        assert messages == ()

    @pytest.mark.asyncio
    async def test_p04_typed_acquisition_failure_exact_code_no_publish(self) -> None:
        """M32D-P04: a typed acquisition error -> FAILED(exact code), no publish."""
        state = _State()
        publisher = _ProbePublisher()
        result: SemanticAcquisitionResult[MispSemanticRecord] = (
            SemanticAcquisitionResult(
                context=_semantic_context(),
                error=DatasourceStageError(
                    stage=DatasourceStage.ACQUISITION,
                    code="rate_limited",
                    retryable=True,
                ),
            )
        )
        producer = _producer(
            state, publisher, acquirer=_FakeCollectionAcquirer(lambda: result)
        )
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.FAILED
        assert outcome.error_code == "rate_limited"
        assert outcome.execution_id is not None
        assert state.types == ["started", "failed"]
        assert publisher.calls == []

    @pytest.mark.asyncio
    async def test_p05_acquisition_exception_unexpected_error_reraises(self) -> None:
        """M32D-P05: unexpected acquisition exception reraises after FAILED."""
        state = _State()

        def boom() -> SemanticAcquisitionResult[MispSemanticRecord]:
            raise RuntimeError("injected acquisition failure")

        publisher = _ProbePublisher()
        producer = _producer(state, publisher, acquirer=_FakeCollectionAcquirer(boom))
        with pytest.raises(RuntimeError, match="injected acquisition failure"):
            await producer.produce()
        assert state.types == ["started", "failed"]
        failed = state.events[-1]
        assert failed.error_code == "unexpected_error"
        assert publisher.calls == []


class TestCollectionProducerConversion:
    """M32D-P06..P07: conversion and message-construction failures."""

    @pytest.mark.asyncio
    async def test_p06_conversion_exception_conversion_failed(self) -> None:
        """M32D-P06: conversion failure -> FAILED(conversion_failed), no publish."""
        state = _State()
        result = _misp_result(
            attributes=(misp_attribute(type_="domain", value=DOMAIN_VALUE),)
        )
        registry = ToEvidenceConverterRegistry(converters=(_RaisingConverter(),))
        publisher = _ProbePublisher()
        producer = _producer(
            state,
            publisher,
            acquirer=_FakeCollectionAcquirer(lambda: result),
            registry=registry,
        )
        with pytest.raises(RuntimeError, match="injected conversion failure"):
            await producer.produce()
        assert state.types == ["started", "failed"]
        failed = state.events[-1]
        assert failed.error_code == "conversion_failed"
        assert publisher.calls == []


class _RaisingConverter(ToEvidenceConverter[MispSemanticRecord]):
    """Converter that raises a deterministic conversion failure."""

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Claim the MISP semantic format."""
        return SemanticFormatId.MISP

    def convert(
        self,
        source: MispSemanticRecord,
        context: EvidenceConversionContext,
    ) -> tuple[ConvertedEvidence, ...]:
        """Raise the injected conversion failure."""
        raise RuntimeError("injected conversion failure")


class TestCollectionProducerPublication:
    """M32D-P08..P12: publication, cancellation, and lifecycle boundaries."""

    @pytest.mark.asyncio
    async def test_p08_publisher_failure_publication_failed(self) -> None:
        """M32D-P08: publisher failure -> FAILED(publication_failed), no COMPLETED."""
        state = _State()
        result = _misp_result(
            attributes=(misp_attribute(type_="domain", value=DOMAIN_VALUE),)
        )
        publisher = _ProbePublisher(fail=True)
        producer = _producer(
            state, publisher, acquirer=_FakeCollectionAcquirer(lambda: result)
        )
        with pytest.raises(RuntimeError, match="injected publish failure"):
            await producer.produce()
        assert state.types == ["started", "converted", "failed"]
        failed = state.events[-1]
        assert failed.error_code == "publication_failed"
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_p09_cancellation_in_acquisition_propagates(self) -> None:
        """M32D-P09: cancellation during acquisition -> CANCELLED, propagate."""
        state = _State()

        def cancelled() -> SemanticAcquisitionResult[MispSemanticRecord]:
            raise asyncio.CancelledError

        publisher = _ProbePublisher()
        producer = _producer(
            state, publisher, acquirer=_FakeCollectionAcquirer(cancelled)
        )
        with pytest.raises(asyncio.CancelledError):
            await producer.produce()
        assert state.types == ["started", "cancelled"]
        assert publisher.calls == []

    @pytest.mark.asyncio
    async def test_p10_cancellation_in_publication_propagates(self) -> None:
        """M32D-P10: cancellation during publication -> CANCELLED, propagate."""
        state = _State()
        result = _misp_result(
            attributes=(misp_attribute(type_="domain", value=DOMAIN_VALUE),)
        )
        publisher = _ProbePublisher(cancelled=True)
        producer = _producer(
            state, publisher, acquirer=_FakeCollectionAcquirer(lambda: result)
        )
        with pytest.raises(asyncio.CancelledError):
            await producer.produce()
        assert state.types[-1] == "cancelled"
        # Exactly one publication call was attempted before cancellation.
        assert len(publisher.calls) == 1
        assert len(publisher.calls[0]) == 1

    @pytest.mark.asyncio
    async def test_p11_lifecycle_append_failure_after_publish_no_republish(
        self,
    ) -> None:
        """M32D-P11: PUBLISHED append failure propagates, no republish/COMPLETED."""
        state = _State()
        state.fail_on_event_type = DatasourceExecutionEventType.PUBLISHED
        result = _misp_result(
            attributes=(misp_attribute(type_="domain", value=DOMAIN_VALUE),)
        )
        publisher = _ProbePublisher()
        producer = _producer(
            state, publisher, acquirer=_FakeCollectionAcquirer(lambda: result)
        )
        with pytest.raises(RuntimeError, match="injected datasource-log append"):
            await producer.produce()
        assert len(publisher.calls) == 1
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_p12_execution_id_propagates_to_messages(self) -> None:
        """M32D-P12: the injected execution ID reaches messages and lifecycles."""
        state = _State()
        log = InMemoryEvidenceLog()
        result = _misp_result(
            attributes=(misp_attribute(type_="domain", value=DOMAIN_VALUE),)
        )
        producer = _producer(
            state,
            log.publisher(),
            acquirer=_FakeCollectionAcquirer(lambda: result),
            execution_id=_EXECUTION_ID,
        )
        outcome = await producer.produce()
        assert outcome.execution_id == _EXECUTION_ID
        assert all(event.execution_id == _EXECUTION_ID for event in state.events)
        (message,) = await _poll_messages(log)
        assert message.datasource_execution_id == _EXECUTION_ID


class TestCollectionProducerContract:
    """M32D-P13..P16: shared flattening, UoW scope, and contract shape."""

    @pytest.mark.asyncio
    async def test_p13_flattening_order_matches_converter_return_order(self) -> None:
        """M32D-P13: source order then converter return order, no sorting."""
        state = _State()
        log = InMemoryEvidenceLog()
        first_uuid = ATTRIBUTE_UUID
        second_uuid = "77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b42"
        result = _misp_result(
            attributes=(
                misp_attribute(type_="domain", value=DOMAIN_VALUE, uuid=first_uuid),
                misp_attribute(type_="ip-src", value=IPV6_VALUE, uuid=second_uuid),
            )
        )
        producer = _producer(
            state, log.publisher(), acquirer=_FakeCollectionAcquirer(lambda: result)
        )
        await producer.produce()
        messages = await _poll_messages(log)
        assert [message.source_record_id for message in messages] == [
            first_uuid,
            second_uuid,
        ]

    @pytest.mark.asyncio
    async def test_p14_no_uow_across_http_and_no_evidence_persistence(self) -> None:
        """M32D-P14: lifecycle UoWs only; no transaction open across HTTP."""
        state = _State()
        payload = misp_rest_search(
            misp_rest_event(
                attributes=(misp_attribute(type_="domain", value=DOMAIN_VALUE),)
            )
        )

        def handler(_request: httpx.Request) -> httpx.Response:
            state.active_at_http.append(state.active)
            return _json_response(payload)

        async with _client(handler) as client:
            datasource = MispDatasource(
                ProviderHttpClient(
                    client=client,
                    policy=ProviderHttpPolicy(max_retries=0, base_delay_seconds=0.01),
                    sleep=no_op_sleep,
                    jitter_fn=zero_jitter,
                ),
                api_key=FIXED_KEY,
                base_url=MISP_REST_SEARCH_ENDPOINT,
                clock=lambda: _OCCURRED_AT,
            )
            producer = _producer(
                state,
                _ProbePublisher(),
                acquirer=datasource,
            )
            outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        assert outcome.published_count == 1
        assert state.active_at_http == [0]
        assert state.active == 0
        # The real MispDatasource appends ACQUIRED/DECODED; one short
        # committed UoW per lifecycle append and nothing else: STARTED,
        # ACQUIRED, DECODED, CONVERTED, PUBLISHED, COMPLETED.
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "published",
            "completed",
        ]
        assert state.commits == 6

    def test_p15_entity_producer_contract_unchanged(self) -> None:
        """M32D-P15: the entity-triggered producer keeps the Entity argument."""
        signature = inspect.signature(DatasourceEvidenceProducer.produce)
        assert "entity" in signature.parameters
        # The entity gate lives on the acquirer contract, not on the
        # producer: the producer still starts failed executions for
        # unsupported entities through ``SemanticAcquirer.supports``.
        from agentic_threat_investigator.app.datasource_provider import (
            SemanticAcquirer,
        )

        assert "supports" in SemanticAcquirer.__abstractmethods__

    def test_p16_collection_producer_has_no_entity_or_supports(self) -> None:
        """M32D-P16: the collection producer deliberately has no Entity gate."""
        signature = inspect.signature(CollectionDatasourceEvidenceProducer.produce)
        assert "entity" not in signature.parameters
        assert not hasattr(CollectionDatasourceEvidenceProducer, "supports")
        protocol_signature = inspect.signature(CollectionSemanticAcquirer.acquire)
        params = protocol_signature.parameters
        assert "definition" in params and "recorder" in params
        assert "entity" not in params
        assert "supports" not in CollectionSemanticAcquirer.__abstractmethods__
        # The real MispDatasource satisfies the collection contract
        # structurally with no wrapper and no fake Entity.
        misp_signature = inspect.signature(MispDatasource.acquire)
        assert "entity" not in misp_signature.parameters


class TestProducerModuleSharedPipeline:
    """M32D-S: the shared post-acquisition helper is used by both producers."""

    def test_s01_shared_pipeline_is_a_module_function(self) -> None:
        """The common pipeline exists once as a private module helper."""
        assert hasattr(producer_module, "_convert_and_publish")
        producer_source = inspect.getsource(producer_module)
        # Both producer classes delegate to the same helper; the pipeline is
        # never copied inline a second time.
        assert producer_source.count("_convert_and_publish(") >= 2
