# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27E datasource-backed ThreatFox provider unit-test matrix.

Stable matrix IDs D27E-A01..A10 (provider/binding contract), D27E-E01..E10
(typed error mapping), D27E-T01..T10 (per-record representation),
D27E-L01..L06 (lifecycle through the real provider executor), and
D27E-U01..U07 (deterministic UoW transaction-boundary probes). The tests
run the real PR 27C ``ThreatFoxDatasource`` (real ``ProviderHttpClient``
over a deterministic local ``httpx.MockTransport`` — only the external
Internet endpoint is faked), the real PR 27D converter, the real PR 27B
recorder over an in-memory UnitOfWork fake, and the real PR 19B
``ProviderWorkExecutor`` with fake reader/persistence/timeline seams.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self
from uuid import UUID, uuid4

import httpx
import pytest

from agentic_threat_investigator.app.datasource_provider import (
    DatasourceEvidenceResult,
    DatasourceProvider,
)
from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    DatasourceStageError,
)
from agentic_threat_investigator.app.evidence_conversion import (
    ConversionError,
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
)
from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.extraction.models import (
    ExtractionResult,
)
from agentic_threat_investigator.app.investigation_timeline import (
    InvestigationTimelineSink,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
    ProviderWorkExecutor,
    UowEntityReader,
)
from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceResult,
    ProviderObservationPersistenceService,
)
from agentic_threat_investigator.app.providers import (
    ProviderErrorCode,
    ProviderResult,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
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
from agentic_threat_investigator.domain.investigation import (
    ProviderExecutionStatus,
    ProviderWorkItem,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)
from agentic_threat_investigator.domain.legacy_evidence import EntityRef, LegacyEvidence
from agentic_threat_investigator.infrastructure.datasources.threatfox import (
    ThreatFoxDatasource,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    ThreatFoxToEvidenceConverter,
    build_threatfox_datasource_provider,
    map_threatfox_stage_error,
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
    CANONICAL_ASYNCRAT_IP,
    CANONICAL_ASYNCRAT_IP_PORT,
    FIXED_KEY,
    asyncrat_domain_record,
    asyncrat_ip_port_record,
    threatfox_search_response,
)

pytestmark = pytest.mark.unit

_OCCURRED_AT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_INVESTIGATION_ID = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
_ENTITY_ID = UUID("11111111-2222-3333-4444-555555555555")
_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

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
_DOMAIN_SUBJECT = EntityRef(
    id=_ENTITY_ID, type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN
)


class _State:
    """Shared recorder/reader test state: durable events and transaction probes."""

    def __init__(self) -> None:
        """Start with an empty durable log and no open transaction."""
        self.events: list[DatasourceLogEvent] = []
        self.pending_append: DatasourceLogEvent | None = None
        self.commits = 0
        self.rollbacks = 0
        self.active = 0
        self.entities: dict[UUID, Entity | None] = {}

    @property
    def types(self) -> list[str]:
        """Return the durable event types in append order."""
        return [event.event_type.value for event in self.events]


class _Logs:
    """In-memory append-only datasource-log fake."""

    def __init__(self, state: _State) -> None:
        """Bind to the shared test state."""
        self.state = state

    async def append(self, event: DatasourceLogEvent) -> None:
        """Record the pending append; the UoW commit applies it."""
        self.state.pending_append = event

    def commit(self) -> None:
        """Apply the pending append to the durable in-memory log."""
        if self.state.pending_append is not None:
            self.state.events.append(self.state.pending_append)
            self.state.pending_append = None


class _Entities:
    """In-memory visible-entity lookup for the executor's short reader UoW."""

    def __init__(self, state: _State) -> None:
        """Bind to the shared test state."""
        self.state = state

    async def get_by_id(self, entity_id: UUID) -> Entity | None:
        """Return the configured visible entity or ``None``."""
        return self.state.entities.get(entity_id)


class _Uow(UnitOfWork):
    """Deterministic in-memory UnitOfWork fake with transaction probes.

    ``__aenter__`` fails the test when a previous transaction is still open
    — the deterministic probe proving no UoW is ever held across HTTP,
    conversion, extraction, or persistence work.
    """

    def __init__(self, state: _State) -> None:
        """Bind the fake UoW to the shared state."""
        self.state = state
        self._logs = _Logs(state)
        self._entities = _Entities(state)
        self.datasource_logs = self._logs  # type: ignore[assignment]
        self.entities = self._entities  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        """Support the test aenter behavior."""
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


def _adapter(
    state: _State,
    client: httpx.AsyncClient,
    *,
    registry: ToEvidenceConverterRegistry | None = None,
    clock: Callable[[], datetime] | None = None,
) -> DatasourceProvider[ThreatFoxRecord]:
    """Build the migrated datasource-backed provider over the real stack."""
    effective_clock: Callable[[], datetime] = clock or (lambda: _OCCURRED_AT)
    return build_threatfox_datasource_provider(
        definition=_DEFINITION,
        datasource=_datasource(client, clock=effective_clock),
        uow_factory=_uow_factory(state),
        clock=effective_clock,
        registry=registry,
    )


def _persisted_result(evidence: LegacyEvidence) -> ProviderObservationPersistenceResult:
    """Build one deterministic committed observation result."""
    recorded = evidence.model_copy(update={"id": evidence.id or uuid4()})
    return ProviderObservationPersistenceResult(
        evidence=recorded,
        entities=(),
        relationships=(),
        observations=(),
    )


class _ProbePersistenceService(ProviderObservationPersistenceService):
    """Persistence probe recording calls and asserting no UoW is open.

    Also injects per-call failures (including cancellation) for the
    deterministic failure matrix.
    """

    def __init__(
        self,
        state: _State,
        *,
        fail_on_call: int | None = None,
        cancelled_on_call: int | None = None,
    ) -> None:
        """Initialize the probe with the shared state and optional failure seams."""
        super().__init__(uow_factory=lambda: _Uow(state))
        self.state = state
        self.calls: list[tuple[LegacyEvidence, ExtractionResult]] = []
        self._fail_on_call = fail_on_call
        self._cancelled_on_call = cancelled_on_call

    async def persist(
        self,
        evidence: LegacyEvidence,
        extraction: ExtractionResult,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> ProviderObservationPersistenceResult:
        """Record the call, assert transaction isolation, and return or fail."""
        # No lifecycle transaction may be open while an observation persists.
        assert self.state.active == 0
        assert evidence.id is not None
        self.calls.append((evidence, extraction))
        call_number = len(self.calls)
        if self._cancelled_on_call == call_number:
            raise asyncio.CancelledError
        if self._fail_on_call == call_number:
            raise RuntimeError("simulated observation persistence failure")
        return _persisted_result(evidence)


class _ProbeTimelineSink(InvestigationTimelineSink):
    """Append-only timeline fake recording the emitted event types."""

    def __init__(self) -> None:
        """Start with an empty event log."""
        self.events: list[InvestigationTimelineEvent] = []

    async def append(self, event: InvestigationTimelineEvent) -> None:
        """Record one timeline event."""
        self.events.append(event)


def _executor(
    state: _State,
    provider: DatasourceProvider[ThreatFoxRecord],
    *,
    persistence: _ProbePersistenceService | None = None,
    timeline: _ProbeTimelineSink | None = None,
    entity: Entity | None = _DOMAIN_ENTITY,
) -> ProviderWorkExecutor:
    """Compose the real executor over the fake reader/persistence/timeline."""
    state.entities = {_ENTITY_ID: entity}
    return ProviderWorkExecutor(
        entity_reader=UowEntityReader(_uow_factory(state)),
        provider_registry={SourceId.THREATFOX: provider},
        extractor=extract,
        persistence_service=persistence or _ProbePersistenceService(state),
        timeline_service=timeline,
        context=ProviderExecutionContext(
            investigation_id=_INVESTIGATION_ID, clock=lambda: _OCCURRED_AT
        ),
    )


def _work_item() -> ProviderWorkItem:
    """Return the fixed ThreatFox work item for the canonical entity."""
    return ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=_ENTITY_ID, depth=0)


class TestDatasourceProviderBinding:
    """D27E-A01..A10: provider identity, support, and binding contract."""

    @pytest.mark.asyncio
    async def test_a01_provider_id_exact_threatfox_urn(self) -> None:
        """D27E-A01: the adapter claims the exact ThreatFox source URN."""
        state = _State()
        async with _client(lambda _: _json_response({})) as client:
            provider = _adapter(state, client)
            assert provider.id == SourceId.THREATFOX.value

    @pytest.mark.asyncio
    async def test_a02_a03_support_domain_and_ip_legacy_compatible(self) -> None:
        """D27E-A02/A03: domain and IP support match the legacy provider."""
        state = _State()
        async with _client(lambda _: _json_response({})) as client:
            provider = _adapter(state, client)
            assert provider.supports(Entity(type=EntityType.DOMAIN, value="a.test"))
            assert provider.supports(
                Entity(type=EntityType.IP_ADDRESS, value=CANONICAL_ASYNCRAT_IP)
            )

    @pytest.mark.asyncio
    async def test_a04_unsupported_type_no_io(self) -> None:
        """D27E-A04: an unsupported entity type returns False with no I/O."""
        state = _State()

        def exploding(_: httpx.Request) -> httpx.Response:
            """Fail the test if the transport is ever reached."""
            raise AssertionError("no I/O is allowed for an unsupported type")

        async with _client(exploding) as client:
            provider = _adapter(state, client)
            for entity_type in (
                EntityType.URL,
                EntityType.MALWARE,
                EntityType.ATTACK_TECHNIQUE,
            ):
                entity = Entity(type=entity_type, value="https://example.com/")
                assert provider.supports(entity) is False
                result = await provider.investigate(_INVESTIGATION_ID, entity)
                assert len(result.errors) == 1
                assert result.errors[0].code is ProviderErrorCode.UNSUPPORTED_INDICATOR
            assert state.events == []

    @pytest.mark.asyncio
    async def test_a05_malformed_value_no_io(self) -> None:
        """D27E-A05: a malformed domain value returns UNSUPPORTED with no I/O."""
        state = _State()

        def exploding(_: httpx.Request) -> httpx.Response:
            """Fail the test if the transport is ever reached."""
            raise AssertionError("no I/O is allowed for a malformed value")

        async with _client(exploding) as client:
            provider = _adapter(state, client)
            malformed = Entity(type=EntityType.DOMAIN, value="broken..name")
            result = await provider.investigate(_INVESTIGATION_ID, malformed)
            assert len(result.errors) == 1
            assert result.errors[0].code is ProviderErrorCode.UNSUPPORTED_INDICATOR
            assert state.events == []

    def test_a06_a07_a08_a09_a10_binding_and_semantic_selection(self) -> None:
        """D27E-A06..A10: exact investigation, subject, definition, converter.

        A successful acquisition converts through the semantic-format-selected
        converter into per-record LegacyEvidence bound to the exact persisted
        target; an empty acquisition is an empty successful result.
        """
        state = _State()
        payload = threatfox_search_response(
            asyncrat_domain_record(),
            asyncrat_domain_record(id="864299", last_seen=None),
        )

        async def scenario() -> None:
            """Run the full binding scenario once."""
            async with _client(lambda _: _json_response(payload)) as client:
                provider = _adapter(state, client)
                result = await provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)

            assert isinstance(result, DatasourceEvidenceResult)
            assert result.provider == SourceId.THREATFOX.value
            # A08: the configured definition owns the acquisition context.
            assert provider.definition == _DEFINITION
            assert len(result.evidence) == 2
            for item in result.evidence:
                # A06/A07: exact Investigation and exact persisted subject.
                assert item.investigation_id == _INVESTIGATION_ID
                assert item.subject == _DOMAIN_SUBJECT
                assert item.subject.id == _ENTITY_ID
            assert [item.source_record_id for item in result.evidence] == [
                "864201",
                "864299",
            ]
            assert state.types == ["started", "acquired", "decoded", "converted"]

        asyncio.run(scenario())

        # A10: a valid no-result succeeds as an empty result.
        state = _State()

        async def empty_scenario() -> ProviderResult:
            """Run the empty-result scenario once."""
            async with _client(
                lambda _: _json_response({"query_status": "no_result"})
            ) as client:
                provider = _adapter(state, client)
                return await provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)

        result = asyncio.run(empty_scenario())
        assert isinstance(result, DatasourceEvidenceResult)
        assert result.evidence == ()
        assert state.types == ["started", "acquired", "decoded", "converted"]

    @pytest.mark.asyncio
    async def test_a09_converter_selected_by_semantic_format_only(self) -> None:
        """D27E-A09: registry selection keys on semantic format, never source.

        A registry that owns only an unrelated semantic format fails closed
        with the typed unknown-format error and no CONVERTED stage, proving
        the adapter never falls back to provider/source-based conversion.
        """
        state = _State()

        class _UnrelatedConverter(ToEvidenceConverter[Any]):
            """Converter claiming an unrelated semantic format."""

            @property
            def semantic_format(self) -> SemanticFormatId:
                """Claim the STIX 2.1 format."""
                return SemanticFormatId.STIX_21

            def convert(
                self,
                source: Any,
                context: EvidenceConversionContext,
            ) -> tuple[ConvertedEvidence, ...]:
                """Never invoked."""
                raise AssertionError("unrelated converter must never run")

        registry = ToEvidenceConverterRegistry(converters=(_UnrelatedConverter(),))
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            provider = _adapter(state, client, registry=registry)
            with pytest.raises(KeyError):
                await provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)
        assert state.types == ["started", "acquired", "decoded", "failed"]
        assert state.events[-1].error_code == "conversion_failed"
        assert "converted" not in state.types


class TestDatasourceProviderErrorMapping:
    """D27E-E01..E10: typed failure classification with no message parsing."""

    @pytest.mark.parametrize(
        ("handler", "expected_code", "lifecycle_code"),
        [
            (
                lambda _request: (_ for _ in ()).throw(
                    httpx.ConnectTimeout("connect timed out")
                ),
                ProviderErrorCode.TIMEOUT,
                "timeout",
            ),
            (
                lambda _request: httpx.Response(
                    429,
                    headers={"Content-Type": "application/json", "Retry-After": "30"},
                ),
                ProviderErrorCode.RATE_LIMITED,
                "rate_limited",
            ),
            (
                lambda _request: httpx.Response(
                    401, headers={"Content-Type": "application/json"}
                ),
                ProviderErrorCode.AUTHENTICATION_FAILED,
                "authentication_failed",
            ),
            (
                lambda _request: httpx.Response(
                    403, headers={"Content-Type": "application/json"}
                ),
                ProviderErrorCode.FORBIDDEN,
                "forbidden",
            ),
            (
                lambda _request: httpx.Response(
                    200,
                    content=b"not json at all",
                    headers={"Content-Type": "application/json"},
                ),
                ProviderErrorCode.INVALID_RESPONSE,
                "serialization_failed",
            ),
            (
                lambda _request: _json_response({"query_status": "confusing"}),
                ProviderErrorCode.INVALID_RESPONSE,
                "semantic_validation_failed",
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_e01_e06_typed_failures_map_deterministically(
        self,
        handler: Callable[[httpx.Request], Any],
        expected_code: ProviderErrorCode,
        lifecycle_code: str,
    ) -> None:
        """D27E-E01..E06: typed acquisition failures map by code, never text."""
        state = _State()
        async with _client(handler) as client:
            provider = _adapter(state, client)
            result = await provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)

        assert not isinstance(result, DatasourceEvidenceResult)
        assert result.evidence == ()
        assert len(result.errors) == 1
        error = result.errors[0]
        assert error.provider == SourceId.THREATFOX.value
        assert error.code is expected_code
        assert error.retryable is expected_code.retryable
        if expected_code is ProviderErrorCode.RATE_LIMITED:
            assert error.retry_after_seconds == 30
        # The FAILED lifecycle carries the bounded stage code; the fixed
        # message text is not persisted. Stage events before the failure
        # (ACQUIRED for serialization/semantic failures, none for transport
        # failures) are legal lifecycle omissions.
        assert state.types[0] == "started"
        assert state.types[-1] == "failed"
        assert state.events[-1].error_code == lifecycle_code
        assert "completed" not in state.types
        assert "timed out" not in str(state.events)

    @pytest.mark.asyncio
    async def test_e07_conversion_failure_bounded_mapping(self) -> None:
        """D27E-E07: conversion failure raises and records conversion_failed."""
        state = _State()

        class _FailingConverter(ToEvidenceConverter[Any]):
            """Deterministic conversion-failure converter."""

            @property
            def semantic_format(self) -> SemanticFormatId:
                """Claim the ThreatFox semantic format."""
                return SemanticFormatId.THREATFOX

            def convert(
                self,
                source: Any,
                context: EvidenceConversionContext,
            ) -> tuple[ConvertedEvidence, ...]:
                """Raise the typed deterministic conversion violation."""
                raise ConversionError("deterministic local conversion failure")

        registry = ToEvidenceConverterRegistry(converters=(_FailingConverter(),))
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            provider = _adapter(state, client, registry=registry)
            with pytest.raises(ConversionError):
                await provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)

        assert state.types == ["started", "acquired", "decoded", "failed"]
        assert state.events[-1].error_code == "conversion_failed"
        assert "converted" not in state.types
        assert "deterministic local" not in str(state.events)

    @pytest.mark.asyncio
    async def test_e08_message_changes_do_not_affect_classification(self) -> None:
        """D27E-E08: different raw messages keep one deterministic code."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            """Return a 401 whose unrelated body differs from the fixture."""
            return httpx.Response(
                401,
                content=b'{"detail": "totally different wording"}',
                headers={"Content-Type": "application/json"},
            )

        async with _client(handler) as client:
            provider = _adapter(state, client)
            result = await provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)
        assert result.errors[0].code is ProviderErrorCode.AUTHENTICATION_FAILED
        assert (
            result.errors[0].message
            == map_threatfox_stage_error(
                DatasourceStageError(
                    stage=DatasourceStage.ACQUISITION,
                    code="authentication_failed",
                    retryable=False,
                )
            )
            .errors[0]
            .message
        )
        assert "wording" not in result.errors[0].message

    @pytest.mark.asyncio
    async def test_e09_secret_bearing_exception_never_persists(self) -> None:
        """D27E-E09: a secret-bearing exception leaves no secret in the log."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            """Raise an exception whose text embeds the Auth-Key."""
            raise RuntimeError(f"boom {FIXED_KEY} secret detail")

        async with _client(handler) as client:
            provider = _adapter(state, client)
            with pytest.raises(RuntimeError):
                await provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)
        assert state.types == ["started", "failed"]
        assert FIXED_KEY not in str(state.events)
        assert "boom" not in str(state.events)

    @pytest.mark.asyncio
    async def test_e10_cancellation_propagates_as_cancelled(self) -> None:
        """D27E-E10: cancellation stays CANCELLED and propagates."""
        state = _State()
        entered = asyncio.Event()
        never = asyncio.Event()

        async def handler(_: httpx.Request) -> httpx.Response:
            """Block until cancelled."""
            entered.set()
            await never.wait()
            return _json_response({})

        async with _client(handler) as client:
            provider = _adapter(state, client)
            task = asyncio.create_task(
                provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)
            )
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert state.types == ["started", "cancelled"]
        assert all(event.error_code is None for event in state.events)


class TestDatasourceProviderRepresentation:
    """D27E-T01..T10: per-record LegacyEvidence provenance through the adapter."""

    @pytest.mark.asyncio
    async def test_t01_t02_t03_one_and_two_records_in_order(self) -> None:
        """D27E-T01/T02/T03: one/two records yield one/two LegacyEvidence in order."""
        state = _State()
        payload = threatfox_search_response(
            asyncrat_domain_record(),
            asyncrat_domain_record(id="864299", last_seen=None),
        )
        async with _client(lambda _: _json_response(payload)) as client:
            provider = _adapter(state, client)
            result = await provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)
        assert isinstance(result, DatasourceEvidenceResult)
        assert [item.source_record_id for item in result.evidence] == [
            "864201",
            "864299",
        ]

    @pytest.mark.asyncio
    async def test_t04_t05_t06_t07_t08_t09_t10_exact_provenance(self) -> None:
        """D27E-T04..T10: exact source_record_id, timestamps, and facts."""
        state = _State()
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            provider = _adapter(state, client)
            result = await provider.investigate(_INVESTIGATION_ID, _DOMAIN_ENTITY)
        assert isinstance(result, DatasourceEvidenceResult)
        (item,) = result.evidence
        assert item.type is EvidenceType.THREAT_INTELLIGENCE
        assert item.investigation_id == _INVESTIGATION_ID
        assert item.subject == _DOMAIN_SUBJECT
        assert item.source == SourceId.THREATFOX.value
        # T04: exact upstream source record identity.
        assert item.source_record_id == "864201"
        assert item.source_url == _ENDPOINT
        # T06: exact acquisition retrieval time.
        assert item.retrieved_at == _OCCURRED_AT
        # T05: observed_at is the record's last seen.
        assert item.observed_at == datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)
        # T07/T08: exactly one match fact per LegacyEvidence and no raw payload.
        matches = item.facts["matches"]
        assert len(matches) == 1
        assert matches[0]["threatfox_id"] == "864201"
        assert item.raw_payload is None
        # T09: source confidence is a source fact only.
        assert matches[0]["confidence_level"] == 100
        # T10: no analytical inference is synthesized.
        serialized = str(item.facts)
        for fragment in ("verdict", "risk", "assessment", "confidence_weight"):
            assert fragment not in serialized

    @pytest.mark.asyncio
    async def test_t02_ip_record_per_record_evidence(self) -> None:
        """D27E-T02: an ip:port record yields one per-record IP LegacyEvidence."""
        state = _State()
        ip_entity = Entity(
            id=_ENTITY_ID, type=EntityType.IP_ADDRESS, value=CANONICAL_ASYNCRAT_IP
        )
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_ip_port_record())
            )
        ) as client:
            provider = _adapter(state, client)
            result = await provider.investigate(_INVESTIGATION_ID, ip_entity)
        assert isinstance(result, DatasourceEvidenceResult)
        (item,) = result.evidence
        assert item.subject.type is EntityType.IP_ADDRESS
        assert item.subject.value == CANONICAL_ASYNCRAT_IP
        assert item.subject.id == _ENTITY_ID
        assert item.facts["matches"][0]["ioc"] == CANONICAL_ASYNCRAT_IP_PORT


def _no_timeline(state: _State) -> _ProbeTimelineSink:
    """Build a timeline sink recording nothing of interest."""
    del state
    return _ProbeTimelineSink()


class _ProbeConverter(ThreatFoxToEvidenceConverter):
    """The real converter wrapped with a no-open-UoW probe."""

    def __init__(self, state: _State) -> None:
        """Bind to the shared probe state."""
        self.state = state

    def convert(
        self, source: ThreatFoxRecord, context: EvidenceConversionContext
    ) -> tuple[ConvertedEvidence, ...]:
        """Assert conversion runs with no transaction open, then delegate."""
        assert self.state.active == 0
        return super().convert(source, context)


class TestDatasourceProviderLifecycle:
    """D27E-L01..L06: terminal ownership through the real provider executor."""

    @pytest.mark.asyncio
    async def test_l01_success_full_lifecycle(self) -> None:
        """D27E-L01: one full lifecycle with COMPLETED after persistence."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            """Fail if any lifecycle or observation UoW is open over HTTP."""
            assert state.active == 0
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        registry = ToEvidenceConverterRegistry(converters=(_ProbeConverter(state),))
        async with _client(handler) as client:
            provider = _adapter(state, client, registry=registry)
            executor = _executor(state, provider)
            outcome = await executor.execute(_work_item())

        assert outcome.status is ProviderExecutionStatus.SUCCEEDED
        assert len(outcome.evidence_ids) == 1
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "completed",
        ]
        # Exactly the lifecycle appends committed (plus the executor's short
        # target-read transaction); no per-LegacyEvidence lifecycle transaction
        # exists.
        assert state.commits == len(state.events) + 1

    @pytest.mark.asyncio
    async def test_l02_three_evidence_one_converted_count(self) -> None:
        """D27E-L02: three LegacyEvidence report one CONVERTED(count=3)."""
        state = _State()
        payload = threatfox_search_response(
            asyncrat_domain_record(),
            asyncrat_domain_record(id="864299", last_seen=None),
        )
        async with _client(lambda _: _json_response(payload)) as client:
            provider = _adapter(state, client)
            executor = _executor(state, provider)
            outcome = await executor.execute(_work_item())

        assert outcome.status is ProviderExecutionStatus.SUCCEEDED
        assert len(outcome.evidence_ids) == 2
        converted = [
            event for event in state.events if event.event_type.value == "converted"
        ]
        assert len(converted) == 1
        assert converted[0].item_count == 2
        assert state.types.count("completed") == 1

    @pytest.mark.asyncio
    async def test_l03_no_result_converted_zero_then_completed(self) -> None:
        """D27E-L03: a valid no-result reports CONVERTED(0) and COMPLETED."""
        state = _State()
        async with _client(
            lambda _: _json_response({"query_status": "no_result"})
        ) as client:
            provider = _adapter(state, client)
            executor = _executor(state, provider)
            outcome = await executor.execute(_work_item())

        assert outcome.status is ProviderExecutionStatus.SUCCEEDED
        assert outcome.evidence_ids == ()
        converted = [
            event for event in state.events if event.event_type.value == "converted"
        ]
        assert converted[0].item_count == 0
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "completed",
        ]

    @pytest.mark.asyncio
    async def test_l04_conversion_failure_failed_no_converted(self) -> None:
        """D27E-L04: conversion failure is FAILED without CONVERTED."""
        state = _State()
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            failing_registry = ToEvidenceConverterRegistry(
                converters=(_FailingConversionConverter(),)
            )
            provider = _adapter(state, client, registry=failing_registry)
            executor = _executor(state, provider)
            outcome = await executor.execute(_work_item())

        assert outcome.status is ProviderExecutionStatus.FAILED
        assert state.types == ["started", "acquired", "decoded", "failed"]
        assert state.events[-1].error_code == "conversion_failed"
        assert "converted" not in state.types
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_l05_persistence_failure_failed_no_completed(self) -> None:
        """D27E-L05: persistence failure is FAILED and never COMPLETED.

        The first LegacyEvidence commits, the second persistence call fails, the
        datasource execution is FAILED with the bounded code, and the
        outcome retains the first committed ID.
        """
        state = _State()
        payload = threatfox_search_response(
            asyncrat_domain_record(),
            asyncrat_domain_record(id="864299", last_seen=None),
        )
        persistence = _ProbePersistenceService(state, fail_on_call=2)
        async with _client(lambda _: _json_response(payload)) as client:
            provider = _adapter(state, client)
            executor = _executor(state, provider, persistence=persistence)
            outcome = await executor.execute(_work_item())

        assert outcome.status is ProviderExecutionStatus.FAILED
        assert len(persistence.calls) == 2
        assert len(outcome.evidence_ids) == 1
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "failed",
        ]
        assert state.events[-1].error_code == "persistence_failed"
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_l06_cancellation_cancelled_only_and_propagates(self) -> None:
        """D27E-L06: cancellation during persistence stays CANCELLED.

        The cancelled persistence call leaves the datasource execution
        CANCELLED (best effort); the CancelledError propagates and the
        execution is never FAILED or COMPLETED.
        """
        state = _State()
        payload = threatfox_search_response(
            asyncrat_domain_record(),
            asyncrat_domain_record(id="864299", last_seen=None),
        )
        persistence = _ProbePersistenceService(state, cancelled_on_call=1)
        async with _client(lambda _: _json_response(payload)) as client:
            provider = _adapter(state, client)
            executor = _executor(state, provider, persistence=persistence)
            with pytest.raises(asyncio.CancelledError):
                await executor.execute(_work_item())

        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "cancelled",
        ]
        assert all(event.error_code is None for event in state.events)
        assert "failed" not in state.types
        assert "completed" not in state.types


class _FailingConversionConverter(ToEvidenceConverter[Any]):
    """Deterministic conversion-failure converter."""

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Claim the ThreatFox semantic format."""
        return SemanticFormatId.THREATFOX

    def convert(
        self,
        source: Any,
        context: EvidenceConversionContext,
    ) -> tuple[ConvertedEvidence, ...]:
        """Raise the typed deterministic conversion violation."""
        raise ConversionError("deterministic local conversion failure")


class TestDatasourceProviderTransactionBoundaries:
    """D27E-U01..U07: deterministic UoW probes (never timing)."""

    @pytest.mark.asyncio
    async def test_u01_u02_u03_u04_no_uow_across_read_http_convert_extract(
        self,
    ) -> None:
        """D27E-U01..U04: no UoW is open across any of the four boundaries."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            """Fail if the target-read or lifecycle UoW leaks over HTTP."""
            assert state.active == 0
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        registry = ToEvidenceConverterRegistry(converters=(_ProbeConverter(state),))
        async with _client(handler) as client:
            provider = _adapter(state, client, registry=registry)

            class _ExtractionProbe:
                """Record extraction calls and assert isolation."""

                def __init__(self) -> None:
                    """Start empty."""
                    self.calls = 0

                def __call__(self, evidence: LegacyEvidence) -> ExtractionResult:
                    """Assert no UoW is open during deterministic extraction."""
                    assert state.active == 0
                    self.calls += 1
                    return extract(evidence)

            extractor = _ExtractionProbe()
            state.entities = {_ENTITY_ID: _DOMAIN_ENTITY}
            executor = ProviderWorkExecutor(
                entity_reader=UowEntityReader(_uow_factory(state)),
                provider_registry={SourceId.THREATFOX: provider},
                extractor=extractor,
                persistence_service=_ProbePersistenceService(state),
                timeline_service=_ProbeTimelineSink(),
                context=ProviderExecutionContext(
                    investigation_id=_INVESTIGATION_ID, clock=lambda: _OCCURRED_AT
                ),
            )
            outcome = await executor.execute(_work_item())

        assert outcome.status is ProviderExecutionStatus.SUCCEEDED
        assert extractor.calls == 1
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "completed",
        ]

    @pytest.mark.asyncio
    async def test_u05_u06_each_evidence_observed_in_distinct_persistence_calls(
        self,
    ) -> None:
        """D27E-U05/U06: per-LegacyEvidence atomic persistence in provider order.

        Each LegacyEvidence is persisted through a distinct call with no lifecycle
        UoW open, in provider-return order, and the lifecycle transaction
        count stays at exactly the lifecycle appends (no multiplication).
        """
        state = _State()
        payload = threatfox_search_response(
            asyncrat_domain_record(),
            asyncrat_domain_record(id="864299", last_seen=None),
        )
        persistence = _ProbePersistenceService(state)
        async with _client(lambda _: _json_response(payload)) as client:
            provider = _adapter(state, client)
            executor = _executor(state, provider, persistence=persistence)
            outcome = await executor.execute(_work_item())

        assert outcome.status is ProviderExecutionStatus.SUCCEEDED
        assert [call[0].id for call in persistence.calls] == list(outcome.evidence_ids)
        assert len(persistence.calls) == 2
        assert outcome.evidence_ids[0] != outcome.evidence_ids[1]
        # U07: lifecycle events are execution-level, never per LegacyEvidence.
        assert state.types.count("converted") == 1
        assert state.types.count("completed") == 1
        assert state.commits == len(state.events) + 1

    @pytest.mark.asyncio
    async def test_u07_binding_failure_fails_lifecycle_not_per_evidence(
        self,
    ) -> None:
        """D27E-U07/P04: source binding failure fails closed.

        PR 28A: conversion is global, so a converter can no longer mis-bind
        an Investigation (the adapter always binds the executor's own
        investigation and subject). The remaining binding surface is the
        emitted global Evidence's ``source``: a converter whose Evidence
        claims a different source than the selected work item is rejected
        before any persistence, the datasource execution is FAILED with the
        bounded binding code, and no observation is ever written.
        """
        state = _State()

        class _ForeignSourceConverter(ToEvidenceConverter[Any]):
            """Converter emitting Evidence whose source mismatches the work item."""

            @property
            def semantic_format(self) -> SemanticFormatId:
                """Claim the ThreatFox semantic format."""
                return SemanticFormatId.THREATFOX

            def convert(
                self,
                source: Any,
                context: EvidenceConversionContext,
            ) -> tuple[ConvertedEvidence, ...]:
                """Return ConvertedEvidence claiming the wrong source URN."""
                del source
                evidence_id = evidence_id_for_source_record(
                    SemanticFormatId.THREATFOX,
                    context.semantic_source.source_id,
                    "864201",
                )
                evidence = Evidence(
                    id=evidence_id,
                    type=EvidenceType.THREAT_INTELLIGENCE,
                    source=SourceId.URLHAUS.value,
                    source_record_id="864201",
                )
                return (
                    ConvertedEvidence(
                        evidence=evidence,
                        observation=EvidenceObservationCandidate(
                            evidence_id=evidence_id,
                            source_url=context.semantic_source.source_reference,
                            retrieved_at=context.semantic_source.retrieved_at,
                            facts={"matches": []},
                            raw_payload=None,
                        ),
                    ),
                )

        persistence = _ProbePersistenceService(state)
        registry = ToEvidenceConverterRegistry(converters=(_ForeignSourceConverter(),))
        async with _client(
            lambda _: _json_response(
                threatfox_search_response(asyncrat_domain_record())
            )
        ) as client:
            provider = _adapter(state, client, registry=registry)
            executor = _executor(state, provider, persistence=persistence)
            outcome = await executor.execute(_work_item())

        assert outcome.status is ProviderExecutionStatus.FAILED
        assert persistence.calls == []
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "failed",
        ]
        assert state.events[-1].error_code == "provider_binding_failed"
        assert "completed" not in state.types
