# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27C ThreatFox acquisition-to-semantic reference-path tests.

Matrix IDs D27C-X01..X09 pin the production acquirer + PR 27B recorder
coordination over a fake in-memory UnitOfWork with a real
``ProviderHttpClient`` and a deterministic local ``httpx.MockTransport``
(sleep-free, zero-jitter): full success/failure/cancellation lifecycles,
stage ordering, one execution identity, short committed transactions with
no UoW held across HTTP or semantic parsing, no CONVERTED event, and no
Evidence/credential leakage. Only the external Internet endpoint is faked.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self

import httpx
import pytest

from agentic_threat_investigator.app.datasource_semantics import DatasourceStage
from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceLogEvent,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.entities import (
    Entity,
    EntityType,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox import (
    ThreatFoxDatasource,
    acquire_threatfox_execution,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
    parse_threatfox_response,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from tests.support.provider_http import no_op_sleep, zero_jitter
from tests.support.threatfox_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    CANONICAL_ASYNCRAT_IP,
    CANONICAL_ASYNCRAT_MALWARE,
    FIXED_KEY,
    asyncrat_domain_record,
    threatfox_search_response,
)

_FIXED_TS = datetime(2026, 5, 1, 10, 0, 0, tzinfo=UTC)
_EPOCH = datetime(2026, 2, 1, 12, 30, 0, tzinfo=UTC)

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)
_DOMAIN_ENTITY = Entity(type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN)
_IP_ENTITY = Entity(type=EntityType.IP_ADDRESS, value=CANONICAL_ASYNCRAT_IP)


class _Logs:
    """In-memory append-only datasource-log fake."""

    def __init__(self, state: "_State") -> None:
        """Bind to the shared test state."""
        self.state = state

    async def append(self, event: DatasourceLogEvent) -> None:
        """Record the pending append; the UoW commit applies it."""
        self.state.pending_append = event


class _State:
    """Shared datasource-test state: durable events and commit accounting."""

    def __init__(self) -> None:
        """Start with an empty durable log."""
        self.events: list[DatasourceLogEvent] = []
        self.pending_append: DatasourceLogEvent | None = None
        self.commits = 0
        self.active = 0
        self.active_at_http: list[int] = []

    @property
    def types(self) -> list[str]:
        """Return the durable event types in append order."""
        return [event.event_type.value for event in self.events]

    @property
    def execution_ids(self) -> set[str]:
        """Return the durable execution identities."""
        return {str(event.execution_id) for event in self.events}

    @property
    def datasource_ids(self) -> set[str]:
        """Return the durable datasource identities."""
        return {event.datasource_id.value for event in self.events}


class _Uow(UnitOfWork):
    """In-memory UnitOfWork fake that tracks open transactions."""

    def __init__(self, state: _State) -> None:
        """Bind the fake UoW to the shared test state."""
        self.state = state
        self._logs = _Logs(state)
        self.datasource_logs = self._logs  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        """Reject nested/overlapping transactions and mark the boundary active."""
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
        """Apply the pending append and count the short committed transaction."""
        if self.state.pending_append is not None:
            self.state.events.append(self.state.pending_append)
            self.state.pending_append = None
        self.state.commits += 1

    async def rollback(self) -> None:
        """Discard the pending append."""
        self.state.pending_append = None


def _factory(state: _State) -> Callable[[], UnitOfWork]:
    """Return a recorder UoW factory bound to the shared state."""
    return lambda: _Uow(state)


def _json_bytes(payload: object) -> bytes:
    """Serialize a payload exactly as httpx would for a JSON response body."""
    return json.dumps(payload).encode("utf-8")


def _json_response(payload: object, status: int = 200) -> httpx.Response:
    """Build a deterministic JSON response with an explicit body length."""
    return httpx.Response(
        status,
        content=_json_bytes(payload),
        headers={"Content-Type": "application/json"},
    )


def _client(
    handler: Callable[[httpx.Request], Any],
) -> httpx.AsyncClient:
    """Build a deterministic mock-transport client."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _datasource(
    client: httpx.AsyncClient,
    *,
    max_retries: int = 0,
    auth_key: str = FIXED_KEY,
    clock: Callable[[], datetime] | None = None,
) -> ThreatFoxDatasource:
    """Build the acquirer with the deterministic test key and policy."""
    return ThreatFoxDatasource(
        ProviderHttpClient(
            client=client,
            policy=ProviderHttpPolicy(max_retries=max_retries, base_delay_seconds=0.01),
            sleep=no_op_sleep,
            jitter_fn=zero_jitter,
        ),
        auth_key=auth_key,
        clock=clock if clock is not None else (lambda: _FIXED_TS),
    )


class TestSuccessLifecycle:
    """D27C-X01/X05/X07/X08/X09: the coordinated success path."""

    @pytest.mark.asyncio
    async def test_x01_valid_response_full_lifecycle(self) -> None:
        """D27C-X01: STARTED, ACQUIRED, DECODED, COMPLETED under one execution."""
        body = _json_bytes(threatfox_search_response(asyncrat_domain_record()))
        state = _State()
        payload = json.loads(body.decode("utf-8"))

        def handler(_: httpx.Request) -> httpx.Response:
            state.active_at_http.append(state.active)
            return _json_response(payload)

        async with _client(handler) as client:
            result = await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert result.error is None
        assert result.context.datasource_id == _DEFINITION.datasource_id
        assert result.context.source_id is SourceId.THREATFOX
        assert result.context.semantic_format is SemanticFormatId.THREATFOX
        assert result.context.retrieved_at == _FIXED_TS
        assert (
            result.context.source_reference == "https://threatfox-api.abuse.ch/api/v1/"
        )
        assert len(result.objects) == 1
        assert result.objects[0].id == "864201"

        assert state.types == ["started", "acquired", "decoded", "completed"]
        assert len(state.execution_ids) == 1
        assert state.datasource_ids == {"threatfox-live"}
        # ACQUIRED carries the exact acquired byte count.
        acquired = state.events[1]
        assert acquired.byte_count == len(body)
        # DECODED carries the exact unique validated record count.
        assert state.events[2].item_count == 1
        # Every append committed in its own short transaction.
        assert state.commits == 4
        assert state.active == 0
        # Acquisition I/O ran with no database transaction open.
        assert state.active_at_http == [0]

    @pytest.mark.asyncio
    async def test_x05_no_result_decoded_zero_then_completed(self) -> None:
        """D27C-X05: a valid no-result is DECODED item_count=0 then COMPLETED."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            return _json_response({"query_status": "no_result"})

        async with _client(handler) as client:
            result = await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert result.error is None
        assert result.objects == ()
        assert state.types == ["started", "acquired", "decoded", "completed"]
        assert state.events[2].item_count == 0

    @pytest.mark.asyncio
    async def test_x07_two_executions_have_distinct_execution_ids(self) -> None:
        """D27C-X07: separate executions never share an execution ID."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        async with _client(handler) as client:
            datasource = _datasource(client)
            await acquire_threatfox_execution(
                datasource=datasource,
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )
            await acquire_threatfox_execution(
                datasource=datasource,
                definition=_DEFINITION,
                entity=_IP_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert len(state.execution_ids) == 2
        started_events = [
            event for event in state.events if event.event_type.value == "started"
        ]
        assert len(started_events) == 2
        assert started_events[0].execution_id != started_events[1].execution_id

    @pytest.mark.asyncio
    async def test_x08_semantic_parse_holds_no_uow_open(self) -> None:
        """D27C-X08: no UoW is open across HTTP I/O or the semantic parse.

        The HTTP handler observes ``active == 0`` during acquisition, every
        append commits its own short transaction (commits == appends), and
        the semantic parse runs strictly between two committed appends.
        """
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            state.active_at_http.append(state.active)
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        async with _client(handler) as client:
            await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert state.active_at_http == [0]
        # Exactly one short committed transaction per appended event; the
        # parse between ACQUIRED and DECODED had no open transaction.
        assert state.commits == len(state.events) == 4
        assert state.active == 0

    @pytest.mark.asyncio
    async def test_x09_semantic_only_path_emits_no_converted(self) -> None:
        """D27C-X09: the semantic-only path never emits a CONVERTED event."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        async with _client(handler) as client:
            await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert "converted" not in state.types
        assert all(event.event_type.value != "converted" for event in state.events)

    @pytest.mark.asyncio
    async def test_auth_key_never_enters_context_or_durable_log(self) -> None:
        """The Auth-Key stays header-only and never reaches context or events."""
        body = _json_bytes(threatfox_search_response(asyncrat_domain_record()))
        state = _State()
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return _json_response(json.loads(body.decode("utf-8")))

        async with _client(handler) as client:
            result = await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert requests[0].headers["Auth-Key"] == FIXED_KEY
        assert FIXED_KEY not in str(result.context)
        assert FIXED_KEY not in str(state.events)


class TestFailureLifecycle:
    """D27C-X02/X03/X04 plus the dimension gate (D27C-U04 path)."""

    @pytest.mark.asyncio
    async def test_x02_http_failure_records_failed_only(self) -> None:
        """D27C-X02: an HTTP failure yields STARTED then FAILED."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={})

        async with _client(handler) as client:
            result = await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert result.objects == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.ACQUISITION
        assert result.error.code == "provider_unavailable"
        assert result.error.retryable is True
        assert state.types == ["started", "failed"]
        assert state.events[-1].error_code == "provider_unavailable"

    @pytest.mark.asyncio
    async def test_x03_serialization_failure_no_decoded(self) -> None:
        """D27C-X03: malformed JSON is a serialization failure, no DECODED."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"{not json",
                headers={"Content-Type": "application/json"},
            )

        async with _client(handler) as client:
            result = await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert result.objects == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SERIALIZATION
        assert result.error.code == "serialization_failed"
        assert result.error.retryable is False
        assert state.types == ["started", "failed"]
        assert "decoded" not in state.types
        assert "acquired" not in state.types

    @pytest.mark.asyncio
    async def test_x04_semantic_failure_acquired_then_failed(self) -> None:
        """D27C-X04: a semantic failure is ACQUIRED then FAILED, no DECODED."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            # Valid JSON with a malformed ThreatFox record.
            return _json_response(
                {"query_status": "ok", "data": [{"id": "not-decimal"}]}
            )

        async with _client(handler) as client:
            result = await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert result.objects == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert result.error.code == "semantic_validation_failed"
        assert state.types == ["started", "acquired", "failed"]
        assert state.events[-1].error_code == "semantic_validation_failed"
        # No raw response body/record content ever enters the durable log.
        assert "not-decimal" not in str(state.events)

    @pytest.mark.asyncio
    async def test_u04_dimension_mismatch_fails_closed_before_io(self) -> None:
        """A definition whose dimensions contradict ThreatFox fails before I/O."""
        mismatched = DatasourceDefinition(
            datasource_id=DatasourceId("threatfox-live"),
            source_id=SourceId.THREATFOX,
            protocol=DatasourceProtocol.HTTPS,
            serialization_format=SerializationFormat.JSON,
            semantic_format=SemanticFormatId.STIX_21,
        )
        called = False
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            nonlocal called
            called = True
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        async with _client(handler) as client:
            with pytest.raises(ValueError, match="semantic_format"):
                await acquire_threatfox_execution(
                    datasource=_datasource(client),
                    definition=mismatched,
                    entity=_DOMAIN_ENTITY,
                    uow_factory=_factory(state),
                    clock=lambda: _EPOCH,
                )
        assert called is False

    @pytest.mark.asyncio
    async def test_unsupported_entity_fails_before_io(self) -> None:
        """An unsupported entity yields a bounded failure with zero I/O."""
        called = False
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            nonlocal called
            called = True
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        entity = Entity(type=EntityType.MALWARE, value="win.asyncrat")
        async with _client(handler) as client:
            result = await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=entity,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )
        assert called is False
        assert result.objects == ()
        assert result.error is not None
        assert result.error.code == "unsupported_indicator"
        assert result.error.retryable is False
        assert state.types == ["started", "failed"]


class TestCancellation:
    """D27C-X06: cancellation propagates and records CANCELLED best-effort."""

    @pytest.mark.asyncio
    async def test_x06_cancellation_propagates_and_records_cancelled(self) -> None:
        """D27C-X06: CANCELLED is recorded and CancelledError propagates."""
        state = _State()
        entered = asyncio.Event()
        never = asyncio.Event()

        async def handler(_: httpx.Request) -> httpx.Response:
            # Deterministic sleep-free blocking inside the transport until
            # the owning task is cancelled.
            entered.set()
            await never.wait()
            return _json_response({})

        async with _client(handler) as client:
            task = asyncio.create_task(
                acquire_threatfox_execution(
                    datasource=_datasource(client),
                    definition=_DEFINITION,
                    entity=_DOMAIN_ENTITY,
                    uow_factory=_factory(state),
                    clock=lambda: _EPOCH,
                )
            )
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert state.types == ["started", "cancelled"]
        assert state.events[-1].event_type.value == "cancelled"
        assert state.events[-1].error_code is None
        assert "failed" not in state.types
        assert "completed" not in state.types


class TestPr28F1JsonVerticalSlices:
    """V28F1-01/02: orjson provider decode preserves the ThreatFox boundary.

    The provider HTTP layer parses bounded response bytes with ``orjson``
    (PR 28F-1); these slices prove the real-format ThreatFox JSON bytes
    reach the production semantic parser with identical Python shapes, and
    that non-standard provider JSON fails closed at the datasource boundary
    with no payload or decoder leakage.
    """

    @pytest.mark.asyncio
    async def test_v28f1_01_http_bytes_to_semantic_records(self) -> None:
        """V28F1-01: real-format bytes -> response_json -> ThreatFoxRecord."""
        record = asyncrat_domain_record(
            threat_type_desc="Botnet C&C server — 威胁情报测试"
        )
        body = json.dumps(threatfox_search_response(record)).encode("utf-8")

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=body,
                headers={"Content-Type": "application/json"},
            )

        async with _client(handler) as client:
            http = ProviderHttpClient(
                client=client, policy=ProviderHttpPolicy(max_retries=0)
            )
            outcome = await http.request_json(
                "POST",
                "https://threatfox-api.abuse.ch/api/v1/",
                json_body={
                    "query": "search_ioc",
                    "search_term": CANONICAL_ASYNCRAT_DOMAIN,
                    "exact_match": True,
                },
            )

        assert outcome.final_error_code is None
        assert outcome.response_bytes == body
        assert isinstance(outcome.response_json, dict)
        semantic = parse_threatfox_response(
            outcome.response_json,
            entity_type=EntityType.DOMAIN,
            canonical_value=CANONICAL_ASYNCRAT_DOMAIN,
        )
        assert semantic.error is None
        assert len(semantic.records) == 1
        parsed = semantic.records[0]
        assert isinstance(parsed, ThreatFoxRecord)
        assert parsed.id == "864201"
        assert parsed.ioc == CANONICAL_ASYNCRAT_DOMAIN
        assert parsed.malware == CANONICAL_ASYNCRAT_MALWARE
        assert parsed.confidence_level == 100
        assert parsed.first_seen == datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)
        assert "威胁情报测试" in parsed.threat_type_desc

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "body",
        [
            b'{"query_status": "ok", "data": [{"x": NaN}]}',
            b'{"query_status": "ok", "data": [{"x": Infinity}]}',
            b'{"query_status": "ok", "data": [{"x": -Infinity}]}',
            b"\xff\xfe\x00",
        ],
    )
    async def test_v28f1_02_nonstandard_json_bounded_serialization_failure(
        self, body: bytes
    ) -> None:
        """V28F1-02: NaN/Infinity/invalid UTF-8 stay bounded at the source."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=body,
                headers={"Content-Type": "application/json"},
            )

        async with _client(handler) as client:
            result = await acquire_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )

        assert result.objects == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SERIALIZATION
        assert result.error.code == "serialization_failed"
        assert result.error.retryable is False
        assert state.types == ["started", "failed"]
        assert "decoded" not in state.types
        assert "acquired" not in state.types
        assert "orjson" not in str(result.error)
        assert "JSONDecodeError" not in str(result.error)
        assert body.decode("utf-8", errors="replace") not in str(state.events)
