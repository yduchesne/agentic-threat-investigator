# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27D ThreatFox Evidence converter and conversion-lifecycle tests.

Matrix IDs D27D-T01..T20 pin the per-record ThreatFox converter mapping:
validated ``ThreatFoxRecord`` input, exact provenance (Investigation,
subject, semantic source URN, retrieval time, credential-free reference,
upstream source record identity, observation time), shared legacy-format
match facts, source-confidence-as-source-fact, no raw payload, no
analytical inference, immutability, and fail-closed type/format misuse.
Matrix IDs D27D-E01..E06 pin the conversion stage vocabulary and the
acquire -> semantic -> pure-conversion -> CONVERTED lifecycle runner over a
fake in-memory UnitOfWork with a real ``ProviderHttpClient`` and a
deterministic local ``httpx.MockTransport`` (only the external Internet
endpoint is faked). No database and no persistence of Evidence are
involved; the legacy provider's runtime behavior is covered unchanged by
the existing provider suites (D27D-L01..L08).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any, Self
from uuid import UUID

import httpx
import pytest

from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    ConversionError,
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
    UnknownSemanticFormatError,
)
from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceLogEvent,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.infrastructure.datasources.threatfox import (
    ThreatFoxDatasource,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    ThreatFoxToEvidenceConverter,
    acquire_and_convert_threatfox_execution,
    build_threatfox_conversion_registry,
    build_threatfox_match_facts,
    format_threatfox_fact_timestamp,
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
    CANONICAL_ASYNCRAT_MALWARE,
    CANONICAL_ASYNCRAT_PRINTABLE,
    FIXED_KEY,
    MATCH_FACT_KEYS,
    asyncrat_domain_record,
    asyncrat_ip_port_record,
    threatfox_search_response,
)

pytestmark = pytest.mark.unit

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_INVESTIGATION_ID = UUID("11111111-2222-3333-4444-555555555555")
_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)
_DOMAIN_ENTITY = Entity(type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN)
_IP_ENTITY = Entity(type=EntityType.IP_ADDRESS, value=CANONICAL_ASYNCRAT_IP)
_DOMAIN_SUBJECT = EntityRef(type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN)
_IP_SUBJECT = EntityRef(type=EntityType.IP_ADDRESS, value=CANONICAL_ASYNCRAT_IP)


def _semantic_context() -> SemanticSourceContext:
    """Build the deterministic PR 27C semantic provenance context."""
    return SemanticSourceContext.from_definition(
        _DEFINITION,
        retrieved_at=_FIXED_TS,
        source_reference=_ENDPOINT,
    )


def _conversion_context(
    subject: EntityRef = _DOMAIN_SUBJECT,
) -> EvidenceConversionContext:
    """Build the deterministic PR 27D conversion context."""
    return EvidenceConversionContext(
        investigation_id=_INVESTIGATION_ID,
        subject=subject,
        semantic_source=_semantic_context(),
    )


def _record(**overrides: Any) -> ThreatFoxRecord:
    """Build one validated ThreatFoxRecord from the synthetic domain fixture."""
    return ThreatFoxRecord.model_validate(asyncrat_domain_record(**overrides))


class TestThreatFoxToEvidenceConverter:
    """D27D-T01..T20: per-record conversion mapping and provenance."""

    def test_t01_valid_domain_record_one_threat_intelligence_evidence(
        self,
    ) -> None:
        """D27D-T01: one valid domain record maps to one TI Evidence."""
        record = _record()
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            record, _conversion_context()
        )
        assert evidence.type == EvidenceType.THREAT_INTELLIGENCE
        assert len(evidence.facts) == 1
        assert thaw_json(evidence.facts["matches"][0]) == build_threatfox_match_facts(
            record
        )

    def test_t02_valid_ip_record_one_evidence(self) -> None:
        """D27D-T02: one valid ip:port record maps to one TI Evidence."""
        record = ThreatFoxRecord.model_validate(asyncrat_ip_port_record())
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            record, _conversion_context(subject=_IP_SUBJECT)
        )
        assert evidence.type == EvidenceType.THREAT_INTELLIGENCE
        assert evidence.subject.type == EntityType.IP_ADDRESS
        assert evidence.subject.value == CANONICAL_ASYNCRAT_IP
        match = evidence.facts["matches"][0]
        assert match["ioc"] == CANONICAL_ASYNCRAT_IP_PORT
        assert match["ioc_type"] == "ip:port"

    def test_t03_investigation_id_exact(self) -> None:
        """D27D-T03: the Evidence carries the context's exact Investigation ID."""
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            _record(), _conversion_context()
        )
        assert evidence.investigation_id == _INVESTIGATION_ID

    def test_t04_subject_exact(self) -> None:
        """D27D-T04: the Evidence carries the exact canonical subject binding."""
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            _record(), _conversion_context()
        )
        assert evidence.subject == _DOMAIN_SUBJECT
        assert evidence.subject.id is None

    def test_t05_source_exact_semantic_source_urn(self) -> None:
        """D27D-T05: source is the exact semantic-source URN."""
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            _record(), _conversion_context()
        )
        assert evidence.source == SourceId.THREATFOX.value

    def test_t06_retrieved_at_exact_semantic_context_time(self) -> None:
        """D27D-T06: retrieved_at is the exact semantic-context time."""
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            _record(), _conversion_context()
        )
        assert evidence.retrieved_at == _FIXED_TS
        assert evidence.retrieved_at.utcoffset() == timedelta(0)

    def test_t07_last_seen_present_observed_at_last_seen(self) -> None:
        """D27D-T07: observed_at is last_seen when present."""
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            _record(), _conversion_context()
        )
        assert evidence.observed_at == datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)

    def test_t08_last_seen_absent_observed_at_first_seen(self) -> None:
        """D27D-T08: observed_at falls back to first_seen without last_seen."""
        record = ThreatFoxRecord.model_validate(asyncrat_ip_port_record(last_seen=None))
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            record, _conversion_context(subject=_IP_SUBJECT)
        )
        assert evidence.observed_at == datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)

    def test_t09_source_reference_approved_safe_url(self) -> None:
        """D27D-T09: source_url is the approved credential-free reference."""
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            _record(), _conversion_context()
        )
        assert evidence.source_url == _ENDPOINT

    def test_t10_match_facts_legacy_keys_and_format(self) -> None:
        """D27D-T10: normalized match facts keep the legacy keys and format."""
        record = _record()
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            record, _conversion_context()
        )
        assert len(evidence.facts) == 1
        matches = evidence.facts["matches"]
        assert len(matches) == 1
        match = matches[0]
        assert set(match) == MATCH_FACT_KEYS
        assert match["threatfox_id"] == "864201"
        assert match["ioc"] == CANONICAL_ASYNCRAT_DOMAIN
        assert match["ioc_type"] == "domain"
        assert match["threat_type"] == "botnet_cc"
        assert match["threat_type_description"] == (
            "Indicator that identifies a botnet command&control server (C&C)"
        )
        assert match["malware"] == CANONICAL_ASYNCRAT_MALWARE
        assert match["malware_printable"] == CANONICAL_ASYNCRAT_PRINTABLE
        assert match["first_seen"] == "2026-08-20T12:00:00Z"
        assert match["last_seen"] == "2026-08-21T12:00:00Z"
        # Shared with the legacy provider: identical thawed match facts.
        assert thaw_json(match) == build_threatfox_match_facts(record)

    def test_t11_confidence_source_fact_only(self) -> None:
        """D27D-T11: source confidence stays a source fact, never a weight."""
        record = _record(confidence_level=75)
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            record, _conversion_context()
        )
        match = evidence.facts["matches"][0]
        assert match["confidence_level"] == 75
        assert set(evidence.facts) == {"matches"}
        serialized = str(evidence.facts)
        for fragment in ("verdict", "risk", "assessment"):
            assert fragment not in serialized

    def test_t12_tags_reference_nulls_preserved_mapping(self) -> None:
        """D27D-T12: tags/reference/nullable source values map unchanged."""
        record = _record(
            reference="https://threatfox.abuse.ch/ioc/864201",
            tags=["AsyncRAT", "malware"],
            malware_printable=None,
        )
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            record, _conversion_context()
        )
        match = evidence.facts["matches"][0]
        assert match["reference"] == "https://threatfox.abuse.ch/ioc/864201"
        assert match["tags"] == ("AsyncRAT", "malware")
        assert match["malware_printable"] is None
        # Null reference/tags are retained as null.
        sparse = ThreatFoxRecord.model_validate(
            asyncrat_domain_record(reference=None, tags=None)
        )
        (sparse_evidence,) = ThreatFoxToEvidenceConverter().convert(
            sparse, _conversion_context()
        )
        sparse_match = sparse_evidence.facts["matches"][0]
        assert sparse_match["reference"] is None
        assert sparse_match["tags"] is None

    def test_t13_raw_payload_none(self) -> None:
        """D27D-T13: the emitted Evidence never copies a raw payload."""
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            _record(), _conversion_context()
        )
        assert evidence.raw_payload is None

    def test_t14_repeated_conversion_equal_output(self) -> None:
        """D27D-T14: repeated conversion yields structurally equal Evidence."""
        converter = ThreatFoxToEvidenceConverter()
        record = _record()
        context = _conversion_context()
        first = converter.convert(record, context)
        second = converter.convert(record, context)
        assert first == second
        assert first[0].id is None and second[0].id is None

    def test_t15_wrong_semantic_format_fails_closed(self) -> None:
        """D27D-T15: lookup under a foreign semantic format fails closed."""
        registry = ToEvidenceConverterRegistry((ThreatFoxToEvidenceConverter(),))
        assert (
            registry.get(SemanticFormatId.THREATFOX).semantic_format
            is SemanticFormatId.THREATFOX
        )
        with pytest.raises(UnknownSemanticFormatError):
            registry.get(SemanticFormatId.STIX_21)

    def test_t16_wrong_object_type_fails_closed(self) -> None:
        """D27D-T16: a non-record source object raises a typed conversion error."""
        with pytest.raises(ConversionError, match="ThreatFoxRecord"):
            ThreatFoxToEvidenceConverter().convert(
                {"ioc": "not-a-record"},  # type: ignore[arg-type]
                _conversion_context(),
            )

    def test_t17_source_and_context_immutable_no_mutation(self) -> None:
        """D27D-T17: conversion never mutates the record or the context."""
        record = _record()
        context = _conversion_context()
        record_snapshot = record.model_dump()
        ThreatFoxToEvidenceConverter().convert(record, context)
        assert record.model_dump() == record_snapshot
        assert context.investigation_id == _INVESTIGATION_ID
        assert context.subject == _DOMAIN_SUBJECT

    def test_t18_credentials_absent(self) -> None:
        """D27D-T18: no credential ever reaches Evidence."""
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            _record(), _conversion_context()
        )
        serialized = f"{evidence.model_dump()} {evidence.source_url}"
        assert FIXED_KEY not in serialized
        assert "Auth-Key" not in serialized
        assert "auth" not in str(evidence.source_url).lower()

    def test_t19_source_record_id_exact_upstream_identity(self) -> None:
        """D27D-T19: source_record_id carries the exact upstream record ID."""
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            _record(), _conversion_context()
        )
        assert evidence.source_record_id == "864201"
        # The ATI persistence identity remains unset.
        assert evidence.id is None

    def test_t20_no_analytical_inference(self) -> None:
        """D27D-T20: conversion never synthesizes verdict, risk, or relations."""
        record = ThreatFoxRecord.model_validate(asyncrat_ip_port_record())
        (evidence,) = ThreatFoxToEvidenceConverter().convert(
            record, _conversion_context(subject=_IP_SUBJECT)
        )
        assert evidence.id is None
        assert evidence.investigation_id == _INVESTIGATION_ID
        assert set(evidence.model_dump()) == {
            "id",
            "investigation_id",
            "type",
            "subject",
            "source",
            "source_record_id",
            "source_url",
            "observed_at",
            "retrieved_at",
            "facts",
            "raw_payload",
        }
        serialized = str(evidence.facts)
        for fragment in (
            "verdict",
            "benign",
            "relationship",
            "associated_with",
            "discovery",
            "pivot",
            "attribution",
        ):
            assert fragment not in serialized

    def test_format_timestamp_shared_helper(self) -> None:
        """The shared timestamp formatter normalizes any aware UTC datetime."""
        assert (
            format_threatfox_fact_timestamp(datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC))
            == "2026-08-20T12:00:00Z"
        )


class _FailingConverter(ToEvidenceConverter[str]):
    """Test-only converter that always fails deterministically at conversion."""

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Return the claimed semantic format."""
        return SemanticFormatId.THREATFOX

    def convert(
        self, source: str, context: EvidenceConversionContext
    ) -> tuple[Evidence, ...]:
        """Raise the typed deterministic conversion failure."""
        raise ConversionError("deterministic local conversion failure")


class _Logs:
    """In-memory append-only datasource-log fake."""

    def __init__(self, state: "_State") -> None:
        """Bind to the shared test state."""
        self.state = state

    async def append(self, event: DatasourceLogEvent) -> None:
        """Record the pending append; the UoW commit applies it."""
        self.state.pending_append = event


class _State:
    """Shared conversion-test state: durable events and commit accounting."""

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


def _json_response(payload: object) -> httpx.Response:
    """Build a deterministic JSON response with an explicit body length."""
    return httpx.Response(
        200,
        content=_json_bytes(payload),
        headers={"Content-Type": "application/json"},
    )


def _client(handler: Callable[[httpx.Request], Any]) -> httpx.AsyncClient:
    """Build a deterministic mock-transport client."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _datasource(
    client: httpx.AsyncClient,
    *,
    clock: Callable[[], datetime] | None = None,
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
        clock=clock if clock is not None else (lambda: _FIXED_TS),
    )


class TestConversionLifecycle:
    """D27D-E01..E06: stage vocabulary and the conversion runner lifecycle."""

    def test_e01_conversion_stage_valid(self) -> None:
        """D27D-E01: CONVERSION is a valid typed error stage."""
        assert DatasourceStage.CONVERSION.value == "conversion"
        assert DatasourceStage.CONVERSION in DatasourceStage

    @pytest.mark.asyncio
    async def test_e02_zero_output_converted_zero_success(self) -> None:
        """D27D-E02: a valid no-result records CONVERTED(0) then COMPLETED."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            return _json_response({"query_status": "no_result"})

        async with _client(handler) as client:
            result, evidence = await acquire_and_convert_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                investigation_id=_INVESTIGATION_ID,
                subject=_DOMAIN_SUBJECT,
                registry=build_threatfox_conversion_registry(),
                uow_factory=_factory(state),
                clock=lambda: _FIXED_TS,
            )

        assert result.error is None
        assert result.objects == ()
        assert evidence == ()
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "completed",
        ]
        converted = state.events[3]
        assert converted.event_type.value == "converted"
        assert converted.item_count == 0
        assert all(event.error_code is None for event in state.events)

    @pytest.mark.asyncio
    async def test_success_one_record_converted_one_completed(self) -> None:
        """One record: pure conversion emits one Evidence; CONVERTED count=1."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            state.active_at_http.append(state.active)
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        async with _client(handler) as client:
            result, evidence = await acquire_and_convert_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                investigation_id=_INVESTIGATION_ID,
                subject=_DOMAIN_SUBJECT,
                registry=build_threatfox_conversion_registry(),
                uow_factory=_factory(state),
                clock=lambda: _FIXED_TS,
            )

        assert result.error is None
        assert len(result.objects) == 1
        assert len(evidence) == 1
        converted = state.events[3]
        assert converted.item_count == 1
        assert evidence[0].subject == _DOMAIN_SUBJECT
        assert evidence[0].source_record_id == "864201"
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "completed",
        ]
        assert len(state.execution_ids) == 1
        assert state.datasource_ids == {"threatfox-live"}
        # Every event committed in its own short transaction; HTTP ran with
        # no database transaction open.
        assert state.commits == 5
        assert state.active == 0
        assert state.active_at_http == [0]

    @pytest.mark.asyncio
    async def test_success_two_records_two_evidence_source_order(self) -> None:
        """Two records: two Evidence in semantic source order; CONVERTED=2."""
        state = _State()
        payload = threatfox_search_response(
            asyncrat_ip_port_record(id="864202", last_seen=None),
            asyncrat_ip_port_record(
                id="864203", ioc=CANONICAL_ASYNCRAT_IP_PORT, last_seen=None
            ),
        )

        def handler(_: httpx.Request) -> httpx.Response:
            return _json_response(payload)

        async with _client(handler) as client:
            result, evidence = await acquire_and_convert_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_IP_ENTITY,
                investigation_id=_INVESTIGATION_ID,
                subject=_IP_SUBJECT,
                registry=build_threatfox_conversion_registry(),
                uow_factory=_factory(state),
                clock=lambda: _FIXED_TS,
            )

        assert result.error is None
        assert [item.source_record_id for item in evidence] == ["864202", "864203"]
        assert state.events[3].event_type.value == "converted"
        assert state.events[3].item_count == 2
        assert state.types[-1] == "completed"

    @pytest.mark.asyncio
    async def test_e03_converter_violation_conversion_failure(self) -> None:
        """D27D-E03: a converter violation records FAILED(conversion_failed).

        The failing converter is selected purely by semantic format (no
        object-shape fallback): STARTED/ACQUIRED/DECODED followed by FAILED,
        never CONVERTED, never COMPLETED, and the typed failure propagates.
        """
        state = _State()
        registry = ToEvidenceConverterRegistry((_FailingConverter(),))

        def handler(_: httpx.Request) -> httpx.Response:
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        async with _client(handler) as client:
            with pytest.raises(ConversionError):
                await acquire_and_convert_threatfox_execution(
                    datasource=_datasource(client),
                    definition=_DEFINITION,
                    entity=_DOMAIN_ENTITY,
                    investigation_id=_INVESTIGATION_ID,
                    subject=_DOMAIN_SUBJECT,
                    registry=registry,
                    uow_factory=_factory(state),
                    clock=lambda: _FIXED_TS,
                )

        assert state.types == ["started", "acquired", "decoded", "failed"]
        assert state.events[-1].error_code == "conversion_failed"
        assert "converted" not in state.types
        assert "completed" not in state.types
        # No exception text is ever represented by the bounded log schema.
        assert all(
            event.error_code == "conversion_failed" or event.error_code is None
            for event in state.events
        )

    @pytest.mark.asyncio
    async def test_e04_durable_error_bounded_conversion_failed_only(self) -> None:
        """D27D-E04: the durable log carries only the bounded conversion code."""
        state = _State()
        registry = ToEvidenceConverterRegistry((_FailingConverter(),))

        def handler(_: httpx.Request) -> httpx.Response:
            return _json_response(threatfox_search_response(asyncrat_domain_record()))

        async with _client(handler) as client:
            with pytest.raises(ConversionError):
                await acquire_and_convert_threatfox_execution(
                    datasource=_datasource(client),
                    definition=_DEFINITION,
                    entity=_DOMAIN_ENTITY,
                    investigation_id=_INVESTIGATION_ID,
                    subject=_DOMAIN_SUBJECT,
                    registry=registry,
                    uow_factory=_factory(state),
                    clock=lambda: _FIXED_TS,
                )

        serialized = str(state.events)
        assert "conversion_failed" in serialized
        assert "deterministic local" not in serialized
        assert FIXED_KEY not in serialized
        assert "asyncrat" not in serialized

    @pytest.mark.asyncio
    async def test_e06_cancellation_records_cancelled_and_propagates(self) -> None:
        """D27D-E06: cancellation records CANCELLED and never FAILED/COMPLETED.

        Deterministic sleep-free cancellation during the HTTP wait: STARTED
        persists, the transport blocks on an event, the task is cancelled,
        the runner records CANCELLED, ``CancelledError`` propagates, and the
        durable log holds exactly STARTED + CANCELLED.
        """
        state = _State()
        entered = asyncio.Event()
        never = asyncio.Event()

        async def handler(_: httpx.Request) -> httpx.Response:
            entered.set()
            await never.wait()
            return _json_response({})

        async with _client(handler) as client:
            task = asyncio.create_task(
                acquire_and_convert_threatfox_execution(
                    datasource=_datasource(client),
                    definition=_DEFINITION,
                    entity=_DOMAIN_ENTITY,
                    investigation_id=_INVESTIGATION_ID,
                    subject=_DOMAIN_SUBJECT,
                    registry=build_threatfox_conversion_registry(),
                    uow_factory=_factory(state),
                    clock=lambda: _FIXED_TS,
                )
            )
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert state.types == ["started", "cancelled"]
        assert all(event.error_code is None for event in state.events)
        assert "failed" not in state.types
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_acquisition_failure_returns_no_evidence(self) -> None:
        """A typed acquisition failure fails with its safe code and no Evidence."""
        state = _State()

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={})

        async with _client(handler) as client:
            result, evidence = await acquire_and_convert_threatfox_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                entity=_DOMAIN_ENTITY,
                investigation_id=_INVESTIGATION_ID,
                subject=_DOMAIN_SUBJECT,
                registry=build_threatfox_conversion_registry(),
                uow_factory=_factory(state),
                clock=lambda: _FIXED_TS,
            )

        assert result.error is not None
        assert result.error.code == "provider_unavailable"
        assert evidence == ()
        assert state.types == ["started", "failed"]
        assert "converted" not in state.types
        assert "completed" not in state.types
