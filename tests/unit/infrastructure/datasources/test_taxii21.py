# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E TAXII 2.1 protocol/envelope and acquisition/pagination tests.

Stable matrix IDs T33E-P01..P18 (protocol/envelope) and T33E-A01..A20
(acquisition/pagination). Only the external TAXII 2.1 HTTPS boundary is
faked with an in-process ``httpx.MockTransport`` that speaks the real TAXII
2.1 wire contract (envelopes, ``more``/``next`` pagination, the
``application/taxii+json;version=2.1`` media type, and date-added headers);
the real ``ProviderHttpClient``, the real ``Taxii21Datasource``, the real
TAXII envelope parser, and the real PR 33A ``parse_stix21_object`` boundary
are exercised. No test touches a live TAXII server, reads the wall clock,
or sleeps for timing.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self, cast

import httpx
import pytest

from agentic_threat_investigator.app.datasource_execution import (
    DatasourceExecutionRecorder,
)
from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
)
from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceCheckpoint,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceLogEvent,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    Stix21Object,
)
from agentic_threat_investigator.infrastructure.datasources.taxii21 import (
    TAXII_CHECKPOINT_KIND,
    Taxii21Datasource,
    Taxii21Error,
    canonicalize_taxii_timestamp,
    format_taxii_timestamp,
    parse_taxii21_object_page,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from tests.support.provider_http import no_op_sleep, zero_jitter
from tests.support.stix21_fixtures import (
    INDICATOR_ID,
    stix_domain_name,
    stix_indicator,
    stix_ipv4_addr,
)
from tests.support.taxii_fixtures import (
    BEARER_TOKEN,
    DATE_ADDED_1,
    DATE_ADDED_2,
    DATE_ADDED_3,
    NEXT_1,
    NEXT_2,
    TAXII_API_ROOT,
    TAXII_COLLECTION_ID,
    TAXII_MEDIA_TYPE,
    TAXII_OBJECTS_URL,
    RecordedTaxiiServer,
    client_for,
    taxii_envelope,
    taxii_response,
)

pytestmark = pytest.mark.unit

_OCCURRED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("opencti-collection"),
    source_id=SourceId.OPENCTI,
    protocol=DatasourceProtocol.TAXII_21,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.STIX_21,
)


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


def _client(handler: Callable[[httpx.Request], Any]) -> httpx.AsyncClient:
    """Build a deterministic mock-transport client."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _datasource(
    client: httpx.AsyncClient,
    *,
    bearer_token: str | None = BEARER_TOKEN,
    api_root_url: str = TAXII_API_ROOT,
    collection_id: str = TAXII_COLLECTION_ID,
    page_size: int = 100,
    max_pages: int = 100,
    initial_added_after: str | None = None,
    checkpoint_reader: (Callable[[], Awaitable[object | None]] | None) = None,
    max_retries: int = 0,
    clock: Callable[[], datetime] | None = None,
) -> Taxii21Datasource:
    """Build the acquirer with deterministic policy and the fixed test token."""
    http = ProviderHttpClient(
        client=client,
        policy=ProviderHttpPolicy(max_retries=max_retries, base_delay_seconds=0.01),
        sleep=no_op_sleep,
        jitter_fn=zero_jitter,
    )
    return Taxii21Datasource(
        http,
        bearer_token=bearer_token,
        api_root_url=api_root_url,
        collection_id=collection_id,
        page_size=page_size,
        max_pages=max_pages,
        initial_added_after=initial_added_after,
        checkpoint_reader=cast(
            Callable[[], Awaitable[DatasourceCheckpoint | None]],
            checkpoint_reader,
        ),
        clock=clock if clock is not None else (lambda: _OCCURRED_AT),
    )


async def _acquire(
    datasource: Taxii21Datasource,
    *,
    definition: DatasourceDefinition = _DEFINITION,
    state: _State | None = None,
) -> tuple[Any, _State]:
    """Run one full acquisition over the real recorder and fake UoW state."""
    state = state or _State()
    recorder = DatasourceExecutionRecorder(
        definition.datasource_id,
        uow_factory=_factory(state),
        clock=lambda: _OCCURRED_AT,
    )
    await recorder.start()
    result = await datasource.acquire(definition=definition, recorder=recorder)
    return result, state


# ---------------------------------------------------------------------------
# Protocol / envelope matrix (T33E-P)
# ---------------------------------------------------------------------------


class TestProtocolEnvelope:
    """T33E-P01..P18: TAXII envelope and pagination contract."""

    def test_p01_empty_objects_more_false_is_valid_empty_page(self) -> None:
        """P01: an empty envelope with more=false is successful empty semantics."""
        page = parse_taxii21_object_page(
            taxii_envelope(), date_added_first=None, date_added_last=None
        )
        assert page.objects == ()
        assert page.more is False
        assert page.next_token is None

    def test_p02_one_stix_object_is_preserved_exactly(self) -> None:
        """P02: one STIX object member is preserved exactly."""
        member = stix_domain_name()
        page = parse_taxii21_object_page(
            taxii_envelope(member), date_added_first=None, date_added_last=None
        )
        assert len(page.objects) == 1
        assert page.objects[0] == member

    def test_p03_multiple_objects_preserve_source_order(self) -> None:
        """P03: multiple members preserve the server's source order."""
        first = stix_domain_name()
        second = stix_ipv4_addr()
        page = parse_taxii21_object_page(
            taxii_envelope(first, second),
            date_added_first=None,
            date_added_last=None,
        )
        assert list(page.objects) == [first, second]

    def test_p04_more_true_with_nonblank_next_is_valid_continuation(self) -> None:
        """P04: more=true with a nonblank opaque next token is valid."""
        page = parse_taxii21_object_page(
            taxii_envelope(more=True, next_token=NEXT_1),
            date_added_first=None,
            date_added_last=None,
        )
        assert page.more is True
        assert page.next_token == NEXT_1

    def test_p05_more_true_without_next_fails_closed(self) -> None:
        """P05: more=true without a next member fails closed."""
        with pytest.raises(Taxii21Error):
            parse_taxii21_object_page(
                taxii_envelope(more=True), date_added_first=None, date_added_last=None
            )

    def test_p06_more_true_with_blank_next_fails_closed(self) -> None:
        """P06: more=true with a blank next token fails closed."""
        with pytest.raises(Taxii21Error):
            parse_taxii21_object_page(
                taxii_envelope(more=True, next_token="   "),
                date_added_first=None,
                date_added_last=None,
            )

    def test_p07_malformed_root_fails_closed(self) -> None:
        """P07: a non-object root fails closed."""
        with pytest.raises(Taxii21Error):
            parse_taxii21_object_page(
                ["not", "an", "object"],
                date_added_first=None,
                date_added_last=None,
            )

    def test_p08_objects_non_array_fails_closed(self) -> None:
        """P08: a non-array objects member fails closed."""
        with pytest.raises(Taxii21Error):
            parse_taxii21_object_page(
                {"objects": {"type": "indicator", "id": INDICATOR_ID}},
                date_added_first=None,
                date_added_last=None,
            )

    @pytest.mark.asyncio
    async def test_p09_object_member_non_object_is_stix_semantic_failure(self) -> None:
        """P09: a non-object member fails the whole acquisition semantically."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        {"objects": ["not-an-object"]},
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _run_simple(datasource)
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert result.error.code == "semantic_validation_failed"
        assert result.objects == ()

    @pytest.mark.asyncio
    async def test_p10_malformed_stix_object_fails_whole_acquisition(self) -> None:
        """P10: a malformed STIX object fails the whole acquisition."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope({"type": "indicator"}),  # missing id
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _run_simple(datasource)
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert result.error.code == "semantic_validation_failed"
        assert result.objects == ()

    @pytest.mark.asyncio
    async def test_p11_valid_unsupported_stix_object_is_accepted(self) -> None:
        """P11: a valid-but-unsupported STIX object is a valid semantic object."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            {
                                "type": "x-custom-event",
                                "id": "x-custom-event--00000000-0000-4000-8000-000000000099",
                                "created": DATE_ADDED_1,
                                "modified": DATE_ADDED_1,
                                "spec_version": "2.1",
                            }
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, state = await _acquire(datasource)
        assert result.error is None
        assert len(result.objects) == 1
        assert isinstance(result.objects[0], Stix21Object)
        assert "converted" not in state.types  # conversion is the producer's job

    @pytest.mark.asyncio
    async def test_p12_bundle_member_never_fake_wrapped(self) -> None:
        """P12: a Bundle member is rejected by the direct object boundary."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            {"type": "bundle", "id": "bundle--1", "objects": []}
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _run_simple(datasource)
        assert result.error is not None
        assert result.error.code == "semantic_validation_failed"
        assert result.objects == ()

    @pytest.mark.asyncio
    async def test_p13_opaque_next_token_is_preserved_verbatim(self) -> None:
        """P13: an opaque punctuation-bearing next token round-trips untouched."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            stix_domain_name(), more=True, next_token=NEXT_2
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                ),
                (
                    taxii_response(
                        taxii_envelope(stix_ipv4_addr()),
                        first=DATE_ADDED_2,
                        last=DATE_ADDED_2,
                    ),
                    NEXT_2,
                ),
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert len(result.objects) == 2
        # The fake server asserted the exact token round-trip in the query.
        assert server.requests[1].query["next"] == NEXT_2

    @pytest.mark.asyncio
    async def test_p14_taxii_media_type_is_accepted(self) -> None:
        """P14: application/taxii+json;version=2.1 content type is accepted."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(stix_domain_name()),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                        content_type=f"{TAXII_MEDIA_TYPE};version=2.1",
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert len(result.objects) == 1

    @pytest.mark.asyncio
    async def test_p15_incompatible_content_type_fails_bounded(self) -> None:
        """P15: an incompatible content type is a bounded serialization failure."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(stix_domain_name()),
                        content_type="application/json",
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SERIALIZATION
        assert result.error.code == "serialization_failed"
        assert result.objects == ()

    def test_p16_valid_date_added_headers_are_canonicalized(self) -> None:
        """P16: valid TAXII date-added headers parse to canonical UTC instants."""
        page = parse_taxii21_object_page(
            taxii_envelope(stix_domain_name()),
            date_added_first="2026-07-01T00:00:00Z",
            date_added_last="2026-07-01T00:00:00.5+00:00",
        )
        assert page.date_added_first == canonicalize_taxii_timestamp(
            "2026-07-01T00:00:00Z"
        )
        assert page.date_added_last == canonicalize_taxii_timestamp(
            "2026-07-01T00:00:00.5+00:00"
        )

    @pytest.mark.asyncio
    async def test_p17_malformed_date_added_header_fails_closed(self) -> None:
        """P17: a malformed date-added header fails the whole acquisition."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(stix_domain_name()),
                        first="not-a-timestamp",
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is not None
        assert result.error.code == "protocol_validation_failed"
        assert result.objects == ()

    @pytest.mark.asyncio
    async def test_p18_source_controlled_error_body_never_exposed(self) -> None:
        """P18: a server-error body carrying secrets/raw text is never exposed."""
        secret = "server-error-body-isolation-marker"
        server = RecordedTaxiiServer(
            [
                (
                    httpx.Response(
                        500,
                        content=json.dumps(
                            {"error": f"internal failure {secret}", "token": secret}
                        ).encode("utf-8"),
                        headers={"Content-Type": TAXII_MEDIA_TYPE},
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is not None
        assert result.error.code == "provider_unavailable"
        assert secret not in repr(result.error)
        assert result.objects == ()


async def _run_simple(
    datasource: Taxii21Datasource,
    definition: DatasourceDefinition = _DEFINITION,
) -> tuple[Any, _State]:
    """Convenience wrapper defaulting a fresh state for one-off tests."""
    return await _acquire(datasource, definition=definition)


# ---------------------------------------------------------------------------
# Acquisition / pagination matrix (T33E-A)
# ---------------------------------------------------------------------------


class TestAcquisitionPagination:
    """T33E-A01..A20: acquisition, pagination, auth, and safety."""

    @pytest.mark.asyncio
    async def test_a01_one_page_no_checkpoint_no_added_after(self) -> None:
        """A01: one page without any checkpoint carries no added_after."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(stix_domain_name()),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert len(result.objects) == 1
        assert "added_after" not in server.requests[0].query
        assert result.progress is not None
        assert result.progress.kind == TAXII_CHECKPOINT_KIND
        assert result.progress.previous is None
        assert result.progress.candidate == format_taxii_timestamp(
            canonicalize_taxii_timestamp(DATE_ADDED_1)
        )

    @pytest.mark.asyncio
    async def test_a02_configured_initial_added_after_sent(self) -> None:
        """A02: the configured initial added_after is sent on the first page."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(stix_domain_name()),
                        first=DATE_ADDED_2,
                        last=DATE_ADDED_2,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(
            client_for(server.handler()), initial_added_after="2026-06-01T00:00:00Z"
        )
        result, _state = await _acquire(datasource)
        assert result.error is None
        sent = server.requests[0].query["added_after"]
        assert canonicalize_taxii_timestamp(sent) == canonicalize_taxii_timestamp(
            "2026-06-01T00:00:00Z"
        )
        assert result.progress is not None
        assert result.progress.previous == format_taxii_timestamp(
            canonicalize_taxii_timestamp("2026-06-01T00:00:00Z")
        )

    @pytest.mark.asyncio
    async def test_a03_durable_checkpoint_wins_over_initial(self) -> None:
        """A03: a durable checkpoint wins over the configured initial value."""
        durable = DATE_ADDED_2

        async def _durable_reader() -> object:
            from agentic_threat_investigator.app.persistence.repositories import (
                DatasourceCheckpoint,
            )

            return DatasourceCheckpoint(
                datasource_id="opencti-collection",
                checkpoint_kind=TAXII_CHECKPOINT_KIND,
                checkpoint_value=durable,
                updated_at=datetime(2026, 6, 1, tzinfo=UTC),
                version=1,
            )

        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(stix_domain_name()),
                        first=DATE_ADDED_2,
                        last=DATE_ADDED_2,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(
            client_for(server.handler()),
            initial_added_after="2020-01-01T00:00:00Z",
            checkpoint_reader=_durable_reader,
        )
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert canonicalize_taxii_timestamp(
            server.requests[0].query["added_after"]
        ) == canonicalize_taxii_timestamp(durable)
        assert result.progress is not None
        assert result.progress.previous == format_taxii_timestamp(
            canonicalize_taxii_timestamp(durable)
        )

    @pytest.mark.asyncio
    async def test_a04_two_pages_use_exact_next_token(self) -> None:
        """A04: page 2 uses the exact page-1 opaque next token."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            stix_domain_name(), more=True, next_token=NEXT_1
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                ),
                (
                    taxii_response(
                        taxii_envelope(stix_ipv4_addr()),
                        first=DATE_ADDED_2,
                        last=DATE_ADDED_2,
                    ),
                    NEXT_1,
                ),
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert [r.query.get("next") for r in server.requests] == [None, NEXT_1]
        assert len(result.objects) == 2

    @pytest.mark.asyncio
    async def test_a05_three_pages_strictly_sequential(self) -> None:
        """A05: three pages are requested in strict sequential order."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            stix_domain_name(), more=True, next_token=NEXT_1
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                ),
                (
                    taxii_response(
                        taxii_envelope(stix_ipv4_addr(), more=True, next_token=NEXT_2),
                        first=DATE_ADDED_2,
                        last=DATE_ADDED_2,
                    ),
                    NEXT_1,
                ),
                (
                    taxii_response(
                        taxii_envelope(stix_indicator(), more=False),
                        first=DATE_ADDED_3,
                        last=DATE_ADDED_3,
                    ),
                    NEXT_2,
                ),
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert [r.query.get("next") for r in server.requests] == [None, NEXT_1, NEXT_2]
        # Candidate covers only the pages that returned objects.
        assert result.progress is not None
        assert result.progress.candidate == format_taxii_timestamp(
            canonicalize_taxii_timestamp(DATE_ADDED_3)
        )

    @pytest.mark.asyncio
    async def test_a06_max_pages_bounded_window_no_extra_request(self) -> None:
        """A06: hitting max_pages with more=true is a successful bounded window."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            stix_domain_name(), more=True, next_token=NEXT_1
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                ),
                (
                    taxii_response(
                        taxii_envelope(stix_ipv4_addr(), more=True, next_token=NEXT_2),
                        first=DATE_ADDED_2,
                        last=DATE_ADDED_2,
                    ),
                    NEXT_1,
                ),
            ]
        )
        datasource = _datasource(client_for(server.handler()), page_size=1, max_pages=2)
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert len(server.requests) == 2
        assert len(result.objects) == 2

    @pytest.mark.asyncio
    async def test_a07_short_final_page_more_false_stops(self) -> None:
        """A07: more=false on a short final page stops the loop."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            stix_domain_name(), more=True, next_token=NEXT_1
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                ),
                (
                    taxii_response(
                        taxii_envelope(stix_indicator()),
                        first=DATE_ADDED_3,
                        last=DATE_ADDED_3,
                    ),
                    NEXT_1,
                ),
            ]
        )
        datasource = _datasource(client_for(server.handler()), page_size=100)
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert len(server.requests) == 2
        assert len(result.objects) == 2

    @pytest.mark.asyncio
    async def test_a08_empty_first_page_successful_empty(self) -> None:
        """A08: an empty first page is successful empty semantics."""
        server = RecordedTaxiiServer(
            [(taxii_response(taxii_envelope(), first=None, last=None), None)]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert result.objects == ()
        # No objects and no previous checkpoint: no advancement proposed.
        assert result.progress is None or result.progress.candidate is None

    @pytest.mark.asyncio
    async def test_a09_http_401_bounded_auth_failure(self) -> None:
        """A09: HTTP 401 maps to a bounded authentication failure."""
        server = RecordedTaxiiServer(
            [(taxii_response({}, status=401, content_type=TAXII_MEDIA_TYPE), None)]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is not None
        assert result.error.code == "authentication_failed"
        assert result.error.retryable is False

    @pytest.mark.asyncio
    async def test_a10_http_403_bounded_forbidden(self) -> None:
        """A10: HTTP 403 maps to a bounded forbidden failure."""
        server = RecordedTaxiiServer(
            [(taxii_response({}, status=403, content_type=TAXII_MEDIA_TYPE), None)]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is not None
        assert result.error.code == "forbidden"

    @pytest.mark.asyncio
    async def test_a11_http_404_bounded_not_found(self) -> None:
        """A11: HTTP 404 maps to a bounded not-found failure."""
        server = RecordedTaxiiServer(
            [(taxii_response({}, status=404, content_type=TAXII_MEDIA_TYPE), None)]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is not None
        assert result.error.code == "not_found"

    @pytest.mark.asyncio
    async def test_a12_http_429_rate_limited_retry(self) -> None:
        """A12: HTTP 429 with Retry-After stays a bounded rate-limited outcome."""
        server = RecordedTaxiiServer(
            [
                (
                    httpx.Response(
                        429,
                        content=b"{}",
                        headers={
                            "Content-Type": TAXII_MEDIA_TYPE,
                            "Retry-After": "1",
                        },
                    ),
                    None,
                ),
                (
                    taxii_response(
                        taxii_envelope(stix_domain_name()),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                ),
            ]
        )
        datasource = _datasource(
            client_for(server.handler()), max_retries=2, clock=lambda: _OCCURRED_AT
        )
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert len(result.objects) == 1
        assert len(server.requests) == 2

    @pytest.mark.asyncio
    async def test_a13_timeout_bounded(self) -> None:
        """A13: a transport timeout maps to a bounded timeout failure."""

        async def _hang(_request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.05)
            raise httpx.TimeoutException("boom")

        datasource = _datasource(
            _client(_hang),
            clock=lambda: _OCCURRED_AT,
        )
        result, _state = await _acquire(datasource)
        assert result.error is not None
        assert result.error.code == "timeout"

    @pytest.mark.asyncio
    async def test_a14_malformed_later_page_fails_whole_acquisition(self) -> None:
        """A14: a malformed page 2 yields zero semantic objects overall."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            stix_domain_name(), more=True, next_token=NEXT_1
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                ),
                (
                    taxii_response({"objects": "nope"}, first=None, last=None),
                    NEXT_1,
                ),
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is not None
        assert result.error.code == "protocol_validation_failed"
        assert result.objects == ()

    @pytest.mark.asyncio
    async def test_a15_malformed_stix_page2_fails_whole_acquisition(self) -> None:
        """A15: a malformed STIX member on page 2 yields zero objects overall."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            stix_domain_name(), more=True, next_token=NEXT_1
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                ),
                (
                    taxii_response(
                        taxii_envelope({"type": "malware"}),  # missing id
                        first=DATE_ADDED_2,
                        last=DATE_ADDED_2,
                    ),
                    NEXT_1,
                ),
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is not None
        assert result.error.code == "semantic_validation_failed"
        assert result.objects == ()

    @pytest.mark.asyncio
    async def test_a16_cancellation_propagates(self) -> None:
        """A16: asyncio.CancelledError propagates unchanged through acquire."""

        async def _cancel(_request: httpx.Request) -> httpx.Response:
            raise asyncio.CancelledError()

        datasource = _datasource(_client(_cancel))
        with pytest.raises(asyncio.CancelledError):
            await _acquire(datasource)

    @pytest.mark.asyncio
    async def test_a17_no_page_prefetch_concurrency(self) -> None:
        """A17: pages are strictly sequential — never more than one in flight."""
        in_flight: list[int] = []
        peak: list[int] = [0]

        def _handler(request: httpx.Request) -> httpx.Response:
            in_flight.append(1)
            peak[0] = max(peak[0], len(in_flight))
            response = taxii_response(
                taxii_envelope(stix_domain_name(), more=True, next_token=NEXT_1),
                first=DATE_ADDED_1,
                last=DATE_ADDED_1,
            )
            in_flight.pop()
            return response

        client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
        datasource = _datasource(client, max_pages=2)
        result, _state = await _acquire(datasource)
        assert peak[0] == 1

    @pytest.mark.asyncio
    async def test_a18_bearer_token_only_in_authorization_header(self) -> None:
        """A18: the bearer token travels only in the Authorization header."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(stix_domain_name()),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is None
        recorded = server.requests[0]
        assert recorded.headers.get("authorization") == f"Bearer {BEARER_TOKEN}"
        assert BEARER_TOKEN not in recorded.url
        assert "token" not in recorded.query

    @pytest.mark.asyncio
    async def test_a19_public_collection_has_no_authorization_header(self) -> None:
        """A19: a public collection sends no Authorization header."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(stix_domain_name()),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client_for(server.handler()), bearer_token=None)
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert "authorization" not in server.requests[0].headers

    @pytest.mark.asyncio
    async def test_a20_collection_reference_is_credential_free(self) -> None:
        """A20: source_reference is credential-free with no incremental state."""
        server = RecordedTaxiiServer(
            [
                (
                    taxii_response(
                        taxii_envelope(
                            stix_domain_name(), more=True, next_token=NEXT_2
                        ),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                ),
                (
                    taxii_response(
                        taxii_envelope(stix_indicator(), more=False),
                        first=DATE_ADDED_2,
                        last=DATE_ADDED_2,
                    ),
                    NEXT_2,
                ),
            ]
        )
        datasource = _datasource(client_for(server.handler()))
        result, _state = await _acquire(datasource)
        assert result.error is None
        assert result.context.source_reference == TAXII_OBJECTS_URL
        assert "?" not in result.context.source_reference
        assert NEXT_2 not in result.context.source_reference
        assert BEARER_TOKEN not in result.context.source_reference
