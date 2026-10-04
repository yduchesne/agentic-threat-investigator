# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E publication-safe checkpoint matrix (T33E-C01..C20).

Runs the real ``CollectionDatasourceEvidenceProducer`` seam over the real
TAXII acquirer/datasource (``httpx.MockTransport`` TAXII 2.1 boundary), the
real PR 33A parser, the real STIX 2.1 converter registry, and the real PR
33E progress committer over an in-memory UnitOfWork fake with a
deterministic checkpoint store. These tests prove the authoritative failure
ordering (PR 33E section 3.7/Step 22): the durable checkpoint advances only
after successful publication, never before; publication-success +
checkpoint-failure permits replay; cancellation leaves the checkpoint
unchanged; TAXII date-added semantics drive the candidate while STIX/ATI
timestamps never do; and the opaque ``next`` token is never a durable
checkpoint value. No database, broker, or network is involved.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self, cast

import httpx
import pytest

from agentic_threat_investigator.app.datasource_evidence_producer import (
    CollectionDatasourceEvidenceProducer,
    DatasourceProducerOutcome,
)
from agentic_threat_investigator.app.datasource_provider import (
    CollectionSemanticAcquirer,
)
from agentic_threat_investigator.app.datasource_semantics import (
    CollectionAcquisitionProgress,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceConsumerId,
    InMemoryEvidenceLog,
)
from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceCheckpoint,
    DatasourceCheckpointConflictError,
    UnitOfWork,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceExecutionEventType,
    DatasourceId,
    DatasourceLogEvent,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
    build_stix21_conversion_registry,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    Stix21Object,
)
from agentic_threat_investigator.infrastructure.datasources.taxii21 import (
    TAXII_CHECKPOINT_KIND,
    Taxii21Datasource,
    format_taxii_timestamp,
)
from agentic_threat_investigator.infrastructure.providers.composition import (
    build_taxii_checkpoint_committer,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from tests.support.provider_http import no_op_sleep, zero_jitter
from tests.support.stix21_fixtures import stix_domain_name
from tests.support.taxii_fixtures import (
    BEARER_TOKEN,
    DATE_ADDED_1,
    DATE_ADDED_2,
    NEXT_1,
    TAXII_API_ROOT,
    TAXII_COLLECTION_ID,
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

_CANDIDATE_1 = format_taxii_timestamp(_OCCURRED_AT)
_CANDIDATE_2 = format_taxii_timestamp(datetime(2026, 7, 2, 0, 0, 0, tzinfo=UTC))


class _CheckpointStore:
    """In-memory compare-and-advance checkpoint store mirroring the contract."""

    def __init__(self) -> None:
        """Start with an empty store and no injected faults."""
        self.rows: dict[tuple[str, str], DatasourceCheckpoint] = {}
        self.fail_get = False
        self.fail_advance = False

    async def get(
        self, *, datasource_id: str, checkpoint_kind: str
    ) -> DatasourceCheckpoint | None:
        """Read the current row or raise an injected read failure."""
        if self.fail_get:
            raise RuntimeError("injected checkpoint read failure")
        return self.rows.get((datasource_id, checkpoint_kind))

    async def advance(
        self,
        *,
        datasource_id: str,
        checkpoint_kind: str,
        expected_value: str | None,
        new_value: str,
        updated_at: datetime,
    ) -> DatasourceCheckpoint:
        """Compare-and-advance with the stored-function conflict contract."""
        if self.fail_advance:
            raise RuntimeError("injected checkpoint advance failure")
        current = self.rows.get((datasource_id, checkpoint_kind))
        if current is None:
            if expected_value is not None:
                raise DatasourceCheckpointConflictError(
                    "stale first advance expectation"
                )
            row = DatasourceCheckpoint(
                datasource_id=datasource_id,
                checkpoint_kind=checkpoint_kind,
                checkpoint_value=new_value,
                updated_at=updated_at,
                version=1,
            )
            self.rows[(datasource_id, checkpoint_kind)] = row
            return row
        if current.checkpoint_value is None or expected_value is None:
            raise DatasourceCheckpointConflictError("stale advance expectation")
        if current.checkpoint_value != expected_value:
            raise DatasourceCheckpointConflictError("stale advance expectation")
        if current.checkpoint_value == new_value:
            return current
        row = DatasourceCheckpoint(
            datasource_id=datasource_id,
            checkpoint_kind=checkpoint_kind,
            checkpoint_value=new_value,
            updated_at=updated_at,
            version=current.version + 1,
        )
        self.rows[(datasource_id, checkpoint_kind)] = row
        return row


class _Logs:
    """In-memory append-only datasource-log fake with failure injection."""

    def __init__(self, state: "_State") -> None:
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

    def rollback(self) -> None:
        """Drop the pending append."""
        self.state.pending_append = None


class _State:
    """Shared producer-test state: durable events and transaction probes."""

    def __init__(self) -> None:
        """Start with an empty durable log and no open transaction."""
        self.events: list[DatasourceLogEvent] = []
        self.pending_append: DatasourceLogEvent | None = None
        self.commits = 0
        self.active = 0
        self.checkpoints = _CheckpointStore()
        self.fail_on_event_type: DatasourceExecutionEventType | None = None

    @property
    def types(self) -> list[str]:
        """Return the durable event types in append order."""
        return [event.event_type.value for event in self.events]


class _Uow(UnitOfWork):
    """Deterministic in-memory UnitOfWork fake exposing the checkpoint store."""

    def __init__(self, state: _State) -> None:
        """Bind the fake UoW to the shared state."""
        self.state = state
        self._logs = _Logs(state)
        self.datasource_logs = self._logs  # type: ignore[assignment]
        self.datasource_checkpoints = state.checkpoints  # type: ignore[assignment]

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


def _uow_factory(state: _State) -> Callable[[], UnitOfWork]:
    """Return a UoW factory bound to the shared probe state."""
    return lambda: _Uow(state)


def _taxii_client(
    pages: list[tuple[Any, str | None]],
) -> httpx.AsyncClient:
    """Build a mock client serving one deterministic TAXII page sequence."""
    server = RecordedTaxiiServer(cast(list[tuple[httpx.Response, str | None]], pages))
    return client_for(server.handler())


def _datasource(
    client: httpx.AsyncClient,
    *,
    checkpoint_reader: Callable[[], Any] | None = None,
    initial_added_after: str | None = None,
) -> Taxii21Datasource:
    """Build the real TAXII acquirer over the real bounded HTTP client."""
    http = ProviderHttpClient(
        client=client,
        policy=ProviderHttpPolicy(max_retries=0, base_delay_seconds=0.01),
        sleep=no_op_sleep,
        jitter_fn=zero_jitter,
    )
    return Taxii21Datasource(
        http,
        api_root_url=TAXII_API_ROOT,
        collection_id=TAXII_COLLECTION_ID,
        bearer_token=BEARER_TOKEN,
        checkpoint_reader=checkpoint_reader,
        initial_added_after=initial_added_after,
        clock=lambda: _OCCURRED_AT,
    )


def _producer(
    state: _State,
    *,
    acquirer: CollectionSemanticAcquirer[Stix21Object],
    publisher: Any,
    committer: Callable[..., Any] | None = None,
) -> CollectionDatasourceEvidenceProducer[Stix21Object]:
    """Build one TAXII collection producer over the injected seams and state."""
    return CollectionDatasourceEvidenceProducer(
        definition=_DEFINITION,
        acquirer=acquirer,
        registry=build_stix21_conversion_registry(),
        publisher=publisher,
        uow_factory=_uow_factory(state),
        clock=lambda: _OCCURRED_AT,
        progress_committer=committer
        or build_taxii_checkpoint_committer(
            _uow_factory(state),
            checkpoint_kind=TAXII_CHECKPOINT_KIND,
            clock=lambda: _OCCURRED_AT,
        ),
    )


class TestCheckpointAdvancementOrdering:
    """T33E-C04..C11: the publication-safe advancement ordering."""

    @pytest.mark.asyncio
    async def test_c04_successful_publish_advances_candidate(self) -> None:
        """C04: a successful publish leads to the candidate being committed."""
        state = _State()
        client = _taxii_client(
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
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        row = state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)]
        assert row.checkpoint_value == format_taxii_timestamp(
            datetime(2026, 7, 1, tzinfo=UTC)
        )
        assert state.types == [
            "started",
            "acquired",
            "decoded",
            "converted",
            "published",
            "completed",
        ]

    @pytest.mark.asyncio
    async def test_c05_http_failure_never_advances(self) -> None:
        """C05: an HTTP failure leaves the checkpoint absent/unchanged."""
        state = _State()
        client = _taxii_client(
            [
                (
                    taxii_response(
                        {}, status=403, content_type="application/taxii+json"
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.FAILED
        assert outcome.error_code == "forbidden"
        assert state.checkpoints.rows == {}
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_c06_stix_parse_failure_never_advances(self) -> None:
        """C06: a STIX parse failure advances nothing."""
        state = _State()
        client = _taxii_client(
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
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.FAILED
        assert outcome.error_code == "semantic_validation_failed"
        assert state.checkpoints.rows == {}

    @pytest.mark.asyncio
    async def test_c07_conversion_failure_never_advances(self) -> None:
        """C07: a conversion failure advances nothing and never publishes."""
        from agentic_threat_investigator.app.evidence_conversion import (
            ConversionError,
            EvidenceConversionContext,
            ToEvidenceConverter,
            ToEvidenceConverterRegistry,
        )
        from agentic_threat_investigator.domain.evidence import ConvertedEvidence

        class _BadConverter(ToEvidenceConverter[Stix21Object]):
            @property
            def semantic_format(self) -> SemanticFormatId:
                return SemanticFormatId.STIX_21

            def convert(
                self,
                source: Stix21Object,
                context: EvidenceConversionContext,
            ) -> tuple[ConvertedEvidence, ...]:
                raise ConversionError("stubbed conversion failure")

        registry = ToEvidenceConverterRegistry(converters=(_BadConverter(),))

        state = _State()
        client = _taxii_client(
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
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = CollectionDatasourceEvidenceProducer(
            definition=_DEFINITION,
            acquirer=datasource,
            registry=registry,
            publisher=log.publisher(),
            uow_factory=_uow_factory(state),
            clock=lambda: _OCCURRED_AT,
            progress_committer=build_taxii_checkpoint_committer(
                _uow_factory(state),
                checkpoint_kind=TAXII_CHECKPOINT_KIND,
                clock=lambda: _OCCURRED_AT,
            ),
        )
        with pytest.raises(ConversionError):
            await producer.produce()
        assert state.checkpoints.rows == {}
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_c08_publication_failure_never_advances(self) -> None:
        """C08: a publisher failure advances nothing and no COMPLETED is appended."""

        class _FailingPublisher:
            async def publish(self, messages: tuple[Any, ...]) -> Any:
                raise RuntimeError("injected publication failure")

        state = _State()
        client = _taxii_client(
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
        datasource = _datasource(client)
        producer = _producer(state, acquirer=datasource, publisher=_FailingPublisher())
        with pytest.raises(RuntimeError):
            await producer.produce()
        assert state.checkpoints.rows == {}
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_c09_published_lifecycle_failure_never_advances(self) -> None:
        """C09: a PUBLISHED lifecycle append failure advances nothing."""
        state = _State()
        state.fail_on_event_type = DatasourceExecutionEventType.PUBLISHED
        client = _taxii_client(
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
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        with pytest.raises(RuntimeError):
            await producer.produce()
        assert state.checkpoints.rows == {}
        assert "completed" not in state.types

    @pytest.mark.asyncio
    async def test_c10_checkpoint_db_failure_after_publish_allows_replay(self) -> None:
        """C10: a checkpoint failure after publish fails the call, no durable advance."""
        state = _State()
        client = _taxii_client(
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
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        # Arm both the checkpoint read and advance to fail: the committer's
        # first repository interaction after PUBLISHED is the advance.
        state.checkpoints.fail_advance = True
        with pytest.raises(RuntimeError):
            await producer.produce()
        assert state.checkpoints.rows == {}
        assert "completed" not in state.types
        # The broker data is not rolled back: exactly one publish happened.
        consumer = log.consumer(EvidenceConsumerId("c10-probe"))
        batch = await consumer.poll(500)
        assert len(batch.records) == 1

    @pytest.mark.asyncio
    async def test_c11_completed_append_failure_keeps_checkpoint_no_republish(
        self,
    ) -> None:
        """C11: a COMPLETED append failure keeps the checkpoint; no republish."""
        state = _State()
        state.fail_on_event_type = DatasourceExecutionEventType.COMPLETED
        client = _taxii_client(
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
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        with pytest.raises(RuntimeError):
            await producer.produce()
        row = state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)]
        assert row.checkpoint_value == format_taxii_timestamp(
            datetime(2026, 7, 1, tzinfo=UTC)
        )
        consumer = log.consumer(EvidenceConsumerId("c11-probe"))
        batch = await consumer.poll(500)
        assert len(batch.records) == 1


class TestCheckpointValueSemantics:
    """T33E-C12..C20: value, idempotency, and source-of-truth semantics."""

    @pytest.mark.asyncio
    async def test_c12_older_candidate_is_rejected(self) -> None:
        """C12: a candidate older than the durable row never moves backward."""
        state = _State()
        state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)] = (
            DatasourceCheckpoint(
                datasource_id="opencti-collection",
                checkpoint_kind=TAXII_CHECKPOINT_KIND,
                checkpoint_value=_CANDIDATE_2,
                updated_at=_OCCURRED_AT,
                version=2,
            )
        )
        committer = build_taxii_checkpoint_committer(
            _uow_factory(state),
            checkpoint_kind=TAXII_CHECKPOINT_KIND,
            clock=lambda: _OCCURRED_AT,
        )
        with pytest.raises(DatasourceCheckpointConflictError):
            await committer(
                _DEFINITION.datasource_id,
                CollectionAcquisitionProgress(
                    kind=TAXII_CHECKPOINT_KIND,
                    previous=_CANDIDATE_1,
                    candidate=_CANDIDATE_1,
                ),
            )

    @pytest.mark.asyncio
    async def test_c13_equal_candidate_is_idempotent_noop(self) -> None:
        """C13: advancing to the current value is an idempotent no-op."""
        state = _State()
        state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)] = (
            DatasourceCheckpoint(
                datasource_id="opencti-collection",
                checkpoint_kind=TAXII_CHECKPOINT_KIND,
                checkpoint_value=_CANDIDATE_1,
                updated_at=_OCCURRED_AT,
                version=4,
            )
        )
        committer = build_taxii_checkpoint_committer(
            _uow_factory(state),
            checkpoint_kind=TAXII_CHECKPOINT_KIND,
            clock=lambda: _OCCURRED_AT,
        )
        await committer(
            _DEFINITION.datasource_id,
            CollectionAcquisitionProgress(
                kind=TAXII_CHECKPOINT_KIND,
                previous=_CANDIDATE_1,
                candidate=_CANDIDATE_1,
            ),
        )
        row = state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)]
        assert row.version == 4

    @pytest.mark.asyncio
    async def test_c14_concurrent_stale_expectation_conflicts(self) -> None:
        """C14: a stale expected value deterministically conflicts, no overwrite."""
        state = _State()
        state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)] = (
            DatasourceCheckpoint(
                datasource_id="opencti-collection",
                checkpoint_kind=TAXII_CHECKPOINT_KIND,
                checkpoint_value=_CANDIDATE_2,
                updated_at=_OCCURRED_AT,
                version=2,
            )
        )
        committer = build_taxii_checkpoint_committer(
            _uow_factory(state),
            checkpoint_kind=TAXII_CHECKPOINT_KIND,
            clock=lambda: _OCCURRED_AT,
        )
        with pytest.raises(DatasourceCheckpointConflictError):
            await committer(
                _DEFINITION.datasource_id,
                CollectionAcquisitionProgress(
                    kind=TAXII_CHECKPOINT_KIND,
                    previous=_CANDIDATE_1,
                    candidate=_CANDIDATE_1,
                ),
            )
        row = state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)]
        assert row.checkpoint_value == _CANDIDATE_2
        assert row.version == 2

    @pytest.mark.asyncio
    async def test_c15_empty_page_no_safe_signal_leaves_cursor(self) -> None:
        """C15: an empty page proposes no advancement beyond the starting value."""
        state = _State()
        client = _taxii_client(
            [(taxii_response(taxii_envelope(), first=None, last=None), None)]
        )
        durable = format_taxii_timestamp(datetime(2026, 6, 1, tzinfo=UTC))

        async def _reader() -> DatasourceCheckpoint | None:
            return DatasourceCheckpoint(
                datasource_id="opencti-collection",
                checkpoint_kind=TAXII_CHECKPOINT_KIND,
                checkpoint_value=durable,
                updated_at=_OCCURRED_AT,
                version=1,
            )

        datasource = _datasource(client, checkpoint_reader=_reader)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        row = state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)]
        assert row.checkpoint_value == durable
        assert row.version == 1

    @pytest.mark.asyncio
    async def test_c17_next_token_never_persisted(self) -> None:
        """C17: the opaque next token is never the durable checkpoint value."""
        state = _State()
        client = _taxii_client(
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
                        taxii_envelope(stix_domain_name()),
                        first=DATE_ADDED_2,
                        last=DATE_ADDED_2,
                    ),
                    NEXT_1,
                ),
            ]
        )
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        row = state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)]
        from agentic_threat_investigator.infrastructure.datasources.taxii21 import (
            canonicalize_taxii_timestamp,
        )

        assert row.checkpoint_value == format_taxii_timestamp(
            canonicalize_taxii_timestamp(DATE_ADDED_2)
        )
        assert NEXT_1 not in row.checkpoint_value

    @pytest.mark.asyncio
    async def test_c18_stix_modified_never_drives_checkpoint(self) -> None:
        """C18: a newer STIX modified timestamp never substitutes for date-added."""
        state = _State()
        future_modified = "2030-01-01T00:00:00Z"
        member = {
            "type": "domain-name",
            "id": "domain-name--11111111-1111-1111-1111-111111111111",
            "value": "malicious-domain.test",
            "created": "2026-01-01T00:00:00Z",
            "modified": future_modified,
        }
        client = _taxii_client(
            [
                (
                    taxii_response(
                        taxii_envelope(member),
                        first=DATE_ADDED_1,
                        last=DATE_ADDED_1,
                    ),
                    None,
                )
            ]
        )
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        row = state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)]
        assert row.checkpoint_value == format_taxii_timestamp(
            datetime(2026, 7, 1, tzinfo=UTC)
        )
        assert row.checkpoint_value != format_taxii_timestamp(
            datetime(2030, 1, 1, tzinfo=UTC)
        )

    @pytest.mark.asyncio
    async def test_c19_retrieved_at_never_drives_checkpoint(self) -> None:
        """C19: ATI retrieved_at (12:00 UTC) never drives the cursor."""
        state = _State()
        client = _taxii_client(
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
        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(state, acquirer=datasource, publisher=log.publisher())
        outcome = await producer.produce()
        assert outcome.outcome is DatasourceProducerOutcome.COMPLETED
        row = state.checkpoints.rows[("opencti-collection", TAXII_CHECKPOINT_KIND)]
        assert row.checkpoint_value == format_taxii_timestamp(
            datetime(2026, 7, 1, tzinfo=UTC)
        )
        assert row.checkpoint_value == format_taxii_timestamp(
            datetime(2026, 7, 1, tzinfo=UTC)
        )

    @pytest.mark.asyncio
    async def test_c20_cancellation_before_commit_leaves_checkpoint(self) -> None:
        """C20: cancellation before the checkpoint commit changes nothing."""

        state = _State()
        client = _taxii_client(
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

        class _CancellingCommitter:
            async def __call__(self, datasource_id: DatasourceId, progress: Any) -> Any:
                raise asyncio.CancelledError()

        import asyncio

        datasource = _datasource(client)
        log = InMemoryEvidenceLog()
        producer = _producer(
            state,
            acquirer=datasource,
            publisher=log.publisher(),
            committer=_CancellingCommitter(),
        )
        with pytest.raises(asyncio.CancelledError):
            await producer.produce()
        assert state.checkpoints.rows == {}
