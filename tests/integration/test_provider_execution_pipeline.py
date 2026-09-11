# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL vertical-slice coverage for provider execution (PR 19B).

One deterministic synthetic provider path exercises the full pipeline:

    persisted DOMAIN root
        -> queued GOOGLE_PUBLIC_DNS work
        -> real GooglePublicDnsProvider over an in-process ASGI virtual
           upstream (host allowlist, no public internet)
        -> normalized DNS Evidence
        -> PR 18B deterministic extraction
        -> PR 18C atomic persistence
        -> ProviderExecutionOutcome and persisted timeline events
"""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select

from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.investigation_timeline import (
    UnitOfWorkInvestigationTimelineSink,
)
from agentic_threat_investigator.app.orchestration import (
    AnalysisOutcome,
    FakeAnalysisExecutor,
    InvestigationGraphContextMismatchError,
    build_legacy_investigation_graph,
    enqueue_provider_work,
)
from agentic_threat_investigator.app.orchestration.composition import (
    build_provider_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.dispatcher import LocalTaskDispatcher
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
    ProviderWorkExecutor,
    UowEntityReader,
)
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceService,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    ProviderExecutionOutcome,
    ProviderExecutionStatus,
    ProviderWorkItem,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.models import (
    EntityRow,
    EvidenceRow,
    RelationshipObservationRow,
    RelationshipRow,
)
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from tests.support.orchestration_fixtures import (
    NoopStatusWriter,
    NoopTransitionService,
    empty_context_loader,
)


def _sufficient_analysis_executor() -> FakeAnalysisExecutor:
    """Return a fake analyst that declares SUFFICIENT once.

    The analyze node defaults the analyzed evidence set to the complete
    current evidence, so a single SUFFICIENT outcome stops the coordinator
    after the provider pipeline drains without authorizing pivots.
    """
    return FakeAnalysisExecutor(
        (
            AnalysisOutcome(
                assessment_id=uuid4(),
                disposition=AnalysisDisposition.SUFFICIENT,
                investigation_version=1,
            ),
        )
    )


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
]

_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
_GOOGLE_DNS_HOST = "dns.google"
_DOMAIN_VALUE = "malicious-domain.test"
_RESOLVED_IP = "203.0.113.42"
_DNS_ACCEPT = "application/json, application/dns-json"


def _dns_a_response() -> dict[str, object]:
    """Build the synthetic A-record response for the canonical trajectory."""
    return {
        "Status": 0,
        "TC": False,
        "RD": True,
        "RA": True,
        "Question": [{"name": f"{_DOMAIN_VALUE}.", "type": 1}],
        "Answer": [
            {
                "name": f"{_DOMAIN_VALUE}.",
                "type": 1,
                "TTL": 300,
                "data": _RESOLVED_IP,
            }
        ],
    }


def _dns_empty_response() -> dict[str, object]:
    """Build an empty NOERROR response for the remaining RR types."""
    return {"Status": 0, "Answer": []}


def _build_stub_app() -> FastAPI:
    """Build the synthetic upstream FastAPI stub application."""
    app = FastAPI()
    app.state.dns_responses = {}
    responses = app.state.dns_responses

    @app.get("/resolve")
    async def dns_resolve(
        request: Request,
        name: str = Query(...),
        rrtype: str = Query(default="", alias="type"),
    ) -> Response:
        """Serve synthetic Google DNS JSON responses for /resolve."""
        assert (
            "AgenticThreatInvestigator" in request.headers["User-Agent"]
        )  # Ruff S-family not enabled; Bandit B101 skipped in pyproject.toml
        assert (
            request.headers["Accept"] == _DNS_ACCEPT
        )  # Ruff S-family not enabled; Bandit B101 skipped in pyproject.toml
        entry = responses.get((name, rrtype))
        assert entry is not None, (
            f"no stub DNS response for {(name, rrtype)!r}"
        )  # Ruff S-family not enabled; Bandit B101 skipped in pyproject.toml
        return JSONResponse(content=entry)

    app.state.dns_responses = responses
    return app


class HostAllowlistASGITransport(httpx.AsyncBaseTransport):
    """Fail-closed guard rejecting unapproved hosts before the ASGI app."""

    def __init__(self, app: FastAPI, *, allowed_hosts: set[str]) -> None:
        self._asgi_transport = httpx.ASGITransport(app=app)
        self._allowed_hosts = allowed_hosts

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Reject unapproved hosts, then delegate to the ASGI transport."""
        host = request.url.host
        if host not in self._allowed_hosts:
            raise RuntimeError(
                f"request to unapproved host {host!r}; allowed={self._allowed_hosts}"
            )
        return await self._asgi_transport.handle_async_request(request)

    async def aclose(self) -> None:
        """Close the wrapped ASGI transport."""
        await self._asgi_transport.aclose()


async def _no_op_sleep(_: float) -> None:
    """Non-blocking async sleep replacement for deterministic tests."""


def _zero_jitter() -> float:
    """Deterministic zero-offset jitter callable."""
    return 0.5


async def seed_root_investigation(
    uow: PostgresUnitOfWork,
) -> tuple[UUID, Entity, int]:
    """Persist one RUNNING investigation whose durable root is the DOMAIN entity.

    The root Entity UUID is allocated once and reused: the canonical DOMAIN
    Entity is persisted with that UUID and the Investigation records the same
    UUID in ``root_entity_ids``, both in one explicit UnitOfWork transaction
    committed exactly once.
    """
    investigation_id = uuid4()
    root_id = uuid4()
    root = await uow.entities.upsert(
        Entity(id=root_id, type=EntityType.DOMAIN, value=_DOMAIN_VALUE)
    )
    created = await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[root_id],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_FIXED_TS,
        )
    )
    await uow.commit()
    return investigation_id, root, created.version


async def test_dns_vertical_slice(
    uow_factory: Callable[[], PostgresUnitOfWork],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The full provider -> extraction -> persistence -> timeline pipeline.

    The production graph executes through ``LocalTaskDispatcher``: a
    recording spy records the queued work item at the dispatch boundary and
    then delegates to the real dispatcher, proving the factory path

        queued ProviderWorkItem -> LangGraph -> LocalTaskDispatcher
        -> ProviderWorkExecutor -> synthetic provider HTTP
        -> Evidence/extraction/persistence -> ProviderExecutionOutcome
    """
    dispatched: list[ProviderWorkItem] = []
    real_dispatch = LocalTaskDispatcher.dispatch

    async def tracking_dispatch(
        self: LocalTaskDispatcher, work_item: ProviderWorkItem
    ) -> ProviderExecutionOutcome:
        dispatched.append(work_item)
        return await real_dispatch(self, work_item)

    monkeypatch.setattr(LocalTaskDispatcher, "dispatch", tracking_dispatch)
    app = _build_stub_app()
    app.state.dns_responses.update(
        {
            (_DOMAIN_VALUE, "A"): _dns_a_response(),
            (_DOMAIN_VALUE, "AAAA"): _dns_empty_response(),
            (_DOMAIN_VALUE, "CNAME"): _dns_empty_response(),
            (_DOMAIN_VALUE, "MX"): _dns_empty_response(),
            (_DOMAIN_VALUE, "NS"): _dns_empty_response(),
            (_DOMAIN_VALUE, "TXT"): _dns_empty_response(),
            (_DOMAIN_VALUE, "SOA"): _dns_empty_response(),
        }
    )

    transport = HostAllowlistASGITransport(app, allowed_hosts={_GOOGLE_DNS_HOST})
    async with httpx.AsyncClient(transport=transport) as client:
        http = ProviderHttpClient(
            client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
        )
        provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)

        async with uow_factory() as uow:
            investigation_id, root, created_version = await seed_root_investigation(uow)

        # PR 19 provider-execution mechanics: the legacy graph drains the
        # queue and ends (the strict PR 21 analyze node requires real
        # Analysis persistence, which this mechanics test does not exercise).
        executor = ProviderWorkExecutor(
            entity_reader=UowEntityReader(uow_factory),
            provider_registry={SourceId.GOOGLE_PUBLIC_DNS: provider},
            extractor=extract,
            persistence_service=ProviderObservationPersistenceService(uow_factory),
            timeline_service=UnitOfWorkInvestigationTimelineSink(uow_factory),
            context=ProviderExecutionContext(
                investigation_id=investigation_id,
                clock=lambda: _FIXED_TS,
            ),
        )
        dispatcher = LocalTaskDispatcher(executor)
        graph = build_legacy_investigation_graph(dispatcher)

        assert root.id is not None
        work_item = ProviderWorkItem(
            provider=SourceId.GOOGLE_PUBLIC_DNS, entity_id=root.id, depth=0
        )
        state = enqueue_provider_work(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[root.id],
                objective="Assess the root indicator.",
                budget=default_investigation_budget(),
                started_at=_FIXED_TS,
                version=created_version,
            ),
            [work_item],
        )
        result = await graph.ainvoke({"investigation": state})
        recorded_state = result["investigation"]
        outcome = recorded_state.last_provider_outcome
        assert outcome is not None
        # The queued item crossed the dispatch boundary exactly once.
        assert dispatched == [work_item]
        assert outcome.status is ProviderExecutionStatus.SUCCEEDED
        assert len(outcome.evidence_ids) == 1
        assert len(outcome.discovered_entity_ids) == 1
        assert len(outcome.relationship_ids) == 1

        assert recorded_state.budget.provider_calls_used == 1
        assert list(recorded_state.evidence_ids) == list(outcome.evidence_ids)
        assert list(recorded_state.relationship_ids) == list(outcome.relationship_ids)
        # Discovered entities are recorded, never automatically scheduled.
        assert recorded_state.pending_provider_work == []

        evidence_id = outcome.evidence_ids[0]
        ip_entity_id = outcome.discovered_entity_ids[0]
        relationship_id = outcome.relationship_ids[0]

        async with uow_factory() as reader:
            assert reader.session is not None
            assert await reader.session.get(EvidenceRow, evidence_id) is not None
            ip_entity = await reader.session.get(EntityRow, ip_entity_id)
            assert ip_entity is not None
            assert ip_entity.entity_type == EntityType.IP_ADDRESS.value
            assert ip_entity.canonical_value == _RESOLVED_IP
            assert (
                await reader.session.get(RelationshipRow, relationship_id) is not None
            )

            observations = await reader.session.execute(
                select(RelationshipObservationRow).where(
                    RelationshipObservationRow.relationship_id == relationship_id,
                    RelationshipObservationRow.evidence_id == evidence_id,
                )
            )
            assert len(observations.scalars().all()) == 1

            # The durable Investigation references the actual root Entity.
            durable = await reader.investigations.get_by_id(investigation_id)
            assert durable is not None
            assert durable.root_entity_ids == [root.id]
            assert recorded_state.root_entity_ids == [root.id]
            assert work_item.entity_id == root.id

            timeline = await reader.timeline_events.list_by_investigation(
                investigation_id
            )
            assert [event.type for event in timeline] == [
                InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
                InvestigationTimelineEventType.EVIDENCE_PERSISTED,
                InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
            ]
            assert InvestigationTimelineEventType.PROVIDER_WORK_FAILED not in [
                event.type for event in timeline
            ]
            started = timeline[0]
            assert started.provider == SourceId.GOOGLE_PUBLIC_DNS
            assert started.target_entity_id == root.id
            persisted_event = timeline[1]
            assert persisted_event.evidence_ids == (evidence_id,)
            assert persisted_event.entity_ids == (root.id, ip_entity_id)
            assert persisted_event.relationship_ids == (relationship_id,)
            completed = timeline[2]
            assert completed.evidence_ids == (evidence_id,)


async def test_dns_missing_root_never_calls_provider(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A work item for a missing target fails without provider invocation."""

    class _NoHttpTransport(httpx.AsyncBaseTransport):
        """Fail the test if any provider HTTP I/O is attempted."""

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            raise RuntimeError("provider HTTP I/O must not occur")

    async with httpx.AsyncClient(transport=_NoHttpTransport()) as client:
        http = ProviderHttpClient(client=client)
        provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
        async with uow_factory() as uow:
            investigation_id, _root, created_version = await seed_root_investigation(
                uow
            )

        graph = build_provider_investigation_graph(
            uow_factory=uow_factory,
            provider_registry={SourceId.GOOGLE_PUBLIC_DNS: provider},
            context=ProviderExecutionContext(
                investigation_id=investigation_id,
                clock=lambda: _FIXED_TS,
            ),
            analysis_executor=_sufficient_analysis_executor(),
            context_loader=empty_context_loader(),
            transition_service=NoopTransitionService(),
            status_writer=NoopStatusWriter(),
        )
        missing_work = ProviderWorkItem(
            provider=SourceId.GOOGLE_PUBLIC_DNS, entity_id=uuid4(), depth=0
        )
        state = enqueue_provider_work(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[uuid4()],
                objective="Assess the root indicator.",
                budget=default_investigation_budget(),
                started_at=_FIXED_TS,
                version=created_version,
            ),
            [missing_work],
        )
        result = await graph.ainvoke({"investigation": state})
        recorded_state = result["investigation"]
        outcome = recorded_state.last_provider_outcome
        assert outcome is not None
        assert outcome.status is not ProviderExecutionStatus.SUCCEEDED
        assert outcome.error is not None
        assert outcome.error.code == "target_not_found"
        assert recorded_state.budget.provider_calls_used == 1

        async with uow_factory() as reader:
            timeline = await reader.timeline_events.list_by_investigation(
                investigation_id
            )
            assert [event.type for event in timeline] == [
                InvestigationTimelineEventType.PROVIDER_WORK_FAILED
            ]
            failed = timeline[0]
            assert failed.error_code == "target_not_found"


async def test_context_mismatch_fails_before_any_persistence(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A graph bound to investigation A rejects state B before every I/O seam.

    The mismatch is raised during graph initialization, so no provider HTTP,
    extraction, persistence, or timeline activity may occur. Durable absence
    is verified with a fresh UoW: no Evidence, timeline event, Relationship,
    or RelationshipObservation exists for either investigation, and neither
    durable Investigation operational state was mutated.
    """
    from agentic_threat_investigator.app.orchestration import (
        InvestigationGraphContextMismatchError,
        build_provider_investigation_graph,
    )

    class _ExplodingTransport(httpx.AsyncBaseTransport):
        """Fail the test if any provider HTTP I/O is attempted."""

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            raise RuntimeError("provider HTTP I/O must not occur for a mismatch")

    async with httpx.AsyncClient(transport=_ExplodingTransport()) as client:
        http = ProviderHttpClient(client=client)
        provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)

        async with uow_factory() as uow:
            investigation_a, root, created_version = await seed_root_investigation(uow)
            investigation_b = uuid4()
            await uow.investigations.create(
                InvestigationState(
                    investigation_id=investigation_b,
                    status=InvestigationStatus.RUNNING,
                    trigger_type=InvestigationTriggerType.MANUAL,
                    root_entity_ids=[root.id or uuid4()],
                    objective="Assess the root indicator.",
                    budget=default_investigation_budget(),
                    started_at=_FIXED_TS,
                )
            )
            await uow.commit()

        graph = build_provider_investigation_graph(
            uow_factory=uow_factory,
            provider_registry={SourceId.GOOGLE_PUBLIC_DNS: provider},
            context=ProviderExecutionContext(
                investigation_id=investigation_a,
                clock=lambda: _FIXED_TS,
            ),
            analysis_executor=_sufficient_analysis_executor(),
            context_loader=empty_context_loader(),
            transition_service=NoopTransitionService(),
            status_writer=NoopStatusWriter(),
        )
        assert root.id is not None
        work_item = ProviderWorkItem(
            provider=SourceId.GOOGLE_PUBLIC_DNS, entity_id=root.id, depth=0
        )
        # The graph is bound to investigation A but is invoked with state B.
        state_b = enqueue_provider_work(
            InvestigationState(
                investigation_id=investigation_b,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[root.id],
                objective="Assess the root indicator.",
                budget=default_investigation_budget(),
                started_at=_FIXED_TS,
                version=created_version,
            ),
            [work_item],
        )
        with pytest.raises(InvestigationGraphContextMismatchError):
            await graph.ainvoke({"investigation": state_b})

        # Durable absence: no Evidence, timeline event, Relationship, or
        # RelationshipObservation was created for either investigation, and
        # neither durable Investigation operational state was mutated.
        async with uow_factory() as reader:
            for investigation_id in (investigation_a, investigation_b):
                evidence_count = await reader.session.execute(  # type: ignore[union-attr]
                    select(EvidenceRow).where(
                        EvidenceRow.investigation_id == investigation_id
                    )
                )
                assert len(evidence_count.scalars().all()) == 0
                timeline = await reader.timeline_events.list_by_investigation(
                    investigation_id
                )
                assert timeline == []
            relationship_count = await reader.session.execute(  # type: ignore[union-attr]
                select(RelationshipRow)
            )
            assert len(relationship_count.scalars().all()) == 0
            observation_count = await reader.session.execute(  # type: ignore[union-attr]
                select(RelationshipObservationRow)
            )
            assert len(observation_count.scalars().all()) == 0
            # Neither durable Investigation operational state was mutated by
            # the rejected invocation.
            for investigation_id in (investigation_a, investigation_b):
                durable = await reader.investigations.get_by_id(investigation_id)
                assert durable is not None
                assert durable.last_provider_outcome is None
                assert durable.completed_provider_work == []
                assert durable.budget.provider_calls_used == 0


async def test_local_dispatcher_binding_rejects_other_investigation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A local dispatcher preserves its production executor's binding.

    A caller who wraps a bound ``ProviderWorkExecutor`` in
    ``LocalTaskDispatcher`` and passes only that dispatcher to the generic
    graph gets automatic binding without an explicit expected investigation
    ID. Invoking the graph with state B raises the typed mismatch error before
    dispatch, provider HTTP, or database work, and durable absence is verified
    with a fresh UoW.
    """
    from agentic_threat_investigator.app.extraction.extractor import extract
    from agentic_threat_investigator.app.investigation_timeline import (
        UnitOfWorkInvestigationTimelineSink,
    )

    class _ExplodingTransport(httpx.AsyncBaseTransport):
        """Fail the test if any provider HTTP I/O is attempted."""

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            raise RuntimeError(
                "provider HTTP I/O must not occur for a binding mismatch"
            )

    async with httpx.AsyncClient(transport=_ExplodingTransport()) as client:
        http = ProviderHttpClient(client=client)
        provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)

        async with uow_factory() as uow:
            investigation_a, root, created_version = await seed_root_investigation(uow)
            investigation_b = uuid4()
            await uow.investigations.create(
                InvestigationState(
                    investigation_id=investigation_b,
                    status=InvestigationStatus.RUNNING,
                    trigger_type=InvestigationTriggerType.MANUAL,
                    root_entity_ids=[root.id or uuid4()],
                    objective="Assess the root indicator.",
                    budget=default_investigation_budget(),
                    started_at=_FIXED_TS,
                )
            )
            await uow.commit()

        # Explicit local composition without an expected ID: the dispatcher
        # wraps the production executor and exposes its authoritative binding,
        # which the generic graph adopts automatically.
        executor = ProviderWorkExecutor(
            entity_reader=UowEntityReader(uow_factory),
            provider_registry={SourceId.GOOGLE_PUBLIC_DNS: provider},
            extractor=extract,
            persistence_service=ProviderObservationPersistenceService(uow_factory),
            timeline_service=UnitOfWorkInvestigationTimelineSink(uow_factory),
            context=ProviderExecutionContext(
                investigation_id=investigation_a,
                clock=lambda: _FIXED_TS,
            ),
        )
        dispatcher = LocalTaskDispatcher(executor)
        graph = build_legacy_investigation_graph(dispatcher)

        assert root.id is not None
        work_item = ProviderWorkItem(
            provider=SourceId.GOOGLE_PUBLIC_DNS, entity_id=root.id, depth=0
        )
        state_b = enqueue_provider_work(
            InvestigationState(
                investigation_id=investigation_b,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[root.id],
                objective="Assess the root indicator.",
                budget=default_investigation_budget(),
                started_at=_FIXED_TS,
                version=created_version,
            ),
            [work_item],
        )
        with pytest.raises(InvestigationGraphContextMismatchError):
            await graph.ainvoke({"investigation": state_b})

        # Durable absence: no Evidence, timeline event, Relationship, or
        # RelationshipObservation was created, and neither durable
        # Investigation operational state was mutated.
        async with uow_factory() as reader:
            for investigation_id in (investigation_a, investigation_b):
                evidence_count = await reader.session.execute(  # type: ignore[union-attr]
                    select(EvidenceRow).where(
                        EvidenceRow.investigation_id == investigation_id
                    )
                )
                assert len(evidence_count.scalars().all()) == 0
                timeline = await reader.timeline_events.list_by_investigation(
                    investigation_id
                )
                assert timeline == []
            relationship_count = await reader.session.execute(  # type: ignore[union-attr]
                select(RelationshipRow)
            )
            assert len(relationship_count.scalars().all()) == 0
            observation_count = await reader.session.execute(  # type: ignore[union-attr]
                select(RelationshipObservationRow)
            )
            assert len(observation_count.scalars().all()) == 0
            for investigation_id in (investigation_a, investigation_b):
                durable = await reader.investigations.get_by_id(investigation_id)
                assert durable is not None
                assert durable.last_provider_outcome is None
                assert durable.completed_provider_work == []
                assert durable.budget.provider_calls_used == 0
