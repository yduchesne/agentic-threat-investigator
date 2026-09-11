# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared deterministic fixtures for the PR 19B provider-work executor tests.

One support module owned by the executor test suite: both executor test
modules import from here and never from each other. Fixed identifiers and
timestamps keep every scenario deterministic; the fakes record calls so tests
can assert sequencing, zero-invocation, and redaction behavior.
"""

# The deterministic fakes intentionally expose a single public operation each
# (get/investigate/persist/append) and share comparable composition blocks
# with the executor test modules; these fakes are test support, not API.

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from agentic_threat_investigator.app.extraction.models import ExtractionResult
from agentic_threat_investigator.app.investigation_timeline import (
    InvestigationTimelineSink,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    EntityReader,
    ProviderExecutionContext,
    ProviderWorkExecutor,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceResult,
    ProviderObservationPersistenceService,
)
from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderError,
    ProviderErrorCode,
    ProviderResult,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import ProviderWorkItem
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipType,
)

FIXED_TS = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
"""Deterministic timestamp returned by the injected test clock."""

INVESTIGATION_ID = UUID("00000000-0000-0000-0000-0000000001a1")
DOMAIN_ENTITY_ID = UUID("00000000-0000-0000-0000-0000000002d1")
IP_VALUE = "203.0.113.42"
DNS_SOURCE = "urn:ati:source:google_public_dns"
FOREIGN_INVESTIGATION_ID = UUID("00000000-0000-0000-0000-0000000009f9")
EVIDENCE_ONE = UUID("00000000-0000-0000-0000-0000000000f1")
SECOND_EVIDENCE = UUID("00000000-0000-0000-0000-0000000000f2")
DISCOVERED_ONE = UUID("00000000-0000-0000-0000-0000000002a1")
RELATIONSHIP_ONE = UUID("00000000-0000-0000-0000-0000000003b1")


def fixed_clock() -> datetime:
    """Return the fixed deterministic test timestamp."""
    return FIXED_TS


def domain_entity(*, entity_id: UUID | None = DOMAIN_ENTITY_ID) -> Entity:
    """Build a canonical persisted domain entity."""
    return Entity(id=entity_id, type=EntityType.DOMAIN, value="malicious.test")


def dns_evidence(
    *, evidence_id: UUID | None = None, subject_id: UUID | None = DOMAIN_ENTITY_ID
) -> Evidence:
    """Build normalized DNS evidence with an A answer."""
    return Evidence(
        id=evidence_id,
        investigation_id=INVESTIGATION_ID,
        type=EvidenceType.DNS,
        subject=EntityRef(
            id=subject_id, type=EntityType.DOMAIN, value="malicious.test"
        ),
        source=SourceId.GOOGLE_PUBLIC_DNS,
        retrieved_at=FIXED_TS,
        facts={"query_name": "malicious.test", "query_type": "A", "answers": []},
    )


def null_uow_factory() -> UnitOfWork:
    """Return a placeholder factory; the fake never opens a transaction."""
    raise NotImplementedError


def provider_error() -> ProviderError:
    """Build one typed provider error."""
    return ProviderError(
        provider=SourceId.GOOGLE_PUBLIC_DNS.value,
        code=ProviderErrorCode.INVALID_RESPONSE,
        message="synthetic provider failure",
        retryable=False,
    )


class FakeEntityReader(EntityReader):
    """Deterministic entity reader backed by a fixed mapping."""

    def __init__(self, entities: dict[UUID, Entity | None]) -> None:
        self.entities = dict(entities)
        self.requested: list[UUID] = []

    async def get(self, entity_id: UUID) -> Entity | None:
        """Return the configured entity, recording the lookup."""
        self.requested.append(entity_id)
        return self.entities.get(entity_id)


class FakeEvidenceProvider(EvidenceProvider):
    """Deterministic EvidenceProvider recording calls and returning a result."""

    def __init__(
        self,
        result: ProviderResult | None = None,
        *,
        supports_target: bool = True,
        raises: BaseException | None = None,
        provider_id: str = SourceId.GOOGLE_PUBLIC_DNS.value,
    ) -> None:
        self._result = result
        self._supports_target = supports_target
        self._raises = raises
        self._provider_id = provider_id
        self.investigate_calls: list[tuple[UUID, Entity]] = []
        self.supports_calls: list[Entity] = []

    @property
    def id(self) -> str:
        """Return the configured stable source URN."""
        return self._provider_id

    def supports(self, entity: Entity) -> bool:
        """Record and report deterministic applicability."""
        self.supports_calls.append(entity)
        return self._supports_target

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Record the call and return the configured outcome."""
        self.investigate_calls.append((investigation_id, entity))
        if self._raises is not None:
            raise self._raises
        assert self._result is not None
        return self._result


class FakePersistenceService(ProviderObservationPersistenceService):
    """Persistence fake recording per-Evidence invocations."""

    def __init__(
        self,
        results: list[ProviderObservationPersistenceResult] | None = None,
        *,
        raises: Exception | None = None,
    ) -> None:
        super().__init__(uow_factory=null_uow_factory)
        self._results = results or []
        self._raises = raises
        self.calls: list[tuple[Evidence, ExtractionResult]] = []

    async def persist(
        self,
        evidence: Evidence,
        extraction: ExtractionResult,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> ProviderObservationPersistenceResult:
        """Record the call and return the configured result or raise."""
        self.calls.append((evidence, extraction))
        if self._raises is not None:
            raise self._raises
        return self._results[len(self.calls) - 1]


class FakeTimelineSink(InvestigationTimelineSink):
    """In-memory append-only timeline sink with an injected failure seam.

    ``fail_on`` raises a generic RuntimeError for the matching event type;
    ``fail_exc`` raises the injected exception for that event type instead,
    letting tests prove exact exception text never reaches logs.
    """

    def __init__(
        self,
        *,
        fail_on: InvestigationTimelineEventType | None = None,
        fail_exc: Exception | None = None,
    ) -> None:
        self.events: list[Any] = []
        self._fail_on = fail_on
        self._fail_exc = fail_exc

    async def append(self, event: Any) -> None:
        """Record the event or raise the injected failure."""
        if self._fail_on is not None and event.type is self._fail_on:
            if self._fail_exc is not None:
                raise self._fail_exc
            raise RuntimeError("injected timeline failure")
        self.events.append(event)


def persisted_result(
    evidence: Evidence,
    *,
    entity_ids: tuple[UUID, ...] = (),
    relationship_ids: tuple[UUID, ...] = (),
) -> ProviderObservationPersistenceResult:
    """Build a persistence result with the supplied committed identities."""
    recorded = evidence.model_copy(update={"id": evidence.id or uuid4()})
    entities = tuple(
        Entity(id=entity_id, type=EntityType.IP_ADDRESS, value=IP_VALUE)
        for entity_id in entity_ids
    )
    relationships = tuple(
        Relationship(
            id=relationship_id,
            source_entity_id=DOMAIN_ENTITY_ID,
            target_entity_id=entity_ids[0] if entity_ids else DOMAIN_ENTITY_ID,
            type=RelationshipType.RESOLVES_TO,
        )
        for relationship_id in relationship_ids
    )
    return ProviderObservationPersistenceResult(
        evidence=recorded,
        entities=entities,
        relationships=relationships,
        observations=(),
    )


def committed_first_observation(
    evidence: Evidence,
) -> ProviderObservationPersistenceResult:
    """Build one committed observation with Evidence, Entity, and Relationship IDs."""
    return persisted_result(
        evidence,
        entity_ids=(DISCOVERED_ONE,),
        relationship_ids=(RELATIONSHIP_ONE,),
    )


def build_executor(
    provider: FakeEvidenceProvider | None,
    entity: Entity | None | object,
    *,
    persistence: FakePersistenceService | None = None,
    timeline: FakeTimelineSink | None = None,
    extractor: Callable[[Evidence], ExtractionResult] | None = None,
) -> ProviderWorkExecutor:
    """Compose one executor from deterministic fakes."""
    if provider is None:
        registry: dict[SourceId, FakeEvidenceProvider] = {}
    else:
        registry = {SourceId.GOOGLE_PUBLIC_DNS: provider}
    return ProviderWorkExecutor(
        entity_reader=FakeEntityReader({DOMAIN_ENTITY_ID: entity}),  # type: ignore[dict-item]
        provider_registry=registry,
        extractor=extractor or (lambda _evidence: ExtractionResult()),
        persistence_service=persistence or FakePersistenceService(),
        timeline_service=timeline,
        context=ProviderExecutionContext(
            investigation_id=INVESTIGATION_ID, clock=fixed_clock
        ),
    )


def dns_work_item() -> ProviderWorkItem:
    """Return the fixed DNS work item."""
    return ProviderWorkItem(
        provider=SourceId.GOOGLE_PUBLIC_DNS, entity_id=DOMAIN_ENTITY_ID, depth=0
    )


def provider_calls_recorded(timeline: FakeTimelineSink) -> list[Any]:
    """Return the started events recorded by the sink."""
    return [
        event
        for event in timeline.events
        if event.type is InvestigationTimelineEventType.PROVIDER_WORK_STARTED
    ]
