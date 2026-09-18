# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared deterministic fixtures for the PR 19B provider-work executor tests.

One support module owned by the executor test suite: both executor test
modules import from here and never from each other. Fixed identifiers and
timestamps keep every scenario deterministic; the fakes record calls so tests
can assert sequencing, zero-invocation, and redaction behavior.

The fixture vocabulary distinguishes stable global Evidence identity from
exact EvidenceObservation identity (PR 28B):

- ``EVIDENCE_ONE`` / ``SECOND_EVIDENCE`` are stable global Evidence UUIDs;
- ``FIRST_OBSERVATION_ID`` / ``SECOND_OBSERVATION_ID`` are the exact
  committed EvidenceObservation UUIDs the fake persistence returns.

Normal executor-success fixtures use ``ConvertedEvidence`` from the migrated
ThreatFox semantic source. The six unmigrated providers (Google DNS, RDAP,
IPinfo Lite, AbuseIPDB, URLhaus, DB-IP) remain ``LEGACY_NOT_SEMANTICALLY_MODELED``:
their ``LegacyEvidence`` output is covered by the ``legacy_dns_evidence``
builder and the executor's fail-closed binding expectation; identity is
never invented for them.
"""

# The deterministic fakes intentionally expose a single public operation each
# (get/investigate/persist/append) and share comparable composition blocks
# with the executor test modules; these fakes are test support, not API.

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionView,
    ExtractionResult,
)
from agentic_threat_investigator.app.investigation_timeline import (
    InvestigationTimelineSink,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    EntityReader,
    ProviderExecutionContext,
    ProviderWorkExecutor,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidencePersistenceOutcome,
    UnitOfWork,
)
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
    ConvertedEvidence,
    Evidence,
    EvidenceObservation,
    EvidenceObservationCandidate,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import ProviderWorkItem
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.domain.legacy_evidence import EntityRef, LegacyEvidence
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
THREATFOX_SOURCE = "urn:ati:source:threatfox"
FOREIGN_INVESTIGATION_ID = UUID("00000000-0000-0000-0000-0000000009f9")

# Stable global Evidence identities (PR 28B).
EVIDENCE_ONE = UUID("00000000-0000-0000-0000-0000000000f1")
SECOND_EVIDENCE = UUID("00000000-0000-0000-0000-0000000000f2")
# Exact committed EvidenceObservation identities returned by the fakes.
FIRST_OBSERVATION_ID = UUID("00000000-0000-0000-0000-0000000000e1")
SECOND_OBSERVATION_ID = UUID("00000000-0000-0000-0000-0000000000e2")
DISCOVERED_ONE = UUID("00000000-0000-0000-0000-0000000002a1")
RELATIONSHIP_ONE = UUID("00000000-0000-0000-0000-0000000003b1")


def fixed_clock() -> datetime:
    """Return the fixed deterministic test timestamp."""
    return FIXED_TS


def domain_entity(*, entity_id: UUID | None = DOMAIN_ENTITY_ID) -> Entity:
    """Build a canonical persisted domain entity."""
    return Entity(id=entity_id, type=EntityType.DOMAIN, value="malicious.test")


def global_converted_evidence(
    *,
    evidence_id: UUID | None = EVIDENCE_ONE,
    source_record_id: str | None = None,
    facts: dict[str, object] | None = None,
    observed_at: datetime | None = None,
) -> ConvertedEvidence:
    """Build one global ConvertedEvidence from the migrated ThreatFox source.

    Stable global Evidence never carries Investigation, subject,
    observation timestamps, facts, or raw payload; the observation candidate
    carries the exact material state.
    """
    identity = evidence_id if evidence_id is not None else uuid4()
    evidence = Evidence(
        id=identity,
        type=EvidenceType.THREAT_INTELLIGENCE,
        source=THREATFOX_SOURCE,
        source_record_id=(
            source_record_id if source_record_id is not None else f"tf-{identity}"
        ),
    )
    candidate = EvidenceObservationCandidate(
        evidence_id=identity,
        observed_at=observed_at,
        retrieved_at=FIXED_TS,
        facts=facts if facts is not None else {"matches": []},
        raw_payload=None,
    )
    return ConvertedEvidence(evidence=evidence, observation=candidate)


def legacy_dns_evidence(
    *, evidence_id: UUID | None = None, subject_id: UUID | None = DOMAIN_ENTITY_ID
) -> LegacyEvidence:
    """Build one unmigrated Google DNS LegacyEvidence observation.

    Transitional PR 28B boundary: the Google DNS provider has no approved
    PR 28A stable identity contract and its output fails closed before
    global persistence. This builder exists only for legacy provider
    fail-closed and provider-contract tests.
    """
    return LegacyEvidence(
        id=evidence_id,
        investigation_id=INVESTIGATION_ID,
        type=EvidenceType.DNS,
        subject=EntityRef(
            id=subject_id, type=EntityType.DOMAIN, value="malicious.test"
        ),
        source=DNS_SOURCE,
        retrieved_at=FIXED_TS,
        facts={"query_name": "malicious.test", "query_type": "A", "answers": []},
    )


def null_uow_factory() -> UnitOfWork:
    """Return a placeholder factory; the fake never opens a transaction."""
    raise NotImplementedError


def provider_error() -> ProviderError:
    """Build one typed provider error."""
    return ProviderError(
        provider=THREATFOX_SOURCE,
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
        provider_id: str = THREATFOX_SOURCE,
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
    """Persistence fake recording per-observation invocations (PR 28B)."""

    def __init__(
        self,
        results: list[ProviderObservationPersistenceResult] | None = None,
        *,
        raises: Exception | None = None,
    ) -> None:
        super().__init__(uow_factory=null_uow_factory)
        self._results = results or []
        self._raises = raises
        self.calls: list[
            tuple[
                ConvertedEvidence,
                Entity,
                ExtractionResult,
                UUID,
                UUID | None,
                UUID | None,
            ]
        ] = []

    async def persist(
        self,
        converted: ConvertedEvidence,
        invocation_entity: Entity,
        extraction: ExtractionResult,
        *,
        investigation_id: UUID,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> ProviderObservationPersistenceResult:
        """Record the call and return the configured result or raise."""
        self.calls.append(
            (
                converted,
                invocation_entity,
                extraction,
                investigation_id,
                actor_id,
                request_id,
            )
        )
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
    converted: ConvertedEvidence,
    *,
    observation_id: UUID | None = None,
    entity_ids: tuple[UUID, ...] = (),
    relationship_ids: tuple[UUID, ...] = (),
    outcome: EvidencePersistenceOutcome = EvidencePersistenceOutcome.CREATED,
) -> ProviderObservationPersistenceResult:
    """Build a PR 28B persistence result with the committed identities.

    ``observation_id`` is the exact committed EvidenceObservation identity
    the fake persistence reports; ``converted.evidence`` is the stable global
    Evidence.
    """
    observation = EvidenceObservation(
        id=observation_id if observation_id is not None else uuid4(),
        evidence_id=converted.evidence.id,
        version=1,
        source_url=converted.observation.source_url,
        observed_at=converted.observation.observed_at,
        retrieved_at=converted.observation.retrieved_at,
        facts=converted.observation.facts,
        raw_payload=converted.observation.raw_payload,
        diff=None,
    )
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
        evidence=converted.evidence,
        observation=observation,
        outcome=outcome,
        entities=entities,
        relationships=relationships,
        observations=(),
    )


def committed_first_observation(
    converted: ConvertedEvidence,
) -> ProviderObservationPersistenceResult:
    """Build one committed observation with stable Evidence + observation IDs."""
    return persisted_result(
        converted,
        observation_id=FIRST_OBSERVATION_ID,
        entity_ids=(DISCOVERED_ONE,),
        relationship_ids=(RELATIONSHIP_ONE,),
    )


def build_executor(
    provider: FakeEvidenceProvider | None,
    entity: Entity | None | object,
    *,
    persistence: FakePersistenceService | None = None,
    timeline: FakeTimelineSink | None = None,
    extractor: Callable[[EvidenceExtractionView], ExtractionResult] | None = None,
    registry_key: SourceId | None = None,
) -> ProviderWorkExecutor:
    """Compose one executor from deterministic fakes.

    The provider registry is normally keyed by the provider's own stable
    source URN, so migrated-success and legacy fail-closed scenarios declare
    their own identity without registry duplication. ``registry_key``
    overrides the registry key (used by registry/provider-id mismatch
    scenarios where the provider is listed under a foreign key).
    """
    registry: dict[SourceId, FakeEvidenceProvider] = {}
    if provider is not None:
        registry[
            registry_key if registry_key is not None else SourceId(provider.id)
        ] = provider
    return ProviderWorkExecutor(
        entity_reader=FakeEntityReader({DOMAIN_ENTITY_ID: entity}),  # type: ignore[dict-item]
        provider_registry=registry,
        extractor=extractor or (lambda _view: ExtractionResult()),
        persistence_service=persistence or FakePersistenceService(),
        timeline_service=timeline,
        context=ProviderExecutionContext(
            investigation_id=INVESTIGATION_ID, clock=fixed_clock
        ),
    )


def threatfox_work_item() -> ProviderWorkItem:
    """Return the fixed migrated ThreatFox work item."""
    return ProviderWorkItem(
        provider=SourceId.THREATFOX, entity_id=DOMAIN_ENTITY_ID, depth=0
    )


def legacy_dns_work_item() -> ProviderWorkItem:
    """Return the fixed unmigrated Google DNS work item (fail-closed path)."""
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
