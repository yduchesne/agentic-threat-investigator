# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the Evidence Analyst execution service.

The real ``AssessmentPersistenceService`` (including the PR 20A provenance
validator) runs against in-memory fakes; a scripted ``FakeLlmClient`` drives
the model boundary; and a deterministic accounting fake records every durable
LLM reservation. No real external model or database participates.
"""

# Fixture arguments intentionally reuse fixture names; the fakes mirror the
# repository seam shape used by the persistence-service suites, and the
# analyst service intentionally takes one explicit dependency per seam.
# The graph/decision scaffolds are shared across the PR 20B test suites; the
# duplication is test-only and deliberately accepted.

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Self, cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.assessment_provenance import (
    AssessmentEvidenceReferenceError,
    AssessmentRelationshipObservationReferenceError,
)
from agentic_threat_investigator.app.evidence_analyst import (
    EvidenceAnalyst,
    EvidenceAnalystInputLoader,
    LlmAccountingService,
)
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.persistence.repositories import (
    AssessmentRepository,
    AuditEventRepository,
    BatchOutcome,
    EntityBatchItem,
    EntityBatchResult,
    EntityRepository,
    EvidenceObservationEntityRepository,
    EvidencePersistenceResult,
    EvidenceRepository,
    InvestigationEvidenceRepository,
    InvestigationRepository,
    InvestigationVersionConflictError,
    InvestigationWriteResult,
    RelationshipObservationRepository,
    RelationshipRepository,
    UnitOfWork,
)
from agentic_threat_investigator.domain.analyst import (
    AnalystEntity,
    AnalystEntityGeointContext,
    AnalystEvidenceItem,
    AnalystGeointContext,
    AnalystGeointLocation,
    AnalystGeointObservation,
    AnalystGeointPrecisionCounts,
    AnalystGeointSummary,
    AnalystRelationshipObservation,
    EvidenceAnalystDecision,
    EvidenceAnalystInput,
    GeographicFinding,
    GeographicFindingKind,
    GeographicTemporalInterpretation,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    RelationshipSupport,
    Verdict,
)
from agentic_threat_investigator.domain.audit import AuditEvent
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    Evidence,
    EvidenceObservation,
    EvidenceObservationEntity,
    EvidenceType,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    InvestigationBudget,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)
from tests.support.llm_fixtures import FakeLlmClient

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class AnalysisWorld:
    """One complete eligible provenance world with scripted LLM and reserves."""

    def __init__(
        self, *, with_observation: bool = True, with_geoint: bool = False
    ) -> None:
        """Bind the fixed world. ``with_geoint`` adds a second GEOLOCATION row."""
        self.investigation_id = uuid4()
        self.source_id = uuid4()
        self.target_id = uuid4()
        self.evidence_id = uuid4()
        self.relationship_id = uuid4()
        self.observation_id = uuid4()
        # PR 26F GEOINT world: a second GEOLOCATION LegacyEvidence row plus two
        # resolved city observations of the source Entity (Seattle, Dallas).
        self.with_geoint = with_geoint
        self.geoint_evidence_id = uuid4()
        self.geoint_obs_seattle_id = uuid4()
        self.geoint_obs_dallas_id = uuid4()
        self.geoint_loc_seattle_id = uuid4()
        self.geoint_loc_dallas_id = uuid4()
        self.investigation = InvestigationState(
            investigation_id=self.investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[self.source_id],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
            version=5,
        )
        self.evidence = EvidenceObservation(
            id=self.evidence_id,
            evidence_id=self.evidence_id,
            version=1,
            retrieved_at=_RETRIEVED_AT,
            facts={"a_records": ["192.0.2.1"]},
        )
        self.relationship = Relationship(
            id=self.relationship_id,
            source_entity_id=self.source_id,
            target_entity_id=self.target_id,
            type=RelationshipType.RESOLVES_TO,
        )
        self.observation = RelationshipObservation(
            id=self.observation_id,
            relationship_id=self.relationship_id,
            evidence_observation_id=self.evidence_id,
            retrieved_at=_RETRIEVED_AT,
            source="urn:ati:source:google_public_dns",
        )
        self.source_entity = Entity(
            id=self.source_id, type=EntityType.DOMAIN, value="example.com"
        )
        self.target_entity = Entity(
            id=self.target_id,
            type=EntityType.IP_ADDRESS,
            value="192.0.2.1",
        )
        self.with_observation = with_observation

    # -- GEOINT context ------------------------------------------------------

    def geoint_observation(
        self,
        *,
        observation_id: UUID,
        evidence_observation_id: UUID,
        location_id: UUID,
        canonical_name: str,
        retrieved_at: datetime,
    ) -> AnalystGeointObservation:
        """Build one resolved city observation of the source Entity."""
        return AnalystGeointObservation(
            observation_id=observation_id,
            entity_id=self.source_id,
            evidence_observation_id=evidence_observation_id,
            location=AnalystGeointLocation(
                location_id=location_id,
                location_type=LocationType.CITY,
                canonical_location_name=canonical_name,
                country_code="US",
                admin1_code="WA",
            ),
            precision=LocationPrecision.CITY,
            resolution_method="canonical_geography_v1",
            observed_at=None,
            retrieved_at=retrieved_at,
            resolved_at=retrieved_at,
        )

    def geoint_context(self) -> AnalystGeointContext:
        """Build the deterministic model-visible GEOINT context."""
        seattle = self.geoint_observation(
            observation_id=self.geoint_obs_seattle_id,
            evidence_observation_id=self.evidence_id,
            location_id=self.geoint_loc_seattle_id,
            canonical_name="Seattle",
            retrieved_at=_RETRIEVED_AT,
        )
        dallas = self.geoint_observation(
            observation_id=self.geoint_obs_dallas_id,
            evidence_observation_id=self.geoint_evidence_id,
            location_id=self.geoint_loc_dallas_id,
            canonical_name="Dallas",
            retrieved_at=datetime(2026, 1, 3, 3, 4, 5, tzinfo=UTC),
        )
        return AnalystGeointContext(
            summary=AnalystGeointSummary(
                entity_count_with_location=1,
                observation_count=2,
                location_count=2,
                country_count=0,
                administrative_area_count=0,
                city_count=2,
                precision_counts=AnalystGeointPrecisionCounts(
                    country=0, administrative_area=0, city=2
                ),
                top_locations=(),
                truncated=False,
            ),
            entities=(
                AnalystEntityGeointContext(
                    entity_id=self.source_id,
                    entity_type=EntityType.DOMAIN,
                    entity_value="example.com",
                    current_observation=seattle,
                    history=(dallas,),
                ),
            ),
        )

    def geoint_decision(
        self,
        *,
        verdict: Verdict = Verdict.INCONCLUSIVE,
        independent: bool = False,
        observation_ids: tuple[UUID, ...] | None = None,
        evidence_observation_ids: tuple[UUID, ...] | None = None,
        entity_ids: tuple[UUID, ...] | None = None,
        location_ids: tuple[UUID, ...] | None = None,
    ) -> EvidenceAnalystDecision:
        """Build a decision with a valid descriptive location-change finding."""
        findings: tuple[AnalyticalFinding, ...] = ()
        if independent:
            findings = (
                AnalyticalFinding(
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="The domain resolves to a block-listed controller.",
                    confidence=AssessmentConfidence.MEDIUM,
                    support=(
                        EvidenceSupport(kind="evidence", evidence_id=self.evidence_id),
                    ),
                ),
            )
        geographic = (
            GeographicFinding(
                kind=GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
                statement=(
                    "Two supported observations identify different canonical "
                    "locations at different effective times."
                ),
                temporal_interpretation=GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED,
                observation_ids=observation_ids
                or (self.geoint_obs_seattle_id, self.geoint_obs_dallas_id),
                evidence_observation_ids=evidence_observation_ids
                or (self.evidence_id, self.geoint_evidence_id),
                entity_ids=entity_ids or (self.source_id,),
                location_ids=location_ids
                or (self.geoint_loc_seattle_id, self.geoint_loc_dallas_id),
            ),
        )
        return EvidenceAnalystDecision(
            verdict=verdict,
            confidence=AssessmentConfidence.MEDIUM,
            summary="The exact observations support the verdict.",
            findings=findings,
            geographic_findings=geographic,
            disposition=AnalysisDisposition.SUFFICIENT,
        )

    # -- analyst input -------------------------------------------------------

    def analyst_input(self) -> EvidenceAnalystInput:
        """Build the deterministic analyst input served by the fake loader."""
        evidence_items: tuple[AnalystEvidenceItem, ...] = (
            AnalystEvidenceItem(
                evidence_observation_id=self.evidence_id,
                type=EvidenceType.DNS,
                entities=(
                    AnalystEntity(
                        entity_id=self.source_id,
                        entity_type=EntityType.DOMAIN,
                        value="example.com",
                    ),
                ),
                source="urn:ati:source:google_public_dns",
                retrieved_at=_RETRIEVED_AT,
                facts={"a_records": ["192.0.2.1"]},
            ),
        )
        if self.with_geoint:
            evidence_items = evidence_items + (
                AnalystEvidenceItem(
                    evidence_observation_id=self.geoint_evidence_id,
                    type=EvidenceType.GEOLOCATION,
                    entities=(
                        AnalystEntity(
                            entity_id=self.source_id,
                            entity_type=EntityType.DOMAIN,
                            value="example.com",
                        ),
                    ),
                    source="urn:ati:source:test",
                    retrieved_at=_RETRIEVED_AT,
                    facts={"country_code": "US", "precision": "city"},
                ),
            )
        observations: tuple[AnalystRelationshipObservation, ...] = ()
        if self.with_observation:
            observations = (
                AnalystRelationshipObservation(
                    relationship_observation_id=self.observation_id,
                    evidence_observation_id=self.evidence_id,
                    relationship_id=self.relationship_id,
                    relationship_type=RelationshipType.RESOLVES_TO,
                    source_entity=AnalystEntity(
                        entity_id=self.source_id,
                        entity_type=EntityType.DOMAIN,
                        value="example.com",
                    ),
                    target_entity=AnalystEntity(
                        entity_id=self.target_id,
                        entity_type=EntityType.IP_ADDRESS,
                        value="192.0.2.1",
                    ),
                    retrieved_at=_RETRIEVED_AT,
                    source="urn:ati:source:google_public_dns",
                ),
            )
        return EvidenceAnalystInput(
            investigation_id=self.investigation_id,
            objective="Assess the root indicator.",
            root_entities=(
                AnalystEntity(
                    entity_id=self.source_id,
                    entity_type=EntityType.DOMAIN,
                    value="example.com",
                ),
            ),
            evidence=evidence_items,
            relationship_observations=observations,
            geoint_context=self.geoint_context() if self.with_geoint else None,
        )

    # -- decisions -----------------------------------------------------------

    def decision(
        self,
        *,
        evidence_support: bool = False,
        graph_support: bool = False,
        verdict: Verdict = Verdict.SUSPICIOUS,
        disposition: FindingDisposition = FindingDisposition.SUPPORTING,
        evidence_id: UUID | None = None,
        observation_id: UUID | None = None,
    ) -> EvidenceAnalystDecision:
        """Build a decision whose support cites this world when requested."""
        support: list[EvidenceSupport | RelationshipSupport] = []
        if evidence_support:
            support.append(
                EvidenceSupport(
                    kind="evidence",
                    evidence_id=evidence_id or self.evidence_id,
                )
            )
        if graph_support:
            support.append(
                RelationshipSupport(
                    kind="relationship_observation",
                    relationship_observation_id=observation_id or self.observation_id,
                )
            )
        findings = (
            AnalyticalFinding(
                category=FindingCategory.NETWORK,
                disposition=disposition,
                statement="The domain resolves to the address.",
                confidence=AssessmentConfidence.MEDIUM,
                support=tuple(support),
            ),
        )
        return EvidenceAnalystDecision(
            verdict=verdict,
            confidence=AssessmentConfidence.MEDIUM,
            summary="The exact observations support the verdict.",
            findings=findings if support else (),
            disposition=AnalysisDisposition.SUFFICIENT,
        )


# ---------------------------------------------------------------------------
# Persistence fakes (same authoritative-world shape as the PR 20A suite)
# ---------------------------------------------------------------------------


class FakeEvidenceObservationEntityRepository(EvidenceObservationEntityRepository):
    """Record observation/Entity associations."""

    def __init__(self, associations: dict[UUID, tuple[UUID, ...]]) -> None:
        self.associations = associations

    async def list_for_observation(
        self, observation_id: UUID
    ) -> list[EvidenceObservationEntity]:
        return [
            EvidenceObservationEntity(
                evidence_observation_id=observation_id, entity_id=entity_id
            )
            for entity_id in self.associations.get(observation_id, ())
        ]

    async def associate(
        self, observation_id: UUID, entity_id: UUID
    ) -> EvidenceObservationEntity:
        self.associations.setdefault(observation_id, ())
        if entity_id not in self.associations[observation_id]:
            self.associations[observation_id] = self.associations[observation_id] + (
                entity_id,
            )
        return EvidenceObservationEntity(
            evidence_observation_id=observation_id, entity_id=entity_id
        )


class FakeInvestigationEvidenceRepository(InvestigationEvidenceRepository):
    """Serve the configured exact admissions."""

    def __init__(self, admissions: dict[UUID, tuple[UUID, ...]]) -> None:
        self.admissions = admissions

    async def list_for_investigation(
        self, investigation_id: UUID
    ) -> list[InvestigationEvidence]:
        return [
            InvestigationEvidence(
                investigation_id=investigation_id,
                evidence_observation_id=observation_id,
                inclusion_reason=InvestigationEvidenceReason.INITIAL,
                added_at=_RETRIEVED_AT,
                added_by=InvestigationEvidenceActor.SYSTEM,
            )
            for observation_id in self.admissions.get(investigation_id, ())
        ]

    async def admit(self, admission: InvestigationEvidence) -> InvestigationEvidence:
        """Record one admission."""
        existing = self.admissions.setdefault(admission.investigation_id, ())
        if admission.evidence_observation_id not in existing:
            self.admissions[admission.investigation_id] = existing + (
                admission.evidence_observation_id,
            )
        return admission


class FakeInvestigationRepository(InvestigationRepository):
    """Serves the visible Investigation and records pointer updates."""

    visible: InvestigationState | None
    pointer_calls: list[tuple[UUID, UUID, int | None]]

    def __init__(self, visible: InvestigationState) -> None:
        self.visible = visible
        self.pointer_calls = []

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        return self.visible

    async def update_assessment_reference(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        self.pointer_calls.append((investigation_id, assessment_id, expected_version))
        return InvestigationWriteResult(investigation_id, 6, BatchOutcome.UPDATED)

    async def update_report_reference(
        self,
        investigation_id: UUID,
        report_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_budget(
        self,
        investigation_id: UUID,
        budget: InvestigationBudget,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def create(self, *args: object, **_: object) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_status(
        self, *args: object, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_coordinator_state(
        self,
        investigation_id: UUID,
        transition_kind: object,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        consumes_replan: bool = False,
    ) -> InvestigationWriteResult:
        """Test fake: accept the transition and report a new version."""
        return InvestigationWriteResult(investigation_id, 7, BatchOutcome.UPDATED)

    async def set_analysis_result(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        analyzed_evidence_ids: list[UUID],
        disposition: object,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationWriteResult:
        """Test fake: accept and report a new version."""
        del (
            assessment_id,
            analyzed_evidence_ids,
            disposition,
            actor_id,
            request_id,
            expected_version,
        )
        return InvestigationWriteResult(investigation_id, 8, BatchOutcome.UPDATED)

    async def soft_delete(self, *args: object, **_: object) -> InvestigationWriteResult:
        raise NotImplementedError


class FakeEvidenceRepository(EvidenceRepository):
    """Serves the configured exact observations and stable Evidence."""

    def __init__(
        self,
        rows: dict[UUID, EvidenceObservation],
        stable: dict[UUID, Evidence],
    ) -> None:
        self.rows = rows
        self.stable = stable

    async def list_for_investigation(
        self, investigation_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[EvidenceObservation]:
        del investigation_id, offset
        return list(self.rows.values())[:limit]

    async def get_observation(self, observation_id: UUID) -> EvidenceObservation | None:
        return self.rows.get(observation_id)

    async def get_stable_evidence(self, evidence_id: UUID) -> Evidence | None:
        return self.stable.get(evidence_id)

    async def list_observations(
        self,
        evidence_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceObservation]:
        return list(self.rows.values())[offset : offset + limit]

    async def persist(
        self, converted: object, *, observation_id: UUID | None = None
    ) -> EvidencePersistenceResult:
        raise NotImplementedError


class FakeObservationRepository(RelationshipObservationRepository):
    """Serves the configured observation rows."""

    def __init__(self, rows: dict[UUID, RelationshipObservation]) -> None:
        self.rows = rows

    async def get_by_id(self, observation_id: UUID) -> RelationshipObservation | None:
        return self.rows.get(observation_id)

    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        raise NotImplementedError

    async def list_for_investigation(
        self, investigation_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[RelationshipObservation]:
        del investigation_id, offset
        return list(self.rows.values())[:limit]


class FakeRelationshipRepository(RelationshipRepository):
    """Serves the configured relationship rows."""

    def __init__(self, rows: dict[UUID, Relationship]) -> None:
        self.rows = rows

    async def get_by_id(
        self, relationship_id: UUID, *, include_deleted: bool = False
    ) -> Relationship | None:
        return self.rows.get(relationship_id)

    async def get_by_identity(
        self,
        source_entity_id: UUID,
        relationship_type: str,
        target_entity_id: UUID,
        *,
        include_deleted: bool = False,
    ) -> Relationship | None:
        raise NotImplementedError

    async def upsert(self, relationship: Relationship, **_: object) -> Relationship:
        raise NotImplementedError

    async def soft_delete(self, relationship_id: UUID, **_: object) -> Relationship:
        raise NotImplementedError


class FakeEntityRepository(EntityRepository):
    """Serves the configured entity rows."""

    def __init__(self, rows: dict[UUID, Entity]) -> None:
        self.rows = rows

    async def get_by_id(
        self, entity_id: UUID, *, include_deleted: bool = False
    ) -> Entity | None:
        return self.rows.get(entity_id)

    async def get_by_identity(
        self, entity_type: str, canonical_value: str, *, include_deleted: bool = False
    ) -> Entity | None:
        raise NotImplementedError

    async def upsert(self, entity: Entity, **_: object) -> Entity:
        raise NotImplementedError

    async def upsert_batch(
        self, items: Sequence[EntityBatchItem]
    ) -> list[EntityBatchResult]:
        raise NotImplementedError

    async def soft_delete(self, entity_id: UUID, **_: object) -> Entity:
        raise NotImplementedError


class FakeAssessmentRepository(AssessmentRepository):
    """Insert-only assessment fake with an injected failure seam."""

    def __init__(self) -> None:
        self.inserted: list[Assessment] = []
        self.assigned_id = uuid4()
        self.fail: Exception | None = None

    async def insert(
        self,
        assessment: Assessment,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Assessment:
        if self.fail is not None:
            raise self.fail
        self.inserted.append(assessment)
        return assessment.model_copy(
            update={
                "id": self.assigned_id,
                "version": 1,
                "created_at": _RETRIEVED_AT,
            }
        )

    async def get_by_id(
        self, assessment_id: UUID, *, include_deleted: bool = False
    ) -> Assessment | None:
        raise NotImplementedError

    async def list_for_investigation(
        self, investigation_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[Assessment]:
        raise NotImplementedError

    async def soft_delete(self, *args: object, **_: object) -> Assessment:
        raise NotImplementedError


class FakeAuditRepository(AuditEventRepository):
    """Append-only audit fake."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> AuditEvent:
        self.events.append(event)
        return event

    async def list_events(self, **_filters: object) -> list[AuditEvent]:
        return self.events


class FakePersistenceUnitOfWork(UnitOfWork):
    """In-memory transaction boundary for the persistence seam."""

    assessments: FakeAssessmentRepository
    audit_events: FakeAuditRepository
    investigations: FakeInvestigationRepository
    evidence: FakeEvidenceRepository
    relationship_observations: FakeObservationRepository
    relationships: FakeRelationshipRepository
    entities: FakeEntityRepository
    commits: int
    rollbacks: int

    def __init__(
        self,
        *,
        world: AnalysisWorld,
        assessments: FakeAssessmentRepository,
        audit_events: FakeAuditRepository,
        investigations: FakeInvestigationRepository,
    ) -> None:
        # One explicit argument per dependency is the UnitOfWork convention.
        self.investigations = investigations
        evidence_rows = {world.evidence_id: world.evidence}
        stable_rows = {
            world.evidence_id: Evidence(
                id=world.evidence_id,
                type=EvidenceType.DNS,
                source="urn:ati:source:google_public_dns",
                source_record_id="analyst-world",
            )
        }
        if world.with_geoint:
            evidence_rows[world.geoint_evidence_id] = EvidenceObservation(
                id=world.geoint_evidence_id,
                evidence_id=world.geoint_evidence_id,
                version=1,
                retrieved_at=_RETRIEVED_AT,
                facts={"country_code": "US", "precision": "city"},
            )
            stable_rows[world.geoint_evidence_id] = Evidence(
                id=world.geoint_evidence_id,
                type=EvidenceType.GEOLOCATION,
                source="urn:ati:source:test",
                source_record_id="analyst-geoint",
            )
        self.evidence = FakeEvidenceRepository(evidence_rows, stable_rows)
        self.evidence_observation_entities = FakeEvidenceObservationEntityRepository(
            dict.fromkeys(evidence_rows, (world.source_id,))
        )
        self.investigation_evidence = FakeInvestigationEvidenceRepository(
            {world.investigation_id: tuple(evidence_rows)}
        )
        self.relationship_observations = FakeObservationRepository(
            {world.observation_id: world.observation} if world.with_observation else {}
        )
        self.relationships = FakeRelationshipRepository(
            {world.relationship_id: world.relationship}
        )
        self.entities = FakeEntityRepository(
            {world.source_id: world.source_entity, world.target_id: world.target_entity}
        )
        self.assessments = assessments
        self.audit_events = audit_events
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        if exc_type is None:
            self.commits += 1
        else:
            self.rollbacks += 1

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


# ---------------------------------------------------------------------------
# Accounting fakes
# ---------------------------------------------------------------------------


@dataclass
class FakeAccountingUnitOfWork(UnitOfWork):
    """In-memory reservation boundary applying budget updates to the state."""

    investigation: InvestigationState

    def __post_init__(self) -> None:
        """Initialize the reservation log."""
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        if exc_type is None:
            self.commits += 1
        else:
            self.rollbacks += 1

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


class FakeAccountingInvestigationRepository(InvestigationRepository):
    """Investigation repository applying budget writes to the in-memory state."""

    state: InvestigationState
    budget_writes: list[InvestigationBudget]
    fail: Exception | None

    def __init__(self, state: InvestigationState) -> None:
        self.state = state
        self.budget_writes: list[InvestigationBudget] = []
        self.fail: Exception | None = None

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        return self.state

    async def update_budget(
        self,
        investigation_id: UUID,
        budget: InvestigationBudget,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        if self.fail is not None:
            raise self.fail
        if expected_version is not None and self.state.version != expected_version:
            raise InvestigationVersionConflictError(investigation_id, expected_version)
        self.budget_writes.append(budget)
        self.state.budget = budget
        self.state.version = (self.state.version or 0) + 1
        return InvestigationWriteResult(
            investigation_id, self.state.version, BatchOutcome.UPDATED
        )

    async def update_assessment_reference(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        **_: object,
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_report_reference(
        self,
        investigation_id: UUID,
        report_id: UUID,
        **_: object,
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def create(self, *args: object, **_: object) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_status(
        self, *args: object, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_coordinator_state(
        self,
        investigation_id: UUID,
        transition_kind: object,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        consumes_replan: bool = False,
    ) -> InvestigationWriteResult:
        """Test fake: accept the transition and report a new version."""
        return InvestigationWriteResult(investigation_id, 7, BatchOutcome.UPDATED)

    async def set_analysis_result(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        analyzed_evidence_ids: list[UUID],
        disposition: object,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationWriteResult:
        """Test fake: accept and report a new version."""
        del (
            assessment_id,
            analyzed_evidence_ids,
            disposition,
            actor_id,
            request_id,
            expected_version,
        )
        return InvestigationWriteResult(investigation_id, 8, BatchOutcome.UPDATED)

    async def soft_delete(self, *args: object, **_: object) -> InvestigationWriteResult:
        raise NotImplementedError


class FakeLoader(EvidenceAnalystInputLoader):
    """Loader stand-in serving a prebuilt input and optional failure."""

    def __init__(self, analyst_input: EvidenceAnalystInput) -> None:
        """Bind the deterministic input; the base factory stays unused."""
        super().__init__(
            cast(Callable[[], UnitOfWork], lambda: None),
            max_evidence_items=10,
        )
        self._analyst_input = analyst_input
        self.fail: Exception | None = None
        self.calls = 0
        self._load_calls = 0

    async def load(self, investigation_id: UUID) -> EvidenceAnalystInput:
        """Return the prebuilt input, raising when configured to fail."""
        self._load_calls += 1
        self.calls = self._load_calls
        if self.fail is not None:
            raise self.fail
        return self._analyst_input


@pytest.fixture
def world() -> AnalysisWorld:
    """Return one deterministic analysis world per test."""
    return AnalysisWorld()


@dataclass
class Harness:
    """The fully-bound analyst plus every observable fake."""

    analyst: EvidenceAnalyst
    llm: FakeLlmClient
    persistence: FakePersistenceUnitOfWork
    accounting_repo: FakeAccountingInvestigationRepository
    assessments: AssessmentPersistenceService


@pytest.fixture
def harness(world: AnalysisWorld) -> Harness:
    """Build the fully-bound analyst plus all observable fakes."""
    fake_llm = FakeLlmClient()
    persistence_uow = FakePersistenceUnitOfWork(
        world=world,
        assessments=FakeAssessmentRepository(),
        audit_events=FakeAuditRepository(),
        investigations=FakeInvestigationRepository(world.investigation),
    )
    accounting_uow = FakeAccountingUnitOfWork(world.investigation)
    accounting_repo = FakeAccountingInvestigationRepository(world.investigation)
    accounting_uow.investigations = accounting_repo
    accounting = LlmAccountingService(lambda: accounting_uow)
    assessments = AssessmentPersistenceService(lambda: persistence_uow, batch_size=100)
    analyst = EvidenceAnalyst(
        input_loader=FakeLoader(world.analyst_input()),
        llm_client=fake_llm,
        assessment_persistence=assessments,
        llm_accounting=accounting,
        max_structured_output_attempts=2,
    )
    return Harness(analyst, fake_llm, persistence_uow, accounting_repo, assessments)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_only_finding_persists(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """A direct LegacyEvidence-only finding validates and persists exactly once."""
    analyst, fake_llm, persistence_uow, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.persistence,
        harness.accounting_repo,
    )
    fake_llm.set_default(world.decision(evidence_support=True))

    persisted = await analyst.analyze(world.investigation_id)

    assert isinstance(persisted, Assessment)
    assert persisted.id is not None
    assert persisted.investigation_id == world.investigation_id
    assert persisted.verdict is Verdict.SUSPICIOUS
    assert persisted.analyzed_evidence_ids == (world.evidence_id,)
    assert len(persistence_uow.assessments.inserted) == 1
    assert persistence_uow.commits == 1
    assert accounting_repo.budget_writes[0].llm_calls_used == 1


@pytest.mark.asyncio
async def test_graph_finding_persists(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """A RelationshipObservation-backed finding validates and persists."""
    analyst, fake_llm = harness.analyst, harness.llm
    fake_llm.set_default(world.decision(graph_support=True))

    persisted = await analyst.analyze(world.investigation_id)

    finding = persisted.findings[0]
    assert isinstance(finding.support[0], RelationshipSupport)
    assert finding.support[0].relationship_observation_id == world.observation_id


@pytest.mark.asyncio
async def test_mixed_support_and_contradiction_preserved(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """Mixed direct/graph support and contradictory dispositions survive."""
    analyst, fake_llm = harness.analyst, harness.llm
    decision = world.decision(
        evidence_support=True,
        graph_support=True,
        disposition=FindingDisposition.CONTRADICTING,
    )
    fake_llm.set_default(decision)

    persisted = await analyst.analyze(world.investigation_id)

    [finding] = persisted.findings
    assert finding.disposition is FindingDisposition.CONTRADICTING
    assert len(finding.support) == 2
    assert isinstance(finding.support[0], EvidenceSupport)
    assert isinstance(finding.support[1], RelationshipSupport)


@pytest.mark.asyncio
async def test_application_stamps_authoritative_identifiers(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """The application, not the model, owns investigation/analyzed IDs."""
    analyst, fake_llm, persistence_uow = (
        harness.analyst,
        harness.llm,
        harness.persistence,
    )
    fake_llm.set_default(world.decision(evidence_support=True))

    await analyst.analyze(world.investigation_id)

    [candidate] = persistence_uow.assessments.inserted
    assert candidate.investigation_id == world.investigation_id
    assert candidate.analyzed_evidence_ids == (world.evidence_id,)
    assert candidate.id is None
    assert candidate.version is None
    assert candidate.created_at is None


@pytest.mark.asyncio
async def test_model_cannot_supply_persistence_metadata(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """Decision fields cannot inject persistence-owned Assessment metadata."""
    analyst, fake_llm, persistence_uow = (
        harness.analyst,
        harness.llm,
        harness.persistence,
    )
    fake_llm.set_default(world.decision(evidence_support=True))

    await analyst.analyze(world.investigation_id)

    [candidate] = persistence_uow.assessments.inserted
    assert candidate.id is None


@pytest.mark.asyncio
async def test_llm_timeout_produces_no_persistence(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """A mapped timeout fails the analysis with no Assessment written."""
    analyst, fake_llm, persistence_uow, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.persistence,
        harness.accounting_repo,
    )
    fake_llm.enqueue(LlmError(LlmErrorCode.TIMEOUT))

    with pytest.raises(LlmError) as holder:
        await analyst.analyze(world.investigation_id)

    assert holder.value.code is LlmErrorCode.TIMEOUT
    assert persistence_uow.assessments.inserted == []
    assert persistence_uow.rollbacks == 0
    assert len(accounting_repo.budget_writes) == 1


@pytest.mark.asyncio
async def test_provider_failure_produces_no_persistence(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """A provider failure is not retried and persists nothing."""
    analyst, fake_llm, persistence_uow, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.persistence,
        harness.accounting_repo,
    )
    fake_llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE))

    with pytest.raises(LlmError) as holder:
        await analyst.analyze(world.investigation_id)

    assert holder.value.code is LlmErrorCode.PROVIDER_FAILURE
    assert persistence_uow.assessments.inserted == []
    assert len(fake_llm.calls) == 1
    assert len(accounting_repo.budget_writes) == 1


@pytest.mark.asyncio
async def test_invalid_output_repairs_once_then_persists(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """Invalid structured output triggers exactly one bounded repair."""
    analyst, fake_llm, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.accounting_repo,
    )
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    fake_llm.enqueue(world.decision(evidence_support=True))

    persisted = await analyst.analyze(world.investigation_id)

    assert persisted.id is not None
    assert len(fake_llm.calls) == 2
    assert len(accounting_repo.budget_writes) == 2
    assert "failed structured-schema validation" in fake_llm.calls[1].user_prompt
    assert "failed structured-schema validation" not in fake_llm.calls[0].user_prompt


@pytest.mark.asyncio
async def test_exhausted_repair_persists_nothing(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """Exhausted structured-output attempts fail with no Assessment."""
    analyst, fake_llm, persistence_uow, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.persistence,
        harness.accounting_repo,
    )
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))

    with pytest.raises(LlmError):
        await analyst.analyze(world.investigation_id)

    assert persistence_uow.assessments.inserted == []
    assert len(fake_llm.calls) == 2
    assert len(accounting_repo.budget_writes) == 2


@pytest.mark.asyncio
async def test_invented_evidence_support_rejected(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """A model-invented LegacyEvidence citation is rejected by PR 20A validation."""
    analyst, fake_llm, persistence_uow = (
        harness.analyst,
        harness.llm,
        harness.persistence,
    )
    fake_llm.set_default(world.decision(evidence_support=True, evidence_id=uuid4()))

    with pytest.raises(AssessmentEvidenceReferenceError):
        await analyst.analyze(world.investigation_id)

    assert persistence_uow.assessments.inserted == []
    assert persistence_uow.commits == 0


@pytest.mark.asyncio
async def test_invented_observation_support_rejected(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """A model-invented RelationshipObservation citation is rejected."""
    analyst, fake_llm, persistence_uow = (
        harness.analyst,
        harness.llm,
        harness.persistence,
    )
    fake_llm.set_default(world.decision(graph_support=True, observation_id=uuid4()))

    with pytest.raises(AssessmentRelationshipObservationReferenceError):
        await analyst.analyze(world.investigation_id)

    assert persistence_uow.assessments.inserted == []


@pytest.mark.asyncio
async def test_persistence_failure_propagates(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """A persistence failure propagates without a pointer update."""
    analyst, fake_llm, persistence_uow = (
        harness.analyst,
        harness.llm,
        harness.persistence,
    )
    persistence_uow.assessments.fail = RuntimeError("disk full")
    fake_llm.set_default(world.decision(evidence_support=True))

    with pytest.raises(RuntimeError, match="disk full"):
        await analyst.analyze(world.investigation_id)

    assert persistence_uow.investigations.pointer_calls == []


@pytest.mark.asyncio
async def test_stale_version_conflict_leaves_no_pointer(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """A stale caller version fails before any reservation or pointer."""
    analyst, fake_llm, persistence_uow, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.persistence,
        harness.accounting_repo,
    )
    fake_llm.set_default(world.decision(evidence_support=True))

    with pytest.raises(InvestigationVersionConflictError):
        await analyst.analyze(world.investigation_id, expected_investigation_version=99)

    assert accounting_repo.budget_writes == []
    assert persistence_uow.investigations.pointer_calls == []
    assert persistence_uow.assessments.inserted == []


@pytest.mark.asyncio
async def test_cancellation_propagates_and_counts_attempt(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """Cancellation propagates unchanged; the attempted call stays reserved."""
    analyst, fake_llm, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.accounting_repo,
    )
    fake_llm.enqueue(asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        await analyst.analyze(world.investigation_id)

    assert len(accounting_repo.budget_writes) == 1
    assert accounting_repo.budget_writes[0].llm_calls_used == 1


@pytest.mark.asyncio
async def test_no_evidence_short_circuits_without_llm(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """No evidence yields a deterministic INCONCLUSIVE with no model call."""
    analyst, fake_llm, persistence_uow, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.persistence,
        harness.accounting_repo,
    )
    world.with_observation = False
    analyst._input_loader = FakeLoader(
        EvidenceAnalystInput(
            investigation_id=world.investigation_id,
            objective="Assess the root indicator.",
        )
    )

    persisted = await analyst.analyze(world.investigation_id)

    assert persisted.verdict is Verdict.INCONCLUSIVE
    assert persisted.confidence is AssessmentConfidence.LOW
    assert persisted.analyzed_evidence_ids == ()
    assert persisted.findings == ()
    assert "No evidence was available" in persisted.limitations[0]
    assert fake_llm.calls == []
    assert accounting_repo.budget_writes == []
    assert persistence_uow.commits == 1


@pytest.mark.asyncio
async def test_repair_prompts_never_reach_investigation_state(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """Prompt content is never stored in Investigation state/persistence."""
    analyst, fake_llm, accounting_repo, persistence_uow = (
        harness.analyst,
        harness.llm,
        harness.accounting_repo,
        harness.persistence,
    )
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    fake_llm.enqueue(world.decision(evidence_support=True))

    await analyst.analyze(world.investigation_id)

    state = accounting_repo.state
    assert "LegacyEvidence items" not in str(state)
    assert "structured-schema validation" not in str(state)
    assert state.budget.llm_calls_used == 2
    assert persistence_uow.audit_events.events[0].metadata == {
        "investigation_id": str(world.investigation_id),
        "version": 1,
    }


def test_analyst_constructor_rejects_attempts_outside_one_to_two() -> None:
    """Even without Settings, attempt counts are hard-limited to 1..2."""
    for invalid in (0, -1, 3):
        with pytest.raises(ValueError, match="1..2"):
            EvidenceAnalyst(
                input_loader=FakeLoader(AnalysisWorld().analyst_input()),
                llm_client=FakeLlmClient(),
                assessment_persistence=AssessmentPersistenceService(
                    lambda: FakePersistenceUnitOfWork(
                        world=AnalysisWorld(),
                        assessments=FakeAssessmentRepository(),
                        audit_events=FakeAuditRepository(),
                        investigations=FakeInvestigationRepository(
                            AnalysisWorld().investigation
                        ),
                    ),
                    batch_size=100,
                ),
                llm_accounting=LlmAccountingService(
                    lambda: FakeAccountingUnitOfWork(AnalysisWorld().investigation)
                ),
                max_structured_output_attempts=invalid,
            )


@pytest.mark.asyncio
async def test_analyst_constructor_accepts_each_boundary_attempt_count() -> None:
    """Both boundary attempt values are accepted."""
    for value in (1, 2):
        analyst = EvidenceAnalyst(
            input_loader=FakeLoader(AnalysisWorld().analyst_input()),
            llm_client=FakeLlmClient(),
            assessment_persistence=AssessmentPersistenceService(
                lambda: FakePersistenceUnitOfWork(
                    world=AnalysisWorld(),
                    assessments=FakeAssessmentRepository(),
                    audit_events=FakeAuditRepository(),
                    investigations=FakeInvestigationRepository(
                        AnalysisWorld().investigation
                    ),
                ),
                batch_size=100,
            ),
            llm_accounting=LlmAccountingService(
                lambda: FakeAccountingUnitOfWork(AnalysisWorld().investigation)
            ),
            max_structured_output_attempts=value,
        )
        assert analyst is not None


@pytest.mark.asyncio
async def test_non_retryable_invalid_output_is_not_retried(
    harness: Harness,
    world: AnalysisWorld,
) -> None:
    """A non-retryable INVALID_STRUCTURED_OUTPUT fails after one attempt.

    ``LlmError.retryable`` is authoritative: exactly one LLM call and one
    durable reservation occur, no Assessment is persisted, and the typed
    error propagates.
    """
    analyst, fake_llm, persistence_uow, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.persistence,
        harness.accounting_repo,
    )
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False))

    with pytest.raises(LlmError) as holder:
        await analyst.analyze(world.investigation_id)

    assert holder.value.code is LlmErrorCode.INVALID_STRUCTURED_OUTPUT
    assert len(fake_llm.calls) == 1
    assert len(accounting_repo.budget_writes) == 1
    assert persistence_uow.assessments.inserted == []
    assert persistence_uow.investigations.pointer_calls == []


class _PromptConstructionError(RuntimeError):
    """A fixed generic local prompt-construction failure for accounting tests."""


@pytest.mark.asyncio
async def test_initial_prompt_failure_consumes_no_llm_budget(
    harness: Harness,
    world: AnalysisWorld,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A prompt-construction failure before any attempt reserves nothing.

    Prompt construction happens before the durable LLM reservation, so a
    local rendering defect must consume zero budget, make zero model calls,
    and touch no persistence or audit state.
    """
    analyst, fake_llm, persistence_uow, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.persistence,
        harness.accounting_repo,
    )
    prompt_calls: list[int] = []

    def failing_prompts(
        analyst_input: object, *, repair: bool = False
    ) -> tuple[str, str]:
        """Record the call and raise a fixed local exception."""
        del analyst_input, repair
        prompt_calls.append(1)
        raise _PromptConstructionError("local prompt rendering failed")

    monkeypatch.setattr(
        "agentic_threat_investigator.app.evidence_analyst.analyst."
        "build_evidence_analyst_prompts",
        failing_prompts,
    )

    with pytest.raises(_PromptConstructionError):
        await analyst.analyze(world.investigation_id)

    assert len(prompt_calls) == 1
    assert fake_llm.calls == []
    assert accounting_repo.budget_writes == []
    assert accounting_repo.state.budget.llm_calls_used == 0
    assert persistence_uow.assessments.inserted == []
    assert persistence_uow.investigations.pointer_calls == []
    assert persistence_uow.audit_events.events == []


@pytest.mark.asyncio
async def test_repair_prompt_failure_reserves_no_second_call(
    harness: Harness,
    world: AnalysisWorld,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed repair-prompt build counts the prior attempt, not a new one.

    The first model invocation returns retryable invalid structured output and
    stays durably counted; the repair prompt then fails to build, so the
    second reservation must never be written and the repair model call never
    begins.
    """
    analyst, fake_llm, persistence_uow, accounting_repo = (
        harness.analyst,
        harness.llm,
        harness.persistence,
        harness.accounting_repo,
    )
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    prompt_calls: list[bool] = []

    def failing_repair_prompts(
        analyst_input: object, *, repair: bool = False
    ) -> tuple[str, str]:
        """Return the initial prompt pair, then fail building the repair."""
        del analyst_input
        prompt_calls.append(repair)
        if repair:
            raise _PromptConstructionError("local repair prompt rendering failed")
        return "system", "user"

    monkeypatch.setattr(
        "agentic_threat_investigator.app.evidence_analyst.analyst."
        "build_evidence_analyst_prompts",
        failing_repair_prompts,
    )

    with pytest.raises(_PromptConstructionError):
        await analyst.analyze(world.investigation_id)

    assert prompt_calls == [False, True]
    assert len(fake_llm.calls) == 1
    assert len(accounting_repo.budget_writes) == 1
    assert accounting_repo.state.budget.llm_calls_used == 1
    assert persistence_uow.assessments.inserted == []
    assert persistence_uow.investigations.pointer_calls == []
    assert persistence_uow.audit_events.events == []
