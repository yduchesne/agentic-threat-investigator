# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ReportWriterInputLoader deterministic assembly (PR 23B)."""

# The fakes mirror the repository seam shape used by the persistence-service
# suites; the single World fixture carries one terminal identity per row.

from __future__ import annotations

from datetime import UTC, datetime
from typing import Self, cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    UnitOfWork,
)
from agentic_threat_investigator.app.report_writer.errors import (
    ReportWriterInputConsistencyError,
    ReportWriterInputLimitError,
    ReportWriterNoCurrentAssessmentError,
)
from agentic_threat_investigator.app.report_writer.input_loader import (
    ReportWriterInputLoader,
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
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
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
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class FakeInvestigationRepository:
    """Serves exactly one configured investigation row."""

    def __init__(self, visible: InvestigationState | None) -> None:
        self.visible = visible

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        return self.visible


class FakeAssessmentRepository:
    """Serves exactly one configured assessment row."""

    def __init__(self, visible: Assessment | None) -> None:
        self.visible = visible

    async def get_by_id(
        self, assessment_id: UUID, *, include_deleted: bool = False
    ) -> Assessment | None:
        return self.visible


class FakeEvidenceRepository:
    """Serves the configured evidence rows by identity."""

    def __init__(self, rows: dict[UUID, Evidence]) -> None:
        self.rows = rows

    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        return self.rows.get(evidence_id)


class FakeObservationRepository:
    """Serves the configured observation rows by identity."""

    def __init__(self, rows: dict[UUID, RelationshipObservation]) -> None:
        self.rows = rows

    async def get_by_id(self, observation_id: UUID) -> RelationshipObservation | None:
        return self.rows.get(observation_id)


class FakeRelationshipRepository:
    """Serves the configured relationship rows by identity."""

    def __init__(self, rows: dict[UUID, Relationship]) -> None:
        self.rows = rows

    async def get_by_id(
        self, relationship_id: UUID, *, include_deleted: bool = False
    ) -> Relationship | None:
        return self.rows.get(relationship_id)


class FakeEntityRepository:
    """Serves the configured entity rows by identity."""

    def __init__(self, rows: dict[UUID, Entity]) -> None:
        self.rows = rows

    async def get_by_id(
        self, entity_id: UUID, *, include_deleted: bool = False
    ) -> Entity | None:
        return self.rows.get(entity_id)


class FakeResearchResultRepository:
    """Serves the configured research results."""

    def __init__(self, rows: list[ResearchResult]) -> None:
        self.rows = rows

    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> list[ResearchResult]:
        return [row for row in self.rows if row.investigation_id == investigation_id]


class FakeUnitOfWork(UnitOfWork):
    """In-memory transaction boundary tracking close."""

    def __init__(self, world: "World") -> None:
        from agentic_threat_investigator.app.persistence.repositories import (
            AssessmentRepository,
            EntityRepository,
            EvidenceRepository,
            InvestigationRepository,
            RelationshipObservationRepository,
            RelationshipRepository,
            ResearchResultRepository,
        )

        self.investigations = cast(InvestigationRepository, world.investigations)
        self.assessments = cast(AssessmentRepository, world.assessments)
        self.evidence = cast(EvidenceRepository, world.evidence)
        self.relationship_observations = cast(
            RelationshipObservationRepository, world.observations
        )
        self.relationships = cast(RelationshipRepository, world.relationships)
        self.entities = cast(EntityRepository, world.entities)
        self.research_results = cast(ResearchResultRepository, world.research_results)
        self.exited = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        self.exited += 1

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


class World:
    """One complete loader world served by the fakes."""

    def __init__(self) -> None:
        self.investigation_id = uuid4()
        self.assessment_id = uuid4()
        self.source_id = uuid4()
        self.target_id = uuid4()
        self.evidence_id = uuid4()
        self.relationship_id = uuid4()
        self.observation_id = uuid4()
        self.result_id = uuid4()
        self.claim_id = uuid4()
        self.citation_id = uuid4()
        self.investigations = FakeInvestigationRepository(
            InvestigationState(
                investigation_id=self.investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[self.source_id],
                objective="Assess the root indicator.",
                budget=default_investigation_budget(),
                started_at=_RETRIEVED_AT,
                assessment_id=self.assessment_id,
                version=5,
            )
        )
        self.evidence = FakeEvidenceRepository(
            {
                self.evidence_id: Evidence(
                    id=self.evidence_id,
                    investigation_id=self.investigation_id,
                    type=EvidenceType.REPUTATION,
                    subject=EntityRef(
                        id=self.source_id,
                        type=EntityType.DOMAIN,
                        value="example.com",
                    ),
                    source="urn:ati:source:abuseipdb",
                    retrieved_at=_RETRIEVED_AT,
                    facts={"score": 90},
                    raw_payload={"http_headers": {"x-secret": "never-leak"}},
                )
            }
        )
        self.relationship = Relationship(
            id=self.relationship_id,
            source_entity_id=self.source_id,
            target_entity_id=self.target_id,
            type=RelationshipType.ASSOCIATED_WITH,
        )
        self.relationships = FakeRelationshipRepository(
            {self.relationship_id: self.relationship}
        )
        self.entities = FakeEntityRepository(
            {
                self.source_id: Entity(
                    id=self.source_id,
                    type=EntityType.DOMAIN,
                    value="example.com",
                ),
                self.target_id: Entity(
                    id=self.target_id,
                    type=EntityType.MALWARE,
                    value="malware",
                ),
            }
        )
        self.observation = RelationshipObservation(
            id=self.observation_id,
            relationship_id=self.relationship_id,
            evidence_id=self.evidence_id,
            investigation_id=self.investigation_id,
            retrieved_at=_RETRIEVED_AT,
            source="urn:ati:source:abuseipdb",
        )
        self.observations = FakeObservationRepository(
            {self.observation_id: self.observation}
        )
        finding = AnalyticalFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            statement="Reputation evidence indicates malicious activity.",
            confidence=AssessmentConfidence.HIGH,
            support=(
                EvidenceSupport(kind="evidence", evidence_id=self.evidence_id),
                RelationshipSupport(
                    kind="relationship_observation",
                    relationship_observation_id=self.observation_id,
                ),
            ),
        )
        self.assessment = Assessment(
            id=self.assessment_id,
            investigation_id=self.investigation_id,
            verdict=Verdict.MALICIOUS,
            confidence=AssessmentConfidence.HIGH,
            summary="The indicator is malicious.",
            analyzed_evidence_ids=(self.evidence_id,),
            findings=(finding,),
            limitations=("a limitation",),
        )
        self.assessments = FakeAssessmentRepository(self.assessment)
        self.research_results = FakeResearchResultRepository(
            [
                ResearchResult(
                    id=self.result_id,
                    investigation_id=self.investigation_id,
                    subject_entity_id=self.source_id,
                    query="context query",
                    claims=(
                        ResearchClaim(
                            id=self.claim_id,
                            text="context claim",
                            citation_ids=(self.citation_id,),
                        ),
                    ),
                    citations=(
                        ResearchCitation(
                            citation_id=self.citation_id,
                            document_id=uuid4(),
                            source_id="urn:ati:source:mitre_attack",
                            source_record_id="report--x",
                            document_type="test",
                            chunk_sequence=1,
                            text="citation text",
                            title="title",
                        ),
                    ),
                    created_at=_RETRIEVED_AT,
                )
            ]
        )

    def add_second_evidence(self) -> UUID:
        """Extend the world with a second analyzed Evidence row."""
        second_id = uuid4()
        self.evidence.rows[second_id] = Evidence(
            id=second_id,
            investigation_id=self.investigation_id,
            type=EvidenceType.REPUTATION,
            subject=EntityRef(
                id=self.source_id, type=EntityType.DOMAIN, value="example.com"
            ),
            source="urn:ati:source:threatfox",
            retrieved_at=_RETRIEVED_AT,
            facts={"found": False},
        )
        self.assessment = self.assessment.model_copy(
            update={
                "analyzed_evidence_ids": (self.evidence_id, second_id),
                "findings": (
                    self.assessment.findings[0].model_copy(
                        update={
                            "support": (
                                EvidenceSupport(
                                    kind="evidence", evidence_id=self.evidence_id
                                ),
                                EvidenceSupport(kind="evidence", evidence_id=second_id),
                            )
                        }
                    ),
                ),
            }
        )
        self.assessments.visible = self.assessment
        return second_id

    def add_second_research_result(self) -> UUID:
        """Extend the world with a second ResearchResult row."""
        second_id = uuid4()
        second_claim_id = uuid4()
        self.research_results.rows.append(
            ResearchResult(
                id=second_id,
                investigation_id=self.investigation_id,
                subject_entity_id=self.source_id,
                query="second context query",
                claims=(
                    ResearchClaim(
                        id=second_claim_id,
                        text="second context claim",
                        citation_ids=(self.citation_id,),
                    ),
                ),
                citations=self.research_results.rows[0].citations,
                created_at=_RETRIEVED_AT,
            )
        )
        return second_id

    def loader(
        self,
        *,
        max_findings: int = 50,
        max_evidence: int = 100,
        max_relationship_observations: int = 200,
        max_research_results: int = 20,
        max_research_claims: int = 100,
        max_serialized_input_bytes: int = 262_144,
    ) -> ReportWriterInputLoader:
        """Build the loader bound to this world."""
        return ReportWriterInputLoader(
            lambda: FakeUnitOfWork(self),
            max_findings=max_findings,
            max_evidence=max_evidence,
            max_relationship_observations=max_relationship_observations,
            max_research_results=max_research_results,
            max_research_claims=max_research_claims,
            max_serialized_input_bytes=max_serialized_input_bytes,
        )


def _inconclusive_world() -> World:
    """Return a world whose investigation has no current assessment."""
    world = World()
    visible = world.investigations.visible
    if visible is None:  # pragma: no cover - world always sets a row
        raise AssertionError("world investigation is missing")
    world.investigations.visible = visible.model_copy(update={"assessment_id": None})
    return world


@pytest.mark.asyncio
async def test_u11_no_current_assessment_async() -> None:
    """23B-U11: an Investigation without a current Assessment fails typed."""
    world = _inconclusive_world()
    with pytest.raises(ReportWriterNoCurrentAssessmentError):
        await world.loader().load(world.investigation_id)


@pytest.mark.asyncio
async def test_u12_assessment_of_another_investigation_fails_closed() -> None:
    """23B-U12: an Assessment bound to another Investigation fails closed."""
    world = World()
    other = world.assessment.model_copy(update={"investigation_id": uuid4()})
    world.assessments.visible = other
    with pytest.raises(ReportWriterInputConsistencyError):
        await world.loader().load(world.investigation_id)


@pytest.mark.asyncio
async def test_u13_missing_analyzed_evidence_fails_closed() -> None:
    """23B-U13: missing analyzed Evidence fails closed (never dropped)."""
    world = World()
    world.evidence.rows.clear()
    with pytest.raises(ReportWriterInputConsistencyError):
        await world.loader().load(world.investigation_id)


@pytest.mark.asyncio
async def test_u14_missing_observation_support_fails_closed() -> None:
    """23B-U14: missing RelationshipObservation support fails closed."""
    world = World()
    world.observations.rows.clear()
    with pytest.raises(ReportWriterInputConsistencyError):
        await world.loader().load(world.investigation_id)


@pytest.mark.asyncio
async def test_u14b_missing_relationship_fails_closed() -> None:
    """Missing canonical Relationship for an observation fails closed."""
    world = World()
    world.relationships.rows.clear()
    with pytest.raises(ReportWriterInputConsistencyError):
        await world.loader().load(world.investigation_id)


@pytest.mark.asyncio
async def test_u14c_missing_endpoint_entity_fails_closed() -> None:
    """Missing canonical endpoint Entity for an observation fails closed."""
    world = World()
    world.entities.rows.pop(world.target_id)
    with pytest.raises(ReportWriterInputConsistencyError):
        await world.loader().load(world.investigation_id)


@pytest.mark.asyncio
async def test_u15_research_of_another_investigation_excluded() -> None:
    """23B-U15: research from another Investigation is excluded per contract."""
    world = World()
    world.research_results.rows[0] = world.research_results.rows[0].model_copy(
        update={"investigation_id": uuid4()}
    )
    loaded = await world.loader().load(world.investigation_id)
    assert loaded.research_results == ()


@pytest.mark.asyncio
async def test_u16_oversized_evidence_set_is_typed_limit_failure() -> None:
    """23B-U16: an oversized analyzed Evidence set fails typed before LLM."""
    world = World()
    world.add_second_evidence()
    with pytest.raises(ReportWriterInputLimitError):
        await world.loader(max_evidence=1).load(world.investigation_id)


@pytest.mark.asyncio
async def test_u17_oversized_research_set_is_typed_limit_failure() -> None:
    """23B-U17: an oversized research set fails typed before LLM."""
    world = World()
    world.add_second_research_result()
    with pytest.raises(ReportWriterInputLimitError):
        await world.loader(max_research_results=1).load(world.investigation_id)
    with pytest.raises(ReportWriterInputLimitError):
        await world.loader(max_research_claims=1).load(world.investigation_id)


@pytest.mark.asyncio
async def test_u18_raw_evidence_payload_never_included() -> None:
    """23B-U18: raw Evidence payloads never enter the report input."""
    world = World()
    loaded = await world.loader().load(world.investigation_id)
    assert len(loaded.evidence) == 1
    assert loaded.evidence[0].facts == {"score": 90}
    serialized = loaded.model_dump_json()
    assert "never-leak" not in serialized
    assert "http_headers" not in serialized


@pytest.mark.asyncio
async def test_u19_deterministic_source_ordering() -> None:
    """23B-U19: input ordering is deterministic for the same world."""
    world = World()
    first = await world.loader().load(world.investigation_id)
    second = await world.loader().load(world.investigation_id)
    assert first.model_dump_json() == second.model_dump_json()
    assert [item.evidence_id for item in first.evidence] == [world.evidence_id]
    assert [
        item.relationship_observation_id for item in first.relationship_observations
    ] == [world.observation_id]


@pytest.mark.asyncio
async def test_u20_deterministic_prompt_bytes() -> None:
    """23B-U20: the same input produces identical prompt bytes."""
    from agentic_threat_investigator.app.report_writer.prompts import (
        build_report_writer_prompts,
    )

    world = World()
    loaded = await world.loader().load(world.investigation_id)
    system_a, user_a = build_report_writer_prompts(loaded)
    system_b, user_b = build_report_writer_prompts(loaded)
    assert system_a == system_b
    assert user_a == user_b
    assert "never-leak" not in user_a


@pytest.mark.asyncio
async def test_loader_closes_transaction() -> None:
    """The read-only UnitOfWork is closed before the input escapes."""
    world = World()
    uow = FakeUnitOfWork(world)
    loader = ReportWriterInputLoader(lambda: uow)
    await loader.load(world.investigation_id)
    assert uow.exited == 1


@pytest.mark.asyncio
async def test_serialized_input_bound_applied() -> None:
    """The serialized-byte bound is enforced before the input escapes."""
    world = World()
    with pytest.raises(ReportWriterInputLimitError):
        await world.loader(max_serialized_input_bytes=1000).load(world.investigation_id)


@pytest.mark.asyncio
async def test_missing_investigation_raises_not_found() -> None:
    """A missing Investigation surfaces the typed not-found error."""
    world = World()
    world.investigations.visible = None
    with pytest.raises(InvestigationNotFoundError):
        await world.loader().load(world.investigation_id)
