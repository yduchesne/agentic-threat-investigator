# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Report Writer fixtures, materialization, and canonical output (PR 23B).

The materializer persists one report scenario fixture through the production
application seams — graph (Investigation, Entities, Evidence, Relationships,
RelationshipObservations) through the ``UnitOfWork``, the authoritative
Assessment through ``AssessmentPersistenceService``, and the ResearchResults
through ``ResearchResultPersistenceService`` — and returns the resolution
that maps every semantic label to its exact persisted UUID.

The canonical output builder turns a scenario and its resolution into the
:class:`ReportWriterOutput` that satisfies the scenario envelope: finding
order from the required finding ordinals, research selection from the
required research-claim labels, and (when the scenario requires narrative)
one statement carrying the scenario's first required canonical phrase with
typed support references resolved to the exact persisted identities.

This is test/evaluation infrastructure only. It proves evaluator behavior
and product wiring; it never claims anything about real-model intelligence.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4, uuid5

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.research_persistence import (
    ResearchResultPersistenceService,
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
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import EntityRef, Evidence
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    ReportNarrativeStatement,
    ReportResearchSelection,
    ReportWriterOutput,
    ResearchClaimRef,
)
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)
from agentic_threat_investigator.evaluation.analyst.materializer import (
    DEFAULT_SCENARIO_NAMESPACE,
)
from agentic_threat_investigator.evaluation.analyst.models import (
    FixtureEntity,
    FixtureEvidence,
    FixtureObservation,
    FixtureRelationship,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ReportWriterScenario,
    ReportWriterScenarioResolution,
)

_FIXED = datetime(2026, 1, 2, tzinfo=UTC)
"""Fixed UTC timestamp for persisted rows that declare none."""

REPORT_SCENARIO_NAMESPACE = uuid5(
    DEFAULT_SCENARIO_NAMESPACE, "urn:ati:evaluation:report_writer:v1"
)
"""Stable namespace for report scenario derived identities."""


@dataclass(frozen=True)
class FixtureFinding:
    """One authoritative Assessment finding the fixture materializes."""

    category: FindingCategory
    disposition: FindingDisposition
    statement: str
    confidence: AssessmentConfidence
    evidence_labels: tuple[str, ...] = ()
    observation_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class FixtureResearchClaim:
    """One persisted ResearchClaim the fixture materializes."""

    label: str
    text: str
    citation_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class FixtureResearchCitation:
    """One persisted ResearchCitation snapshot the fixture materializes."""

    label: str
    title: str
    source_id: str
    source_record_id: str
    text: str
    source_url: str | None = None


@dataclass(frozen=True)
class FixtureResearchResult:
    """One persisted ResearchResult the fixture materializes."""

    subject_label: str
    query: str
    claims: tuple[FixtureResearchClaim, ...] = ()
    citations: tuple[FixtureResearchCitation, ...] = ()


@dataclass(frozen=True)
class ReportWriterFixture:
    """A deterministic, label-based description of one report scenario graph."""

    objective: str
    root_entity: str
    entities: tuple[FixtureEntity, ...]
    evidence: tuple[FixtureEvidence, ...] = ()
    relationships: tuple[FixtureRelationship, ...] = ()
    observations: tuple[FixtureObservation, ...] = ()
    verdict: Verdict = Verdict.MALICIOUS
    confidence: AssessmentConfidence = AssessmentConfidence.HIGH
    summary: str = "Canonical scenario assessment summary."
    findings: tuple[FixtureFinding, ...] = ()
    limitations: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    recommended_next_steps: tuple[str, ...] = ()
    research_results: tuple[FixtureResearchResult, ...] = ()


def planned_report_identity(
    scenario: ReportWriterScenario,
    kind: str,
    label: str,
    *,
    namespace: UUID = REPORT_SCENARIO_NAMESPACE,
) -> UUID:
    """Return the deterministic planned UUID for one fixture label and kind."""
    return uuid5(
        namespace,
        f"urn:ati:scenario:{scenario.id}:v{scenario.version}:{kind}:{label}",
    )


def report_scenario_resolution(
    scenario: ReportWriterScenario,
    fixture: ReportWriterFixture,
    *,
    namespace: UUID = REPORT_SCENARIO_NAMESPACE,
) -> ReportWriterScenarioResolution:
    """Return the planned identities for one scenario (no database needed)."""
    investigation_id = planned_report_identity(
        scenario, "investigation", "root", namespace=namespace
    )
    assessment_id = planned_report_identity(
        scenario, "assessment", "root", namespace=namespace
    )
    entity_ids = {
        entity.label: planned_report_identity(
            scenario, "entity", entity.label, namespace=namespace
        )
        for entity in fixture.entities
    }
    evidence_ids = {
        evidence.label: planned_report_identity(
            scenario, "evidence", evidence.label, namespace=namespace
        )
        for evidence in fixture.evidence
    }
    relationship_ids = {
        relationship.label: planned_report_identity(
            scenario, "relationship", relationship.label, namespace=namespace
        )
        for relationship in fixture.relationships
    }
    observation_ids = {
        observation.label: planned_report_identity(
            scenario, "observation", observation.label, namespace=namespace
        )
        for observation in fixture.observations
    }
    research_result_ids: dict[str, UUID] = {}
    research_claim_ids: dict[str, UUID] = {}
    citation_ids: dict[str, UUID] = {}
    for ordinal, result in enumerate(fixture.research_results, start=1):
        result_label = f"result_{ordinal}"
        research_result_ids[result_label] = planned_report_identity(
            scenario, "research_result", result_label, namespace=namespace
        )
        for claim in result.claims:
            research_claim_ids[claim.label] = planned_report_identity(
                scenario, "research_claim", claim.label, namespace=namespace
            )
        for citation in result.citations:
            citation_ids[citation.label] = planned_report_identity(
                scenario, "citation", citation.label, namespace=namespace
            )
    return ReportWriterScenarioResolution(
        investigation_id=investigation_id,
        assessment_id=assessment_id,
        entity_ids=entity_ids,
        evidence_ids=evidence_ids,
        relationship_ids=relationship_ids,
        observation_ids=observation_ids,
        research_result_ids=research_result_ids,
        research_claim_ids=research_claim_ids,
        citation_ids=citation_ids,
    )


class ReportWriterScenarioMaterializer:
    """Persist one report fixture through the production application seams."""

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        *,
        namespace: UUID = REPORT_SCENARIO_NAMESPACE,
    ) -> None:
        """Bind the UnitOfWork factory and identity namespace."""
        self._uow_factory = uow_factory
        self._namespace = namespace

    async def materialize(
        self,
        scenario: ReportWriterScenario,
        fixture: ReportWriterFixture,
    ) -> ReportWriterScenarioResolution:
        """Persist graph, Assessment, and research; return the resolution.

        Identity maps are built from the identities the repositories actually
        persisted (entities and relationships are canonical resources whose
        durable identities may differ from the planned UUIDs); the Assessment
        and research identities are planned and confirmed.
        """
        planned = report_scenario_resolution(
            scenario, fixture, namespace=self._namespace
        )
        (
            entity_ids,
            evidence_ids,
            relationship_ids,
            observation_ids,
        ) = await self._persist_graph(scenario, fixture, planned)
        resolution = ReportWriterScenarioResolution(
            investigation_id=planned.investigation_id,
            assessment_id=planned.assessment_id,
            entity_ids=entity_ids,
            evidence_ids=evidence_ids,
            relationship_ids=relationship_ids,
            observation_ids=observation_ids,
            research_result_ids=planned.research_result_ids,
            research_claim_ids=planned.research_claim_ids,
            citation_ids=planned.citation_ids,
        )
        await self._persist_assessment(fixture, resolution)
        await self._persist_research(fixture, resolution)
        return resolution

    async def _persist_graph(
        self,
        scenario: ReportWriterScenario,
        fixture: ReportWriterFixture,
        planned: ReportWriterScenarioResolution,
    ) -> tuple[
        dict[str, UUID],
        dict[str, UUID],
        dict[str, UUID],
        dict[str, UUID],
    ]:
        """Persist entities, Investigation, Evidence, Relationships, Observations.

        Returns the repository-confirmed identity maps; canonical Entity and
        Relationship identities are taken from the repository return values.
        """
        del scenario
        entity_ids: dict[str, UUID] = {}
        evidence_ids: dict[str, UUID] = {}
        relationship_ids: dict[str, UUID] = {}
        observation_ids: dict[str, UUID] = {}
        async with self._uow_factory() as uow:
            for entity in fixture.entities:
                persisted_entity = await uow.entities.upsert(
                    Entity(
                        id=planned.entity_ids[entity.label],
                        type=entity.type,
                        value=entity.value,
                    )
                )
                entity_ids[entity.label] = _confirm_id(
                    persisted_entity, "entity", entity.label
                )
            await uow.investigations.create(
                InvestigationState(
                    investigation_id=planned.investigation_id,
                    status=InvestigationStatus.RUNNING,
                    trigger_type=InvestigationTriggerType.MANUAL,
                    root_entity_ids=[entity_ids[fixture.root_entity]],
                    objective=fixture.objective,
                    budget=default_investigation_budget(),
                    started_at=_FIXED,
                )
            )
            for evidence in fixture.evidence:
                subject = _entity_by_label(fixture, evidence.subject)
                persisted_evidence = await uow.evidence.insert(
                    Evidence(
                        id=planned.evidence_ids[evidence.label],
                        investigation_id=planned.investigation_id,
                        type=evidence.type,
                        subject=EntityRef(
                            id=entity_ids[evidence.subject],
                            type=subject.type,
                            value=subject.value,
                        ),
                        source=evidence.source,
                        observed_at=evidence.observed_at,
                        retrieved_at=evidence.retrieved_at or _FIXED,
                        facts=dict(evidence.facts),
                    )
                )
                evidence_ids[evidence.label] = _confirm_id(
                    persisted_evidence, "evidence", evidence.label
                )
            for relationship in fixture.relationships:
                persisted_relationship = await uow.relationships.upsert(
                    Relationship(
                        id=planned.relationship_ids[relationship.label],
                        source_entity_id=entity_ids[relationship.source],
                        target_entity_id=entity_ids[relationship.target],
                        type=relationship.type,
                    )
                )
                relationship_ids[relationship.label] = _confirm_id(
                    persisted_relationship, "relationship", relationship.label
                )
            for observation in fixture.observations:
                persisted_observation = await uow.relationship_observations.append(
                    RelationshipObservation(
                        id=planned.observation_ids[observation.label],
                        relationship_id=relationship_ids[observation.relationship],
                        evidence_id=evidence_ids[observation.evidence],
                        investigation_id=planned.investigation_id,
                        retrieved_at=_FIXED,
                        source=observation.source,
                        confidence=observation.confidence,
                    )
                )
                observation_ids[observation.label] = _confirm_id(
                    persisted_observation, "relationship_observation", observation.label
                )
        return entity_ids, evidence_ids, relationship_ids, observation_ids

    async def _persist_assessment(
        self,
        fixture: ReportWriterFixture,
        resolution: ReportWriterScenarioResolution,
    ) -> None:
        """Persist the authoritative Assessment through the production service."""
        findings: list[AnalyticalFinding] = []
        for finding in fixture.findings:
            support: list[EvidenceSupport | RelationshipSupport] = []
            for label in finding.evidence_labels:
                support.append(
                    EvidenceSupport(
                        kind="evidence",
                        evidence_id=resolution.evidence_ids[label],
                    )
                )
            for label in finding.observation_labels:
                support.append(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=resolution.observation_ids[label],
                    )
                )
            findings.append(
                AnalyticalFinding(
                    category=finding.category,
                    disposition=finding.disposition,
                    statement=finding.statement,
                    confidence=finding.confidence,
                    support=tuple(support),
                )
            )
        analyzed = tuple(
            resolution.evidence_ids[evidence.label] for evidence in fixture.evidence
        )
        assessment = Assessment(
            id=resolution.assessment_id,
            investigation_id=resolution.investigation_id,
            verdict=fixture.verdict,
            confidence=fixture.confidence,
            summary=fixture.summary,
            analyzed_evidence_ids=analyzed,
            findings=tuple(findings),
            limitations=fixture.limitations,
            unresolved_questions=fixture.unresolved_questions,
            recommended_next_steps=fixture.recommended_next_steps,
        )
        persisted = await AssessmentPersistenceService(
            self._uow_factory
        ).persist_assessment(assessment)
        if persisted.id is None:  # pragma: no cover - service assigns identity
            raise ValueError("assessment persistence returned no identity")
        if persisted.id != resolution.assessment_id:
            raise ValueError(
                "assessment persistence did not confirm the planned identity"
            )

    async def _persist_research(
        self,
        fixture: ReportWriterFixture,
        resolution: ReportWriterScenarioResolution,
    ) -> None:
        """Persist the fixture's ResearchResults through the production service."""
        if not fixture.research_results:
            return
        persistence = ResearchResultPersistenceService(self._uow_factory)
        for ordinal, result in enumerate(fixture.research_results, start=1):
            result_label = f"result_{ordinal}"
            claims = tuple(
                ResearchClaim(
                    id=resolution.research_claim_ids[claim.label],
                    text=claim.text,
                    citation_ids=tuple(
                        resolution.citation_ids[label]
                        for label in claim.citation_labels
                    ),
                )
                for claim in result.claims
            )
            citations = tuple(
                ResearchCitation(
                    citation_id=resolution.citation_ids[citation.label],
                    document_id=uuid4(),
                    source_id=citation.source_id,
                    source_record_id=citation.source_record_id,
                    document_type="test",
                    chunk_sequence=1,
                    text=citation.text,
                    title=citation.title,
                    source_url=citation.source_url,
                )
                for citation in result.citations
            )
            await persistence.persist(
                ResearchResult(
                    id=resolution.research_result_ids[result_label],
                    investigation_id=resolution.investigation_id,
                    subject_entity_id=resolution.entity_ids[result.subject_label],
                    query=result.query,
                    claims=claims,
                    citations=citations,
                    created_at=_FIXED,
                )
            )


def build_canonical_report_output(
    scenario: ReportWriterScenario,
    resolution: ReportWriterScenarioResolution,
    fixture: ReportWriterFixture,
) -> ReportWriterOutput:
    """Build the deterministic output satisfying the scenario envelope."""
    expected = scenario.expected
    finding_order = tuple(sorted(expected.required_assessment_finding_ordinals))

    research_context: list[ReportResearchSelection] = []
    for label in expected.required_research_claim_labels:
        result_label = _result_label_for_claim(fixture, label)
        if result_label is None or label not in resolution.research_claim_ids:
            continue
        research_context.append(
            ReportResearchSelection(
                research_result_id=resolution.research_result_ids[result_label],
                research_claim_id=resolution.research_claim_ids[label],
            )
        )

    support: list[AssessmentFindingRef | ResearchClaimRef] = []
    for ordinal in finding_order:
        support.append(
            AssessmentFindingRef(
                kind="assessment_finding",
                assessment_id=resolution.assessment_id,
                finding_ordinal=ordinal,
            )
        )
    for selection in research_context:
        support.append(
            ResearchClaimRef(
                kind="research_claim",
                research_result_id=selection.research_result_id,
                research_claim_id=selection.research_claim_id,
            )
        )

    statements: tuple[ReportNarrativeStatement, ...] = ()
    if expected.required_phrases:
        statements = (
            ReportNarrativeStatement(
                text=expected.required_phrases[0],
                support=tuple(support),
            ),
        )
    return ReportWriterOutput(
        title=f"Canonical report for {scenario.id}",
        executive_summary=statements,
        finding_order=finding_order,
        research_context=tuple(research_context),
    )


def _result_label_for_claim(
    fixture: ReportWriterFixture, claim_label: str
) -> str | None:
    """Return the result label owning one claim label, if any."""
    for ordinal, result in enumerate(fixture.research_results, start=1):
        for claim in result.claims:
            if claim.label == claim_label:
                return f"result_{ordinal}"
    return None


def _entity_by_label(fixture: ReportWriterFixture, label: str) -> FixtureEntity:
    """Return the declared fixture entity for one label."""
    for entity in fixture.entities:
        if entity.label == label:
            return entity
    raise ValueError(  # pragma: no cover - fixtures validate their labels
        f"fixture declares no entity with label {label!r}"
    )


def _confirm_id(persisted: object, kind: str, label: str) -> UUID:
    """Return the repository-confirmed persisted identity or fail closed."""
    persisted_id = getattr(persisted, "id", None)
    if persisted_id is None or not isinstance(persisted_id, UUID):
        raise ValueError(
            f"repository did not confirm a persisted {kind} id for label {label!r}"
        )
    confirmed: UUID = persisted_id
    return confirmed
