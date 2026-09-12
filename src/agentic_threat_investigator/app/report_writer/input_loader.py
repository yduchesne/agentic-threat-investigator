# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic assembly of the Report Writer input (PR 23B).

The loader runs one short, read-only UnitOfWork against persisted
authoritative resources only, then closes the transaction before the caller
may invoke the LLM. The current Assessment is resolved through the
Investigation's durable ``assessment_id`` pointer — never ``MAX(version)`` —
and the Evidence/RelationshipObservation material is exactly the
Assessment's analyzed set and finding supports (PR 23B snapshot rule), never
arbitrary later Evidence/Research added after the Assessment.

Raw provider payloads never enter the Report Writer: evidence is minimized
through the analyst view (:class:`AnalystEvidenceItem`), which carries
normalized facts only. Input ordering and bounds are deterministic: the same
persisted investigation state always yields the same serialized
:class:`~agentic_threat_investigator.domain.report.ReportWriterInput`.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    UnitOfWork,
)
from agentic_threat_investigator.app.report_writer.errors import (
    ReportWriterInputConsistencyError,
    ReportWriterInputLimitError,
    ReportWriterNoCurrentAssessmentError,
)
from agentic_threat_investigator.domain.analyst import (
    AnalystEntity,
    AnalystEvidenceItem,
    AnalystRelationshipObservation,
)
from agentic_threat_investigator.domain.assessment import (
    Assessment,
    RelationshipSupport,
)
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import EntityRef, Evidence
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)
from agentic_threat_investigator.domain.report import ReportWriterInput
from agentic_threat_investigator.domain.research import ResearchResult

_BOUND_FINDINGS = "assessment_findings"
_BOUND_EVIDENCE = "analyzed_evidence"
_BOUND_OBSERVATIONS = "relationship_observations"
_BOUND_RESEARCH_RESULTS = "research_results"
_BOUND_RESEARCH_CLAIMS = "research_claims"
_BOUND_SERIALIZED = "serialized_input"

# Hard constructor ceilings mirroring the Settings validators so a direct
# caller cannot bypass the configured safety ceilings.
_MAX_FINDINGS_CEILING = 500
_MAX_EVIDENCE_CEILING = 500
_MAX_OBSERVATIONS_CEILING = 1000
_MAX_RESEARCH_RESULTS_CEILING = 200
_MAX_RESEARCH_CLAIMS_CEILING = 2000
_MAX_INPUT_BYTES_CEILING = 1_000_000
_MAX_INPUT_BYTES_FLOOR = 1000


class ReportWriterInputLoader:
    """Assemble the immutable, bounded report input for one Investigation.

    ``max_findings``, ``max_evidence``, ``max_relationship_observations``,
    ``max_research_results``, ``max_research_claims``, and
    ``max_serialized_input_bytes`` are the explicit context bounds; an
    oversize input raises :class:`ReportWriterInputLimitError` before any
    model call. Hard ceilings mirror the ``Settings`` validators so direct
    construction cannot bypass them.
    """

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        *,
        max_findings: int = 50,
        max_evidence: int = 100,
        max_relationship_observations: int = 200,
        max_research_results: int = 20,
        max_research_claims: int = 100,
        max_serialized_input_bytes: int = 262_144,
    ) -> None:
        """Bind the UnitOfWork factory and the explicit context bounds."""
        if not 1 <= max_findings <= _MAX_FINDINGS_CEILING:
            raise ValueError(
                f"max_findings must be in the range 1..{_MAX_FINDINGS_CEILING}"
            )
        if not 1 <= max_evidence <= _MAX_EVIDENCE_CEILING:
            raise ValueError(
                f"max_evidence must be in the range 1..{_MAX_EVIDENCE_CEILING}"
            )
        if not 1 <= max_relationship_observations <= _MAX_OBSERVATIONS_CEILING:
            raise ValueError(
                "max_relationship_observations must be in the range "
                f"1..{_MAX_OBSERVATIONS_CEILING}"
            )
        if not 1 <= max_research_results <= _MAX_RESEARCH_RESULTS_CEILING:
            raise ValueError(
                "max_research_results must be in the range "
                f"1..{_MAX_RESEARCH_RESULTS_CEILING}"
            )
        if not 1 <= max_research_claims <= _MAX_RESEARCH_CLAIMS_CEILING:
            raise ValueError(
                "max_research_claims must be in the range "
                f"1..{_MAX_RESEARCH_CLAIMS_CEILING}"
            )
        if (
            not _MAX_INPUT_BYTES_FLOOR
            <= max_serialized_input_bytes
            <= _MAX_INPUT_BYTES_CEILING
        ):
            raise ValueError(
                "max_serialized_input_bytes must be in the range "
                f"{_MAX_INPUT_BYTES_FLOOR}..{_MAX_INPUT_BYTES_CEILING}"
            )
        self._uow_factory = uow_factory
        self._max_findings = max_findings
        self._max_evidence = max_evidence
        self._max_relationship_observations = max_relationship_observations
        self._max_research_results = max_research_results
        self._max_research_claims = max_research_claims
        self._max_serialized_input_bytes = max_serialized_input_bytes

    async def load(self, investigation_id: UUID) -> ReportWriterInput:
        """Load the bounded input in one read-only UnitOfWork.

        The UnitOfWork is closed before the returned input escapes, so no
        transaction is ever left open across LLM latency.
        """
        async with self._uow_factory() as uow:
            return await self._load_in_transaction(uow, investigation_id)

    async def _load_in_transaction(
        self, uow: UnitOfWork, investigation_id: UUID
    ) -> ReportWriterInput:
        """Assemble the input while the read-only transaction is open."""
        # Loading several correlated resource maps in one loop per resource is
        # intrinsic; the branch/local counts reflect that shape.
        investigation = await uow.investigations.get_by_id(investigation_id)
        if investigation is None:
            raise InvestigationNotFoundError(str(investigation_id))

        assessment_id = investigation.assessment_id
        if assessment_id is None:
            raise ReportWriterNoCurrentAssessmentError(investigation_id)

        assessment = await uow.assessments.get_by_id(assessment_id)
        if assessment is None:
            raise ReportWriterInputConsistencyError(
                f"current assessment is missing or not visible: {assessment_id}"
            )
        if assessment.investigation_id != investigation_id:
            raise ReportWriterInputConsistencyError(
                f"current assessment belongs to another investigation: {assessment_id}"
            )
        if len(assessment.findings) > self._max_findings:
            raise ReportWriterInputLimitError(
                _BOUND_FINDINGS, self._max_findings, len(assessment.findings)
            )

        # Evidence material is exactly the Assessment's analyzed set (PR 23B
        # snapshot rule). Every identity must resolve to a visible Evidence of
        # this Investigation; missing provenance fails closed.
        evidence_items = tuple(
            await self._load_analyzed_evidence(uow, investigation_id, assessment)
        )

        observations, relationships, entities = await self._load_observation_context(
            uow, investigation_id, assessment
        )
        observation_items = self._build_observation_items(
            observations, relationships, entities
        )
        if len(observation_items) > self._max_relationship_observations:
            raise ReportWriterInputLimitError(
                _BOUND_OBSERVATIONS,
                self._max_relationship_observations,
                len(observation_items),
            )

        research_results = await self._load_research_results(uow, investigation_id)

        report_input = ReportWriterInput(
            investigation_id=investigation_id,
            objective=investigation.objective,
            assessment=assessment,
            evidence=evidence_items,
            relationship_observations=observation_items,
            research_results=research_results,
        )
        serialized = report_input.model_dump_json().encode("utf-8")
        if len(serialized) > self._max_serialized_input_bytes:
            raise ReportWriterInputLimitError(
                _BOUND_SERIALIZED,
                self._max_serialized_input_bytes,
                len(serialized),
            )
        return report_input

    async def _load_analyzed_evidence(
        self,
        uow: UnitOfWork,
        investigation_id: UUID,
        assessment: Assessment,
    ) -> list[AnalystEvidenceItem]:
        """Load the exact analyzed Evidence set in Assessment order."""
        analyzed = list(assessment.analyzed_evidence_ids)
        if len(analyzed) > self._max_evidence:
            raise ReportWriterInputLimitError(
                _BOUND_EVIDENCE, self._max_evidence, len(analyzed)
            )
        items: list[AnalystEvidenceItem] = []
        for evidence_id in analyzed:
            evidence = await uow.evidence.get_by_id(evidence_id)
            if evidence is None:
                raise ReportWriterInputConsistencyError(
                    f"analyzed evidence is missing or not visible: {evidence_id}"
                )
            if evidence.investigation_id != investigation_id:
                raise ReportWriterInputConsistencyError(
                    f"analyzed evidence belongs to another investigation: {evidence_id}"
                )
            items.append(self._build_evidence_item(evidence))
        return items

    async def _load_observation_context(
        self,
        uow: UnitOfWork,
        investigation_id: UUID,
        assessment: Assessment,
    ) -> tuple[
        list[RelationshipObservation],
        dict[UUID, Relationship],
        dict[UUID, Entity],
    ]:
        """Load the observation support set and its render context.

        Only RelationshipObservations referenced by Assessment findings are
        report material; each must resolve to Evidence of the analyzed set
        and to a stable Relationship with visible endpoint Entities.
        """
        observation_ids: list[UUID] = []
        for finding in assessment.findings:
            for support in finding.support:
                if isinstance(support, RelationshipSupport):
                    observation_ids.append(support.relationship_observation_id)
        if len(observation_ids) > self._max_relationship_observations:
            raise ReportWriterInputLimitError(
                _BOUND_OBSERVATIONS,
                self._max_relationship_observations,
                len(observation_ids),
            )

        analyzed = set(assessment.analyzed_evidence_ids)
        observations: list[RelationshipObservation] = []
        for observation_id in observation_ids:
            observation = await uow.relationship_observations.get_by_id(observation_id)
            if observation is None:
                raise ReportWriterInputConsistencyError(
                    f"relationship observation support is missing or not visible: "
                    f"{observation_id}"
                )
            if (
                observation.investigation_id is not None
                and observation.investigation_id != investigation_id
            ):
                raise ReportWriterInputConsistencyError(
                    f"relationship observation belongs to another investigation: "
                    f"{observation_id}"
                )
            if observation.evidence_id not in analyzed:
                raise ReportWriterInputConsistencyError(
                    f"observation evidence is outside the analyzed set: "
                    f"{observation_id}"
                )
            observations.append(observation)

        relationships: dict[UUID, Relationship] = {}
        pending_relationships = {
            observation.relationship_id for observation in observations
        }
        for relationship_id in pending_relationships:
            relationship = await uow.relationships.get_by_id(relationship_id)
            if relationship is None:
                raise ReportWriterInputConsistencyError(
                    f"relationship observation references a missing or "
                    f"ineligible relationship: {relationship_id}"
                )
            relationships[relationship_id] = relationship

        entities: dict[UUID, Entity] = {}
        pending_entities = {
            endpoint
            for relationship in relationships.values()
            for endpoint in (
                relationship.source_entity_id,
                relationship.target_entity_id,
            )
        }
        for entity_id in pending_entities:
            entity = await uow.entities.get_by_id(entity_id)
            if entity is None:
                raise ReportWriterInputConsistencyError(
                    f"relationship observation references a missing or "
                    f"ineligible entity: {entity_id}"
                )
            entities[entity_id] = entity
        return observations, relationships, entities

    async def _load_research_results(
        self,
        uow: UnitOfWork,
        investigation_id: UUID,
    ) -> tuple[ResearchResult, ...]:
        """Load bounded persisted ResearchResults in deterministic order."""
        results = await uow.research_results.list_by_investigation(investigation_id)
        if len(results) > self._max_research_results:
            raise ReportWriterInputLimitError(
                _BOUND_RESEARCH_RESULTS,
                self._max_research_results,
                len(results),
            )
        claim_count = sum(len(result.claims) for result in results)
        if claim_count > self._max_research_claims:
            raise ReportWriterInputLimitError(
                _BOUND_RESEARCH_CLAIMS,
                self._max_research_claims,
                claim_count,
            )
        return tuple(results)

    @staticmethod
    def _build_observation_items(
        observations: list[RelationshipObservation],
        relationships: dict[UUID, Relationship],
        entities: dict[UUID, Entity],
    ) -> tuple[AnalystRelationshipObservation, ...]:
        """Map resolved observations to the deterministic analyst view."""
        items: list[AnalystRelationshipObservation] = []
        for observation in observations:
            relationship = relationships[observation.relationship_id]
            source_entity = entities[relationship.source_entity_id]
            target_entity = entities[relationship.target_entity_id]
            items.append(
                AnalystRelationshipObservation(
                    relationship_observation_id=observation.id,
                    evidence_id=observation.evidence_id,
                    relationship_id=observation.relationship_id,
                    relationship_type=relationship.type,
                    source_entity=_analyst_entity(source_entity),
                    target_entity=_analyst_entity(target_entity),
                    observed_at=observation.observed_at,
                    retrieved_at=observation.retrieved_at,
                    source=observation.source,
                    confidence=observation.confidence,
                )
            )
        return tuple(items)

    @staticmethod
    def _build_evidence_item(evidence: Evidence) -> AnalystEvidenceItem:
        """Map one persisted Evidence row to its minimized analyst view.

        Only normalized facts are carried; ``raw_payload`` never enters the
        Report Writer context.
        """
        evidence_id = evidence.id
        if evidence_id is None:  # pragma: no cover - persisted rows carry it
            raise ValueError("persisted evidence has no identity")
        return AnalystEvidenceItem(
            evidence_id=evidence_id,
            type=evidence.type,
            subject=_evidence_subject(evidence.subject),
            source=evidence.source,
            source_record_id=evidence.source_record_id,
            observed_at=evidence.observed_at,
            retrieved_at=evidence.retrieved_at,
            facts=dict(evidence.facts),
        )


def _analyst_entity(entity: Entity) -> AnalystEntity:
    """Map a persisted canonical Entity to its analyst view."""
    if entity.id is None:  # pragma: no cover - persisted rows carry an id
        raise ValueError("persisted entity has no identity")
    return AnalystEntity(
        entity_id=entity.id,
        entity_type=entity.type,
        value=entity.value,
    )


def _evidence_subject(subject: EntityRef) -> AnalystEntity:
    """Map the subject reference of an Evidence row to its analyst view."""
    if subject.id is None:  # pragma: no cover - persisted rows carry an id
        raise ValueError("persisted evidence subject has no identity")
    return AnalystEntity(
        entity_id=subject.id,
        entity_type=subject.type,
        value=subject.value,
    )
