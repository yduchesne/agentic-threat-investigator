# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Assessment provenance validation.

PR 20A deliberately separates repository reads from pure rules: callers
assemble an immutable :class:`AssessmentProvenanceContext` from repository
reads, then a :class:`AssessmentProvenanceValidator` decides eligibility
without any provider, network, dispatcher, or LLM call.

Provenance semantics:

- Direct source-fact claims cite one immutable Evidence that was analyzed by
  the Assessment and belongs to the same Investigation. Evidence may
  validly support zero RelationshipObservations.
- Graph-backed claims cite exactly one RelationshipObservation; the cited
  observation resolves to the exact Evidence and stable Relationship it
  recorded at observation time, so another observation of the same
  Relationship can never substitute.
- The context's ``relationships``/``entities`` maps hold only eligible
  (non-deleted) rows; a citation that resolves outside those maps is
  missing or ineligible and is rejected.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from uuid import UUID

from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    EvidenceSupport,
    RelationshipSupport,
    Verdict,
    support_key,
)
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)


class AssessmentValidationError(ValueError):
    """Base class for deterministic Assessment validation failures."""


class AssessmentInvestigationMismatchError(AssessmentValidationError):
    """The Assessment or its support escapes its Investigation's scope."""


class AssessmentEvidenceReferenceError(AssessmentValidationError):
    """An Evidence reference is missing, unanalyzed, or malformed."""


class AssessmentRelationshipObservationReferenceError(AssessmentValidationError):
    """A RelationshipObservation reference is missing or malformed."""


class AssessmentProvenanceMismatchError(AssessmentValidationError):
    """Structural Finding/verdict provenance rules are violated."""


@dataclass(frozen=True)
class AssessmentProvenanceContext:
    """Immutable snapshot of everything the validator may consult.

    ``investigation`` is the visible Investigation or ``None``. ``evidence``
    and ``relationship_observations`` are full immutable snapshots keyed by
    ID. ``relationships`` and ``entities`` contain only eligible (non-deleted)
    rows: the loader is responsible for that filtering, so "missing" and
    "soft-deleted" are deliberately indistinguishable to the validator.

    Every mapping is snapshotted into a read-only mapping at construction:
    later mutation of the loader's source dictionaries cannot change the
    context, and mutation through the context itself is rejected.
    """

    investigation: InvestigationState | None
    evidence: Mapping[UUID, Evidence] = field(default_factory=dict)
    relationship_observations: Mapping[UUID, RelationshipObservation] = field(
        default_factory=dict
    )
    relationships: Mapping[UUID, Relationship] = field(default_factory=dict)
    entities: Mapping[UUID, Entity] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Snapshot every mapping into an immutable read-only view."""
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))
        object.__setattr__(
            self,
            "relationship_observations",
            MappingProxyType(dict(self.relationship_observations)),
        )
        object.__setattr__(
            self, "relationships", MappingProxyType(dict(self.relationships))
        )
        object.__setattr__(self, "entities", MappingProxyType(dict(self.entities)))


class AssessmentProvenanceValidator:  # pylint: disable=too-few-public-methods
    """Deterministic validation of Assessment provenance rules.

    No provider, network, dispatcher, or LLM call is ever performed; the
    validator operates exclusively on its immutable context.
    """

    def validate(
        self, assessment: Assessment, context: AssessmentProvenanceContext
    ) -> None:
        """Validate the Assessment or raise the first typed failure."""
        self._validate_investigation(assessment, context)
        self._validate_analyzed_evidence(assessment, context)
        for finding in assessment.findings:
            self._validate_finding(assessment, context, finding)

    @staticmethod
    def _validate_investigation(
        assessment: Assessment, context: AssessmentProvenanceContext
    ) -> None:
        """Require the Assessment Investigation to exist, be visible, and match."""
        investigation = context.investigation
        if investigation is None:
            raise AssessmentInvestigationMismatchError(
                f"assessment investigation is missing or not visible: "
                f"{assessment.investigation_id}"
            )
        if investigation.investigation_id != assessment.investigation_id:
            raise AssessmentInvestigationMismatchError(
                f"provenance context investigation "
                f"{investigation.investigation_id} does not match the "
                f"assessment investigation {assessment.investigation_id}"
            )

    @staticmethod
    def _validate_analyzed_evidence(
        assessment: Assessment, context: AssessmentProvenanceContext
    ) -> None:
        """Require every analyzed Evidence ID to exist and belong to the Investigation.

        An empty analyzed set is approved only for an INCONCLUSIVE Assessment
        with no material Findings.
        """
        analyzed = assessment.analyzed_evidence_ids
        if len(analyzed) != len(set(analyzed)):
            raise AssessmentEvidenceReferenceError(
                "assessment duplicates an analyzed evidence id"
            )
        if not analyzed:
            if assessment.verdict is not Verdict.INCONCLUSIVE:
                raise AssessmentProvenanceMismatchError(
                    "an assessment with no analyzed evidence must be INCONCLUSIVE"
                )
            if assessment.findings:
                raise AssessmentProvenanceMismatchError(
                    "an assessment with no analyzed evidence cannot carry material findings"
                )
            return
        for evidence_id in analyzed:
            evidence = context.evidence.get(evidence_id)
            if evidence is None:
                raise AssessmentEvidenceReferenceError(
                    f"analyzed evidence does not exist: {evidence_id}"
                )
            if evidence.investigation_id != assessment.investigation_id:
                raise AssessmentInvestigationMismatchError(
                    f"analyzed evidence belongs to another investigation: {evidence_id}"
                )

    @staticmethod
    def _validate_finding(
        assessment: Assessment,
        context: AssessmentProvenanceContext,
        finding: AnalyticalFinding,
    ) -> None:
        """Validate one Finding and every typed support reference."""
        if not finding.statement.strip():
            raise AssessmentValidationError("finding statement must not be blank")
        if not finding.support:
            raise AssessmentValidationError("finding must carry at least one support")
        keys = [support_key(support) for support in finding.support]
        if len(keys) != len(set(keys)):
            raise AssessmentProvenanceMismatchError(
                f"finding duplicates a support reference in category {finding.category.value}"
            )
        for support in finding.support:
            if isinstance(support, EvidenceSupport):
                _validate_evidence_support(assessment, context, support)
            else:
                _validate_relationship_support(assessment, context, support)


def _validate_evidence_support(
    assessment: Assessment,
    context: AssessmentProvenanceContext,
    support: EvidenceSupport,
) -> None:
    """Require an EvidenceSupport to resolve inside the analyzed set."""
    evidence = context.evidence.get(support.evidence_id)
    if evidence is None:
        raise AssessmentEvidenceReferenceError(
            f"finding cites unknown evidence: {support.evidence_id}"
        )
    if evidence.investigation_id != assessment.investigation_id:
        raise AssessmentInvestigationMismatchError(
            f"finding cites evidence from another investigation: {support.evidence_id}"
        )
    if support.evidence_id not in assessment.analyzed_evidence_ids:
        raise AssessmentEvidenceReferenceError(
            f"finding cites evidence outside the analyzed set: {support.evidence_id}"
        )


def _validate_relationship_support(
    assessment: Assessment,
    context: AssessmentProvenanceContext,
    support: RelationshipSupport,
) -> None:
    """Validate a RelationshipSupport against its exact observation chain."""
    observation = context.relationship_observations.get(
        support.relationship_observation_id
    )
    if observation is None:
        raise AssessmentRelationshipObservationReferenceError(
            f"finding cites missing relationship observation: "
            f"{support.relationship_observation_id}"
        )
    if (
        observation.investigation_id is not None
        and observation.investigation_id != assessment.investigation_id
    ):
        raise AssessmentInvestigationMismatchError(
            f"finding cites an observation from another investigation: "
            f"{support.relationship_observation_id}"
        )
    evidence = context.evidence.get(observation.evidence_id)
    if evidence is None:
        raise AssessmentEvidenceReferenceError(
            f"observation references missing evidence: {observation.evidence_id}"
        )
    if evidence.investigation_id != assessment.investigation_id:
        raise AssessmentInvestigationMismatchError(
            f"observation evidence belongs to another investigation: "
            f"{observation.evidence_id}"
        )
    if observation.evidence_id not in assessment.analyzed_evidence_ids:
        raise AssessmentEvidenceReferenceError(
            f"observation evidence is outside the analyzed set: {observation.evidence_id}"
        )
    relationship = context.relationships.get(observation.relationship_id)
    if relationship is None:
        raise AssessmentProvenanceMismatchError(
            f"observation references a missing or ineligible relationship: "
            f"{observation.relationship_id}"
        )
    _validate_entity(context, relationship.source_entity_id)
    _validate_entity(context, relationship.target_entity_id)


def _validate_entity(context: AssessmentProvenanceContext, entity_id: UUID) -> None:
    """Require a relationship endpoint to exist and be eligible."""
    if entity_id not in context.entities:
        raise AssessmentProvenanceMismatchError(
            f"observation references a missing or ineligible entity: {entity_id}"
        )
