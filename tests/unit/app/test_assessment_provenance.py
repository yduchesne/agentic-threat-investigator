# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the Assessment provenance validator (PR 20A + PR 28B).

Assessment provenance identities are exact EvidenceObservation values
(PR 28B), and Investigation membership comes exclusively from
``InvestigationEvidence`` admission: a global observation that is not
admitted to the Assessment's Investigation fails closed exactly like the
old cross-Investigation LegacyEvidence check.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.assessment_provenance import (
    AssessmentEvidenceReferenceError,
    AssessmentInvestigationMismatchError,
    AssessmentProvenanceContext,
    AssessmentProvenanceMismatchError,
    AssessmentProvenanceValidator,
    AssessmentRelationshipObservationReferenceError,
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
    EvidenceObservation,
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

_STARTED_AT = datetime(2026, 1, 1, tzinfo=UTC)
_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class Chain:
    """One deterministic exact-observation provenance chain."""

    def __init__(self) -> None:
        """Bind the fixed identities and the authoritative observation."""
        self.investigation_id = uuid4()
        self.observation_id = uuid4()
        self.source_id = uuid4()
        self.target_id = uuid4()
        self.relationship_id = uuid4()
        self.source_entity = Entity(
            id=self.source_id, type=EntityType.DOMAIN, value="example.com"
        )
        self.target_entity = Entity(
            id=self.target_id,
            type=EntityType.IP_ADDRESS,
            value="203.0.113.42",
        )
        self.relationship = Relationship(
            id=self.relationship_id,
            source_entity_id=self.source_id,
            target_entity_id=self.target_id,
            type=RelationshipType.RESOLVES_TO,
        )
        self.evidence = self.make_evidence(observation_id=self.observation_id)
        self.evidence_id = self.observation_id
        self.observation = self.make_observation(
            evidence_observation_id=self.evidence_id,
            relationship_id=self.relationship_id,
            observation_id=uuid4(),
        )

    def _investigation(self) -> InvestigationState:
        """Build the visible Investigation for the provenance context."""
        return InvestigationState(
            investigation_id=self.investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[uuid4()],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_STARTED_AT,
        )

    @property
    def investigation(self) -> InvestigationState:
        """Return the visible Investigation."""
        return self._investigation()

    def make_evidence(
        self, *, observation_id: UUID | None = None
    ) -> EvidenceObservation:
        """Build one immutable global EvidenceObservation."""
        identity = observation_id if observation_id is not None else uuid4()
        return EvidenceObservation(
            id=identity,
            evidence_id=uuid4(),
            version=1,
            retrieved_at=_RETRIEVED_AT,
            facts={},
        )

    def make_observation(
        self,
        *,
        observation_id: UUID | None = None,
        evidence_observation_id: UUID,
        relationship_id: UUID,
    ) -> RelationshipObservation:
        """Build one immutable relationship observation.

        PR 28B: the domain observation carries no Investigation correlation;
        Investigation membership of the cited observation flows through its
        exact backing EvidenceObservation admission.
        """
        return RelationshipObservation(
            id=observation_id or uuid4(),
            relationship_id=relationship_id,
            evidence_observation_id=evidence_observation_id,
            retrieved_at=_RETRIEVED_AT,
            source="urn:ati:source:threatfox",
        )

    def context(
        self,
        *,
        evidence: dict[UUID, EvidenceObservation] | None = None,
        observations: dict[UUID, RelationshipObservation] | None = None,
        relationships: dict[UUID, Relationship] | None = None,
        entities: dict[UUID, Entity] | None = None,
        admitted: set[UUID] | None = None,
    ) -> AssessmentProvenanceContext:
        """Build an immutable validation context over this chain.

        Admission is explicit: contexts default to admitting exactly the
        supplied evidence-observation map, and tests pass ``admitted`` to
        model unadmitted global observations (PR 28B fail closed).
        """
        evidence_map: dict[UUID, EvidenceObservation] = (
            {self.evidence_id: self.evidence} if evidence is None else evidence
        )
        return AssessmentProvenanceContext(
            investigation=self.investigation,
            evidence=evidence_map,
            admitted_observation_ids=frozenset(
                admitted if admitted is not None else set(evidence_map)
            ),
            relationship_observations=(
                {self.observation_id: self.observation}
                if observations is None
                else observations
            ),
            relationships=(
                {self.relationship_id: self.relationship}
                if relationships is None
                else relationships
            ),
            entities=(
                {
                    self.source_id: self.source_entity,
                    self.target_id: self.target_entity,
                }
                if entities is None
                else entities
            ),
        )


def finding_factory(
    *,
    support: tuple[EvidenceSupport | RelationshipSupport, ...],
    disposition: FindingDisposition = FindingDisposition.SUPPORTING,
    category: FindingCategory = FindingCategory.NETWORK,
    statement: str = "A deterministic analytical claim.",
) -> AnalyticalFinding:
    """Build one Finding with the supplied typed support."""
    return AnalyticalFinding(
        category=category,
        disposition=disposition,
        statement=statement,
        confidence=AssessmentConfidence.MEDIUM,
        support=support,
    )


def assessment_factory(
    chain: Chain,
    *,
    analyzed: tuple[UUID, ...] | None = None,
    findings: tuple[AnalyticalFinding, ...] = (),
    verdict: Verdict = Verdict.SUSPICIOUS,
    confidence: AssessmentConfidence = AssessmentConfidence.MEDIUM,
) -> Assessment:
    """Build a candidate Assessment over the chain."""
    return Assessment(
        investigation_id=chain.investigation_id,
        verdict=verdict,
        confidence=confidence,
        summary="The exact observations support the verdict.",
        analyzed_evidence_ids=((chain.evidence_id,) if analyzed is None else analyzed),
        findings=findings,
    )


def validate(candidate: Assessment, ctx: AssessmentProvenanceContext) -> None:
    """Run the deterministic validator without additional setup."""
    AssessmentProvenanceValidator().validate(candidate, ctx)


# ---------------------------------------------------------------------------
# Evidence cases 1-4
# ---------------------------------------------------------------------------


def test_valid_evidence_support() -> None:
    """A cited analyzed admitted observation is valid."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        analyzed=(chain.evidence_id,),
        findings=(
            finding_factory(
                support=(
                    EvidenceSupport(kind="evidence", evidence_id=chain.evidence_id),
                )
            ),
        ),
    )
    validate(candidate, chain.context())


def test_evidence_absent_from_analyzed_set_is_rejected() -> None:
    """Support may cite only observations the analyst explicitly analyzed."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        analyzed=(uuid4(),),
        findings=(
            finding_factory(
                support=(
                    EvidenceSupport(kind="evidence", evidence_id=chain.evidence_id),
                )
            ),
        ),
    )
    with pytest.raises(AssessmentEvidenceReferenceError):
        validate(candidate, chain.context())


def test_nonexistent_evidence_is_rejected() -> None:
    """Citing an observation outside the persisted snapshot is invalid."""
    chain = Chain()
    phantom_id = uuid4()
    candidate = assessment_factory(
        chain,
        analyzed=(phantom_id,),
        findings=(
            finding_factory(
                support=(EvidenceSupport(kind="evidence", evidence_id=phantom_id),)
            ),
        ),
    )
    with pytest.raises(AssessmentEvidenceReferenceError):
        validate(candidate, chain.context())


def test_evidence_with_zero_relationship_observations_is_valid() -> None:
    """Direct source-fact claims need no relationships at all."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        analyzed=(chain.evidence_id,),
        findings=(
            finding_factory(
                support=(
                    EvidenceSupport(kind="evidence", evidence_id=chain.evidence_id),
                )
            ),
        ),
    )
    validate(candidate, chain.context())


# ---------------------------------------------------------------------------
# Admission cases (PR 28B)
# ---------------------------------------------------------------------------


def test_unadmitted_analyzed_observation_is_rejected() -> None:
    """B2-A02: a global observation not admitted to the Investigation fails closed."""
    chain = Chain()
    global_observation = chain.make_evidence()
    ctx = chain.context(
        evidence={
            chain.evidence_id: chain.evidence,
            global_observation.id: global_observation,
        },
        admitted={chain.evidence_id},
    )
    candidate = assessment_factory(
        chain,
        analyzed=(global_observation.id,),
    )
    with pytest.raises(AssessmentInvestigationMismatchError):
        validate(candidate, ctx)


def test_unadmitted_support_observation_is_rejected() -> None:
    """B2-A02: support citing an unadmitted observation fails closed."""
    chain = Chain()
    global_observation = chain.make_evidence()
    ctx = chain.context(
        evidence={
            chain.evidence_id: chain.evidence,
            global_observation.id: global_observation,
        },
        admitted={chain.evidence_id},
    )
    candidate = assessment_factory(
        chain,
        analyzed=(chain.evidence_id, global_observation.id),
        findings=(
            finding_factory(
                support=(
                    EvidenceSupport(kind="evidence", evidence_id=global_observation.id),
                )
            ),
        ),
    )
    with pytest.raises(AssessmentInvestigationMismatchError):
        validate(candidate, ctx)


def test_a04_stable_evidence_id_where_observation_required_is_rejected() -> None:
    """B2-A04: a stable Evidence ID is not an admissible observation identity."""
    chain = Chain()
    stable_id = uuid4()  # a stable Evidence id, never an observation id
    candidate = assessment_factory(
        chain,
        analyzed=(stable_id,),
    )
    # No observation carries the stable id, so the analyzed set is unresolvable.
    with pytest.raises(AssessmentEvidenceReferenceError):
        validate(candidate, chain.context())


# ---------------------------------------------------------------------------
# Relationship cases 6-19
# ---------------------------------------------------------------------------


def test_valid_relationship_observation_support() -> None:
    """The full exact chain validates."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                )
            ),
        ),
    )
    validate(candidate, chain.context())


def test_nonexistent_observation_is_rejected() -> None:
    """A graph claim over an unknown observation identity is invalid."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=uuid4(),
                    ),
                )
            ),
        ),
    )
    with pytest.raises(AssessmentRelationshipObservationReferenceError):
        validate(candidate, chain.context())


def test_unadmitted_observation_evidence_is_rejected() -> None:
    """B2-A02: the observation's backing observation must be admitted."""
    chain = Chain()
    unadmitted = chain.make_evidence()
    observation = chain.make_observation(
        evidence_observation_id=unadmitted.id,
        relationship_id=chain.relationship_id,
    )
    ctx = chain.context(
        observations={observation.id: observation},
        evidence={chain.evidence_id: chain.evidence, unadmitted.id: unadmitted},
        admitted={chain.evidence_id},
    )
    candidate = assessment_factory(
        chain,
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=observation.id,
                    ),
                )
            ),
        ),
    )
    with pytest.raises(AssessmentInvestigationMismatchError):
        validate(candidate, ctx)


def test_observation_evidence_absent_from_analyzed_set_is_rejected() -> None:
    """The observation's exact EvidenceObservation must be analyzed."""
    chain = Chain()
    unanalyzed = chain.make_evidence()
    observation = chain.make_observation(
        evidence_observation_id=unanalyzed.id,
        relationship_id=chain.relationship_id,
    )
    ctx = chain.context(
        observations={observation.id: observation},
        evidence={unanalyzed.id: unanalyzed, chain.evidence_id: chain.evidence},
    )
    candidate = assessment_factory(
        chain,
        analyzed=(chain.evidence_id,),
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=observation.id,
                    ),
                )
            ),
        ),
    )
    with pytest.raises(AssessmentEvidenceReferenceError):
        validate(candidate, ctx)


def test_missing_relationship_is_rejected() -> None:
    """A broken graph chain (absent Relationship) is invalid."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                )
            ),
        ),
    )
    with pytest.raises(AssessmentProvenanceMismatchError):
        validate(candidate, chain.context(relationships={}))


def test_deleted_relationship_is_rejected() -> None:
    """A soft-deleted Relationship is ineligible support backing."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                )
            ),
        ),
    )
    # Loader omits soft-deleted rows, so the ineligible edge is absent.
    with pytest.raises(AssessmentProvenanceMismatchError):
        validate(candidate, chain.context(relationships={}))


def test_missing_source_entity_is_rejected() -> None:
    """The Relationship's source Entity must exist and be eligible."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                )
            ),
        ),
    )
    ctx = chain.context(entities={chain.target_id: chain.target_entity})
    with pytest.raises(AssessmentProvenanceMismatchError):
        validate(candidate, ctx)


def test_missing_target_entity_is_rejected() -> None:
    """The Relationship's target Entity must exist and be eligible."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                )
            ),
        ),
    )
    ctx = chain.context(entities={chain.source_id: chain.source_entity})
    with pytest.raises(AssessmentProvenanceMismatchError):
        validate(candidate, ctx)


def test_one_observation_can_support_multiple_observations() -> None:
    """One exact observation may back several graph claims."""
    chain = Chain()
    second_target = Entity(id=uuid4(), type=EntityType.IP_ADDRESS, value="198.51.100.7")
    if second_target.id is None:  # pragma: no cover - fixture invariant
        raise AssertionError("fixture entity has no identity")
    second_relationship = Relationship(
        id=uuid4(),
        source_entity_id=chain.source_id,
        target_entity_id=second_target.id,
        type=RelationshipType.USES_NAME_SERVER,
    )
    second_observation = chain.make_observation(
        evidence_observation_id=chain.evidence_id,
        relationship_id=second_relationship.id,
    )
    ctx = chain.context(
        observations={
            chain.observation_id: chain.observation,
            second_observation.id: second_observation,
        },
        relationships={
            chain.relationship_id: chain.relationship,
            second_relationship.id: second_relationship,
        },
        entities={
            chain.source_id: chain.source_entity,
            chain.target_id: chain.target_entity,
            second_target.id: second_target,
        },
    )
    candidate = assessment_factory(
        chain,
        analyzed=(chain.evidence_id,),
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=second_observation.id,
                    ),
                )
            ),
        ),
    )
    validate(candidate, ctx)


def test_one_relationship_can_have_multiple_observations() -> None:
    """Repeated observations of the stable edge are all individually citable."""
    chain = Chain()
    later = chain.make_evidence()
    later_observation = chain.make_observation(
        evidence_observation_id=later.id,
        relationship_id=chain.relationship_id,
    )
    ctx = chain.context(
        evidence={chain.evidence_id: chain.evidence, later.id: later},
        observations={
            chain.observation_id: chain.observation,
            later_observation.id: later_observation,
        },
    )
    candidate = assessment_factory(
        chain,
        analyzed=(chain.evidence_id, later.id),
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=later_observation.id,
                    ),
                )
            ),
        ),
    )
    validate(candidate, ctx)


def test_exact_observation_resolves_exact_evidence() -> None:
    """The cited observation resolves to exactly the analyzed observation."""
    chain = Chain()
    other = chain.make_evidence()
    ctx = chain.context(evidence={chain.evidence_id: chain.evidence, other.id: other})
    candidate = assessment_factory(
        chain,
        analyzed=(other.id,),
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                )
            ),
        ),
    )
    # The observation's exact backing observation is not analyzed.
    with pytest.raises(AssessmentEvidenceReferenceError):
        validate(candidate, ctx)
    exact = candidate.model_copy(update={"analyzed_evidence_ids": (chain.evidence_id,)})
    validate(exact, ctx)


def test_another_observation_of_same_relationship_cannot_substitute() -> None:
    """A different observation of the same edge never substitutes."""
    chain = Chain()
    later = chain.make_evidence()
    other_observation = chain.make_observation(
        evidence_observation_id=later.id,
        relationship_id=chain.relationship_id,
    )
    ctx = chain.context(
        evidence={chain.evidence_id: chain.evidence, later.id: later},
        observations={
            chain.observation_id: chain.observation,
            other_observation.id: other_observation,
        },
    )
    substituted = assessment_factory(
        chain,
        analyzed=(chain.evidence_id,),
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=other_observation.id,
                    ),
                )
            ),
        ),
    )
    with pytest.raises(AssessmentEvidenceReferenceError):
        validate(substituted, ctx)
    exact = assessment_factory(
        chain,
        analyzed=(chain.evidence_id,),
        findings=(
            finding_factory(
                support=(
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                )
            ),
        ),
    )
    validate(exact, ctx)


def test_bare_relationship_id_cannot_parse_as_graph_support() -> None:
    """Graph support requires the observation identity, never a bare edge."""
    with pytest.raises(ValidationError):
        AnalyticalFinding.model_validate(
            {
                "category": FindingCategory.NETWORK,
                "disposition": FindingDisposition.SUPPORTING,
                "statement": "Bare relationship id.",
                "confidence": AssessmentConfidence.LOW,
                "support": [{"relationship_id": str(uuid4())}],
            }
        )


# ---------------------------------------------------------------------------
# Assessment cases 20-25
# ---------------------------------------------------------------------------


def test_mixed_support_is_valid() -> None:
    """A Finding may cite both direct observation support and an observation."""
    chain = Chain()
    candidate = assessment_factory(
        chain,
        analyzed=(chain.evidence_id,),
        findings=(
            finding_factory(
                category=FindingCategory.REPUTATION,
                support=(
                    EvidenceSupport(kind="evidence", evidence_id=chain.evidence_id),
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=chain.observation_id,
                    ),
                ),
            ),
        ),
    )
    validate(candidate, chain.context())


def test_duplicate_support_is_rejected() -> None:
    """Duplicate support inside one Finding is a provenance mismatch."""
    chain = Chain()
    finding = AnalyticalFinding.model_construct(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement="Duplicated citation.",
        confidence=AssessmentConfidence.LOW,
        support=(
            EvidenceSupport(kind="evidence", evidence_id=chain.evidence_id),
            EvidenceSupport(kind="evidence", evidence_id=chain.evidence_id),
        ),
    )
    candidate = assessment_factory(
        chain, analyzed=(chain.evidence_id,), findings=(finding,)
    )
    with pytest.raises(AssessmentProvenanceMismatchError):
        validate(candidate, chain.context())


def test_no_evidence_inconclusive_is_approved() -> None:
    """The approved no-evidence case is an INCONCLUSIVE Assessment."""
    chain = Chain()
    candidate = assessment_factory(chain, analyzed=(), verdict=Verdict.INCONCLUSIVE)
    validate(candidate, chain.context())


def test_no_evidence_benign_is_rejected() -> None:
    """Absence of malicious evidence never proves BENIGN."""
    chain = Chain()
    candidate = assessment_factory(chain, analyzed=(), verdict=Verdict.BENIGN)
    with pytest.raises(AssessmentProvenanceMismatchError):
        validate(candidate, chain.context())


def test_no_evidence_malicious_is_rejected() -> None:
    """A claim of MALICIOUS requires analyzed evidence."""
    chain = Chain()
    candidate = assessment_factory(chain, analyzed=(), verdict=Verdict.MALICIOUS)
    with pytest.raises(AssessmentProvenanceMismatchError):
        validate(candidate, chain.context())


def test_errors_expose_safe_identifiers_only() -> None:
    """Validation errors carry IDs/categories, never evidence payloads."""
    chain = Chain()
    phantom_id = uuid4()
    candidate = assessment_factory(
        chain,
        analyzed=(phantom_id,),
        findings=(
            finding_factory(
                support=(EvidenceSupport(kind="evidence", evidence_id=phantom_id),)
            ),
        ),
    )
    with pytest.raises(AssessmentEvidenceReferenceError) as exc_info:
        validate(candidate, chain.context())
    message = str(exc_info.value)
    assert str(phantom_id) in message
    # Candidate payload/summary text never leaks into the error.
    assert "Deterministic analytical claim" not in message
    assert "The exact observations support the verdict." not in message
    assert "facts" not in message


def test_context_investigation_mismatch_is_rejected() -> None:
    """A visible but different context Investigation is a typed failure."""
    chain = Chain()
    other = Chain()
    assessment = Assessment(
        investigation_id=chain.investigation_id,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="The exact observations support the verdict.",
        analyzed_evidence_ids=(chain.evidence_id,),
    )
    context = AssessmentProvenanceContext(
        investigation=other.investigation,
        evidence={chain.evidence_id: chain.evidence},
        admitted_observation_ids=frozenset({chain.evidence_id}),
    )
    with pytest.raises(AssessmentInvestigationMismatchError):
        validate(assessment, context)
