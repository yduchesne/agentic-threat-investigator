# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the deterministic Assessment provenance validator.

The synthetic chain factories intentionally mirror the other persistence
service fixtures; the shared shape is conventional in this suite.
"""

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

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_STARTED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def investigation_id() -> UUID:
    """Return a fresh investigation identity for one test."""
    return uuid4()


class Chain:
    """A complete, eligible provenance chain with concrete stable identities.

    The count of terminal UUID attributes is intentional: every identity is
    concrete so strict Mypy never sees the domain's optional persistence
    predicates as keys into the context maps.
    """

    def __init__(self, investigation: UUID | None = None) -> None:
        self.investigation_id = investigation or investigation_id()
        self.source_id = uuid4()
        self.target_id = uuid4()
        self.evidence_id = uuid4()
        self.relationship_id = uuid4()
        self.observation_id = uuid4()
        self.investigation = self._investigation()
        self.source_entity = Entity(
            id=self.source_id, type=EntityType.DOMAIN, value="example.com"
        )
        self.target_entity = Entity(
            id=self.target_id, type=EntityType.IP_ADDRESS, value="192.0.2.1"
        )
        self.evidence = self.make_evidence()
        self.relationship = Relationship(
            id=self.relationship_id,
            source_entity_id=self.source_id,
            target_entity_id=self.target_id,
            type=RelationshipType.RESOLVES_TO,
        )
        self.observation = self.make_observation(
            evidence_id=self.evidence_id,
            relationship_id=self.relationship_id,
            investigation=self.investigation_id,
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

    def make_evidence(
        self, *, evidence_id: UUID | None = None, subject: str = "example.com"
    ) -> Evidence:
        """Build one immutable evidence observation."""
        return Evidence(
            id=evidence_id or uuid4(),
            investigation_id=self.investigation_id,
            type=EvidenceType.DNS,
            subject=EntityRef(type=EntityType.DOMAIN, value=subject),
            source="urn:ati:source:google_public_dns",
            retrieved_at=_RETRIEVED_AT,
        )

    def make_observation(
        self,
        *,
        observation_id: UUID | None = None,
        evidence_id: UUID,
        relationship_id: UUID,
        investigation: UUID,
    ) -> RelationshipObservation:
        """Build one immutable relationship observation."""
        return RelationshipObservation(
            id=observation_id or uuid4(),
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            investigation_id=investigation,
            retrieved_at=_RETRIEVED_AT,
            source="urn:ati:source:google_public_dns",
        )

    def context(
        self,
        *,
        evidence: dict[UUID, Evidence] | None = None,
        observations: dict[UUID, RelationshipObservation] | None = None,
        relationships: dict[UUID, Relationship] | None = None,
        entities: dict[UUID, Entity] | None = None,
    ) -> AssessmentProvenanceContext:
        """Build an immutable validation context over this chain."""
        return AssessmentProvenanceContext(
            investigation=self.investigation,
            evidence=(
                {self.evidence_id: self.evidence} if evidence is None else evidence
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
        summary="Evidence supports the verdict.",
        analyzed_evidence_ids=((chain.evidence_id,) if analyzed is None else analyzed),
        findings=findings,
    )


def validate(candidate: Assessment, ctx: AssessmentProvenanceContext) -> None:
    """Run the deterministic validator without additional setup."""
    AssessmentProvenanceValidator().validate(candidate, ctx)


# ---------------------------------------------------------------------------
# Evidence cases 1-5
# ---------------------------------------------------------------------------


def test_valid_evidence_support() -> None:
    """A cited analyzed evidence of the same investigation is valid."""
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


def test_evidence_from_another_investigation_is_rejected() -> None:
    """Cross-investigation evidence never satisfies an Assessment."""
    chain = Chain()
    foreign = chain.make_evidence()
    foreign = Evidence(
        id=foreign.id or uuid4(),
        investigation_id=uuid4(),
        type=EvidenceType.REPUTATION,
        subject=EntityRef(type=EntityType.DOMAIN, value="elsewhere.example"),
        source="urn:ati:source:threatfox",
        retrieved_at=_RETRIEVED_AT,
    )
    if foreign.id is None:  # pragma: no cover - fixture invariant
        raise AssertionError("fixture evidence has no identity")
    ctx = chain.context(
        evidence={foreign.id: foreign, chain.evidence_id: chain.evidence}
    )
    candidate = assessment_factory(
        chain,
        analyzed=(foreign.id,),
        findings=(
            finding_factory(
                support=(EvidenceSupport(kind="evidence", evidence_id=foreign.id),)
            ),
        ),
    )
    with pytest.raises(AssessmentInvestigationMismatchError):
        validate(candidate, ctx)


def test_evidence_absent_from_analyzed_set_is_rejected() -> None:
    """Support may cite only evidence the analyst explicitly analyzed."""
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
    """Citing evidence outside the persisted snapshot is invalid."""
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


def test_observation_from_wrong_investigation_is_rejected() -> None:
    """An observation bound to another Investigation cannot be cited."""
    chain = Chain()
    observation = chain.make_observation(
        evidence_id=chain.evidence_id,
        relationship_id=chain.relationship_id,
        investigation=uuid4(),
    )
    ctx = chain.context(observations={observation.id: observation})
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


def test_observation_evidence_from_wrong_investigation_is_rejected() -> None:
    """The observation's Evidence must belong to the Assessment Investigation."""
    chain = Chain()
    foreign = Evidence(
        id=uuid4(),
        investigation_id=uuid4(),
        type=EvidenceType.REPUTATION,
        subject=EntityRef(type=EntityType.DOMAIN, value="other.example"),
        source="urn:ati:src:threatfox",
        retrieved_at=_RETRIEVED_AT,
    )
    if foreign.id is None:  # pragma: no cover - fixture invariant
        raise AssertionError("fixture evidence has no identity")
    observation = chain.make_observation(
        evidence_id=foreign.id,
        relationship_id=chain.relationship_id,
        investigation=chain.investigation_id,
    )
    ctx = chain.context(
        observations={observation.id: observation},
        evidence={foreign.id: foreign, chain.evidence_id: chain.evidence},
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
    """The observation's exact Evidence must be part of the analyzed set."""
    chain = Chain()
    unanalyzed = Evidence(
        id=uuid4(),
        investigation_id=chain.investigation_id,
        type=EvidenceType.DNS,
        subject=EntityRef(type=EntityType.DOMAIN, value="unanalyzed.example"),
        source="urn:ati:source:google_public_dns",
        retrieved_at=_RETRIEVED_AT,
    )
    if unanalyzed.id is None:  # pragma: no cover - fixture invariant
        raise AssertionError("fixture evidence has no identity")
    observation = chain.make_observation(
        evidence_id=unanalyzed.id,
        relationship_id=chain.relationship_id,
        investigation=chain.investigation_id,
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


def test_one_evidence_can_support_multiple_observations() -> None:
    """One Evidence observation may back several graph claims."""
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
        evidence_id=chain.evidence_id,
        relationship_id=second_relationship.id,
        investigation=chain.investigation_id,
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
    later = Evidence(
        id=uuid4(),
        investigation_id=chain.investigation_id,
        type=EvidenceType.REPUTATION,
        subject=EntityRef(type=EntityType.DOMAIN, value="later.example"),
        source="urn:ati:src:urlhaus",
        retrieved_at=_RETRIEVED_AT,
    )
    if later.id is None:  # pragma: no cover - fixture invariant
        raise AssertionError("fixture evidence has no identity")
    later_observation = chain.make_observation(
        evidence_id=later.id,
        relationship_id=chain.relationship_id,
        investigation=chain.investigation_id,
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
    """The cited observation resolves to exactly the analyzed Evidence."""
    chain = Chain()
    other = Evidence(
        id=uuid4(),
        investigation_id=chain.investigation_id,
        type=EvidenceType.DNS,
        subject=EntityRef(type=EntityType.DOMAIN, value="other.example"),
        source="urn:ati:test:source",
        retrieved_at=_RETRIEVED_AT,
    )
    if other.id is None:  # pragma: no cover - fixture invariant
        raise AssertionError("fixture evidence has no identity")
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
    # The observation's exact Evidence is not analyzed, so the citation fails.
    with pytest.raises(AssessmentEvidenceReferenceError):
        validate(candidate, ctx)
    exact = candidate.model_copy(update={"analyzed_evidence_ids": (chain.evidence_id,)})
    validate(exact, ctx)


def test_another_observation_of_same_relationship_cannot_substitute() -> None:
    """A different observation of the same edge never substitutes."""
    chain = Chain()
    later = Evidence(
        id=uuid4(),
        investigation_id=chain.investigation_id,
        type=EvidenceType.REPUTATION,
        subject=EntityRef(type=EntityType.DOMAIN, value="later.example"),
        source="urn:ati:test:urlhaus",
        retrieved_at=_RETRIEVED_AT,
    )
    if later.id is None:  # pragma: no cover - fixture invariant
        raise AssertionError("fixture evidence has no identity")
    other_observation = chain.make_observation(
        evidence_id=later.id,
        relationship_id=chain.relationship_id,
        investigation=chain.investigation_id,
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
    """A Finding may cite both direct Evidence and an observation."""
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
    assert "Evidence supports the verdict." not in message
    assert "facts" not in message


def test_context_investigation_mismatch_is_rejected() -> None:
    """A visible but different context Investigation is a typed failure."""

    chain = Chain()
    other = Chain()
    assessment = Assessment(
        investigation_id=chain.investigation_id,
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Evidence supports the verdict.",
        analyzed_evidence_ids=(chain.evidence_id,),
    )
    context = AssessmentProvenanceContext(
        investigation=other.investigation,
        evidence={chain.evidence_id: chain.evidence},
        relationship_observations={chain.observation_id: chain.observation},
        relationships={chain.relationship_id: chain.relationship},
        entities={
            chain.source_id: chain.source_entity,
            chain.target_id: chain.target_entity,
        },
    )
    with pytest.raises(AssessmentInvestigationMismatchError, match="does not match"):
        validate(assessment, context)


def test_context_mappings_are_immutable_snapshots() -> None:
    """Context maps reject mutation and never alias the loader's dictionaries."""

    chain = Chain()
    source_evidence: dict[UUID, Evidence] = {chain.evidence_id: chain.evidence}
    source_entities: dict[UUID, Entity] = {
        chain.source_id: chain.source_entity,
        chain.target_id: chain.target_entity,
    }
    context = AssessmentProvenanceContext(
        investigation=chain.investigation,
        evidence=source_evidence,
        relationship_observations={},
        relationships={chain.relationship_id: chain.relationship},
        entities=source_entities,
    )
    with pytest.raises(TypeError):
        context.evidence[uuid4()] = chain.evidence  # type: ignore[index]
    with pytest.raises(TypeError):
        context.entities[uuid4()] = chain.source_entity  # type: ignore[index]
    # Mutating the original loader dictionaries does not alter the snapshot.
    source_evidence[uuid4()] = chain.evidence
    source_entities.pop(chain.source_id)
    assert chain.evidence_id in context.evidence
    assert chain.source_id in context.entities
