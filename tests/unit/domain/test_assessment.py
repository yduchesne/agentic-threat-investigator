# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 20A Assessment domain contract."""

from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    FindingSupport,
    RelationshipSupport,
    Verdict,
    support_key,
)


def assessment_factory(
    *,
    analyzed_evidence_ids: tuple[UUID, ...] = (uuid4(),),
    findings: tuple[AnalyticalFinding, ...] = (),
    verdict: Verdict = Verdict.SUSPICIOUS,
) -> Assessment:
    """Build a deterministic valid Assessment."""
    return Assessment(
        investigation_id=uuid4(),
        verdict=verdict,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Evidence supports the verdict.",
        analyzed_evidence_ids=analyzed_evidence_ids,
        findings=findings,
        limitations=("limited provider coverage",),
        unresolved_questions=("Is the target still active?",),
        recommended_next_steps=("Query reputation sources daily.",),
    )


def finding_factory(
    *,
    support: tuple[FindingSupport, ...] = (
        EvidenceSupport(kind="evidence", evidence_id=uuid4()),
    ),
    disposition: FindingDisposition = FindingDisposition.SUPPORTING,
    category: FindingCategory = FindingCategory.REPUTATION,
) -> AnalyticalFinding:
    """Build a deterministic valid Finding."""
    return AnalyticalFinding(
        category=category,
        disposition=disposition,
        statement="A reputation source flags the subject.",
        confidence=AssessmentConfidence.MEDIUM,
        support=support,
    )


def test_verdict_values_are_stable() -> None:
    """The verdict vocabulary retains every documented value."""

    assert {item.value for item in Verdict} == {
        "benign",
        "suspicious",
        "malicious",
        "inconclusive",
    }
    assert {Verdict.BENIGN, Verdict.SUSPICIOUS, Verdict.MALICIOUS, Verdict.INCONCLUSIVE}


def test_confidence_values_are_stable() -> None:
    """The confidence vocabulary retains every documented value."""

    assert {item.value for item in AssessmentConfidence} == {"low", "medium", "high"}


def test_evidence_support_carries_an_evidence_identity() -> None:
    """Direct support references exactly one Evidence id."""

    support = EvidenceSupport(kind="evidence", evidence_id=uuid4())

    assert support.evidence_id is not None

    with pytest.raises(ValidationError, match="missing"):
        EvidenceSupport()  # type: ignore[call-arg]


def test_relationship_support_carries_an_observation_identity() -> None:
    """Graph support references exactly one RelationshipObservation id."""

    support = RelationshipSupport(
        kind="relationship_observation", relationship_observation_id=uuid4()
    )

    assert support.relationship_observation_id is not None

    with pytest.raises(ValidationError, match="missing"):
        RelationshipSupport()  # type: ignore[call-arg]


def test_support_models_reject_extra_fields() -> None:
    """Unexpected fields on support references are rejected."""

    with pytest.raises(ValidationError, match="extra"):
        EvidenceSupport(kind="evidence", evidence_id=uuid4(), rationale="not supported")  # type: ignore[call-arg]
    with pytest.raises(ValidationError, match="extra"):
        RelationshipSupport(kind="relationship_observation", relationship_observation_id=uuid4(), evidence_id=uuid4())  # type: ignore[call-arg]


def test_support_references_are_immutable() -> None:
    """Support references cannot be mutated after construction."""

    support = EvidenceSupport(kind="evidence", evidence_id=uuid4())

    with pytest.raises(ValidationError, match="frozen"):
        support.evidence_id = uuid4()


def test_support_discriminator_is_explicit() -> None:
    """Support identity uses an explicit kind, never nullable-field inference."""

    evidence_id = uuid4()
    observation_id = uuid4()

    assert support_key(EvidenceSupport(kind="evidence", evidence_id=evidence_id)) == (
        "evidence",
        evidence_id,
    )
    assert support_key(
        RelationshipSupport(
            kind="relationship_observation", relationship_observation_id=observation_id
        )
    ) == ("relationship_observation", observation_id)


def test_finding_requires_nonblank_statement() -> None:
    """A Finding statement must not be blank."""

    with pytest.raises(ValidationError, match="blank"):
        AnalyticalFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            statement="   \t ",
            confidence=AssessmentConfidence.LOW,
            support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
        )


def test_finding_rejects_empty_support() -> None:
    """Every material Finding must carry support."""

    with pytest.raises(ValidationError, match="at least one support"):
        AnalyticalFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            statement="A claim without support.",
            confidence=AssessmentConfidence.LOW,
            support=(),
        )


def test_finding_rejects_duplicate_support() -> None:
    """Duplicate support references are rejected, never silently repaired."""

    evidence_id = uuid4()
    with pytest.raises(ValidationError, match="unique"):
        AnalyticalFinding(
            category=FindingCategory.REPUTATION,
            disposition=FindingDisposition.SUPPORTING,
            statement="Duplicated citation.",
            confidence=AssessmentConfidence.LOW,
            support=(
                EvidenceSupport(kind="evidence", evidence_id=evidence_id),
                EvidenceSupport(kind="evidence", evidence_id=evidence_id),
            ),
        )


def test_finding_dispositions_are_supporting_or_contradicting() -> None:
    """Findings bear a bounded support/contradiction disposition."""

    supporting = finding_factory(disposition=FindingDisposition.SUPPORTING)
    contradicting = finding_factory(
        disposition=FindingDisposition.CONTRADICTING,
        category=FindingCategory.GEOLOCATION,
    )

    assert supporting.disposition is FindingDisposition.SUPPORTING
    assert contradicting.disposition is FindingDisposition.CONTRADICTING


def test_finding_supports_mixed_kinds() -> None:
    """One Finding may cite both Evidence and RelationshipObservation support."""

    finding = finding_factory(
        support=(
            EvidenceSupport(kind="evidence", evidence_id=uuid4()),
            RelationshipSupport(
                kind="relationship_observation", relationship_observation_id=uuid4()
            ),
        )
    )

    assert len(finding.support) == 2


def test_assessment_rejects_duplicate_analyzed_evidence() -> None:
    """Duplicate analyzed Evidence identities are contract violations."""

    evidence_id = uuid4()
    with pytest.raises(ValidationError, match="duplicates"):
        assessment_factory(analyzed_evidence_ids=(evidence_id, evidence_id))


def test_assessment_rejects_unexpected_fields() -> None:
    """Unexpected Assessment fields are rejected."""

    with pytest.raises(ValidationError, match="extra"):
        Assessment(
            investigation_id=uuid4(),
            verdict=Verdict.SUSPICIOUS,
            confidence=AssessmentConfidence.MEDIUM,
            summary="Guessing.",
            analyzed_evidence_ids=(uuid4(),),
            prompt_hint="not a field",
        )  # type: ignore[call-arg]


def test_assessment_never_embeds_graph_objects() -> None:
    """Assessment provenance is IDs only; graph objects cannot be embedded."""

    with pytest.raises(ValidationError):
        Assessment(
            investigation_id=uuid4(),
            verdict=Verdict.SUSPICIOUS,
            confidence=AssessmentConfidence.MEDIUM,
            summary="Nested object.",
            analyzed_evidence_ids=(uuid4(),),
            findings=(
                AnalyticalFinding(
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="Resolves downward.",
                    confidence=AssessmentConfidence.MEDIUM,
                    support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
                ),
            ),
            evidence_objects=("nope",),  # type: ignore[call-arg]
        )


def test_finding_supports_are_enforced_as_typed_provenance() -> None:
    """Only EvidenceSupport and RelationshipSupport satisfy Finding support."""

    with pytest.raises(ValidationError):
        AnalyticalFinding.model_validate(
            {
                "category": FindingCategory.REPUTATION,
                "disposition": FindingDisposition.SUPPORTING,
                "statement": "Bare relationship ID must not parse.",
                "confidence": AssessmentConfidence.LOW,
                "support": [{"relationship_id": str(uuid4())}],
            }
        )


def test_json_round_trip_preserves_provenance() -> None:
    """The canonical JSON form round-trips exact provenance."""

    evidence_id = uuid4()
    observation_id = uuid4()
    assessment = assessment_factory(
        analyzed_evidence_ids=(evidence_id,),
        findings=(
            finding_factory(),
            finding_factory(
                category=FindingCategory.ASSOCIATION,
                disposition=FindingDisposition.CONTRADICTING,
                support=(
                    EvidenceSupport(kind="evidence", evidence_id=evidence_id),
                    RelationshipSupport(
                        kind="relationship_observation",
                        relationship_observation_id=observation_id,
                    ),
                ),
            ),
        ),
    )

    restored = Assessment.model_validate_json(assessment.model_dump_json())

    assert restored == assessment
    assert restored.findings[1].support == (
        EvidenceSupport(kind="evidence", evidence_id=evidence_id),
        RelationshipSupport(
            kind="relationship_observation", relationship_observation_id=observation_id
        ),
    )


def test_support_discriminator_required_in_durable_json() -> None:
    """Durable JSON carries the kind discriminator; omitting it is rejected."""

    evidence_id = uuid4()
    with pytest.raises(ValidationError):
        EvidenceSupport.model_validate({"evidence_id": evidence_id})
    with pytest.raises(ValidationError):
        RelationshipSupport.model_validate({"relationship_observation_id": uuid4()})
    dumped = EvidenceSupport(kind="evidence", evidence_id=evidence_id).model_dump()
    assert dumped["kind"] == "evidence"
    assert (
        '"kind":"evidence"'
        in EvidenceSupport(kind="evidence", evidence_id=evidence_id).model_dump_json()
    )
    observation_dump = RelationshipSupport(
        kind="relationship_observation", relationship_observation_id=uuid4()
    ).model_dump()
    assert observation_dump["kind"] == "relationship_observation"


def test_support_unknown_discriminator_rejected() -> None:
    """An unknown discriminator value is never accepted."""

    with pytest.raises(ValidationError):
        EvidenceSupport.model_validate({"kind": "relationship", "evidence_id": uuid4()})
    with pytest.raises(ValidationError):
        RelationshipSupport.model_validate(
            {"kind": "evidence", "relationship_observation_id": uuid4()}
        )


def test_support_discriminator_id_mismatch_rejected() -> None:
    """A discriminator paired with the wrong ID field is rejected."""

    with pytest.raises(ValidationError):
        EvidenceSupport.model_validate(
            {"kind": "evidence", "relationship_observation_id": uuid4()}
        )
    with pytest.raises(ValidationError):
        RelationshipSupport.model_validate(
            {"kind": "relationship_observation", "evidence_id": uuid4()}
        )


def test_support_bare_relationship_reference_rejected() -> None:
    """A bare relationship_id is not a valid support shape."""

    with pytest.raises(ValidationError):
        EvidenceSupport.model_validate({"kind": "evidence", "relationship_id": uuid4()})
    with pytest.raises(ValidationError):
        RelationshipSupport.model_validate(
            {"kind": "relationship_observation", "relationship_id": uuid4()}
        )


def test_support_both_reference_fields_rejected() -> None:
    """Carrying both reference ID fields in one support is rejected."""

    with pytest.raises(ValidationError):
        EvidenceSupport.model_validate(
            {
                "kind": "evidence",
                "evidence_id": uuid4(),
                "relationship_observation_id": uuid4(),
            }
        )
    with pytest.raises(ValidationError):
        RelationshipSupport.model_validate(
            {
                "kind": "relationship_observation",
                "evidence_id": uuid4(),
                "relationship_observation_id": uuid4(),
            }
        )


def test_finding_support_union_discriminated_round_trip() -> None:
    """A Finding's support tuple survives JSON round-trip with exact order."""

    finding = AnalyticalFinding(
        category=FindingCategory.NETWORK,
        disposition=FindingDisposition.SUPPORTING,
        statement="DNS resolves the domain.",
        confidence=AssessmentConfidence.MEDIUM,
        support=(
            EvidenceSupport(kind="evidence", evidence_id=uuid4()),
            RelationshipSupport(
                kind="relationship_observation", relationship_observation_id=uuid4()
            ),
        ),
    )
    restored = AnalyticalFinding.model_validate_json(finding.model_dump_json())
    assert restored == finding
    assert [type(item) for item in restored.support] == [
        EvidenceSupport,
        RelationshipSupport,
    ]
