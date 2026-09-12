# SPDX-License-Identifier: AGPL-3.0-only
"""ResearchSynthesisEvaluator unit tests (PR 22D, matrix 22D-U16..U34)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)
from agentic_threat_investigator.evaluation.research import (
    ExpectedResearchClaim,
    ExpectedResearchResult,
    ResearchEpistemicSnapshot,
    ResearchFixtureReference,
    ResearchScenarioResolution,
    ResearchSynthesisEvaluationResult,
    ResearchSynthesisEvaluator,
    ResearchSynthesisFailureCode,
    ResearchSynthesisScenario,
)

_INVESTIGATION = UUID("00000000-0000-0000-0000-0000000000c1")
_SUBJECT = UUID("00000000-0000-0000-0000-0000000000c2")
_ALPHA = UUID("00000000-0000-0000-0000-0000000000c3")
_BETA = UUID("00000000-0000-0000-0000-0000000000c4")
_OTHER = UUID("00000000-0000-0000-0000-0000000000c5")


_GAMMA = UUID("00000000-0000-0000-0000-0000000000c6")


def _citation(
    citation_id: UUID,
    *,
    source_record_id: str = "record-a",
    document_type: str = "attack_technique",
) -> ResearchCitation:
    """Build one immutable citation snapshot."""
    return ResearchCitation(
        citation_id=citation_id,
        document_id=uuid4(),
        source_id="urn:ati:source:mitre_attack",
        source_record_id=source_record_id,
        document_type=document_type,
        chunk_sequence=1,
        text="deterministic citation text",
    )


def _claim(claim_id: UUID, text: str, citation_ids: tuple[UUID, ...]) -> ResearchClaim:
    """Build one immutable research claim."""
    return ResearchClaim(id=claim_id, text=text, citation_ids=citation_ids)


def _result(
    *,
    claims: tuple[ResearchClaim, ...] = (),
    citations: tuple[ResearchCitation, ...] = (),
    investigation_id: UUID = _INVESTIGATION,
    subject_entity_id: UUID = _SUBJECT,
) -> ResearchResult:
    """Build one immutable persisted result."""
    return ResearchResult(
        id=uuid4(),
        investigation_id=investigation_id,
        subject_entity_id=subject_entity_id,
        query="obfuscate command and control traffic",
        claims=claims,
        citations=citations,
        created_at=datetime(2026, 1, 15, tzinfo=UTC),
    )


def _result_construct(
    *,
    claims: tuple[ResearchClaim, ...] = (),
    citations: tuple[ResearchCitation, ...] = (),
    investigation_id: UUID = _INVESTIGATION,
) -> ResearchResult:
    """Build a result bypassing domain validation for negative evaluator cases.

    The domain contract already enforces citation closure at construction; the
    evaluator still defends the same invariant on persisted read-back, so the
    unit matrix exercises that defense with an intentionally malformed value.
    """
    return ResearchResult.model_construct(
        id=uuid4(),
        investigation_id=investigation_id,
        subject_entity_id=_SUBJECT,
        query="obfuscate command and control traffic",
        claims=claims,
        citations=citations,
        created_at=datetime(2026, 1, 15, tzinfo=UTC),
    )


def _snapshot(**overrides: Any) -> ResearchEpistemicSnapshot:
    """Build an empty epistemic snapshot with deterministic overrides."""
    params: dict[str, Any] = {
        "evidence_ids": (),
        "relationship_observation_ids": (),
        "assessment_identities": (),
    }
    params.update(overrides)
    return ResearchEpistemicSnapshot(**params)


def _scenario(**overrides: Any) -> ResearchSynthesisScenario:
    """Build a synthesis scenario requiring one Alpha-cited claim."""
    params: dict[str, Any] = {
        "id": "unit.synthesis-scenario",
        "version": 1,
        "fixture": ResearchFixtureReference(name="mitre-attack-small"),
        "query": "obfuscate command and control traffic",
        "max_results": 3,
        "source_records": {
            "alpha": "record-a",
            "beta": "record-b",
            "gamma": "record-c",
        },
        "expected": ExpectedResearchResult(
            min_claims=1,
            max_claims=3,
            required_citation_labels=("alpha",),
            required_claims=(
                ExpectedResearchClaim(
                    citation_labels=("alpha",),
                    required_phrases=("obscures command-and-control traffic",),
                ),
            ),
        ),
    }
    params.update(overrides)
    return ResearchSynthesisScenario(**params)


def _resolution(**overrides: Any) -> ResearchScenarioResolution:
    """Build a resolution mapping alpha/beta labels to exact citation UUIDs."""
    params: dict[str, Any] = {
        "citations": {"alpha": _ALPHA, "beta": _BETA},
        "source_records": {
            "alpha": "record-a",
            "beta": "record-b",
        },
    }
    params.update(overrides)
    return ResearchScenarioResolution(**params)


def _evaluate(
    scenario: ResearchSynthesisScenario,
    result: ResearchResult,
    *,
    supplied: tuple[UUID, ...] = (_ALPHA, _BETA),
    before: ResearchEpistemicSnapshot | None = None,
    after: ResearchEpistemicSnapshot | None = None,
    resolution: ResearchScenarioResolution | None = None,
) -> ResearchSynthesisEvaluationResult:
    """Run one deterministic evaluation with default passing snapshots."""
    empty = _snapshot()
    return ResearchSynthesisEvaluator().evaluate(
        scenario=scenario,
        resolution=resolution or _resolution(),
        result=result,
        supplied_citation_ids=supplied,
        before_snapshot=before or empty,
        after_snapshot=after or empty,
        expected_investigation_id=_INVESTIGATION,
        expected_subject_entity_id=_SUBJECT,
    )


def _alpha_result() -> ResearchResult:
    """Build the canonical Alpha-cited passing result."""
    return _result(
        claims=(
            _claim(
                uuid4(),
                "The technique obscures command-and-control traffic.",
                (_ALPHA,),
            ),
        ),
        citations=(_citation(_ALPHA),),
    )


def test_u16_valid_result_passes_and_metrics_are_perfect() -> None:
    """U16: exact citation closure over result and supplied sets passes."""
    result = _evaluate(_scenario(), _alpha_result())
    assert result.passed, result.failures
    assert result.metrics.citation_validity_rate == pytest.approx(1.0)
    assert result.metrics.required_citation_coverage == pytest.approx(1.0)
    assert result.metrics.required_claim_coverage == pytest.approx(1.0)
    assert result.metrics.epistemic_promotion_count == 0


def test_u17_claim_cites_absent_result_citation_fails_closure() -> None:
    """U17: a claim citing a citation absent from result snapshots fails."""
    result = _result_construct(
        claims=(_claim(uuid4(), "Unsupported closure.", (_OTHER,)),),
        citations=(_citation(_ALPHA),),
    )
    evaluation = _evaluate(_scenario(), result)
    assert not evaluation.passed
    assert ResearchSynthesisFailureCode.INVALID_CITATION_CLOSURE in evaluation.failures


def test_u18_result_citation_was_not_supplied_fails() -> None:
    """U18: a persisted citation never supplied to the model fails."""
    result = _result(
        claims=(_claim(uuid4(), "Cites alpha.", (_ALPHA,)),),
        citations=(_citation(_ALPHA),),
    )
    evaluation = _evaluate(_scenario(), result, supplied=(_BETA,))
    assert not evaluation.passed
    assert ResearchSynthesisFailureCode.CITATION_NOT_SUPPLIED in evaluation.failures


def test_u19_required_citation_absent_fails() -> None:
    """U19: a required citation label absent from the result fails."""
    result = _result(
        claims=(_claim(uuid4(), "Cites beta only.", (_BETA,)),),
        citations=(_citation(_BETA, source_record_id="record-b"),),
    )
    evaluation = _evaluate(
        _scenario(),
        result,
        supplied=(_ALPHA, _BETA),
    )
    assert not evaluation.passed
    assert ResearchSynthesisFailureCode.REQUIRED_CITATION_MISSING in evaluation.failures


def test_u20_forbidden_citation_present_fails() -> None:
    """U20: a forbidden citation label present in the result fails."""
    scenario = _scenario(
        expected=ExpectedResearchResult(
            min_claims=0,
            required_citation_labels=(),
            required_claims=(),
            forbidden_citation_labels=("beta",),
        )
    )
    result = _result(
        claims=(_claim(uuid4(), "Cites beta.", (_BETA,)),),
        citations=(_citation(_BETA, source_record_id="record-b"),),
    )
    evaluation = _evaluate(scenario, result)
    assert not evaluation.passed
    assert ResearchSynthesisFailureCode.FORBIDDEN_CITATION_USED in evaluation.failures


def test_u21_expected_empty_result_is_empty_passes() -> None:
    """U21: an explicitly expected empty result passes with zero LLM work."""
    scenario = _scenario(
        expected=ExpectedResearchResult(expected_empty_result=True, max_claims=0)
    )
    evaluation = _evaluate(scenario, _result())
    assert evaluation.passed, evaluation.failures
    assert evaluation.metrics.citation_validity_rate == pytest.approx(1.0)


def test_u22_expected_empty_result_not_empty_fails() -> None:
    """U22: expected-empty semantics reject a claim-bearing result."""
    scenario = _scenario(
        expected=ExpectedResearchResult(expected_empty_result=True, max_claims=0)
    )
    evaluation = _evaluate(scenario, _alpha_result())
    assert not evaluation.passed
    assert (
        ResearchSynthesisFailureCode.EXPECTED_EMPTY_RESULT_NOT_EMPTY
        in evaluation.failures
    )


def test_u23_required_claim_phrases_and_citations_satisfied() -> None:
    """U23: a claim satisfying citation identity plus phrases passes."""
    evaluation = _evaluate(_scenario(), _alpha_result())
    assert evaluation.passed, evaluation.failures


def test_u24_phrase_present_with_wrong_citation_fails() -> None:
    """U24: correct phrase on a claim with the wrong citation fails matching."""
    result = _result(
        claims=(
            _claim(
                uuid4(),
                "The technique obscures command-and-control traffic.",
                (_BETA,),
            ),
        ),
        citations=(_citation(_BETA, source_record_id="record-b"),),
    )
    evaluation = _evaluate(_scenario(), result)
    assert not evaluation.passed
    assert ResearchSynthesisFailureCode.REQUIRED_CLAIM_MISSING in evaluation.failures
    assert ResearchSynthesisFailureCode.REQUIRED_CITATION_MISSING in evaluation.failures


def test_u25_contradiction_pair_complete_passes() -> None:
    """U25: both declared contradiction sides satisfy the envelope."""
    scenario = _scenario(
        expected=ExpectedResearchResult(
            min_claims=2,
            max_claims=2,
            required_citation_labels=("alpha", "beta"),
            required_claims=(
                ExpectedResearchClaim(
                    citation_labels=("alpha",),
                    required_phrases=("increases detection visibility",),
                ),
                ExpectedResearchClaim(
                    citation_labels=("beta",),
                    required_phrases=("decreases detection visibility",),
                ),
            ),
        )
    )
    result = _result(
        claims=(
            _claim(
                uuid4(),
                "Alpha increases detection visibility via telemetry.",
                (_ALPHA,),
            ),
            _claim(
                uuid4(),
                "Beta decreases detection visibility via telemetry.",
                (_BETA,),
            ),
        ),
        citations=(_citation(_ALPHA), _citation(_BETA, source_record_id="record-b")),
    )
    evaluation = _evaluate(scenario, result)
    assert evaluation.passed, evaluation.failures
    assert evaluation.metrics.required_claim_coverage == pytest.approx(1.0)


def test_u26_contradiction_pair_one_sided_fails() -> None:
    """U26: a one-sided contradiction fails both citation and claim gates."""
    scenario = _scenario(
        expected=ExpectedResearchResult(
            min_claims=2,
            max_claims=2,
            required_citation_labels=("alpha", "beta"),
            required_claims=(
                ExpectedResearchClaim(
                    citation_labels=("alpha",),
                    required_phrases=("increases detection visibility",),
                ),
                ExpectedResearchClaim(
                    citation_labels=("beta",),
                    required_phrases=("decreases detection visibility",),
                ),
            ),
        )
    )
    result = _result(
        claims=(
            _claim(
                uuid4(),
                "Alpha increases detection visibility via telemetry.",
                (_ALPHA,),
            ),
        ),
        citations=(_citation(_ALPHA),),
    )
    evaluation = _evaluate(scenario, result)
    assert not evaluation.passed
    assert ResearchSynthesisFailureCode.REQUIRED_CLAIM_MISSING in evaluation.failures
    assert ResearchSynthesisFailureCode.REQUIRED_CITATION_MISSING in evaluation.failures
    assert evaluation.metrics.required_claim_coverage == pytest.approx(0.5)


def test_u27_deterministic_failure_ordering() -> None:
    """U27: the emitted failure tuple follows the stable documented order."""
    _GAMMA = UUID("00000000-0000-0000-0000-0000000000c6")
    scenario = _scenario(
        expected=ExpectedResearchResult(
            min_claims=1,
            max_claims=3,
            required_citation_labels=("alpha",),
            forbidden_citation_labels=("gamma",),
            required_claims=(
                ExpectedResearchClaim(
                    citation_labels=("alpha",),
                    required_phrases=("obscures command-and-control traffic",),
                ),
            ),
        )
    )
    # Wrong investigation; claim cites a citation missing from the snapshots;
    # a forbidden label is present; alpha and the expected claim are absent.
    result = _result_construct(
        investigation_id=UUID("00000000-0000-0000-0000-0000000000ff"),
        claims=(
            _claim(
                uuid4(),
                "The technique obscures command-and-control traffic.",
                (_BETA,),
            ),
        ),
        citations=(_citation(_GAMMA),),
    )
    resolution = _resolution(
        citations={"alpha": _ALPHA, "beta": _BETA, "gamma": _GAMMA}
    )
    evaluation = _evaluate(scenario, result, supplied=(_BETA,), resolution=resolution)
    assert evaluation.failures == (
        ResearchSynthesisFailureCode.RESULT_INVESTIGATION_MISMATCH,
        ResearchSynthesisFailureCode.INVALID_CITATION_CLOSURE,
        ResearchSynthesisFailureCode.CITATION_NOT_SUPPLIED,
        ResearchSynthesisFailureCode.REQUIRED_CITATION_MISSING,
        ResearchSynthesisFailureCode.FORBIDDEN_CITATION_USED,
        ResearchSynthesisFailureCode.REQUIRED_CLAIM_MISSING,
    )


def test_u28_zero_required_citations_coverage_is_denominator_safe() -> None:
    """U28: no required citations yields full coverage without division."""
    scenario = _scenario(
        expected=ExpectedResearchResult(min_claims=0, required_claims=())
    )
    result = _result(
        claims=(_claim(uuid4(), "An extra structurally valid claim.", (_ALPHA,)),),
        citations=(_citation(_ALPHA),),
    )
    evaluation = _evaluate(scenario, result)
    assert evaluation.metrics.required_citation_coverage == pytest.approx(1.0)
    assert evaluation.passed, evaluation.failures


def test_u29_extra_structurally_valid_claim_is_permitted() -> None:
    """U29: an unbound extra claim is permitted unless forbiddden."""
    scenario = _scenario(
        expected=ExpectedResearchResult(
            min_claims=1,
            max_claims=None,
            required_citation_labels=("alpha",),
            required_claims=(
                ExpectedResearchClaim(
                    citation_labels=("alpha",),
                    required_phrases=("obscures command-and-control traffic",),
                ),
            ),
        )
    )
    result = _result(
        claims=(
            _claim(
                uuid4(),
                "The technique obscures command-and-control traffic.",
                (_ALPHA,),
            ),
            _claim(uuid4(), "An extra non-material contextual note.", (_BETA,)),
        ),
        citations=(_citation(_ALPHA), _citation(_BETA, source_record_id="record-b")),
    )
    evaluation = _evaluate(scenario, result)
    assert evaluation.passed, evaluation.failures


def test_u30_epistemic_snapshot_unchanged_passes() -> None:
    """U30: unchanged before/after Evidence identities pass the gate."""
    before = _snapshot(evidence_ids=(_OTHER,))
    evaluation = _evaluate(
        _scenario(),
        _alpha_result(),
        before=before,
        after=_snapshot(evidence_ids=(_OTHER,)),
    )
    assert evaluation.passed, evaluation.failures


def test_u31_new_evidence_after_research_fails_promotion() -> None:
    """U31: new Evidence during a pure research interval is promotion."""
    before = _snapshot()
    after = _snapshot(evidence_ids=(_OTHER,))
    evaluation = _evaluate(_scenario(), _alpha_result(), before=before, after=after)
    assert not evaluation.passed
    assert (
        ResearchSynthesisFailureCode.EVIDENCE_PROMOTION_DETECTED in evaluation.failures
    )
    assert evaluation.metrics.epistemic_promotion_count == 1


def test_u32_new_relationship_observation_fails_promotion() -> None:
    """U32: a new RelationshipObservation during research is promotion."""
    before = _snapshot()
    after = _snapshot(relationship_observation_ids=(_OTHER,))
    evaluation = _evaluate(_scenario(), _alpha_result(), before=before, after=after)
    assert not evaluation.passed
    assert (
        ResearchSynthesisFailureCode.RELATIONSHIP_OBSERVATION_PROMOTION_DETECTED
        in evaluation.failures
    )
    assert evaluation.metrics.epistemic_promotion_count == 1


def test_u33_assessment_version_change_fails_promotion() -> None:
    """U33: an Assessment identity/version change during research is promotion."""
    before = _snapshot(assessment_identities=((_OTHER, 1),))
    after = _snapshot(assessment_identities=((_OTHER, 2),))
    evaluation = _evaluate(_scenario(), _alpha_result(), before=before, after=after)
    assert not evaluation.passed
    assert (
        ResearchSynthesisFailureCode.ASSESSMENT_PROMOTION_DETECTED
        in evaluation.failures
    )


def test_u34_research_result_only_is_not_promotion() -> None:
    """U34: only a ResearchResult appearing across the interval passes."""
    evaluation = _evaluate(_scenario(), _alpha_result())
    assert evaluation.passed, evaluation.failures


def test_result_subject_mismatch_fails() -> None:
    """A persisted result for a different subject entity fails structurally."""
    result = _result(subject_entity_id=uuid4())
    evaluation = _evaluate(
        _scenario(),
        result,
        supplied=(_ALPHA,),
    )
    assert not evaluation.passed
    assert ResearchSynthesisFailureCode.RESULT_SUBJECT_MISMATCH in evaluation.failures


def test_unknown_resolution_label_fails_closed() -> None:
    """An expectation label missing from the resolution fails with a ValueError."""
    resolution = _resolution(citations={"beta": _BETA})
    with pytest.raises(ValueError):
        _evaluate(_scenario(), _alpha_result(), resolution=resolution)


def test_unexpected_empty_result_with_required_material_fails() -> None:
    """An empty result under a demanding scenario fails distinctly."""
    evaluation = _evaluate(_scenario(), _result())
    assert not evaluation.passed
    assert ResearchSynthesisFailureCode.UNEXPECTED_EMPTY_RESULT in evaluation.failures
    assert ResearchSynthesisFailureCode.REQUIRED_CITATION_MISSING in evaluation.failures


def test_whitespace_normalized_phrase_matching() -> None:
    """Phrase matching uses canonical whitespace normalization only."""
    result = _result(
        claims=(
            _claim(
                uuid4(),
                "The   technique obscures  command-and-control\ttraffic.",
                (_ALPHA,),
            ),
        ),
        citations=(_citation(_ALPHA),),
    )
    evaluation = _evaluate(_scenario(), result)
    assert evaluation.passed, evaluation.failures


def test_forbidden_phrase_disqualifies_candidate_claim() -> None:
    """A citation-compatible claim containing a forbidden phrase is rejected."""
    scenario = _scenario(
        expected=ExpectedResearchResult(
            min_claims=1,
            required_citation_labels=("alpha",),
            required_claims=(
                ExpectedResearchClaim(
                    citation_labels=("alpha",),
                    required_phrases=("obscures command-and-control traffic",),
                    forbidden_phrases=("increases detection visibility",),
                ),
            ),
        )
    )
    result = _result(
        claims=(
            _claim(
                uuid4(),
                "The technique obscures command-and-control traffic and increases "
                "detection visibility.",
                (_ALPHA,),
            ),
        ),
        citations=(_citation(_ALPHA),),
    )
    evaluation = _evaluate(scenario, result)
    assert not evaluation.passed
    assert ResearchSynthesisFailureCode.REQUIRED_CLAIM_MISSING in evaluation.failures
