# SPDX-License-Identifier: AGPL-3.0-only
"""Research evaluation model validation tests (PR 22D)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.evaluation.research import (
    ExpectedResearchClaim,
    ExpectedResearchResult,
    ResearchRetrievalEvaluationResult,
    ResearchRetrievalFailureCode,
    ResearchRetrievalMetrics,
    ResearchRetrievalScenario,
    ResearchSynthesisEvaluationResult,
    ResearchSynthesisFailureCode,
    ResearchSynthesisMetrics,
    ResearchSynthesisScenario,
)


def test_retrieval_scenario_rejects_blank_query_and_description() -> None:
    """Blank queries and blank descriptions fail model validation."""
    with pytest.raises(ValidationError):
        ResearchRetrievalScenario(
            id="unit.scenario", version=1, query="   ", max_results=3
        )
    with pytest.raises(ValidationError):
        ResearchRetrievalScenario(
            id="unit.scenario", version=1, query="q", max_results=3, description=" "
        )


def test_retrieval_scenario_rejects_blank_filters_and_overlap() -> None:
    """Blank filter entries and required/forbidden overlap fail closed."""
    with pytest.raises(ValidationError):
        ResearchRetrievalScenario(
            id="unit.scenario", version=1, query="q", max_results=3, source_ids=(" ",)
        )
    with pytest.raises(ValidationError):
        ResearchRetrievalScenario(
            id="unit.scenario",
            version=1,
            query="q",
            max_results=3,
            expected_relevant_source_records=("rec",),
            expected_forbidden_source_records=("rec",),
        )
    with pytest.raises(ValidationError):
        ResearchRetrievalScenario(
            id="unit.scenario",
            version=1,
            query="q",
            max_results=3,
            expected_relevant_source_records=("rec",),
            expected_retrieval_gap=True,
        )


def test_retrieval_result_passed_consistency_validator() -> None:
    """A contradictory passed/failures combination is rejected."""
    with pytest.raises(ValidationError):
        ResearchRetrievalEvaluationResult(
            passed=True,
            failures=(ResearchRetrievalFailureCode.FILTER_VIOLATION,),
            metrics=ResearchRetrievalMetrics(
                recall_at_k=None, precision_at_k=None, mrr=None
            ),
        )


def test_claim_expectation_rejects_invalid_labels_and_blank_phrases() -> None:
    """Invalid semantic labels and blank phrases fail model validation."""
    with pytest.raises(ValidationError):
        ExpectedResearchClaim(citation_labels=("Not Valid!",))
    with pytest.raises(ValidationError):
        ExpectedResearchClaim(citation_labels=("alpha",), required_phrases=("   ",))


def test_result_envelope_bounds_and_label_contracts() -> None:
    """Claim-count bounds and required/forbidden label contracts fail closed."""
    with pytest.raises(ValidationError):
        ExpectedResearchResult(min_claims=5, max_claims=2)
    with pytest.raises(ValidationError):
        ExpectedResearchResult(
            required_citation_labels=("same",), forbidden_citation_labels=("same",)
        )
    with pytest.raises(ValidationError):
        ExpectedResearchResult(
            required_claims=(ExpectedResearchClaim(citation_labels=("undeclared",)),)
        )


def test_synthesis_scenario_rejects_blank_filters_and_undeclared_labels() -> None:
    """Blank filters, blank records, and undeclared labels fail closed."""
    from agentic_threat_investigator.evaluation.research import (
        ResearchFixtureReference,
    )

    def base(**overrides: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": "unit.synthesis",
            "version": 1,
            "fixture": ResearchFixtureReference(name="fixture"),
            "query": "q",
            "max_results": 3,
            "expected": ExpectedResearchResult(),
        }
        payload.update(overrides)
        return payload

    with pytest.raises(ValidationError):
        ResearchSynthesisScenario(**base(source_ids=(" ",)))
    with pytest.raises(ValidationError):
        ResearchSynthesisScenario(**base(source_records={"alpha": "   "}))
    with pytest.raises(ValidationError):
        ResearchSynthesisScenario(
            **base(
                source_records={},
                expected=ExpectedResearchResult(
                    required_citation_labels=("missing-label",)
                ),
            )
        )


def test_synthesis_result_passed_consistency_validator() -> None:
    """A contradictory synthesis result is rejected by the model."""
    with pytest.raises(ValidationError):
        ResearchSynthesisEvaluationResult(
            scenario_id="unit.s",
            scenario_version=1,
            passed=True,
            failures=(ResearchSynthesisFailureCode.CLAIM_COUNT_OUT_OF_BOUNDS,),
            metrics=ResearchSynthesisMetrics(
                citation_validity_rate=1.0,
                required_citation_coverage=1.0,
                required_claim_coverage=1.0,
                epistemic_promotion_count=0,
            ),
        )
