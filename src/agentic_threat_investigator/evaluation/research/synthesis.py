# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic research synthesis evaluation (PR 22D).

The evaluator consumes a persisted :class:`ResearchResult` produced through
the unchanged production research path, one :class:`ResearchSynthesisScenario`,
the exact scenario resolution (semantic labels -> persisted citation UUIDs),
the exact citation IDs supplied to the model invocation, and the
evaluation-only epistemic snapshots taken immediately before and after the
research interval. It is synchronous and pure: no database, network, LLM,
environment, or clock access.

Citation identity is authoritative: every claim citation must close over the
result's citation snapshots, every result citation must have been supplied to
the model, required/forbidden citation labels resolve to exact UUIDs, and
expected claims match by citation-set compatibility plus canonical
whitespace-normalized phrase membership. No stemming, embeddings, fuzzy
similarity, or LLM judging is ever used.
"""

from __future__ import annotations

from uuid import UUID

from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.evaluation.research.models import (
    ExpectedResearchClaim,
    ResearchEpistemicSnapshot,
    ResearchScenarioResolution,
    ResearchSynthesisEvaluationResult,
    ResearchSynthesisFailureCode,
    ResearchSynthesisMetrics,
    ResearchSynthesisScenario,
    _normalize_whitespace,
)

# Stable deterministic emission order for synthesis failures. The order is a
# fixed tuple used in a single pass; failure-code generation never depends on
# unordered set iteration.
_FAILURE_ORDER: tuple[ResearchSynthesisFailureCode, ...] = (
    ResearchSynthesisFailureCode.RESULT_INVESTIGATION_MISMATCH,
    ResearchSynthesisFailureCode.RESULT_SUBJECT_MISMATCH,
    ResearchSynthesisFailureCode.INVALID_CITATION_CLOSURE,
    ResearchSynthesisFailureCode.CITATION_NOT_SUPPLIED,
    ResearchSynthesisFailureCode.EXPECTED_EMPTY_RESULT_NOT_EMPTY,
    ResearchSynthesisFailureCode.UNEXPECTED_EMPTY_RESULT,
    ResearchSynthesisFailureCode.CLAIM_COUNT_OUT_OF_BOUNDS,
    ResearchSynthesisFailureCode.REQUIRED_CITATION_MISSING,
    ResearchSynthesisFailureCode.FORBIDDEN_CITATION_USED,
    ResearchSynthesisFailureCode.REQUIRED_CLAIM_MISSING,
    ResearchSynthesisFailureCode.FORBIDDEN_CLAIM_CONTENT,
    ResearchSynthesisFailureCode.EVIDENCE_PROMOTION_DETECTED,
    ResearchSynthesisFailureCode.RELATIONSHIP_OBSERVATION_PROMOTION_DETECTED,
    ResearchSynthesisFailureCode.ASSESSMENT_PROMOTION_DETECTED,
)


class ResearchSynthesisEvaluator:
    """Evaluate one persisted ResearchResult against one synthesis scenario."""

    def evaluate(
        self,
        *,
        scenario: ResearchSynthesisScenario,
        resolution: ResearchScenarioResolution,
        result: ResearchResult,
        supplied_citation_ids: tuple[UUID, ...],
        before_snapshot: ResearchEpistemicSnapshot,
        after_snapshot: ResearchEpistemicSnapshot,
        expected_investigation_id: UUID,
        expected_subject_entity_id: UUID,
    ) -> ResearchSynthesisEvaluationResult:
        """Return stable failures and structural metrics.

        Every expectation label is resolved through ``resolution`` exactly
        once; an unknown label fails closed with a ``ValueError`` rather than
        being silently ignored.
        """
        failures: set[ResearchSynthesisFailureCode] = set()

        if result.investigation_id != expected_investigation_id:
            failures.add(ResearchSynthesisFailureCode.RESULT_INVESTIGATION_MISMATCH)
        if result.subject_entity_id != expected_subject_entity_id:
            failures.add(ResearchSynthesisFailureCode.RESULT_SUBJECT_MISMATCH)

        result_citation_ids = tuple(
            citation.citation_id for citation in result.citations
        )
        result_citation_set = set(result_citation_ids)
        supplied_set = set(supplied_citation_ids)

        # Exact claim/result citation closure, then supplied-membership.
        for claim in result.claims:
            for citation_id in claim.citation_ids:
                if citation_id not in result_citation_set:
                    failures.add(ResearchSynthesisFailureCode.INVALID_CITATION_CLOSURE)
        for citation_id in result_citation_ids:
            if citation_id not in supplied_set:
                failures.add(ResearchSynthesisFailureCode.CITATION_NOT_SUPPLIED)

        # Explicit empty-result semantics.
        expected_empty = scenario.expected.expected_empty_result
        result_empty = not result.claims and not result.citations
        if expected_empty and not result_empty:
            failures.add(ResearchSynthesisFailureCode.EXPECTED_EMPTY_RESULT_NOT_EMPTY)
        demands_material = bool(
            scenario.expected.required_claims
            or scenario.expected.required_citation_labels
        )
        if not expected_empty and result_empty and demands_material:
            failures.add(ResearchSynthesisFailureCode.UNEXPECTED_EMPTY_RESULT)

        # Claim-count envelope.
        claim_count = len(result.claims)
        if claim_count < scenario.expected.min_claims or (
            scenario.expected.max_claims is not None
            and claim_count > scenario.expected.max_claims
        ):
            failures.add(ResearchSynthesisFailureCode.CLAIM_COUNT_OUT_OF_BOUNDS)

        # Required/forbidden citation labels resolve to exact UUIDs.
        required_ids = [
            _resolve_citation(scenario, resolution, label)
            for label in scenario.expected.required_citation_labels
        ]
        required_used = 0
        for citation_id in required_ids:
            if citation_id in result_citation_set:
                required_used += 1
            else:
                failures.add(ResearchSynthesisFailureCode.REQUIRED_CITATION_MISSING)
        for label in scenario.expected.forbidden_citation_labels:
            forbidden_id = _resolve_citation(scenario, resolution, label)
            if forbidden_id in result_citation_set:
                failures.add(ResearchSynthesisFailureCode.FORBIDDEN_CITATION_USED)

        # Required-claim envelope: citation-set compatibility first, then
        # canonical phrase membership. Multiple satisfied candidates are
        # deterministically acceptable (first persisted claim order).
        claims_satisfied = 0
        for expected_claim in scenario.expected.required_claims:
            if _claim_satisfies(scenario, result, resolution, expected_claim):
                claims_satisfied += 1
            else:
                failures.add(ResearchSynthesisFailureCode.REQUIRED_CLAIM_MISSING)

        # Epistemic promotion hard gates (author-declared defaults).
        promotion_count = 0
        if scenario.expected.expect_no_evidence_promotion and (
            set(before_snapshot.evidence_ids) != set(after_snapshot.evidence_ids)
        ):
            failures.add(ResearchSynthesisFailureCode.EVIDENCE_PROMOTION_DETECTED)
            promotion_count += 1
        if scenario.expected.expect_no_evidence_promotion and (
            set(before_snapshot.relationship_observation_ids)
            != set(after_snapshot.relationship_observation_ids)
        ):
            failures.add(
                ResearchSynthesisFailureCode.RELATIONSHIP_OBSERVATION_PROMOTION_DETECTED
            )
            promotion_count += 1
        if scenario.expected.expect_no_assessment_promotion and (
            set(before_snapshot.assessment_identities)
            != set(after_snapshot.assessment_identities)
        ):
            failures.add(ResearchSynthesisFailureCode.ASSESSMENT_PROMOTION_DETECTED)
            promotion_count += 1

        ordered_failures = _order_failures(failures)
        metrics = ResearchSynthesisMetrics(
            citation_validity_rate=_citation_validity_rate(result, supplied_set),
            required_citation_coverage=(
                required_used / len(required_ids) if required_ids else 1.0
            ),
            required_claim_coverage=(
                claims_satisfied / len(scenario.expected.required_claims)
                if scenario.expected.required_claims
                else 1.0
            ),
            epistemic_promotion_count=promotion_count,
        )
        return ResearchSynthesisEvaluationResult(
            scenario_id=scenario.id,
            scenario_version=scenario.version,
            passed=not ordered_failures,
            failures=tuple(ordered_failures),
            metrics=metrics,
        )


def _resolve_citation(
    scenario: ResearchSynthesisScenario,
    resolution: ResearchScenarioResolution,
    label: str,
) -> UUID:
    """Resolve one citation label to its exact persisted UUID or fail closed."""
    citation_id = resolution.citations.get(label)
    if citation_id is None:
        raise ValueError(
            f"scenario {scenario.id!r} citation label {label!r} is not resolved"
        )
    return citation_id


def _claim_satisfies(
    scenario: ResearchSynthesisScenario,
    result: ResearchResult,
    resolution: ResearchScenarioResolution,
    expected: ExpectedResearchClaim,
) -> bool:
    """Return whether any persisted claim satisfies the claim expectation.

    Citation-set compatibility comes first: the claim must cite every
    required resolved label. Phrase constraints then apply to the claim text
    after canonical whitespace normalization; forbidden phrases disqualify a
    candidate. Selection never uses similarity scores or fuzzy matching, and
    unknown labels fail closed with :class:`ValueError`.
    """
    required_ids = tuple(
        _resolve_citation(scenario, resolution, label)
        for label in expected.citation_labels
    )
    required_set = set(required_ids)
    for claim in result.claims:
        if not required_set <= set(claim.citation_ids):
            continue
        normalized = _normalize_whitespace(claim.text)
        if any(
            _normalize_whitespace(phrase) not in normalized
            for phrase in expected.required_phrases
        ):
            continue
        if any(
            _normalize_whitespace(phrase) in normalized
            for phrase in expected.forbidden_phrases
        ):
            continue
        return True
    return False


def _citation_validity_rate(result: ResearchResult, supplied_set: set[UUID]) -> float:
    """Return the fraction of claim citation references that are valid.

    A reference is valid when it closes over the result's citation snapshots
    and was supplied to the model. With zero references the rate is 1.0 only
    for genuinely empty results (no claims and no citations); otherwise 0.0.
    """
    total = sum(len(claim.citation_ids) for claim in result.claims)
    if total == 0:
        return 1.0 if not result.citations else 0.0
    result_citation_set = {citation.citation_id for citation in result.citations}
    valid = 0
    for claim in result.claims:
        for citation_id in claim.citation_ids:
            if citation_id in result_citation_set and citation_id in supplied_set:
                valid += 1
    return valid / total


def _order_failures(
    failures: set[ResearchSynthesisFailureCode],
) -> list[ResearchSynthesisFailureCode]:
    """Emit failures in the stable documented order, deduplicated."""
    seen: set[ResearchSynthesisFailureCode] = set()
    ordered: list[ResearchSynthesisFailureCode] = []
    for code in _FAILURE_ORDER:
        if code in failures and code not in seen:
            seen.add(code)
            ordered.append(code)
    return ordered
