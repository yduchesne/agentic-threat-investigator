# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic FakeLlmClient decision builder for PR 20C scenarios.

The builder turns a loaded :class:`AnalystScenario` and its materialized
:class:`AnalystScenarioResolution` into an :class:`EvidenceAnalystDecision`
that satisfies the scenario's expected envelope: the verdict and confidence
come from the allowed envelopes and every required Finding / contradiction
side is emitted with its required support resolved to the exact persisted
UUIDs. Canonical limitation/question/next-step phrases come from the
scenario's expectations, so the fake decision and the evaluator can never
drift.

The builder is test infrastructure only. It proves evaluator behavior and
product wiring; it never claims anything about real-model intelligence.
"""

from __future__ import annotations

from uuid import UUID

from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    RelationshipSupport,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.evaluation.analyst.models import (
    AnalystScenario,
    AnalystScenarioResolution,
    ExpectedFinding,
)

_TEMPLATE_STATEMENT = "Canonical scenario finding: {category} {disposition}."
_TEMPLATE_SUMMARY = "Canonical scenario assessment for {scenario_id}."


def _pick_verdict(scenario: AnalystScenario, verdict: Verdict | None) -> Verdict:
    """Return the explicit verdict or the smallest allowed envelope value."""
    if verdict is not None:
        return verdict
    return min(scenario.expected.allowed_verdicts, key=lambda item: item.value)


def _pick_confidence(
    scenario: AnalystScenario, confidence: AssessmentConfidence | None
) -> AssessmentConfidence:
    """Return the explicit confidence or the smallest allowed envelope value."""
    if confidence is not None:
        return confidence
    return min(scenario.expected.allowed_confidence, key=lambda item: item.value)


def _finding_confidence(
    expectation: ExpectedFinding,
    scenario: AnalystScenario,
    fallback: AssessmentConfidence,
) -> AssessmentConfidence:
    """Return the expectation's smallest allowed confidence when constrained."""
    if not expectation.allowed_confidence:
        return fallback
    return min(expectation.allowed_confidence, key=lambda item: item.value)


def _support(
    resolution: AnalystScenarioResolution, expectation: ExpectedFinding
) -> tuple[EvidenceSupport | RelationshipSupport, ...]:
    """Resolve one expectation's required support labels to exact UUIDs."""
    supports: list[EvidenceSupport | RelationshipSupport] = []
    for label in sorted(expectation.required_evidence_support):
        supports.append(
            EvidenceSupport(kind="evidence", evidence_id=resolution.evidence_ids[label])
        )
    for label in sorted(expectation.required_relationship_support):
        supports.append(
            RelationshipSupport(
                kind="relationship_observation",
                relationship_observation_id=resolution.relationship_observation_ids[
                    label
                ],
            )
        )
    return tuple(supports)


def _expectation_key(finding: AnalyticalFinding) -> tuple[object, ...]:
    """Return a stable identity for deduplicating emitted canonical Findings."""
    support_keys = tuple(
        sorted(
            (
                support.kind,
                support.evidence_id
                if isinstance(support, EvidenceSupport)
                else support.relationship_observation_id,
            )
            for support in finding.support
        )
    )
    return (
        finding.category,
        finding.disposition,
        support_keys,
        finding.confidence,
    )


def canonical_decision(
    scenario: AnalystScenario,
    resolution: AnalystScenarioResolution,
    *,
    verdict: Verdict | None = None,
    confidence: AssessmentConfidence | None = None,
) -> EvidenceAnalystDecision:
    """Build the deterministic decision that satisfies the scenario envelope.

    Every required Finding and required contradiction side must declare both
    a category and a disposition; the builder raises ``ValueError`` for an
    expectation it cannot render as a structured Finding.
    """
    selected_verdict = _pick_verdict(scenario, verdict)
    selected_confidence = _pick_confidence(scenario, confidence)

    findings: list[AnalyticalFinding] = []
    seen: set[tuple[object, ...]] = set()

    def emit(expectation: ExpectedFinding) -> None:
        """Emit one structured Finding for an expectation unless duplicated."""
        if expectation.category is None or expectation.disposition is None:
            raise ValueError(
                "canonical decision generation requires category and disposition "
                "on every required Finding and contradiction side"
            )
        support = _support(resolution, expectation)
        finding = AnalyticalFinding(
            category=expectation.category,
            disposition=expectation.disposition,
            statement=_TEMPLATE_STATEMENT.format(
                category=expectation.category.value,
                disposition=expectation.disposition.value,
            ),
            confidence=_finding_confidence(expectation, scenario, selected_confidence),
            support=support,
        )
        key = _expectation_key(finding)
        if key in seen:
            return
        seen.add(key)
        findings.append(finding)

    for expectation in scenario.expected.required_findings:
        emit(expectation)
    for contradiction in scenario.expected.required_contradictions:
        emit(contradiction.supporting_finding)
        emit(contradiction.contradicting_finding)

    return EvidenceAnalystDecision(
        verdict=selected_verdict,
        confidence=selected_confidence,
        summary=_TEMPLATE_SUMMARY.format(scenario_id=scenario.id),
        findings=tuple(findings),
        limitations=tuple(sorted(scenario.expected.required_limitations)),
        unresolved_questions=tuple(
            sorted(scenario.expected.required_unresolved_questions)
        ),
        recommended_next_steps=tuple(sorted(scenario.expected.required_next_steps)),
        disposition=AnalysisDisposition.SUFFICIENT,
    )


def evidence_only_finding(
    *,
    category: FindingCategory,
    disposition: FindingDisposition,
    evidence_ids: tuple[UUID, ...],
    confidence: AssessmentConfidence = AssessmentConfidence.MEDIUM,
    statement: str = "Canonical scenario finding.",
) -> AnalyticalFinding:
    """Build one deterministic direct-Evidence Finding for negative slices.

    Negative vertical slices deliberately build structurally valid but
    behaviorally wrong Assessments; this helper keeps them compact.
    """
    return AnalyticalFinding(
        category=category,
        disposition=disposition,
        statement=statement,
        confidence=confidence,
        support=tuple(
            EvidenceSupport(kind="evidence", evidence_id=evidence_id)
            for evidence_id in evidence_ids
        ),
    )
