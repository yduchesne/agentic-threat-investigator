# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure deterministic behavioral evaluator for the Evidence Analyst (PR 20C).

The evaluator consumes a **persisted** :class:`Assessment` (returned/read
through normal repository semantics), a loaded :class:`AnalystScenario`, and
its :class:`AnalystScenarioResolution`. It never evaluates raw LLM output,
pre-persistence decisions, prompt text, or provider response objects.

The evaluator performs no database, network, LLM, environment, or clock
access: everything it needs is passed in. It never mutates its inputs, fails
closed on unknown fixture labels, rejects nothing silently, and emits
failures in a fixed group order:

1. verdict;
2. confidence;
3. required findings (``REQUIRED_FINDING_MISSING``,
   ``REQUIRED_SUPPORT_MISSING``, ``FORBIDDEN_SUPPORT_USED``), in declaration
   order;
4. forbidden findings (``FORBIDDEN_FINDING_PRESENT``), in declaration order;
5. material support (``CONTEXTUAL_EVIDENCE_MISUSED``,
   ``UNSUPPORTED_MATERIAL_FINDING``), in Assessment finding order;
6. required contradictions (``REQUIRED_CONTRADICTION_MISSING``), in
   declaration order;
7. limitations, then unresolved questions, then next steps (each sorted by
   canonical phrase).

Within a group the ordering never depends on set/hash iteration.
"""

from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
)
from agentic_threat_investigator.evaluation.analyst.models import (
    AnalystEvaluationFailure,
    AnalystEvaluationFailureCode,
    AnalystEvaluationMetrics,
    AnalystEvaluationResult,
    AnalystScenario,
    AnalystScenarioResolution,
    ExpectedAssessment,
    ExpectedFinding,
    ForbiddenFinding,
    UnknownFixtureLabelError,
    expected_support_labels,
)


def _normalize_phrase(value: str) -> str:
    """Return the documented normalized form of one canonical phrase.

    Normalization is deliberately narrow and documented: surrounding
    whitespace is trimmed and internal whitespace runs collapse to a single
    space. No case folding, stemming, substring, or fuzzy matching is ever
    performed.
    """
    return " ".join(value.strip().split())


def _sorted_labels(labels: Iterable[str]) -> list[str]:
    """Return labels sorted for deterministic messages and phrase checks."""
    return sorted(labels)


class _ResolutionLookup:
    """Resolve fixture labels to persisted UUIDs, failing closed on unknowns."""

    def __init__(self, resolution: AnalystScenarioResolution) -> None:
        """Bind the immutable resolution map."""
        self._resolution = resolution

    def evidence(self, label: str) -> UUID:
        """Return the persisted Evidence UUID for one label or raise."""
        try:
            return self._resolution.evidence_ids[label]
        except KeyError as exc:
            raise UnknownFixtureLabelError("evidence", label) from exc

    def observation(self, label: str) -> UUID:
        """Return the persisted RelationshipObservation UUID or raise."""
        try:
            return self._resolution.relationship_observation_ids[label]
        except KeyError as exc:
            raise UnknownFixtureLabelError("relationship_observation", label) from exc


def _support_sets(finding: AnalyticalFinding) -> tuple[set[UUID], set[UUID]]:
    """Return the finding's Evidence and RelationshipObservation support sets."""
    evidence: set[UUID] = set()
    relationships: set[UUID] = set()
    for support in finding.support:
        if isinstance(support, EvidenceSupport):
            evidence.add(support.evidence_id)
        else:
            relationships.add(support.relationship_observation_id)
    return evidence, relationships


def _forbidden_labels_used(
    expectation: ExpectedFinding,
    finding: AnalyticalFinding,
    lookup: _ResolutionLookup,
) -> tuple[bool, list[str], list[str]]:
    """Return whether a Finding cites the expectation's forbidden labels."""
    actual_evidence, actual_relationships = _support_sets(finding)
    used_evidence = sorted(
        label
        for label in expectation.forbidden_evidence_support
        if lookup.evidence(label) in actual_evidence
    )
    used_relationships = sorted(
        label
        for label in expectation.forbidden_relationship_support
        if lookup.observation(label) in actual_relationships
    )
    return bool(used_evidence or used_relationships), used_evidence, used_relationships


def _finding_satisfies(
    expectation: ExpectedFinding,
    finding: AnalyticalFinding,
    lookup: _ResolutionLookup,
) -> bool:
    """Return whether one Finding satisfies one structural expectation.

    Satisfaction requires matching category and disposition (where
    constrained), every required support label inside the Finding's support,
    no forbidden support label, and an allowed confidence where constrained.
    """
    if (
        expectation.category is not None
        and finding.category is not expectation.category
    ):
        return False
    if expectation.disposition is not None and (
        finding.disposition is not expectation.disposition
    ):
        return False
    actual_evidence, actual_relationships = _support_sets(finding)
    for label in expectation.required_evidence_support:
        if lookup.evidence(label) not in actual_evidence:
            return False
    for label in expectation.required_relationship_support:
        if lookup.observation(label) not in actual_relationships:
            return False
    if expectation.allowed_confidence and (
        finding.confidence not in expectation.allowed_confidence
    ):
        return False
    return not _forbidden_labels_used(expectation, finding, lookup)[0]


def _expectation_description(expectation: ExpectedFinding) -> str:
    """Render one expectation deterministically for failure messages."""
    parts: list[str] = []
    if expectation.category is not None:
        parts.append(f"category={expectation.category.value}")
    if expectation.disposition is not None:
        parts.append(f"disposition={expectation.disposition.value}")
    if expectation.required_evidence_support:
        parts.append(
            "evidence=["
            + ",".join(_sorted_labels(expectation.required_evidence_support))
            + "]"
        )
    if expectation.required_relationship_support:
        parts.append(
            "observations=["
            + ",".join(_sorted_labels(expectation.required_relationship_support))
            + "]"
        )
    return " ".join(parts)


class EvidenceAnalystEvaluator:
    """Compare one persisted Assessment against one scenario envelope.

    The evaluator is a stateless synchronous object; all inputs arrive
    through :meth:`evaluate`, so identical inputs always produce identical
    JSON-compatible results.
    """

    def evaluate(
        self,
        *,
        scenario: AnalystScenario,
        resolution: AnalystScenarioResolution,
        assessment: Assessment,
    ) -> AnalystEvaluationResult:
        """Return the deterministic behavioral result for the Assessment."""
        expected = scenario.expected
        lookup = _ResolutionLookup(resolution)
        failures: list[AnalystEvaluationFailure] = []

        self._validate_resolution_coverage(expected, lookup)
        verdict_acceptable, confidence_acceptable = (
            self._evaluate_verdict_and_confidence(expected, assessment, failures)
        )
        required_stats = self._evaluate_required_findings(
            expected, assessment, lookup, failures
        )
        self._evaluate_forbidden_findings(expected, assessment, lookup, failures)
        material_violations = self._evaluate_material_support(
            expected, assessment, lookup, failures
        )
        contradiction_stats = self._evaluate_contradictions(
            expected, assessment, lookup, failures
        )
        text_stats = self._evaluate_text_requirements(expected, assessment, failures)

        metrics = AnalystEvaluationMetrics(
            verdict_acceptable=verdict_acceptable,
            confidence_acceptable=confidence_acceptable,
            required_findings_total=required_stats.total,
            required_findings_satisfied=required_stats.satisfied,
            required_support_total=required_stats.support_total,
            required_support_satisfied=required_stats.support_satisfied,
            forbidden_support_violations=material_violations,
            required_contradictions_total=contradiction_stats.total,
            required_contradictions_satisfied=contradiction_stats.satisfied,
            required_limitations_total=text_stats.limitations_total,
            required_limitations_satisfied=text_stats.limitations_satisfied,
            required_unresolved_questions_total=text_stats.questions_total,
            required_unresolved_questions_satisfied=text_stats.questions_satisfied,
            required_next_steps_total=text_stats.next_steps_total,
            required_next_steps_satisfied=text_stats.next_steps_satisfied,
        )
        return AnalystEvaluationResult(
            scenario_id=scenario.id,
            scenario_version=scenario.version,
            passed=not failures,
            failures=tuple(failures),
            metrics=metrics,
        )

    # -- group helpers -------------------------------------------------------

    @staticmethod
    def _validate_resolution_coverage(
        expected: ExpectedAssessment, lookup: _ResolutionLookup
    ) -> None:
        """Resolve every expectation label before any comparison begins.

        The evaluator fails closed on unknown labels even when a required
        Finding is absent and its support labels would never otherwise be
        resolved: a hand-built resolution missing a reference always raises
        :class:`UnknownFixtureLabelError` deterministically.
        """
        evidence_labels, observation_labels = expected_support_labels(expected)
        for label in evidence_labels:
            lookup.evidence(label)
        for label in observation_labels:
            lookup.observation(label)

    @staticmethod
    def _evaluate_verdict_and_confidence(
        expected: ExpectedAssessment,
        assessment: Assessment,
        failures: list[AnalystEvaluationFailure],
    ) -> tuple[bool, bool]:
        """Evaluate the verdict and confidence envelopes in order."""
        verdict_acceptable = assessment.verdict in expected.allowed_verdicts
        if not verdict_acceptable:
            allowed = ",".join(sorted(item.value for item in expected.allowed_verdicts))
            failures.append(
                AnalystEvaluationFailure(
                    code=AnalystEvaluationFailureCode.VERDICT_NOT_ALLOWED,
                    message=(
                        f"verdict {assessment.verdict.value!r} is not within the "
                        f"allowed envelope [{allowed}]"
                    ),
                )
            )
        confidence_acceptable = assessment.confidence in expected.allowed_confidence
        if not confidence_acceptable:
            allowed = ",".join(
                sorted(item.value for item in expected.allowed_confidence)
            )
            failures.append(
                AnalystEvaluationFailure(
                    code=AnalystEvaluationFailureCode.CONFIDENCE_NOT_ALLOWED,
                    message=(
                        f"confidence {assessment.confidence.value!r} is not within "
                        f"the allowed envelope [{allowed}]"
                    ),
                )
            )
        return verdict_acceptable, confidence_acceptable

    @staticmethod
    def _evaluate_required_findings(
        expected: ExpectedAssessment,
        assessment: Assessment,
        lookup: _ResolutionLookup,
        failures: list[AnalystEvaluationFailure],
    ) -> "_RequiredStats":
        """Evaluate every required Finding expectation in declaration order.

        A requirement is satisfied when at least one candidate Finding
        (matching category/disposition where constrained) carries the
        complete required support set, uses no forbidden support, and has an
        allowed confidence where constrained. Candidates using forbidden
        support are reported with ``FORBIDDEN_SUPPORT_USED`` and never
        satisfy the requirement.

        ``required_support_satisfied`` is the best single clean candidate's
        required-label coverage: the candidate carrying the most required
        evidence/observation labels (ties keep Assessment declaration order)
        contributes exactly that count, even when it does not carry the
        complete set or fails the Finding-confidence constraint. Support
        satisfaction therefore never depends on the union of multiple
        Findings and is never erased by a confidence mismatch.
        """
        satisfied = 0
        support_satisfied = 0
        support_total = 0
        for expectation in expected.required_findings:
            candidates = [
                finding
                for finding in assessment.findings
                if _matches_shape(expectation, finding)
            ]
            expectation_support_total = len(
                expectation.required_evidence_support
            ) + len(expectation.required_relationship_support)
            support_total += expectation_support_total
            if not candidates:
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING,
                        message=(
                            "required finding missing, found no candidate for: "
                            + _expectation_description(expectation)
                        ),
                    )
                )
                continue

            tainted = [
                finding
                for finding in candidates
                if _forbidden_labels_used(expectation, finding, lookup)[0]
            ]
            if tainted:
                used_labels: set[str] = set()
                for finding in tainted:
                    _, evidence_used, observation_used = _forbidden_labels_used(
                        expectation, finding, lookup
                    )
                    used_labels.update(evidence_used)
                    used_labels.update(observation_used)
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.FORBIDDEN_SUPPORT_USED,
                        message=(
                            "forbidden support used by a candidate of "
                            + _expectation_description(expectation)
                            + ": "
                            + ",".join(sorted(used_labels))
                        ),
                    )
                )
            clean = [finding for finding in candidates if finding not in tainted]

            # The best clean candidate carries the most required labels; ties
            # keep Assessment declaration order. It feeds ONLY the support
            # metric and missing-label diagnostics; Finding satisfaction
            # below considers every fully supported candidate.
            best: AnalyticalFinding | None = None
            best_count = 0
            if clean:
                best = clean[0]
                best_count = _required_support_count(expectation, best, lookup)
                for finding in clean[1:]:
                    count = _required_support_count(expectation, finding, lookup)
                    if count > best_count:
                        best = finding
                        best_count = count
            support_satisfied += best_count

            if not clean:
                if expectation_support_total > 0:
                    failures.append(
                        AnalystEvaluationFailure(
                            code=AnalystEvaluationFailureCode.REQUIRED_SUPPORT_MISSING,
                            message=(
                                "required support missing for "
                                + _expectation_description(expectation)
                                + ", no clean candidate"
                            ),
                        )
                    )
                else:
                    # Every candidate uses forbidden support, so no clean
                    # candidate can satisfy the shape/confidence expectation.
                    failures.append(
                        AnalystEvaluationFailure(
                            code=AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING,
                            message=(
                                "required finding missing, no clean candidate for: "
                                + _expectation_description(expectation)
                            ),
                        )
                    )
                continue

            # Fully supported candidates are the only ones allowed to satisfy
            # the requirement; every one is confidence-checked so an earlier
            # disallowed-confidence tie cannot mask a later allowed one.
            fully_supported = [
                finding
                for finding in clean
                if _carries_required_support(expectation, finding, lookup)
            ]
            if not fully_supported:
                assert best is not None  # clean is non-empty here
                missing = _missing_support_labels(expectation, best, lookup)
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.REQUIRED_SUPPORT_MISSING,
                        message=(
                            "required support missing for "
                            + _expectation_description(expectation)
                            + ", missing evidence=["
                            + ",".join(missing.evidence)
                            + "] observations=["
                            + ",".join(missing.observations)
                            + "]"
                        ),
                    )
                )
                continue

            if expectation.allowed_confidence and not any(
                finding.confidence in expectation.allowed_confidence
                for finding in fully_supported
            ):
                allowed = ",".join(
                    sorted(item.value for item in expectation.allowed_confidence)
                )
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.REQUIRED_FINDING_MISSING,
                        message=(
                            "required finding unsatisfied, no candidate with "
                            f"allowed confidence [{allowed}] for: "
                            + _expectation_description(expectation)
                        ),
                    )
                )
                continue

            satisfied += 1
        return _RequiredStats(
            total=len(expected.required_findings),
            satisfied=satisfied,
            support_total=support_total,
            support_satisfied=support_satisfied,
        )

    @staticmethod
    def _evaluate_forbidden_findings(
        expected: ExpectedAssessment,
        assessment: Assessment,
        lookup: _ResolutionLookup,
        failures: list[AnalystEvaluationFailure],
    ) -> None:
        """Report every ForbiddenFinding pattern matched by an actual Finding."""
        for pattern in expected.forbidden_findings:
            matched, used_labels = _forbidden_pattern_match(pattern, assessment, lookup)
            if matched:
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.FORBIDDEN_FINDING_PRESENT,
                        message=(
                            "forbidden finding present for pattern "
                            + _forbidden_description(pattern)
                            + " using ["
                            + ",".join(used_labels)
                            + "]"
                        ),
                    )
                )

    def _evaluate_material_support(
        self,
        expected: ExpectedAssessment,
        assessment: Assessment,
        lookup: _ResolutionLookup,
        failures: list[AnalystEvaluationFailure],
    ) -> int:
        """Report actual Findings that misuse contextual-only support.

        A contextual-only label (declared through ``forbidden_evidence_support``
        / ``forbidden_relationship_support``) may only be cited by a
        GEOLOCATION-category SUPPORTING Finding — the domain's explicit
        contextual category; any other citation is
        ``CONTEXTUAL_EVIDENCE_MISUSED``. When a misusing Finding's support is
        entirely contextual-only it is also ``UNSUPPORTED_MATERIAL_FINDING``.
        """
        evidence_labels = set(expected.forbidden_evidence_support)
        observation_labels = set(expected.forbidden_relationship_support)
        if not evidence_labels and not observation_labels:
            return 0
        forbidden_evidence = {lookup.evidence(label) for label in evidence_labels}
        forbidden_observations = {
            lookup.observation(label) for label in observation_labels
        }
        violations = 0
        for finding in assessment.findings:
            actual_evidence, actual_relationships = _support_sets(finding)
            used_evidence = sorted(
                label
                for label in evidence_labels
                if lookup.evidence(label) in actual_evidence
            )
            used_observations = sorted(
                label
                for label in observation_labels
                if lookup.observation(label) in actual_relationships
            )
            used_labels = used_evidence + used_observations
            if not used_labels:
                continue
            if (
                finding.category is FindingCategory.GEOLOCATION
                and finding.disposition is FindingDisposition.SUPPORTING
            ):
                continue
            violations += 1
            failures.append(
                AnalystEvaluationFailure(
                    code=AnalystEvaluationFailureCode.CONTEXTUAL_EVIDENCE_MISUSED,
                    message=(
                        "contextual evidence used as material support in "
                        f"{finding.category.value} {finding.disposition.value} "
                        "finding: [" + ",".join(used_labels) + "]"
                    ),
                )
            )
            entirely_contextual = (
                actual_evidence <= forbidden_evidence
                and actual_relationships <= forbidden_observations
            )
            if entirely_contextual:
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.UNSUPPORTED_MATERIAL_FINDING,
                        message=(
                            "unsupported material finding in "
                            f"{finding.category.value} {finding.disposition.value} "
                            "finding: support is entirely contextual-only ["
                            + ",".join(used_labels)
                            + "]"
                        ),
                    )
                )
        return violations

    @staticmethod
    def _evaluate_contradictions(
        expected: ExpectedAssessment,
        assessment: Assessment,
        lookup: _ResolutionLookup,
        failures: list[AnalystEvaluationFailure],
    ) -> "_RequiredStats":
        """Evaluate every required contradiction pair in declaration order.

        A pair is satisfied only when both sides are each satisfied by some
        Finding. Finding-level sub-failures are not emitted for contradiction
        sides; the single ``REQUIRED_CONTRADICTION_MISSING`` failure keeps the
        failure set deterministic and non-redundant.
        """
        satisfied = 0
        for contradiction in expected.required_contradictions:
            supporting_ok = any(
                _finding_satisfies(contradiction.supporting_finding, finding, lookup)
                for finding in assessment.findings
            )
            contradicting_ok = any(
                _finding_satisfies(contradiction.contradicting_finding, finding, lookup)
                for finding in assessment.findings
            )
            if not supporting_ok or not contradicting_ok:
                sides: list[str] = []
                if not supporting_ok:
                    sides.append(
                        "supporting("
                        + _expectation_description(contradiction.supporting_finding)
                        + ")"
                    )
                if not contradicting_ok:
                    sides.append(
                        "contradicting("
                        + _expectation_description(contradiction.contradicting_finding)
                        + ")"
                    )
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.REQUIRED_CONTRADICTION_MISSING,
                        message="required contradiction missing: "
                        + " and ".join(sides),
                    )
                )
                continue
            satisfied += 1
        return _RequiredStats(
            total=len(expected.required_contradictions),
            satisfied=satisfied,
            support_total=0,
            support_satisfied=0,
        )

    @staticmethod
    def _evaluate_text_requirements(
        expected: ExpectedAssessment,
        assessment: Assessment,
        failures: list[AnalystEvaluationFailure],
    ) -> "_TextStats":
        """Evaluate canonical limitation/question/next-step phrase requirements.

        Comparison is exact normalized membership: the persisted Assessment
        text collections are compared to the scenario's repository-owned
        canonical phrases. Extra persisted items are always allowed.
        """
        limitations = set(expected.required_limitations)
        questions = set(expected.required_unresolved_questions)
        next_steps = set(expected.required_next_steps)
        actual_limitations = {
            _normalize_phrase(item) for item in assessment.limitations
        }
        actual_questions = {
            _normalize_phrase(item) for item in assessment.unresolved_questions
        }
        actual_next_steps = {
            _normalize_phrase(item) for item in assessment.recommended_next_steps
        }
        limitations_satisfied = 0
        for phrase in _sorted_labels(limitations):
            if _normalize_phrase(phrase) not in actual_limitations:
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.REQUIRED_LIMITATION_MISSING,
                        message=f"required limitation missing: {phrase!r}",
                    )
                )
            else:
                limitations_satisfied += 1
        questions_satisfied = 0
        for phrase in _sorted_labels(questions):
            if _normalize_phrase(phrase) not in actual_questions:
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.REQUIRED_UNRESOLVED_QUESTION_MISSING,
                        message=f"required unresolved question missing: {phrase!r}",
                    )
                )
            else:
                questions_satisfied += 1
        next_steps_satisfied = 0
        for phrase in _sorted_labels(next_steps):
            if _normalize_phrase(phrase) not in actual_next_steps:
                failures.append(
                    AnalystEvaluationFailure(
                        code=AnalystEvaluationFailureCode.REQUIRED_NEXT_STEP_MISSING,
                        message=f"required next step missing: {phrase!r}",
                    )
                )
            else:
                next_steps_satisfied += 1
        return _TextStats(
            limitations_total=len(limitations),
            limitations_satisfied=limitations_satisfied,
            questions_total=len(questions),
            questions_satisfied=questions_satisfied,
            next_steps_total=len(next_steps),
            next_steps_satisfied=next_steps_satisfied,
        )


def _matches_shape(expectation: ExpectedFinding, finding: AnalyticalFinding) -> bool:
    """Return whether a Finding's category/disposition match the expectation."""
    return not (
        (
            expectation.category is not None
            and finding.category is not expectation.category
        )
        or (
            expectation.disposition is not None
            and finding.disposition is not expectation.disposition
        )
    )


def _carries_required_support(
    expectation: ExpectedFinding,
    finding: AnalyticalFinding,
    lookup: _ResolutionLookup,
) -> bool:
    """Return whether a Finding carries every required support reference."""
    actual_evidence, actual_relationships = _support_sets(finding)
    for label in expectation.required_evidence_support:
        if lookup.evidence(label) not in actual_evidence:
            return False
    for label in expectation.required_relationship_support:
        if lookup.observation(label) not in actual_relationships:
            return False
    return True


def _required_support_count(
    expectation: ExpectedFinding,
    finding: AnalyticalFinding,
    lookup: _ResolutionLookup,
) -> int:
    """Return how many required support labels one Finding carries.

    Only clean, shape-matching candidates are ever passed here; forbidden
    support does not contribute and is handled by the caller before this
    helper runs.
    """
    actual_evidence, actual_relationships = _support_sets(finding)
    count = 0
    for label in expectation.required_evidence_support:
        if lookup.evidence(label) in actual_evidence:
            count += 1
    for label in expectation.required_relationship_support:
        if lookup.observation(label) in actual_relationships:
            count += 1
    return count


def _missing_support_labels(
    expectation: ExpectedFinding,
    finding: AnalyticalFinding,
    lookup: _ResolutionLookup,
) -> "_MissingLabels":
    """Return required labels absent from one single candidate's support.

    Missing-label reporting is deliberately per-candidate: the union of
    several Findings never "covers" a label that no single Finding cites.
    """
    actual_evidence, actual_relationships = _support_sets(finding)
    missing_evidence = sorted(
        label
        for label in expectation.required_evidence_support
        if lookup.evidence(label) not in actual_evidence
    )
    missing_relationships = sorted(
        label
        for label in expectation.required_relationship_support
        if lookup.observation(label) not in actual_relationships
    )
    return _MissingLabels(evidence=missing_evidence, observations=missing_relationships)


def _forbidden_pattern_match(
    pattern: ForbiddenFinding,
    assessment: Assessment,
    lookup: _ResolutionLookup,
) -> tuple[bool, list[str]]:
    """Return whether any Finding matches a ForbiddenFinding pattern.

    Matching uses the used support labels (sorted) so the outcome is
    deterministic regardless of set/hash iteration order.
    """
    for finding in assessment.findings:
        if pattern.category is not None and finding.category is not pattern.category:
            continue
        if pattern.disposition is not None and (
            finding.disposition is not pattern.disposition
        ):
            continue
        actual_evidence, actual_relationships = _support_sets(finding)
        used_evidence = sorted(
            label
            for label in pattern.evidence_support
            if lookup.evidence(label) in actual_evidence
        )
        used_relationships = sorted(
            label
            for label in pattern.relationship_support
            if lookup.observation(label) in actual_relationships
        )
        if not pattern.evidence_support and not pattern.relationship_support:
            return True, []
        if used_evidence or used_relationships:
            return True, used_evidence + used_relationships
    return False, []


def _forbidden_description(pattern: ForbiddenFinding) -> str:
    """Render one ForbiddenFinding pattern deterministically."""
    parts: list[str] = []
    if pattern.category is not None:
        parts.append(f"category={pattern.category.value}")
    if pattern.disposition is not None:
        parts.append(f"disposition={pattern.disposition.value}")
    if pattern.evidence_support:
        parts.append(
            "evidence=[" + ",".join(_sorted_labels(pattern.evidence_support)) + "]"
        )
    if pattern.relationship_support:
        parts.append(
            "observations=["
            + ",".join(_sorted_labels(pattern.relationship_support))
            + "]"
        )
    return " ".join(parts)


class _RequiredStats:
    """Aggregated deterministic counts for one required-finding family."""

    def __init__(
        self,
        *,
        total: int,
        satisfied: int,
        support_total: int,
        support_satisfied: int,
    ) -> None:
        """Record the family's total/satisfied and support counts."""
        self.total = total
        self.satisfied = satisfied
        self.support_total = support_total
        self.support_satisfied = support_satisfied


class _TextStats:
    """Aggregated deterministic phrase counts for the text requirements."""

    def __init__(
        self,
        *,
        limitations_total: int,
        limitations_satisfied: int,
        questions_total: int,
        questions_satisfied: int,
        next_steps_total: int,
        next_steps_satisfied: int,
    ) -> None:
        """Record the limitation/question/next-step total/satisfied counts."""
        self.limitations_total = limitations_total
        self.limitations_satisfied = limitations_satisfied
        self.questions_total = questions_total
        self.questions_satisfied = questions_satisfied
        self.next_steps_total = next_steps_total
        self.next_steps_satisfied = next_steps_satisfied


class _MissingLabels:
    """Missing required support labels, split by support kind."""

    def __init__(self, *, evidence: list[str], observations: list[str]) -> None:
        """Record the missing evidence and observation labels."""
        self.evidence = evidence
        self.observations = observations
