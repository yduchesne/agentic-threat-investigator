# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic end-to-end Investigation evaluation (PR 30F).

:class:`InvestigationEvaluator` compares the authoritative durable snapshot
of one completed investigation (terminal Investigation, final Assessment,
persisted report, Evidence observations, Entities, Relationships, Research
results, structured actions) against the scenario's expected outcome
envelope. It is synchronous and pure: no database, network, LLM,
environment, or clock access.

Every correctness rule is a binary predicate over stable structural
identities; findings are matched by ``<category>:<disposition>`` codes,
never by parsing prose. Hard-gate invariants (Research/Evidence separation,
RelationshipObservation provenance, Assessment/report reference closure,
unknown-entity execution, duplicate work) are evaluated rather than
hardcoded. Numeric observations are explicit envelope operands only; no
aggregate score is ever computed.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from agentic_threat_investigator.domain.assessment import (
    Assessment,
    EvidenceSupport,
)
from agentic_threat_investigator.domain.evidence import EvidenceObservation
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.relationships import (
    RelationshipObservation,
)
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    InvestigationReport,
    ResearchClaimRef,
)
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.evaluation.coordinator import CoordinatorActionRecord
from agentic_threat_investigator.evaluation.investigation.models import (
    InvestigationEvaluationOutput,
    InvestigationEvaluationResult,
    InvestigationExecutionMetrics,
    InvestigationFailureCode,
    InvestigationScenario,
    InvestigationScenarioResolution,
)

_ACTION_PIVOT_EXECUTED = "urn:ati:action:pivot_executed"
_ACTION_RESEARCH_REQUESTED = "urn:ati:action:research_requested"
_ACTION_INVESTIGATION_STOPPED = "urn:ati:action:investigation_stopped"


def _finding_code(category: object, disposition: object) -> str:
    """Render one stable finding code ``<category>:<disposition>``."""
    return f"{category.value}:{disposition.value}"  # type: ignore[attr-defined]


class InvestigationEvaluator:
    """Evaluate one persisted end-to-end snapshot against one scenario.

    No LLM, embeddings, regex fact extraction, or fuzzy similarity is ever
    used: comparisons are exact structural membership over persisted
    identities.
    """

    def evaluate(
        self,
        scenario: InvestigationScenario,
        resolution: InvestigationScenarioResolution,
        output: InvestigationEvaluationOutput,
    ) -> InvestigationEvaluationResult:
        """Return the immutable evaluation result for one scenario."""
        failures: list[InvestigationFailureCode] = []
        expected = scenario.expected
        final_state = output.final_investigation
        assessment = output.final_assessment

        self._terminal_failures(expected, final_state, failures)
        if assessment is None:
            failures.append(InvestigationFailureCode.FINAL_ASSESSMENT_MISSING)
            return self._result(scenario, failures, output.execution_metrics)
        self._assessment_failures(expected, assessment, failures)
        self._evidence_failures(expected, resolution, final_state, output, failures)
        self._relationship_failures(expected, output, failures)
        self._research_failures(expected, resolution, output, failures)
        self._provenance_failures(assessment, output, failures)
        if output.report is None:
            if expected.report.required:
                failures.append(InvestigationFailureCode.REPORT_MISSING)
        else:
            self._report_failures(
                expected,
                assessment,
                output.report,
                output.research_results,
                output.evidence_observations,
                output.relationship_observations,
                failures,
            )
        self._trajectory_failures(expected, final_state, output, failures)
        self._efficiency_failures(expected, output.execution_metrics, failures)
        return self._result(scenario, failures, output.execution_metrics)

    @staticmethod
    def _result(
        scenario: InvestigationScenario,
        failures: list[InvestigationFailureCode],
        metrics: InvestigationExecutionMetrics,
    ) -> InvestigationEvaluationResult:
        """Build the bounded immutable result."""
        return InvestigationEvaluationResult(
            scenario_id=scenario.id,
            scenario_version=scenario.version,
            passed=not failures,
            failures=tuple(failures),
            metrics=metrics,
        )

    @staticmethod
    def _terminal_failures(
        expected: object,
        final_state: InvestigationState,
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Compare the durable terminal state against the envelope."""
        terminal = expected.terminal  # type: ignore[attr-defined]
        trajectory = expected.trajectory  # type: ignore[attr-defined]
        if final_state.status is not terminal.status:
            failures.append(InvestigationFailureCode.TERMINAL_STATUS_MISMATCH)
        if (
            terminal.stop_reason is not None
            and final_state.stop_reason != terminal.stop_reason.value
        ):
            failures.append(InvestigationFailureCode.TERMINAL_STATUS_MISMATCH)
        if trajectory.termination_required and final_state.stop_reason is None:
            failures.append(InvestigationFailureCode.TERMINATION_MISSING)

    @staticmethod
    def _assessment_failures(
        expected: object,
        assessment: Assessment,
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Compare the final Assessment against the envelope."""
        envelope = expected.assessment  # type: ignore[attr-defined]
        if assessment.verdict is not envelope.verdict:
            failures.append(InvestigationFailureCode.ASSESSMENT_VERDICT_MISMATCH)
        if assessment.confidence is not envelope.confidence:
            failures.append(InvestigationFailureCode.ASSESSMENT_CONFIDENCE_MISMATCH)
        observed_codes = {
            _finding_code(finding.category, finding.disposition)
            for finding in assessment.findings
        }
        missing = sorted(set(envelope.required_findings) - observed_codes)
        if missing:
            failures.append(InvestigationFailureCode.REQUIRED_FINDING_MISSING)
        included_forbidden = sorted(set(envelope.forbidden_findings) & observed_codes)
        if included_forbidden:
            failures.append(InvestigationFailureCode.FORBIDDEN_FINDING_INCLUDED)

    @staticmethod
    def _investigation_entity_ids(final_state: InvestigationState) -> set[UUID]:
        """Return the exact entity universe of one investigation."""
        return set(final_state.root_entity_ids) | set(final_state.discovered_entity_ids)

    @staticmethod
    def _evidence_failures(
        expected: object,
        resolution: InvestigationScenarioResolution,
        final_state: InvestigationState,
        output: InvestigationEvaluationOutput,
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Compare admitted Evidence and entity membership."""
        envelope = expected.evidence  # type: ignore[attr-defined]
        observed_sources = {evidence.source for evidence in output.stable_evidence}
        missing_sources = sorted(set(envelope.required_sources) - observed_sources)
        if missing_sources:
            failures.append(InvestigationFailureCode.REQUIRED_EVIDENCE_SOURCE_MISSING)
        entity_ids = InvestigationEvaluator._investigation_entity_ids(final_state)
        for label in envelope.required_entity_labels:
            entity_id = resolution.entity_ids.get(label)
            if entity_id is None or entity_id not in entity_ids:
                failures.append(InvestigationFailureCode.REQUIRED_ENTITY_MISSING)
        for label in envelope.forbidden_entity_labels:
            entity_id = resolution.entity_ids.get(label)
            if entity_id is not None and entity_id in entity_ids:
                failures.append(InvestigationFailureCode.FORBIDDEN_ENTITY_INCLUDED)

    @staticmethod
    def _relationship_failures(
        expected: object,
        output: InvestigationEvaluationOutput,
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Compare the durable RelationshipType universe."""
        envelope = expected.relationships  # type: ignore[attr-defined]
        observed = {relationship.type.value for relationship in output.relationships}
        missing = sorted(set(envelope.required) - observed)
        if missing:
            failures.append(InvestigationFailureCode.REQUIRED_RELATIONSHIP_MISSING)
        included_forbidden = sorted(set(envelope.forbidden) & observed)
        if included_forbidden:
            failures.append(InvestigationFailureCode.FORBIDDEN_RELATIONSHIP_INCLUDED)

    @staticmethod
    def _research_failures(
        expected: object,
        resolution: InvestigationScenarioResolution,
        output: InvestigationEvaluationOutput,
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Compare persisted Research results and request authorization."""
        envelope = expected.research  # type: ignore[attr-defined]
        trajectory = expected.trajectory  # type: ignore[attr-defined]
        result_subjects = {
            result.subject_entity_id for result in output.research_results
        }
        requested_subjects = {
            action.entity_id
            for action in output.actions
            if action.action == _ACTION_RESEARCH_REQUESTED
        }
        for label in envelope.required_subject_labels:
            entity_id = resolution.entity_ids.get(label)
            if entity_id is None or entity_id not in result_subjects:
                failures.append(InvestigationFailureCode.REQUIRED_RESEARCH_MISSING)
        for label in envelope.forbidden_subject_labels:
            entity_id = resolution.entity_ids.get(label)
            if entity_id is not None and entity_id in result_subjects:
                failures.append(InvestigationFailureCode.FORBIDDEN_RESEARCH_INCLUDED)
        for label in trajectory.required_research:
            entity_id = resolution.entity_ids.get(label)
            if entity_id is None or entity_id not in requested_subjects:
                failures.append(InvestigationFailureCode.RESEARCH_AUTHORIZATION_MISSING)
        for label in trajectory.forbidden_research:
            entity_id = resolution.entity_ids.get(label)
            if entity_id is not None and entity_id in requested_subjects:
                failures.append(InvestigationFailureCode.FORBIDDEN_RESEARCH_INCLUDED)

    @staticmethod
    def _provenance_failures(
        assessment: Assessment,
        output: InvestigationEvaluationOutput,
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Enforce the epistemic/provenance hard gates on durable state.

        ResearchResult identities never collide with Evidence identities;
        every RelationshipObservation closes against admitted Evidence and
        Relationships; Assessment references resolve to admitted material.
        """
        evidence_observation_ids = {
            observation.id for observation in output.evidence_observations
        }
        relationship_ids = {relationship.id for relationship in output.relationships}
        relationship_observation_ids = {
            observation.id for observation in output.relationship_observations
        }
        research_ids = {result.id for result in output.research_results}
        if research_ids & evidence_observation_ids:
            failures.append(InvestigationFailureCode.RESEARCH_EVIDENCE_SEPARATION)
        for observation in output.relationship_observations:
            if (
                observation.evidence_observation_id not in evidence_observation_ids
                or observation.relationship_id not in relationship_ids
            ):
                failures.append(
                    InvestigationFailureCode.RELATIONSHIP_OBSERVATION_PROVENANCE
                )
                break
        if not set(assessment.analyzed_evidence_ids).issubset(evidence_observation_ids):
            failures.append(InvestigationFailureCode.UNSUPPORTED_MATERIAL_REFERENCE)
        for finding in assessment.findings:
            for support in finding.support:
                if isinstance(support, EvidenceSupport):
                    if support.evidence_id not in evidence_observation_ids:
                        failures.append(
                            InvestigationFailureCode.UNSUPPORTED_MATERIAL_REFERENCE
                        )
                        break
                elif support.relationship_observation_id not in (
                    relationship_observation_ids
                ):
                    failures.append(
                        InvestigationFailureCode.UNSUPPORTED_MATERIAL_REFERENCE
                    )
                    break
            else:
                continue
            break

    @staticmethod
    def _report_failures(
        expected: object,
        assessment: Assessment,
        report: InvestigationReport,
        research_results: Sequence[ResearchResult],
        evidence_observations: Sequence[EvidenceObservation],
        relationship_observations: Sequence[RelationshipObservation],
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Compare the persisted report against the envelope and Assessment."""
        envelope = expected.report  # type: ignore[attr-defined]
        if report.verdict is not assessment.verdict:
            failures.append(InvestigationFailureCode.REPORT_VERDICT_MISMATCH)
        if report.confidence is not assessment.confidence:
            failures.append(InvestigationFailureCode.REPORT_CONFIDENCE_MISMATCH)
        ordinals = {finding.assessment_finding_ordinal for finding in report.findings}
        missing = sorted(set(envelope.required_finding_ordinals) - ordinals)
        if missing:
            failures.append(InvestigationFailureCode.REPORT_REQUIRED_FINDING_MISSING)
        included_forbidden = sorted(set(envelope.forbidden_finding_ordinals) & ordinals)
        if included_forbidden:
            failures.append(InvestigationFailureCode.REPORT_FORBIDDEN_FINDING_INCLUDED)
        normalized_limitations = {" ".join(item.split()) for item in report.limitations}
        for limitation in envelope.required_limitations:
            if limitation not in normalized_limitations:
                failures.append(InvestigationFailureCode.REQUIRED_LIMITATION_MISSING)
                break
        if len(report.research_context) < envelope.min_research_context:
            failures.append(InvestigationFailureCode.REPORT_RESEARCH_CONTEXT_MISSING)
        InvestigationEvaluator._report_reference_failures(
            assessment,
            report,
            research_results,
            evidence_observations,
            relationship_observations,
            failures,
        )

    @staticmethod
    def _report_reference_failures(
        assessment: Assessment,
        report: InvestigationReport,
        research_results: Sequence[ResearchResult],
        evidence_observations: Sequence[EvidenceObservation],
        relationship_observations: Sequence[RelationshipObservation],
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Enforce report reference closure against admitted material.

        Every top-level source identity set, every research-context claim
        snapshot, and every narrative support reference must resolve to the
        actual final Assessment/Research material of this investigation.
        """
        evidence_observation_ids = {
            observation.id for observation in evidence_observations
        }
        relationship_observation_ids = {
            observation.id for observation in relationship_observations
        }
        results_by_id = {result.id: result for result in research_results}
        valid_result_ids = set(results_by_id)
        if not set(report.source_evidence_ids).issubset(evidence_observation_ids):
            failures.append(InvestigationFailureCode.INVALID_REPORT_REFERENCE)
            return
        if not set(report.source_relationship_observation_ids).issubset(
            relationship_observation_ids
        ):
            failures.append(InvestigationFailureCode.INVALID_REPORT_REFERENCE)
            return
        if not set(report.source_research_result_ids).issubset(valid_result_ids):
            failures.append(InvestigationFailureCode.INVALID_REPORT_REFERENCE)
            return
        for snapshot in report.research_context:
            result = results_by_id.get(snapshot.research_result_id)
            if result is None or not any(
                claim.id == snapshot.research_claim_id for claim in result.claims
            ):
                failures.append(InvestigationFailureCode.INVALID_REPORT_REFERENCE)
                return
        assessment_finding_count = len(assessment.findings)
        for statement in report.executive_summary:
            for ref in statement.support:
                if isinstance(ref, AssessmentFindingRef):
                    if (
                        ref.assessment_id != assessment.id
                        or ref.finding_ordinal > assessment_finding_count
                    ):
                        failures.append(
                            InvestigationFailureCode.INVALID_REPORT_REFERENCE
                        )
                        return
                elif isinstance(ref, ResearchClaimRef):
                    result = results_by_id.get(ref.research_result_id)
                    if result is None or not any(
                        claim.id == ref.research_claim_id for claim in result.claims
                    ):
                        failures.append(
                            InvestigationFailureCode.INVALID_REPORT_REFERENCE
                        )
                        return

    @staticmethod
    def _trajectory_failures(
        expected: object,
        final_state: InvestigationState,
        output: InvestigationEvaluationOutput,
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Compare the structured trajectory against the envelope."""
        envelope = expected.trajectory  # type: ignore[attr-defined]
        actions = output.actions
        action_values = {action.action for action in actions}
        missing_actions = sorted(set(envelope.required_actions) - action_values)
        if missing_actions:
            failures.append(InvestigationFailureCode.REQUIRED_ACTION_MISSING)
        included_forbidden = sorted(set(envelope.forbidden_actions) & action_values)
        if included_forbidden:
            failures.append(InvestigationFailureCode.FORBIDDEN_ACTION_INCLUDED)
        entity_ids = InvestigationEvaluator._investigation_entity_ids(final_state)
        for action in actions:
            if (
                action.action == _ACTION_PIVOT_EXECUTED
                and action.entity_id not in entity_ids
            ):
                failures.append(InvestigationFailureCode.UNKNOWN_ENTITY_EXECUTION)
                break
        executed_depths = [
            action.depth
            for action in actions
            if action.action == _ACTION_PIVOT_EXECUTED and action.depth is not None
        ]
        if (
            envelope.max_depth is not None
            and executed_depths
            and max(executed_depths) > envelope.max_depth
        ):
            failures.append(InvestigationFailureCode.DEPTH_POLICY_VIOLATION)
        if envelope.termination_required and (
            _ACTION_INVESTIGATION_STOPPED not in action_values
        ):
            failures.append(InvestigationFailureCode.TERMINAL_ACTION_MISSING)
        last_stop = -1
        for index, action in enumerate(actions):
            if action.action == _ACTION_INVESTIGATION_STOPPED:
                last_stop = index
        if last_stop != -1 and len(actions) > last_stop + 1:
            failures.append(InvestigationFailureCode.ACTION_AFTER_TERMINAL)

    @staticmethod
    def _efficiency_failures(
        expected: object,
        metrics: InvestigationExecutionMetrics,
        failures: list[InvestigationFailureCode],
    ) -> None:
        """Apply each authored efficiency envelope as an independent predicate."""
        envelope = expected.efficiency  # type: ignore[attr-defined]
        checks = (
            (
                envelope.max_provider_calls,
                metrics.provider_calls,
                InvestigationFailureCode.PROVIDER_CALL_LIMIT_EXCEEDED,
            ),
            (
                envelope.max_llm_calls,
                metrics.llm_calls,
                InvestigationFailureCode.LLM_CALL_LIMIT_EXCEEDED,
            ),
            (
                envelope.max_replans,
                metrics.replans,
                InvestigationFailureCode.REPLAN_LIMIT_EXCEEDED,
            ),
            (
                envelope.max_pivots,
                metrics.pivot_count,
                InvestigationFailureCode.PIVOT_LIMIT_EXCEEDED,
            ),
            (
                envelope.max_duplicate_provider_calls,
                metrics.duplicate_provider_calls,
                InvestigationFailureCode.DUPLICATE_PROVIDER_CALL_LIMIT_EXCEEDED,
            ),
            (
                envelope.max_duplicate_entity_investigations,
                metrics.duplicate_entity_investigations,
                InvestigationFailureCode.DUPLICATE_ENTITY_LIMIT_EXCEEDED,
            ),
            (
                envelope.max_total_actions,
                metrics.total_actions,
                InvestigationFailureCode.TOTAL_ACTIONS_LIMIT_EXCEEDED,
            ),
        )
        for maximum, observed, code in checks:
            if maximum is not None and observed > maximum:
                failures.append(code)


def coordinator_actions(
    events: Sequence[object],
) -> tuple[CoordinatorActionRecord, ...]:
    """Convert ordered durable timeline events into structured actions.

    Thin alias so evaluation adapters never parse logs; the production
    timeline-to-action converter remains the only source of action records.
    """
    from agentic_threat_investigator.app.orchestration.timeline_actions import (
        convert_timeline_actions,
    )
    from agentic_threat_investigator.domain.investigation_timeline import (
        InvestigationTimelineEvent,
    )

    typed = tuple(
        event for event in events if isinstance(event, InvestigationTimelineEvent)
    )
    return convert_timeline_actions(typed)
