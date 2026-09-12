# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Report Writer behavioral evaluation (PR 23B).

:class:`ReportWriterEvaluator` compares a persisted
:class:`InvestigationReport` against a repository-owned scenario envelope and
emits stable failure codes. It is deliberately NOT semantic entailment
verification: reference integrity is proven by the application provenance
validator; these scenarios prove expected behavior on known inputs through
exact structural membership and canonical phrase envelopes.

Verdict/confidence mismatch should normally be impossible after application
stamping; the evaluator retains those checks as a hard gate.
"""

from __future__ import annotations

from uuid import UUID

from agentic_threat_investigator.domain.report import (
    InvestigationReport,
    ResearchClaimRef,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ExpectedReportWriterOutput,
    ReportWriterEvaluationInput,
    ReportWriterEvaluationResult,
    ReportWriterFailureCode,
    ReportWriterMetrics,
    ReportWriterScenario,
    ReportWriterScenarioResolution,
    normalize_phrase,
)


class ReportWriterEvaluator:
    """Evaluate one persisted report against one scenario envelope.

    No LLM, embeddings, regex fact extraction, or fuzzy similarity is ever
    used: comparisons are exact structural membership plus normalized-phrase
    containment.
    """

    def evaluate(
        self,
        scenario: ReportWriterScenario,
        resolution: ReportWriterScenarioResolution,
        evaluation_input: ReportWriterEvaluationInput,
    ) -> ReportWriterEvaluationResult:
        """Return the immutable evaluation result for one scenario."""
        expected = scenario.expected
        report = evaluation_input.report
        failures: list[ReportWriterFailureCode] = []

        if expected.expected_no_report:
            if report is not None:
                failures.append(ReportWriterFailureCode.REPORT_STRUCTURE_INVALID)
            if (
                evaluation_input.execution_error_code
                and expected.expected_execution_error_code
                and evaluation_input.execution_error_code
                != expected.expected_execution_error_code
            ):
                failures.append(ReportWriterFailureCode.REPORT_STRUCTURE_INVALID)
            return self._result(scenario, failures, report)

        if report is None:
            failures.append(ReportWriterFailureCode.REPORT_STRUCTURE_INVALID)
            return self._result(scenario, failures, None)

        failures.extend(self._structural_failures(expected, report, resolution))
        return self._result(scenario, failures, report)

    @staticmethod
    def _result(
        scenario: ReportWriterScenario,
        failures: list[ReportWriterFailureCode],
        report: InvestigationReport | None,
    ) -> ReportWriterEvaluationResult:
        """Build the bounded metrics for one evaluation outcome."""
        if report is None:
            metrics = ReportWriterMetrics(
                narrative_statement_count=0,
                included_research_claim_count=0,
                required_finding_coverage=0.0,
                required_research_coverage=0.0,
            )
        else:
            ordinals = tuple(
                finding.assessment_finding_ordinal for finding in report.findings
            )
            required = set(scenario.expected.required_assessment_finding_ordinals)
            finding_coverage = (
                len(required & set(ordinals)) / len(required) if required else 1.0
            )
            research_required = set(scenario.expected.required_research_claim_labels)
            research_coverage = (
                len(research_required) / len(research_required)
                if research_required
                else 1.0
            )
            metrics = ReportWriterMetrics(
                narrative_statement_count=len(report.executive_summary),
                included_finding_ordinals=ordinals,
                included_research_claim_count=len(report.research_context),
                required_finding_coverage=finding_coverage,
                required_research_coverage=research_coverage,
            )
        return ReportWriterEvaluationResult(
            scenario_id=scenario.id,
            scenario_version=scenario.version,
            passed=not failures,
            failures=tuple(failures),
            metrics=metrics,
        )

    def _structural_failures(
        self,
        expected: ExpectedReportWriterOutput,
        report: InvestigationReport,
        resolution: ReportWriterScenarioResolution,
    ) -> list[ReportWriterFailureCode]:
        """Compare the persisted report against the envelope."""
        failures: list[ReportWriterFailureCode] = []

        if report.verdict is not expected.verdict:
            failures.append(ReportWriterFailureCode.VERDICT_MISMATCH)
        if report.confidence is not expected.confidence:
            failures.append(ReportWriterFailureCode.CONFIDENCE_MISMATCH)

        ordinals = {finding.assessment_finding_ordinal for finding in report.findings}
        required_findings = set(expected.required_assessment_finding_ordinals)
        forbidden_findings = set(expected.forbidden_assessment_finding_ordinals)
        missing_findings = sorted(required_findings - ordinals)
        if missing_findings:
            failures.append(ReportWriterFailureCode.REQUIRED_ASSESSMENT_FINDING_MISSING)
        included_forbidden = sorted(forbidden_findings & ordinals)
        if included_forbidden:
            failures.append(
                ReportWriterFailureCode.FORBIDDEN_ASSESSMENT_FINDING_INCLUDED
            )

        included_claims = {
            snapshot.research_claim_id for snapshot in report.research_context
        }
        expected_by_label = resolution.research_claim_ids
        required_claims = {
            expected_by_label[label]
            for label in expected.required_research_claim_labels
            if label in expected_by_label
        }
        missing_claims = required_claims - included_claims
        if missing_claims:
            failures.append(ReportWriterFailureCode.REQUIRED_RESEARCH_CLAIM_MISSING)
        forbidden_claims = {
            expected_by_label[label]
            for label in expected.forbidden_research_claim_labels
            if label in expected_by_label
        }
        if forbidden_claims & included_claims:
            failures.append(ReportWriterFailureCode.FORBIDDEN_RESEARCH_CLAIM_INCLUDED)

        for limitation in expected.required_limitations:
            if normalize_phrase(limitation) not in {
                normalize_phrase(item) for item in report.limitations
            }:
                failures.append(ReportWriterFailureCode.REQUIRED_LIMITATION_MISSING)
                break
        for question in expected.required_unresolved_questions:
            if normalize_phrase(question) not in {
                normalize_phrase(item) for item in report.unresolved_questions
            }:
                failures.append(
                    ReportWriterFailureCode.REQUIRED_UNRESOLVED_QUESTION_MISSING
                )
                break
        for step in expected.required_next_steps:
            if normalize_phrase(step) not in {
                normalize_phrase(item) for item in report.recommended_next_steps
            }:
                failures.append(ReportWriterFailureCode.REQUIRED_NEXT_STEP_MISSING)
                break

        statement_count = len(report.executive_summary)
        if statement_count < expected.min_narrative_statements or (
            expected.max_narrative_statements is not None
            and statement_count > expected.max_narrative_statements
        ):
            failures.append(ReportWriterFailureCode.REPORT_STATEMENT_ENVELOPE_VIOLATION)
        else:
            narrative_text = " ".join(
                statement.text for statement in report.executive_summary
            )
            normalized = normalize_phrase(narrative_text)
            for phrase in expected.required_phrases:
                if phrase not in normalized:
                    failures.append(
                        ReportWriterFailureCode.REPORT_STATEMENT_ENVELOPE_VIOLATION
                    )
                    break
            for phrase in expected.forbidden_phrases:
                if phrase in normalized:
                    failures.append(
                        ReportWriterFailureCode.REPORT_STATEMENT_ENVELOPE_VIOLATION
                    )
                    break

        # Unsupported-source hard gate: every research claim referenced by the
        # report (research context or narrative support) must belong to the
        # scenario-declared claim universe. This mirrors the application
        # validator and is retained as a hard evaluation gate.
        allowed_claims = set(resolution.research_claim_ids.values())
        referenced_claims: set[UUID] = {
            snapshot.research_claim_id for snapshot in report.research_context
        }
        for statement in report.executive_summary:
            for ref in statement.support:
                if isinstance(ref, ResearchClaimRef):
                    referenced_claims.add(ref.research_claim_id)
        if referenced_claims - allowed_claims:
            failures.append(ReportWriterFailureCode.UNSUPPORTED_SOURCE_REFERENCE)
        return failures


def planned_research_claim_id(
    scenario: ReportWriterScenario, label: str, namespace: UUID
) -> UUID:
    """Return the deterministic claim identity a materializer must use.

    Runtime UUIDs never appear in scenario files; the harness plans the exact
    ``ResearchClaim.id`` from the stable scenario identity and label so
    evaluation resolution never depends on runtime randomness.
    """
    from uuid import uuid5

    return uuid5(
        namespace,
        f"urn:ati:scenario:{scenario.id}:v{scenario.version}:research_claim:{label}",
    )
