# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""CoordinatorTrajectoryEvaluator unit tests (PR 21).

Covers every failure code, denominator-safe metrics, deterministic failure
ordering, and depth-aware provider-work matching.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    StopReason,
    default_investigation_budget,
)
from agentic_threat_investigator.evaluation.coordinator import (
    ACTION_INVESTIGATION_STOPPED,
    ACTION_PIVOT_ENQUEUED,
    ACTION_PIVOT_EXECUTED,
    ACTION_PROVIDER_QUERY,
    CoordinatorActionRecord,
    CoordinatorEvaluationFailureCode,
    CoordinatorFixtureReference,
    CoordinatorScenario,
    CoordinatorScenarioResolution,
    CoordinatorTrajectoryEvaluator,
    ExpectedCoordinatorTrajectory,
)

_ROOT = UUID("00000000-0000-0000-0000-0000000000a1")
_IP = UUID("00000000-0000-0000-0000-0000000000a2")
_MALWARE = UUID("00000000-0000-0000-0000-0000000000a3")
_INVENTED = UUID("00000000-0000-0000-0000-0000000000ff")


def _state(**overrides: Any) -> InvestigationState:
    """Build a minimal terminal state for evaluation."""
    params: dict[str, Any] = {
        "investigation_id": UUID("00000000-0000-0000-0000-0000000000e1"),
        "status": InvestigationStatus.COMPLETED,
        "trigger_type": InvestigationTriggerType.MANUAL,
        "root_entity_ids": [_ROOT],
        "objective": "Assess the root indicator.",
        "budget": default_investigation_budget(),
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "stop_reason": StopReason.SUFFICIENT_EVIDENCE.value,
        "discovered_entity_ids": [_IP],
    }
    params.update(overrides)
    return InvestigationState(**params)


def _scenario(**overrides: Any) -> CoordinatorScenario:
    """Build a scenario expecting one pivot and sufficient stop."""
    params: dict[str, Any] = {
        "id": "scenario.domain-dns-ip",
        "version": 1,
        "fixture": CoordinatorFixtureReference(name="domain-dns-ip"),
        "expected": ExpectedCoordinatorTrajectory(
            required_pivots=("resolved_ip",),
            expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        ),
    }
    params.update(overrides)
    return CoordinatorScenario(**params)


def _resolution(**overrides: Any) -> CoordinatorScenarioResolution:
    """Build a simple resolution mapping labels to exact entities/work."""
    params: dict[str, Any] = {
        "entities": {"resolved_ip": _IP, "root_domain": _ROOT},
        "provider_work": {
            "abuseipdb_resolved_ip": (
                SourceId.ABUSEIPDB.value,
                _IP,
                1,
            )
        },
    }
    params.update(overrides)
    return CoordinatorScenarioResolution(**params)


def _actions(*records: CoordinatorActionRecord) -> tuple[CoordinatorActionRecord, ...]:
    """Build an action tuple from records."""
    return tuple(records)


class TestEvaluatorCore:
    """Passing scenarios and positive metrics."""

    def test_well_formed_trajectory_passes(self) -> None:
        """A compliant trajectory passes with zero failures."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PROVIDER_QUERY,
                    entity_id=_ROOT,
                    provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                    depth=0,
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_ENQUEUED,
                    entity_id=_IP,
                    depth=1,
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED,
                    entity_id=_IP,
                    depth=1,
                ),
                CoordinatorActionRecord(
                    action=ACTION_INVESTIGATION_STOPPED,
                    reason="sufficient_evidence",
                ),
            ),
        )
        assert result.passed
        assert result.failures == ()
        assert result.metrics["required_pivot_recall"] == 1.0
        assert result.metrics["invented_entity_pivot_rate"] == 0.0
        assert result.metrics["stop_decision_accuracy"] == 1.0
        assert result.metrics["termination"] == 1.0

    def test_zero_denominators_are_safe(self) -> None:
        """Empty pivot/requirement sets never divide by zero."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    required_pivots=(),
                    expected_stop_reason=StopReason.NO_ELIGIBLE_PIVOTS,
                )
            ),
            resolution=_resolution(),
            final_state=_state(stop_reason=StopReason.NO_ELIGIBLE_PIVOTS.value),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_INVESTIGATION_STOPPED,
                    reason="no_eligible_pivots",
                ),
            ),
        )
        assert result.passed
        for metric in (
            "required_pivot_recall",
            "invalid_pivot_rate",
            "invented_entity_pivot_rate",
            "duplicate_action_rate",
        ):
            assert result.metrics[metric] == 0.0 or result.metrics[metric] == 1.0


class TestEvaluatorFailures:
    """Every failure code is produced deterministically."""

    def test_invented_entity_pivot_detected(self) -> None:
        """A pivot onto an unknown entity fails the hard gate."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED,
                    entity_id=_INVENTED,
                    depth=1,
                ),
            ),
        )
        assert CoordinatorEvaluationFailureCode.INVENTED_ENTITY_PIVOT in result.failures
        assert CoordinatorEvaluationFailureCode.POLICY_INVALID_PIVOT in result.failures
        # One action that is both invented and unauthorized counts once per
        # gate type but is not double-counted inside a single rate.
        assert result.metrics["invented_entity_pivot_rate"] == 1.0
        assert result.metrics["policy_invalid_pivot_rate"] == 1.0
        assert result.metrics["invalid_pivot_rate"] == 1.0

    def test_required_pivot_missing(self) -> None:
        """Missing required pivots produce REQUIRED_PIVOT_MISSING."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(),
        )
        assert (
            CoordinatorEvaluationFailureCode.REQUIRED_PIVOT_MISSING in result.failures
        )
        assert result.metrics["required_pivot_recall"] == 0.0

    def test_forbidden_pivot_executed(self) -> None:
        """A forbidden pivot produces FORBIDDEN_PIVOT_EXECUTED."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    forbidden_pivots=("resolved_ip",),
                    expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                )
            ),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED,
                    entity_id=_IP,
                    depth=1,
                ),
            ),
        )
        assert (
            CoordinatorEvaluationFailureCode.FORBIDDEN_PIVOT_EXECUTED in result.failures
        )

    def test_duplicate_pivot_detected(self) -> None:
        """Repeated pivot executions produce DUPLICATE_ACTION."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED, entity_id=_IP, depth=1
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED, entity_id=_IP, depth=1
                ),
            ),
        )
        assert CoordinatorEvaluationFailureCode.DUPLICATE_ACTION in result.failures

    def test_stop_reason_mismatch_detected(self) -> None:
        """Wrong terminal stop reason produces STOP_REASON_MISMATCH."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(),
            resolution=_resolution(),
            final_state=_state(stop_reason=StopReason.NO_ELIGIBLE_PIVOTS.value),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED, entity_id=_IP, depth=1
                ),
            ),
        )
        assert CoordinatorEvaluationFailureCode.STOP_REASON_MISMATCH in result.failures
        assert result.metrics["stop_decision_accuracy"] == 0.0

    def test_provider_budget_violation_detected(self) -> None:
        """Provider budget overrun produces PROVIDER_BUDGET_VIOLATION."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                    max_provider_calls=1,
                )
            ),
            resolution=_resolution(),
            final_state=_state(
                budget=_budget_with_provider_calls(2),
            ),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PROVIDER_QUERY,
                    entity_id=_ROOT,
                    provider=SourceId.GOOGLE_PUBLIC_DNS.value,
                    depth=0,
                ),
            ),
        )
        assert (
            CoordinatorEvaluationFailureCode.PROVIDER_BUDGET_VIOLATION
            in result.failures
        )

    def test_replan_budget_violation_detected(self) -> None:
        """Replan overrun produces REPLAN_BUDGET_VIOLATION."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                    max_replans=1,
                )
            ),
            resolution=_resolution(),
            final_state=_state(budget=_budget_with_replans(2)),
            actions=_actions(),
        )
        assert (
            CoordinatorEvaluationFailureCode.REPLAN_BUDGET_VIOLATION in result.failures
        )

    def test_entity_budget_violation_detected(self) -> None:
        """Working-set overrun produces ENTITY_BUDGET_VIOLATION."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                    max_entities=1,
                )
            ),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_ENQUEUED,
                    entity_id=_IP,
                    depth=1,
                    entity_count=2,
                ),
                CoordinatorActionRecord(
                    action=ACTION_INVESTIGATION_STOPPED,
                    reason=StopReason.SUFFICIENT_EVIDENCE.value,
                ),
            ),
        )
        assert (
            CoordinatorEvaluationFailureCode.ENTITY_BUDGET_VIOLATION in result.failures
        )

    def test_depth_budget_violation_detected(self) -> None:
        """A provider query deeper than the limit violates the depth budget."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                    max_depth=1,
                )
            ),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PROVIDER_QUERY,
                    entity_id=_IP,
                    provider=SourceId.ABUSEIPDB.value,
                    depth=2,
                ),
            ),
        )
        assert (
            CoordinatorEvaluationFailureCode.DEPTH_BUDGET_VIOLATION in result.failures
        )

    def test_non_termination_detected(self) -> None:
        """A final state without a stop reason is NON_TERMINATION."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(),
            resolution=_resolution(),
            final_state=_state(stop_reason=None),
            actions=_actions(),
        )
        assert CoordinatorEvaluationFailureCode.NON_TERMINATION in result.failures
        assert result.metrics["termination"] == 0.0

    def test_required_provider_work_missing(self) -> None:
        """A required provider query with wrong depth is missing."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    required_provider_work=("abuseipdb_resolved_ip",),
                    expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                )
            ),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PROVIDER_QUERY,
                    entity_id=_IP,
                    provider=SourceId.ABUSEIPDB.value,
                    depth=0,  # expected depth 1
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED,
                    entity_id=_IP,
                    depth=1,
                ),
            ),
        )
        assert (
            CoordinatorEvaluationFailureCode.REQUIRED_PROVIDER_WORK_MISSING
            in result.failures
        )

    def test_forbidden_provider_work_executed(self) -> None:
        """Forbidden provider work executes produce a failure."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    forbidden_provider_work=("abuseipdb_resolved_ip",),
                    expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                )
            ),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PROVIDER_QUERY,
                    entity_id=_IP,
                    provider=SourceId.ABUSEIPDB.value,
                    depth=1,
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED,
                    entity_id=_IP,
                    depth=1,
                ),
            ),
        )
        assert (
            CoordinatorEvaluationFailureCode.FORBIDDEN_PROVIDER_WORK_EXECUTED
            in result.failures
        )

    def test_failure_order_is_deterministic(self) -> None:
        """Failures preserve a stable first-seen order without duplicates."""
        evaluator = CoordinatorTrajectoryEvaluator()
        result = evaluator.evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    required_pivots=("resolved_ip",),
                    expected_stop_reason=StopReason.NO_ELIGIBLE_PIVOTS,
                )
            ),
            resolution=_resolution(
                entities={"resolved_ip": _IP, "root_domain": _ROOT},
            ),
            final_state=_state(stop_reason=StopReason.SUFFICIENT_EVIDENCE.value),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED, entity_id=_IP, depth=1
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED, entity_id=_IP, depth=1
                ),
            ),
        )
        ordered = list(result.failures)
        assert ordered == list(dict.fromkeys(ordered))
        assert CoordinatorEvaluationFailureCode.DUPLICATE_ACTION in ordered
        assert CoordinatorEvaluationFailureCode.STOP_REASON_MISMATCH in ordered

    def test_enqueue_after_execution_does_not_authorize_pivot(self) -> None:
        """Authorization must precede execution in the action sequence."""
        result = CoordinatorTrajectoryEvaluator().evaluate(
            observed_transitions=1,
            scenario=_scenario(),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED, entity_id=_IP, depth=1
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_ENQUEUED, entity_id=_IP, depth=1
                ),
                CoordinatorActionRecord(
                    action=ACTION_INVESTIGATION_STOPPED,
                    reason=StopReason.SUFFICIENT_EVIDENCE.value,
                ),
            ),
        )
        assert CoordinatorEvaluationFailureCode.POLICY_INVALID_PIVOT in result.failures
        assert result.metrics["policy_invalid_pivot_rate"] == 1.0

    def test_missing_stop_action_sets_termination_metric_to_zero(self) -> None:
        """A terminal state without its durable stop action is not termination."""
        result = CoordinatorTrajectoryEvaluator().evaluate(
            observed_transitions=1,
            scenario=_scenario(),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_ENQUEUED, entity_id=_IP, depth=1
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED, entity_id=_IP, depth=1
                ),
            ),
        )
        assert CoordinatorEvaluationFailureCode.NON_TERMINATION in result.failures
        assert result.metrics["termination"] == 0.0


class TestEvaluatorEntityBudgetBoundary:
    """Entity-budget evaluation at the exact-capacity boundary (PR 21B).

    The evaluator must not flag a depth>0 pivot whose entity count equals
    ``max_entities``: under deterministic admission the pivoted entity is
    admitted and the pivot is legal. Only a strictly above-budget count is a
    violation. The evaluator still does not independently reconstruct
    coordinator admission policy; that broader hardening belongs to PR 21D.
    """

    def test_exact_capacity_pivot_is_not_a_violation(self) -> None:
        """Case 7.1: entity_count == max_entities is not a violation."""
        result = CoordinatorTrajectoryEvaluator().evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                    max_entities=2,
                )
            ),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_ENQUEUED,
                    entity_id=_IP,
                    depth=1,
                    entity_count=2,
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED,
                    entity_id=_IP,
                    depth=1,
                    entity_count=2,
                ),
                CoordinatorActionRecord(
                    action=ACTION_INVESTIGATION_STOPPED,
                    reason=StopReason.SUFFICIENT_EVIDENCE.value,
                ),
            ),
        )
        assert result.passed
        assert (
            CoordinatorEvaluationFailureCode.ENTITY_BUDGET_VIOLATION
            not in result.failures
        )

    def test_above_budget_pivot_is_a_violation(self) -> None:
        """Case 7.2: entity_count > max_entities remains a violation."""
        result = CoordinatorTrajectoryEvaluator().evaluate(
            observed_transitions=1,
            scenario=_scenario(
                expected=ExpectedCoordinatorTrajectory(
                    expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                    max_entities=2,
                )
            ),
            resolution=_resolution(),
            final_state=_state(),
            actions=_actions(
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_ENQUEUED,
                    entity_id=_IP,
                    depth=1,
                    entity_count=3,
                ),
                CoordinatorActionRecord(
                    action=ACTION_PIVOT_EXECUTED,
                    entity_id=_IP,
                    depth=1,
                    entity_count=3,
                ),
                CoordinatorActionRecord(
                    action=ACTION_INVESTIGATION_STOPPED,
                    reason=StopReason.SUFFICIENT_EVIDENCE.value,
                ),
            ),
        )
        assert (
            CoordinatorEvaluationFailureCode.ENTITY_BUDGET_VIOLATION in result.failures
        )


def _budget_with_provider_calls(calls: int) -> object:
    """Return a budget with the provider counter set."""

    budget = default_investigation_budget()
    return budget.model_copy(update={"provider_calls_used": calls})


def _budget_with_replans(replans: int) -> object:
    """Return a budget with the replan counter set."""

    budget = default_investigation_budget()
    return budget.model_copy(update={"replans_used": replans})
