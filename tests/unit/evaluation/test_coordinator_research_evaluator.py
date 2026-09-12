# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""CoordinatorTrajectoryEvaluator research lifecycle tests (PR 22D, U35-U42).

Extends the PR 21 evaluator coverage with the delivered PR 22C research
lifecycle: RESEARCH_REQUESTED recognition, required/forbidden requests,
duplicate detection past a resolved unchanged context, bounded request
budgets, research termination, and backward compatibility of existing
non-research scenarios.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    MAX_RESEARCH_EXECUTION_ATTEMPTS,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    ResearchExecutionState,
    ResearchExecutionStatus,
    StopReason,
    default_investigation_budget,
)
from agentic_threat_investigator.evaluation.coordinator import (
    ACTION_INVESTIGATION_STOPPED,
    ACTION_PIVOT_ENQUEUED,
    ACTION_PIVOT_EXECUTED,
    ACTION_PROVIDER_QUERY,
    ACTION_RESEARCH_REQUESTED,
    CoordinatorActionRecord,
    CoordinatorEvaluationFailureCode,
    CoordinatorEvaluationResult,
    CoordinatorFixtureReference,
    CoordinatorScenario,
    CoordinatorScenarioResolution,
    CoordinatorTrajectoryEvaluator,
    ExpectedCoordinatorTrajectory,
    ExpectedPivot,
)

_ROOT = UUID("00000000-0000-0000-0000-0000000000a1")
_IP = UUID("00000000-0000-0000-0000-0000000000a2")
_MALWARE = UUID("00000000-0000-0000-0000-0000000000a3")


def _state(**overrides: Any) -> InvestigationState:
    """Build a minimal terminal state with one completed research execution."""
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
        "research_required_for_entity_ids": [_MALWARE],
        "research_executions": [],
    }
    params.update(overrides)
    executions = params.get("research_executions")
    if isinstance(executions, list):
        completed_ids = [
            execution.result_id
            for execution in executions
            if (
                execution.status is ResearchExecutionStatus.COMPLETED
                and execution.result_id is not None
            )
        ]
        if completed_ids and "research_result_ids" not in params:
            params["research_result_ids"] = completed_ids
    return InvestigationState(**params)


def _execution(
    status: ResearchExecutionStatus,
    *,
    attempts: int = 1,
    entity_id: UUID | None = None,
) -> ResearchExecutionState:
    """Build one durable research execution entry."""
    return ResearchExecutionState(
        subject_entity_id=entity_id or _MALWARE,
        context_fingerprint="ati-research-context-v1:fixture",
        query="Provide contextual threat-research information about malware.",
        status=status,
        attempts=attempts,
        result_id=(
            UUID("00000000-0000-0000-0000-0000000000d1")
            if status is ResearchExecutionStatus.COMPLETED
            else None
        ),
    )


def _scenario(**overrides: Any) -> CoordinatorScenario:
    """Build a research-aware scenario for the malware fixture."""
    params: dict[str, Any] = {
        "id": "scenario.malware-research",
        "version": 1,
        "fixture": CoordinatorFixtureReference(name="malware-research"),
        "expected": ExpectedCoordinatorTrajectory(
            allowed_pivots=(ExpectedPivot(entity="resolved_ip", depth=1),),
            required_pivots=("resolved_ip",),
            required_research_markers=("malware_asyncrat",),
            required_research_requests=("malware_asyncrat",),
            max_research_requests=1,
            require_research_termination=True,
            expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        ),
    }
    params.update(overrides)
    return CoordinatorScenario(**params)


def _resolution(**overrides: Any) -> CoordinatorScenarioResolution:
    """Build a resolution mapping the fixture labels to exact entities."""
    params: dict[str, Any] = {
        "entities": {
            "root_domain": _ROOT,
            "resolved_ip": _IP,
            "malware_asyncrat": _MALWARE,
        },
        "provider_work": {
            "dns_root_domain": (SourceId.GOOGLE_PUBLIC_DNS.value, _ROOT, 0),
            "threatfox_resolved_ip": (SourceId.THREATFOX.value, _IP, 1),
        },
    }
    params.update(overrides)
    return CoordinatorScenarioResolution(**params)


def _research_request(*, entity_id: UUID | None = _MALWARE) -> CoordinatorActionRecord:
    """Build one RESEARCH_REQUESTED action record."""
    return CoordinatorActionRecord(
        action=ACTION_RESEARCH_REQUESTED, entity_id=entity_id
    )


def _stopped() -> CoordinatorActionRecord:
    """Build the canonical INVESTIGATION_STOPPED action."""
    return CoordinatorActionRecord(
        action=ACTION_INVESTIGATION_STOPPED, reason=StopReason.SUFFICIENT_EVIDENCE.value
    )


def _evaluate(
    scenario: CoordinatorScenario,
    *,
    actions: tuple[CoordinatorActionRecord, ...],
    state: InvestigationState,
) -> CoordinatorEvaluationResult:
    """Run one deterministic trajectory evaluation."""
    return CoordinatorTrajectoryEvaluator().evaluate(
        scenario=scenario,
        resolution=_resolution(),
        final_state=state,
        actions=actions,
        observed_transitions=5,
    )


def _base_actions(
    research_entity: UUID | None = _MALWARE,
) -> tuple[CoordinatorActionRecord, ...]:
    """Return the minimal passing action sequence for the scenario."""
    requested: tuple[CoordinatorActionRecord, ...] = (
        (_research_request(),) if research_entity is not None else ()
    )
    return (
        CoordinatorActionRecord(
            action=ACTION_PROVIDER_QUERY,
            entity_id=_ROOT,
            provider="urn:ati:source:google_public_dns",
            depth=0,
        ),
        CoordinatorActionRecord(action=ACTION_PIVOT_ENQUEUED, entity_id=_IP, depth=1),
        CoordinatorActionRecord(action=ACTION_PIVOT_EXECUTED, entity_id=_IP, depth=1),
        CoordinatorActionRecord(
            action=ACTION_PROVIDER_QUERY,
            entity_id=_IP,
            provider="urn:ati:source:threatfox",
            depth=1,
        ),
        *requested,
        _stopped(),
    )


def test_u35_required_research_request_observed_passes() -> None:
    """U35: an observed required research request passes."""
    state = _state(research_executions=[_execution(ResearchExecutionStatus.COMPLETED)])
    result = _evaluate(_scenario(), actions=_base_actions(), state=state)
    assert result.passed, result.failures
    assert result.metrics["research_request_count"] == 1.0
    assert result.metrics["duplicate_research_request_count"] == 0.0
    assert result.metrics["research_terminated"] == 1.0


def test_u36_required_research_request_missing_fails() -> None:
    """U36: a missing required research request fails with a stable code."""
    state = _state(research_executions=[])
    result = _evaluate(
        _scenario(),
        actions=_base_actions(research_entity=None),
        state=state,
    )
    assert not result.passed
    assert (
        CoordinatorEvaluationFailureCode.REQUIRED_RESEARCH_REQUEST_MISSING
        in result.failures
    )


def test_u37_forbidden_research_request_fails() -> None:
    """U37: a forbidden research request for an entity fails."""
    scenario = _scenario(
        expected=ExpectedCoordinatorTrajectory(
            allowed_pivots=(ExpectedPivot(entity="resolved_ip", depth=1),),
            required_pivots=("resolved_ip",),
            forbidden_research_requests=("malware_asyncrat",),
            expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        )
    )
    state = _state(research_executions=[_execution(ResearchExecutionStatus.COMPLETED)])
    result = _evaluate(scenario, actions=_base_actions(), state=state)
    assert not result.passed
    assert (
        CoordinatorEvaluationFailureCode.FORBIDDEN_RESEARCH_REQUEST_EXECUTED
        in result.failures
    )


def _research_budget_scenario(max_research_requests: int) -> CoordinatorScenario:
    """Build the canonical scenario with an explicit research request budget."""
    return _scenario(
        expected=ExpectedCoordinatorTrajectory(
            allowed_pivots=(ExpectedPivot(entity="resolved_ip", depth=1),),
            required_pivots=("resolved_ip",),
            required_research_markers=("malware_asyncrat",),
            required_research_requests=("malware_asyncrat",),
            max_research_requests=max_research_requests,
            require_research_termination=True,
            expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        )
    )


def test_u38_legitimate_bounded_retry_is_not_duplicate() -> None:
    """U38: two attempts of one retried context are never duplicates."""
    state = _state(
        research_executions=[_execution(ResearchExecutionStatus.COMPLETED, attempts=2)]
    )
    actions = _base_actions() + (_research_request(),)
    result = _evaluate(_research_budget_scenario(2), actions=actions, state=state)
    assert result.passed, result.failures
    assert result.metrics["duplicate_research_request_count"] == 0.0
    assert result.metrics["research_request_count"] == 2.0


def test_u39_request_after_completion_is_duplicate() -> None:
    """U39: a request after an unchanged completed context is a duplicate."""
    state = _state(
        research_executions=[_execution(ResearchExecutionStatus.COMPLETED, attempts=1)]
    )
    actions = _base_actions() + (_research_request(),)
    result = _evaluate(_scenario(), actions=actions, state=state)
    assert not result.passed
    assert (
        CoordinatorEvaluationFailureCode.DUPLICATE_RESEARCH_REQUEST in result.failures
    )
    assert result.metrics["duplicate_research_request_count"] == 1.0
    # The bounded budget is also exceeded: three requests observed.
    assert CoordinatorEvaluationFailureCode.RESEARCH_REQUEST_BUDGET_VIOLATION in (
        result.failures
    )


def test_u40_exhausted_context_has_no_further_request() -> None:
    """U40: two bounded attempts ending EXHAUSTED are not duplicates."""
    state = _state(
        research_executions=[
            _execution(
                ResearchExecutionStatus.EXHAUSTED,
                attempts=MAX_RESEARCH_EXECUTION_ATTEMPTS,
            )
        ]
    )
    actions = _base_actions() + (_research_request(),)
    result = _evaluate(_research_budget_scenario(2), actions=actions, state=state)
    assert result.passed, result.failures
    assert result.metrics["research_terminated"] == 1.0


def test_u41_transition_bound_exceeded_is_nontermination() -> None:
    """U41: exceeding the explicit transition bound is a hard failure."""
    state = _state(research_executions=[_execution(ResearchExecutionStatus.COMPLETED)])
    result = CoordinatorTrajectoryEvaluator().evaluate(
        scenario=_scenario(),
        resolution=_resolution(),
        final_state=state,
        actions=_base_actions(),
        observed_transitions=200,
    )
    assert not result.passed
    assert CoordinatorEvaluationFailureCode.NON_TERMINATION in result.failures


def test_u42_existing_pr21_scenario_without_research_fields_is_unchanged() -> None:
    """U42: a pre-research scenario envelope evaluates without research fields."""
    step = ExpectedCoordinatorTrajectory(
        allowed_pivots=(ExpectedPivot(entity="resolved_ip", depth=1),),
        required_pivots=("resolved_ip",),
        expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
    )
    assert step.required_research_requests == ()
    assert step.forbidden_research_requests == ()
    assert step.max_research_requests is None
    assert step.require_research_termination is False
    scenario = CoordinatorScenario(
        id="scenario.pre-research",
        version=1,
        fixture=CoordinatorFixtureReference(name="malware-research"),
        expected=step,
    )
    state = _state(research_required_for_entity_ids=[], research_executions=[])
    result = _evaluate(
        scenario, actions=_base_actions(research_entity=None), state=state
    )
    assert result.passed, result.failures
    assert result.metrics["research_request_count"] == 0.0
    assert result.metrics["research_terminated"] == 1.0


def test_dangling_requested_execution_fails_research_termination() -> None:
    """A REQUESTED execution at the stop boundary fails research termination."""
    state = _state(
        research_executions=[_execution(ResearchExecutionStatus.REQUESTED, attempts=1)]
    )
    result = _evaluate(
        _research_budget_scenario(2), actions=_base_actions(), state=state
    )
    assert not result.passed
    assert CoordinatorEvaluationFailureCode.RESEARCH_NOT_TERMINATED in result.failures
