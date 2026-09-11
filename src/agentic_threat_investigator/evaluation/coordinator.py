# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure deterministic coordinator trajectory evaluation (PR 21).

The evaluator consumes structured action records (never logs), a resolved
scenario, and the authoritative final ``InvestigationState``. It is
synchronous and pure: no database, network, LLM, environment, or clock
access. Hard-gate invariants (invented/policy-invalid pivots, budget
violations, non-termination) are evaluated rather than hardcoded.
"""

import json
from enum import Enum
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    StopReason,
)

# Stable PR 21 action URNs shared by emission and evaluation.
ACTION_PROVIDER_QUERY = "urn:ati:action:provider_query"
ACTION_ENTITY_DISCOVERED = "urn:ati:action:entity_discovered"
ACTION_PIVOT_ENQUEUED = "urn:ati:action:pivot_enqueued"
ACTION_PIVOT_EXECUTED = "urn:ati:action:pivot_executed"
ACTION_PIVOT_SKIPPED = "urn:ati:action:pivot_skipped"
ACTION_ASSESSMENT_REQUESTED = "urn:ati:action:assessment_requested"
ACTION_INVESTIGATION_STOPPED = "urn:ati:action:investigation_stopped"


class CoordinatorScenarioLoadError(ValueError):
    """A scenario file or corpus directory cannot be loaded.

    Loading is strict and fails closed: malformed JSON, unsupported versions,
    blank fixture names, duplicate scenario identities, and duplicate
    expectation labels are all deterministic load errors.
    """

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        """Record the message and optional offending file path."""
        suffix = f" ({path})" if path is not None else ""
        super().__init__(f"{message}{suffix}")
        self.path = path


class _ScenarioValidator(BaseModel):
    """Strict envelope for loading one scenario JSON file."""

    model_config = ConfigDict(extra="forbid")

    id: str
    version: int = Field(ge=1)
    description: str | None = None
    fixture: CoordinatorFixtureReference
    expected: ExpectedCoordinatorTrajectory

    @model_validator(mode="after")
    def fixture_name_present(self) -> "_ScenarioValidator":
        """Reject blank fixture reference names."""
        if not self.fixture.name.strip():
            raise ValueError("coordinator fixture name must not be blank")
        return self

    @model_validator(mode="after")
    def labels_unique(self) -> "_ScenarioValidator":
        """Reject duplicate labels and require an explicit transition bound."""
        if "max_transitions" not in self.expected.model_fields_set:
            raise ValueError("max_transitions must be explicitly provided")
        for field in (
            "required_pivots",
            "forbidden_pivots",
            "required_provider_work",
            "forbidden_provider_work",
            "required_research_markers",
        ):
            values = getattr(self.expected, field)
            if len(values) != len(set(values)):
                raise ValueError(f"{field} must not contain duplicate labels")
        return self


def load_coordinator_scenarios_directory(
    directory: Path | str,
) -> tuple[CoordinatorScenario, ...]:
    """Load every coordinator scenario from a directory in sorted file order.

    Fails closed: unknown JSON fields, invalid models, malformed JSON, and
    duplicate scenario identities (across files) raise a typed load error.
    Discovery order is deterministic (sorted file names), so a corpus
    directory always yields the same scenario tuple.
    """
    root = Path(directory)
    if not root.is_dir():
        raise CoordinatorScenarioLoadError(
            "coordinator scenario directory does not exist", path=root
        )
    scenario_files = sorted(root.glob("*.json"))
    if not scenario_files:
        raise CoordinatorScenarioLoadError(
            "coordinator scenario directory contains no JSON files", path=root
        )
    scenarios: list[CoordinatorScenario] = []
    seen_ids: set[str] = set()
    for path in scenario_files:
        try:
            raw = json.loads(path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CoordinatorScenarioLoadError(
                "malformed coordinator scenario JSON", path=path
            ) from exc
        if not isinstance(raw, dict):
            raise CoordinatorScenarioLoadError(
                "coordinator scenario must be a JSON object", path=path
            )
        try:
            envelope = _ScenarioValidator.model_validate(raw)
        except ValidationError as exc:
            raise CoordinatorScenarioLoadError(
                f"invalid coordinator scenario: {exc.errors()[0]['msg'] if exc.errors() else 'validation failed'}",
                path=path,
            ) from exc
        if envelope.id in seen_ids:
            raise CoordinatorScenarioLoadError(
                f"duplicate coordinator scenario id: {envelope.id}", path=path
            )
        seen_ids.add(envelope.id)
        scenarios.append(
            CoordinatorScenario(
                id=envelope.id,
                version=envelope.version,
                fixture=envelope.fixture,
                expected=envelope.expected,
            )
        )
    return tuple(scenarios)


class CoordinatorActionRecord(BaseModel):
    """Structured observable coordinator action; never reconstructed from logs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str
    entity_id: UUID | None = None
    provider: str | None = None
    depth: int | None = Field(default=None, ge=0)
    reason: str | None = None
    provider_calls_used: int | None = Field(default=None, ge=0)
    replans_used: int | None = Field(default=None, ge=0)
    entity_count: int | None = Field(default=None, ge=0)


class CoordinatorFixtureReference(BaseModel):
    """Stable semantic fixture reference for a coordinator scenario."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str


class ExpectedCoordinatorTrajectory(BaseModel):
    """Scenario envelope for deterministic coordinator behavior."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    required_pivots: tuple[str, ...] = ()
    forbidden_pivots: tuple[str, ...] = ()
    required_provider_work: tuple[str, ...] = ()
    forbidden_provider_work: tuple[str, ...] = ()
    required_research_markers: tuple[str, ...] = ()
    expected_stop_reason: StopReason
    max_provider_calls: int | None = Field(default=None, ge=0)
    max_entities: int | None = Field(default=None, ge=0)
    max_depth: int | None = Field(default=None, ge=0)
    max_replans: int | None = Field(default=None, ge=0)
    max_transitions: int = Field(default=100, gt=0)


class CoordinatorScenario(BaseModel):
    """Repository-owned, versioned coordinator evaluation scenario."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: int = Field(ge=1)
    fixture: CoordinatorFixtureReference
    expected: ExpectedCoordinatorTrajectory


class CoordinatorEvaluationFailureCode(str, Enum):
    """Stable hard-gate failure codes."""

    REQUIRED_PIVOT_MISSING = "required_pivot_missing"
    FORBIDDEN_PIVOT_EXECUTED = "forbidden_pivot_executed"
    INVENTED_ENTITY_PIVOT = "invented_entity_pivot"
    POLICY_INVALID_PIVOT = "policy_invalid_pivot"
    DUPLICATE_ACTION = "duplicate_action"
    STOP_REASON_MISMATCH = "stop_reason_mismatch"
    PROVIDER_BUDGET_VIOLATION = "provider_budget_violation"
    ENTITY_BUDGET_VIOLATION = "entity_budget_violation"
    DEPTH_BUDGET_VIOLATION = "depth_budget_violation"
    REPLAN_BUDGET_VIOLATION = "replan_budget_violation"
    NON_TERMINATION = "non_termination"
    REQUIRED_PROVIDER_WORK_MISSING = "required_provider_work_missing"
    FORBIDDEN_PROVIDER_WORK_EXECUTED = "forbidden_provider_work_executed"
    REQUIRED_RESEARCH_MARKER_MISSING = "required_research_marker_missing"


class CoordinatorScenarioResolution(BaseModel):
    """Resolved semantic labels for one materialized scenario."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entities: dict[str, UUID] = Field(default_factory=dict)
    provider_work: dict[str, tuple[str, UUID, int]] = Field(default_factory=dict)


class CoordinatorEvaluationResult(BaseModel):
    """Deterministic evaluation result and bounded metrics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    passed: bool
    failures: tuple[CoordinatorEvaluationFailureCode, ...] = ()
    metrics: dict[str, float] = Field(default_factory=dict)


class CoordinatorTrajectoryEvaluator:
    """Evaluate actions and final operational state without external effects."""

    def evaluate(
        self,
        *,
        scenario: CoordinatorScenario,
        resolution: CoordinatorScenarioResolution,
        final_state: InvestigationState,
        actions: tuple[CoordinatorActionRecord, ...],
        observed_transitions: int,
    ) -> CoordinatorEvaluationResult:
        """Return stable failures and denominator-safe coordinator metrics."""
        if observed_transitions < 1:
            raise ValueError("observed_transitions must be positive")
        failures: list[CoordinatorEvaluationFailureCode] = []

        pivot_executed = [
            item
            for item in actions
            if item.action == ACTION_PIVOT_EXECUTED and item.entity_id is not None
        ]
        provider_queries = [
            item for item in actions if item.action == ACTION_PROVIDER_QUERY
        ]
        pivot_ids = [item.entity_id for item in pivot_executed if item.entity_id]
        known = set(final_state.root_entity_ids) | set(
            final_state.discovered_entity_ids
        )

        # Invented-entity hard gate: a pivot target outside roots/discoveries.
        invented = sum(
            entity_id not in known for entity_id in pivot_ids if entity_id is not None
        )
        if invented:
            failures.append(CoordinatorEvaluationFailureCode.INVENTED_ENTITY_PIVOT)

        # Required pivots.
        for label in scenario.expected.required_pivots:
            target = resolution.entities.get(label)
            if target is not None and target not in pivot_ids:
                failures.append(CoordinatorEvaluationFailureCode.REQUIRED_PIVOT_MISSING)

        # Forbidden pivots.
        for label in scenario.expected.forbidden_pivots:
            target = resolution.entities.get(label)
            if target is not None and target in pivot_ids:
                failures.append(
                    CoordinatorEvaluationFailureCode.FORBIDDEN_PIVOT_EXECUTED
                )

        for label in scenario.expected.required_research_markers:
            target = resolution.entities.get(label)
            if (
                target is None
                or target not in final_state.research_required_for_entity_ids
            ):
                failures.append(
                    CoordinatorEvaluationFailureCode.REQUIRED_RESEARCH_MARKER_MISSING
                )

        # Duplicate pivots.
        duplicate_pivots = len(pivot_ids) - len(set(pivot_ids))
        if duplicate_pivots:
            failures.append(CoordinatorEvaluationFailureCode.DUPLICATE_ACTION)

        # Duplicate provider-query identities (provider, entity, depth).
        query_keys = [
            (item.provider, item.entity_id, item.depth)
            for item in provider_queries
            if item.provider is not None and item.entity_id is not None
        ]
        duplicate_queries = len(query_keys) - len(set(query_keys))
        if duplicate_queries:
            failures.append(CoordinatorEvaluationFailureCode.DUPLICATE_ACTION)

        # Required provider work (provider, entity, depth).
        for label in scenario.expected.required_provider_work:
            work_info = resolution.provider_work.get(label)
            if work_info is None:
                failures.append(
                    CoordinatorEvaluationFailureCode.REQUIRED_PROVIDER_WORK_MISSING
                )
                continue
            provider, entity_id, depth = work_info
            found = any(
                item.provider == provider
                and item.entity_id == entity_id
                and item.depth == depth
                for item in provider_queries
            )
            if not found:
                failures.append(
                    CoordinatorEvaluationFailureCode.REQUIRED_PROVIDER_WORK_MISSING
                )

        # Forbidden provider work.
        for label in scenario.expected.forbidden_provider_work:
            work_info = resolution.provider_work.get(label)
            if work_info is None:
                continue
            provider, entity_id, depth = work_info
            found = any(
                item.provider == provider
                and item.entity_id == entity_id
                and item.depth == depth
                for item in provider_queries
            )
            if found:
                failures.append(
                    CoordinatorEvaluationFailureCode.FORBIDDEN_PROVIDER_WORK_EXECUTED
                )

        # Budget violations.
        if (
            scenario.expected.max_provider_calls is not None
            and final_state.budget.provider_calls_used
            > scenario.expected.max_provider_calls
        ):
            failures.append(CoordinatorEvaluationFailureCode.PROVIDER_BUDGET_VIOLATION)
        if (
            scenario.expected.max_replans is not None
            and final_state.budget.replans_used > scenario.expected.max_replans
        ):
            failures.append(CoordinatorEvaluationFailureCode.REPLAN_BUDGET_VIOLATION)
        if scenario.expected.max_entities is not None and any(
            item.action in (ACTION_PIVOT_ENQUEUED, ACTION_PIVOT_EXECUTED)
            and item.depth is not None
            and item.depth > 0
            and item.entity_count is not None
            and item.entity_count >= scenario.expected.max_entities
            for item in actions
        ):
            failures.append(CoordinatorEvaluationFailureCode.ENTITY_BUDGET_VIOLATION)
        max_observed_depth = max(
            (item.depth or 0 for item in provider_queries), default=0
        )
        if (
            scenario.expected.max_depth is not None
            and max_observed_depth > scenario.expected.max_depth
        ):
            failures.append(CoordinatorEvaluationFailureCode.DEPTH_BUDGET_VIOLATION)

        # Authorization is order-sensitive: an enqueue authorizes only a
        # later execution for the exact entity/depth identity.
        seen_enqueues: set[tuple[UUID | None, int | None]] = set()
        policy_invalid_flags: list[bool] = []
        for item in actions:
            key = (item.entity_id, item.depth)
            if item.action == ACTION_PIVOT_ENQUEUED:
                seen_enqueues.add(key)
            elif item.action == ACTION_PIVOT_EXECUTED and item.entity_id is not None:
                policy_invalid_flags.append(key not in seen_enqueues)
        policy_invalid = sum(policy_invalid_flags)
        if policy_invalid:
            failures.append(CoordinatorEvaluationFailureCode.POLICY_INVALID_PIVOT)

        stopped_actions = [
            item for item in actions if item.action == ACTION_INVESTIGATION_STOPPED
        ]
        terminal_state = (
            final_state.stop_reason is not None
            and final_state.status.value in ("completed", "failed")
            and (
                (
                    final_state.stop_reason == StopReason.FATAL_ERROR.value
                    and final_state.status.value == "failed"
                )
                or (
                    final_state.stop_reason != StopReason.FATAL_ERROR.value
                    and final_state.status.value == "completed"
                )
            )
        )
        one_stop_action = len(stopped_actions) == 1
        matching_stop = (
            one_stop_action and stopped_actions[0].reason == final_state.stop_reason
        )
        within_bound = (
            observed_transitions > 0
            and observed_transitions <= scenario.expected.max_transitions
        )
        terminated = (
            terminal_state and one_stop_action and matching_stop and within_bound
        )
        duplicate_stops = max(0, len(stopped_actions) - 1)
        if duplicate_stops:
            failures.append(CoordinatorEvaluationFailureCode.DUPLICATE_ACTION)
        if not terminated:
            failures.append(CoordinatorEvaluationFailureCode.NON_TERMINATION)
        if terminal_state and one_stop_action and not matching_stop:
            failures.append(CoordinatorEvaluationFailureCode.STOP_REASON_MISMATCH)

        # Stop decision accuracy: the final stop reason equals expectation.
        if (
            final_state.stop_reason != scenario.expected.expected_stop_reason.value
            and terminal_state
        ):
            failures.append(CoordinatorEvaluationFailureCode.STOP_REASON_MISMATCH)

        # Deduplicate while preserving first-seen deterministic order.
        unique_failures = tuple(dict.fromkeys(failures))

        required_recall = (
            sum(
                resolution.entities.get(label) in pivot_ids
                for label in scenario.expected.required_pivots
                if resolution.entities.get(label) is not None
            )
            / len(scenario.expected.required_pivots)
            if scenario.expected.required_pivots
            else 1.0
        )
        stop_decision_accuracy = (
            1.0
            if final_state.stop_reason == scenario.expected.expected_stop_reason.value
            else 0.0
        )
        denied = sum(1 for item in actions if item.action.endswith("pivot_skipped"))
        authorized = len(pivot_ids)
        invented_flags = [item.entity_id not in known for item in pivot_executed]
        invalid_count = sum(
            invented or unauthorized
            for invented, unauthorized in zip(
                invented_flags, policy_invalid_flags, strict=True
            )
        )
        invented_unique = sum(invented_flags)
        invalid_pivot_rate = invalid_count / authorized if authorized else 0.0
        duplicate_count = duplicate_pivots + duplicate_queries + duplicate_stops
        duplicate_denominator = len(pivot_ids) + len(query_keys) + len(stopped_actions)
        return CoordinatorEvaluationResult(
            passed=not unique_failures,
            failures=unique_failures,
            metrics={
                "required_pivot_recall": float(required_recall),
                "invalid_pivot_rate": float(invalid_pivot_rate),
                "invented_entity_pivot_rate": float(
                    invented_unique / authorized if authorized else 0.0
                ),
                "policy_invalid_pivot_rate": float(
                    policy_invalid / authorized if authorized else 0.0
                ),
                "duplicate_action_rate": float(
                    duplicate_count / duplicate_denominator
                    if duplicate_denominator
                    else 0.0
                ),
                "stop_decision_accuracy": float(stop_decision_accuracy),
                "budget_violation_rate": 1.0
                if any(
                    code in unique_failures
                    for code in (
                        CoordinatorEvaluationFailureCode.PROVIDER_BUDGET_VIOLATION,
                        CoordinatorEvaluationFailureCode.ENTITY_BUDGET_VIOLATION,
                        CoordinatorEvaluationFailureCode.DEPTH_BUDGET_VIOLATION,
                        CoordinatorEvaluationFailureCode.REPLAN_BUDGET_VIOLATION,
                    )
                )
                else 0.0,
                "termination": 1.0 if terminated else 0.0,
                "denied_candidate_count": float(denied),
            },
        )
