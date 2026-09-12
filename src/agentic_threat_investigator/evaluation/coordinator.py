# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure deterministic coordinator trajectory evaluation (PR 21/21D).

The evaluator consumes structured action records (never logs), a resolved
scenario, and the authoritative final ``InvestigationState``. It is
synchronous and pure: no database, network, LLM, environment, or clock
access. Hard-gate invariants (invented/policy-invalid pivots, budget
violations, non-termination) are evaluated rather than hardcoded.

Each scenario declares an exhaustive legal pivot oracle
(``allowed_pivots``: semantic entity label + exact depth). The evaluator
independently checks pivot authorization (``PIVOT_ENQUEUED``) and
``PIVOT_EXECUTED`` against that oracle and requires execution to follow a
matching enqueue; it never re-implements CoordinatorPolicy.
"""

import json
from enum import Enum
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    ResearchExecutionStatus,
    StopReason,
)

# Stable PR 21 action URNs shared by emission and evaluation.
ACTION_PROVIDER_QUERY = "urn:ati:action:provider_query"
ACTION_ENTITY_DISCOVERED = "urn:ati:action:entity_discovered"
ACTION_PIVOT_ENQUEUED = "urn:ati:action:pivot_enqueued"
ACTION_PIVOT_EXECUTED = "urn:ati:action:pivot_executed"
ACTION_PIVOT_SKIPPED = "urn:ati:action:pivot_skipped"
ACTION_RESEARCH_REQUESTED = "urn:ati:action:research_requested"
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
        """Reject duplicate labels and enforce allowed-pivot consistency.

        ``allowed_pivots`` and ``max_transitions`` must both be explicitly
        present in scenario JSON; omission must never silently mean "no
        pivot is legal". Exact ``(entity label, depth)`` identities must be
        unique, every ``required_pivots`` label must be represented in
        ``allowed_pivots``, and no ``forbidden_pivots`` label may appear in
        ``allowed_pivots``.
        """
        for field in ("allowed_pivots", "max_transitions"):
            if field not in self.expected.model_fields_set:
                raise ValueError(f"{field} must be explicitly provided")
        for field in (
            "required_pivots",
            "forbidden_pivots",
            "required_provider_work",
            "forbidden_provider_work",
            "required_research_markers",
            "required_research_requests",
            "forbidden_research_requests",
        ):
            values = getattr(self.expected, field)
            if len(values) != len(set(values)):
                raise ValueError(f"{field} must not contain duplicate labels")
        allowed = self.expected.allowed_pivots
        allowed_identities = [(pivot.entity, pivot.depth) for pivot in allowed]
        if len(allowed_identities) != len(set(allowed_identities)):
            raise ValueError(
                "allowed_pivots must not contain duplicate entity/depth identities"
            )
        allowed_labels = {pivot.entity for pivot in allowed}
        missing_required = sorted(set(self.expected.required_pivots) - allowed_labels)
        if missing_required:
            raise ValueError(
                "required_pivots must be represented in allowed_pivots: "
                + ", ".join(missing_required)
            )
        forbidden_overlap = sorted(set(self.expected.forbidden_pivots) & allowed_labels)
        if forbidden_overlap:
            raise ValueError(
                "forbidden_pivots must not appear in allowed_pivots: "
                + ", ".join(forbidden_overlap)
            )
        research_overlap = sorted(
            set(self.expected.required_research_requests)
            & set(self.expected.forbidden_research_requests)
        )
        if research_overlap:
            raise ValueError(
                "research labels cannot be both required and forbidden: "
                + ", ".join(research_overlap)
            )
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


class ExpectedPivot(BaseModel):
    """One exhaustive legal pivot identity declared by a scenario.

    Identity is the semantic entity label plus the exact expected depth:
    ``resolved_ip`` at depth 1 and ``resolved_ip`` at depth 2 are different
    policy identities (PR 21D Invariant B).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity: str
    depth: int = Field(ge=0)

    @model_validator(mode="after")
    def entity_present(self) -> "ExpectedPivot":
        """Reject blank semantic entity labels."""
        if not self.entity.strip():
            raise ValueError("expected pivot entity label must not be blank")
        return self


class ExpectedCoordinatorTrajectory(BaseModel):
    """Scenario envelope for deterministic coordinator behavior."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # The exhaustive legal pivot universe for the scenario: an observed
    # PIVOT_ENQUEUED/PIVOT_EXECUTED outside this set is policy-invalid.
    # The JSON loader requires the field to be explicitly present.
    allowed_pivots: tuple[ExpectedPivot, ...] = ()
    required_pivots: tuple[str, ...] = ()
    forbidden_pivots: tuple[str, ...] = ()
    required_provider_work: tuple[str, ...] = ()
    forbidden_provider_work: tuple[str, ...] = ()
    required_research_markers: tuple[str, ...] = ()
    required_research_requests: tuple[str, ...] = ()
    forbidden_research_requests: tuple[str, ...] = ()
    max_research_requests: int | None = Field(default=None, ge=0)
    require_research_termination: bool = False
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
    REQUIRED_RESEARCH_REQUEST_MISSING = "required_research_request_missing"
    FORBIDDEN_RESEARCH_REQUEST_EXECUTED = "forbidden_research_request_executed"
    DUPLICATE_RESEARCH_REQUEST = "duplicate_research_request"
    RESEARCH_REQUEST_BUDGET_VIOLATION = "research_request_budget_violation"
    RESEARCH_NOT_TERMINATED = "research_not_terminated"


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

        # Delivered research lifecycle (PR 22C/22D). The evaluator recognizes
        # RESEARCH_REQUESTED actions and final durable research execution
        # state; it never re-implements CoordinatorPolicy. Required/forbidden
        # requests resolve semantic entity labels exactly; the declared
        # bounded request budget is enforced; and a duplicate is a request
        # beyond the durable authorized attempt total for its subject (a post-
        # completion/exhaustion re-request), never merely count > 1, so a
        # legitimate bounded retry is never misclassified.
        research_requests = [
            item
            for item in actions
            if item.action == ACTION_RESEARCH_REQUESTED and item.entity_id is not None
        ]
        request_counts: dict[UUID, int] = {}
        for item in research_requests:
            entity_id = item.entity_id
            if entity_id is None:
                continue
            request_counts[entity_id] = request_counts.get(entity_id, 0) + 1
        request_entity_ids = set(request_counts)

        for label in scenario.expected.required_research_requests:
            target = resolution.entities.get(label)
            if target is None or target not in request_entity_ids:
                failures.append(
                    CoordinatorEvaluationFailureCode.REQUIRED_RESEARCH_REQUEST_MISSING
                )
        for label in scenario.expected.forbidden_research_requests:
            target = resolution.entities.get(label)
            if target is not None and target in request_entity_ids:
                failures.append(
                    CoordinatorEvaluationFailureCode.FORBIDDEN_RESEARCH_REQUEST_EXECUTED
                )
        if (
            scenario.expected.max_research_requests is not None
            and len(research_requests) > scenario.expected.max_research_requests
        ):
            failures.append(
                CoordinatorEvaluationFailureCode.RESEARCH_REQUEST_BUDGET_VIOLATION
            )

        attempts_by_subject: dict[UUID, int] = {}
        for execution in final_state.research_executions:
            attempts_by_subject[execution.subject_entity_id] = (
                attempts_by_subject.get(execution.subject_entity_id, 0)
                + execution.attempts
            )
        duplicate_entities = sum(
            1
            for entity_id, count in request_counts.items()
            if count > attempts_by_subject.get(entity_id, 0)
        )
        if duplicate_entities:
            failures.append(CoordinatorEvaluationFailureCode.DUPLICATE_RESEARCH_REQUEST)

        research_terminated = True
        if scenario.expected.require_research_termination:
            dangling_requested = any(
                execution.status is ResearchExecutionStatus.REQUESTED
                for execution in final_state.research_executions
            )
            if (research_requests and not final_state.research_executions) or (
                dangling_requested
            ):
                research_terminated = False
                failures.append(
                    CoordinatorEvaluationFailureCode.RESEARCH_NOT_TERMINATED
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
        # ENTITY_BUDGET_VIOLATION only when a pivot action's entity count is
        # strictly above the budget: an exact-capacity (:code:`entity_count ==
        # max_entities`) pivot onto an already-admitted entity is legal under
        # the deterministic admission rule (PR 21B). The evaluator does not
        # reconstruct coordinator admission policy; it evaluates the recorded
        # budget counters against the scenario envelope.
        if scenario.expected.max_entities is not None and any(
            item.action in (ACTION_PIVOT_ENQUEUED, ACTION_PIVOT_EXECUTED)
            and item.depth is not None
            and item.depth > 0
            and item.entity_count is not None
            and item.entity_count > scenario.expected.max_entities
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

        # Independent pivot-policy check (PR 21D). The scenario owns an
        # exhaustive legal pivot oracle; the evaluator never reconstructs
        # CoordinatorPolicy. A pivot identity is ``(entity_id, depth)``:
        #  - an ENQUEUED or EXECUTED identity outside ``allowed_pivot_keys``
        #    is policy-invalid (authorization is independently validated);
        #  - an EXECUTED identity without a preceding matching ENQUEUED is
        #    policy-invalid (order validation is preserved);
        #  - a pivot action without a usable identity is policy-invalid but
        #    never crashes the evaluator.
        # Metrics count unique observed identities so one illegal identity
        # enqueued and later executed contributes once, never twice.
        allowed_pivot_keys: set[tuple[UUID, int]] = set()
        for pivot in scenario.expected.allowed_pivots:
            allowed_entity_id = resolution.entities.get(pivot.entity)
            if allowed_entity_id is None:
                raise ValueError(
                    "allowed pivot entity is unresolved in scenario resolution: "
                    f"{pivot.entity!r}"
                )
            allowed_pivot_keys.add((allowed_entity_id, pivot.depth))
        observed_pivot_keys: set[tuple[UUID, int]] = set()
        invalid_policy_keys: set[tuple[UUID, int]] = set()
        seen_enqueues: set[tuple[UUID, int]] = set()
        malformed_pivot_actions = 0
        for item in actions:
            if item.action not in (ACTION_PIVOT_ENQUEUED, ACTION_PIVOT_EXECUTED):
                continue
            if item.entity_id is None or item.depth is None:
                malformed_pivot_actions += 1
                continue
            key = (item.entity_id, item.depth)
            observed_pivot_keys.add(key)
            if item.action == ACTION_PIVOT_ENQUEUED:
                seen_enqueues.add(key)
                if key not in allowed_pivot_keys:
                    invalid_policy_keys.add(key)
            else:
                if key not in allowed_pivot_keys:
                    invalid_policy_keys.add(key)
                if key not in seen_enqueues:
                    invalid_policy_keys.add(key)
        if malformed_pivot_actions or invalid_policy_keys:
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
        # invalid_pivot_rate is the union over unique executed pivot
        # identities of invented and policy-invalid executions; one pivot
        # never counts twice and the rate stays in [0.0, 1.0].
        executed_pivot_keys = {
            (item.entity_id, item.depth)
            for item in pivot_executed
            if item.depth is not None
        }
        invented_executed_keys = {
            key for key in executed_pivot_keys if key[0] not in known
        }
        policy_invalid_executed_keys = invalid_policy_keys & executed_pivot_keys
        invalid_executed_keys = invented_executed_keys | policy_invalid_executed_keys
        invalid_pivot_rate = (
            len(invalid_executed_keys) / len(executed_pivot_keys)
            if executed_pivot_keys
            else 0.0
        )
        invented_unique = sum(invented_flags)
        policy_invalid_pivot_rate = (
            len(invalid_policy_keys) / len(observed_pivot_keys)
            if observed_pivot_keys
            else 0.0
        )
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
                "policy_invalid_pivot_rate": float(policy_invalid_pivot_rate),
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
                "research_request_count": float(len(research_requests)),
                "duplicate_research_request_count": float(duplicate_entities),
                "research_terminated": 1.0 if research_terminated else 0.0,
            },
        )
