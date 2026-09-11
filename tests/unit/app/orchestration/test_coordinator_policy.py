# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""CoordinatorPolicy unit tests (PR 21).

Tests the pure deterministic policy logic: pivot eligibility, depth/budget
enforcement, duplicate suppression, stop reason precedence, and replan
semantics. All tests are synchronous and use in-memory state/context only.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.app.orchestration.coordinator import (
    CoordinatorAction,
    CoordinatorEntityView,
    CoordinatorPolicy,
    CoordinatorPolicyContext,
    MappingProviderWorkPlanner,
    PivotRejectionReason,
    ProviderWorkPlanner,
)
from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    EntityTraversalState,
    InvestigationBudget,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    PivotRequest,
    PivotStatus,
    ProviderWorkItem,
    StopReason,
)

_ROOT_DOMAIN_ID = UUID("00000000-0000-0000-0000-000000000001")
_DISCOVERED_IP_ID = UUID("00000000-0000-0000-0000-000000000002")
_MALWARE_ID = UUID("00000000-0000-0000-0000-000000000003")
_OTHER_ENTITY = UUID("00000000-0000-0000-0000-000000000004")
_DOMAIN_B_ID = UUID("00000000-0000-0000-0000-000000000005")
_IP_A_ID = UUID("00000000-0000-0000-0000-000000000006")
_IP_B_ID = UUID("00000000-0000-0000-0000-000000000007")


def _small_budget(**overrides: int) -> InvestigationBudget:
    """Return a budget with reduced defaults for boundary testing."""
    params: dict[str, int] = {
        "max_depth": 2,
        "max_entities": 10,
        "max_provider_calls": 40,
        "max_replans": 3,
        "max_llm_calls": 10,
    }
    params.update(overrides)
    return InvestigationBudget(**params)


def _state(**overrides: Any) -> InvestigationState:
    """Return a minimal running investigation state for testing."""
    from datetime import UTC, datetime

    params: dict[str, Any] = {
        "investigation_id": UUID("00000000-0000-0000-0000-0000000000a1"),
        "status": InvestigationStatus.RUNNING,
        "trigger_type": InvestigationTriggerType.MANUAL,
        "root_entity_ids": [_ROOT_DOMAIN_ID],
        "objective": "Test investigation",
        "budget": _small_budget(),
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    params.update(overrides)
    # Auto-build traversal metadata from roots + discoveries so tests do not
    # need to author coherent traversal entries by hand; the production flow
    # builds traversal through record_provider_outcome instead.
    if "traversal" not in params:
        traversal: list[EntityTraversalState] = []
        ordinal = 0
        for entity_id in params.get("root_entity_ids", []):
            traversal.append(
                EntityTraversalState(
                    entity_id=entity_id,
                    first_discovery_ordinal=ordinal,
                    minimum_depth=0,
                )
            )
            ordinal += 1
        for entity_id in params.get("discovered_entity_ids", []):
            traversal.append(
                EntityTraversalState(
                    entity_id=entity_id,
                    first_discovery_ordinal=ordinal,
                    minimum_depth=1,
                )
            )
            ordinal += 1
        params["traversal"] = traversal
    return InvestigationState(**params)


def _context(
    entities: list[CoordinatorEntityView] | None = None,
    assessment: Assessment | None = None,
) -> CoordinatorPolicyContext:
    """Return a minimal context for testing."""
    if entities is None:
        entities = [
            CoordinatorEntityView(
                entity_id=_ROOT_DOMAIN_ID,
                entity_type=EntityType.DOMAIN,
            ),
        ]
    return CoordinatorPolicyContext(
        entities=tuple(entities),
        current_assessment=assessment,
    )


def _planner() -> ProviderWorkPlanner:
    """Return a planner that covers DOMAIN and IP_ADDRESS."""
    return MappingProviderWorkPlanner(
        applicability={
            SourceId.GOOGLE_PUBLIC_DNS: frozenset({EntityType.DOMAIN}),
            SourceId.RDAP: frozenset({EntityType.DOMAIN}),
            SourceId.ABUSEIPDB: frozenset({EntityType.IP_ADDRESS}),
            SourceId.THREATFOX: frozenset({EntityType.IP_ADDRESS}),
        }
    )


def _policy() -> CoordinatorPolicy:
    """Return a policy using the test planner."""
    return CoordinatorPolicy(_planner())


class TestCoordinatorDecisionBasics:
    """Core coordinator decision semantics."""

    def test_known_root_domain_authorizes_provider_work(self) -> None:
        """A known root domain with no work yet authorizes a pivot."""
        policy = _policy()
        state = _state()
        context = _context()
        decision = policy.decide(state=state, context=context)
        # No pending work, no assessment, no evidence — should authorize pivot.
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT

    def test_pending_provider_work_returns_execute(self) -> None:
        """Pending provider work is always selected first."""
        policy = _policy()
        state = _state(
            pending_provider_work=[
                ProviderWorkItem(
                    provider=SourceId.GOOGLE_PUBLIC_DNS,
                    entity_id=_ROOT_DOMAIN_ID,
                    depth=0,
                )
            ]
        )
        context = _context()
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.EXECUTE_PROVIDER_WORK

    def test_unknown_entity_not_authorized(self) -> None:
        """An entity not in the context is never authorized."""
        policy = _policy()
        state = _state(
            discovered_entity_ids=[_OTHER_ENTITY],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        # Only root domain is eligible.
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT
        assert decision.pivots
        assert decision.pivots[0].entity_id == _ROOT_DOMAIN_ID

    def test_deleted_entity_not_eligible(self) -> None:
        """A soft-deleted entity is never eligible for a pivot."""
        policy = _policy()
        state = _state(discovered_entity_ids=[_OTHER_ENTITY])
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_OTHER_ENTITY,
                    entity_type=EntityType.IP_ADDRESS,
                    deleted=True,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        # Only the root domain is eligible.
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT
        assert decision.pivots
        assert decision.pivots[0].entity_id == _ROOT_DOMAIN_ID

    def test_already_investigated_entity_not_eligible(self) -> None:
        """An entity already in investigated_entity_ids is skipped."""
        policy = _policy()
        state = _state(
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            investigated_entity_ids=[_DISCOVERED_IP_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        # Only the root domain is eligible (not yet investigated).
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT
        assert len(decision.pivots) == 1
        assert decision.pivots[0].entity_id == _ROOT_DOMAIN_ID

    def test_missing_candidate_returns_candidate_specific_rejection(self) -> None:
        """A missing persisted root is rejected as UNKNOWN_TARGET."""
        decision = _policy().decide(
            state=_state(),
            context=CoordinatorPolicyContext(missing_entity_ids=(_ROOT_DOMAIN_ID,)),
        )
        assert decision.action is CoordinatorAction.STOP
        assert len(decision.rejections) == 1
        rejection = decision.rejections[0]
        assert rejection.entity_id == _ROOT_DOMAIN_ID
        assert rejection.proposed_depth == 0
        assert rejection.reason.value == "unknown_target"


class TestCoordinatorStopReasons:
    """Stop reason precedence and boundary conditions."""

    def test_no_eligible_pivot_returns_stop(self) -> None:
        """When all candidates are exhausted, the coordinator stops."""
        policy = _policy()
        state = _state(
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.STOP
        assert decision.stop_reason is StopReason.NO_ELIGIBLE_PIVOTS

    def test_sufficient_evidence_returns_stop(self) -> None:
        """SUFFICIENT disposition means stop."""
        policy = _policy()
        state = _state(
            analysis_disposition=AnalysisDisposition.SUFFICIENT.value,
        )
        context = _context()
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.STOP
        assert decision.stop_reason is StopReason.SUFFICIENT_EVIDENCE

    def test_no_eligible_pivots_with_needs_more_evidence_returns_stop(self) -> None:
        """NEEDS_MORE_EVIDENCE but no eligible pivot -> stop."""
        policy = _policy()
        state = _state(
            analysis_disposition=AnalysisDisposition.NEEDS_MORE_EVIDENCE.value,
            # The root domain is already investigated.
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        # NEEDS_MORE_EVIDENCE with no eligible candidates -> stop.
        assert decision.action is CoordinatorAction.STOP
        assert decision.stop_reason is StopReason.NO_ELIGIBLE_PIVOTS

    def test_provider_budget_exhausted_stop(self) -> None:
        """Provider budget exhausted returns specific stop reason."""
        policy = _policy()
        state = _state(
            budget=_small_budget(max_provider_calls=5, provider_calls_used=5),
        )
        context = _context()
        decision = policy.decide(state=state, context=context)
        # Provider budget is the blocker.
        assert decision.action is CoordinatorAction.STOP
        assert decision.stop_reason is StopReason.PROVIDER_BUDGET_EXHAUSTED

    def test_depth_limit_stop(self) -> None:
        """Depth limit reached returns specific stop reason."""
        policy = _policy()
        # max_depth=0 means no pivoting beyond depth 0.
        # Only candidate is the discovered IP at depth 1, which is blocked by depth.
        state = _state(
            budget=_small_budget(max_depth=0, max_entities=10, max_provider_calls=40),
            root_entity_ids=[],  # Empty root set: only discovered entity.
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            traversal=[
                EntityTraversalState(
                    entity_id=_DISCOVERED_IP_ID,
                    first_discovery_ordinal=0,
                    minimum_depth=1,
                )
            ],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.STOP
        assert decision.stop_reason is StopReason.DEPTH_LIMIT_REACHED


class TestCoordinatorPivotAuthorization:
    """Pivot creation and duplicate suppression."""

    def test_authorize_pivot_creates_pivot_request(self) -> None:
        """Authorizing a pivot creates a PivotRequest with correct fields."""
        policy = _policy()
        state = _state()
        context = _context()
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT
        assert len(decision.pivots) == 1
        pivot = decision.pivots[0]
        assert pivot.entity_id == _ROOT_DOMAIN_ID
        assert pivot.depth == 0  # Root entity has depth 0
        assert pivot.status is PivotStatus.PENDING

    def test_authorize_pivot_plans_provider_work(self) -> None:
        """Authorizing a pivot includes planned provider work items."""
        policy = _policy()
        state = _state()
        context = _context()
        decision = policy.decide(state=state, context=context)
        assert decision.work_items
        # Root domain has DNS + RDAP work items.
        assert len(decision.work_items) >= 1
        work_item = decision.work_items[0]
        assert work_item.entity_id == _ROOT_DOMAIN_ID

    def test_duplicate_pivot_not_authorized(self) -> None:
        """An already-investigated entity is not authorized again."""
        policy = _policy()
        state = _state(
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
        )
        context = _context()
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.STOP

    def test_researchable_entity_marked_not_pivoted(self) -> None:
        """A RESEARCHABLE entity is marked for research, not pivoted."""
        policy = _policy()
        state = _state(
            discovered_entity_ids=[_MALWARE_ID],
            # Root already investigated so coordinator processes malware.
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_MALWARE_ID,
                    entity_type=EntityType.MALWARE,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        # Researchable entities are marked but not pivoted.
        assert decision.research_entity_ids == (_MALWARE_ID,)


class TestCoordinatorReplan:
    """Replan semantics and budgeting."""

    def test_needs_more_evidence_before_replan(self) -> None:
        """NEEDS_MORE_EVIDENCE can authorize a pivot round."""
        policy = _policy()
        state = _state(
            analysis_disposition=AnalysisDisposition.NEEDS_MORE_EVIDENCE.value,
        )
        context = _context()
        decision = policy.decide(state=state, context=context)
        # Root domain is still eligible and has work items.
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT

    def test_replan_exhausted_after_replans(self) -> None:
        """Replan budget exhaustion returns REPLAN_LIMIT_REACHED."""
        policy = _policy()
        state = _state(
            analysis_disposition=AnalysisDisposition.NEEDS_MORE_EVIDENCE.value,
            budget=_small_budget(max_replans=1, replans_used=1),
        )
        context = _context()
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.STOP
        assert decision.stop_reason is StopReason.REPLAN_LIMIT_REACHED

    def test_root_work_allowed_at_entity_budget_capacity(self) -> None:
        """A single admitted root still receives its initial provider work.

        Roots count toward the working set but are already admitted: the
        entity budget limits expansion to additional unique discovered
        entities and never prevents bounded provider work on an admitted
        root (HIGH-3).
        """
        policy = _policy()
        state = _state(
            analysis_disposition=AnalysisDisposition.NEEDS_MORE_EVIDENCE.value,
            budget=_small_budget(max_entities=1, max_replans=2),
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        # One root entity with max_entities=1: the root pivot is authorized.
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT
        assert decision.pivots
        assert decision.pivots[0].entity_id == _ROOT_DOMAIN_ID

    def test_sole_discovered_entity_within_capacity_is_admitted(self) -> None:
        """A discovered entity within deterministic capacity is authorized.

        With no roots and ``max_entities=1``, the sole discovered entity is
        the first (and only) unique entity in the ordered working set, so it
        is admitted and eligible (PR 21B deterministic admission); the old
        ``len(roots | discovered) >= max_entities`` global check would have
        blocked it incorrectly.
        """
        policy = _policy()
        state = _state(
            analysis_disposition=AnalysisDisposition.NEEDS_MORE_EVIDENCE.value,
            budget=_small_budget(max_entities=1, max_replans=2),
            root_entity_ids=[],
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            investigated_entity_ids=[],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT
        assert decision.pivots
        assert decision.pivots[0].entity_id == _DISCOVERED_IP_ID


class TestCoordinatorEntityBudgetAdmission:
    """Deterministic entity-budget admission semantics (PR 21B).

    ``max_entities`` is bounded admission over unique roots then discovered
    entities in first-discovery order: an already-admitted entity remains
    eligible at exact capacity while persisted overflow discoveries are
    rejected with ``ENTITY_BUDGET``.
    """

    def test_discovered_entity_at_exact_capacity_is_admitted(self) -> None:
        """U1: root + one IP with max_entities=2 admits the IP pivot."""
        policy = _policy()
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT
        assert len(decision.pivots) == 1
        assert decision.pivots[0].entity_id == _DISCOVERED_IP_ID
        assert decision.pivots[0].depth == 1
        assert any(item.entity_id == _DISCOVERED_IP_ID for item in decision.work_items)
        assert not any(
            rejection.reason is PivotRejectionReason.ENTITY_BUDGET
            for rejection in decision.rejections
        )

    def test_first_overflow_discovery_is_rejected(self) -> None:
        """U2: third unique entity beyond max_entities=2 is ENTITY_BUDGET."""
        policy = _policy()
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            discovered_entity_ids=[_IP_A_ID, _IP_B_ID],
            investigated_entity_ids=[_ROOT_DOMAIN_ID, _IP_A_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_IP_A_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
                CoordinatorEntityView(
                    entity_id=_IP_B_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.STOP
        assert decision.stop_reason is StopReason.ENTITY_BUDGET_EXHAUSTED
        overflow = next(
            rejection
            for rejection in decision.rejections
            if rejection.entity_id == _IP_B_ID
        )
        assert overflow.reason is PivotRejectionReason.ENTITY_BUDGET
        assert overflow.proposed_depth == 1

    def test_later_overflow_entity_does_not_invalidate_earlier_admitted(self) -> None:
        """U3: an admitted IP stays eligible even when an overflow IP exists.

        Ordered working set is [root, ip_a, ip_b]; ip_a is the second entity
        and therefore admitted, so it is authorized even though three
        persisted/discovered entities exist and ``max_entities=2``.
        """
        policy = _policy()
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            discovered_entity_ids=[_IP_A_ID, _IP_B_ID],
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_IP_A_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
                CoordinatorEntityView(
                    entity_id=_IP_B_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT
        assert len(decision.pivots) == 1
        assert decision.pivots[0].entity_id == _IP_A_ID
        assert decision.pivots[0].depth == 1
        assert not any(
            rejection.reason is PivotRejectionReason.ENTITY_BUDGET
            for rejection in decision.rejections
        )

    def test_multiple_roots_consume_admission_capacity(self) -> None:
        """U4: roots count toward max_entities; the discovered IP overflows."""
        policy = _policy()
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            root_entity_ids=[_ROOT_DOMAIN_ID, _DOMAIN_B_ID],
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            investigated_entity_ids=[_ROOT_DOMAIN_ID, _DOMAIN_B_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DOMAIN_B_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.STOP
        assert decision.stop_reason is StopReason.ENTITY_BUDGET_EXHAUSTED
        assert any(
            rejection.entity_id == _DISCOVERED_IP_ID
            and rejection.reason is PivotRejectionReason.ENTITY_BUDGET
            for rejection in decision.rejections
        )

    def test_duplicate_ids_do_not_consume_capacity_twice(self) -> None:
        """U5: admission capacity is based on unique entity IDs only.

        The same identity appearing through both root and discovery
        bookkeeping counts once; the real discovery IP still fits in the
        remaining capacity.
        """
        state = InvestigationState(
            investigation_id=UUID("00000000-0000-0000-0000-0000000000a1"),
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[_ROOT_DOMAIN_ID, _DOMAIN_B_ID],
            discovered_entity_ids=[_ROOT_DOMAIN_ID, _DISCOVERED_IP_ID],
            objective="Capacity counts unique IDs.",
            budget=_small_budget(max_entities=3, max_replans=2),
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            traversal=[
                EntityTraversalState(
                    entity_id=_ROOT_DOMAIN_ID,
                    first_discovery_ordinal=0,
                    minimum_depth=0,
                ),
                EntityTraversalState(
                    entity_id=_DOMAIN_B_ID,
                    first_discovery_ordinal=1,
                    minimum_depth=0,
                ),
                EntityTraversalState(
                    entity_id=_DISCOVERED_IP_ID,
                    first_discovery_ordinal=2,
                    minimum_depth=1,
                ),
            ],
        )
        admitted = CoordinatorPolicy._admitted_entity_ids(state)
        assert admitted == (_ROOT_DOMAIN_ID, _DOMAIN_B_ID, _DISCOVERED_IP_ID)

    def test_admitted_helper_truncates_at_max_entities(self) -> None:
        """The helper never returns more than max_entities unique IDs."""
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            discovered_entity_ids=[_IP_A_ID, _IP_B_ID],
        )
        admitted = CoordinatorPolicy._admitted_entity_ids(state)
        assert admitted == (_ROOT_DOMAIN_ID, _IP_A_ID)

    def test_admitted_helper_fails_closed_on_malformed_traversal(self) -> None:
        """A discovered entity without traversal metadata fails closed."""
        state = _state(discovered_entity_ids=[_DISCOVERED_IP_ID])
        malformed = state.model_copy(update={"traversal": [state.traversal[0]]})
        with pytest.raises(ValueError, match="traversal metadata"):
            CoordinatorPolicy._admitted_entity_ids(malformed)


class TestCoordinatorSuppressionAfterTimingChange:
    """Duplicate suppression must not depend on the investigated marker (PR 21B).

    Since authorization no longer marks an entity investigated, suppression
    between authorization and execution must come from pending pivot/work
    state and execution-depth bookkeeping.
    """

    def test_pending_provider_work_suppresses_reauthorization(self) -> None:
        """Case 6.1a: pending work executes first; no duplicate pivot."""
        policy = _policy()
        work = ProviderWorkItem(
            provider=SourceId.ABUSEIPDB,
            entity_id=_DISCOVERED_IP_ID,
            depth=1,
        )
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
            pending_pivots=[
                PivotRequest(
                    entity_id=_DISCOVERED_IP_ID,
                    reason="eligible_pivot",
                    depth=1,
                    status=PivotStatus.PENDING,
                )
            ],
            pending_provider_work=[work],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.EXECUTE_PROVIDER_WORK
        assert decision.pivots == ()

    def test_pending_pivot_suppresses_reauthorization(self) -> None:
        """Case 6.1b: a pending pivot blocks the same pivot when work drained.

        The entity is NOT yet investigated (authorization happened but
        selection/execution never started), so suppression must come from the
        pending pivot itself, not from the investigated marker.
        """
        policy = _policy()
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
            pending_pivots=[
                PivotRequest(
                    entity_id=_DISCOVERED_IP_ID,
                    reason="eligible_pivot",
                    depth=1,
                    status=PivotStatus.PENDING,
                )
            ],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.pivots == ()
        rejection = next(
            rejection
            for rejection in decision.rejections
            if rejection.entity_id == _DISCOVERED_IP_ID
        )
        # Suppression comes from the pending pivot itself: the candidate is
        # rejected as a DUPLICATE_PIVOT without ever being authorized again.
        assert rejection.reason is PivotRejectionReason.DUPLICATE_PIVOT

    def test_current_work_is_suppressed(self) -> None:
        """Case 6.2: selected/in-progress work is not reauthorized."""
        policy = _policy()
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            investigated_entity_ids=[_ROOT_DOMAIN_ID, _DISCOVERED_IP_ID],
            current_provider_work=ProviderWorkItem(
                provider=SourceId.ABUSEIPDB,
                entity_id=_DISCOVERED_IP_ID,
                depth=1,
            ),
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.pivots == ()

    def test_completed_work_is_suppressed(self) -> None:
        """Case 6.3: completed equivalent work is not reauthorized."""
        policy = _policy()
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            investigated_entity_ids=[_ROOT_DOMAIN_ID, _DISCOVERED_IP_ID],
            completed_provider_work=[
                ProviderWorkItem(
                    provider=SourceId.ABUSEIPDB,
                    entity_id=_DISCOVERED_IP_ID,
                    depth=1,
                )
            ],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.pivots == ()

    def test_shallower_rediscovery_remains_eligible(self) -> None:
        """Case 6.4: prior execution at depth 3 does not block depth 1."""
        policy = _policy()
        state = _state(
            budget=_small_budget(max_entities=2, max_replans=2),
            discovered_entity_ids=[_DISCOVERED_IP_ID],
            investigated_entity_ids=[_ROOT_DOMAIN_ID, _DISCOVERED_IP_ID],
        )
        entries = [
            EntityTraversalState(
                entity_id=_ROOT_DOMAIN_ID,
                first_discovery_ordinal=0,
                minimum_depth=0,
                best_investigated_depth=0,
            ),
            EntityTraversalState(
                entity_id=_DISCOVERED_IP_ID,
                first_discovery_ordinal=1,
                minimum_depth=1,
                best_investigated_depth=3,
            ),
        ]
        state = state.model_copy(update={"traversal": entries})
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT
        assert decision.pivots[0].entity_id == _DISCOVERED_IP_ID
        assert decision.pivots[0].depth == 1


class TestCoordinatorAnalysisRequest:
    """Analysis request conditions."""

    def test_new_evidence_requests_analysis(self) -> None:
        """Unanalyzed evidence triggers analysis request."""
        policy = _policy()
        state = _state(
            evidence_ids=[UUID("00000000-0000-0000-0000-0000000000e1")],
        )
        context = _context()
        decision = policy.decide(state=state, context=context)
        # No disposition and unanalyzed evidence -> request analysis.
        assert decision.action is CoordinatorAction.REQUEST_ANALYSIS

    def test_analyzed_evidence_no_new_evidence_no_analysis(self) -> None:
        """Already-analyzed evidence with no new evidence does not re-request."""
        policy = _policy()
        ev_id = UUID("00000000-0000-0000-0000-0000000000e1")
        state = _state(
            evidence_ids=[ev_id],
            analyzed_evidence_ids=[ev_id],
            analysis_disposition=AnalysisDisposition.EXHAUSTED.value,
            # All entities already investigated so no new pivots.
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
        )
        context = _context()
        decision = policy.decide(state=state, context=context)
        # Evidence was already analyzed, EXHAUSTED, no new candidate -> stop.
        assert decision.action is CoordinatorAction.STOP


class TestCoordinatorDeterministicOrder:
    """Deterministic candidate ordering and tie-breaking."""

    def test_known_entities_ordered_by_depth(self) -> None:
        """Entities are processed in depth order, root first."""
        policy = _policy()
        state = _state(
            discovered_entity_ids=[_DISCOVERED_IP_ID, _MALWARE_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
                CoordinatorEntityView(
                    entity_id=_DISCOVERED_IP_ID,
                    entity_type=EntityType.IP_ADDRESS,
                ),
                CoordinatorEntityView(
                    entity_id=_MALWARE_ID,
                    entity_type=EntityType.MALWARE,
                ),
            ]
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.AUTHORIZE_PIVOT


class TestCoordinatorWithDisposition:
    """Coordinator behavior given a specific analysis disposition in context."""

    def test_exhausted_with_no_candidates_stops(self) -> None:
        """EXHAUSTED disposition with no eligible candidates -> stop."""
        policy = _policy()
        state = _state(
            investigated_entity_ids=[_ROOT_DOMAIN_ID],
        )
        context = _context(
            entities=[
                CoordinatorEntityView(
                    entity_id=_ROOT_DOMAIN_ID,
                    entity_type=EntityType.DOMAIN,
                ),
            ],
            assessment=Assessment(
                investigation_id=state.investigation_id,
                verdict=Verdict.INCONCLUSIVE,
                confidence=AssessmentConfidence.LOW,
                summary="Inconclusive.",
                analyzed_evidence_ids=(),
                limitations=("No evidence available.",),
            ),
        )
        decision = policy.decide(state=state, context=context)
        assert decision.action is CoordinatorAction.STOP
        assert decision.stop_reason is StopReason.NO_ELIGIBLE_PIVOTS
