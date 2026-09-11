# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for PR 19A typed orchestration models and serialization."""

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.orchestration.models import (
    apply_work_selection,
    authorize_pivot,
    record_provider_outcome,
    select_provider_work,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    EntityTraversalState,
    InvestigationError,
    InvestigationState,
    PivotRequest,
    PivotStatus,
    ProviderExecutionOutcome,
    ProviderExecutionStatus,
    ProviderWorkItem,
)
from tests.support.orchestration_fixtures import (
    SCENARIO_DOMAIN_ID,
    SCENARIO_IP_ID,
    scenario_dns_outcome,
    scenario_dns_work_item,
    scenario_initial_state,
    scenario_investigation_state,
    scenario_rdap_work_item,
)


class TestProviderWorkItem:
    """Validation tests for the typed provider work item."""

    def test_valid_work_item(self) -> None:
        work_item = ProviderWorkItem(
            provider=SourceId.GOOGLE_PUBLIC_DNS,
            entity_id=SCENARIO_DOMAIN_ID,
            depth=0,
        )
        assert work_item.provider is SourceId.GOOGLE_PUBLIC_DNS
        assert work_item.entity_id == SCENARIO_DOMAIN_ID
        assert work_item.depth == 0

    def test_negative_depth_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ProviderWorkItem(
                provider=SourceId.GOOGLE_PUBLIC_DNS,
                entity_id=SCENARIO_DOMAIN_ID,
                depth=-1,
            )

    def test_unexpected_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ProviderWorkItem(
                provider=SourceId.GOOGLE_PUBLIC_DNS,
                entity_id=SCENARIO_DOMAIN_ID,
                depth=0,
                metadata={"unexpected": True},  # type: ignore[call-arg]
            )

    def test_work_item_is_hashable(self) -> None:
        work_item = scenario_dns_work_item()
        duplicate = scenario_dns_work_item()
        assert work_item == duplicate
        assert hash(work_item) == hash(duplicate)
        assert len({work_item, duplicate}) == 1


class TestProviderExecutionOutcome:
    """Validation and serialization tests for execution outcomes."""

    def test_outcome_json_serialization(self) -> None:
        outcome = scenario_dns_outcome()
        payload = outcome.model_dump(mode="json")
        assert payload["status"] == "succeeded"
        assert payload["work_item"]["provider"] == "urn:ati:source:google_public_dns"
        assert payload["discovered_entity_ids"] == [str(SCENARIO_IP_ID)]
        restored = ProviderExecutionOutcome.model_validate(payload)
        assert restored == outcome

    def test_failed_outcome_carries_typed_error(self) -> None:
        error = InvestigationError(
            source="urn:ati:source:rdap",
            code="provider_failure",
            message="RDAP lookup failed",
            recoverable=True,
        )
        outcome = ProviderExecutionOutcome(
            work_item=scenario_dns_work_item(),
            status=ProviderExecutionStatus.FAILED,
            error=error,
        )
        assert outcome.error == error
        restored = ProviderExecutionOutcome.model_validate(
            outcome.model_dump(mode="json")
        )
        assert restored.error == error


class TestStateSerialization:
    """Checkpoint-compatibility tests for the extended orchestration state."""

    def test_state_json_round_trip(self) -> None:
        state = scenario_initial_state()
        payload = state.model_dump(mode="json")
        reconstructed = InvestigationState.model_validate(payload)
        assert reconstructed == state
        assert reconstructed.pending_provider_work == [
            scenario_dns_work_item(),
            scenario_rdap_work_item(),
        ]
        assert reconstructed.current_provider_work is None
        assert reconstructed.last_provider_outcome is None


def _authorized_ip_state() -> InvestigationState:
    """Return an authorized-but-not-selected IP pivot state (PR 21B).

    The root DOMAIN is not yet investigated here; callers that need the root
    exhausted must build on this state. The IP discovery carries a traversal
    entry at depth 1 so selection can record ``best_investigated_depth``.
    """
    base = scenario_investigation_state().model_copy(
        update={
            "discovered_entity_ids": [SCENARIO_IP_ID],
            "traversal": [
                EntityTraversalState(
                    entity_id=SCENARIO_DOMAIN_ID,
                    first_discovery_ordinal=0,
                    minimum_depth=0,
                ),
                EntityTraversalState(
                    entity_id=SCENARIO_IP_ID,
                    first_discovery_ordinal=1,
                    minimum_depth=1,
                ),
            ],
        }
    )
    return authorize_pivot(
        base,
        PivotRequest(entity_id=SCENARIO_IP_ID, reason="eligible_pivot", depth=1),
        [
            ProviderWorkItem(
                provider=SourceId.ABUSEIPDB,
                entity_id=SCENARIO_IP_ID,
                depth=1,
            )
        ],
    )


class TestInvestigatedTiming:
    """investigated_entity_ids lifecycle: authorization vs execution (PR 21B).

    Authorization only enqueues; the entity becomes investigated when its
    provider work is actually selected for execution.
    """

    def test_authorization_does_not_mark_entity_investigated(self) -> None:
        """Case 4.1: authorize_pivot leaves the entity uninvestigated."""
        state = _authorized_ip_state()
        assert [pivot.entity_id for pivot in state.pending_pivots] == [SCENARIO_IP_ID]
        assert state.pending_provider_work == [
            ProviderWorkItem(
                provider=SourceId.ABUSEIPDB,
                entity_id=SCENARIO_IP_ID,
                depth=1,
            )
        ]
        assert SCENARIO_IP_ID not in state.investigated_entity_ids
        entry = next(
            entry for entry in state.traversal if entry.entity_id == SCENARIO_IP_ID
        )
        assert entry.best_investigated_depth is None
        # Authorization alone consumes no provider/replan budget.
        assert state.budget.provider_calls_used == 0
        assert state.budget.replans_used == 0

    def test_selecting_provider_work_marks_entity_investigated(self) -> None:
        """Case 4.2: selecting work marks the entity investigated exactly once."""
        authorized = _authorized_ip_state()
        selected = select_provider_work(authorized)
        applied = apply_work_selection(selected)
        assert applied.current_provider_work == ProviderWorkItem(
            provider=SourceId.ABUSEIPDB,
            entity_id=SCENARIO_IP_ID,
            depth=1,
        )
        assert applied.investigated_entity_ids == [SCENARIO_IP_ID]
        entry = next(
            entry for entry in applied.traversal if entry.entity_id == SCENARIO_IP_ID
        )
        assert entry.best_investigated_depth == 1
        pivot = next(
            pivot
            for pivot in applied.pending_pivots
            if pivot.entity_id == SCENARIO_IP_ID
        )
        assert pivot.status is PivotStatus.IN_PROGRESS
        # Selection alone consumes no provider/replan budget: the counter
        # increments only when the provider outcome is actually recorded.
        assert applied.budget.provider_calls_used == 0
        assert applied.budget.replans_used == 0

    def test_second_provider_for_same_pivot_does_not_duplicate_id(self) -> None:
        """Case 4.3: later work for the same entity/depth stays deduplicated."""
        base = scenario_investigation_state().model_copy(
            update={
                "discovered_entity_ids": [SCENARIO_IP_ID],
                "traversal": [
                    EntityTraversalState(
                        entity_id=SCENARIO_DOMAIN_ID,
                        first_discovery_ordinal=0,
                        minimum_depth=0,
                    ),
                    EntityTraversalState(
                        entity_id=SCENARIO_IP_ID,
                        first_discovery_ordinal=1,
                        minimum_depth=1,
                    ),
                ],
            }
        )
        abuseipdb = ProviderWorkItem(
            provider=SourceId.ABUSEIPDB,
            entity_id=SCENARIO_IP_ID,
            depth=1,
        )
        threatfox = ProviderWorkItem(
            provider=SourceId.THREATFOX,
            entity_id=SCENARIO_IP_ID,
            depth=1,
        )
        authorized = authorize_pivot(
            base,
            PivotRequest(entity_id=SCENARIO_IP_ID, reason="eligible_pivot", depth=1),
            [abuseipdb, threatfox],
        )
        first = apply_work_selection(select_provider_work(authorized))
        assert first.investigated_entity_ids == [SCENARIO_IP_ID]
        outcome = record_provider_outcome(
            first,
            ProviderExecutionOutcome(
                work_item=abuseipdb,
                status=ProviderExecutionStatus.SUCCEEDED,
            ),
        )
        second = apply_work_selection(select_provider_work(outcome))
        assert second.current_provider_work == threatfox
        assert second.investigated_entity_ids == [SCENARIO_IP_ID]

    def test_authorization_without_execution_remains_uninvestigated(self) -> None:
        """Case 4.4: crash/resume between authorization and selection."""
        state = _authorized_ip_state()
        assert state.current_provider_work is None
        assert SCENARIO_IP_ID not in state.investigated_entity_ids
        assert all(entry.best_investigated_depth is None for entry in state.traversal)

    def test_shallower_execution_updates_best_depth(self) -> None:
        """Case 4.5: executed at depth 3, selected at depth 1 -> best depth 1."""
        work = ProviderWorkItem(
            provider=SourceId.ABUSEIPDB,
            entity_id=SCENARIO_IP_ID,
            depth=1,
        )
        state = scenario_investigation_state().model_copy(
            update={
                "discovered_entity_ids": [SCENARIO_IP_ID],
                "investigated_entity_ids": [SCENARIO_IP_ID],
                "pending_pivots": [
                    PivotRequest(
                        entity_id=SCENARIO_IP_ID,
                        reason="eligible_pivot",
                        depth=1,
                        status=PivotStatus.PENDING,
                    )
                ],
                "pending_provider_work": [work],
                "traversal": [
                    EntityTraversalState(
                        entity_id=SCENARIO_DOMAIN_ID,
                        first_discovery_ordinal=0,
                        minimum_depth=0,
                    ),
                    EntityTraversalState(
                        entity_id=SCENARIO_IP_ID,
                        first_discovery_ordinal=1,
                        minimum_depth=1,
                        best_investigated_depth=3,
                    ),
                ],
            }
        )
        applied = apply_work_selection(select_provider_work(state))
        entry = next(
            entry for entry in applied.traversal if entry.entity_id == SCENARIO_IP_ID
        )
        assert entry.best_investigated_depth == 1
        assert applied.investigated_entity_ids == [SCENARIO_IP_ID]
