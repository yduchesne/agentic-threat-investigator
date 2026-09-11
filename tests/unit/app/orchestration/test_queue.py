# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for deterministic provider-work queue mechanics (PR 19A)."""

import pytest

from agentic_threat_investigator.app.orchestration.models import (
    enqueue_provider_work,
    record_provider_outcome,
    select_next_provider_work,
    select_provider_work,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationError,
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
    scenario_rdap_outcome,
    scenario_rdap_work_item,
)

ABUSEIPDB_WORK = ProviderWorkItem(
    provider=SourceId.ABUSEIPDB, entity_id=SCENARIO_DOMAIN_ID, depth=0
)


class TestEnqueueProviderWork:
    """Deterministic queue insertion and duplicate suppression."""

    def test_enqueue_one_item(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(), [scenario_dns_work_item()]
        )
        assert state.pending_provider_work == [scenario_dns_work_item()]

    def test_preserves_fifo_order(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(),
            [scenario_dns_work_item(), scenario_rdap_work_item()],
        )
        assert state.pending_provider_work == [
            scenario_dns_work_item(),
            scenario_rdap_work_item(),
        ]

    def test_duplicate_pending_item_ignored(self) -> None:
        state = scenario_investigation_state()
        state = enqueue_provider_work(state, [scenario_dns_work_item()])
        state = enqueue_provider_work(state, [scenario_dns_work_item()])
        assert state.pending_provider_work == [scenario_dns_work_item()]

    def test_completed_item_not_reenqueued(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(), [scenario_dns_work_item()]
        )
        outcome = scenario_dns_outcome()
        state = select_provider_work(state)
        state = record_provider_outcome(state, outcome)
        state = enqueue_provider_work(state, [scenario_dns_work_item()])
        assert state.pending_provider_work == []
        assert state.completed_provider_work == [scenario_dns_work_item()]

    def test_does_not_mutate_input_work_items(self) -> None:
        work_items = [scenario_dns_work_item(), scenario_rdap_work_item()]
        state = enqueue_provider_work(scenario_investigation_state(), work_items)
        state = enqueue_provider_work(state, [scenario_dns_work_item()])
        assert len(work_items) == 2
        assert len(state.pending_provider_work) == 2


class TestSelectNextProviderWork:
    """FIFO selection tests."""

    def test_selects_first_pending_item(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(),
            [scenario_dns_work_item(), scenario_rdap_work_item()],
        )
        assert select_next_provider_work(state) == scenario_dns_work_item()

    def test_empty_queue_selects_nothing(self) -> None:
        assert select_next_provider_work(scenario_investigation_state()) is None

    def test_select_provider_work_sets_current(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(),
            [scenario_dns_work_item(), scenario_rdap_work_item()],
        )
        state = select_provider_work(state)
        assert state.current_provider_work == scenario_dns_work_item()
        assert state.pending_provider_work == [
            scenario_dns_work_item(),
            scenario_rdap_work_item(),
        ]


class TestRecordProviderOutcome:
    """Outcome bookkeeping tests."""

    def test_record_success_moves_work_pending_to_completed(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(), [scenario_dns_work_item()]
        )
        state = select_provider_work(state)
        state = record_provider_outcome(state, scenario_dns_outcome())
        assert state.pending_provider_work == []
        assert state.completed_provider_work == [scenario_dns_work_item()]

    def test_record_failure_also_moves_work_pending_to_completed(self) -> None:
        state = enqueue_provider_work(scenario_investigation_state(), [ABUSEIPDB_WORK])
        state = select_provider_work(state)
        outcome = ProviderExecutionOutcome(
            work_item=ABUSEIPDB_WORK,
            status=ProviderExecutionStatus.FAILED,
            error=InvestigationError(
                source="urn:ati:source:abuseipdb",
                code="provider_failure",
                message="provider unavailable",
                recoverable=True,
            ),
        )
        state = record_provider_outcome(state, outcome)
        assert state.pending_provider_work == []
        assert state.completed_provider_work == [ABUSEIPDB_WORK]
        assert state.last_provider_outcome is not None
        assert state.last_provider_outcome.status is ProviderExecutionStatus.FAILED

    def test_provider_counter_increments_exactly_once(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(), [scenario_dns_work_item()]
        )
        state = select_provider_work(state)
        before = state.budget.provider_calls_used
        state = record_provider_outcome(state, scenario_dns_outcome())
        assert state.budget.provider_calls_used == before + 1

    def test_discovered_ids_merge_without_duplicates_in_first_seen_order(self) -> None:
        state = scenario_investigation_state()
        state = state.model_copy(update={"discovered_entity_ids": [SCENARIO_IP_ID]})
        state = enqueue_provider_work(state, [scenario_dns_work_item()])
        state = select_provider_work(state)
        duplicate_discovery = ProviderExecutionOutcome(
            work_item=scenario_dns_work_item(),
            status=ProviderExecutionStatus.SUCCEEDED,
            discovered_entity_ids=(SCENARIO_IP_ID, SCENARIO_DOMAIN_ID),
        )
        state = record_provider_outcome(state, duplicate_discovery)
        assert state.discovered_entity_ids == [SCENARIO_IP_ID, SCENARIO_DOMAIN_ID]

    def test_error_outcome_appends_one_typed_error(self) -> None:
        state = enqueue_provider_work(scenario_investigation_state(), [ABUSEIPDB_WORK])
        state = select_provider_work(state)
        error = InvestigationError(
            source="urn:ati:source:abuseipdb",
            code="provider_failure",
            message="provider unavailable",
            recoverable=True,
        )
        state = record_provider_outcome(
            state,
            ProviderExecutionOutcome(
                work_item=ABUSEIPDB_WORK,
                status=ProviderExecutionStatus.FAILED,
                error=error,
            ),
        )
        assert state.errors == [error]

    def test_current_work_cleared_after_recording_outcome(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(), [scenario_dns_work_item()]
        )
        state = select_provider_work(state)
        state = record_provider_outcome(state, scenario_dns_outcome())
        assert state.current_provider_work is None
        assert state.last_provider_outcome == scenario_dns_outcome()

    def test_recording_mismatched_outcome_rejected(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(), [scenario_dns_work_item()]
        )
        state = select_provider_work(state)
        with pytest.raises(ValueError, match="current provider work item"):
            record_provider_outcome(state, scenario_rdap_outcome())

    def test_recording_twice_rejected(self) -> None:
        state = enqueue_provider_work(
            scenario_investigation_state(), [scenario_dns_work_item()]
        )
        state = select_provider_work(state)
        state = record_provider_outcome(state, scenario_dns_outcome())
        # Force a re-recording attempt with the outcome still attached to the
        # work item, as a defensive-invariant check on the helper.
        replay_state = state.model_copy(
            update={"current_provider_work": scenario_dns_work_item()}
        )
        with pytest.raises(ValueError, match="already completed"):
            record_provider_outcome(replay_state, scenario_dns_outcome())


class TestScenarioMechanics:
    """End-to-end helper mechanics using the PR 19A scenario."""

    def test_scenario_queue_mechanics(self) -> None:
        state = scenario_initial_state()
        assert [item.provider for item in state.pending_provider_work] == [
            SourceId.GOOGLE_PUBLIC_DNS,
            SourceId.RDAP,
        ]
        first = select_next_provider_work(state)
        assert first is not None and first.provider is SourceId.GOOGLE_PUBLIC_DNS
        state = select_provider_work(state)
        state = record_provider_outcome(state, scenario_dns_outcome())
        assert state.discovered_entity_ids == [SCENARIO_IP_ID]
        assert state.pending_provider_work == [scenario_rdap_work_item()]
