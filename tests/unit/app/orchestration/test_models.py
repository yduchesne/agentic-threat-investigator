# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for PR 19A typed orchestration models and serialization."""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-few-public-methods

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationError,
    InvestigationState,
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
