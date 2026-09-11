# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Bookkeeping tests for extended provider-execution outcome IDs (PR 19B)."""

from uuid import UUID

import pytest

from agentic_threat_investigator.app.orchestration.models import (
    enqueue_provider_work,
    record_provider_outcome,
    select_provider_work,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    ProviderExecutionOutcome,
    ProviderExecutionStatus,
    ProviderWorkItem,
)
from tests.support.orchestration_fixtures import (
    scenario_dns_work_item,
    scenario_investigation_state,
)

_EVIDENCE_A = UUID("00000000-0000-0000-0000-0000000000e1")
_EVIDENCE_B = UUID("00000000-0000-0000-0000-0000000000e2")
_EVIDENCE_C = UUID("00000000-0000-0000-0000-0000000000e5")
_RELATIONSHIP_A = UUID("00000000-0000-0000-0000-0000000000e3")
_RELATIONSHIP_B = UUID("00000000-0000-0000-0000-0000000000e4")
_DISCOVERY_A = UUID("00000000-0000-0000-0000-0000000001d1")
_DISCOVERY_B = UUID("00000000-0000-0000-0000-0000000001d2")


def _outcome(
    *,
    evidence_ids: tuple[UUID, ...] = (),
    relationship_ids: tuple[UUID, ...] = (),
    discovered_entity_ids: tuple[UUID, ...] = (),
    work_item: ProviderWorkItem | None = None,
) -> ProviderExecutionOutcome:
    """Build a succeeded outcome with the supplied operational IDs."""
    return ProviderExecutionOutcome(
        work_item=work_item or scenario_dns_work_item(),
        status=ProviderExecutionStatus.SUCCEEDED,
        evidence_ids=evidence_ids,
        discovered_entity_ids=discovered_entity_ids,
        relationship_ids=relationship_ids,
    )


def _rdap_work_item() -> ProviderWorkItem:
    """Return a second work item for a distinct provider."""
    return ProviderWorkItem(
        provider=SourceId.RDAP,
        entity_id=UUID("00000000-0000-0000-0000-0000000000d1"),
        depth=0,
    )


@pytest.mark.asyncio
async def test_evidence_ids_merge_into_state_first_seen_order() -> None:
    """Evidence and relationship IDs merge deterministically into state."""
    state = select_provider_work(
        enqueue_provider_work(
            scenario_investigation_state(), [scenario_dns_work_item()]
        )
    )
    recorded = record_provider_outcome(
        state,
        _outcome(
            evidence_ids=(_EVIDENCE_A, _EVIDENCE_B),
            relationship_ids=(_RELATIONSHIP_A, _RELATIONSHIP_B),
            discovered_entity_ids=(_DISCOVERY_A, _DISCOVERY_B),
        ),
    )
    assert list(recorded.evidence_ids) == [_EVIDENCE_A, _EVIDENCE_B]
    assert list(recorded.relationship_ids) == [_RELATIONSHIP_A, _RELATIONSHIP_B]
    assert list(recorded.discovered_entity_ids) == [_DISCOVERY_A, _DISCOVERY_B]


@pytest.mark.asyncio
async def test_relationship_and_evidence_ids_deduplicate_across_work() -> None:
    """Repeated IDs across work items keep the first-seen position only."""
    initial = enqueue_provider_work(
        scenario_investigation_state(),
        [scenario_dns_work_item(), _rdap_work_item()],
    )
    first = record_provider_outcome(
        select_provider_work(initial),
        _outcome(
            evidence_ids=(_EVIDENCE_A,),
            relationship_ids=(_RELATIONSHIP_A,),
            discovered_entity_ids=(_DISCOVERY_A,),
        ),
    )
    second = record_provider_outcome(
        select_provider_work(first),
        _outcome(
            work_item=_rdap_work_item(),
            evidence_ids=(_EVIDENCE_B, _EVIDENCE_A),
            relationship_ids=(_RELATIONSHIP_B,),
            discovered_entity_ids=(_DISCOVERY_B, _DISCOVERY_A),
        ),
    )
    assert list(second.evidence_ids) == [_EVIDENCE_A, _EVIDENCE_B]
    assert list(second.relationship_ids) == [_RELATIONSHIP_A, _RELATIONSHIP_B]
    assert list(second.discovered_entity_ids) == [_DISCOVERY_A, _DISCOVERY_B]


@pytest.mark.asyncio
async def test_provider_counter_once_per_work_item_regardless_of_evidence() -> None:
    """Three persisted Evidence observations still consume one provider call."""
    state = enqueue_provider_work(
        scenario_investigation_state(), [scenario_dns_work_item()]
    )
    recorded = record_provider_outcome(
        select_provider_work(state),
        _outcome(evidence_ids=(_EVIDENCE_A, _EVIDENCE_B, _EVIDENCE_C)),
    )
    assert recorded.budget.provider_calls_used == 1
