# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Evaluation-only query tracing seam unit tests (PR 26G).

The recording wrapper delegates every read unchanged and records the exact
operation, scope, bounds, and continuation state the delivered
``GeointAnalysisTools`` facade performs.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from agentic_threat_investigator.app.query.geoint import (
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointObservationQuery,
    GeointSummaryQuery,
)
from agentic_threat_investigator.evaluation.geoint.models import (
    GeointToolOperation,
)
from agentic_threat_investigator.evaluation.geoint.tracing import (
    RecordingGeointQueryService,
)
from tests.support.geoint_fixtures import (
    FakeGeointQueryService,
    location_ref,
    observation_item,
    zero_summary,
)

pytestmark = pytest.mark.asyncio


async def test_records_summary_and_entity_reads() -> None:
    """Summary and Entity reads are recorded with their exact scope."""
    investigation_id = uuid4()
    entity_id = uuid4()
    delegate = FakeGeointQueryService(summary_result=zero_summary())
    wrapper = RecordingGeointQueryService(delegate)

    await wrapper.summary(GeointSummaryQuery(investigation_id=investigation_id))
    await wrapper.get_entity(
        GeointEntityQuery(investigation_id=investigation_id, entity_id=entity_id)
    )

    [summary_record, entity_record] = wrapper.records
    assert summary_record.operation is GeointToolOperation.SUMMARY
    assert summary_record.investigation_id == investigation_id
    assert entity_record.operation is GeointToolOperation.CURRENT_FOR_ENTITY
    assert entity_record.entity_id == entity_id


async def test_records_history_page_with_continuation_state() -> None:
    """A bounded history page records limit, cursor absence, and has_more."""
    investigation_id = uuid4()
    entity_id = uuid4()
    delegate = FakeGeointQueryService(
        history_by_entity={
            entity_id: [
                observation_item(entity_id=entity_id, evidence_id=uuid4())
                for _ in range(3)
            ]
        }
    )
    wrapper = RecordingGeointQueryService(delegate)

    page = await wrapper.list_entity_observations(
        GeointEntityObservationListQuery(
            investigation_id=investigation_id,
            entity_id=entity_id,
            limit=2,
            cursor=None,
        )
    )
    assert len(page.items) == 2
    [record] = wrapper.records
    assert record.operation is GeointToolOperation.HISTORY_FOR_ENTITY
    assert record.limit == 2
    assert record.cursor_requested is False
    assert record.has_more is True


async def test_records_observation_detail_identity() -> None:
    """Exact observation reads record the requested observation identity."""
    investigation_id = uuid4()
    observation_id = uuid4()
    delegate = FakeGeointQueryService()
    wrapper = RecordingGeointQueryService(delegate)

    await wrapper.get_observation(
        GeointObservationQuery(
            investigation_id=investigation_id, observation_id=observation_id
        )
    )
    [record] = wrapper.records
    assert record.operation is GeointToolOperation.OBSERVATION_DETAIL
    assert record.observation_id == observation_id


async def test_delegates_failures_unchanged() -> None:
    """Typed failures and cancellation propagate unchanged through the wrapper."""
    investigation_id = uuid4()
    failure = RuntimeError("delegate failure")
    delegate = FakeGeointQueryService(fail=failure)
    wrapper = RecordingGeointQueryService(delegate)
    with pytest.raises(RuntimeError, match="delegate failure"):
        await wrapper.summary(GeointSummaryQuery(investigation_id=investigation_id))
    # The failed read is still recorded (the record reflects the attempt).
    assert len(wrapper.records) == 1


async def test_location_reads_preserve_containment_flags() -> None:
    """Location reads record include_contained and containment application."""
    investigation_id = uuid4()
    location_id = uuid4()
    delegate = FakeGeointQueryService()
    wrapper = RecordingGeointQueryService(delegate)
    from agentic_threat_investigator.app.query.geoint import (
        GeointLocationEntityListQuery,
    )

    await wrapper.list_location_entities(
        GeointLocationEntityListQuery(
            investigation_id=investigation_id,
            location_id=location_id,
            include_contained=True,
            limit=5,
            cursor=None,
        )
    )
    [record] = wrapper.records
    assert record.operation is GeointToolOperation.ENTITIES_IN_LOCATION
    assert record.location_id == location_id
    assert record.include_contained is True
    assert record.cursor_requested is False


def test_location_ref_builder_omits_coordinates_by_default() -> None:
    """The unit fixture reference omits representative coordinates."""
    ref = location_ref()
    assert ref.latitude is None and ref.longitude is None
