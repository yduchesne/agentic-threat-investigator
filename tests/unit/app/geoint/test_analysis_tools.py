# SPDX-License-Identifier: AGPL-3.0-only
"""G26F-T matrix: bounded GEOINT analysis tool facade (PR 26F).

Proves the facade delegates exactly to the existing ``GeointQueryService``,
clamps page sizes, never drains cursors, reports continuation honestly, and
propagates cancellation. The fake query service replaces only the read
boundary; no SQL/PostGIS participates.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.geoint.analysis_tools import (
    GeointAnalysisTools,
)
from agentic_threat_investigator.app.query.geoint import (
    GeointEntityQuery,
    GeointObservationDetail,
    GeointObservationQuery,
    GeointSummaryQuery,
)
from agentic_threat_investigator.domain.entities import EntityType
from tests.support.geoint_fixtures import (
    FakeGeointQueryService,
    entity_location_item,
    observation_item,
    zero_summary,
)


def make_tools(
    service: FakeGeointQueryService, *, max_observations_per_entity: int = 25
) -> GeointAnalysisTools:
    """Build one facade over the fake query service with a small bound."""
    return GeointAnalysisTools(
        service, max_observations_per_entity=max_observations_per_entity
    )


@pytest.mark.asyncio
async def test_g26f_t01_summary_delegates_exact_investigation_query() -> None:
    """G26F-T01 the summary delegates the exact Investigation-scoped query."""
    investigation_id = uuid4()
    service = FakeGeointQueryService(summary_result=zero_summary())
    tools = make_tools(service)

    result = await tools.summary(investigation_id)

    assert result is service.summary_result
    assert service.summary_calls == [
        GeointSummaryQuery(investigation_id=investigation_id)
    ]


@pytest.mark.asyncio
async def test_g26f_t02_current_entity_delegates_exact_query() -> None:
    """G26F-T02 the current-Entity read delegates the exact scoped query."""
    investigation_id = uuid4()
    entity_id = uuid4()
    item = entity_location_item(entity_id=entity_id)
    service = FakeGeointQueryService(current_by_entity={entity_id: item})
    tools = make_tools(service)

    result = await tools.current_for_entity(investigation_id, entity_id)

    assert result is item
    assert service.entity_calls == [
        GeointEntityQuery(investigation_id=investigation_id, entity_id=entity_id)
    ]


@pytest.mark.asyncio
async def test_g26f_t03_history_returns_one_bounded_page() -> None:
    """G26F-T03 history returns exactly one bounded page."""
    investigation_id = uuid4()
    entity_id = uuid4()
    observations = [
        observation_item(entity_id=entity_id, evidence_id=uuid4()) for _ in range(3)
    ]
    service = FakeGeointQueryService(
        history_by_entity={entity_id: observations},
        current_by_entity={entity_id: entity_location_item(entity_id=entity_id)},
    )
    tools = make_tools(service, max_observations_per_entity=2)

    result = await tools.history_for_entity(investigation_id, entity_id, limit=7)

    assert [item.observation_id for item in result.items] == [
        item.observation_id for item in observations[:2]
    ]
    assert len(service.history_calls) == 1
    assert service.history_calls[0].limit == 2
    assert service.history_calls[0].cursor is None


@pytest.mark.asyncio
async def test_g26f_t04_history_has_more_without_second_query() -> None:
    """G26F-T04 has_more=true when a continuation exists; no second query."""
    investigation_id = uuid4()
    entity_id = uuid4()
    service = FakeGeointQueryService(
        history_by_entity={
            entity_id: [
                observation_item(entity_id=entity_id, evidence_id=uuid4())
                for _ in range(4)
            ]
        },
        current_by_entity={entity_id: entity_location_item(entity_id=entity_id)},
    )
    tools = make_tools(service, max_observations_per_entity=3)

    result = await tools.history_for_entity(investigation_id, entity_id, limit=3)

    assert result.has_more is True
    assert len(result.items) == 3
    assert len(service.history_calls) == 1
    # The continuation cursor must never be exposed to the model.
    assert "cursor" not in result.model_dump()


@pytest.mark.asyncio
async def test_g26f_t05_location_exact_containment_flag_false() -> None:
    """G26F-T05 an exact Location selection reports containment=false."""
    investigation_id = uuid4()
    location_id = uuid4()
    service = FakeGeointQueryService(
        location_entities={
            (location_id, False): [entity_location_item(entity_id=uuid4())]
        }
    )
    tools = make_tools(service)

    result = await tools.entities_in_location(
        investigation_id, location_id, include_contained=False, limit=5
    )

    assert result.containment_requested is False
    assert result.containment_applied is False
    assert len(service.location_entity_calls) == 1
    assert service.location_entity_calls[0].include_contained is False


@pytest.mark.asyncio
async def test_g26f_t06_location_contained_containment_flag_true() -> None:
    """G26F-T06 a contained selection reports containment=true honestly."""
    investigation_id = uuid4()
    location_id = uuid4()
    service = FakeGeointQueryService(
        location_entities={
            (location_id, True): [entity_location_item(entity_id=uuid4())]
        }
    )
    tools = make_tools(service)

    result = await tools.entities_in_location(
        investigation_id, location_id, include_contained=True, limit=5
    )

    assert result.containment_requested is True
    assert result.containment_applied is True
    assert service.location_entity_calls[0].include_contained is True


@pytest.mark.asyncio
async def test_g26f_t06b_location_observations_delegates_containment() -> None:
    """G26F-T06b the Location-observations read delegates exactly."""
    investigation_id = uuid4()
    location_id = uuid4()
    entity_id = uuid4()
    service = FakeGeointQueryService(
        location_observations={
            (location_id, True): [
                observation_item(entity_id=entity_id, evidence_id=uuid4())
            ]
        }
    )
    tools = make_tools(service)

    result = await tools.observations_in_location(
        investigation_id, location_id, include_contained=True, limit=5
    )

    assert len(result.items) == 1
    assert result.containment_requested is True
    assert result.containment_applied is True
    assert len(service.location_observation_calls) == 1
    assert service.location_observation_calls[0].location_id == location_id
    assert service.location_observation_calls[0].include_contained is True


@pytest.mark.asyncio
async def test_g26f_t07_observation_detail_exact_scoped_lookup() -> None:
    """G26F-T07 the observation detail read is the exact scoped lookup."""
    investigation_id = uuid4()
    observation_id = uuid4()
    entity_id = uuid4()
    detail = GeointObservationDetail(
        observation=observation_item(entity_id=entity_id, evidence_id=uuid4()),
        entity_type=EntityType.IP_ADDRESS,
        entity_value="203.0.113.10",
        display_name=None,
    )
    service = FakeGeointQueryService(observation_details={observation_id: detail})
    tools = make_tools(service)

    result = await tools.observation(investigation_id, observation_id)

    assert result is detail
    assert service.observation_calls == [
        GeointObservationQuery(
            investigation_id=investigation_id, observation_id=observation_id
        )
    ]


@pytest.mark.asyncio
async def test_g26f_t07b_unknown_observation_detail_is_none() -> None:
    """G26F-T07b an unknown scoped detail fails closed with ``None``."""
    investigation_id = uuid4()
    service = FakeGeointQueryService(observation_details={})
    tools = make_tools(service)

    result = await tools.observation(investigation_id, uuid4())

    assert result is None
    assert len(service.observation_calls) == 1


@pytest.mark.asyncio
async def test_g26f_t08_requested_limit_over_bound_is_clamped() -> None:
    """G26F-T08 a requested page size over the bound is clamped, not honored."""
    investigation_id = uuid4()
    entity_id = uuid4()
    observations = [
        observation_item(entity_id=entity_id, evidence_id=uuid4()) for _ in range(5)
    ]
    service = FakeGeointQueryService(
        history_by_entity={entity_id: observations},
        current_by_entity={entity_id: entity_location_item(entity_id=entity_id)},
    )
    tools = make_tools(service, max_observations_per_entity=2)

    result = await tools.history_for_entity(investigation_id, entity_id, limit=500)

    assert len(result.items) == 2
    assert service.history_calls[0].limit == 2
    assert result.has_more is True


@pytest.mark.asyncio
async def test_g26f_t09_cancellation_propagates_unchanged() -> None:
    """G26F-T09 cancellation propagates unchanged through the facade."""
    investigation_id = uuid4()
    service = FakeGeointQueryService(fail=asyncio.CancelledError())
    tools = make_tools(service)

    with pytest.raises(asyncio.CancelledError):
        await tools.summary(investigation_id)


@pytest.mark.asyncio
async def test_g26f_t10_facade_has_no_sql_or_postgis_surface() -> None:
    """G26F-T10 the facade performs no mutation and exposes no SQL surface.

    The module imports only the application query contracts and the domain;
    the object graph carries no SQLAlchemy/PostGIS attribute.
    """
    import inspect

    import agentic_threat_investigator.app.geoint.analysis_tools as module

    source = inspect.getsource(module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
    assert "import postgis" not in source
    assert "ST_" not in source
    service = FakeGeointQueryService(summary_result=zero_summary())
    tools = make_tools(service)
    # The public surface is read-only: no insert/update/delete/commit method.
    public = {name for name in dir(tools) if not name.startswith("_")}
    assert not {"insert", "update", "delete", "commit", "rollback"} & public


def test_facade_constructor_validates_page_bound() -> None:
    """Direct construction cannot bypass the page-bound ceiling."""
    from agentic_threat_investigator.app.geoint.analysis_tools import (
        _MAX_OBSERVATIONS_PER_ENTITY_CEILING,
    )

    service = FakeGeointQueryService(summary_result=zero_summary())
    for invalid in (0, -1, _MAX_OBSERVATIONS_PER_ENTITY_CEILING + 1):
        with pytest.raises(ValueError, match="max_observations_per_entity"):
            GeointAnalysisTools(service, max_observations_per_entity=invalid)


@pytest.mark.asyncio
async def test_aclose_invokes_close_hook_exactly_once() -> None:
    """The close hook releases the bound resource exactly once."""
    closed: list[str] = []

    async def close() -> None:
        """Record one close invocation."""
        closed.append("closed")

    tools = GeointAnalysisTools(
        FakeGeointQueryService(summary_result=zero_summary()), on_close=close
    )
    await tools.aclose()
    await tools.aclose()
    assert closed == ["closed"]
