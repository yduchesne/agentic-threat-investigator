# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic PR 26F unit-test fixtures: fake query service and builders.

The fake replaces only the ``GeointQueryService`` read boundary; unit tests
of the analysis facade, the context policy, and the Evidence Analyst never
exercise SQL/PostGIS. The canonical PR 26F integration slice uses the real
``PostgresGeointQueryService`` over PostgreSQL/PostGIS with ``FakeLlmClient``
only at the model boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.app.query.geoint import (
    GeointEntityLocationItem,
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointLocationEntityListQuery,
    GeointLocationObservationListQuery,
    GeointLocationPage,
    GeointLocationRef,
    GeointObservationDetail,
    GeointObservationItem,
    GeointObservationQuery,
    GeointPrecisionCounts,
    GeointQueryService,
    GeointSummary,
    GeointSummaryQuery,
    GeointTopLocation,
)
from agentic_threat_investigator.app.query.models import QueryPage
from agentic_threat_investigator.domain.analyst import (
    AnalystGeointLocation,
    AnalystGeointObservation,
    AnalystGeointPrecisionCounts,
    AnalystGeointSummary,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def location_ref(
    *,
    location_type: LocationType = LocationType.CITY,
    canonical_name: str = "Seattle",
    country_code: str = "US",
    admin1_code: str | None = "WA",
    parent_location_id: UUID | None = None,
) -> GeointLocationRef:
    """Build one canonical Location reference without representative coordinates."""
    return GeointLocationRef(
        location_id=uuid4(),
        location_type=location_type,
        canonical_name=canonical_name,
        country_code=country_code,
        admin1_code=admin1_code,
        parent_location_id=parent_location_id,
        latitude=None,
        longitude=None,
    )


def observation_item(
    *,
    entity_id: UUID,
    evidence_id: UUID,
    location: GeointLocationRef | None = None,
    observation_id: UUID | None = None,
    precision: LocationPrecision = LocationPrecision.CITY,
    observed_at: datetime | None = FIXED,
    retrieved_at: datetime = FIXED,
) -> GeointObservationItem:
    """Build one Investigation-scoped observation read item."""
    return GeointObservationItem(
        observation_id=observation_id or uuid4(),
        entity_id=entity_id,
        location=location or location_ref(),
        evidence_id=evidence_id,
        precision=precision,
        resolution_method="canonical_geography_v1",
        observed_at=observed_at,
        retrieved_at=retrieved_at,
        resolved_at=retrieved_at,
    )


def entity_location_item(
    *,
    entity_id: UUID,
    entity_type: EntityType = EntityType.IP_ADDRESS,
    entity_value: str = "203.0.113.10",
    observation: GeointObservationItem | None = None,
    evidence_id: UUID | None = None,
) -> GeointEntityLocationItem:
    """Build one Entity current-context read item."""
    return GeointEntityLocationItem(
        entity_id=entity_id,
        entity_type=entity_type,
        entity_value=entity_value,
        display_name=None,
        current_observation=observation
        or observation_item(entity_id=entity_id, evidence_id=evidence_id or uuid4()),
    )


def analyst_observation(
    *,
    observation_id: UUID,
    entity_id: UUID,
    evidence_id: UUID,
    location: AnalystGeointLocation | None = None,
    precision: LocationPrecision = LocationPrecision.CITY,
    observed_at: datetime | None = FIXED,
    retrieved_at: datetime = FIXED,
) -> AnalystGeointObservation:
    """Build one model-visible geographic observation DTO."""
    return AnalystGeointObservation(
        observation_id=observation_id,
        entity_id=entity_id,
        evidence_id=evidence_id,
        location=location
        or AnalystGeointLocation(
            location_id=uuid4(),
            location_type=LocationType.CITY,
            canonical_location_name="Seattle",
            country_code="US",
            admin1_code="WA",
        ),
        precision=precision,
        resolution_method="canonical_geography_v1",
        observed_at=observed_at,
        retrieved_at=retrieved_at,
        resolved_at=retrieved_at,
    )


def analyst_summary(
    *,
    observation_count: int = 0,
    entity_count_with_location: int = 0,
    location_count: int = 0,
    truncated: bool = False,
) -> AnalystGeointSummary:
    """Build one empty-or-populated model-visible summary DTO."""
    return AnalystGeointSummary(
        entity_count_with_location=entity_count_with_location,
        observation_count=observation_count,
        location_count=location_count,
        country_count=0,
        administrative_area_count=0,
        city_count=location_count,
        precision_counts=AnalystGeointPrecisionCounts(
            country=0,
            administrative_area=0,
            city=observation_count,
        ),
        top_locations=(),
        truncated=truncated,
    )


@dataclass
class FakeGeointQueryService(GeointQueryService):
    """Scripted in-memory implementation of the PR 26D read boundary.

    Every method records its invocation so tests can assert the exact query
    scopes, page sizes, and the absence of second-page fetching. Set
    ``fail`` to inject a typed exception (including ``asyncio.CancelledError``)
    that propagates unchanged through the facade.
    """

    summary_result: GeointSummary | None = None
    current_by_entity: dict[UUID, GeointEntityLocationItem] = field(
        default_factory=dict
    )
    history_by_entity: dict[UUID, list[GeointObservationItem]] = field(
        default_factory=dict
    )
    location_entities: dict[tuple[UUID, bool], list[GeointEntityLocationItem]] = field(
        default_factory=dict
    )
    location_observations: dict[tuple[UUID, bool], list[GeointObservationItem]] = field(
        default_factory=dict
    )
    observation_details: dict[UUID, GeointObservationDetail] = field(
        default_factory=dict
    )
    fail: BaseException | None = None
    summary_calls: list[GeointSummaryQuery] = field(default_factory=list)
    entity_calls: list[GeointEntityQuery] = field(default_factory=list)
    history_calls: list[GeointEntityObservationListQuery] = field(default_factory=list)
    location_entity_calls: list[GeointLocationEntityListQuery] = field(
        default_factory=list
    )
    location_observation_calls: list[GeointLocationObservationListQuery] = field(
        default_factory=list
    )
    observation_calls: list[GeointObservationQuery] = field(default_factory=list)

    def _maybe_fail(self) -> None:
        """Raise the injected failure so cancellation/failures propagate."""
        if self.fail is not None:
            raise self.fail

    async def summary(self, query: GeointSummaryQuery) -> GeointSummary:
        """Record and answer one summary read."""
        self._maybe_fail()
        self.summary_calls.append(query)
        if self.summary_result is None:
            raise AssertionError("FakeGeointQueryService has no summary configured")
        return self.summary_result

    async def get_entity(
        self, query: GeointEntityQuery
    ) -> GeointEntityLocationItem | None:
        """Record and answer one Entity current read."""
        self._maybe_fail()
        self.entity_calls.append(query)
        return self.current_by_entity.get(query.entity_id)

    async def list_entity_observations(
        self, query: GeointEntityObservationListQuery
    ) -> QueryPage[GeointObservationItem]:
        """Record and answer one bounded Entity history page."""
        self._maybe_fail()
        self.history_calls.append(query)
        if query.cursor is not None:
            raise AssertionError("the analysis facade must never request a cursor")
        items = self.history_by_entity.get(query.entity_id, [])[: query.limit]
        full = self.history_by_entity.get(query.entity_id, [])
        return QueryPage(
            items=tuple(items),
            next_cursor="cursor" if len(full) > query.limit else None,
        )

    async def list_location_entities(
        self, query: GeointLocationEntityListQuery
    ) -> GeointLocationPage[GeointEntityLocationItem]:
        """Record and answer one bounded Location-Entities page."""
        self._maybe_fail()
        self.location_entity_calls.append(query)
        if query.cursor is not None:
            raise AssertionError("the analysis facade must never request a cursor")
        key = (query.location_id, query.include_contained)
        items = self.location_entities.get(key, [])[: query.limit]
        full = self.location_entities.get(key, [])
        return GeointLocationPage(
            items=tuple(items),
            next_cursor="cursor" if len(full) > query.limit else None,
            containment_applied=query.include_contained,
        )

    async def list_location_observations(
        self, query: GeointLocationObservationListQuery
    ) -> GeointLocationPage[GeointObservationItem]:
        """Record and answer one bounded Location-observations page."""
        self._maybe_fail()
        self.location_observation_calls.append(query)
        if query.cursor is not None:
            raise AssertionError("the analysis facade must never request a cursor")
        key = (query.location_id, query.include_contained)
        items = self.location_observations.get(key, [])[: query.limit]
        full = self.location_observations.get(key, [])
        return GeointLocationPage(
            items=tuple(items),
            next_cursor="cursor" if len(full) > query.limit else None,
            containment_applied=query.include_contained,
        )

    async def get_observation(
        self, query: GeointObservationQuery
    ) -> GeointObservationDetail | None:
        """Record and answer one exact observation read."""
        self._maybe_fail()
        self.observation_calls.append(query)
        return self.observation_details.get(query.observation_id)


def zero_summary() -> GeointSummary:
    """Build one all-zero bounded summary read model."""
    return GeointSummary(
        entity_count_with_location=0,
        observation_count=0,
        location_count=0,
        country_count=0,
        administrative_area_count=0,
        city_count=0,
        precision_counts=GeointPrecisionCounts(
            country=0, administrative_area=0, city=0
        ),
        top_locations=(),
        truncated=False,
    )


def summary_with_top_locations(location: GeointLocationRef) -> GeointSummary:
    """Build one summary carrying one top-location group."""
    return GeointSummary(
        entity_count_with_location=1,
        observation_count=1,
        location_count=1,
        country_count=0,
        administrative_area_count=0,
        city_count=1,
        precision_counts=GeointPrecisionCounts(
            country=0, administrative_area=0, city=1
        ),
        top_locations=(GeointTopLocation(location=location, scoped_entity_count=1),),
        truncated=False,
    )
