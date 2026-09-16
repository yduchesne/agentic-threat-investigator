# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Evaluation-only recording seam over the PR 26D query boundary (PR 26G).

PR 26F deliberately has no production operation trace; PR 26G must not add
generic production tracing. This module instead wraps an existing
:class:`GeointQueryService` (the real ``PostgresGeointQueryService`` in
integration, a scripted fake in unit tests) and records every operation the
delivered :class:`GeointAnalysisTools` facade performs. The recorded
:class:`GeointToolOperationRecord` values feed the deterministic evaluator's
tool/context checks (allowed operations, bounds, no cursor draining, no
Location fan-out, no containment expansion, no proximity) without touching
production code.
"""

from __future__ import annotations

from agentic_threat_investigator.app.query.geoint import (
    GeointEntityLocationItem,
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointLocationEntityListQuery,
    GeointLocationObservationListQuery,
    GeointLocationPage,
    GeointObservationDetail,
    GeointObservationItem,
    GeointObservationQuery,
    GeointQueryService,
    GeointSummary,
    GeointSummaryQuery,
)
from agentic_threat_investigator.app.query.models import QueryPage
from agentic_threat_investigator.evaluation.geoint.models import (
    GeointToolOperation,
    GeointToolOperationRecord,
)


class RecordingGeointQueryService(GeointQueryService):
    """Delegating query service that records every operation deterministically.

    All reads delegate to the wrapped service unchanged; the record list is
    the only addition and is never consulted by production code.
    """

    def __init__(self, delegate: GeointQueryService) -> None:
        """Bind the delegate and an empty record list."""
        self._delegate = delegate
        self.records: list[GeointToolOperationRecord] = []

    async def summary(self, query: GeointSummaryQuery) -> GeointSummary:
        """Record and delegate one bounded summary read."""
        self.records.append(
            GeointToolOperationRecord(
                operation=GeointToolOperation.SUMMARY,
                investigation_id=query.investigation_id,
            )
        )
        return await self._delegate.summary(query)

    async def get_entity(
        self, query: GeointEntityQuery
    ) -> GeointEntityLocationItem | None:
        """Record and delegate one Entity current read."""
        self.records.append(
            GeointToolOperationRecord(
                operation=GeointToolOperation.CURRENT_FOR_ENTITY,
                investigation_id=query.investigation_id,
                entity_id=query.entity_id,
            )
        )
        return await self._delegate.get_entity(query)

    async def list_entity_observations(
        self, query: GeointEntityObservationListQuery
    ) -> QueryPage[GeointObservationItem]:
        """Record and delegate one bounded Entity history page."""
        page = await self._delegate.list_entity_observations(query)
        self.records.append(
            GeointToolOperationRecord(
                operation=GeointToolOperation.HISTORY_FOR_ENTITY,
                investigation_id=query.investigation_id,
                entity_id=query.entity_id,
                limit=query.limit,
                cursor_requested=query.cursor is not None,
                has_more=page.next_cursor is not None,
            )
        )
        return page

    async def list_location_entities(
        self, query: GeointLocationEntityListQuery
    ) -> GeointLocationPage[GeointEntityLocationItem]:
        """Record and delegate one bounded Location-Entities page."""
        page = await self._delegate.list_location_entities(query)
        self.records.append(
            GeointToolOperationRecord(
                operation=GeointToolOperation.ENTITIES_IN_LOCATION,
                investigation_id=query.investigation_id,
                location_id=query.location_id,
                limit=query.limit,
                include_contained=query.include_contained,
                cursor_requested=query.cursor is not None,
                has_more=page.next_cursor is not None,
            )
        )
        return page

    async def list_location_observations(
        self, query: GeointLocationObservationListQuery
    ) -> GeointLocationPage[GeointObservationItem]:
        """Record and delegate one bounded Location-observations page."""
        page = await self._delegate.list_location_observations(query)
        self.records.append(
            GeointToolOperationRecord(
                operation=GeointToolOperation.OBSERVATIONS_IN_LOCATION,
                investigation_id=query.investigation_id,
                location_id=query.location_id,
                limit=query.limit,
                include_contained=query.include_contained,
                cursor_requested=query.cursor is not None,
                has_more=page.next_cursor is not None,
            )
        )
        return page

    async def get_observation(
        self, query: GeointObservationQuery
    ) -> GeointObservationDetail | None:
        """Record and delegate one exact observation read."""
        self.records.append(
            GeointToolOperationRecord(
                operation=GeointToolOperation.OBSERVATION_DETAIL,
                investigation_id=query.investigation_id,
                observation_id=query.observation_id,
            )
        )
        return await self._delegate.get_observation(query)


def tool_trace(
    service: RecordingGeointQueryService,
) -> tuple[GeointToolOperationRecord, ...]:
    """Return the recorded tool operations as an immutable tuple."""
    return tuple(service.records)
