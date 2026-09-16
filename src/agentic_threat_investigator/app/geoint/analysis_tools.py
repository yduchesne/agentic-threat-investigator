# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded deterministic GEOINT analysis tools (PR 26F).

:class:`GeointAnalysisTools` is a small read-only application facade over
the existing Investigation-scoped :class:`GeointQueryService`. \"Tools\" here
are ATI-owned deterministic application/query contracts used to construct
bounded model context; the model never directly executes SQL/PostGIS and
``LlmClient`` remains a structured-output-only boundary.

Every call is Investigation-scoped and delegates to the existing query
service. The facade never imports SQLAlchemy/PostGIS, decodes cursors,
drains pages, mutates, owns a database transaction, or calls the LLM.
Pageable operations return exactly one bounded first page with explicit
``has_more`` continuation state; the opaque continuation cursor is never
exposed and the model cannot autonomously paginate.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.app.query.geoint import (
    GeointEntityLocationItem,
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointLocationEntityListQuery,
    GeointLocationObservationListQuery,
    GeointObservationDetail,
    GeointObservationItem,
    GeointObservationQuery,
    GeointQueryService,
    GeointSummary,
    GeointSummaryQuery,
)

_MAX_OBSERVATIONS_PER_ENTITY_CEILING = 200
"""Hard ceiling mirroring the Settings validator for direct construction."""

T = TypeVar("T")


class GeointAnalysisToolPage(BaseModel, Generic[T]):
    """One bounded tool page with explicit continuation state (PR 26F).

    ``has_more`` is ``true`` exactly when the underlying collection has a
    continuation cursor (the service fetched at least one additional row);
    the cursor itself is never part of the model-visible envelope. The
    containment flags are meaningful for the Location-scoped tools only and
    report the request and its honest application.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[T, ...]
    has_more: bool
    containment_requested: bool = False
    containment_applied: bool = False


GeointHistoryToolResult = GeointAnalysisToolPage[GeointObservationItem]
"""One bounded Entity-history page with explicit continuation state."""

GeointEntitiesToolResult = GeointAnalysisToolPage[GeointEntityLocationItem]
"""One bounded Location-Entities page with explicit containment state."""

GeointObservationsToolResult = GeointAnalysisToolPage[GeointObservationItem]
"""One bounded Location-observations page with explicit containment state."""


class GeointAnalysisTools:
    """Read-only bounded GEOINT analysis facade over ``GeointQueryService``.

    The configured ``max_observations_per_entity`` is the application-level
    analyst GEOINT page bound: a requested page size is clamped to this
    bound before the query executes and no additional pages are ever
    fetched. ``on_close`` is an optional hook (for example closing the
    short-lived read session) invoked once by :meth:`aclose`; the facade
    itself never owns a database transaction.
    """

    def __init__(
        self,
        query_service: GeointQueryService,
        *,
        max_observations_per_entity: int = 25,
        on_close: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        """Bind the query service, the page bound, and the optional close hook.

        ``on_close`` is invoked once by :meth:`aclose`; production composition
        supplies the hook that closes the short-lived read session.
        """
        if not 1 <= max_observations_per_entity <= _MAX_OBSERVATIONS_PER_ENTITY_CEILING:
            raise ValueError(
                "max_observations_per_entity must be in the range "
                f"1..{_MAX_OBSERVATIONS_PER_ENTITY_CEILING}"
            )
        self._query_service = query_service
        self._max_observations_per_entity = max_observations_per_entity
        self._on_close = on_close

    @property
    def max_observations_per_entity(self) -> int:
        """Return the application-level analyst GEOINT page bound."""
        return self._max_observations_per_entity

    async def summary(self, investigation_id: UUID) -> GeointSummary:
        """Return the bounded Investigation geographic summary."""
        return await self._query_service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )

    async def current_for_entity(
        self, investigation_id: UUID, entity_id: UUID
    ) -> GeointEntityLocationItem | None:
        """Return one Entity's Investigation-relative current context, if any."""
        return await self._query_service.get_entity(
            GeointEntityQuery(investigation_id=investigation_id, entity_id=entity_id)
        )

    async def history_for_entity(
        self, investigation_id: UUID, entity_id: UUID, *, limit: int
    ) -> GeointHistoryToolResult:
        """Return one bounded page of the Entity's scoped history.

        The requested ``limit`` is clamped to the analyst page bound before
        query execution; exactly one first page is fetched and ``has_more``
        reports whether older observations exist.
        """
        page = await self._query_service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_id,
                entity_id=entity_id,
                limit=self._clamp_limit(limit),
                cursor=None,
            )
        )
        return GeointHistoryToolResult(
            items=page.items, has_more=page.next_cursor is not None
        )

    async def entities_in_location(
        self,
        investigation_id: UUID,
        location_id: UUID,
        *,
        include_contained: bool,
        limit: int,
    ) -> GeointEntitiesToolResult:
        """Return one bounded page of Entities observed at the Location scope.

        ``include_contained`` is the existing exact/contained boolean;
        containment is server-owned and reported honestly through
        ``containment_applied``.
        """
        page = await self._query_service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=location_id,
                include_contained=include_contained,
                limit=self._clamp_limit(limit),
                cursor=None,
            )
        )
        return GeointEntitiesToolResult(
            items=page.items,
            has_more=page.next_cursor is not None,
            containment_requested=include_contained,
            containment_applied=page.containment_applied,
        )

    async def observations_in_location(
        self,
        investigation_id: UUID,
        location_id: UUID,
        *,
        include_contained: bool,
        limit: int,
    ) -> GeointObservationsToolResult:
        """Return one bounded page of observations at the Location scope.

        ``include_contained`` is the existing exact/contained boolean;
        containment is server-owned and reported honestly through
        ``containment_applied``.
        """
        page = await self._query_service.list_location_observations(
            GeointLocationObservationListQuery(
                investigation_id=investigation_id,
                location_id=location_id,
                include_contained=include_contained,
                limit=self._clamp_limit(limit),
                cursor=None,
            )
        )
        return GeointObservationsToolResult(
            items=page.items,
            has_more=page.next_cursor is not None,
            containment_requested=include_contained,
            containment_applied=page.containment_applied,
        )

    async def observation(
        self, investigation_id: UUID, observation_id: UUID
    ) -> GeointObservationDetail | None:
        """Return one exact observation bound to the Investigation, if any."""
        return await self._query_service.get_observation(
            GeointObservationQuery(
                investigation_id=investigation_id, observation_id=observation_id
            )
        )

    def _clamp_limit(self, requested: int) -> int:
        """Return the requested page size clamped to the analyst bound."""
        if requested < 1:
            raise ValueError("tool page limit must be positive")
        return min(requested, self._max_observations_per_entity)

    async def aclose(self) -> None:
        """Release the optional bound resource exactly once.

        The default implementation releases nothing: the facade owns no
        database transaction. Production composition supplies the hook that
        closes the short-lived read session.
        """
        if self._on_close is None:
            return
        await self._on_close()
        self._on_close = None
