# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL/PostGIS Investigation-scoped GEOINT read queries (PR 26D).

Every statement is a complete literal constant with all externally-derived
values bound as parameters: no SQL text, function name, or geometry
expression is ever assembled from user input. Investigation scope is always
proved through the exact Evidence chain
(``ati.entity_location_observation.evidence_id ->
ati.evidence.investigation_id``); global ``EntityLocation`` materialized
state is never read as Investigation-relative current. The service issues
SELECT statements only, never INSERT/UPDATE/DELETE and never a commit.

Containment (``include_contained=true``) is a spatially bounded child
selection: the exact selected Location plus child canonical Locations
covered by the selected boundary via boundary-inclusive ``ST_Covers`` with an
explicit bounding-box pre-filter (GiST ``location_geometry_gist_idx``). A
city Point never expands and a NULL selected geometry degrades to the exact
selection, each reported honestly through ``containment_applied``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.geoint import (
    DEFAULT_GEONT_SUMMARY_TOP_LOCATIONS,
    GeointEntityLocationItem,
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointLocationEntityListQuery,
    GeointLocationObservationListQuery,
    GeointLocationPage,
    GeointObservationDetail,
    GeointObservationItem,
    GeointObservationQuery,
    GeointPrecisionCounts,
    GeointQueryService,
    GeointReadError,
    GeointSummary,
    GeointSummaryQuery,
    GeointTopLocation,
    geoint_entity_location_item_from_row,
    geoint_location_ref_from_row,
    geoint_observation_detail_from_row,
    geoint_observation_item_from_row,
    location_entity_sort_values,
    observation_sort_values,
    parse_location_entity_cursor,
    parse_observation_cursor,
)
from agentic_threat_investigator.app.query.models import QueryLimits, QueryPage
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    QueryKind,
    encode_cursor,
    require_cursor_for_query,
)
from agentic_threat_investigator.domain.geoint import LocationType

# Every statement below is one complete literal constant with the shared
# projection/joins/predicates inlined: SQL text is never assembled at runtime
# (no concatenation, no format templates), every externally-derived value is
# a bound parameter, and no user-derived SQL fragment or function name can
# ever enter a statement. The centroid is exposed only as the paired
# latitude/longitude; raw EWKT/WKB boundary geometry never leaves the query
# layer. Evidence type is not re-filtered by reads: the immutable append
# stored function already rejects non-GEOLOCATION Evidence (U26A4).
#
# Exact Evidence-scope key (PR 28B): an observation is scoped to the
# Investigation iff its exact evidence_observation_id is admitted through
# ati.investigation_evidence. PR 26A currentness ordering: the greater
# ``(COALESCE(observed_at, retrieved_at), observation id)`` pair wins; the
# newest-first read order inverts that exact ordering.

_OBSERVATION_PROJECTION = """
      ob.id AS observation_id,
      ob.entity_id AS entity_id,
      ob.evidence_observation_id AS evidence_observation_id,
      ob."precision" AS "precision",
      ob.observed_at AS observed_at,
      ob.retrieved_at AS retrieved_at,
      ob.resolved_at AS resolved_at,
      ob.resolution_method AS resolution_method,
      ent.entity_type AS entity_type,
      ent.canonical_value AS canonical_value,
      ent.display_name AS display_name,
      loc.id AS location_id,
      loc.location_type AS location_type,
      loc.canonical_name AS canonical_name,
      loc.country_code AS country_code,
      loc.admin1_code AS admin1_code,
      loc.admin2_code AS admin2_code,
      loc.parent_location_id AS parent_location_id,
      ST_Y(loc.centroid) AS latitude,
      ST_X(loc.centroid) AS longitude"""

_DETAIL_SQL = """
    SELECT
      ob.id AS observation_id,
      ob.entity_id AS entity_id,
      ob.evidence_observation_id AS evidence_observation_id,
      ob."precision" AS "precision",
      ob.observed_at AS observed_at,
      ob.retrieved_at AS retrieved_at,
      ob.resolved_at AS resolved_at,
      ob.resolution_method AS resolution_method,
      ent.entity_type AS entity_type,
      ent.canonical_value AS canonical_value,
      ent.display_name AS display_name,
      loc.id AS location_id,
      loc.location_type AS location_type,
      loc.canonical_name AS canonical_name,
      loc.country_code AS country_code,
      loc.admin1_code AS admin1_code,
      loc.admin2_code AS admin2_code,
      loc.parent_location_id AS parent_location_id,
      ST_Y(loc.centroid) AS latitude,
      ST_X(loc.centroid) AS longitude
    FROM ati.entity_location_observation ob
    JOIN ati.evidence_observation eo ON eo.id = ob.evidence_observation_id
    JOIN ati.evidence ev ON ev.id = eo.evidence_id
    JOIN ati.entity ent ON ent.id = ob.entity_id
    JOIN ati.location loc ON loc.id = ob.location_id
    WHERE ob.id = :observation_id
      AND EXISTS (
            SELECT 1 FROM ati.investigation_evidence ie
            WHERE ie.evidence_observation_id = ob.evidence_observation_id
              AND ie.investigation_id = :investigation_id)
    LIMIT 1
"""

_ENTITY_CURRENT_SQL = """
    SELECT
      ob.id AS observation_id,
      ob.entity_id AS entity_id,
      ob.evidence_observation_id AS evidence_observation_id,
      ob."precision" AS "precision",
      ob.observed_at AS observed_at,
      ob.retrieved_at AS retrieved_at,
      ob.resolved_at AS resolved_at,
      ob.resolution_method AS resolution_method,
      ent.entity_type AS entity_type,
      ent.canonical_value AS canonical_value,
      ent.display_name AS display_name,
      loc.id AS location_id,
      loc.location_type AS location_type,
      loc.canonical_name AS canonical_name,
      loc.country_code AS country_code,
      loc.admin1_code AS admin1_code,
      loc.admin2_code AS admin2_code,
      loc.parent_location_id AS parent_location_id,
      ST_Y(loc.centroid) AS latitude,
      ST_X(loc.centroid) AS longitude
    FROM ati.entity_location_observation ob
    JOIN ati.evidence_observation eo ON eo.id = ob.evidence_observation_id
    JOIN ati.evidence ev ON ev.id = eo.evidence_id
    JOIN ati.entity ent ON ent.id = ob.entity_id
    JOIN ati.location loc ON loc.id = ob.location_id
    WHERE ob.entity_id = :entity_id
      AND EXISTS (
            SELECT 1 FROM ati.investigation_evidence ie
            WHERE ie.evidence_observation_id = ob.evidence_observation_id
              AND ie.investigation_id = :investigation_id)
    ORDER BY COALESCE(ob.observed_at, ob.retrieved_at) DESC, ob.id DESC
    LIMIT 1
"""

_ENTITY_HISTORY_SQL = """
    SELECT
      ob.id AS observation_id,
      ob.entity_id AS entity_id,
      ob.evidence_observation_id AS evidence_observation_id,
      ob."precision" AS "precision",
      ob.observed_at AS observed_at,
      ob.retrieved_at AS retrieved_at,
      ob.resolved_at AS resolved_at,
      ob.resolution_method AS resolution_method,
      ent.entity_type AS entity_type,
      ent.canonical_value AS canonical_value,
      ent.display_name AS display_name,
      loc.id AS location_id,
      loc.location_type AS location_type,
      loc.canonical_name AS canonical_name,
      loc.country_code AS country_code,
      loc.admin1_code AS admin1_code,
      loc.admin2_code AS admin2_code,
      loc.parent_location_id AS parent_location_id,
      ST_Y(loc.centroid) AS latitude,
      ST_X(loc.centroid) AS longitude
    FROM ati.entity_location_observation ob
    JOIN ati.evidence_observation eo ON eo.id = ob.evidence_observation_id
    JOIN ati.evidence ev ON ev.id = eo.evidence_id
    JOIN ati.entity ent ON ent.id = ob.entity_id
    JOIN ati.location loc ON loc.id = ob.location_id
    WHERE ob.entity_id = :entity_id
      AND EXISTS (
            SELECT 1 FROM ati.investigation_evidence ie
            WHERE ie.evidence_observation_id = ob.evidence_observation_id
              AND ie.investigation_id = :investigation_id)
      AND (CAST(:cursor_time AS timestamptz) IS NULL
           OR COALESCE(ob.observed_at, ob.retrieved_at) < CAST(:cursor_time AS timestamptz)
           OR (COALESCE(ob.observed_at, ob.retrieved_at) = CAST(:cursor_time AS timestamptz)
               AND ob.id < CAST(:cursor_id AS uuid)))
    ORDER BY COALESCE(ob.observed_at, ob.retrieved_at) DESC, ob.id DESC
    LIMIT :limit
"""

# Contained selection: the selected Location plus every canonical Location
# whose geometry it covers. ``sel`` is the single selected row; the ``&&``
# bounding-box pre-filter lets PostgreSQL use the GiST geometry index before
# the boundary-inclusive ST_Covers test. An exact selection is the same
# statement shape with the single Location predicate.
_LOCATION_OBSERVATIONS_EXACT_SQL = """
    SELECT
      ob.id AS observation_id,
      ob.entity_id AS entity_id,
      ob.evidence_observation_id AS evidence_observation_id,
      ob."precision" AS "precision",
      ob.observed_at AS observed_at,
      ob.retrieved_at AS retrieved_at,
      ob.resolved_at AS resolved_at,
      ob.resolution_method AS resolution_method,
      ent.entity_type AS entity_type,
      ent.canonical_value AS canonical_value,
      ent.display_name AS display_name,
      loc.id AS location_id,
      loc.location_type AS location_type,
      loc.canonical_name AS canonical_name,
      loc.country_code AS country_code,
      loc.admin1_code AS admin1_code,
      loc.admin2_code AS admin2_code,
      loc.parent_location_id AS parent_location_id,
      ST_Y(loc.centroid) AS latitude,
      ST_X(loc.centroid) AS longitude
    FROM ati.entity_location_observation ob
    JOIN ati.evidence_observation eo ON eo.id = ob.evidence_observation_id
    JOIN ati.evidence ev ON ev.id = eo.evidence_id
    JOIN ati.entity ent ON ent.id = ob.entity_id
    JOIN ati.location loc ON loc.id = ob.location_id
    WHERE ob.location_id = :location_id
      AND EXISTS (
            SELECT 1 FROM ati.investigation_evidence ie
            WHERE ie.evidence_observation_id = ob.evidence_observation_id
              AND ie.investigation_id = :investigation_id)
      AND (CAST(:cursor_time AS timestamptz) IS NULL
           OR COALESCE(ob.observed_at, ob.retrieved_at) < CAST(:cursor_time AS timestamptz)
           OR (COALESCE(ob.observed_at, ob.retrieved_at) = CAST(:cursor_time AS timestamptz)
               AND ob.id < CAST(:cursor_id AS uuid)))
    ORDER BY COALESCE(ob.observed_at, ob.retrieved_at) DESC, ob.id DESC
    LIMIT :limit
"""

_LOCATION_OBSERVATIONS_CONTAINED_SQL = """
    SELECT
      ob.id AS observation_id,
      ob.entity_id AS entity_id,
      ob.evidence_observation_id AS evidence_observation_id,
      ob."precision" AS "precision",
      ob.observed_at AS observed_at,
      ob.retrieved_at AS retrieved_at,
      ob.resolved_at AS resolved_at,
      ob.resolution_method AS resolution_method,
      ent.entity_type AS entity_type,
      ent.canonical_value AS canonical_value,
      ent.display_name AS display_name,
      loc.id AS location_id,
      loc.location_type AS location_type,
      loc.canonical_name AS canonical_name,
      loc.country_code AS country_code,
      loc.admin1_code AS admin1_code,
      loc.admin2_code AS admin2_code,
      loc.parent_location_id AS parent_location_id,
      ST_Y(loc.centroid) AS latitude,
      ST_X(loc.centroid) AS longitude
    FROM ati.entity_location_observation ob
    JOIN ati.evidence_observation eo ON eo.id = ob.evidence_observation_id
    JOIN ati.evidence ev ON ev.id = eo.evidence_id
    JOIN ati.entity ent ON ent.id = ob.entity_id
    JOIN ati.location loc ON loc.id = ob.location_id
    WHERE ob.location_id IN (
            SELECT l.id FROM ati.location l, ati.location sel
            WHERE sel.id = :location_id
              AND (l.id = sel.id
                   OR (l.geometry IS NOT NULL AND sel.geometry IS NOT NULL
                       AND l.geometry && sel.geometry
                       AND ST_Covers(sel.geometry, l.geometry))))
      AND EXISTS (
            SELECT 1 FROM ati.investigation_evidence ie
            WHERE ie.evidence_observation_id = ob.evidence_observation_id
              AND ie.investigation_id = :investigation_id)
      AND (CAST(:cursor_time AS timestamptz) IS NULL
           OR COALESCE(ob.observed_at, ob.retrieved_at) < CAST(:cursor_time AS timestamptz)
           OR (COALESCE(ob.observed_at, ob.retrieved_at) = CAST(:cursor_time AS timestamptz)
               AND ob.id < CAST(:cursor_id AS uuid)))
    ORDER BY COALESCE(ob.observed_at, ob.retrieved_at) DESC, ob.id DESC
    LIMIT :limit
"""

# One Entity per row: DISTINCT ON entity_id selects the latest qualifying
# observation (PR 26A ordering), then the outer keyset pages the
# deterministic (entity_type, canonical_value, entity_id) order.
_LOCATION_ENTITIES_EXACT_SQL = """
    SELECT * FROM (
      SELECT DISTINCT ON (ob.entity_id)
        ob.id AS observation_id,
        ob.entity_id AS entity_id,
        ob.evidence_observation_id AS evidence_observation_id,
        ob."precision" AS "precision",
        ob.observed_at AS observed_at,
        ob.retrieved_at AS retrieved_at,
        ob.resolved_at AS resolved_at,
        ob.resolution_method AS resolution_method,
        ent.entity_type AS entity_type,
        ent.canonical_value AS canonical_value,
        ent.display_name AS display_name,
        loc.id AS location_id,
        loc.location_type AS location_type,
        loc.canonical_name AS canonical_name,
        loc.country_code AS country_code,
        loc.admin1_code AS admin1_code,
        loc.admin2_code AS admin2_code,
        loc.parent_location_id AS parent_location_id,
        ST_Y(loc.centroid) AS latitude,
        ST_X(loc.centroid) AS longitude
      FROM ati.entity_location_observation ob
      JOIN ati.evidence_observation eo ON eo.id = ob.evidence_observation_id
    JOIN ati.evidence ev ON ev.id = eo.evidence_id
      JOIN ati.entity ent ON ent.id = ob.entity_id
      JOIN ati.location loc ON loc.id = ob.location_id
      WHERE ob.location_id = :location_id
        AND EXISTS (
            SELECT 1 FROM ati.investigation_evidence ie
            WHERE ie.evidence_observation_id = ob.evidence_observation_id
              AND ie.investigation_id = :investigation_id)
      ORDER BY ob.entity_id, COALESCE(ob.observed_at, ob.retrieved_at) DESC,
               ob.id DESC
    ) latest
    WHERE (CAST(:cursor_type AS text) IS NULL
           OR (latest.entity_type, latest.canonical_value, latest.entity_id)
              > (CAST(:cursor_type AS text), CAST(:cursor_value AS text),
                 CAST(:cursor_id AS uuid)))
    ORDER BY latest.entity_type, latest.canonical_value, latest.entity_id
    LIMIT :limit
"""

_LOCATION_ENTITIES_CONTAINED_SQL = """
    SELECT * FROM (
      SELECT DISTINCT ON (ob.entity_id)
        ob.id AS observation_id,
        ob.entity_id AS entity_id,
        ob.evidence_observation_id AS evidence_observation_id,
        ob."precision" AS "precision",
        ob.observed_at AS observed_at,
        ob.retrieved_at AS retrieved_at,
        ob.resolved_at AS resolved_at,
        ob.resolution_method AS resolution_method,
        ent.entity_type AS entity_type,
        ent.canonical_value AS canonical_value,
        ent.display_name AS display_name,
        loc.id AS location_id,
        loc.location_type AS location_type,
        loc.canonical_name AS canonical_name,
        loc.country_code AS country_code,
        loc.admin1_code AS admin1_code,
        loc.admin2_code AS admin2_code,
        loc.parent_location_id AS parent_location_id,
        ST_Y(loc.centroid) AS latitude,
        ST_X(loc.centroid) AS longitude
      FROM ati.entity_location_observation ob
      JOIN ati.evidence_observation eo ON eo.id = ob.evidence_observation_id
    JOIN ati.evidence ev ON ev.id = eo.evidence_id
      JOIN ati.entity ent ON ent.id = ob.entity_id
      JOIN ati.location loc ON loc.id = ob.location_id
      WHERE ob.location_id IN (
              SELECT l.id FROM ati.location l, ati.location sel
              WHERE sel.id = :location_id
                AND (l.id = sel.id
                     OR (l.geometry IS NOT NULL AND sel.geometry IS NOT NULL
                         AND l.geometry && sel.geometry
                         AND ST_Covers(sel.geometry, l.geometry))))
        AND EXISTS (
            SELECT 1 FROM ati.investigation_evidence ie
            WHERE ie.evidence_observation_id = ob.evidence_observation_id
              AND ie.investigation_id = :investigation_id)
      ORDER BY ob.entity_id, COALESCE(ob.observed_at, ob.retrieved_at) DESC,
               ob.id DESC
    ) latest
    WHERE (CAST(:cursor_type AS text) IS NULL
           OR (latest.entity_type, latest.canonical_value, latest.entity_id)
              > (CAST(:cursor_type AS text), CAST(:cursor_value AS text),
                 CAST(:cursor_id AS uuid)))
    ORDER BY latest.entity_type, latest.canonical_value, latest.entity_id
    LIMIT :limit
"""

# Selection capability lookup: does the selected Location exist, is it a
# city Point, and does it carry a usable boundary geometry?
_SELECTED_LOCATION_SQL = (
    "SELECT location_type, ST_AsEWKT(geometry) AS geometry_ewkt "
    "FROM ati.location WHERE id = :location_id LIMIT 1"
)

_SUMMARY_COUNTS_SQL = """
    SELECT
      count(*) AS observation_count,
      count(DISTINCT ob.entity_id) AS entity_count_with_location,
      count(DISTINCT ob.location_id) AS location_count,
      count(DISTINCT ob.location_id) FILTER (
        WHERE loc.location_type = 'country') AS country_count,
      count(DISTINCT ob.location_id) FILTER (
        WHERE loc.location_type = 'administrative_area')
        AS administrative_area_count,
      count(DISTINCT ob.location_id) FILTER (
        WHERE loc.location_type = 'city') AS city_count,
      count(*) FILTER (WHERE ob."precision" = 'country')
        AS precision_country,
      count(*) FILTER (WHERE ob."precision" = 'administrative_area')
        AS precision_administrative_area,
      count(*) FILTER (WHERE ob."precision" = 'city') AS precision_city
    FROM ati.entity_location_observation ob
    JOIN ati.evidence_observation eo ON eo.id = ob.evidence_observation_id
    JOIN ati.evidence ev ON ev.id = eo.evidence_id
    JOIN ati.location loc ON loc.id = ob.location_id
    WHERE EXISTS (
          SELECT 1 FROM ati.investigation_evidence ie
          WHERE ie.evidence_observation_id = ob.evidence_observation_id
            AND ie.investigation_id = :investigation_id)
"""

_SUMMARY_TOP_LOCATIONS_SQL = """
    SELECT
      loc.id AS location_id,
      loc.location_type AS location_type,
      loc.canonical_name AS canonical_name,
      loc.country_code AS country_code,
      loc.admin1_code AS admin1_code,
      loc.admin2_code AS admin2_code,
      loc.parent_location_id AS parent_location_id,
      ST_Y(loc.centroid) AS latitude,
      ST_X(loc.centroid) AS longitude,
      count(DISTINCT ob.entity_id) AS scoped_entity_count
    FROM ati.entity_location_observation ob
    JOIN ati.evidence_observation eo ON eo.id = ob.evidence_observation_id
    JOIN ati.evidence ev ON ev.id = eo.evidence_id
    JOIN ati.location loc ON loc.id = ob.location_id
    WHERE EXISTS (
          SELECT 1 FROM ati.investigation_evidence ie
          WHERE ie.evidence_observation_id = ob.evidence_observation_id
            AND ie.investigation_id = :investigation_id)
    GROUP BY loc.id, loc.location_type, loc.canonical_name, loc.country_code,
             loc.admin1_code, loc.admin2_code, loc.parent_location_id,
             ST_Y(loc.centroid), ST_X(loc.centroid)
    ORDER BY scoped_entity_count DESC, loc.canonical_name ASC, loc.id ASC
    LIMIT :top_limit
"""


def _observation_cursor_values(row: Any) -> tuple[str, str]:
    """Return the canonical cursor sort values of one observation row."""
    return observation_sort_values(
        row["observed_at"], row["retrieved_at"], row["observation_id"]
    )


class PostgresGeointQueryService(GeointQueryService):
    """Bounded Investigation-scoped GEOINT reads over one active session.

    The service shares the per-request read session with every other PR 23A
    query service, validates page sizes through the shared
    :class:`QueryLimits`, and never writes. Purposely written as complete
    literal SELECT statements so PostGIS calls stay bounded and constant.
    """

    def __init__(
        self,
        session: AsyncSession,
        limits: QueryLimits | None = None,
        summary_top_locations: int = DEFAULT_GEONT_SUMMARY_TOP_LOCATIONS,
    ) -> None:
        """Bind the read session, shared limits, and the summary group bound."""
        if summary_top_locations < 1:
            raise ValueError("geoint summary top_locations bound must be positive")
        self._session = session
        self._limits = limits or QueryLimits()
        self._summary_top_locations = summary_top_locations

    async def summary(self, query: GeointSummaryQuery) -> GeointSummary:
        """Return one bounded Investigation-scoped geographic summary."""
        params = {"investigation_id": query.investigation_id}
        counts = (
            (await self._session.execute(text(_SUMMARY_COUNTS_SQL), params))
            .mappings()
            .one()
        )
        top_limit = self._summary_top_locations + 1
        top_rows = list(
            (
                await self._session.execute(
                    text(_SUMMARY_TOP_LOCATIONS_SQL),
                    {**params, "top_limit": top_limit},
                )
            )
            .mappings()
            .all()
        )
        truncated = len(top_rows) > self._summary_top_locations
        top_locations = tuple(
            GeointTopLocation(
                location=geoint_location_ref_from_row(row),
                scoped_entity_count=int(row["scoped_entity_count"]),
            )
            for row in top_rows[: self._summary_top_locations]
        )
        precision_counts = GeointPrecisionCounts(
            country=int(counts["precision_country"]),
            administrative_area=int(counts["precision_administrative_area"]),
            city=int(counts["precision_city"]),
        )
        try:
            return GeointSummary(
                entity_count_with_location=int(counts["entity_count_with_location"]),
                observation_count=int(counts["observation_count"]),
                location_count=int(counts["location_count"]),
                country_count=int(counts["country_count"]),
                administrative_area_count=int(counts["administrative_area_count"]),
                city_count=int(counts["city_count"]),
                precision_counts=precision_counts,
                top_locations=top_locations,
                truncated=truncated,
            )
        except ValidationError as error:
            # Corrupt persisted vocabulary (unreachable through the versioned
            # append path) must fail the read closed as a safe internal
            # contract error, never as a user-input 400.
            raise GeointReadError(
                "persisted geoint summary counts are inconsistent"
            ) from error

    async def get_entity(
        self, query: GeointEntityQuery
    ) -> GeointEntityLocationItem | None:
        """Return the Entity's Investigation-relative current context, if any.

        The latest qualifying observation is selected under the exact PR 26A
        ordering; the global ``EntityLocation`` row is never consulted.
        """
        row = (
            (
                await self._session.execute(
                    text(_ENTITY_CURRENT_SQL),
                    {
                        "entity_id": query.entity_id,
                        "investigation_id": query.investigation_id,
                    },
                )
            )
            .mappings()
            .first()
        )
        return None if row is None else geoint_entity_location_item_from_row(row)

    async def list_entity_observations(
        self, query: GeointEntityObservationListQuery
    ) -> QueryPage[GeointObservationItem]:
        """Return one bounded page of the Entity's scoped observation history."""
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.GEOINT_ENTITY_OBSERVATIONS,
            filter_fingerprint=query.fingerprint(),
        )
        cursor_time: datetime | None = None
        cursor_id: UUID | None = None
        if envelope is not None:
            cursor_time, cursor_id = parse_observation_cursor(
                envelope, "entity observation"
            )
        params: dict[str, object] = {
            "entity_id": query.entity_id,
            "investigation_id": query.investigation_id,
            "cursor_time": cursor_time,
            "cursor_id": cursor_id,
            "limit": limit + 1,
        }
        rows = list(
            (await self._session.execute(text(_ENTITY_HISTORY_SQL), params))
            .mappings()
            .all()
        )
        page = rows[:limit]
        items = tuple(geoint_observation_item_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.GEOINT_ENTITY_OBSERVATIONS,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=_observation_cursor_values(last),
                )
            )
        return QueryPage(items=items, next_cursor=next_cursor)

    async def list_location_entities(
        self, query: GeointLocationEntityListQuery
    ) -> GeointLocationPage[GeointEntityLocationItem]:
        """Return one bounded page of Entities observed at the Location scope."""
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.GEOINT_LOCATION_ENTITIES,
            filter_fingerprint=query.fingerprint(),
        )
        contained = await self._containment_applicable(query)
        cursor_type: str | None = None
        cursor_value: str | None = None
        cursor_id: UUID | None = None
        if envelope is not None:
            cursor_type, cursor_value, cursor_id = parse_location_entity_cursor(
                envelope
            )
        statement = (
            _LOCATION_ENTITIES_CONTAINED_SQL
            if contained
            else _LOCATION_ENTITIES_EXACT_SQL
        )
        params: dict[str, object] = {
            "location_id": query.location_id,
            "investigation_id": query.investigation_id,
            "cursor_type": cursor_type,
            "cursor_value": cursor_value,
            "cursor_id": cursor_id,
            "limit": limit + 1,
        }
        rows = list(
            (await self._session.execute(text(statement), params)).mappings().all()
        )
        page = rows[:limit]
        items = tuple(geoint_entity_location_item_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.GEOINT_LOCATION_ENTITIES,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=location_entity_sort_values(
                        last["entity_type"], last["canonical_value"], last["entity_id"]
                    ),
                )
            )
        return GeointLocationPage(
            items=items, next_cursor=next_cursor, containment_applied=contained
        )

    async def list_location_observations(
        self, query: GeointLocationObservationListQuery
    ) -> GeointLocationPage[GeointObservationItem]:
        """Return one bounded page of observations at the Location scope."""
        limit = self._limits.validate_limit(query.limit)
        envelope = require_cursor_for_query(
            query.cursor,
            query_kind=QueryKind.GEOINT_LOCATION_OBSERVATIONS,
            filter_fingerprint=query.fingerprint(),
        )
        contained = await self._containment_applicable(query)
        cursor_time: datetime | None = None
        cursor_id: UUID | None = None
        if envelope is not None:
            cursor_time, cursor_id = parse_observation_cursor(
                envelope, "location observation"
            )
        statement = (
            _LOCATION_OBSERVATIONS_CONTAINED_SQL
            if contained
            else _LOCATION_OBSERVATIONS_EXACT_SQL
        )
        params: dict[str, object] = {
            "location_id": query.location_id,
            "investigation_id": query.investigation_id,
            "cursor_time": cursor_time,
            "cursor_id": cursor_id,
            "limit": limit + 1,
        }
        rows = list(
            (await self._session.execute(text(statement), params)).mappings().all()
        )
        page = rows[:limit]
        items = tuple(geoint_observation_item_from_row(row) for row in page)
        next_cursor: str | None = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = encode_cursor(
                CursorEnvelope(
                    query_kind=QueryKind.GEOINT_LOCATION_OBSERVATIONS,
                    filter_fingerprint=query.fingerprint(),
                    sort_values=_observation_cursor_values(last),
                )
            )
        return GeointLocationPage(
            items=items, next_cursor=next_cursor, containment_applied=contained
        )

    async def get_observation(
        self, query: GeointObservationQuery
    ) -> GeointObservationDetail | None:
        """Return one observation bound to the Investigation, if any.

        The SQL proves ``observation.id`` matches the requested identity and
        that its exact Evidence row belongs to the path Investigation; a
        cross-scope lookup fails closed with ``None``.
        """
        row = (
            (
                await self._session.execute(
                    text(_DETAIL_SQL),
                    {
                        "observation_id": query.observation_id,
                        "investigation_id": query.investigation_id,
                    },
                )
            )
            .mappings()
            .first()
        )
        return None if row is None else geoint_observation_detail_from_row(row)

    async def _containment_applicable(
        self, query: GeointLocationEntityListQuery | GeointLocationObservationListQuery
    ) -> bool:
        """Return whether a spatial containment selection will be performed.

        Containment applies only when requested and the selected Location
        exists with a non-NULL boundary geometry and is not a city Point
        (cities never expand; a NULL geometry degrades to the exact
        selection, reported honestly through ``containment_applied``).
        """
        if not query.include_contained:
            return False
        row = (
            (
                await self._session.execute(
                    text(_SELECTED_LOCATION_SQL),
                    {"location_id": query.location_id},
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return False
        if row["location_type"] == LocationType.CITY.value:
            return False
        geometry_ewkt = row["geometry_ewkt"]
        return isinstance(geometry_ewkt, str) and bool(geometry_ewkt.strip())
