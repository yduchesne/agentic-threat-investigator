# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL/PostGIS deterministic canonical geography resolver (PR 26B).

A bounded read/canonicalization service over the canonical ``ati.location``
reference table. It performs deterministic narrowing only (country code ->
administrative code/name -> city name) and uses PostGIS containment
(``ST_Covers``, boundary-inclusive) solely as a disambiguation signal among
equally-valued candidates when the claim supplies coordinates.

Spatial containment never: upgrades claim precision, invents a city, infers
hierarchy, or produces a threat relationship. This service never mutates any
persisted state (read-only transaction-truth engine for PR 26C).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.geoint.resolution import (
    CANDIDATE_LIMIT,
    CanonicalGeographyResolver,
    ambiguous_result,
    candidate_sort_key,
    ensure_valid_claim,
    matched_fields_for_claim,
    resolved_result,
    unresolvable_result,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
    Location,
    LocationCandidate,
    LocationPrecision,
    LocationType,
)

# Canonical Location read projection. Every statement below is a complete
# literal constant (the projection is inlined per statement) so no SQL text
# is assembled at runtime; every externally-derived value — including the
# candidate limit — flows through bound parameters. The projection is:
#   id, location_type, name, canonical_name, country_code, admin1_code,
#   admin2_code, parent_location_id, version, created_at, updated_at,
#   ST_AsEWKT(geometry) AS geometry_ewkt, ST_AsEWKT(centroid) AS centroid_ewkt
_COUNTRY_BY_CODE_SQL = (
    "SELECT id, location_type, name, canonical_name, country_code, "
    "admin1_code, admin2_code, parent_location_id, version, "
    "created_at, updated_at, "
    "ST_AsEWKT(geometry) AS geometry_ewkt, "
    "ST_AsEWKT(centroid) AS centroid_ewkt "
    "FROM ati.location "
    "WHERE location_type = 'country' AND country_code = :country_code LIMIT 1"
)

_ADMIN_CANDIDATES_SQL = (
    "SELECT id, location_type, name, canonical_name, country_code, "
    "admin1_code, admin2_code, parent_location_id, version, "
    "created_at, updated_at, "
    "ST_AsEWKT(geometry) AS geometry_ewkt, "
    "ST_AsEWKT(centroid) AS centroid_ewkt "
    "FROM ati.location "
    "WHERE location_type = 'administrative_area' "
    "AND country_code = :country_code "
    "AND (CAST(:admin_code AS text) IS NULL "
    "     OR admin1_code = :admin_code "
    "     OR admin2_code = :admin_code) "
    "AND (CAST(:admin_name AS text) IS NULL "
    "     OR LOWER(canonical_name) = LOWER(:admin_name)) "
    "ORDER BY country_code, admin1_code, COALESCE(admin2_code, ''), "
    "canonical_name, id ASC LIMIT :candidate_limit"
)

_CITY_CANDIDATES_SQL = (
    "SELECT id, location_type, name, canonical_name, country_code, "
    "admin1_code, admin2_code, parent_location_id, version, "
    "created_at, updated_at, "
    "ST_AsEWKT(geometry) AS geometry_ewkt, "
    "ST_AsEWKT(centroid) AS centroid_ewkt "
    "FROM ati.location l "
    "WHERE l.location_type = 'city' "
    "AND l.country_code = :country_code "
    "AND LOWER(l.canonical_name) = LOWER(:city_name) "
    "ORDER BY l.country_code, l.admin1_code, COALESCE(l.admin2_code, ''), "
    "l.canonical_name, l.id ASC LIMIT :candidate_limit"
)

_CITY_WITH_ADMIN_CONTEXT_SQL = (
    "SELECT id, location_type, name, canonical_name, country_code, "
    "admin1_code, admin2_code, parent_location_id, version, "
    "created_at, updated_at, "
    "ST_AsEWKT(geometry) AS geometry_ewkt, "
    "ST_AsEWKT(centroid) AS centroid_ewkt "
    "FROM ati.location l "
    "WHERE l.location_type = 'city' "
    "AND l.country_code = :country_code "
    "AND LOWER(l.canonical_name) = LOWER(:city_name) "
    "AND l.admin1_code = CAST(:admin1 AS text) "
    "AND (CAST(:admin2 AS text) IS NULL OR l.admin2_code = :admin2) "
    "ORDER BY l.country_code, l.admin1_code, COALESCE(l.admin2_code, ''), "
    "l.canonical_name, l.id ASC LIMIT :candidate_limit"
)

_LOCATIONS_BY_IDS_SQL = (
    "SELECT id, location_type, name, canonical_name, country_code, "
    "admin1_code, admin2_code, parent_location_id, version, "
    "created_at, updated_at, "
    "ST_AsEWKT(geometry) AS geometry_ewkt, "
    "ST_AsEWKT(centroid) AS centroid_ewkt "
    "FROM ati.location WHERE id IN :location_ids"
)


def _location_from_row(row: Any) -> Location:
    """Map one EWKT-aware resolution row to a canonical Location."""
    return Location(
        id=row["id"],
        type=LocationType(row["location_type"]),
        name=row["name"],
        canonical_name=row["canonical_name"],
        country_code=row["country_code"],
        admin1_code=row["admin1_code"],
        admin2_code=row["admin2_code"],
        parent_location_id=row["parent_location_id"],
        geometry=row["geometry_ewkt"],
        centroid=row["centroid_ewkt"],
        version=row["version"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class PostgresCanonicalGeographyResolver(CanonicalGeographyResolver):
    """Deterministic canonical claim narrowing over PostgreSQL/PostGIS."""

    def __init__(self, session: AsyncSession) -> None:
        """Bind one active read session (no mutation is ever issued)."""
        self._session = session

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Resolve one validated claim with deterministic narrowing."""
        ensure_valid_claim(claim)
        claim_fields = matched_fields_for_claim(claim)

        if claim.precision is LocationPrecision.COUNTRY:
            if claim.country_code is None:
                if claim_fields:
                    return unresolvable_result("missing_country_context")
                return unresolvable_result("missing_semantic_context")
            country = await self._country_by_code(claim.country_code)
            if country is None:
                return unresolvable_result("unknown_country")
            return resolved_result(
                country, reason_code="exact_semantic_match", matched_fields=claim_fields
            )

        if claim.precision is LocationPrecision.ADMINISTRATIVE_AREA:
            if claim.country_code is None:
                return unresolvable_result("missing_country_context")
            candidates = await self._administrative_candidates(claim)
            if not candidates:
                return unresolvable_result("unknown_administrative_area")
            return await self._decide(claim, candidates, claim_fields)

        # city precision
        if claim.country_code is None:
            return unresolvable_result("missing_country_context")
        admin_context = await self._resolve_admin_context(claim)
        if isinstance(admin_context, CanonicalLocationResolution):
            return admin_context
        candidates = await self._city_candidates(claim, admin_context)
        if not candidates:
            return unresolvable_result("unknown_city")
        return await self._decide(claim, candidates, claim_fields)

    # -- narrowing queries -------------------------------------------------

    async def _country_by_code(self, country_code: str) -> Location | None:
        """Resolve the canonical country for one ISO-style code, if any.

        The statement is assembled from static module constants only; every
        externally-derived value is a bound parameter.
        """
        result = await self._session.execute(
            text(_COUNTRY_BY_CODE_SQL), {"country_code": country_code}
        )
        row = result.mappings().first()
        return None if row is None else _location_from_row(row)

    async def _resolve_admin_context(
        self, claim: GeographicClaim
    ) -> Location | None | CanonicalLocationResolution:
        """Resolve the claim's administrative context when admin fields exist.

        Returns the unique administrative Location when the claim supplies
        admin fields that resolve exactly; a resolution verdict when the admin
        narrowing is itself ambiguous or unresolvable; or ``None`` when the
        claim supplies no admin fields (city narrowed by country only).
        """
        if claim.administrative_area is None and claim.administrative_area_code is None:
            return None
        candidates = await self._administrative_candidates(claim)
        if not candidates:
            return unresolvable_result("unknown_administrative_area")
        if len(candidates) > 1:
            return ambiguous_result(
                [
                    LocationCandidate(location=location, matched_fields=fields)
                    for location, fields in candidates
                ],
                reason_code="multiple_candidates",
            )
        return candidates[0][0]

    async def _administrative_candidates(
        self, claim: GeographicClaim
    ) -> list[tuple[Location, tuple[str, ...]]]:
        """Narrow administrative-area candidates within the claimed country.

        Matched-field reasoning: the claim's explicit administrative code OR
        administrative name (inside the country) participate in the narrowing;
        the code matches either admin level deterministically.
        """
        assert claim.country_code is not None
        result = await self._session.execute(
            text(_ADMIN_CANDIDATES_SQL),
            {
                "country_code": claim.country_code,
                "admin_code": claim.administrative_area_code,
                "admin_name": claim.administrative_area,
                "candidate_limit": CANDIDATE_LIMIT + 1,
            },
        )
        matched: tuple[str, ...]
        if claim.administrative_area is not None:
            matched = ("administrative_area_name",)
        else:
            matched = ("administrative_area_code",)
        return [(_location_from_row(row), matched) for row in result.mappings().all()]

    async def _city_candidates(
        self,
        claim: GeographicClaim,
        admin_context: Location | None,
    ) -> list[tuple[Location, tuple[str, ...]]]:
        """Narrow city candidates within the claim's country/admin context."""
        assert claim.country_code is not None
        assert claim.city is not None
        params: dict[str, object] = {
            "country_code": claim.country_code,
            "city_name": claim.city,
            "admin1": admin_context.admin1_code if admin_context is not None else None,
            "admin2": admin_context.admin2_code if admin_context is not None else None,
            "candidate_limit": CANDIDATE_LIMIT + 1,
        }
        statement = (
            _CITY_WITH_ADMIN_CONTEXT_SQL
            if admin_context is not None
            else _CITY_CANDIDATES_SQL
        )
        result = await self._session.execute(text(statement), params)
        return [
            (_location_from_row(row), ("city_name",)) for row in result.mappings().all()
        ]

    # -- decision ----------------------------------------------------------

    async def _decide(
        self,
        claim: GeographicClaim,
        candidates: list[tuple[Location, tuple[str, ...]]],
        claim_fields: tuple[str, ...],
    ) -> CanonicalLocationResolution:
        """Return resolved/ambiguous over equally-valued candidates.

        A unique candidate resolves; multiple candidates with coordinates are
        disambiguated by boundary-inclusive containment (``ST_Covers``)
        against the candidate's polygon (cities use their admin parent
        polygon); anything else is explicit ambiguity.
        """
        ordered = sorted(candidates, key=lambda pair: candidate_sort_key(pair[0]))
        if len(ordered) == 1:
            location, matched = ordered[0]
            return resolved_result(
                location,
                reason_code="exact_semantic_match",
                matched_fields=claim_fields,
            )
        if claim.latitude is None or claim.longitude is None:
            return ambiguous_result(
                [
                    LocationCandidate(location=loc, matched_fields=fields)
                    for loc, fields in ordered
                ],
                reason_code="multiple_candidates",
            )
        covering = await self._covering_candidates(claim, ordered)
        if covering:
            covering_locations = [pair[0] for pair in covering]
            if len(covering) == 1:
                return resolved_result(
                    covering_locations[0],
                    reason_code="containment_disambiguation",
                    matched_fields=claim_fields,
                )
            return ambiguous_result(
                [
                    LocationCandidate(location=loc, matched_fields=fields)
                    for loc, fields in covering
                ],
                reason_code="competing_boundary_coverage",
            )
        return ambiguous_result(
            [
                LocationCandidate(location=loc, matched_fields=fields)
                for loc, fields in ordered
            ],
            reason_code="multiple_candidates",
        )

    async def _covering_candidates(
        self,
        claim: GeographicClaim,
        candidates: list[tuple[Location, tuple[str, ...]]],
    ) -> list[tuple[Location, tuple[str, ...]]]:
        """Return candidates whose containing polygon covers the claim point.

        Containers: the candidate's own polygon for country/administrative
        candidates and the candidate's admin-parent polygon for city
        candidates (a city geometry is a Point, so the administrative polygon
        is the meaningful container). Coverage is boundary-inclusive
        ``ST_Covers`` guarded by the ``&&`` bounding-box pre-filter so the
        GiST index is eligible; candidates without spatial state simply
        cannot be confirmed by containment and are excluded.
        """
        assert claim.latitude is not None and claim.longitude is not None
        if not candidates:
            return []
        pair_by_id: dict[UUID, tuple[Location, tuple[str, ...]]] = {}
        area_pairs: list[tuple[Location, tuple[str, ...]]] = []
        city_pairs: list[tuple[Location, tuple[str, ...]]] = []
        for pair in candidates:
            location = pair[0]
            if location.id is not None:
                pair_by_id[location.id] = pair
            if location.type is LocationType.CITY:
                city_pairs.append(pair)
            elif location.geometry is not None:
                area_pairs.append(pair)

        covering: list[tuple[Location, tuple[str, ...]]] = []
        area_ids = [pair[0].id for pair in area_pairs if pair[0].id is not None]
        if area_ids:
            covered = await self._ids_covered_by_point(area_ids, claim)
            covering.extend(pair for pair in area_pairs if pair[0].id in covered)

        parent_ids: list[UUID] = []
        for location, _ in city_pairs:
            if (
                location.parent_location_id is not None
                and location.parent_location_id not in parent_ids
            ):
                parent_ids.append(location.parent_location_id)
        if parent_ids:
            covered_parents = await self._ids_covered_by_point(parent_ids, claim)
            parent_locations = await self._locations_by_ids(covered_parents)
            parent_ids_of_covering: set[UUID] = set()
            for parent in parent_locations:
                if parent.id is not None:
                    parent_ids_of_covering.add(parent.id)
            covering.extend(
                pair
                for pair in city_pairs
                if pair[0].parent_location_id in parent_ids_of_covering
            )
        return covering

    async def _ids_covered_by_point(
        self, location_ids: list[UUID], claim: GeographicClaim
    ) -> set[UUID]:
        """Return the Location ids whose polygon covers the claim point.

        Boundary-inclusive ``ST_Covers`` with an explicit ``&&`` bounding-box
        pre-filter so PostgreSQL can use ``location_geometry_gist_idx`` for
        the containment candidate selection (the concrete PR 26B spatial
        path; ``EXPLAIN`` coverage lives in the integration matrix).
        """
        assert claim.latitude is not None and claim.longitude is not None
        statement = text(
            """
            SELECT l.id FROM ati.location l
            WHERE l.id IN :location_ids
              AND l.geometry && ST_SetSRID(ST_Point(:longitude, :latitude), 4326)
              AND ST_Covers(
                  l.geometry, ST_SetSRID(ST_Point(:longitude, :latitude), 4326))
            """
        ).bindparams(bindparam("location_ids", expanding=True))
        result = await self._session.execute(
            statement,
            {
                "location_ids": location_ids,
                "longitude": claim.longitude,
                "latitude": claim.latitude,
            },
        )
        return {row[0] for row in result.all()}

    async def _locations_by_ids(self, location_ids: set[UUID]) -> list[Location]:
        """Fetch bounded canonical Locations by their identifiers."""
        if not location_ids:
            return []
        statement = text(_LOCATIONS_BY_IDS_SQL).bindparams(
            bindparam("location_ids", expanding=True)
        )
        result = await self._session.execute(
            statement, {"location_ids": list(location_ids)}
        )
        return [_location_from_row(row) for row in result.mappings().all()]
