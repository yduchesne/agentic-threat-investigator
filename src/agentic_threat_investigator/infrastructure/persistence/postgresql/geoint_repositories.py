# SPDX-License-Identifier: AGPL-3.0-only
"""Thin PostgreSQL adapters for the PR 26 GEOINT persistence contracts.

Every GEOINT mutation routes through versioned SQL API stored functions:
PR 26A (``ati.upsert_location``, ``ati.append_entity_location_observation``,
``ati.create_geo_resolution``, SQL API v0021/v0022) and the PR 26B canonical
reference/spatial path (``ati.upsert_reference_location``, SQL API v0023).
PostgreSQL owns canonical identity, spatial validity, provenance validation,
version allocation, reference enrichment, and current-state reconciliation.
These adapters never commit, never allocate versions, and never reconcile
EntityLocation in Python. Reads use direct SELECT only for the approved
exact/bounded lookups; PR 26B spatial reads select ``ST_AsEWKT`` so the
domain sees the documented EWKT text representation, never PostGIS objects.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    CanonicalLocationConflictError,
    EntityLocationObservationDuplicateError,
    EntityLocationObservationRepository,
    EntityLocationRepository,
    GeoEntityNotFoundError,
    GeoEvidenceNotFoundError,
    GeoEvidenceSubjectMismatchError,
    GeoEvidenceTypeError,
    GeoInvalidInputError,
    GeoLocationNotFoundError,
    GeoResolutionClaimantMismatchError,
    GeoResolutionDuplicateStateError,
    GeoResolutionInvalidTransitionError,
    GeoResolutionLeaseExpiredError,
    GeoResolutionNotFoundError,
    GeoResolutionRepository,
    GeoResolutionRetryExhaustedError,
    GeoResolutionTerminalReplayConflictError,
    GeoResolutionVersionConflictError,
    InvalidReferenceGeometryError,
    InvalidReferenceHierarchyError,
    LocationIdentityConflictError,
    LocationReferenceOutcome,
    LocationRepository,
    LocationWriteResult,
    UnsupportedReferenceRecordError,
)
from agentic_threat_investigator.domain.geoint import (
    EntityLocation,
    EntityLocationObservation,
    GeoResolution,
    GeoResolutionStatus,
    Location,
    LocationPrecision,
    LocationType,
)

from .errors import (
    SQLSTATE_GEOLOCATION_ENTITY_NOT_FOUND,
    SQLSTATE_GEOLOCATION_EVIDENCE_NOT_FOUND,
    SQLSTATE_GEOLOCATION_EVIDENCE_SUBJECT_MISMATCH,
    SQLSTATE_GEOLOCATION_EVIDENCE_TYPE_INVALID,
    SQLSTATE_GEOLOCATION_INVALID_INPUT,
    SQLSTATE_GEOLOCATION_LOCATION_IDENTITY_INCOMPATIBLE,
    SQLSTATE_GEOLOCATION_LOCATION_NOT_FOUND,
    SQLSTATE_GEOLOCATION_OBSERVATION_DUPLICATE,
    SQLSTATE_GEOLOCATION_RESOLUTION_DUPLICATE_STATE,
    SQLSTATE_GEORESOLUTION_CLAIMANT_MISMATCH,
    SQLSTATE_GEORESOLUTION_INVALID_TRANSITION,
    SQLSTATE_GEORESOLUTION_LEASE_EXPIRED,
    SQLSTATE_GEORESOLUTION_NOT_FOUND,
    SQLSTATE_GEORESOLUTION_RETRY_EXHAUSTED,
    SQLSTATE_GEORESOLUTION_STALE_VERSION,
    SQLSTATE_GEORESOLUTION_TERMINAL_REPLAY_CONFLICT,
    SQLSTATE_REFERENCE_CANONICAL_CONFLICT,
    SQLSTATE_REFERENCE_GEOMETRY_INVALID,
    SQLSTATE_REFERENCE_HIERARCHY_INVALID,
    SQLSTATE_REFERENCE_RECORD_UNSUPPORTED,
    sqlstate,
)
from .models import (
    EntityLocationObservationRow,
    EntityLocationRow,
    GeoResolutionRow,
)

# Explicit read projection for canonical Locations. PR 26B spatial columns are
# never mapped into SQLAlchemy rows; reads select ST_AsEWKT so the domain
# receives the documented EWKT text representation (SRID=4326;...) without
# leaking PostGIS/psycopg objects, and NULL spatial state round-trips as NULL.
_LOCATION_SELECT = text(
    """
    SELECT id, location_type, name, canonical_name, country_code,
           admin1_code, admin2_code, parent_location_id, version,
           created_at, updated_at,
           ST_AsEWKT(geometry) AS geometry_ewkt,
           ST_AsEWKT(centroid) AS centroid_ewkt
    FROM ati.location
    """
)


def _location(row: Any) -> Location:
    """Map an EWKT-aware Location row to its domain model."""
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


def _observation(row: EntityLocationObservationRow) -> EntityLocationObservation:
    """Map an observation row to its immutable domain model."""
    return EntityLocationObservation(
        id=row.id,
        entity_id=row.entity_id,
        location_id=row.location_id,
        evidence_observation_id=row.evidence_observation_id,
        precision=LocationPrecision(row.precision),
        observed_at=row.observed_at,
        retrieved_at=row.retrieved_at,
        resolved_at=row.resolved_at,
        resolution_method=row.resolution_method,
        version=row.version,
        created_at=row.created_at,
    )


def _entity_location(row: EntityLocationRow) -> EntityLocation:
    """Map a current-state row to its domain model."""
    return EntityLocation(
        entity_id=row.entity_id,
        location_id=row.location_id,
        precision=LocationPrecision(row.precision),
        latest_observation_id=row.latest_observation_id,
        first_observed_at=row.first_observed_at,
        last_observed_at=row.last_observed_at,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _resolution(row: Any) -> GeoResolution:
    """Map a GeoResolution row to its domain model.

    Accepts both SQLAlchemy ORM rows and stored-function ``RowMapping``
    results (SQL API v0024 returns authoritative rows as mappings), both of
    which expose the same attribute surface.
    """
    return GeoResolution(
        id=row.id,
        entity_id=row.entity_id,
        evidence_observation_id=row.evidence_observation_id,
        status=GeoResolutionStatus(row.status),
        attempt_count=row.attempt_count,
        next_attempt_at=row.next_attempt_at,
        claimed_by=row.claimed_by,
        lease_expires_at=row.lease_expires_at,
        resolved_location_id=row.resolved_location_id,
        last_error_code=row.last_error_code,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _map_location_error(error: DBAPIError) -> None:
    """Map a versioned SQL API SQLSTATE to the typed Location error, if known."""
    state = sqlstate(error)
    if state == SQLSTATE_GEOLOCATION_LOCATION_NOT_FOUND:
        raise GeoLocationNotFoundError() from error
    if state == SQLSTATE_GEOLOCATION_LOCATION_IDENTITY_INCOMPATIBLE:
        raise LocationIdentityConflictError() from error
    if state == SQLSTATE_GEOLOCATION_INVALID_INPUT:
        detail = getattr(getattr(error, "orig", None), "diag", None)
        message = getattr(detail, "message_primary", None) or "invalid location input"
        raise GeoInvalidInputError(message) from error
    raise


def _map_resolution_error(error: DBAPIError, *, resolution_id: UUID) -> None:
    """Map a SQL API v0024 lifecycle SQLSTATE to the typed resolution error.

    Provenance SQLSTATEs (U26A1-U26A6) are mapped at the call site where
    the exact identities are known; this helper owns the U26C lifecycle
    codes and the shared invalid-input state.
    """
    state = sqlstate(error)
    detail = getattr(getattr(error, "orig", None), "diag", None)
    message = getattr(detail, "message_primary", None)
    if state == SQLSTATE_GEORESOLUTION_NOT_FOUND:
        raise GeoResolutionNotFoundError(resolution_id) from error
    if state == SQLSTATE_GEORESOLUTION_INVALID_TRANSITION:
        raise GeoResolutionInvalidTransitionError(resolution_id) from error
    if state == SQLSTATE_GEORESOLUTION_STALE_VERSION:
        raise GeoResolutionVersionConflictError(resolution_id, 0) from error
    if state == SQLSTATE_GEORESOLUTION_CLAIMANT_MISMATCH:
        raise GeoResolutionClaimantMismatchError(resolution_id) from error
    if state == SQLSTATE_GEORESOLUTION_LEASE_EXPIRED:
        raise GeoResolutionLeaseExpiredError(resolution_id) from error
    if state == SQLSTATE_GEORESOLUTION_RETRY_EXHAUSTED:
        raise GeoResolutionRetryExhaustedError(resolution_id) from error
    if state == SQLSTATE_GEORESOLUTION_TERMINAL_REPLAY_CONFLICT:
        raise GeoResolutionTerminalReplayConflictError(resolution_id) from error
    if state == SQLSTATE_GEOLOCATION_INVALID_INPUT:
        raise GeoInvalidInputError(message or "invalid geo resolution input") from error
    raise


def _map_reference_error(error: DBAPIError) -> None:
    """Map a SQL API v0023 SQLSTATE to the typed reference error, if known."""
    state = sqlstate(error)
    detail = getattr(getattr(error, "orig", None), "diag", None)
    message = getattr(detail, "message_primary", None)
    if state == SQLSTATE_REFERENCE_GEOMETRY_INVALID:
        raise InvalidReferenceGeometryError(message) from error
    if state == SQLSTATE_REFERENCE_HIERARCHY_INVALID:
        raise InvalidReferenceHierarchyError(message) from error
    if state == SQLSTATE_REFERENCE_CANONICAL_CONFLICT:
        raise CanonicalLocationConflictError() from error
    if state == SQLSTATE_REFERENCE_RECORD_UNSUPPORTED:
        raise UnsupportedReferenceRecordError(message) from error
    raise


class PostgresLocationRepository(LocationRepository):
    """Persist canonical Locations through the active transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _fetch(
        self, where_sql: str, where_params: dict[str, object]
    ) -> Location | None:
        """Select one EWKT-aware canonical Location row with the given predicate."""
        result = await self.session.execute(
            text(f"{_LOCATION_SELECT.text} WHERE {where_sql} LIMIT 1"), where_params
        )
        row = result.mappings().first()
        return None if row is None else _location(row)

    async def get_by_id(self, location_id: UUID) -> Location | None:
        """Return the canonical Location with the given identifier, if any."""
        return await self._fetch("id = :location_id", {"location_id": location_id})

    async def get_by_identity(
        self,
        *,
        location_type: str,
        country_code: str,
        admin1_code: str | None,
        admin2_code: str | None,
        canonical_name: str,
    ) -> Location | None:
        """Find a canonical Location by its approved identity tuple.

        Null admin components are normalized through the same COALESCE
        expression the canonical identity unique index uses, so callers never
        distinguish empty-string from NULL themselves.
        """
        return await self._fetch(
            """
            location_type = :location_type
              AND country_code = :country_code
              AND COALESCE(admin1_code, '') = COALESCE(:admin1_code, '')
              AND COALESCE(admin2_code, '') = COALESCE(:admin2_code, '')
              AND canonical_name = :canonical_name
            """,
            {
                "location_type": location_type,
                "country_code": country_code,
                "admin1_code": admin1_code,
                "admin2_code": admin2_code,
                "canonical_name": canonical_name,
            },
        )

    async def upsert(self, location: Location) -> Location:
        """Create or reuse the canonical Location through the SQL function.

        The database owns canonical-identity resolution, race-safe creation,
        and version allocation; this adapter performs no Python-side version
        allocation and never self-commits. The PR 26A path carries no spatial
        state.
        """
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, created FROM ati.upsert_location(
                        :id, :location_type, :name, :canonical_name,
                        :country_code, :admin1_code, :admin2_code,
                        :parent_location_id)
                """),
                {
                    "id": location.id,
                    "location_type": location.type.value,
                    "name": location.name,
                    "canonical_name": location.canonical_name,
                    "country_code": location.country_code,
                    "admin1_code": location.admin1_code,
                    "admin2_code": location.admin2_code,
                    "parent_location_id": location.parent_location_id,
                },
            )
        except DBAPIError as error:
            _map_location_error(error)
        written_id, _version, _created = result.one()
        fetched = await self.get_by_id(written_id)
        if (
            fetched is None
        ):  # pragma: no cover - the function and transaction are atomic
            raise RuntimeError("location write returned no row")
        return fetched

    async def upsert_reference(self, location: Location) -> LocationWriteResult:
        """Create/enrich/reuse one canonical reference/spatial Location (PR 26B).

        Routes exclusively through ``ati.upsert_reference_location`` (SQL API
        v0023), serializing the EWKT spatial state carried by the domain
        ``Location``. The database owns spatial validity, reference
        enrichment, version allocation, and race safety; the adapter maps the
        deterministic outcome and typed SQLSTATEs and never commits.
        """
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, outcome FROM ati.upsert_reference_location(
                        :id, :location_type, :name, :canonical_name,
                        :country_code, :admin1_code, :admin2_code,
                        :parent_location_id, :geometry, :centroid)
                """),
                {
                    "id": location.id,
                    "location_type": location.type.value,
                    "name": location.name,
                    "canonical_name": location.canonical_name,
                    "country_code": location.country_code,
                    "admin1_code": location.admin1_code,
                    "admin2_code": location.admin2_code,
                    "parent_location_id": location.parent_location_id,
                    "geometry": location.geometry,
                    "centroid": location.centroid,
                },
            )
        except DBAPIError as error:
            _map_reference_error(error)
        written_id, _version, outcome_value = result.one()
        fetched = await self.get_by_id(written_id)
        if (
            fetched is None
        ):  # pragma: no cover - the function and transaction are atomic
            raise RuntimeError("reference location write returned no row")
        return LocationWriteResult(
            location=fetched, outcome=LocationReferenceOutcome(outcome_value)
        )


class PostgresEntityLocationRepository(EntityLocationRepository):
    """Read-only repository for current materialized EntityLocation state."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_entity_id(self, entity_id: UUID) -> EntityLocation | None:
        """Return the current EntityLocation of one Entity, if any."""
        row = await self.session.get(EntityLocationRow, entity_id)
        return None if row is None else _entity_location(row)


class PostgresEntityLocationObservationRepository(EntityLocationObservationRepository):
    """Append and read immutable EntityLocationObservation rows."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, observation_id: UUID) -> EntityLocationObservation | None:
        """Return an immutable observation by its identity."""
        row = await self.session.get(EntityLocationObservationRow, observation_id)
        return None if row is None else _observation(row)

    async def list_for_entity(
        self,
        entity_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EntityLocationObservation]:
        """Return bounded observations for one Entity in deterministic order.

        Ordering is newest-first by retrieval time with a stable UUID
        tie-breaker, matching the Evidence/RelationshipObservation analyst
        listing convention. ``limit`` and ``offset`` must be non-negative.
        """
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        limit = min(limit, 1000)
        result = await self.session.execute(
            select(EntityLocationObservationRow)
            .where(EntityLocationObservationRow.entity_id == entity_id)
            .order_by(
                EntityLocationObservationRow.retrieved_at.desc(),
                EntityLocationObservationRow.id.asc(),
            )
            .limit(limit)
            .offset(offset)
        )
        return [_observation(row) for row in result.scalars().all()]

    async def append(
        self, observation: EntityLocationObservation
    ) -> EntityLocationObservation:
        """Append one immutable observation and reconcile current state.

        The versioned stored function validates Entity visibility, Location
        and Evidence existence, the GEOLOCATION Evidence type, the exact
        Evidence subject, and reconciles the current EntityLocation atomically
        in the same transaction. No update/delete path exists.
        """
        try:
            await self.session.execute(
                text("""
                    SELECT id, version FROM ati.append_entity_location_observation(
                        :id, :entity_id, :location_id, :evidence_observation_id,
                        :precision,
                        :observed_at, :retrieved_at, :resolved_at,
                        :resolution_method)
                """),
                {
                    "id": observation.id,
                    "entity_id": observation.entity_id,
                    "location_id": observation.location_id,
                    "evidence_observation_id": observation.evidence_observation_id,
                    "precision": observation.precision.value,
                    "observed_at": observation.observed_at,
                    "retrieved_at": observation.retrieved_at,
                    "resolved_at": observation.resolved_at,
                    "resolution_method": observation.resolution_method,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_GEOLOCATION_ENTITY_NOT_FOUND:
                raise GeoEntityNotFoundError(observation.entity_id) from error
            if state == SQLSTATE_GEOLOCATION_LOCATION_NOT_FOUND:
                raise GeoLocationNotFoundError(observation.location_id) from error
            if state == SQLSTATE_GEOLOCATION_EVIDENCE_NOT_FOUND:
                raise GeoEvidenceNotFoundError(
                    observation.evidence_observation_id
                ) from error
            if state == SQLSTATE_GEOLOCATION_EVIDENCE_TYPE_INVALID:
                raise GeoEvidenceTypeError(
                    observation.evidence_observation_id
                ) from error
            if state == SQLSTATE_GEOLOCATION_EVIDENCE_SUBJECT_MISMATCH:
                raise GeoEvidenceSubjectMismatchError(
                    observation.evidence_observation_id, observation.entity_id
                ) from error
            if state == SQLSTATE_GEOLOCATION_OBSERVATION_DUPLICATE:
                raise EntityLocationObservationDuplicateError(observation.id) from error
            if state == SQLSTATE_GEOLOCATION_INVALID_INPUT:
                detail = getattr(getattr(error, "orig", None), "diag", None)
                message = (
                    getattr(detail, "message_primary", None) or "invalid observation"
                )
                raise GeoInvalidInputError(message) from error
            raise
        row = await self.session.get(EntityLocationObservationRow, observation.id)
        if row is None:  # pragma: no cover - the function and transaction are atomic
            raise RuntimeError("observation write returned no row")
        return _observation(row)


class PostgresGeoResolutionRepository(GeoResolutionRepository):
    """Persist and progress GeoResolution work through the active transaction.

    Lifecycle mutations (claim, resolved/unresolvable completion, bounded
    retry/failure) route exclusively through SQL API v0024 stored functions;
    this adapter maps the typed SQLSTATEs and never commits.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, resolution_id: UUID) -> GeoResolution | None:
        """Return one GeoResolution work record by its identity."""
        row = await self.session.get(GeoResolutionRow, resolution_id)
        return None if row is None else _resolution(row)

    async def get_by_entity_evidence(
        self, entity_id: UUID, evidence_observation_id: UUID
    ) -> GeoResolution | None:
        """Return the GeoResolution for one Entity/EvidenceObservation pair."""
        result = await self.session.execute(
            select(GeoResolutionRow).where(
                GeoResolutionRow.entity_id == entity_id,
                GeoResolutionRow.evidence_observation_id == evidence_observation_id,
            )
        )
        row = result.scalar_one_or_none()
        return None if row is None else _resolution(row)

    async def create_pending(self, resolution: GeoResolution) -> GeoResolution:
        """Create (or idempotently reuse) the initial PENDING work record.

        The database validates the Entity/Evidence binding and the GEOLOCATION
        Evidence type, owns race safety on the unique pair, and rejects a
        duplicate pair that is no longer in the initial pending shape.
        """
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, created FROM ati.create_geo_resolution(
                        :id, :entity_id, :evidence_observation_id)
                """),
                {
                    "id": resolution.id,
                    "entity_id": resolution.entity_id,
                    "evidence_observation_id": resolution.evidence_observation_id,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_GEOLOCATION_ENTITY_NOT_FOUND:
                raise GeoEntityNotFoundError(resolution.entity_id) from error
            if state == SQLSTATE_GEOLOCATION_EVIDENCE_NOT_FOUND:
                raise GeoEvidenceNotFoundError(
                    resolution.evidence_observation_id
                ) from error
            if state == SQLSTATE_GEOLOCATION_EVIDENCE_TYPE_INVALID:
                raise GeoEvidenceTypeError(
                    resolution.evidence_observation_id
                ) from error
            if state == SQLSTATE_GEOLOCATION_EVIDENCE_SUBJECT_MISMATCH:
                raise GeoEvidenceSubjectMismatchError(
                    resolution.evidence_observation_id, resolution.entity_id
                ) from error
            if state == SQLSTATE_GEOLOCATION_RESOLUTION_DUPLICATE_STATE:
                raise GeoResolutionDuplicateStateError(
                    resolution.entity_id, resolution.evidence_observation_id
                ) from error
            raise
        written_id, _version, _created = result.one()
        row = await self.session.get(GeoResolutionRow, written_id)
        if row is None:  # pragma: no cover - the function and transaction are atomic
            raise RuntimeError("geo resolution write returned no row")
        return _resolution(row)

    @staticmethod
    def _resolution_rows(result: Any) -> list[GeoResolution]:
        """Deserialize authoritative lifecycle rows from a stored function."""
        return [_resolution(row) for row in result.mappings().all()]

    async def claim_batch(
        self,
        *,
        claimed_by: str,
        limit: int,
        lease_seconds: int,
        max_attempts: int,
    ) -> list[GeoResolution]:
        """Claim a bounded batch of eligible work in the active transaction.

        Routes through ``ati.claim_geo_resolutions`` (SQL API v0024), which
        performs the bounded ``FOR UPDATE SKIP LOCKED`` selection, persists
        the claimant/lease/attempt/version state, and returns the
        authoritative claimed rows. The caller's UnitOfWork is the commit
        boundary; repositories never commit.
        """
        result = await self.session.execute(
            text("""
                SELECT id, entity_id, evidence_id, status, attempt_count,
                       next_attempt_at, claimed_by, lease_expires_at,
                       resolved_location_id, last_error_code, version,
                       created_at, updated_at
                  FROM ati.claim_geo_resolutions(
                       :claimed_by, :claim_limit, :lease_seconds,
                       :max_attempts)
            """),
            {
                "claimed_by": claimed_by,
                "claim_limit": limit,
                "lease_seconds": lease_seconds,
                "max_attempts": max_attempts,
            },
        )
        return self._resolution_rows(result)

    async def complete_resolved(
        self,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        observation: EntityLocationObservation,
    ) -> GeoResolution:
        """Atomically complete one claimed row as RESOLVED (SQL API v0024).

        The single versioned stored function validates status/version/
        claimant/live lease and the exact Entity/Evidence/Location
        provenance, appends the immutable observation (idempotent under
        replay), reconciles the current EntityLocation, and terminates the
        work. A replay of the exact same successful completion is a no-op;
        any conflicting terminal replay is a typed error with no mutation.
        """
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, entity_id, evidence_observation_id, status,
                           attempt_count,
                           next_attempt_at, claimed_by, lease_expires_at,
                           resolved_location_id, last_error_code, version,
                           created_at, updated_at
                      FROM ati.complete_geo_resolution_resolved(
                           :resolution_id, :expected_version, :claimed_by,
                           :observation_id, :location_id, :precision,
                           :observed_at, :retrieved_at, :resolved_at,
                           :resolution_method)
                """),
                {
                    "resolution_id": resolution_id,
                    "expected_version": expected_version,
                    "claimed_by": claimed_by,
                    "observation_id": observation.id,
                    "location_id": observation.location_id,
                    "precision": observation.precision.value,
                    "observed_at": observation.observed_at,
                    "retrieved_at": observation.retrieved_at,
                    "resolved_at": observation.resolved_at,
                    "resolution_method": observation.resolution_method,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_GEOLOCATION_ENTITY_NOT_FOUND:
                raise GeoEntityNotFoundError(observation.entity_id) from error
            if state == SQLSTATE_GEOLOCATION_LOCATION_NOT_FOUND:
                raise GeoLocationNotFoundError(observation.location_id) from error
            if state == SQLSTATE_GEOLOCATION_EVIDENCE_NOT_FOUND:
                raise GeoEvidenceNotFoundError(
                    observation.evidence_observation_id
                ) from error
            if state == SQLSTATE_GEOLOCATION_EVIDENCE_TYPE_INVALID:
                raise GeoEvidenceTypeError(
                    observation.evidence_observation_id
                ) from error
            if state == SQLSTATE_GEOLOCATION_EVIDENCE_SUBJECT_MISMATCH:
                raise GeoEvidenceSubjectMismatchError(
                    observation.evidence_observation_id, observation.entity_id
                ) from error
            if state == SQLSTATE_GEOLOCATION_OBSERVATION_DUPLICATE:
                raise EntityLocationObservationDuplicateError(observation.id) from error
            _map_resolution_error(error, resolution_id=resolution_id)
        rows = result.mappings().all()
        if not rows:  # pragma: no cover - the function always returns one row
            raise RuntimeError("geo resolution completion returned no row")
        return _resolution(rows[0])

    async def complete_unresolvable(
        self,
        *,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        error_code: str,
    ) -> GeoResolution:
        """Terminate one claimed row as UNRESOLVABLE with a stable reason code.

        Routes through ``ati.complete_geo_resolution_unresolvable``: no
        observation and no EntityLocation mutation are created, the resolved
        Location stays NULL, and lease/retry state is cleared.
        """
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, entity_id, evidence_observation_id, status,
                           attempt_count,
                           next_attempt_at, claimed_by, lease_expires_at,
                           resolved_location_id, last_error_code, version,
                           created_at, updated_at
                      FROM ati.complete_geo_resolution_unresolvable(
                           :resolution_id, :expected_version, :claimed_by,
                           :error_code)
                """),
                {
                    "resolution_id": resolution_id,
                    "expected_version": expected_version,
                    "claimed_by": claimed_by,
                    "error_code": error_code,
                },
            )
        except DBAPIError as error:
            _map_resolution_error(error, resolution_id=resolution_id)
        rows = result.mappings().all()
        if not rows:  # pragma: no cover - the function always returns one row
            raise RuntimeError("geo resolution completion returned no row")
        return _resolution(rows[0])

    async def record_failure(
        self,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        error_code: str,
        *,
        retryable: bool,
        retry_base_seconds: float,
        retry_max_seconds: float,
        max_attempts: int,
    ) -> GeoResolution:
        """Record one bounded failure on the claimed row (SQL API v0024).

        A retryable failure with budget remaining returns the row to PENDING
        with a deterministic bounded backoff; exhaustion or a non-retryable
        failure terminates it as FAILED with no next attempt. The error code
        is a bounded machine code; exception text is never persisted.
        """
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, entity_id, evidence_observation_id, status,
                           attempt_count,
                           next_attempt_at, claimed_by, lease_expires_at,
                           resolved_location_id, last_error_code, version,
                           created_at, updated_at
                      FROM ati.record_geo_resolution_failure(
                           :resolution_id, :expected_version, :claimed_by,
                           :error_code, :retryable, :retry_base_seconds,
                           :retry_max_seconds, :max_attempts)
                """),
                {
                    "resolution_id": resolution_id,
                    "expected_version": expected_version,
                    "claimed_by": claimed_by,
                    "error_code": error_code,
                    "retryable": retryable,
                    "retry_base_seconds": retry_base_seconds,
                    "retry_max_seconds": retry_max_seconds,
                    "max_attempts": max_attempts,
                },
            )
        except DBAPIError as error:
            _map_resolution_error(error, resolution_id=resolution_id)
        rows = result.mappings().all()
        if not rows:  # pragma: no cover - the function always returns one row
            raise RuntimeError("geo resolution failure returned no row")
        return _resolution(rows[0])
