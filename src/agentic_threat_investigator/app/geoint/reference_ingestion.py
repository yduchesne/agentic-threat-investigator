# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical geography reference ingestion service (PR 26B).

One deterministic ingestion path for canonical country/administrative-area/
city reference records. Responsibilities:

1. validate the complete batch before any mutation where practical
   (hierarchy structure, shape, and spatial input syntax fail closed);
2. process deterministically in parent-before-child order, so parents always
   exist before a child is persisted, independent of corpus input order;
3. derive deterministic UUIDv5 canonical identities from ATI canonical
   identity (never from external source identifiers);
4. route exclusively through the reference Location upsert
   (``ati.upsert_reference_location``, SQL API v0023) which owns spatial
   validity, reference enrichment, version allocation, and race safety;
5. return bounded ingestion statistics.

The whole batch executes in one UnitOfWork transaction: any rejected record
rolls back the entire batch, so a malformed corpus can never leave a partial
inconsistent hierarchy.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from uuid import UUID

from agentic_threat_investigator.app.geoint.canonicalization import (
    CanonicalReferenceLocation,
    IdentityTuple,
    canonical_centroid_ewkt,
    canonical_geometry_ewkt,
    parent_identity,
    reference_identity,
    serialize_reference_location,
    validate_reference_hierarchy,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvalidReferenceHierarchyError,
    LocationReferenceOutcome,
    UnitOfWork,
)
from agentic_threat_investigator.domain.geo_reference import GeographicReferenceRecord
from agentic_threat_investigator.domain.geoint import Location, LocationType


@dataclass(frozen=True)
class ReferenceIngestionStatistics:
    """Bounded outcome counters for one canonical corpus ingestion run.

    ``conflicts`` and ``rejected`` are part of the documented outcome
    algebra; under PR 26B's fail-closed canonical-corpus policy any
    conflicting or malformed record *raises* and rolls back the whole
    batch, so both counters are zero on every successful run. They remain
    first-class so a future per-record policy can count-and-continue
    without changing the result type.
    """

    created: int = 0
    enriched: int = 0
    unchanged: int = 0
    conflicts: int = 0
    rejected: int = 0

    def total(self) -> int:
        """Return every processed record (outcome classes are disjoint)."""
        return (
            self.created
            + self.enriched
            + self.unchanged
            + self.conflicts
            + self.rejected
        )


def _record_key(record: GeographicReferenceRecord) -> tuple[object, ...]:
    """Return the deterministic parent-before-child processing order key.

    Countries first, then administrative areas (all admin1 rows before any
    admin2 row, since admin codes are non-empty when present), then cities;
    a stable canonical-name/admin-code tie-breaker keeps the order total.
    """
    if record.location_type is LocationType.COUNTRY:
        return (0, "", "country", record.canonical_name, record.admin1_code or "")
    if record.location_type is LocationType.ADMINISTRATIVE_AREA:
        return (
            1,
            record.admin2_code or "",
            "admin",
            record.canonical_name,
            record.admin1_code or "",
        )
    return (2, "", "city", record.canonical_name, record.admin1_code or "")


def _to_location(canonical: CanonicalReferenceLocation) -> Location:
    """Map one canonical serialization onto the domain Location."""
    return Location(
        id=canonical.location_id,
        type=canonical.location_type,
        name=canonical.name,
        canonical_name=canonical.canonical_name,
        country_code=canonical.country_code,
        admin1_code=canonical.admin1_code,
        admin2_code=canonical.admin2_code,
        parent_location_id=canonical.parent_location_id,
        geometry=canonical.geometry,
        centroid=canonical.centroid,
    )


class ReferenceIngestionService:
    """Ingest one deterministic canonical reference corpus batch."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork]) -> None:
        """Bind the short-transaction UnitOfWork factory."""
        self._uow_factory = uow_factory

    async def ingest(
        self, records: Sequence[GeographicReferenceRecord]
    ) -> ReferenceIngestionStatistics:
        """Validate and ingest one complete reference batch atomically.

        Raises fail-closed (``InvalidReferenceGeometryError``,
        ``InvalidReferenceHierarchyError``, ``CanonicalLocationConflictError``,
        ``UnsupportedReferenceRecordError``) without partial mutation when any
        record violates the deterministic reference contract.
        """
        ordered: list[GeographicReferenceRecord] = list(records)
        validate_reference_hierarchy(ordered)
        # Pre-canonicalize spatial input syntax before any mutation so a
        # malformed record fails the batch immediately.
        for record in ordered:
            canonical_geometry_ewkt(record.geometry, location_type=record.location_type)
            canonical_centroid_ewkt(record.centroid)

        batch_identities = {reference_identity(record) for record in ordered}
        needed_identities = batch_identities | {
            parent_identity(record.parent)
            for record in ordered
            if record.parent is not None
        }
        ordered_records = sorted(ordered, key=_record_key)

        created = enriched = unchanged = conflicts = rejected = 0
        resolved_ids: dict[IdentityTuple, UUID] = {}
        async with self._uow_factory() as uow:
            # Resolve every identity that may be used as a parent (including
            # identities that pre-exist the batch, e.g. PR 26A Locations).
            for identity in sorted(needed_identities):
                existing = await uow.locations.get_by_identity(
                    location_type=identity[0],
                    country_code=identity[1],
                    admin1_code=identity[2] or None,
                    admin2_code=identity[3] or None,
                    canonical_name=identity[4],
                )
                if existing is not None and existing.id is not None:
                    resolved_ids[identity] = existing.id
            for record in ordered_records:
                parent_id: UUID | None = None
                if record.parent is not None:
                    key = parent_identity(record.parent)
                    parent_id = resolved_ids.get(key)
                    if parent_id is None:
                        raise InvalidReferenceHierarchyError(
                            f"parent is not available in the database or corpus: "
                            f"{record.parent.location_type.value} "
                            f"{record.parent.canonical_name} "
                            f"{record.parent.country_code}"
                        )
                canonical = serialize_reference_location(
                    record, parent_location_id=parent_id
                )
                written = await uow.locations.upsert_reference(_to_location(canonical))
                outcome = written.outcome
                if written.location.id is not None:
                    resolved_ids[reference_identity(record)] = written.location.id
                if outcome is LocationReferenceOutcome.CREATED:
                    created += 1
                elif outcome is LocationReferenceOutcome.ENRICHED:
                    enriched += 1
                elif outcome is LocationReferenceOutcome.UNCHANGED:
                    unchanged += 1
                else:
                    conflicts += 1
        return ReferenceIngestionStatistics(
            created=created,
            enriched=enriched,
            unchanged=unchanged,
            conflicts=conflicts,
            rejected=rejected,
        )
