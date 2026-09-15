# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B reference ingestion service unit tests (in-memory repository).

Covers deterministic parent-before-child processing, canonical UUIDv5
identity pass-through, no-op re-imports, fail-closed pre-validation without
mutation, and input-order independence. The real PostgreSQL/PostGIS
behavior lives in the G26B-I integration matrix.
"""

from __future__ import annotations

from collections.abc import Callable
from types import TracebackType
from typing import cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.geoint.reference_ingestion import (
    ReferenceIngestionService,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvalidReferenceGeometryError,
    InvalidReferenceHierarchyError,
    LocationReferenceOutcome,
    LocationRepository,
    LocationWriteResult,
    UnitOfWork,
)
from agentic_threat_investigator.domain.geo_reference import (
    GeographicReferenceRecord,
    ReferenceParent,
)
from agentic_threat_investigator.domain.geoint import (
    Location,
    LocationType,
    canonical_location_uuid,
)

Identity = tuple[str, str, str, str, str]


def _identity(location: Location) -> Identity:
    """Return the canonical identity of one Location as normalized strings."""
    return (
        location.type.value,
        location.country_code,
        location.admin1_code or "",
        location.admin2_code or "",
        location.canonical_name,
    )


class FakeLocations(LocationRepository):
    """In-memory canonical Location repository with authoritative outcomes."""

    def __init__(self) -> None:
        """Start with an empty store and a call log."""
        self.store: dict[Identity, LocationWriteResult] = {}
        self.calls: list[Location] = []

    def _next_version(self) -> int:
        """Return the next ever-increasing version token (like the sequence)."""
        return (
            max((r.location.version or 0) for r in self.store.values()) + 1
            if self.store
            else 1
        )

    async def get_by_id(self, location_id: UUID) -> Location | None:
        """Return a stored Location by identifier."""
        for result in self.store.values():
            if result.location.id == location_id:
                return result.location
        return None

    async def get_by_identity(
        self,
        *,
        location_type: str,
        country_code: str,
        admin1_code: str | None,
        admin2_code: str | None,
        canonical_name: str,
    ) -> Location | None:
        """Return the stored canonical Location matching the identity tuple."""
        identity = (
            location_type,
            country_code,
            admin1_code or "",
            admin2_code or "",
            canonical_name,
        )
        result = self.store.get(identity)
        return None if result is None else result.location

    async def upsert(self, location: Location) -> Location:
        """Unused by the reference ingestion path; fail loudly if called."""
        raise AssertionError("upsert must not be used by reference ingestion")

    async def upsert_reference(self, location: Location) -> LocationWriteResult:
        """Persist with CREATED/UNCHANGED/ENRICHED deterministic semantics."""
        self.calls.append(location)
        identity = _identity(location)
        existing = self.store.get(identity)
        if existing is None:
            written = LocationWriteResult(
                location=location.model_copy(
                    update={
                        "id": location.id or uuid4(),
                        "version": self._next_version(),
                    }
                ),
                outcome=LocationReferenceOutcome.CREATED,
            )
            self.store[identity] = written
            return written
        previous = existing.location
        if (
            previous.name == location.name
            and previous.parent_location_id == location.parent_location_id
            and previous.geometry == location.geometry
            and previous.centroid == location.centroid
        ):
            return LocationWriteResult(
                location=previous, outcome=LocationReferenceOutcome.UNCHANGED
            )
        written = LocationWriteResult(
            location=location.model_copy(
                update={"id": previous.id, "version": self._next_version()}
            ),
            outcome=LocationReferenceOutcome.ENRICHED,
        )
        self.store[identity] = written
        return written


class FakeUnitOfWork:
    """In-memory transaction seam exposing the fake Location repository."""

    locations: LocationRepository

    def __init__(self, locations: FakeLocations) -> None:
        """Bind the fake repository."""
        self.locations = locations
        self.real_locations = locations

    async def __aenter__(self) -> "FakeUnitOfWork":
        """Serve as its own transaction boundary (no commit needed)."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Nothing to commit or roll back in memory."""


def _country(**overrides: object) -> GeographicReferenceRecord:
    """Build one US country record."""
    values: dict[str, object] = {
        "location_type": LocationType.COUNTRY,
        "name": "United States",
        "canonical_name": "United States",
        "country_code": "US",
    }
    values.update(overrides)
    return GeographicReferenceRecord.model_validate(values)


def _corpus() -> list[GeographicReferenceRecord]:
    """Return a small deterministic corpus (country -> admin -> two cities)."""
    country = _country()
    admin = GeographicReferenceRecord(
        location_type=LocationType.ADMINISTRATIVE_AREA,
        name="Washington",
        canonical_name="Washington",
        country_code="US",
        admin1_code="WA",
        parent=ReferenceParent(
            location_type=LocationType.COUNTRY,
            country_code="US",
            canonical_name="United States",
        ),
        geometry="SRID=4326;POLYGON((-125 45,-116 45,-116 49.5,-125 49.5,-125 45))",
    )
    seattle = GeographicReferenceRecord(
        location_type=LocationType.CITY,
        name="Seattle",
        canonical_name="Seattle",
        country_code="US",
        admin1_code="WA",
        parent=ReferenceParent(
            location_type=LocationType.ADMINISTRATIVE_AREA,
            country_code="US",
            admin1_code="WA",
            canonical_name="Washington",
        ),
        geometry="SRID=4326;POINT(-122.3321 47.6062)",
    )
    auburn = GeographicReferenceRecord(
        location_type=LocationType.CITY,
        name="Auburn",
        canonical_name="Auburn",
        country_code="US",
        admin1_code="WA",
        parent=ReferenceParent(
            location_type=LocationType.ADMINISTRATIVE_AREA,
            country_code="US",
            admin1_code="WA",
            canonical_name="Washington",
        ),
    )
    return [country, admin, seattle, auburn]


def _factory(locations: FakeLocations) -> Callable[[], UnitOfWork]:
    """Return a fake UoW factory typed as the application seam."""
    return cast(Callable[[], UnitOfWork], lambda: FakeUnitOfWork(locations))


@pytest.mark.asyncio
async def test_i01_parent_before_child_order_and_stats() -> None:
    """G26B-I01 countries -> admins -> cities; parents exist before children."""
    locations = FakeLocations()
    stats = await ReferenceIngestionService(_factory(locations)).ingest(_corpus())
    assert stats.created == 4
    assert stats.enriched == 0 and stats.unchanged == 0
    assert stats.conflicts == 0 and stats.rejected == 0
    assert stats.total() == 4
    # Deterministic order: country first, admin second, cities after.
    assert [call.type for call in locations.calls] == [
        LocationType.COUNTRY,
        LocationType.ADMINISTRATIVE_AREA,
        LocationType.CITY,
        LocationType.CITY,
    ]
    # Children receive the authoritative parent row id.
    admin = locations.calls[1]
    assert admin.id is not None
    seattle = next(call for call in locations.calls if call.canonical_name == "Seattle")
    assert seattle.parent_location_id == admin.id
    assert seattle.geometry == "SRID=4326;POINT(-122.3321 47.6062)"
    auburn = next(call for call in locations.calls if call.canonical_name == "Auburn")
    assert auburn.parent_location_id == admin.id and auburn.geometry is None


@pytest.mark.asyncio
async def test_i03_deterministic_ids_are_identical() -> None:
    """G26B-I03 canonical UUIDv5 ids are identical across clean databases."""
    first = FakeLocations()
    second = FakeLocations()
    await ReferenceIngestionService(_factory(first)).ingest(_corpus())
    await ReferenceIngestionService(_factory(second)).ingest(_corpus())
    for left, right in zip(first.calls, second.calls, strict=True):
        assert left.id == right.id
        assert left.id == canonical_location_uuid(
            location_type=left.type,
            country_code=left.country_code,
            admin1_code=left.admin1_code,
            admin2_code=left.admin2_code,
            canonical_name=left.canonical_name,
        )


@pytest.mark.asyncio
async def test_i02_second_identical_import_is_a_no_op() -> None:
    """G26B-I02 a second identical import is a complete no-op."""
    locations = FakeLocations()
    service = ReferenceIngestionService(_factory(locations))
    first = await service.ingest(_corpus())
    second = await service.ingest(_corpus())
    assert first.created == 4
    assert second.unchanged == 4 and second.created == 0
    assert len(locations.store) == 4


@pytest.mark.asyncio
async def test_i10_input_order_does_not_change_result() -> None:
    """G26B-I10 corpus input order never changes canonical IDs/hierarchy."""
    locations = FakeLocations()
    service = ReferenceIngestionService(_factory(locations))
    await service.ingest(list(reversed(_corpus())))  # children first in input
    # Processing order is still parent-before-child with deterministic IDs.
    assert [call.type for call in locations.calls] == [
        LocationType.COUNTRY,
        LocationType.ADMINISTRATIVE_AREA,
        LocationType.CITY,
        LocationType.CITY,
    ]
    admin = locations.calls[1]
    assert locations.calls[2].parent_location_id == admin.id


@pytest.mark.asyncio
async def test_i08_malformed_geometry_fails_closed_without_mutation() -> None:
    """G26B-I08 malformed source geometry fails closed before any mutation."""
    locations = FakeLocations()
    corpus = _corpus()
    corpus[1] = corpus[1].model_copy(update={"geometry": "SRID=3857;POINT(0 0)"})
    with pytest.raises(InvalidReferenceGeometryError, match="4326"):
        await ReferenceIngestionService(_factory(locations)).ingest(corpus)
    assert locations.calls == []
    assert locations.store == {}


@pytest.mark.asyncio
async def test_hierarchy_missing_parent_fails_closed_without_mutation() -> None:
    """A child whose parent is absent from corpus and database fails closed."""
    locations = FakeLocations()
    corpus = _corpus()
    corpus[2] = corpus[2].model_copy(
        update={
            "parent": ReferenceParent(
                location_type=LocationType.ADMINISTRATIVE_AREA,
                country_code="US",
                admin1_code="OR",
                canonical_name="Oregon",
            )
        }
    )
    with pytest.raises(InvalidReferenceHierarchyError, match="parent"):
        await ReferenceIngestionService(_factory(locations)).ingest(corpus)
    assert locations.calls == []


@pytest.mark.asyncio
async def test_geometry_refresh_enriches_same_row_and_second_refresh_is_noop() -> None:
    """G26B-I05/I06 geometry refresh enriches; repeat refresh is a no-op."""
    locations = FakeLocations()
    service = ReferenceIngestionService(_factory(locations))
    first = await service.ingest(_corpus())
    admin_identity = ("administrative_area", "US", "WA", "", "Washington")
    first_version = locations.store[admin_identity].location.version
    refreshed_records: list[GeographicReferenceRecord] = []
    for record in _corpus():
        if (
            record.location_type is LocationType.ADMINISTRATIVE_AREA
            and record.admin1_code == "WA"
        ):
            refreshed_records.append(
                record.model_copy(
                    update={
                        "geometry": "SRID=4326;POLYGON((-125 46,-117 46,-117 49,-125 49,-125 46))",
                        "centroid": None,
                        "parent": record.parent,
                    }
                )
            )
        else:
            refreshed_records.append(record)
    second = await service.ingest(refreshed_records)
    third = await service.ingest(refreshed_records)
    assert first.created == 4
    assert second.enriched == 1 and second.unchanged == 3
    assert third.unchanged == 4 and third.enriched == 0
    # The same canonical row received a new database-issued version token.
    refreshed_version = locations.store[admin_identity].location.version
    assert first_version is not None and refreshed_version is not None
    assert refreshed_version > first_version
    assert third.unchanged == 4
