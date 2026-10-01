# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26E seeder unit tests (G26E-S01..S06).

The GEOINT seeder is harness-only deterministic canonical seeding. Unit
coverage fixes the pure contracts — allowlisted scenarios, deterministic
identity derivation, the explicit E2E environment guard, bounded
idempotency, and the scenario/other-investigation validation — without
any database. The real PostgreSQL + PostGIS resolution behavior lives in
the PR 26E integration tests.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.persistence.repositories import (
    EvidencePersistenceOutcome,
    EvidencePersistenceResult,
    GeoResolutionDuplicateStateError,
    InvestigationEvidenceAdmissionConflictError,
)
from agentic_threat_investigator.config.settings import OperatingMode, Settings
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservation,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    CanonicalLocationResolutionStatus,
    EntityLocationObservation,
    GeographicClaim,
    GeoResolution,
    GeoResolutionStatus,
    Location,
    LocationCandidate,
    LocationPrecision,
    LocationType,
)
from tests.e2e_support.seed_geoint import (
    E2E_SEEDING_ENABLE_ENV,
    SEED_RETRIEVED_AT,
    E2eSeedIncompatibleResolutionError,
    E2eSeedingGuardError,
    E2eSeedResolutionConflictError,
    E2eSeedResolutionIncompleteError,
    SeedUnitOfWork,
    UnknownSeedScenarioError,
    _parse_investigation_id,
    apply_seed,
    build_seed_units,
    derive_entity_id,
    require_e2e_environment,
    scenario_fixtures,
)

INVESTIGATION_ID = UUID("20000000-0000-4000-8000-000000000001")
OTHER_INVESTIGATION_ID = UUID("20000001-0000-4000-8000-000000000002")


def _fake_settings(
    mode: OperatingMode = OperatingMode.FAKE,
) -> Settings:
    """Build a minimal fake-mode settings object (Pydantic defaults win)."""
    return Settings(
        database_url="postgresql+psycopg://user:pass@127.0.0.1:5432/db",
        operating_mode=mode,
    )


def test_g26e_s01_scenarios_are_allowlisted_and_bounded() -> None:
    """The five scenarios exist and are the only legal names."""
    for name in (
        "entity_history",
        "same_location",
        "containment",
        "cross_investigation",
        "non_mappable",
    ):
        assert scenario_fixtures(name)
    with pytest.raises(UnknownSeedScenarioError):
        scenario_fixtures("unknown_scenario")
    with pytest.raises(UnknownSeedScenarioError):
        scenario_fixtures("seattle")


def test_g26e_s02_identities_are_deterministic() -> None:
    """Entity/evidence/resolution UUIDs derive purely from the inputs."""
    first = build_seed_units(INVESTIGATION_ID, "same_location")
    second = build_seed_units(INVESTIGATION_ID, "same_location")
    assert first == second
    assert len(first) == 2
    assert first[0].entity_id == derive_entity_id("203.0.113.20")
    assert first[0].evidence.observation.retrieved_at is not None
    assert first[0].evidence.evidence.type is not None
    assert first[0].evidence.observation.facts["country_code"] == "US"
    assert first[0].evidence.observation.facts["city"] == "Seattle"


def test_g26e_s03_fixtures_map_to_the_canonical_resolution_vocabulary() -> None:
    """Evidence facts use the exact PR 26C claim vocabulary."""
    for name in ("entity_history", "same_location", "containment", "non_mappable"):
        for unit in build_seed_units(INVESTIGATION_ID, name):
            facts = unit.evidence.observation.facts
            assert facts["country_code"] in ("US", "ZZ")
            assert facts["precision"] in ("city", "region", "country")
            assert unit.evidence.observation.observed_at is not None
            assert unit.evidence.observation.retrieved_at is not None


def test_g26e_s04_cross_investigation_scoping_and_guard() -> None:
    """The second Investigation bound is only legal for the scenario."""
    units = build_seed_units(
        INVESTIGATION_ID,
        "cross_investigation",
        other_investigation_id=OTHER_INVESTIGATION_ID,
    )
    assert len(units) == 2
    assert units[0].admitted_to == INVESTIGATION_ID
    assert units[1].admitted_to == OTHER_INVESTIGATION_ID
    # The other-investigation parameter is never silently accepted.
    with pytest.raises(UnknownSeedScenarioError):
        build_seed_units(
            INVESTIGATION_ID,
            "same_location",
            other_investigation_id=OTHER_INVESTIGATION_ID,
        )


def test_g26e_s05_e2e_environment_guard_fails_closed() -> None:
    """Both fake mode and the dedicated E2E flag are mandatory."""
    settings = _fake_settings()
    require_e2e_environment(settings, {E2E_SEEDING_ENABLE_ENV: "1"})
    require_e2e_environment(settings, {E2E_SEEDING_ENABLE_ENV: "true"})
    with pytest.raises(E2eSeedingGuardError):
        require_e2e_environment(settings, {})
    with pytest.raises(E2eSeedingGuardError):
        require_e2e_environment(
            settings,
            {E2E_SEEDING_ENABLE_ENV: "nah"},
        )
    production = _fake_settings(OperatingMode.PRODUCTION)
    with pytest.raises(E2eSeedingGuardError):
        require_e2e_environment(
            production,
            {E2E_SEEDING_ENABLE_ENV: "1"},
        )


def test_g26e_s06_timestamps_and_investigation_ids_parse_fail_closed() -> None:
    """Seed epoch timestamps are fixed and Investigation parsing is strict."""
    assert SEED_RETRIEVED_AT.tzinfo == UTC
    assert _parse_investigation_id("20000000-0000-4000-8000-000000000001") == (
        INVESTIGATION_ID
    )
    with pytest.raises(ValueError):
        _parse_investigation_id("not-a-uuid")
    with pytest.raises(ValueError):
        _parse_investigation_id("00000000-0000-0000-0000-000000000000")


# ---------------------------------------------------------------------------
# PR corrective GEOINT seed idempotency — deterministic in-memory world
# (SI01..SI20 unit matrix).
#
# The fake world mirrors the authoritative PostgreSQL semantics the seeder
# already leans on: stable Evidence + per-Investigation EvidenceObservation,
# idempotent association/admission replay, and semantic (entity, observation)
# GeoResolution identity with the duplicate-state guard. It never invents a
# parallel persistence architecture; it is the same narrow seam the seeder
# protocol consumes.
# ---------------------------------------------------------------------------

LOCATION_ID = UUID("30000000-0000-4000-8000-00000000000a")


def _material_facts(facts: dict[str, Any]) -> dict[str, Any]:
    """Return one plain copy of the persisted facts mapping."""
    return dict(dict(facts))


@dataclass
class _SeedWorld:
    """One shared in-memory durable world under the fake repositories."""

    observations: dict[UUID, EvidenceObservation] = field(default_factory=dict)
    stable: dict[UUID, Evidence] = field(default_factory=dict)
    associations: set[tuple[UUID, UUID]] = field(default_factory=set)
    admissions: dict[tuple[UUID, UUID], InvestigationEvidence] = field(
        default_factory=dict
    )
    resolutions: dict[UUID, GeoResolution] = field(default_factory=dict)
    canonical_observations: dict[UUID, EntityLocationObservation] = field(
        default_factory=dict
    )
    entity_id_overrides: dict[str, UUID] = field(default_factory=dict)
    upserted: list[Entity] = field(default_factory=list)
    create_pending_calls: int = 0
    # Narrow error seams (these are test-injected faults, never product paths).
    persist_error: type[Exception] | None = None
    admit_error: type[Exception] | None = None
    claim_error: type[BaseException] | None = None
    race_read_none: bool = False
    race_read_miss_once: bool = False

    @property
    def investigation_ids(self) -> set[UUID]:
        """Every Investigation referenced by any admission is visible."""
        return {inv for inv, _obs in self.admissions}


class _FakeEvidence:
    """In-memory exact-observation repository with stable-evidence reuse."""

    def __init__(self, world: _SeedWorld) -> None:
        self._world = world

    async def get_observation(self, observation_id: UUID) -> EvidenceObservation | None:
        """Return the stored observation, if any."""
        return self._world.observations.get(observation_id)

    async def get_stable_evidence(self, evidence_id: UUID) -> Evidence | None:
        """Return the stored stable Evidence, if any."""
        return self._world.stable.get(evidence_id)

    async def persist(
        self, converted: ConvertedEvidence, *, observation_id: UUID | None = None
    ) -> EvidencePersistenceResult:
        """Mirror ``ati.persist_evidence_observation`` reuse/create semantics."""
        if self._world.persist_error is not None:
            raise self._world.persist_error()
        stable = self._world.stable.get(converted.evidence.id)
        candidate = converted.observation
        material = {
            "observed_at": candidate.observed_at,
            "source_url": candidate.source_url,
            "facts": _material_facts(candidate.facts),
            "raw_payload": candidate.raw_payload,
        }
        if stable is not None:
            latest = max(
                (
                    row
                    for row in self._world.observations.values()
                    if row.evidence_id == converted.evidence.id
                ),
                key=lambda row: row.version,
            )
            latest_material = {
                "observed_at": latest.observed_at,
                "source_url": latest.source_url,
                "facts": _material_facts(latest.facts),
                "raw_payload": latest.raw_payload,
            }
            if material == latest_material:
                return EvidencePersistenceResult(
                    evidence=converted.evidence,
                    observation=latest,
                    outcome=EvidencePersistenceOutcome.UNCHANGED,
                    version=latest.version,
                )
        observation = EvidenceObservation(
            id=observation_id or uuid4(),
            evidence_id=converted.evidence.id,
            version=1,
            source_url=candidate.source_url,
            observed_at=candidate.observed_at,
            retrieved_at=candidate.retrieved_at,
            facts=_material_facts(candidate.facts),
            raw_payload=candidate.raw_payload,
            diff=None,
        )
        self._world.observations[observation.id] = observation
        self._world.stable[converted.evidence.id] = converted.evidence
        return EvidencePersistenceResult(
            evidence=converted.evidence,
            observation=observation,
            outcome=EvidencePersistenceOutcome.CREATED,
            version=1,
        )


class _FakeEntities:
    """In-memory canonical entity repository with deterministic overrides."""

    def __init__(self, world: _SeedWorld) -> None:
        self._world = world

    async def upsert(
        self, entity: Entity, *, expected_version: int | None = None
    ) -> Entity:
        """Record and return the entity with its authoritative persisted id."""
        self._world.upserted.append(entity)
        override = self._world.entity_id_overrides.get(entity.value)
        return entity.model_copy(update={"id": override or entity.id})


class _FakeObservationEntity:
    """Records observation/Entity associations idempotently."""

    def __init__(self, world: _SeedWorld) -> None:
        self._world = world

    async def associate(self, observation_id: UUID, entity_id: UUID) -> Any:
        """Record one pair (replay-safe)."""
        self._world.associations.add((observation_id, entity_id))
        return None


class _FakeInvestigationEvidence:
    """In-memory admission with exact replay / conflict semantics."""

    def __init__(self, world: _SeedWorld) -> None:
        self._world = world

    async def admit(self, admission: InvestigationEvidence) -> InvestigationEvidence:
        """Record one admission; immutable metadata conflicts are typed errors."""
        if self._world.admit_error is not None:
            raise self._world.admit_error()
        key = (admission.investigation_id, admission.evidence_observation_id)
        existing = self._world.admissions.get(key)
        if existing is not None:
            if (
                existing.inclusion_reason is not admission.inclusion_reason
                or existing.added_by is not admission.added_by
                or existing.discovered_from_evidence_observation_id
                is not admission.discovered_from_evidence_observation_id
            ):
                raise InvestigationEvidenceAdmissionConflictError(
                    admission.investigation_id, admission.evidence_observation_id
                )
            return existing
        self._world.admissions[key] = admission
        return admission


class _FakeGeoResolutions:
    """In-memory GeoResolution lifecycle mirroring the SQL API guard."""

    def __init__(self, world: _SeedWorld) -> None:
        self._world = world

    def _pairs(self, entity_id: UUID, observation_id: UUID) -> list[GeoResolution]:
        """Return every resolution row for one semantic pair."""
        return [
            row
            for row in self._world.resolutions.values()
            if row.entity_id == entity_id
            and row.evidence_observation_id == observation_id
        ]

    async def get_by_entity_evidence(
        self, entity_id: UUID, evidence_id: UUID
    ) -> GeoResolution | None:
        """Return one row per semantic pair (database enforces uniqueness).

        ``race_read_miss_once`` models a concurrent actor creating the pair
        between the seeder's read and its create attempt: the first read
        returns None while the store already owns the row.
        """
        if self._world.race_read_none:
            return None
        rows = self._pairs(entity_id, evidence_id)
        if not rows:
            return None
        if self._world.race_read_miss_once:
            self._world.race_read_miss_once = False
            return None
        return rows[0]

    @staticmethod
    def _fresh_pending(row: GeoResolution) -> bool:
        """Mirror the SQL fresh-PENDING shape check."""
        return (
            row.status is GeoResolutionStatus.PENDING
            and row.attempt_count == 0
            and row.claimed_by is None
            and row.lease_expires_at is None
            and row.resolved_location_id is None
            and row.last_error_code is None
        )

    async def create_pending(self, resolution: GeoResolution) -> GeoResolution:
        """Create or idempotently reuse; progressed duplicates raise the guard."""
        self._world.create_pending_calls += 1
        existing = self._pairs(resolution.entity_id, resolution.evidence_observation_id)
        if existing:
            row = existing[0]
            if self._fresh_pending(row):
                return row
            raise GeoResolutionDuplicateStateError(
                resolution.entity_id, resolution.evidence_observation_id
            )
        row = resolution.model_copy(
            update={
                "id": resolution.id,
                "status": GeoResolutionStatus.PENDING,
                "version": 1,
            }
        )
        if row.id is None:  # pragma: no cover - tests always supply candidate ids
            raise RuntimeError("fake resolution without an identity")
        self._world.resolutions[row.id] = row
        return row

    async def claim_batch(
        self,
        *,
        claimed_by: str,
        limit: int,
        lease_seconds: int,
        max_attempts: int,
    ) -> list[GeoResolution]:
        """Claim due PENDING rows in memory (terminal/unleased rows untouched)."""
        if self._world.claim_error is not None:
            raise self._world.claim_error()
        claimed: list[GeoResolution] = []
        for row in list(self._world.resolutions.values()):
            if len(claimed) >= limit:
                break
            if row.status is not GeoResolutionStatus.PENDING:
                continue
            row.status = GeoResolutionStatus.PROCESSING
            row.claimed_by = claimed_by
            row.attempt_count += 1
            row.lease_expires_at = datetime.now(UTC) + timedelta(seconds=lease_seconds)
            row.version = (row.version or 0) + 1
            claimed.append(row)
        return claimed

    async def complete_resolved(
        self,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        observation: EntityLocationObservation,
    ) -> GeoResolution:
        """Complete one claimed row as RESOLVED with its canonical observation."""
        row = self._world.resolutions[resolution_id]
        row.status = GeoResolutionStatus.RESOLVED
        row.resolved_location_id = observation.location_id
        row.claimed_by = None
        row.lease_expires_at = None
        row.version = (row.version or 0) + 1
        self._world.canonical_observations[observation.id] = observation
        return row

    async def complete_unresolvable(
        self,
        *,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        error_code: str,
    ) -> GeoResolution:
        """Mark one claimed row terminal UNRESOLVABLE (used by state setup)."""
        row = self._world.resolutions[resolution_id]
        row.status = GeoResolutionStatus.UNRESOLVABLE
        row.claimed_by = None
        row.lease_expires_at = None
        row.last_error_code = error_code
        row.version = (row.version or 0) + 1
        return row

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
        """Mark one claimed row terminal FAILED (used by state setup)."""
        row = self._world.resolutions[resolution_id]
        row.status = GeoResolutionStatus.FAILED
        row.claimed_by = None
        row.lease_expires_at = None
        row.last_error_code = error_code
        row.version = (row.version or 0) + 1
        return row


class _FakeObservationStore:
    """In-memory canonical EntityLocationObservation reader (exact provenance)."""

    def __init__(self, world: _SeedWorld) -> None:
        self._world = world

    async def list_for_entity(
        self,
        entity_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EntityLocationObservation]:
        """Return the bounded observations of one Entity."""
        return [
            row
            for row in self._world.canonical_observations.values()
            if row.entity_id == entity_id
        ]


class FakeUnitOfWork:
    """In-memory seam satisfying the seeder and worker persistence needs."""

    def __init__(self, world: _SeedWorld, *, known_investigations: set[UUID]) -> None:
        """Bind the shared durable world and the visible Investigation set."""
        self._world = world
        self.investigations = _FakeInvestigations(known_investigations)
        self.entities = _FakeEntities(world)
        self.evidence = _FakeEvidence(world)
        self.evidence_observation_entities = _FakeObservationEntity(world)
        self.investigation_evidence = _FakeInvestigationEvidence(world)
        self.geo_resolutions = _FakeGeoResolutions(world)
        self.entity_location_observations = _FakeObservationStore(world)

    async def __aenter__(self) -> "FakeUnitOfWork":
        """Serve as its own transaction boundary."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Nothing to commit or roll back in memory."""


class _FakeInvestigations:
    """In-memory investigation reader for the seeder's visibility probe."""

    def __init__(self, known: set[UUID]) -> None:
        self.known = known

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> Any:
        """Return a sentinel for a known visible Investigation, else None."""
        return object() if investigation_id in self.known else None


class _FakeResolverStub(LocationResolver):
    """One deterministic canonical resolution (Seattle) for unit tests."""

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Return a deterministic RESOLVED location for any claim."""
        location = Location(
            id=LOCATION_ID,
            type=LocationType.COUNTRY,
            name="United States",
            canonical_name="United States",
            country_code="US",
        )
        return CanonicalLocationResolution(
            status=CanonicalLocationResolutionStatus.RESOLVED,
            location=location,
            candidates=(LocationCandidate(location=location),),
            reason_code="exact_semantic_match",
        )


def _observation_for(unit: Any) -> EvidenceObservation:
    """Build the exact deterministic observation one seed would persist."""
    return EvidenceObservation(
        id=unit.evidence_id,
        evidence_id=unit.evidence.evidence.id,
        version=1,
        source_url=unit.evidence.observation.source_url,
        observed_at=unit.evidence.observation.observed_at,
        retrieved_at=unit.evidence.observation.retrieved_at,
        facts=_material_facts(unit.evidence.observation.facts),
        raw_payload=unit.evidence.observation.raw_payload,
        diff=None,
    )


def _canonical_observation(
    unit: Any, entity_id: UUID, *, observation_id: UUID, observation_uuid: UUID
) -> EntityLocationObservation:
    """Build the canonical observation the production completion persists."""
    precision = {
        "city": LocationPrecision.CITY,
        "region": LocationPrecision.ADMINISTRATIVE_AREA,
        "country": LocationPrecision.COUNTRY,
    }[unit.evidence.observation.facts["precision"]]
    return EntityLocationObservation(
        id=observation_uuid,
        entity_id=entity_id,
        location_id=LOCATION_ID,
        evidence_observation_id=observation_id,
        precision=precision,
        observed_at=unit.evidence.observation.observed_at,
        retrieved_at=unit.evidence.observation.retrieved_at,
        resolved_at=SEED_RETRIEVED_AT,
        resolution_method="canonical_geography_v1",
    )


def _seed_world_with_evidence(
    investigation_id: UUID, scenario: str
) -> tuple[_SeedWorld, list[Any]]:
    """Pre-seed one scenario's deterministic Evidence rows (no work/observations)."""
    units = build_seed_units(investigation_id, scenario)
    world = _SeedWorld()
    for unit in units:
        observation = _observation_for(unit)
        world.observations[observation.id] = observation
        world.stable[unit.evidence.evidence.id] = unit.evidence.evidence
    return world, list(units)


def _uow(
    world: _SeedWorld,
    investigation_id: UUID,
    *,
    extra_known: set[UUID] | None = None,
) -> FakeUnitOfWork:
    """Open the shared in-memory UoW seam with the visible Investigations."""
    known = {investigation_id} | set(extra_known or ())
    return FakeUnitOfWork(world, known_investigations=known)


def _run(
    world: _SeedWorld,
    investigation_id: UUID,
    scenario: str,
    *,
    other_investigation_id: UUID | None = None,
    extra_known: set[UUID] | None = None,
) -> Any:
    """Drive ``apply_seed`` over the shared in-memory world."""
    known = set(extra_known or ())
    if other_investigation_id is not None:
        known.add(other_investigation_id)
    return apply_seed(
        lambda: cast(SeedUnitOfWork, _uow(world, investigation_id, extra_known=known)),
        _FakeResolverStub(),
        investigation_id,
        scenario,
        other_investigation_id=other_investigation_id,
    )


# ---------------------------------------------------------------------------
# SI unit matrix — state-aware GEOINT seeding idempotency.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_si01_evidence_absent_resolution_absent_creates_pending() -> None:
    """SI01: absent Evidence + absent work persists prerequisites and PENDING."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world = _SeedWorld()
    report = await _run(world, INVESTIGATION_ID, "non_mappable")
    assert list(report.created_evidence_ids) == [unit.evidence_id]
    assert list(report.evidence_ids) == [unit.evidence_id]
    (row,) = world.resolutions.values()
    assert row.status is GeoResolutionStatus.RESOLVED
    assert row.id == unit.resolution_id
    assert len(report.observation_ids) == 1


@pytest.mark.asyncio
async def test_si02_evidence_present_resolution_absent_creates_work() -> None:
    """SI02: reused Evidence still establishes association/admission and work."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world, _units = _seed_world_with_evidence(INVESTIGATION_ID, "non_mappable")
    report = await _run(world, INVESTIGATION_ID, "non_mappable")
    assert list(report.reused_evidence_ids) == [unit.evidence_id]
    assert (unit.evidence_id, unit.entity_id) in world.associations
    assert (INVESTIGATION_ID, unit.evidence_id) in world.admissions
    (row,) = world.resolutions.values()
    assert row.status is GeoResolutionStatus.RESOLVED
    assert len(report.observation_ids) == 1


@pytest.mark.asyncio
async def test_si03_pending_exists_reused_without_create() -> None:
    """SI03: a pre-existing PENDING pair is reused; no create is attempted."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world, _units = _seed_world_with_evidence(INVESTIGATION_ID, "non_mappable")
    world.resolutions[unit.resolution_id] = GeoResolution(
        id=unit.resolution_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.PENDING,
        version=1,
    )
    report = await _run(world, INVESTIGATION_ID, "non_mappable")
    assert world.create_pending_calls == 0
    assert len(world.resolutions) == 1
    (row,) = world.resolutions.values()
    assert row.status is GeoResolutionStatus.RESOLVED
    assert len(report.observation_ids) == 1


@pytest.mark.asyncio
async def test_si04_processing_exists_reused_not_reset() -> None:
    """SI04: PROCESSING work is reused; the lease/owner is never touched."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world, _units = _seed_world_with_evidence(INVESTIGATION_ID, "non_mappable")
    world.resolutions[unit.resolution_id] = GeoResolution(
        id=unit.resolution_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.PROCESSING,
        attempt_count=1,
        claimed_by="other-worker",
        lease_expires_at=SEED_RETRIEVED_AT + timedelta(hours=1),
        version=4,
    )
    world.canonical_observations[unit.resolution_id] = _canonical_observation(
        unit,
        unit.entity_id,
        observation_id=unit.evidence_id,
        observation_uuid=unit.resolution_id,
    )
    report = await _run(world, INVESTIGATION_ID, "non_mappable")
    assert world.create_pending_calls == 0
    (row,) = world.resolutions.values()
    assert row.status is GeoResolutionStatus.PROCESSING
    assert row.claimed_by == "other-worker"
    assert row.version == 4
    assert len(report.observation_ids) == 1


@pytest.mark.asyncio
async def test_si05_resolved_with_observation_reused_and_verified() -> None:
    """SI05: RESOLVED work with the exact canonical observation is reused."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world, _units = _seed_world_with_evidence(INVESTIGATION_ID, "non_mappable")
    existing_id = uuid4()
    world.resolutions[existing_id] = GeoResolution(
        id=existing_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.RESOLVED,
        resolved_location_id=LOCATION_ID,
        version=3,
    )
    expected_observation = uuid4()
    world.canonical_observations[expected_observation] = _canonical_observation(
        unit,
        unit.entity_id,
        observation_id=unit.evidence_id,
        observation_uuid=expected_observation,
    )
    report = await _run(world, INVESTIGATION_ID, "non_mappable")
    assert world.create_pending_calls == 0
    (row,) = world.resolutions.values()
    assert row.id != unit.resolution_id  # existing UUID differs: not a conflict
    assert row.status is GeoResolutionStatus.RESOLVED
    assert list(report.observation_ids) == [expected_observation]


@pytest.mark.asyncio
async def test_si06_unresolvable_terminal_fails_closed() -> None:
    """SI06: UNRESOLVABLE work is incompatible with the expected fixture."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world, _units = _seed_world_with_evidence(INVESTIGATION_ID, "non_mappable")
    existing_id = uuid4()
    world.resolutions[existing_id] = GeoResolution(
        id=existing_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.UNRESOLVABLE,
        last_error_code="ambiguous_location",
        version=2,
    )
    with pytest.raises(E2eSeedIncompatibleResolutionError):
        await _run(world, INVESTIGATION_ID, "non_mappable")
    assert world.create_pending_calls == 0
    (row,) = world.resolutions.values()
    assert row.status is GeoResolutionStatus.UNRESOLVABLE


@pytest.mark.asyncio
async def test_si07_failed_terminal_fails_closed() -> None:
    """SI07: FAILED work is incompatible with the expected fixture."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world, _units = _seed_world_with_evidence(INVESTIGATION_ID, "non_mappable")
    existing_id = uuid4()
    world.resolutions[existing_id] = GeoResolution(
        id=existing_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.FAILED,
        last_error_code="resolver_error",
        version=2,
    )
    with pytest.raises(E2eSeedIncompatibleResolutionError):
        await _run(world, INVESTIGATION_ID, "non_mappable")
    assert world.create_pending_calls == 0
    (row,) = world.resolutions.values()
    assert row.status is GeoResolutionStatus.FAILED


@pytest.mark.asyncio
async def test_si08_duplicate_race_rereads_pending_and_recovers() -> None:
    """SI08: duplicate-state create race re-reads a PENDING pair and recovers."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world = _SeedWorld()
    # A racing actor scheduled a retry (non-fresh PENDING) for the pair the
    # seeder is about to persist: create_pending must raise the guard.
    existing_id = uuid4()
    world.resolutions[existing_id] = GeoResolution(
        id=existing_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.PENDING,
        attempt_count=1,
        next_attempt_at=SEED_RETRIEVED_AT,
        version=2,
    )
    world.race_read_miss_once = True
    report = await _run(world, INVESTIGATION_ID, "non_mappable")
    assert world.create_pending_calls == 1  # the single raced attempt
    assert len(world.resolutions) == 1  # no duplicate work
    (row,) = world.resolutions.values()
    assert row.id != unit.resolution_id
    assert row.status is GeoResolutionStatus.RESOLVED
    assert len(report.observation_ids) == 1


@pytest.mark.asyncio
async def test_si09_duplicate_race_rereads_processing_and_recovers() -> None:
    """SI09: duplicate-state create race re-reads PROCESSING and respects it."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world = _SeedWorld()
    existing_id = uuid4()
    world.resolutions[existing_id] = GeoResolution(
        id=existing_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.PROCESSING,
        attempt_count=1,
        claimed_by="other-worker",
        lease_expires_at=SEED_RETRIEVED_AT + timedelta(hours=1),
        version=3,
    )
    world.canonical_observations[uuid4()] = _canonical_observation(
        unit,
        unit.entity_id,
        observation_id=unit.evidence_id,
        observation_uuid=uuid4(),
    )
    world.race_read_miss_once = True
    report = await _run(world, INVESTIGATION_ID, "non_mappable")
    (row,) = world.resolutions.values()
    assert row.status is GeoResolutionStatus.PROCESSING
    assert row.claimed_by == "other-worker"
    assert len(report.observation_ids) == 1


@pytest.mark.asyncio
async def test_si10_duplicate_race_rereads_resolved_and_verifies() -> None:
    """SI10: duplicate-state create race re-reads RESOLVED and verifies it."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world = _SeedWorld()
    existing_id = uuid4()
    world.resolutions[existing_id] = GeoResolution(
        id=existing_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.RESOLVED,
        resolved_location_id=LOCATION_ID,
        version=3,
    )
    world.race_read_miss_once = True
    observation_id = uuid4()
    world.canonical_observations[observation_id] = _canonical_observation(
        unit,
        unit.entity_id,
        observation_id=unit.evidence_id,
        observation_uuid=observation_id,
    )
    report = await _run(world, INVESTIGATION_ID, "non_mappable")
    (row,) = world.resolutions.values()
    assert row.status is GeoResolutionStatus.RESOLVED
    assert list(report.observation_ids) == [observation_id]


@pytest.mark.asyncio
async def test_si11_duplicate_state_without_reread_row_fails() -> None:
    """SI11: duplicate-state followed by a missing re-read fails closed."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world = _SeedWorld()
    existing_id = uuid4()
    world.resolutions[existing_id] = GeoResolution(
        id=existing_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.PROCESSING,
        version=3,
    )
    world.race_read_none = True
    with pytest.raises(E2eSeedResolutionConflictError):
        await _run(world, INVESTIGATION_ID, "non_mappable")


@pytest.mark.asyncio
async def test_si12_reused_evidence_reestablishes_association_and_admission() -> None:
    """SI12: reused Evidence missing association/admission is reconciled."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world, _units = _seed_world_with_evidence(INVESTIGATION_ID, "non_mappable")
    assert world.associations == set()
    assert world.admissions == {}
    await _run(world, INVESTIGATION_ID, "non_mappable")
    assert (unit.evidence_id, unit.entity_id) in world.associations
    assert (INVESTIGATION_ID, unit.evidence_id) in world.admissions


@pytest.mark.asyncio
async def test_si13_admission_replay_conflict_propagates() -> None:
    """SI13: conflicting immutable admission metadata is a typed conflict."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world, _units = _seed_world_with_evidence(INVESTIGATION_ID, "non_mappable")
    world.admissions[(INVESTIGATION_ID, unit.evidence_id)] = InvestigationEvidence(
        investigation_id=INVESTIGATION_ID,
        evidence_observation_id=unit.evidence_id,
        inclusion_reason=InvestigationEvidenceReason.INITIAL,
        added_at=SEED_RETRIEVED_AT,
        added_by=InvestigationEvidenceActor.ANALYST,
    )
    with pytest.raises(InvestigationEvidenceAdmissionConflictError):
        await _run(world, INVESTIGATION_ID, "non_mappable")


@pytest.mark.asyncio
async def test_si14_entity_upsert_different_canonical_id_used_everywhere() -> None:
    """SI14: a pre-existing canonical Entity id from upsert is authoritative."""
    (unit, other_unit) = build_seed_units(INVESTIGATION_ID, "same_location")
    canonical_id = uuid4()
    world = _SeedWorld()
    world.entity_id_overrides[unit.entity_value] = canonical_id
    report = await _run(world, INVESTIGATION_ID, "same_location")
    assert unit.entity_id != canonical_id
    assert canonical_id in report.entity_ids
    # Only the overridden unit binds the returned canonical id; the untouched
    # unit keeps its deterministic id, and both verify through the id upsert
    # returned (never the deterministic candidate).
    for row in world.resolutions.values():
        if row.evidence_observation_id == unit.evidence_id:
            assert row.entity_id == canonical_id
        else:
            assert row.entity_id == other_unit.entity_id
    assert len(report.observation_ids) == 2


@pytest.mark.asyncio
async def test_si15_resolved_without_expected_observation_fails() -> None:
    """SI15: RESOLVED work without its expected canonical observation fails."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    world, _units = _seed_world_with_evidence(INVESTIGATION_ID, "non_mappable")
    existing_id = uuid4()
    world.resolutions[existing_id] = GeoResolution(
        id=existing_id,
        entity_id=unit.entity_id,
        evidence_observation_id=unit.evidence_id,
        status=GeoResolutionStatus.RESOLVED,
        version=3,
    )
    with pytest.raises(E2eSeedResolutionIncompleteError):
        await _run(world, INVESTIGATION_ID, "non_mappable")


@pytest.mark.asyncio
async def test_si16_exact_seed_twice_no_duplicates() -> None:
    """SI16: the exact seed twice never duplicates Evidence/work/observations."""
    (first_unit, _second_unit) = build_seed_units(INVESTIGATION_ID, "same_location")
    world = _SeedWorld()
    first = await _run(world, INVESTIGATION_ID, "same_location")
    assert len(first.created_evidence_ids) == 2
    second = await _run(world, INVESTIGATION_ID, "same_location")
    assert second.created_evidence_ids == ()
    assert sorted(second.reused_evidence_ids) == sorted(first.created_evidence_ids)
    assert len(world.observations) == 2
    assert len(world.resolutions) == 2
    assert len(world.canonical_observations) == 2
    assert first_unit.evidence_id in world.observations


@pytest.mark.asyncio
async def test_si17_cross_investigation_replay_preserves_scope() -> None:
    """SI17: cross-Investigation replay keeps the designated scopes intact."""
    units = build_seed_units(
        INVESTIGATION_ID,
        "cross_investigation",
        other_investigation_id=OTHER_INVESTIGATION_ID,
    )
    world = _SeedWorld()
    first = await _run(
        world,
        INVESTIGATION_ID,
        "cross_investigation",
        other_investigation_id=OTHER_INVESTIGATION_ID,
    )
    assert len(first.created_evidence_ids) == 2
    second = await _run(
        world,
        INVESTIGATION_ID,
        "cross_investigation",
        other_investigation_id=OTHER_INVESTIGATION_ID,
    )
    assert second.created_evidence_ids == ()
    assert len(second.reused_evidence_ids) == 2
    assert len(world.resolutions) == 2
    assert len(world.canonical_observations) == 2
    for unit in units:
        scope = (
            INVESTIGATION_ID
            if unit.admitted_to == INVESTIGATION_ID
            else OTHER_INVESTIGATION_ID
        )
        assert (scope, unit.evidence_id) in world.admissions


@pytest.mark.asyncio
async def test_si18_unknown_scenario_fails_closed() -> None:
    """SI18: an unknown scenario fails closed before any persistence."""
    world = _SeedWorld()
    with pytest.raises(UnknownSeedScenarioError):
        await _run(world, INVESTIGATION_ID, "unknown_scenario")
    assert world.resolutions == {}
    assert world.observations == {}


@pytest.mark.asyncio
async def test_si19_unexpected_database_error_propagates() -> None:
    """SI19: an unexpected database error is never swallowed."""
    world = _SeedWorld()
    world.persist_error = RuntimeError
    with pytest.raises(RuntimeError):
        await _run(world, INVESTIGATION_ID, "non_mappable")


@pytest.mark.asyncio
async def test_si20_cancellation_propagates() -> None:
    """SI20: ``asyncio.CancelledError`` always propagates unchanged."""
    world = _SeedWorld()
    world.claim_error = asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await _run(world, INVESTIGATION_ID, "non_mappable")
