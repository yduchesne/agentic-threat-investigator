# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Harness-only deterministic GEOINT seeding seam (PR 26E §18).

The PR 26E browser workflows must see real canonical geographic truth
created through the *normal* PR 26 pipeline:

```text
browser-created Investigation
 -> deterministic normal GEOLOCATION LegacyEvidence
 -> GeoResolution
 -> production PR 26 resolver/completion
 -> canonical Location / EntityLocationObservation
 -> PR 26D API
 -> PR 26E browser
```

This module is the smallest deterministic real-stack seeding option: a
test-support CLI that persists ordinary canonical IP Entities and
immutable ``GEOLOCATION`` LegacyEvidence rows (exactly like the PR 25C seeder),
creates the deterministic ``GeoResolution`` work rows, and then drives the
**production** :class:`GeoResolutionWorker` with the real
``PostgresCanonicalGeographyResolver`` to atomic completion. The
canonical Location, ``EntityLocationObservation``, and ``EntityLocation``
reconciliation are created by the production stored functions — never by
direct inserts (PR 26E §18: "Never directly insert Location,
EntityLocationObservation or EntityLocation to make UI tests pass").

Non-negotiable seam properties (mirrors PR 25C §16-§24):

- test/E2E-only, explicitly invoked, scoped to the throwaway E2E database;
- deterministic and idempotent/bounded: deterministic UUID/timestamp
  derivation means repeated invocation of one scenario for one
  Investigation reuses the exact same rows instead of duplicating them;
- offline and non-LLM: no network, no provider, no orchestration beyond
  the local worker;
- inaccessible through production HTTP: there is deliberately no seed
  endpoint in ``api/``;
- inactive in normal local fake mode: both ``ATI_OPERATING_MODE=fake``
  **and** the dedicated ``ATI_E2E_SEEDING_ENABLED`` flag are required;
- no raw SQL: every write goes through the normal repositories and the
  SQL-API-owned worker lifecycle.

Reference geography must be loaded through the normal PR 26B work
(``ati-geography-build`` + ``ati-geography-import``) before seeding; the
seeder fails when resolution did not produce the expected observations.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Protocol, Self, cast
from uuid import UUID, uuid5

from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.geoint.worker import (
    GeoResolutionWorker,
    GeoResolutionWorkerConfig,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EntityLocationObservationRepository,
    EntityRepository,
    EvidenceObservationEntityRepository,
    EvidenceRepository,
    GeoResolutionRepository,
    InvestigationEvidenceRepository,
    InvestigationRepository,
)
from agentic_threat_investigator.config import get_settings
from agentic_threat_investigator.config.settings import OperatingMode, Settings
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
    GeoResolution,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.composites import (
    register_batch_composites,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

LOGGER = logging.getLogger("ati.e2e_support.seed_geoint")

# The dedicated E2E seeding enable flag (same gate as PR 25C).
E2E_SEEDING_ENABLE_ENV = "ATI_E2E_SEEDING_ENABLED"

# Fixed deterministic UTC timestamps shared by every seeded row. A
# repeated invocation derives the same timestamps, keeping the persisted
# rows byte-identical and the worker completions (and the PR 26A
# currentness ordering) deterministic.
SEED_RETRIEVED_AT = datetime(2026, 7, 1, tzinfo=UTC)
SEED_OBSERVED_AT = SEED_RETRIEVED_AT - timedelta(hours=1)
SEED_RESOLVED_AT = datetime(2026, 7, 1, 3, 0, 0, tzinfo=UTC)

# Fixed namespace under which every seeded identity is deterministically
# derived (uuid5). Syntactic UUID only: it never identifies a stored row.
_SEED_NAMESPACE = UUID("b4e7c4d0-4a2e-4f8a-bc6e-7e9a0d8f1b2c")

# Bounded worker policy used by one seeding run (completion only).
_WORKER_CONFIG = GeoResolutionWorkerConfig(
    enabled=True,
    worker_id="seed-geoint",
    batch_size=100,
    lease_seconds=300,
    poll_interval_seconds=1.0,
    max_attempts=3,
    retry_base_seconds=60.0,
    retry_max_seconds=3600.0,
)


class E2eSeedingGuardError(RuntimeError):
    """Raised when the explicit E2E seeding environment guard fails."""


class UnknownSeedScenarioError(ValueError):
    """Raised for a scenario name outside the allowlist."""


class E2eSeedInvestigationMissingError(LookupError):
    """Raised when the target Investigation does not exist or is not visible."""


class E2eSeedResolutionIncompleteError(RuntimeError):
    """Raised when the production resolver produced no expected observation."""


@dataclass(frozen=True)
class GeointFixture:
    """One deterministic GEOLOCATION fixture for the canonical pipeline.

    The exact fact vocabulary (``country_code``/``region``/``city``/
    ``precision``) mirrors the PR 26C claim extraction contract so the
    seeded LegacyEvidence resolves canonically. Geography is explicitly
    synthetic test data (documentation-reserved IP ranges, the ATI
    reference fixture corpus) and asserts nothing about the real location
    of those addresses.
    """

    entity_value: str
    facts: dict[str, str]
    # Per-observation retrieval offset from SEED_RETRIEVED_AT (hours).
    retrieval_hours: int


# Documentation-reserved IP ranges only (RFC 5737 documentation block
# 192.0.2.0/24 and RFC 5737 TEST-NET), never routable production
# addresses. City facts resolve to Seattle/Dallas, an administrative fact
# to Washington, and the country fact to EdgeLand (ZZ), which the
# reference fixture corpus persists with NULL geometry/centroid so its
# representative coordinates are absent.
SEATTLE_FIXTURE = {
    "country_code": "US",
    "region": "Washington",
    "city": "Seattle",
    "precision": "city",
}
DALLAS_FIXTURE = {
    "country_code": "US",
    "region": "Texas",
    "city": "Dallas",
    "precision": "city",
}
WASHINGTON_FIXTURE = {
    "country_code": "US",
    "region": "Washington",
    "precision": "region",
}
EDGELAND_FIXTURE = {
    "country_code": "ZZ",
    "precision": "country",
}


def as_fixtures(
    values: tuple[tuple[str, dict[str, str], int], ...],
) -> tuple[GeointFixture, ...]:
    """Build fixture tuples with bounded names (deterministic)."""
    return tuple(
        GeointFixture(entity_value=value, facts=dict(facts), retrieval_hours=hours)
        for value, facts, hours in values
    )


# Allowlisted scenario -> ordered fixtures. No generic fixture DSL
# exists; only these five named scenarios are legal.
SEED_SCENARIOS: Mapping[str, tuple[GeointFixture, ...]] = {
    # One Entity, two Locations/times (Seattle earlier, Dallas newer).
    "entity_history": as_fixtures(
        (
            ("203.0.113.10", SEATTLE_FIXTURE, 0),
            ("203.0.113.10", DALLAS_FIXTURE, 5),
        )
    ),
    # Two unrelated Entities at the same canonical city.
    "same_location": as_fixtures(
        (
            ("203.0.113.20", SEATTLE_FIXTURE, 0),
            ("203.0.113.30", SEATTLE_FIXTURE, 0),
        )
    ),
    # Entity A at city precision (Seattle); Entity B at admin precision
    # (Washington) so exact vs contained differ at WA/US.
    "containment": as_fixtures(
        (
            ("203.0.113.40", SEATTLE_FIXTURE, 0),
            ("203.0.113.50", WASHINGTON_FIXTURE, 0),
        )
    ),
    # Shared Entity observed at different Locations/times: the second
    # observation is attached to a *different* Investigation, so I1 must
    # never see it (requires --other-investigation).
    "cross_investigation": as_fixtures(
        (
            ("203.0.113.60", SEATTLE_FIXTURE, 0),
            ("203.0.113.60", DALLAS_FIXTURE, 5),
        )
    ),
    # Valid observation whose canonical Location has no representative
    # coordinates (EdgeLand country, NULL centroid).
    "non_mappable": as_fixtures((("203.0.113.70", EDGELAND_FIXTURE, 0),)),
}

SCENARIO_NAMES: tuple[str, ...] = tuple(SEED_SCENARIOS)


def scenario_fixtures(scenario: str) -> tuple[GeointFixture, ...]:
    """Return the fixtures of one allowlisted scenario (fail closed)."""
    fixtures = SEED_SCENARIOS.get(scenario)
    if fixtures is None:
        raise UnknownSeedScenarioError(
            f"unknown geoint seed scenario {scenario!r}; "
            f"allowlisted scenarios are {', '.join(SCENARIO_NAMES)}"
        )
    return fixtures


def derive_entity_id(entity_value: str) -> UUID:
    """Derive the deterministic canonical Entity UUID for one value."""
    return uuid5(_SEED_NAMESPACE, f"sgeoint-entity:{entity_value}")


def derive_evidence_id(
    investigation_id: UUID,
    scenario: str,
    index: int,
    entity_value: str,
    *,
    other_investigation_id: UUID | None = None,
) -> UUID:
    """Derive the deterministic immutable LegacyEvidence UUID for one fixture row.

    The cross-Investigation scenario derives the second row against the
    *other* Investigation so repeated runs reuse the exact same row and
    I1's scope stays immune to it.
    """
    scope = investigation_id
    if other_investigation_id is not None and index >= 1:
        scope = other_investigation_id
    return uuid5(
        _SEED_NAMESPACE,
        f"sgeoint-evidence:{scenario}:{scope}:{index}:{entity_value}",
    )


def derive_resolution_id(
    investigation_id: UUID,
    scenario: str,
    index: int,
    entity_id: UUID,
    evidence_id: UUID,
    *,
    other_investigation_id: UUID | None = None,
) -> UUID:
    """Derive the deterministic GeoResolution identity of one fixture row."""
    scope = investigation_id
    if other_investigation_id is not None and index >= 1:
        scope = other_investigation_id
    return uuid5(
        _SEED_NAMESPACE,
        f"sgeoint-resolution:{scenario}:{scope}:{index}:{entity_id}:{evidence_id}",
    )


@dataclass(frozen=True)
class SeedUnit:
    """One deterministic Entity + GEOLOCATION observation + resolution plan."""

    entity_id: UUID
    evidence_id: UUID
    resolution_id: UUID
    entity_value: str
    evidence: ConvertedEvidence
    admitted_to: UUID

    @property
    def entity(self) -> Entity:
        """The canonical IP entity of this unit (persistence canonicalizes)."""
        return Entity(
            id=self.entity_id, type=EntityType.IP_ADDRESS, value=self.entity_value
        )


def build_seed_units(
    investigation_id: UUID,
    scenario: str,
    *,
    other_investigation_id: UUID | None = None,
) -> tuple[SeedUnit, ...]:
    """Build the deterministic persistence plan of one scenario.

    The units derive purely from the allowlisted scenario and the exact
    Investigation UUIDs: identical inputs yield identical entity/evidence/
    resolution UUIDs and timestamps. No raw payload, provider payload,
    secret, or analyst-supplied fact ever enters the plan.
    """
    fixtures = scenario_fixtures(scenario)
    if scenario == "cross_investigation" and other_investigation_id is None:
        raise UnknownSeedScenarioError(
            "geoint seed scenario 'cross_investigation' requires --other-investigation"
        )
    if scenario != "cross_investigation" and other_investigation_id is not None:
        raise UnknownSeedScenarioError(
            f"scenario {scenario!r} does not accept --other-investigation"
        )
    units: list[SeedUnit] = []
    for index, fixture in enumerate(fixtures):
        entity_id = derive_entity_id(fixture.entity_value)
        evidence_id = derive_evidence_id(
            investigation_id,
            scenario,
            index,
            fixture.entity_value,
            other_investigation_id=other_investigation_id,
        )
        resolution_id = derive_resolution_id(
            investigation_id,
            scenario,
            index,
            entity_id,
            evidence_id,
            other_investigation_id=other_investigation_id,
        )
        retrieved_at = SEED_RETRIEVED_AT + timedelta(hours=fixture.retrieval_hours)
        stable_id = uuid5(
            _SEED_NAMESPACE,
            f"sgeoint-stable:{scenario}:{index}:{fixture.entity_value}",
        )
        evidence = ConvertedEvidence(
            evidence=Evidence(
                id=stable_id,
                type=EvidenceType.GEOLOCATION,
                source="urn:ati:source:e2e-seed",
                source_record_id=f"sgeoint:{scenario}:{index}:{fixture.entity_value}",
            ),
            observation=EvidenceObservationCandidate(
                evidence_id=stable_id,
                source_url=None,
                observed_at=SEED_OBSERVED_AT + timedelta(hours=fixture.retrieval_hours),
                retrieved_at=retrieved_at,
                facts=dict(fixture.facts),
                raw_payload=None,
            ),
        )
        units.append(
            SeedUnit(
                entity_id=entity_id,
                evidence_id=evidence_id,
                resolution_id=resolution_id,
                entity_value=fixture.entity_value,
                evidence=evidence,
                admitted_to=(
                    investigation_id
                    if index == 0
                    else (other_investigation_id or investigation_id)
                ),
            )
        )
    return tuple(units)


@dataclass(frozen=True)
class SeedReport:
    """Bounded machine-readable diagnostics of one seeding invocation."""

    scenario: str
    investigation_id: UUID
    other_investigation_id: UUID | None
    entity_ids: tuple[UUID, ...] = field(default_factory=tuple)
    evidence_ids: tuple[UUID, ...] = field(default_factory=tuple)
    observation_ids: tuple[UUID, ...] = field(default_factory=tuple)
    created_evidence_ids: tuple[UUID, ...] = field(default_factory=tuple)
    reused_evidence_ids: tuple[UUID, ...] = field(default_factory=tuple)

    def render(self) -> str:
        """Render one diagnostic line containing no secrets or payloads."""
        parts = [
            "E2E-GEOINT-SEED",
            f"scenario={self.scenario}",
            f"investigation={self.investigation_id}",
        ]
        if self.other_investigation_id is not None:
            parts.append(f"other_investigation={self.other_investigation_id}")
        parts.append(
            f"observation_ids={','.join(str(uuid) for uuid in self.observation_ids)}"
        )
        return " ".join(parts)


def require_e2e_environment(
    settings: Settings, environ: Mapping[str, str] | None = None
) -> None:
    """Fail closed unless the explicit E2E seeding guard is satisfied.

    Both conditions are mandatory (PR 25C §23): operating mode ``fake``
    and the dedicated ``ATI_E2E_SEEDING_ENABLED`` flag. Normal manual fake
    mode is refused so product fake behavior never changes.
    """
    environment = os.environ if environ is None else environ
    if settings.operating_mode is not OperatingMode.FAKE:
        raise E2eSeedingGuardError(
            "geoint seeding refused: ATI_OPERATING_MODE must be fake "
            f"(got {settings.operating_mode.value!r})"
        )
    flag = environment.get(E2E_SEEDING_ENABLE_ENV, "").strip().lower()
    if flag not in ("1", "true", "yes", "on"):
        raise E2eSeedingGuardError(
            "geoint seeding refused: the dedicated E2E seeding flag "
            f"{E2E_SEEDING_ENABLE_ENV} must be set to 1/true/yes/on"
        )


class SeedUnitOfWork(Protocol):
    """The narrow persistence seam the seeder consumes.

    ``PostgresUnitOfWork`` satisfies this protocol; unit tests inject an
    in-memory fake. Only the read/write affordances required by the
    normal application path are exposed.
    """

    investigations: InvestigationRepository
    entities: EntityRepository
    evidence: EvidenceRepository
    evidence_observation_entities: EvidenceObservationEntityRepository
    investigation_evidence: InvestigationEvidenceRepository
    geo_resolutions: GeoResolutionRepository
    entity_location_observations: EntityLocationObservationRepository

    async def __aenter__(self) -> Self:
        """Enter the transaction boundary."""

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit on success, roll back on failure."""


SeedUnitOfWorkFactory = Callable[[], SeedUnitOfWork]


async def apply_seed(
    uow_factory: SeedUnitOfWorkFactory,
    resolver: LocationResolver,
    investigation_id: UUID,
    scenario: str,
    *,
    other_investigation_id: UUID | None = None,
) -> SeedReport:
    """Persist evidence, enqueue work, and complete it through the worker.

    Every row is an ordinary canonical IP Entity + ``GEOLOCATION`` LegacyEvidence
    of the exact Investigation, a deterministic PENDING ``GeoResolution``,
    and the production worker completion (canonical matching + atomic
    stored-function completion creating the ``EntityLocationObservation``)
    — never a direct Location/Observation insert.
    """
    scenario_fixtures(scenario)  # validate allowlist before any persistence

    units = build_seed_units(
        investigation_id,
        scenario,
        other_investigation_id=other_investigation_id,
    )
    report = SeedReport(
        scenario=scenario,
        investigation_id=investigation_id,
        other_investigation_id=other_investigation_id,
    )

    # 1. Persist evidence + create PENDING work through the repositories.
    async with uow_factory() as uow:
        investigation = await uow.investigations.get_by_id(investigation_id)
        if investigation is None:
            raise E2eSeedInvestigationMissingError(
                f"investigation not found or not visible: {investigation_id}"
            )
        if (
            other_investigation_id is not None
            and await uow.investigations.get_by_id(other_investigation_id) is None
        ):
            raise E2eSeedInvestigationMissingError(
                f"other investigation not found or not visible: {other_investigation_id}"
            )
        entity_ids: list[UUID] = []
        evidence_ids: list[UUID] = []
        created: list[UUID] = []
        reused: list[UUID] = []
        for unit in units:
            entity = await uow.entities.upsert(unit.entity)
            if entity.id is None:  # pragma: no cover
                raise RuntimeError("seeded entity persisted without an id")
            entity_ids.append(entity.id)
            existing = await uow.evidence.get_observation(unit.evidence_id)
            if existing is not None:
                reused.append(unit.evidence_id)
                evidence_ids.append(unit.evidence_id)
                continue
            persisted = await uow.evidence.persist(
                unit.evidence, observation_id=unit.evidence_id
            )
            created.append(persisted.observation.id)
            evidence_ids.append(persisted.observation.id)
            await uow.evidence_observation_entities.associate(
                persisted.observation.id, entity.id
            )
            await uow.investigation_evidence.admit(
                InvestigationEvidence(
                    investigation_id=unit.admitted_to,
                    evidence_observation_id=persisted.observation.id,
                    inclusion_reason=InvestigationEvidenceReason.INITIAL,
                    added_at=SEED_RETRIEVED_AT,
                    added_by=InvestigationEvidenceActor.SYSTEM,
                )
            )
            pending = GeoResolution(
                id=unit.resolution_id,
                entity_id=entity.id,
                evidence_observation_id=persisted.observation.id,
            )
            await uow.geo_resolutions.create_pending(pending)
        report = SeedReport(
            scenario=scenario,
            investigation_id=investigation_id,
            other_investigation_id=other_investigation_id,
            entity_ids=tuple(entity_ids),
            evidence_ids=tuple(evidence_ids),
            created_evidence_ids=tuple(created),
            reused_evidence_ids=tuple(reused),
        )

    # 2. Production worker completion (claim -> resolve -> atomic complete).
    worker = GeoResolutionWorker(
        uow_factory=uow_factory,  # type: ignore[arg-type]
        resolver=resolver,
        config=_WORKER_CONFIG,
        clock=lambda: SEED_RESOLVED_AT,
    )
    await worker.run_once()

    # 3. Verify the canonical Observation rows exist through the worker's
    #    own repository boundary (never by direct table reads). An idempotent
    #    re-run claims nothing (the rows are already terminal), so the
    #    verification is the honest gate: every expected unit needs its
    #    canonical Observation row. One extra bounded pass drains any
    #    claim-boundary leftovers before the final check fails with the
    #    geography-not-imported diagnostic.
    observation_ids: list[UUID] = []

    async def missing_units() -> list[SeedUnit]:
        missing: list[SeedUnit] = []
        async with uow_factory() as uow:
            for unit in units:
                rows = await uow.entity_location_observations.list_for_entity(
                    unit.entity_id
                )
                if not [
                    row
                    for row in rows
                    if row.evidence_observation_id == unit.evidence_id
                ]:
                    missing.append(unit)
        return missing

    missing = await missing_units()
    if missing:
        await worker.run_once()
        missing = await missing_units()
    if missing:
        raise E2eSeedResolutionIncompleteError(
            f"expected a canonical observation for entity {missing[0].entity_id} "
            f"evidence {missing[0].evidence_id}; the reference geography may "
            "not be imported or the claim is invalid"
        )
    async with uow_factory() as uow:
        for unit in units:
            rows = await uow.entity_location_observations.list_for_entity(
                unit.entity_id
            )
            for row in rows:
                if row.evidence_observation_id != unit.evidence_id:
                    continue
                if row.id is None:  # pragma: no cover
                    raise E2eSeedResolutionIncompleteError(
                        "canonical observation persisted without an identity"
                    )
                observation_ids.append(row.id)
    return SeedReport(
        scenario=scenario,
        investigation_id=investigation_id,
        other_investigation_id=other_investigation_id,
        entity_ids=report.entity_ids,
        evidence_ids=report.evidence_ids,
        observation_ids=tuple(observation_ids),
        created_evidence_ids=report.created_evidence_ids,
        reused_evidence_ids=report.reused_evidence_ids,
    )


class _SessionBoundResolver(LocationResolver):
    """Production resolver seam with one short read session per resolve."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """Bind the read-session factory."""
        self._session_factory = session_factory

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Resolve through the real PostGIS canonical resolver."""
        from agentic_threat_investigator.infrastructure.persistence.postgresql.canonical_geography_resolver import (
            PostgresCanonicalGeographyResolver,
        )

        async with self._session_factory() as session:
            return await PostgresCanonicalGeographyResolver(session).resolve(claim)


def _make_engine(settings: Settings) -> AsyncEngine:
    """Create the async engine and register the batch composite types."""
    url = settings.database_url.replace(
        "postgresql+psycopg://", "postgresql+psycopg_async://", 1
    )
    engine = create_async_engine(url)

    @sqlalchemy_event.listens_for(engine.sync_engine, "connect")
    def _register_composites(dbapi_connection: object, _record: object) -> None:
        """Register custom types before a pooled connection is used."""
        run_async = getattr(dbapi_connection, "run_async", None)
        if run_async is not None:
            run_async(register_batch_composites)

    return engine


def _parse_investigation_id(raw: str) -> UUID:
    """Parse and canonically lowercase one Investigation UUID (fail closed)."""
    try:
        parsed = UUID(raw)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(f"malformed investigation id: {raw!r}") from exc
    if parsed.hex == "0" * 32:
        raise ValueError("investigation id must not be the nil UUID")
    return parsed


def seed_main(argv: list[str] | None = None) -> int:
    """Run the one-shot E2E GEOINT seeder and exit with its status code.

    Bounded machine-readable diagnostics print to stdout (including the
    exact observation UUIDs for cross-scope assertions); every failure
    path returns a nonzero status with no secret output. The browser never
    receives database credentials: the harness invokes this CLI, and the
    Playwright spec only observes the exit status and stdout.
    """
    parser = argparse.ArgumentParser(
        prog="ati-e2e-seed-geoint",
        description=(
            "Deterministic canonical GEOINT seeding for the isolated E2E "
            "database. Requires ATI_OPERATING_MODE=fake and "
            f"{E2E_SEEDING_ENABLE_ENV}=1."
        ),
    )
    parser.add_argument(
        "--investigation",
        required=True,
        metavar="UUID",
        help="exact browser-created Investigation UUID to attach the rows to",
    )
    parser.add_argument(
        "--other-investigation",
        metavar="UUID",
        default=None,
        help="second Investigation UUID (cross_investigation scenario only)",
    )
    parser.add_argument(
        "--scenario",
        required=True,
        choices=SCENARIO_NAMES,
        help="allowlisted seeding scenario name",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    try:
        require_e2e_environment(settings)
    except E2eSeedingGuardError as exc:
        print(f"E2E-GEOINT-SEED-FAILED {exc}", file=sys.stderr)
        return 2
    try:
        investigation_id = _parse_investigation_id(args.investigation)
        other_investigation_id = (
            None
            if args.other_investigation is None
            else _parse_investigation_id(args.other_investigation)
        )
    except ValueError as exc:
        print(f"E2E-GEOINT-SEED-FAILED {exc}", file=sys.stderr)
        return 2

    engine = _make_engine(settings)
    session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine, expire_on_commit=False
    )

    def uow_factory() -> SeedUnitOfWork:
        """Open one short transaction against the isolated E2E database."""
        return cast(SeedUnitOfWork, PostgresUnitOfWork(session_factory))

    async def run() -> int:
        try:
            report = await apply_seed(
                uow_factory,
                resolver=_SessionBoundResolver(session_factory),
                investigation_id=investigation_id,
                scenario=args.scenario,
                other_investigation_id=other_investigation_id,
            )
        except (
            UnknownSeedScenarioError,
            E2eSeedInvestigationMissingError,
            E2eSeedResolutionIncompleteError,
        ) as exc:
            print(f"E2E-GEOINT-SEED-FAILED {exc}", file=sys.stderr)
            return 2
        except Exception:
            LOGGER.exception("geoint seeding failed")
            print(
                "E2E-GEOINT-SEED-FAILED unexpected persistence error", file=sys.stderr
            )
            return 1
        finally:
            await engine.dispose()
        print(report.render())
        return 0

    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(seed_main())
