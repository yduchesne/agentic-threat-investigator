# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Harness-only deterministic geolocation seeding seam (PR 25C).

The PR 23D fake world composes no DB-IP provider, so a completed fake-world
Investigation persists no ``GEOLOCATION`` LegacyEvidence and the PR 25A projection
is honestly empty. The PR 25B E24 browser workflow cannot assert a real
marker against that empty state. This module is the smallest deterministic
real-stack seeding option agreed by the PR 25B STOP report: a test-support
CLI that persists ordinary canonical IP Entities and immutable
``GEOLOCATION`` LegacyEvidence rows into the isolated throwaway E2E database
through the normal application persistence seam.

Non-negotiable seam properties (PR 25C §16-§24):

- test/E2E-only, explicitly invoked, scoped to the throwaway E2E database;
- deterministic and idempotent/bounded: deterministic UUID/timestamp
  derivation means repeated invocation of one scenario for one
  Investigation reuses the exact same rows instead of duplicating them;
- offline and non-LLM: no network, no provider, no MMDB artifact, no
  orchestration;
- inaccessible through production HTTP: there is deliberately no seed
  endpoint in ``api/``;
- inactive in normal local fake mode: both ``ATI_OPERATING_MODE=fake``
  **and** the dedicated ``ATI_E2E_SEEDING_ENABLED`` flag are required;
- no raw SQL: every write goes through
  ``investigations.get_by_id``/``entities.upsert``/``evidence.insert`` of a
  real ``PostgresUnitOfWork`` (or an injected fake in unit tests).

The module is invoked directly by the isolated E2E harness
(``scripts/e2e-seed-geolocation.sh``) after the browser creates the exact
Investigation UUID:

``python -m tests.e2e_support.seed_geolocation --investigation <uuid> --scenario <name>``

Reserved documentation IP ranges are used exclusively; the fixture
geography is explicitly synthetic test data and never asserts real
geolocation for those addresses.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
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

from agentic_threat_investigator.app.persistence.repositories import (
    EntityRepository,
    EvidenceObservationEntityRepository,
    EvidenceRepository,
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
from agentic_threat_investigator.domain.geolocation import GeoPrecision
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.persistence.postgresql.composites import (
    register_batch_composites,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

LOGGER = logging.getLogger("ati.e2e_support.seed_geolocation")

# The dedicated E2E seeding enable flag. ``ATI_OPERATING_MODE=fake`` alone
# is deliberately insufficient (PR 25C §23): normal manual fake mode must
# remain unchanged, so this opt-in flag gates the seam on top of the
# operating mode.
E2E_SEEDING_ENABLE_ENV = "ATI_E2E_SEEDING_ENABLED"

# Provider must be the exact existing DB-IP City Lite source identifier
# expected by the PR 25A read projection.
PROVIDER = SourceId.DBIP_CITY_LITE.value

# Fixed deterministic UTC retrieval epoch shared by every seeded row. A
# repeated invocation derives the same timestamps, keeping the persisted
# rows byte-identical and the projection deterministic.
SEED_RETRIEVED_AT = datetime(2026, 6, 1, tzinfo=UTC)

# Fixed namespace under which every seeded identity is deterministically
# derived (uuid5). Syntactic UUID only: it never identifies a stored row.
_SEED_NAMESPACE = UUID("71ceced6-25c5-4fbe-8e19-8d0d16f5c3a7")


class E2eSeedingGuardError(RuntimeError):
    """Raised when the explicit E2E seeding environment guard fails."""


class UnknownSeedScenarioError(ValueError):
    """Raised for a scenario name outside the allowlist."""


class E2eSeedInvestigationMissingError(LookupError):
    """Raised when the target Investigation does not exist or is not visible."""


@dataclass(frozen=True)
class GeolocationFixture:
    """One deterministic reserved-range geolocation fixture (PR 25C §21).

    ``precision`` uses the actual current ``GeoPrecision`` enum. Geography is
    explicitly synthetic test data; it asserts nothing about the real
    location of documentation-reserved IP addresses.
    """

    ip: str
    country_code: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    precision: GeoPrecision


# Documentation-reserved IP ranges only (RFC 5737 documentation block
# 192.0.2.0/24 and RFC 5737 TEST-NET-1/2), never routable production
# addresses. City coordinates pair exactly (latitude/longitude always both
# present or both absent).
S_GEO_01 = GeolocationFixture(
    ip="203.0.113.10",
    country_code="US",
    region="Washington",
    city="Seattle",
    latitude=47.6062,
    longitude=-122.3321,
    precision=GeoPrecision.CITY,
)
S_GEO_02 = GeolocationFixture(
    ip="203.0.113.20",
    country_code="US",
    region="Texas",
    city="Dallas",
    latitude=32.7792,
    longitude=-96.8000,
    precision=GeoPrecision.CITY,
)
S_GEO_03 = GeolocationFixture(
    ip="198.51.100.30",
    country_code="US",
    region="Washington",
    city="Seattle",
    latitude=47.6062,
    longitude=-122.3321,
    precision=GeoPrecision.CITY,
)
S_GEO_04 = GeolocationFixture(
    ip="192.0.2.40",
    country_code="US",
    region="Oregon",
    city=None,
    latitude=None,
    longitude=None,
    precision=GeoPrecision.REGION,
)

# Allowlisted scenario -> ordered fixtures (PR 25C §20). No generic fixture
# DSL exists: only these four named scenarios are legal.
SEED_SCENARIOS: Mapping[str, tuple[GeolocationFixture, ...]] = {
    "single_mappable": (S_GEO_01,),
    "multi_ioc": (S_GEO_01, S_GEO_02),
    "non_mappable": (S_GEO_04,),
    "same_location": (S_GEO_01, S_GEO_03),
}

SCENARIO_NAMES: tuple[str, ...] = tuple(SEED_SCENARIOS)


def scenario_fixtures(scenario: str) -> tuple[GeolocationFixture, ...]:
    """Return the fixtures of one allowlisted scenario (fail closed).

    Raises :class:`UnknownSeedScenarioError` for any name outside the
    allowlist; no partial or fuzzy matching is performed.
    """
    fixtures = SEED_SCENARIOS.get(scenario)
    if fixtures is None:
        raise UnknownSeedScenarioError(
            f"unknown geolocation seed scenario {scenario!r}; "
            f"allowlisted scenarios are {', '.join(SCENARIO_NAMES)}"
        )
    return fixtures


def derive_entity_id(ip: str) -> UUID:
    """Derive the deterministic canonical Entity UUID for one fixture IP."""
    return uuid5(_SEED_NAMESPACE, f"sgeo-entity:{ip}")


def derive_evidence_id(
    investigation_id: UUID, scenario: str, index: int, ip: str
) -> UUID:
    """Derive the deterministic EvidenceObservation UUID for one fixture row."""
    return uuid5(
        _SEED_NAMESPACE,
        f"sgeo-observation:{scenario}:{investigation_id}:{index}:{ip}",
    )


@dataclass(frozen=True)
class SeedEvidenceUnit:
    """One deterministic Entity + global GEOLOCATION Evidence pair to persist.

    PR 28B: the unit persists a global ``ConvertedEvidence`` (stable
    Evidence + observation candidate) with the deterministic observation
    identity ``evidence_id``; the seeder admits it and associates the
    canonical Entity.
    """

    entity_id: UUID
    evidence_id: UUID
    ip: str
    converted: ConvertedEvidence

    @property
    def entity(self) -> Entity:
        """The canonical IP entity of this unit (persistence canonicalizes)."""
        return Entity(id=self.entity_id, type=EntityType.IP_ADDRESS, value=self.ip)


def _fixture_facts(fixture: GeolocationFixture) -> dict[str, object]:
    """Serialize one fixture into the approved persisted facts vocabulary.

    The facts keys mirror the DB-IP City Lite normalization output exactly
    (``provider``, ``precision``, ``country_code``, ``region``, ``city``,
    ``latitude``, ``longitude``) so the PR 25A mapper consumes them without
    reinterpretation.
    """
    return {
        "country_code": fixture.country_code,
        "region": fixture.region,
        "city": fixture.city,
        "latitude": fixture.latitude,
        "longitude": fixture.longitude,
        "provider": PROVIDER,
        "precision": fixture.precision.value,
    }


def build_seed_units(
    investigation_id: UUID, scenario: str
) -> tuple[SeedEvidenceUnit, ...]:
    """Build the deterministic persistence plan of one scenario.

    The units are derived purely from the allowlisted scenario and the exact
    Investigation UUID: identical inputs yield identical entity/evidence
    UUIDs and timestamps (C-S09 determinism). No raw payload, provider
    payload, secret, or analyst-supplied fact ever enters the plan
    (C-S11).
    """
    units: list[SeedEvidenceUnit] = []
    for index, fixture in enumerate(scenario_fixtures(scenario)):
        entity_id = derive_entity_id(fixture.ip)
        evidence_id = derive_evidence_id(investigation_id, scenario, index, fixture.ip)
        stable_evidence = Evidence(
            id=uuid5(
                _SEED_NAMESPACE,
                f"sgeo-evidence-stable:{scenario}:{index}:{fixture.ip}",
            ),
            type=EvidenceType.GEOLOCATION,
            source=PROVIDER,
            source_record_id=f"sgeo:{scenario}:{index}:{fixture.ip}",
        )
        converted = ConvertedEvidence(
            evidence=stable_evidence,
            observation=EvidenceObservationCandidate(
                evidence_id=stable_evidence.id,
                source_url=None,
                observed_at=None,
                retrieved_at=SEED_RETRIEVED_AT,
                facts=_fixture_facts(fixture),
                raw_payload=None,
            ),
        )
        units.append(
            SeedEvidenceUnit(
                entity_id=entity_id,
                evidence_id=evidence_id,
                ip=fixture.ip,
                converted=converted,
            )
        )
    return tuple(units)


@dataclass(frozen=True)
class SeedReport:
    """Bounded machine-readable diagnostics of one seeding invocation."""

    scenario: str
    investigation_id: UUID
    entity_ids: tuple[UUID, ...] = field(default_factory=tuple)
    created_evidence_ids: tuple[UUID, ...] = field(default_factory=tuple)
    reused_evidence_ids: tuple[UUID, ...] = field(default_factory=tuple)

    def render(self) -> str:
        """Render one diagnostic line containing no secrets or payloads."""
        return (
            "E2E-SEED "
            f"scenario={self.scenario} "
            f"investigation={self.investigation_id} "
            f"entities={len(self.entity_ids)} "
            f"created_evidence={len(self.created_evidence_ids)} "
            f"reused_evidence={len(self.reused_evidence_ids)} "
            f"entity_ids={','.join(str(uuid) for uuid in self.entity_ids)} "
            f"evidence_ids={','.join(str(uuid) for uuid in (*self.created_evidence_ids, *self.reused_evidence_ids))}"
        )


def require_e2e_environment(
    settings: Settings, environ: Mapping[str, str] | None = None
) -> None:
    """Fail closed unless the explicit E2E seeding guard is satisfied.

    Both conditions are mandatory (PR 25C §23): the operating mode must be
    ``fake`` **and** the dedicated ``ATI_E2E_SEEDING_ENABLED`` flag must be
    present with a truthy value. Normal manual fake mode (fake mode without
    the flag) is refused so product fake behavior never changes.
    """
    environment = os.environ if environ is None else environ
    if settings.operating_mode is not OperatingMode.FAKE:
        raise E2eSeedingGuardError(
            "geolocation seeding refused: ATI_OPERATING_MODE must be fake "
            f"(got {settings.operating_mode.value!r})"
        )
    flag = environment.get(E2E_SEEDING_ENABLE_ENV, "").strip().lower()
    if flag not in ("1", "true", "yes", "on"):
        raise E2eSeedingGuardError(
            "geolocation seeding refused: the dedicated E2E seeding flag "
            f"{E2E_SEEDING_ENABLE_ENV} must be set to 1/true/yes/on"
        )


class SeedUnitOfWork(Protocol):
    """The narrow persistence seam the seeder consumes (PR 25C §24).

    ``PostgresUnitOfWork`` satisfies this protocol; unit tests inject an
    in-memory fake. Only the ``investigations.get_by_id``,
    ``entities.upsert``, and ``evidence.get_by_id``/``evidence.insert``
    affordances are ever used — every write stays on the normal application
    persistence path. The members are typed by the application ABCs because
    those are the exact interfaces the concrete PostgreSQL adapter exposes.
    """

    investigations: InvestigationRepository
    entities: EntityRepository
    evidence: EvidenceRepository
    evidence_observation_entities: EvidenceObservationEntityRepository
    investigation_evidence: InvestigationEvidenceRepository

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
    investigation_id: UUID,
    scenario: str,
) -> SeedReport:
    """Persist one allowlisted scenario through the normal UoW/repositories.

    Every row is an ordinary PR 25A-readable IP Entity + ``GEOLOCATION``
    LegacyEvidence of the exact Investigation. The LegacyEvidence subject always binds
    to the persisted canonical Entity id (never to the deterministic input
    UUID when a pre-existing canonical row owns a different identity).
    Idempotency is bounded by the deterministic LegacyEvidence UUID: an existing
    row is reused, never re-inserted or duplicated (C-S10).
    """
    scenario_fixtures(scenario)  # validate allowlist before any persistence
    async with uow_factory() as uow:
        investigation = await uow.investigations.get_by_id(investigation_id)
        if investigation is None:
            raise E2eSeedInvestigationMissingError(
                f"investigation not found or not visible: {investigation_id}"
            )
        entity_ids: list[UUID] = []
        created: list[UUID] = []
        reused: list[UUID] = []
        for unit in build_seed_units(investigation_id, scenario):
            entity = await uow.entities.upsert(unit.entity)
            if entity.id is None:  # pragma: no cover - persisted rows have IDs
                raise RuntimeError("seeded entity persisted without an id")
            entity_ids.append(entity.id)
            existing = await uow.evidence.get_observation(unit.evidence_id)
            if existing is not None:
                reused.append(unit.evidence_id)
                continue
            persisted = await uow.evidence.persist(
                unit.converted, observation_id=unit.evidence_id
            )
            await uow.evidence_observation_entities.associate(
                persisted.observation.id, entity.id
            )
            await uow.investigation_evidence.admit(
                InvestigationEvidence(
                    investigation_id=investigation_id,
                    evidence_observation_id=persisted.observation.id,
                    inclusion_reason=InvestigationEvidenceReason.INITIAL,
                    added_at=SEED_RETRIEVED_AT,
                    added_by=InvestigationEvidenceActor.SYSTEM,
                )
            )
            created.append(persisted.observation.id)
        return SeedReport(
            scenario=scenario,
            investigation_id=investigation_id,
            entity_ids=tuple(entity_ids),
            created_evidence_ids=tuple(created),
            reused_evidence_ids=tuple(reused),
        )


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
    """Run the one-shot E2E geolocation seeder and exit with its status code.

    Bounded machine-readable diagnostics print to stdout; every failure
    path returns a nonzero status with no secret output. The browser never
    receives database credentials: the harness invokes this CLI, and the
    Playwright spec only observes the exit status and stdout.
    """
    parser = argparse.ArgumentParser(
        prog="ati-e2e-seed-geolocation",
        description=(
            "Deterministic GEOLOCATION seeding for the isolated E2E database. "
            "Requires ATI_OPERATING_MODE=fake and "
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
        print(f"E2E-SEED-FAILED {exc}", file=sys.stderr)
        return 2
    try:
        investigation_id = _parse_investigation_id(args.investigation)
    except ValueError as exc:
        print(f"E2E-SEED-FAILED {exc}", file=sys.stderr)
        return 2

    engine = _make_engine(settings)
    session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine, expire_on_commit=False
    )

    def uow_factory() -> SeedUnitOfWork:
        """Open one short transaction against the isolated E2E database.

        The concrete PostgreSQL UoW satisfies the narrow seed seam by
        construction; the cast only tells the type checker that the
        subclass-typed repository attributes conform (the same convention
        the production UoW itself uses for its repository attributes).
        """
        return cast(SeedUnitOfWork, PostgresUnitOfWork(session_factory))

    async def run() -> int:
        try:
            report = await apply_seed(uow_factory, investigation_id, args.scenario)
        except (UnknownSeedScenarioError, E2eSeedInvestigationMissingError) as exc:
            print(f"E2E-SEED-FAILED {exc}", file=sys.stderr)
            return 2
        except Exception:
            LOGGER.exception("geolocation seeding failed")
            print("E2E-SEED-FAILED unexpected persistence error", file=sys.stderr)
            return 1
        finally:
            await engine.dispose()
        print(report.render())
        return 0

    return asyncio.run(run())


def main(argv: list[str] | None = None) -> int:
    """Console entry point alias for ``python -m`` invocation."""
    return seed_main(argv)


if __name__ == "__main__":
    sys.exit(seed_main())
