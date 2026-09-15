# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 25C seeder unit tests (C-S01..C-S13).

The seeder is harness-only deterministic geolocation seeding. Unit coverage
fixes the pure contracts — allowlisted scenarios, deterministic identity
derivation, the explicit E2E environment guard, bounded idempotency, and
the normal repository/UoW persistence seam — without any database. The
real PostgreSQL behavior lives in the PR 25C integration tests.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC
from pathlib import Path
from types import TracebackType
from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.app.persistence.repositories import (
    EntityBatchItem,
    EntityBatchResult,
    EntityRepository,
    EvidenceRepository,
    InvestigationRepository,
)
from agentic_threat_investigator.config.settings import OperatingMode, Settings
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.geolocation import GeoPrecision
from agentic_threat_investigator.domain.identifiers import SourceId
from tests.e2e_support.seed_geolocation import (
    E2E_SEEDING_ENABLE_ENV,
    PROVIDER,
    SEED_RETRIEVED_AT,
    E2eSeedingGuardError,
    E2eSeedInvestigationMissingError,
    SeedEvidenceUnit,
    UnknownSeedScenarioError,
    _parse_investigation_id,
    apply_seed,
    build_seed_units,
    derive_entity_id,
    derive_evidence_id,
    require_e2e_environment,
    scenario_fixtures,
    seed_main,
)

INVESTIGATION_ID = UUID("20000000-0000-4000-8000-000000000001")


class FakeEntities(EntityRepository):
    """In-memory canonical entity repository recording every upsert.

    Only :meth:`upsert` is exercised by the seeder; the remaining ABC
    contract methods are unreachable stubs for the in-memory world.
    """

    def __init__(self) -> None:
        self.upserted: list[Entity] = []

    async def upsert(
        self, entity: Entity, *, expected_version: int | None = None
    ) -> Entity:
        """Record and return the entity with its deterministic identity."""
        self.upserted.append(entity)
        return entity.model_copy(update={"id": entity.id})

    async def get_by_identity(  # pragma: no cover - unused stub
        self,
        entity_type: str,
        canonical_value: str,
        *,
        include_deleted: bool = False,
    ) -> Entity | None:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def get_by_id(  # pragma: no cover - unused stub
        self, entity_id: UUID, *, include_deleted: bool = False
    ) -> Entity | None:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def upsert_batch(  # pragma: no cover - unused stub
        self, items: Sequence[EntityBatchItem]
    ) -> list[EntityBatchResult]:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def soft_delete(  # pragma: no cover - unused stub
        self,
        entity_id: UUID,
        *,
        actor_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Entity:
        """Unused in-memory stub."""
        raise NotImplementedError


class FakeEvidence(EvidenceRepository):
    """In-memory immutable evidence store with deterministic identities."""

    def __init__(self) -> None:
        self.rows: dict[UUID, Evidence] = {}

    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        """Return the stored evidence row, if any."""
        return self.rows.get(evidence_id)

    async def insert(
        self,
        evidence: Evidence,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Evidence:
        """Store the row and return it with its identity."""
        assert evidence.id is not None
        self.rows[evidence.id] = evidence
        return evidence

    async def list_for_investigation(  # pragma: no cover - unused stub
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Evidence]:
        """Unused in-memory stub."""
        raise NotImplementedError


class FakeInvestigations(InvestigationRepository):
    """In-memory investigation reader driven by an explicit visibility set."""

    def __init__(self, known: set[UUID]) -> None:
        self.known = known

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> Any:
        """Return a sentinel for known visible Investigations, else None."""
        return object() if investigation_id in self.known else None

    async def create(  # pragma: no cover - unused stub
        self,
        state: Any,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Any:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def update_assessment_reference(  # pragma: no cover - unused stub
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Any:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def update_report_reference(  # pragma: no cover - unused stub
        self,
        investigation_id: UUID,
        report_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Any:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def set_analysis_result(  # pragma: no cover - unused stub
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        analyzed_evidence_ids: list[UUID],
        disposition: Any,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> Any:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def update_budget(  # pragma: no cover - unused stub
        self,
        investigation_id: UUID,
        budget: Any,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Any:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def update_status(  # pragma: no cover - unused stub
        self,
        investigation_id: UUID,
        status: Any,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Any:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def update_coordinator_state(  # pragma: no cover - unused stub
        self,
        investigation_id: UUID,
        transition_kind: Any,
        state: Any,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        consumes_replan: bool = False,
    ) -> Any:
        """Unused in-memory stub."""
        raise NotImplementedError

    async def soft_delete(  # pragma: no cover - unused stub
        self,
        investigation_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Any:
        """Unused in-memory stub."""
        raise NotImplementedError


class FakeUnitOfWork:
    """In-memory seam satisfying the seeder's ``SeedUnitOfWork``.

    The member attributes are annotated with the application ABC types
    (the same convention the production PostgreSQL UoW follows) so the
    seam is exactly the protocol the seeder consumes; the runtime
    instances are the in-memory fakes above.
    """

    investigations: InvestigationRepository
    entities: EntityRepository
    evidence: EvidenceRepository
    # Concrete in-memory views for test assertions (the ABC-typed members
    # above keep the seam identical to the production UoW's typing).
    entity_store: FakeEntities
    evidence_store: FakeEvidence

    def __init__(
        self,
        *,
        known_investigations: set[UUID],
        entities: FakeEntities | None = None,
        evidence: FakeEvidence | None = None,
    ) -> None:
        entity_store = entities or FakeEntities()
        evidence_store = evidence or FakeEvidence()
        self.investigations = FakeInvestigations(known_investigations)
        self.entities = entity_store
        self.evidence = evidence_store
        self.entity_store = entity_store
        self.evidence_store = evidence_store

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


def _settings(*, mode: OperatingMode) -> Settings:
    """Build one typed settings fixture for the guard tests."""
    return Settings(operating_mode=mode)


def _facts(unit: SeedEvidenceUnit) -> dict[str, object]:
    """Return the frozen facts of one seed unit as a plain dictionary."""
    assert isinstance(unit.evidence.facts, dict)
    return dict(unit.evidence.facts)


def test_cs01_unknown_scenario_rejected() -> None:
    """C-S01: any scenario outside the allowlist fails closed."""
    with pytest.raises(UnknownSeedScenarioError):
        scenario_fixtures("bogus_scenario")
    with pytest.raises(UnknownSeedScenarioError):
        build_seed_units(INVESTIGATION_ID, "single_mappable_extra")
    with pytest.raises(UnknownSeedScenarioError):
        scenario_fixtures("")


def test_cs02_malformed_investigation_id_rejected() -> None:
    """C-S02: non-UUID and nil Investigation IDs fail closed."""
    with pytest.raises(ValueError, match="malformed investigation id"):
        _parse_investigation_id("not-a-uuid")
    with pytest.raises(ValueError, match="nil UUID"):
        _parse_investigation_id("00000000-0000-0000-0000-000000000000")


@pytest.mark.asyncio
async def test_cs03_missing_investigation_rejected() -> None:
    """C-S03: an absent/soft-deleted Investigation refuses seeding."""
    with pytest.raises(E2eSeedInvestigationMissingError):
        await apply_seed(
            lambda: FakeUnitOfWork(known_investigations=set()),
            INVESTIGATION_ID,
            "single_mappable",
        )


def test_cs04_e2e_guard_required() -> None:
    """C-S04: both fake mode and the dedicated flag are mandatory."""
    with pytest.raises(E2eSeedingGuardError, match="must be fake"):
        require_e2e_environment(
            _settings(mode=OperatingMode.PRODUCTION), {E2E_SEEDING_ENABLE_ENV: "1"}
        )
    with pytest.raises(E2eSeedingGuardError, match="dedicated E2E seeding flag"):
        require_e2e_environment(_settings(mode=OperatingMode.FAKE), {})
    # Both conditions satisfied: no exception.
    require_e2e_environment(
        _settings(mode=OperatingMode.FAKE), {E2E_SEEDING_ENABLE_ENV: "1"}
    )


def test_cs13_cli_guard_refuses_without_flag(monkeypatch: Any) -> None:
    """C-S13: the CLI exits nonzero when the guard is not satisfied."""
    monkeypatch.delenv("ATI_OPERATING_MODE", raising=False)
    monkeypatch.delenv(E2E_SEEDING_ENABLE_ENV, raising=False)
    assert (
        seed_main(
            ["--investigation", str(INVESTIGATION_ID), "--scenario", "single_mappable"]
        )
        == 2
    )


def test_cs05_valid_single_mappable_construction() -> None:
    """C-S05: one fully paired city-precision fixture per unit."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "single_mappable")
    assert unit.entity_id == derive_entity_id("203.0.113.10")
    assert unit.evidence_id == derive_evidence_id(
        INVESTIGATION_ID, "single_mappable", 0, "203.0.113.10"
    )
    assert unit.evidence.type is EvidenceType.GEOLOCATION
    assert unit.evidence.investigation_id == INVESTIGATION_ID
    assert unit.evidence.subject.value == "203.0.113.10"
    facts = _facts(unit)
    assert facts["provider"] == PROVIDER == SourceId.DBIP_CITY_LITE.value
    assert facts["precision"] == GeoPrecision.CITY.value
    assert facts["latitude"] == 47.6062 and facts["longitude"] == -122.3321
    assert facts["city"] == "Seattle" and facts["region"] == "Washington"


def test_cs06_distinct_multi_ioc_identities() -> None:
    """C-S06: multi-IOC fixtures keep distinct Entity/Evidence identities."""
    first, second = build_seed_units(INVESTIGATION_ID, "multi_ioc")
    assert first.ip == "203.0.113.10" and second.ip == "203.0.113.20"
    assert first.entity_id != second.entity_id
    assert first.evidence_id != second.evidence_id
    assert first.evidence.subject.id == first.entity_id
    assert second.evidence.subject.id == second.entity_id


def test_cs07_same_coordinate_identities_remain_distinct() -> None:
    """C-S07: identical coordinates never collide Entity/Evidence identity."""
    first, second = build_seed_units(INVESTIGATION_ID, "same_location")
    assert first.ip == "203.0.113.10" and second.ip == "198.51.100.30"
    assert _facts(first)["latitude"] == _facts(second)["latitude"]
    assert _facts(first)["longitude"] == _facts(second)["longitude"]
    assert first.entity_id != second.entity_id
    assert first.evidence_id != second.evidence_id


def test_cs08_null_null_coordinate_fixture_valid() -> None:
    """C-S08: valid region/country context with null/null coordinates."""
    (unit,) = build_seed_units(INVESTIGATION_ID, "non_mappable")
    facts = _facts(unit)
    assert facts["latitude"] is None and facts["longitude"] is None
    assert facts["precision"] == GeoPrecision.REGION.value
    assert facts["country_code"] == "US" and facts["region"] == "Oregon"
    assert unit.ip == "192.0.2.40"
    # The pair is complete: neither coordinate may be present alone.
    assert (facts["latitude"] is None) == (facts["longitude"] is None)


def test_cs09_deterministic_timestamps_and_values() -> None:
    """C-S09: repeated derivation yields identical UUIDs and timestamps."""
    first = build_seed_units(INVESTIGATION_ID, "multi_ioc")
    second = build_seed_units(INVESTIGATION_ID, "multi_ioc")
    for left, right in zip(first, second, strict=True):
        assert left.entity_id == right.entity_id
        assert left.evidence_id == right.evidence_id
        assert (
            left.evidence.retrieved_at
            == right.evidence.retrieved_at
            == SEED_RETRIEVED_AT
        )
        assert left.evidence.retrieved_at.tzinfo == UTC
        assert _facts(left) == _facts(right)
        assert left.evidence.source_record_id is None
        assert left.evidence.observed_at is None


@pytest.mark.asyncio
async def test_cs10_repeated_invocation_bounded_idempotent() -> None:
    """C-S10: re-seeding reuses rows and never creates uncontrolled duplicates."""
    world = FakeUnitOfWork(known_investigations={INVESTIGATION_ID})

    first = await apply_seed(lambda: world, INVESTIGATION_ID, "multi_ioc")
    assert len(first.created_evidence_ids) == 2
    assert first.reused_evidence_ids == ()
    assert len(world.evidence_store.rows) == 2
    assert len(world.entity_store.upserted) == 2

    second = await apply_seed(lambda: world, INVESTIGATION_ID, "multi_ioc")
    assert second.created_evidence_ids == ()
    assert tuple(sorted(second.reused_evidence_ids)) == tuple(
        sorted(first.created_evidence_ids)
    )
    assert len(world.evidence_store.rows) == 2
    assert len(world.entity_store.upserted) == 4  # canonical upserts, no new rows

    third = await apply_seed(lambda: world, INVESTIGATION_ID, "multi_ioc")
    assert third.created_evidence_ids == ()
    assert len(world.evidence_store.rows) == 2


def test_cs11_no_raw_payload_or_secrets_required() -> None:
    """C-S11: seed units carry no raw payload and no secret-bearing values."""
    for scenario in ("single_mappable", "multi_ioc", "non_mappable", "same_location"):
        for unit in build_seed_units(INVESTIGATION_ID, scenario):
            assert unit.evidence.raw_payload is None
            assert unit.evidence.source_url is None
            rendered = f"{unit.evidence.model_dump(mode='json')} {unit.entity.model_dump(mode='json')}"
            for secret_marker in ("password", "api_key", "token", "secret"):
                assert secret_marker not in rendered.lower()


def test_cs12_normal_repository_uow_seam_used() -> None:
    """C-S12: the seeder writes only through normal repository affordances.

    Structural review: the seeder module owns no SQLALCHEMY ``text``
    execution and no session-level SQL, so persistence necessarily flows
    through the ``investigations.get_by_id`` / ``entities.upsert`` /
    ``evidence.insert`` seam (behaviorally exercised by the
    real-PostgreSQL integration tests).
    """
    import tests.e2e_support.seed_geolocation as module

    assert module.__file__ is not None
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "text(" not in source
    assert "session.execute" not in source
    # The concrete production adapter is the only persistence seam used.
    assert "PostgresUnitOfWork" in source
