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

from datetime import UTC
from uuid import UUID

import pytest

from agentic_threat_investigator.config.settings import OperatingMode, Settings
from tests.e2e_support.seed_geoint import (
    E2E_SEEDING_ENABLE_ENV,
    SEED_RETRIEVED_AT,
    E2eSeedingGuardError,
    UnknownSeedScenarioError,
    _parse_investigation_id,
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
