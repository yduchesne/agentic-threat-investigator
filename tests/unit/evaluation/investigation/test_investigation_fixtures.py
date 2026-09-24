# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for Investigation fixture worlds (PR 30F)."""

from __future__ import annotations

import pytest

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.evaluation.investigation.fixtures import (
    SUPPORTED_FIXTURE_NAMES,
    InvestigationFixtureError,
    build_investigation_provider_registry,
    investigation_fixture,
)


def test_known_fixture_resolves_exact_world() -> None:
    """A known fixture returns its exact declared world (F01)."""
    fixture = investigation_fixture("f02-malicious-multi-source")
    assert fixture.root_label == "root_domain"
    assert fixture.root_type is EntityType.DOMAIN
    assert fixture.root_value == "update-package.test"
    assert fixture.enabled_providers == (
        SourceId.GOOGLE_PUBLIC_DNS,
        SourceId.RDAP,
        SourceId.THREATFOX,
        SourceId.ABUSEIPDB,
    )
    assert fixture.world_entities["resolved_ip"] == (
        EntityType.IP_ADDRESS,
        "203.0.113.81",
    )
    assert fixture.world_entities["malware_family"] == (
        EntityType.MALWARE,
        "malware.badloader_v2",
    )


def test_unknown_fixture_fails_closed() -> None:
    """An unknown fixture name fails closed (F02)."""
    with pytest.raises(InvestigationFixtureError):
        investigation_fixture("no-such-fixture")


def test_supported_fixture_names_registered() -> None:
    """The six canonical fixture worlds are all registered."""
    assert {
        "f02-malicious-multi-source",
        "f01-benign",
        "f05-insufficient-evidence",
        "conflicting-evidence",
        "research-required-malware",
        "f02-shared-infrastructure-cycle",
    } == SUPPORTED_FIXTURE_NAMES


def test_scenario_owned_worlds_validate_through_catalog() -> None:
    """Custom worlds pass the strict catalog extraction-contract validation.

    Loading the catalog proves every observation is extractable through the
    production extraction contracts; the investigation_fixture() seam already
    loaded them, so a second explicit lookup must not raise.
    """
    for name in ("conflicting-evidence", "research-required-malware"):
        fixture = investigation_fixture(name)
        assert fixture.catalog is not None
        assert fixture.enabled_providers


def test_provider_registry_states_truth_only() -> None:
    """The fixture provider registry exposes exactly the enabled providers (F06).

    Providers implement the production EvidenceProvider boundary over the
    fixture catalog; the registry never contains unscripted providers.
    """
    fixture = investigation_fixture("f02-malicious-multi-source")
    registry = build_investigation_provider_registry(fixture)
    assert set(registry) == set(fixture.enabled_providers)
    for provider, implementation in registry.items():
        assert implementation.id == provider.value
