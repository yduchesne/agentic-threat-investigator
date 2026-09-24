# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned end-to-end Investigation fixture worlds (PR 30F).

Each repository scenario references a fixture by stable name. A fixture
declares the canonical root indicator, the exact deterministic provider
world (through the repository-owned fake-runtime catalog), and the semantic
labels the scenario expectations reference. Providers are fixture-owned
**truth only**: they implement the production
:class:`~agentic_threat_investigator.app.providers.EvidenceProvider` boundary
and emit :class:`ConvertedEvidence` the existing production extractors
already understand, so the **production** Coordinator graph, policy,
transitions, budgets, analysis, research, and report lifecycle run exactly
as authored. No Coordinator policy is reimplemented and no log is parsed.

World truth sources:

- packaged worlds (F01 benign, F02 malicious multi-source, F05 insufficient)
  come from the repository-owned packaged fake catalog;
- scenario-owned worlds (conflicting evidence, research-required malware)
  are authored inline in this module and validated through the same strict
  catalog loader (including the production extraction-contract check).

The provider registry for one fixture enables exactly the providers whose
world truth the scenario authorizes; an unenabled provider is never planned
by the production Coordinator.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeWorldCatalog,
)
from agentic_threat_investigator.infrastructure.fake_runtime.providers import (
    FakeWorldEvidenceProvider,
)

_FIXED_CLOCK = datetime(2026, 10, 1, tzinfo=UTC)
"""Fixed UTC retrieval clock of every fixture-world provider.

The clock sits after every authored ``observed_at`` so no observation is
withheld as "future" by the catalog's source-history semantics.
"""


class InvestigationFixtureError(ValueError):
    """A fixture name or expectation label cannot be resolved.

    Resolution fails closed: unknown fixture names, unknown labels, and
    malformed world definitions are deterministic errors.
    """

    def __init__(self, message: str) -> None:
        """Record the fail-closed resolution message."""
        super().__init__(message)


@dataclass(frozen=True)
class InvestigationFixture:
    """One deterministic investigation world entry point."""

    name: str
    """Stable fixture reference used by scenario JSON."""

    root_label: str
    """Semantic label of the root indicator (for example ``root_domain``)."""

    root_type: EntityType
    """Canonical entity type of the root indicator."""

    root_value: str
    """Canonical entity value of the root indicator."""

    enabled_providers: tuple[SourceId, ...]
    """Exact provider set whose world truth the scenario authorizes."""

    world_entities: dict[str, tuple[EntityType, str]]
    """Semantic label -> canonical entity identity for post-run resolution."""

    catalog: FakeWorldCatalog
    """The deterministic world catalog this fixture reads its truth from."""


def _catalog_from_dicts(
    *, world: dict[str, Any], scenarios: dict[str, Any]
) -> FakeWorldCatalog:
    """Load and strictly validate one scenario-owned world catalog."""
    return FakeWorldCatalog.load(
        json.dumps(world).encode("utf-8"),
        json.dumps(scenarios).encode("utf-8"),
    )


def _dns_facts(
    query_name: str, query_type: str, answers: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build strict NOERROR DNS facts accepted by the production DNS extractor."""
    return {
        "query_name": query_name,
        "query_type": query_type,
        "status": 0,
        "flags": {"rd": True, "ra": True},
        "answers": answers,
    }


def _registration_facts(handle: str) -> dict[str, Any]:
    """Build RDAP registration facts accepted by the production extractor."""
    return {
        "object_class_name": "domain",
        "handle": handle,
        "registrar": "Synthetic Registrar",
    }


def _network_facts(handle: str, prefix: str) -> dict[str, Any]:
    """Build RDAP network facts accepted by the production extractor."""
    return {
        "object_class_name": "ip network",
        "handle": handle,
        "cidr0_cidrs": [{"prefix": prefix, "length": 24}],
    }


def _reputation_facts(score: int, reports: int) -> dict[str, Any]:
    """Build AbuseIPDB reputation facts accepted by the production extractor."""
    return {
        "abuse_confidence_score": score,
        "country_code": "US",
        "total_reports": reports,
    }


def _threatfox_facts(malware: str, ioc: str, ioc_type: str) -> dict[str, Any]:
    """Build ThreatFox match facts accepted by the production extractor."""
    return {
        "matches": [
            {
                "threatfox_id": "9000301",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "threat_type": "botnet_cc",
                "threat_type_description": "C&C server",
                "malware": malware,
                "malware_printable": malware,
                "confidence_level": 85,
                "first_seen": "2026-04-15T00:00:00Z",
                "last_seen": "2026-06-01T00:00:00Z",
                "reference": None,
                "tags": ["c2", "dropper"],
            }
        ]
    }


def _scenario_owned_catalog(
    *, scenario_id: str, root_value: str, world: dict[str, Any]
) -> FakeWorldCatalog:
    """Wrap one scenario-owned provider world with its root scenario entry."""
    return _catalog_from_dicts(
        world=world,
        scenarios={
            "schema_version": 1,
            "world_id": "fake_world_v1",
            "scenarios": [
                {
                    "scenario_id": scenario_id,
                    "description": "Repository-owned investigation evaluation world.",
                    "root_indicators": [{"type": "domain", "value": root_value}],
                }
            ],
        },
    )


_PACKAGED = FakeWorldCatalog.load_packaged()
"""The repository-owned packaged synthetic world (F01-F05)."""

_CONFLICT_WORLD: dict[str, Any] = {
    "schema_version": 1,
    "world_id": "fake_world_v1",
    "provider_results": [
        {
            "provider_id": SourceId.GOOGLE_PUBLIC_DNS.value,
            "entity_type": "domain",
            "entity_value": "conflict-hub.test",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:dns",
                    "observed_at": "2026-06-01T08:00:00Z",
                    "facts": _dns_facts(
                        "conflict-hub.test",
                        "A",
                        [
                            {
                                "name": "conflict-hub.test",
                                "record_type": "A",
                                "ttl": 300,
                                "value": "203.0.113.200",
                            }
                        ],
                    ),
                }
            ],
        },
        {
            "provider_id": SourceId.RDAP.value,
            "entity_type": "domain",
            "entity_value": "conflict-hub.test",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:registration",
                    "observed_at": "2026-06-01T08:00:00Z",
                    "facts": _registration_facts("D-CONFLICT-HUB"),
                }
            ],
        },
        {
            "provider_id": SourceId.RDAP.value,
            "entity_type": "ip_address",
            "entity_value": "203.0.113.200",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:network",
                    "observed_at": "2026-06-01T08:00:00Z",
                    "facts": _network_facts("NET-203-0-113-CONFLICT", "203.0.113.0"),
                }
            ],
        },
        {
            "provider_id": SourceId.ABUSEIPDB.value,
            "entity_type": "ip_address",
            "entity_value": "203.0.113.200",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:reputation",
                    "observed_at": "2026-06-02T08:00:00Z",
                    "facts": _reputation_facts(5, 0),
                }
            ],
        },
        {
            "provider_id": SourceId.THREATFOX.value,
            "entity_type": "ip_address",
            "entity_value": "203.0.113.200",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:threat_intelligence",
                    "observed_at": "2026-06-02T08:00:00Z",
                    "facts": _threatfox_facts(
                        "conflict-loader", "203.0.113.200", "ip_address"
                    ),
                }
            ],
        },
    ],
    "batch_artifacts": [],
}
"""Conflict world: ThreatFox malware association vs clean AbuseIPDB reputation."""

_CONFLICT_CATALOG = _scenario_owned_catalog(
    scenario_id="INV-S04-conflicting-evidence",
    root_value="conflict-hub.test",
    world=_CONFLICT_WORLD,
)

_RESEARCH_WORLD: dict[str, Any] = {
    "schema_version": 1,
    "world_id": "fake_world_v1",
    "provider_results": [
        {
            "provider_id": SourceId.GOOGLE_PUBLIC_DNS.value,
            "entity_type": "domain",
            "entity_value": "cdn-update.test",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:dns",
                    "observed_at": "2026-06-01T08:00:00Z",
                    "facts": _dns_facts(
                        "cdn-update.test",
                        "A",
                        [
                            {
                                "name": "cdn-update.test",
                                "record_type": "A",
                                "ttl": 300,
                                "value": "203.0.113.201",
                            }
                        ],
                    ),
                }
            ],
        },
        {
            "provider_id": SourceId.RDAP.value,
            "entity_type": "domain",
            "entity_value": "cdn-update.test",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:registration",
                    "observed_at": "2026-06-01T08:00:00Z",
                    "facts": _registration_facts("D-CDN-UPDATE"),
                }
            ],
        },
        {
            "provider_id": SourceId.RDAP.value,
            "entity_type": "ip_address",
            "entity_value": "203.0.113.201",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:network",
                    "observed_at": "2026-06-01T08:00:00Z",
                    "facts": _network_facts("NET-203-0-113-RESEARCH", "203.0.113.0"),
                }
            ],
        },
        {
            "provider_id": SourceId.ABUSEIPDB.value,
            "entity_type": "ip_address",
            "entity_value": "203.0.113.201",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:reputation",
                    "observed_at": "2026-06-02T08:00:00Z",
                    "facts": _reputation_facts(70, 5),
                }
            ],
        },
        {
            "provider_id": SourceId.THREATFOX.value,
            "entity_type": "ip_address",
            "entity_value": "203.0.113.201",
            "observations": [
                {
                    "evidence_type": "urn:ati:evidence:threat_intelligence",
                    "observed_at": "2026-06-02T08:00:00Z",
                    "facts": _threatfox_facts(
                        "stealth-loader", "203.0.113.201", "ip_address"
                    ),
                }
            ],
        },
    ],
    "batch_artifacts": [],
}
"""Research world: the resolved IP carries the researchable malware association."""

_RESEARCH_CATALOG = _scenario_owned_catalog(
    scenario_id="INV-S05-research-required",
    root_value="cdn-update.test",
    world=_RESEARCH_WORLD,
)

_INVESTIGATION_FIXTURES: dict[str, InvestigationFixture] = {
    "f02-malicious-multi-source": InvestigationFixture(
        name="f02-malicious-multi-source",
        root_label="root_domain",
        root_type=EntityType.DOMAIN,
        root_value="update-package.test",
        enabled_providers=(
            SourceId.GOOGLE_PUBLIC_DNS,
            SourceId.RDAP,
            SourceId.THREATFOX,
            SourceId.ABUSEIPDB,
        ),
        world_entities={
            "root_domain": (EntityType.DOMAIN, "update-package.test"),
            "resolved_ip": (EntityType.IP_ADDRESS, "203.0.113.81"),
            "malware_family": (EntityType.MALWARE, "malware.badloader_v2"),
        },
        catalog=_PACKAGED,
    ),
    "f01-benign": InvestigationFixture(
        name="f01-benign",
        root_label="root_domain",
        root_type=EntityType.DOMAIN,
        root_value="alice-corp.test",
        enabled_providers=(
            SourceId.GOOGLE_PUBLIC_DNS,
            SourceId.RDAP,
            SourceId.THREATFOX,
            SourceId.URLHAUS,
            SourceId.ABUSEIPDB,
        ),
        world_entities={
            "root_domain": (EntityType.DOMAIN, "alice-corp.test"),
            "resolved_ip": (EntityType.IP_ADDRESS, "203.0.113.10"),
            "mail_neighbor": (EntityType.DOMAIN, "mail-relay.test"),
            "malware_family": (EntityType.MALWARE, "malware.badloader_v2"),
        },
        catalog=_PACKAGED,
    ),
    "f05-insufficient-evidence": InvestigationFixture(
        name="f05-insufficient-evidence",
        root_label="root_domain",
        root_type=EntityType.DOMAIN,
        root_value="order-portal.test",
        enabled_providers=(
            SourceId.GOOGLE_PUBLIC_DNS,
            SourceId.RDAP,
            SourceId.THREATFOX,
            SourceId.ABUSEIPDB,
        ),
        world_entities={
            "root_domain": (EntityType.DOMAIN, "order-portal.test"),
            "resolved_ip": (EntityType.IP_ADDRESS, "198.51.100.25"),
        },
        catalog=_PACKAGED,
    ),
    "conflicting-evidence": InvestigationFixture(
        name="conflicting-evidence",
        root_label="root_domain",
        root_type=EntityType.DOMAIN,
        root_value="conflict-hub.test",
        enabled_providers=(
            SourceId.GOOGLE_PUBLIC_DNS,
            SourceId.RDAP,
            SourceId.THREATFOX,
            SourceId.ABUSEIPDB,
        ),
        world_entities={
            "root_domain": (EntityType.DOMAIN, "conflict-hub.test"),
            "resolved_ip": (EntityType.IP_ADDRESS, "203.0.113.200"),
            "malware_family": (EntityType.MALWARE, "conflict-loader"),
        },
        catalog=_CONFLICT_CATALOG,
    ),
    "research-required-malware": InvestigationFixture(
        name="research-required-malware",
        root_label="root_domain",
        root_type=EntityType.DOMAIN,
        root_value="cdn-update.test",
        enabled_providers=(
            SourceId.GOOGLE_PUBLIC_DNS,
            SourceId.RDAP,
            SourceId.THREATFOX,
            SourceId.ABUSEIPDB,
        ),
        world_entities={
            "root_domain": (EntityType.DOMAIN, "cdn-update.test"),
            "resolved_ip": (EntityType.IP_ADDRESS, "203.0.113.201"),
            "malware_family": (EntityType.MALWARE, "stealth-loader"),
        },
        catalog=_RESEARCH_CATALOG,
    ),
    "f02-shared-infrastructure-cycle": InvestigationFixture(
        name="f02-shared-infrastructure-cycle",
        root_label="root_domain",
        root_type=EntityType.DOMAIN,
        root_value="update-package.test",
        enabled_providers=(
            SourceId.GOOGLE_PUBLIC_DNS,
            SourceId.RDAP,
            SourceId.ABUSEIPDB,
        ),
        world_entities={
            "root_domain": (EntityType.DOMAIN, "update-package.test"),
            "resolved_ip": (EntityType.IP_ADDRESS, "203.0.113.81"),
            "neighbor_ip": (EntityType.IP_ADDRESS, "203.0.113.12"),
            "malware_family": (EntityType.MALWARE, "malware.badloader_v2"),
        },
        catalog=_PACKAGED,
    ),
}

SUPPORTED_FIXTURE_NAMES: frozenset[str] = frozenset(_INVESTIGATION_FIXTURES)
"""Stable set of supported investigation fixture names."""


def investigation_fixture(name: str) -> InvestigationFixture:
    """Return the exact fixture or fail closed on unknown names."""
    try:
        return _INVESTIGATION_FIXTURES[name]
    except KeyError as exc:
        raise InvestigationFixtureError(
            f"unknown investigation fixture: {name!r}"
        ) from exc


def build_investigation_provider_registry(
    fixture: InvestigationFixture,
) -> dict[SourceId, EvidenceProvider]:
    """Compose the deterministic provider registry for one fixture.

    World truth comes exclusively from the fixture's enabled providers over
    its bound catalog; no provider policy is invented and the production
    Coordinator decides all work planning.
    """
    return {
        provider: FakeWorldEvidenceProvider(
            provider, fixture.catalog, clock=lambda: _FIXED_CLOCK
        )
        for provider in fixture.enabled_providers
    }
