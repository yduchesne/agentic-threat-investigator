# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic fake runtime unit tests (PR 23D).

Covers the strict fixture schema validation, the shared-world catalog
lookups, the fake live providers, and the operating-mode composition
branches. Stable IDs follow the PR 23D plan matrix (23D-U07 through
23D-U34).
"""

from __future__ import annotations

import sys
from collections.abc import Awaitable
from datetime import UTC, datetime
from typing import TypeVar
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.providers import (
    ProviderErrorCode,
)
from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config import OperatingMode, Settings
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FAKE_WORLD_ID,
    FAKE_WORLD_SCHEMA_VERSION,
    FakeBatchArtifactData,
    FakeObservation,
    FakeProviderErrorData,
    FakeProviderResultData,
    FakeRootIndicatorData,
    FakeScenarioCollection,
    FakeScenarioData,
    FakeWorldCatalog,
    FakeWorldData,
    FakeWorldValidationError,
)
from agentic_threat_investigator.infrastructure.fake_runtime.providers import (
    FakeWorldEvidenceProvider,
)
from agentic_threat_investigator.infrastructure.intelligence_composition import (
    build_fake_intelligence_sources,
    build_production_intelligence_sources,
)

T = TypeVar("T")

_FIXED_TS = datetime(2026, 6, 1, tzinfo=UTC)

DNS_OBSERVATION = FakeObservation(
    evidence_type=EvidenceType.DNS,
    observed_at=_FIXED_TS,
    facts={
        "query_name": "alice-corp.test",
        "query_type": "A",
        "status": 0,
        "flags": {"rd": True, "ra": True},
        "answers": [
            {
                "name": "alice-corp.test",
                "record_type": "A",
                "ttl": 300,
                "value": "203.0.113.10",
            }
        ],
    },
)


def _world(
    *,
    results: tuple[FakeProviderResultData, ...] = (),
    artifacts: tuple[FakeBatchArtifactData, ...] = (),
) -> FakeWorldData:
    """Build one minimal valid synthetic world definition."""
    return FakeWorldData(
        schema_version=FAKE_WORLD_SCHEMA_VERSION,
        world_id=FAKE_WORLD_ID,
        provider_results=results,
        batch_artifacts=artifacts,
    )


def _scenarios(
    *,
    scenarios: tuple[FakeScenarioData, ...] = (),
) -> FakeScenarioCollection:
    """Build one minimal valid scenario collection definition."""
    return FakeScenarioCollection(
        schema_version=FAKE_WORLD_SCHEMA_VERSION,
        world_id=FAKE_WORLD_ID,
        scenarios=scenarios,
    )


def _dns_result(entity_value: str = "alice-corp.test") -> FakeProviderResultData:
    """Return one DNS provider lookup for the shared benign domain."""
    return FakeProviderResultData(
        provider_id=SourceId.GOOGLE_PUBLIC_DNS.value,
        entity_type=EntityType.DOMAIN,
        entity_value=entity_value,
        observations=(DNS_OBSERVATION,),
    )


def _packaged_catalog() -> FakeWorldCatalog:
    """Load the repository-owned packaged world for integration-style checks."""
    return FakeWorldCatalog.load_packaged()


def _packaged_provider() -> FakeWorldEvidenceProvider:
    """Return the Google DNS fake over the packaged world."""
    return FakeWorldEvidenceProvider(
        SourceId.GOOGLE_PUBLIC_DNS, _packaged_catalog(), clock=lambda: _FIXED_TS
    )


# -- Fixture schema validation (23D-U07..U10, U27, U28) --------------------


def test_u07_duplicate_scenario_id_fails_closed() -> None:
    """Duplicate scenario IDs are rejected at load time."""
    scenario = FakeScenarioData(
        scenario_id="S1",
        description="one",
        root_indicators=(
            FakeRootIndicatorData(type=EntityType.DOMAIN, value="a.test"),
        ),
    )
    with pytest.raises(ValidationError, match="duplicate scenario"):
        _scenarios(scenarios=(scenario, scenario))


def test_u08_duplicate_root_indicator_fails_closed() -> None:
    """Duplicate root indicator keys across scenarios are rejected."""
    first = FakeScenarioData(
        scenario_id="S1",
        description="one",
        root_indicators=(
            FakeRootIndicatorData(type=EntityType.DOMAIN, value="a.test"),
        ),
    )
    second = FakeScenarioData(
        scenario_id="S2",
        description="two",
        root_indicators=(
            FakeRootIndicatorData(type=EntityType.DOMAIN, value="a.test"),
        ),
    )
    with pytest.raises(ValidationError, match="duplicate root"):
        _scenarios(scenarios=(first, second))


def test_u09_unknown_provider_id_fails_closed() -> None:
    """Unknown provider IDs are rejected in the world definition."""
    with pytest.raises(ValidationError, match="unsupported provider"):
        FakeProviderResultData(
            provider_id="urn:ati:source:unknown",
            entity_type=EntityType.DOMAIN,
            entity_value="a.test",
            no_result=True,
        )


def test_u10_malformed_timestamp_fails_closed() -> None:
    """Non-timezone-aware observation timestamps are rejected."""
    with pytest.raises(ValidationError, match="timezone-aware"):
        FakeObservation(
            evidence_type=EvidenceType.DNS,
            observed_at=datetime(2026, 1, 1),  # naive
            facts={"query_name": "a.test"},
        )


def test_u10b_unsupported_schema_version_fails_closed() -> None:
    """23D-U28: an unsupported fixture schema version is rejected."""
    with pytest.raises(ValidationError, match="schema version"):
        FakeWorldData(
            schema_version=99,
            world_id=FAKE_WORLD_ID,
            provider_results=(),
        )


def test_u27_fixture_path_escape_is_rejected() -> None:
    """Absolute and traversing batch artifact paths fail closed."""
    for bad_path in ("../escape.json", "/absolute/path.json", "v1\\..\\escape.json"):
        with pytest.raises(ValidationError, match="path"):
            FakeBatchArtifactData(
                source_id=SourceId.MITRE_ATTACK.value,
                package_path=bad_path,
                dataset_path="mitre-attack/fake.json",
            )


def test_u10c_malformed_entity_identity_fails_closed() -> None:
    """Non-canonical entity values are rejected in world lookups."""
    with pytest.raises(ValidationError, match="canonical"):
        FakeProviderResultData(
            provider_id=SourceId.GOOGLE_PUBLIC_DNS.value,
            entity_type=EntityType.DOMAIN,
            entity_value="Example.COM",  # not canonical
            no_result=True,
        )


def test_u10d_ambiguous_lookup_shape_fails_closed() -> None:
    """A lookup that is simultaneously observations and error is rejected."""
    with pytest.raises(ValidationError, match="observations, no_result, or error"):
        FakeProviderResultData(
            provider_id=SourceId.GOOGLE_PUBLIC_DNS.value,
            entity_type=EntityType.DOMAIN,
            entity_value="a.test",
            observations=(DNS_OBSERVATION,),
            error=FakeProviderErrorData(code=ProviderErrorCode.NOT_FOUND, message="x"),
        )


def test_scenario_root_without_world_data_fails_closed() -> None:
    """A scenario root that resolves to no world data is rejected."""
    world = _world(results=(_dns_result(),))
    scenarios = _scenarios(
        scenarios=(
            FakeScenarioData(
                scenario_id="S1",
                description="one",
                root_indicators=(
                    FakeRootIndicatorData(type=EntityType.DOMAIN, value="ghost.test"),
                ),
            ),
        )
    )
    with pytest.raises(FakeWorldValidationError, match="does not resolve"):
        FakeWorldCatalog(world, scenarios)


def test_researchable_root_without_provider_data_is_valid() -> None:
    """A RESEARCHABLE root (research lifecycle) needs no provider lookup."""
    world = _world()
    scenarios = _scenarios(
        scenarios=(
            FakeScenarioData(
                scenario_id="S1",
                description="research root",
                root_indicators=(
                    FakeRootIndicatorData(
                        type=EntityType.ATTACK_TECHNIQUE, value="T1566.001"
                    ),
                ),
            ),
        )
    )
    catalog = FakeWorldCatalog(world, scenarios)
    assert (
        catalog.scenario_for_root_indicator(EntityType.ATTACK_TECHNIQUE, "T1566.001")
        == "S1"
    )


# -- Catalog lookup determinism (23D-U11, U29, U31, U33, U34) -------------


def test_u11_unknown_indicator_is_deterministic_no_result() -> None:
    """Unknown indicators return a bounded no-result, never random data."""
    catalog = _packaged_catalog()
    for _ in range(3):
        response = catalog.provider_response(
            SourceId.THREATFOX.value,
            EntityType.DOMAIN,
            "unknown-entity.test",
            _FIXED_TS,
        )
        assert response.observations == ()
        assert response.error is None


def test_u33_pivot_lookup_continues_deterministically() -> None:
    """A related world entity resolved through a pivot keeps world data."""
    catalog = _packaged_catalog()
    root = catalog.provider_response(
        SourceId.GOOGLE_PUBLIC_DNS.value,
        EntityType.DOMAIN,
        "update-package.test",
        _FIXED_TS,
    )
    # The DNS A/CNAME chain yields the second-hop domain via extraction; the
    # catalog resolves that related entity deterministically.
    related = catalog.provider_response(
        SourceId.GOOGLE_PUBLIC_DNS.value,
        EntityType.DOMAIN,
        "assets-edge.test",
        _FIXED_TS,
    )
    assert root.observations
    assert related.observations
    assert related.observations[0].facts["answers"][0]["value"] == "203.0.113.81"


def test_u34_unknown_pivot_is_bounded_dead_end() -> None:
    """An unknown pivot entity yields a bounded deterministic no-result."""
    catalog = _packaged_catalog()
    response = catalog.provider_response(
        SourceId.URLHAUS.value,
        EntityType.DOMAIN,
        "dead-end.test",
        _FIXED_TS,
    )
    assert response.observations == ()
    assert response.error is None


def test_u29_shared_world_entity_resolves_consistently() -> None:
    """Shared infrastructure resolves identically across scenario lookups."""
    catalog = _packaged_catalog()
    for provider, entity_type, value in [
        (SourceId.IPINFO_LITE.value, EntityType.IP_ADDRESS, "203.0.113.10"),
        (SourceId.IPINFO_LITE.value, EntityType.IP_ADDRESS, "203.0.113.80"),
    ]:
        first = catalog.provider_response(provider, entity_type, value, _FIXED_TS)
        second = catalog.provider_response(provider, entity_type, value, _FIXED_TS)
        assert [o.facts for o in first.observations] == [
            o.facts for o in second.observations
        ]


def test_u31_ambient_noise_is_deterministic() -> None:
    """Repeated ambient lookups return the same semantic data."""
    catalog = _packaged_catalog()
    responses = [
        catalog.provider_response(
            SourceId.GOOGLE_PUBLIC_DNS.value,
            EntityType.DOMAIN,
            "alice-corp.test",
            _FIXED_TS,
        )
        for _ in range(3)
    ]
    for response in responses[1:]:
        assert [o.facts for o in response.observations] == [
            o.facts for o in responses[0].observations
        ]


def test_u30_shared_prefix_spans_benign_and_suspicious_without_labeling() -> None:
    """Shared infrastructure data carries no automatic malicious label."""
    catalog = _packaged_catalog()
    benign = catalog.provider_response(
        SourceId.RDAP.value, EntityType.IP_ADDRESS, "203.0.113.10", _FIXED_TS
    )
    suspicious = catalog.provider_response(
        SourceId.RDAP.value, EntityType.IP_ADDRESS, "203.0.113.81", _FIXED_TS
    )
    assert benign.observations
    assert suspicious.observations
    assert benign.observations[0].facts["cidr0_cidrs"][0] == {
        "prefix": "203.0.113.0",
        "length": 24,
    }
    assert (
        suspicious.observations[0].facts["cidr0_cidrs"][0]
        == benign.observations[0].facts["cidr0_cidrs"][0]
    )
    for observation in (*benign.observations, *suspicious.observations):
        joined = str(observation.facts).lower()
        assert "malicious" not in joined
        assert "signal" not in joined


def test_u32_fixture_relevance_labels_are_not_evidence() -> None:
    """Fixture-internal classifications never surface as Evidence facts."""
    provider = _packaged_provider()
    entity = Entity(id=uuid4(), type=EntityType.DOMAIN, value="alice-corp.test")
    result = asyncio_run(provider.investigate(uuid4(), entity))
    for evidence in result.evidence:
        joined = str(evidence.facts).lower()
        assert "signal" not in joined
        assert "ambient" not in joined
        assert "inconclusive" not in joined


# -- Fake provider contract behavior (23D-U12..U17, U26) -------------------


def test_u12_fake_provider_supports_planned_entity() -> None:
    """The fake Google DNS provider supports domain/IP like the real one."""
    provider = _packaged_provider()
    assert provider.supports(Entity(id=uuid4(), type=EntityType.DOMAIN, value="a.test"))
    assert provider.supports(
        Entity(id=uuid4(), type=EntityType.IP_ADDRESS, value="203.0.113.10")
    )
    assert not provider.supports(
        Entity(id=uuid4(), type=EntityType.ASN, value="AS64500")
    )


def test_u13_fake_provider_rejects_unsupported_entity() -> None:
    """An unsupported entity yields the standard typed rejection, no result."""
    provider = _packaged_provider()
    entity = Entity(id=uuid4(), type=EntityType.ASN, value="AS64500")
    result = asyncio_run(provider.investigate(uuid4(), entity))
    assert result.evidence == ()
    assert len(result.errors) == 1
    assert result.errors[0].code is ProviderErrorCode.UNSUPPORTED_INDICATOR


def test_u14_same_lookup_is_semantically_equivalent() -> None:
    """Repeated provider lookups differ only in stamped retrieval fields."""
    catalog = _packaged_catalog()
    first_clock = datetime(2026, 6, 1, tzinfo=UTC)
    second_clock = datetime(2026, 6, 2, tzinfo=UTC)
    first = FakeWorldEvidenceProvider(
        SourceId.THREATFOX, catalog, clock=lambda: first_clock
    )
    second = FakeWorldEvidenceProvider(
        SourceId.THREATFOX, catalog, clock=lambda: second_clock
    )
    entity = Entity(id=uuid4(), type=EntityType.DOMAIN, value="update-package.test")
    first_result = asyncio_run(first.investigate(uuid4(), entity))
    second_result = asyncio_run(second.investigate(uuid4(), entity))
    assert len(first_result.evidence) == len(second_result.evidence)
    assert first_result.evidence[0].facts == second_result.evidence[0].facts
    assert first_result.evidence[0].observed_at == second_result.evidence[0].observed_at
    # Only the injected retrieval clock differs.
    assert first_result.evidence[0].retrieved_at == first_clock
    assert second_result.evidence[0].retrieved_at == second_clock


def test_u15_fake_provider_no_result_uses_empty_semantics() -> None:
    """An explicit no-result lookup returns an empty successful ProviderResult."""
    provider = _packaged_provider()
    entity = Entity(id=uuid4(), type=EntityType.IP_ADDRESS, value="203.0.113.12")
    result = asyncio_run(provider.investigate(uuid4(), entity))
    assert result.evidence == ()
    assert result.errors == ()


def test_u16_fake_provider_error_uses_bounded_failure_semantics() -> None:
    """A configured provider error returns the typed bounded error result."""
    catalog = _packaged_catalog()
    provider = FakeWorldEvidenceProvider(
        SourceId.THREATFOX, catalog, clock=lambda: _FIXED_TS
    )
    entity = Entity(id=uuid4(), type=EntityType.IP_ADDRESS, value="198.51.100.99")
    result = asyncio_run(provider.investigate(uuid4(), entity))
    assert result.evidence == ()
    assert len(result.errors) == 1
    assert result.errors[0].code is ProviderErrorCode.PROVIDER_UNAVAILABLE
    assert result.errors[0].retryable is True


def test_u17_fake_provider_has_no_network_transport() -> None:
    """Importing and running fake providers never loads the HTTP transport."""
    before = set(sys.modules)
    catalog = _packaged_catalog()
    provider = FakeWorldEvidenceProvider(
        SourceId.GOOGLE_PUBLIC_DNS, catalog, clock=lambda: _FIXED_TS
    )
    entity = Entity(
        id=uuid4(),
        type=EntityType.DOMAIN,
        value="update-package.test",
    )
    result = asyncio_run(provider.investigate(uuid4(), entity))
    after = set(sys.modules)
    loaded = after - before
    assert not any(
        module.startswith("agentic_threat_investigator.infrastructure.providers.http")
        for module in loaded
    )
    assert not any(module.startswith("httpx") for module in loaded)
    assert result.evidence


def test_u26_observed_and_retrieved_timestamps_are_distinct() -> None:
    """Source-semantic observed_at stays separate from the retrieval clock."""
    catalog = _packaged_catalog()
    provider = FakeWorldEvidenceProvider(
        SourceId.GOOGLE_PUBLIC_DNS, catalog, clock=lambda: _FIXED_TS
    )
    entity = Entity(id=uuid4(), type=EntityType.DOMAIN, value="logistics-corp.test")
    result = asyncio_run(provider.investigate(uuid4(), entity))
    assert result.evidence
    for evidence in result.evidence:
        assert evidence.observed_at is not None
        assert evidence.observed_at != evidence.retrieved_at


def test_retrieval_clock_withholds_future_observations() -> None:
    """Observations later than the retrieval clock are deterministically withheld."""
    catalog = _packaged_catalog()
    early = FakeWorldEvidenceProvider(
        SourceId.GOOGLE_PUBLIC_DNS,
        catalog,
        clock=lambda: datetime(2026, 7, 1, tzinfo=UTC),
    )
    late = FakeWorldEvidenceProvider(
        SourceId.GOOGLE_PUBLIC_DNS,
        catalog,
        clock=lambda: datetime(2026, 10, 1, tzinfo=UTC),
    )
    entity = Entity(id=uuid4(), type=EntityType.DOMAIN, value="logistics-corp.test")
    early_result = asyncio_run(early.investigate(uuid4(), entity))
    late_result = asyncio_run(late.investigate(uuid4(), entity))
    assert len(early_result.evidence) < len(late_result.evidence)
    early_targets = {
        ev.facts["answers"][0]["value"]
        for ev in early_result.evidence
        if ev.facts.get("query_type") == "A"
    }
    late_targets = {
        ev.facts["answers"][0]["value"]
        for ev in late_result.evidence
        if ev.facts.get("query_type") == "A"
    }
    assert early_targets == {"203.0.113.60"}
    assert late_targets == {"203.0.113.60", "198.51.100.77"}


def test_fake_evidence_marks_synthetic_provenance() -> None:
    """Fake evidence carries the non-semantic synthetic-world marker."""
    provider = _packaged_provider()
    entity = Entity(id=uuid4(), type=EntityType.DOMAIN, value="update-package.test")
    result = asyncio_run(provider.investigate(uuid4(), entity))
    assert result.evidence
    for evidence in result.evidence:
        assert evidence.raw_payload is not None
        assert evidence.raw_payload.get("synthetic_world") == FAKE_WORLD_ID


# -- Composition branches (23D-U18..U21) ----------------------------------


def test_u18_fake_mode_composition_only_fake_live_providers() -> None:
    """Fake mode composes only fake live providers for the v0.1 source set."""
    sources = build_fake_intelligence_sources(
        Settings(operating_mode=OperatingMode.FAKE),
        catalog=_packaged_catalog(),
        clock=lambda: _FIXED_TS,
    )
    registry = sources.provider_registry
    assert set(registry) == {
        SourceId.GOOGLE_PUBLIC_DNS,
        SourceId.RDAP,
        SourceId.IPINFO_LITE,
        SourceId.ABUSEIPDB,
        SourceId.THREATFOX,
        SourceId.URLHAUS,
    }
    for provider in registry.values():
        assert isinstance(provider, FakeWorldEvidenceProvider)
    assert sources.batch_bindings


class _SimpleSecretsResolver(SecretsResolver):
    """Deterministic resolver returning placeholder values for every name."""

    def get(self, name: str) -> str | None:
        del name
        return "synthetic-placeholder"

    def require(self, name: str) -> str:
        return "synthetic-placeholder"


def test_u19_production_mode_composition_only_real_providers() -> None:
    """Production mode composes the real provider registry, never fakes."""
    settings = Settings(operating_mode=OperatingMode.PRODUCTION)
    sources = asyncio_run(
        build_production_intelligence_sources(
            settings, secrets=_SimpleSecretsResolver()
        )
    )
    try:
        registry = sources.provider_registry
        assert SourceId.GOOGLE_PUBLIC_DNS in registry
        assert SourceId.THREATFOX in registry
        for provider in registry.values():
            assert not isinstance(provider, FakeWorldEvidenceProvider)
        assert sources.batch_bindings == ()
    finally:
        asyncio_run(sources.aclose())


def test_u20_fake_mode_resolves_no_production_secrets() -> None:
    """Fake composition requires no production provider secrets."""
    resolver_calls: list[str] = []

    class TrackingResolver(_SimpleSecretsResolver):
        def require(self, name: str) -> str:
            resolver_calls.append(name)
            return "synthetic-placeholder"

    sources = build_fake_intelligence_sources(
        Settings(operating_mode=OperatingMode.FAKE),
        catalog=_packaged_catalog(),
        clock=lambda: _FIXED_TS,
    )
    assert set(sources.provider_registry) == {
        SourceId.GOOGLE_PUBLIC_DNS,
        SourceId.RDAP,
        SourceId.IPINFO_LITE,
        SourceId.ABUSEIPDB,
        SourceId.THREATFOX,
        SourceId.URLHAUS,
    }
    assert resolver_calls == []


def test_u21_fake_mode_keeps_real_llm_composition() -> None:
    """Operating mode never replaces the configured LLM implementation."""
    fake_settings = Settings(operating_mode=OperatingMode.FAKE)
    production_settings = Settings(operating_mode=OperatingMode.PRODUCTION)
    assert fake_settings.llm_model == production_settings.llm_model
    assert fake_settings.llm_api_key_secret == production_settings.llm_api_key_secret
    # The fake composition never constructs or imports the LLM adapter.
    before = set(sys.modules)
    build_fake_intelligence_sources(
        fake_settings, catalog=_packaged_catalog(), clock=lambda: _FIXED_TS
    )
    loaded = set(sys.modules) - before
    assert not any(
        module.startswith("agentic_threat_investigator.infrastructure.llm")
        for module in loaded
    )


def test_i12_fake_composition_fails_closed_on_missing_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing fake fixture fails composition before any work."""
    import agentic_threat_investigator.infrastructure.fake_runtime.catalog as catalog_module

    def _raise() -> FakeWorldCatalog:
        raise FakeWorldValidationError("fake batch artifact is missing")

    monkeypatch.setattr(catalog_module.FakeWorldCatalog, "load_packaged", _raise)
    with pytest.raises(FakeWorldValidationError, match="missing"):
        build_fake_intelligence_sources(Settings(operating_mode=OperatingMode.FAKE))


def test_i13_production_missing_secret_fails_without_fake_fallback() -> None:
    """Missing production credentials fail production composition, never fake."""

    class _EmptyResolver(SecretsResolver):
        def get(self, name: str) -> str | None:
            del name
            return None

    with pytest.raises(Exception) as excinfo:
        asyncio_run(
            build_production_intelligence_sources(
                Settings(operating_mode=OperatingMode.PRODUCTION),
                secrets=_EmptyResolver(),
            )
        )
    # The production failure is typed and never a fake fallback.
    from agentic_threat_investigator.app.secrets import SecretNotFoundError

    assert isinstance(excinfo.value, SecretNotFoundError)


def test_packaged_world_scenarios_are_stable_entry_points() -> None:
    """Every packaged scenario resolves to its named entry point."""
    catalog = _packaged_catalog()
    assert (
        catalog.scenario_for_root_indicator(EntityType.DOMAIN, "alice-corp.test")
        == "F01-benign"
    )
    assert (
        catalog.scenario_for_root_indicator(EntityType.DOMAIN, "update-package.test")
        == "F02-malicious-multi-source"
    )
    assert (
        catalog.scenario_for_root_indicator(EntityType.DOMAIN, "logistics-corp.test")
        == "F03-relationship-evolution"
    )
    assert (
        catalog.scenario_for_root_indicator(EntityType.ATTACK_TECHNIQUE, "T1566.001")
        == "F04-research-required"
    )
    assert (
        catalog.scenario_for_root_indicator(EntityType.DOMAIN, "order-portal.test")
        == "F05-insufficient-evidence"
    )


async def _run(coro: Awaitable[T]) -> T:
    """Await one fake coroutine deterministically."""
    return await coro


def asyncio_run(coro: Awaitable[T]) -> T:
    """Run one fake coroutine deterministically."""
    import asyncio

    return asyncio.run(_run(coro))
