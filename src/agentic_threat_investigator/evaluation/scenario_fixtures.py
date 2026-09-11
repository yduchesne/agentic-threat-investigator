# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator fixture registry and semantic-label resolution (PR 21).

Each repository-owned scenario references a fixture by stable name. The
resolver validates the fixture exists and every required/forbidden semantic
label in the expectation envelope resolves against that fixture's declared
entity and provider-work label universes, then binds a deterministic,
scenario-stable UUID to every entity label and an exact
``(provider, entity_uuid, depth)`` identity to every provider-work label.

The resolver is pure: no database, network, LLM, or clock access. It fails
closed on unknown fixture names, unknown labels, and any required/forbidden
overlap.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid5

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.evaluation.coordinator import (
    CoordinatorScenario,
    CoordinatorScenarioResolution,
)


class CoordinatorFixtureError(ValueError):
    """A fixture name or expectation label cannot be resolved.

    Resolution fails closed: unknown fixture names, unresolved semantic
    labels, and required/forbidden overlap are deterministic errors.
    """

    def __init__(self, message: str) -> None:
        """Record the fail-closed resolution message."""
        super().__init__(message)


# Declared fixture universe: fixture name -> (entity labels, provider-work labels).
# Provider-work labels map to (provider, entity label, depth). This registry is
# the single source of truth for the thirteen supported fixtures.
_COORDINATOR_FIXTURES: dict[
    str, tuple[frozenset[str], dict[str, tuple[str, str, int]]]
] = {
    "canonical-domain-ip": (
        frozenset({"root_domain", "resolved_ip"}),
        {
            "dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0),
            "threatfox_resolved_ip": ("urn:ati:source:threatfox", "resolved_ip", 1),
        },
    ),
    "duplicate-ip": (
        frozenset({"root_domain", "resolved_ip"}),
        {"abuseipdb_resolved_ip": ("urn:ati:source:abuseipdb", "resolved_ip", 1)},
    ),
    "already-investigated-ip": (
        frozenset({"root_domain", "resolved_ip"}),
        {"dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0)},
    ),
    "non-pivotable-discovery": (
        frozenset({"root_domain", "no_provider_entity"}),
        {"dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0)},
    ),
    "depth-limit": (
        frozenset({"root_domain", "deep_ip"}),
        {"dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0)},
    ),
    "provider-budget": (
        frozenset({"root_domain"}),
        {"dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0)},
    ),
    "entity-budget": (
        frozenset({"root_domain", "resolved_ip"}),
        {"dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0)},
    ),
    "sufficient-evidence": (
        frozenset({"root_domain"}),
        {"dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0)},
    ),
    "no-eligible-pivots": (
        frozenset({"root_domain"}),
        {"dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0)},
    ),
    "one-replan": (
        frozenset({"root_domain", "resolved_ip"}),
        {
            "dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0),
            "abuseipdb_resolved_ip": ("urn:ati:source:abuseipdb", "resolved_ip", 1),
        },
    ),
    "replan-limit": (
        frozenset({"root_domain"}),
        {"dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0)},
    ),
    "cycle-suppression": (
        frozenset({"root_domain", "resolved_ip"}),
        {"abuseipdb_resolved_ip": ("urn:ati:source:abuseipdb", "resolved_ip", 1)},
    ),
    "malware-research": (
        frozenset({"root_domain", "resolved_ip", "malware_asyncrat"}),
        {
            "dns_root_domain": ("urn:ati:source:google_public_dns", "root_domain", 0),
            "threatfox_resolved_ip": ("urn:ati:source:threatfox", "resolved_ip", 1),
        },
    ),
}

SUPPORTED_FIXTURE_NAMES: frozenset[str] = frozenset(_COORDINATOR_FIXTURES)


@dataclass(frozen=True)
class CoordinatorProviderScript:
    """One fixture-owned deterministic provider-work script."""

    label: str
    provider: SourceId
    target_label: str
    depth: int


@dataclass(frozen=True)
class CoordinatorMaterializedFixture:
    """Persisted initial fixture plus provider/analyst scripts and resolution."""

    initial_state: InvestigationState
    resolution: CoordinatorScenarioResolution
    provider_scripts: tuple[CoordinatorProviderScript, ...]
    analyst_dispositions: tuple[AnalysisDisposition, ...]
    entity_identities: dict[str, tuple[EntityType, str]]


class CoordinatorScenarioMaterializer:
    """Own fixture persistence, scripts, and post-execution resolution."""

    @staticmethod
    def _entity_identity(
        scenario: CoordinatorScenario, label: str
    ) -> tuple[EntityType, str]:
        """Return the fixture-owned canonical Entity identity for a label."""
        if label == "root_domain":
            value = (
                "malicious-domain.test"
                if scenario.fixture.name == "canonical-domain-ip"
                else f"{scenario.fixture.name}.test"
            )
            return EntityType.DOMAIN, value
        if "malware" in label:
            return EntityType.MALWARE, "asyncrat"
        if "no_provider" in label:
            return EntityType.ORGANIZATION, f"{scenario.fixture.name}-organization"
        suffix = 99 if "deep" in label else 42
        return EntityType.IP_ADDRESS, f"203.0.113.{suffix}"

    async def materialize(
        self,
        scenario: CoordinatorScenario,
        uow_factory: Callable[[], UnitOfWork],
    ) -> CoordinatorMaterializedFixture:
        """Persist the initial fixture and return all deterministic scripts."""
        declared = resolve_coordinator_scenario(scenario)
        identities = {
            label: self._entity_identity(scenario, label) for label in declared.entities
        }
        runtime_entities: dict[str, UUID] = {}
        async with uow_factory() as uow:
            for label, declared_id in declared.entities.items():
                entity_type, value = identities[label]
                persisted = await uow.entities.upsert(
                    Entity(id=declared_id, type=entity_type, value=value)
                )
                if persisted.id is None:
                    raise CoordinatorFixtureError(
                        f"fixture entity has no persisted identity: {label}"
                    )
                runtime_entities[label] = persisted.id
            root_id = runtime_entities.get("root_domain")
            if root_id is None:
                raise CoordinatorFixtureError("fixture requires root_domain")
            budget = default_investigation_budget().model_copy(
                update={
                    key: value
                    for key, value in {
                        "max_provider_calls": scenario.expected.max_provider_calls,
                        "max_entities": scenario.expected.max_entities,
                        "max_depth": scenario.expected.max_depth,
                        "max_replans": scenario.expected.max_replans,
                    }.items()
                    if value is not None
                }
            )
            initial = InvestigationState(
                investigation_id=uuid5(root_id, scenario.id),
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[root_id],
                objective=f"Execute coordinator scenario {scenario.id}.",
                budget=budget,
                started_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
            created = await uow.investigations.create(initial)
        initial = initial.model_copy(update={"version": created.version})
        resolution = self.resolve_runtime(scenario, runtime_entities)
        scripts = tuple(
            CoordinatorProviderScript(
                label=label,
                provider=SourceId(provider),
                target_label=next(
                    entity_label
                    for entity_label, entity_id in resolution.entities.items()
                    if entity_id == target_id
                ),
                depth=depth,
            )
            for label, (provider, target_id, depth) in resolution.provider_work.items()
        )
        analyst_dispositions = (
            (AnalysisDisposition.NEEDS_MORE_EVIDENCE, AnalysisDisposition.SUFFICIENT)
            if scenario.id in {"domain-discovers-ip", "one-justified-replan"}
            else (
                (AnalysisDisposition.SUFFICIENT,)
                if scenario.expected.expected_stop_reason.value == "sufficient_evidence"
                else ()
            )
        )
        return CoordinatorMaterializedFixture(
            initial_state=initial,
            resolution=resolution,
            provider_scripts=scripts,
            analyst_dispositions=analyst_dispositions,
            entity_identities=identities,
        )

    async def resolve_persisted(
        self,
        scenario: CoordinatorScenario,
        uow_factory: Callable[[], UnitOfWork],
    ) -> CoordinatorScenarioResolution:
        """Resolve every semantic label from canonical persisted identities."""
        declared = resolve_coordinator_scenario(scenario)
        runtime: dict[str, UUID] = {}
        async with uow_factory() as uow:
            for label in declared.entities:
                entity_type, value = self._entity_identity(scenario, label)
                entity = await uow.entities.get_by_identity(entity_type.value, value)
                if entity is None or entity.id is None:
                    raise CoordinatorFixtureError(
                        f"persisted fixture label is unresolved: {label}"
                    )
                runtime[label] = entity.id
        return self.resolve_runtime(scenario, runtime)

    def resolve_runtime(
        self,
        scenario: CoordinatorScenario,
        runtime_entities: dict[str, UUID],
    ) -> CoordinatorScenarioResolution:
        """Build exact runtime resolution or fail on missing/extra labels."""
        entities, provider_work = _COORDINATOR_FIXTURES.get(
            scenario.fixture.name, (None, None)
        )
        if entities is None or provider_work is None:
            raise CoordinatorFixtureError(
                f"unknown coordinator fixture: {scenario.fixture.name!r}"
            )
        supplied = set(runtime_entities)
        if supplied != set(entities):
            missing = sorted(set(entities) - supplied)
            extra = sorted(supplied - set(entities))
            raise CoordinatorFixtureError(
                f"runtime fixture labels mismatch; missing={missing}, extra={extra}"
            )
        if len(set(runtime_entities.values())) != len(runtime_entities):
            raise CoordinatorFixtureError("runtime entity labels must resolve uniquely")
        work_resolution = {
            label: (provider, runtime_entities[entity_label], depth)
            for label, (provider, entity_label, depth) in provider_work.items()
        }
        resolution = CoordinatorScenarioResolution(
            entities=dict(runtime_entities), provider_work=work_resolution
        )
        # Reuse fail-closed expectation validation before returning runtime IDs.
        resolve_coordinator_scenario(scenario)
        return resolution


def resolve_coordinator_scenario(
    scenario: CoordinatorScenario,
) -> CoordinatorScenarioResolution:
    """Resolve one scenario's semantic labels against its declared fixture.

    Fails closed on unknown fixture names, unresolved required/forbidden
    labels, and required/forbidden overlap among pivots.
    """
    entities, provider_work = _COORDINATOR_FIXTURES.get(
        scenario.fixture.name, (None, None)
    )
    if entities is None or provider_work is None:
        raise CoordinatorFixtureError(
            f"unknown coordinator fixture: {scenario.fixture.name!r}"
        )

    required = set(scenario.expected.required_pivots)
    forbidden = set(scenario.expected.forbidden_pivots)
    overlap = required & forbidden
    if overlap:
        raise CoordinatorFixtureError(
            f"labels cannot be both required and forbidden: {sorted(overlap)}"
        )

    required_work = set(scenario.expected.required_provider_work)
    forbidden_work = set(scenario.expected.forbidden_provider_work)
    work_overlap = required_work & forbidden_work
    if work_overlap:
        raise CoordinatorFixtureError(
            "provider-work labels cannot be both required and forbidden: "
            f"{sorted(work_overlap)}"
        )

    # Entity labels referenced by required/forbidden pivots, the scenario's
    # allowed-pivot oracle, and provider work.
    referenced_entities: set[str] = set(required | forbidden)
    referenced_entities.update(scenario.expected.required_research_markers)
    referenced_entities.update(
        pivot.entity for pivot in scenario.expected.allowed_pivots
    )
    referenced_work: set[str] = set(required_work | forbidden_work)
    for work_label in referenced_work:
        work = provider_work.get(work_label)
        if work is None:
            raise CoordinatorFixtureError(
                f"unknown provider-work label: {work_label!r}"
            )
        referenced_entities.add(work[1])

    unknown = referenced_entities - set(entities)
    if unknown:
        raise CoordinatorFixtureError(
            f"unresolved fixture entity labels: {sorted(unknown)}"
        )

    namespace = uuid5(UUID("00000000-0000-0000-0000-0000000000ca"), scenario.id)
    entity_resolution = {label: uuid5(namespace, label) for label in sorted(entities)}
    work_resolution = {
        label: (provider, entity_resolution[entity_label], depth)
        for label, (provider, entity_label, depth) in provider_work.items()
    }
    return CoordinatorScenarioResolution(
        entities=entity_resolution,
        provider_work=work_resolution,
    )
