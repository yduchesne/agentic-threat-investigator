# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D deterministic Coordinator fixture-world composition.

Each repository coordinator scenario declares one fixture whose deterministic
world the production Coordinator graph executes against. Providers here are
fixture-owned truth, never policy: they implement the production
:class:`~agentic_threat_investigator.app.providers.EvidenceProvider` boundary
and emit PR 28A/B semantic :class:`ConvertedEvidence` (normalized facts the
existing production extractors already understand), so the **production**
Coordinator graph, policy, transitions, budgets, analysis, and research
lifecycle run exactly as authored. No Coordinator policy is reimplemented and
no log is parsed.

World truth per provider script:

- ``google_public_dns`` on the root DOMAIN resolves the fixture's
  ``resolved_ip`` (an A record the DNS extractor turns into a DISCOVERED IP +
  ``RESOLVES_TO`` assertion) when the fixture declares that label; otherwise
  it returns a valid empty result (a legitimate miss with no discovery).
- ``abuseipdb`` on an IP returns contextual reputation facts (the registered
  reputation extractor derives no graph structure).
- ``threatfox`` on an IP associates the fixture malware family
  (``ASSOCIATED_WITH`` + researched malware discovery) only for fixtures that
  declare a malware label; otherwise it returns a valid empty result.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid5

from agentic_threat_investigator.app.orchestration.research import (
    ResearchAgentResearchExecutor,
)
from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    convert_timeline_actions,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderResult,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)
from agentic_threat_investigator.evaluation.coordinator import CoordinatorActionRecord
from agentic_threat_investigator.evaluation.scenario_fixtures import (
    CoordinatorMaterializedFixture,
)

_FIXED_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
"""Fixed UTC timestamp for every fixture-world observation."""

_DNS_FLAGS = {"ad": False, "cd": False, "ra": True, "rd": True, "tc": False}
"""Strict NOERROR DNS flags accepted by the production DNS extractor."""

_DNS_NAMESPACE = UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
"""Stable namespace for fixture-world Evidence identities."""


def _converted(
    *,
    provider: str,
    source_record_id: str,
    evidence_type: EvidenceType,
    facts: dict[str, Any],
) -> ConvertedEvidence:
    """Build one normalized PR 28A ConvertedEvidence observation."""
    evidence_id = uuid5(_DNS_NAMESPACE, source_record_id)
    return ConvertedEvidence(
        evidence=Evidence(
            id=evidence_id,
            type=evidence_type,
            source=provider,
            source_record_id=source_record_id,
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=evidence_id,
            retrieved_at=_FIXED_TS,
            observed_at=_FIXED_TS,
            facts=facts,
        ),
    )


class FixtureDnsProvider(EvidenceProvider):
    """Fixture-world Google Public DNS provider (semantic ConvertedEvidence)."""

    def __init__(self, *, domain: str, resolved_ip: str | None) -> None:
        """Bind the fixture root domain and optional resolved IP truth.

        When the fixture declares no IP label, the DNS world returns a valid
        extractable TXT observation (no entity discovery), so the provider
        round still produces analyzable evidence without inventing graph
        structure.
        """
        self._domain = domain
        self._resolved_ip = resolved_ip

    @property
    def id(self) -> str:
        """Return the stable Google Public DNS source identity."""
        return SourceId.GOOGLE_PUBLIC_DNS.value

    def supports(self, entity: Entity) -> bool:
        """Support only DOMAIN entities (the fixture root work)."""
        return entity.type is EntityType.DOMAIN

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Return the fixture A-record, or a TXT observation when no IP is declared."""
        del investigation_id
        if self._resolved_ip is None:
            return ProviderResult(
                provider=self.id,
                evidence=(
                    _converted(
                        provider=self.id,
                        source_record_id=f"scenario:fixture:dns:{entity.value}:txt",
                        evidence_type=EvidenceType.DNS,
                        facts={
                            "query_name": self._domain,
                            "query_type": "TXT",
                            "status": 0,
                            "flags": _DNS_FLAGS,
                            "answers": [
                                {
                                    "name": self._domain,
                                    "record_type": "TXT",
                                    "ttl": 300,
                                    "value": "v=spf1 -all",
                                }
                            ],
                        },
                    ),
                ),
            )
        return ProviderResult(
            provider=self.id,
            evidence=(
                _converted(
                    provider=self.id,
                    source_record_id=f"scenario:fixture:dns:{entity.value}",
                    evidence_type=EvidenceType.DNS,
                    facts={
                        "query_name": self._domain,
                        "query_type": "A",
                        "status": 0,
                        "flags": _DNS_FLAGS,
                        "answers": [
                            {
                                "name": self._domain,
                                "record_type": "A",
                                "ttl": 300,
                                "value": self._resolved_ip,
                            }
                        ],
                    },
                ),
            ),
        )


class FixtureAbuseIpdbProvider(EvidenceProvider):
    """Fixture-world AbuseIPDB provider (contextual reputation facts only)."""

    @property
    def id(self) -> str:
        """Return the stable AbuseIPDB source identity."""
        return SourceId.ABUSEIPDB.value

    def supports(self, entity: Entity) -> bool:
        """Support only IP-address entities."""
        return entity.type is EntityType.IP_ADDRESS

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Return contextual reputation facts with no graph structure."""
        del investigation_id
        return ProviderResult(
            provider=self.id,
            evidence=(
                _converted(
                    provider=self.id,
                    source_record_id=f"scenario:fixture:abuseipdb:{entity.value}",
                    evidence_type=EvidenceType.REPUTATION,
                    facts={"type": "contextual", "score": 0},
                ),
            ),
        )


class FixtureThreatFoxProvider(EvidenceProvider):
    """Fixture-world ThreatFox provider (optional malware association truth)."""

    def __init__(self, *, malware: str | None) -> None:
        """Bind the fixture malware identifier (``None`` = benign world)."""
        self._malware = malware

    @property
    def id(self) -> str:
        """Return the stable ThreatFox source identity."""
        return SourceId.THREATFOX.value

    def supports(self, entity: Entity) -> bool:
        """Support only IP-address entities."""
        return entity.type is EntityType.IP_ADDRESS

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Return the fixture malware association, or a valid empty result."""
        del investigation_id
        if self._malware is None:
            return ProviderResult(provider=self.id, evidence=())
        return ProviderResult(
            provider=self.id,
            evidence=(
                _converted(
                    provider=self.id,
                    source_record_id=f"scenario:fixture:threatfox:{entity.value}",
                    evidence_type=EvidenceType.THREAT_INTELLIGENCE,
                    facts={
                        "matches": [
                            {
                                "malware": self._malware,
                                "malware_printable": self._malware,
                            }
                        ]
                    },
                ),
            ),
        )


def build_fixture_provider_registry(
    materialized: CoordinatorMaterializedFixture,
) -> dict[SourceId, EvidenceProvider]:
    """Compose the deterministic provider registry for one materialized fixture.

    World truth comes exclusively from the materialized fixture's declared
    entity identities and provider scripts; no provider policy is invented.
    """
    identities = materialized.entity_identities
    root_value = identities.get("root_domain", (EntityType.DOMAIN, ""))[1]
    resolved_value: str | None = None
    malware_value: str | None = None
    for entity_type, value in identities.values():
        if entity_type is EntityType.IP_ADDRESS:
            resolved_value = value
        elif entity_type is EntityType.MALWARE:
            malware_value = value
    available: dict[SourceId, EvidenceProvider] = {
        SourceId.GOOGLE_PUBLIC_DNS: FixtureDnsProvider(
            domain=root_value, resolved_ip=resolved_value
        ),
        SourceId.ABUSEIPDB: FixtureAbuseIpdbProvider(),
        # World truth: the fixture IP always associates with the AsyncRAT
        # malware family. Any fixture whose coordinator plans ThreatFox work
        # discovers the researchable malware (scenario semantics decide
        # research policy; the fixture world only supplies provider truth).
        SourceId.THREATFOX: FixtureThreatFoxProvider(
            malware=malware_value or "asyncrat"
        ),
    }
    # The world exposes Google Public DNS (root-domain discovery is planned by
    # the production Coordinator itself) plus exactly the providers the
    # fixture declares scripted provider work for. Registering an unscripted
    # provider would make the Coordinator plan extra work the scenario never
    # authorizes (for example dual ThreatFox + AbuseIPDB coverage of one IP).
    scripted = {script.provider for script in materialized.provider_scripts}
    return {
        provider: implementation
        for provider, implementation in available.items()
        if provider is SourceId.GOOGLE_PUBLIC_DNS or provider in scripted
    }


def coordinator_actions(
    events: tuple[InvestigationTimelineEvent, ...] | list[InvestigationTimelineEvent],
) -> tuple[CoordinatorActionRecord, ...]:
    """Convert ordered timeline events into structured action records.

    Thin alias over the production timeline->action converter so evaluation
    adapters never import the production mapper directly and never parse logs.
    """
    return convert_timeline_actions(tuple(events))


class CoordinatorFixtureRunner:
    """Run the production Coordinator graph for one materialized fixture.

    Composes the production :class:`LocalInvestigationRunner` with the
    fixture-world provider registry and the caller-supplied analysis and
    research executor factories; the production Coordinator policy/graph and
    persistence execute unchanged.
    """

    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        analysis_executor_factory: AnalysisExecutorFactory,
        research_executor_factory: ResearchExecutorFactory | None = None,
        clock: Callable[[], datetime] | None = None,
        recursion_limit: int = 40,
    ) -> None:
        """Bind the persistence, executor factories, and recursion bound."""
        self._uow_factory = uow_factory
        self._analysis_executor_factory = analysis_executor_factory
        self._research_executor_factory = research_executor_factory
        self._clock = clock if clock is not None else (lambda: _FIXED_TS)
        self._recursion_limit = recursion_limit

    async def run(
        self, materialized: CoordinatorMaterializedFixture
    ) -> InvestigationState:
        """Execute the production runner and return the terminal investigation."""
        runner = LocalInvestigationRunner(
            uow_factory=self._uow_factory,
            provider_registry=build_fixture_provider_registry(materialized),
            analysis_executor_factory=self._analysis_executor_factory,
            research_executor_factory=self._research_executor_factory,
            clock=self._clock,
            recursion_limit=self._recursion_limit,
        )
        return await runner.run(materialized.initial_state.investigation_id)


AnalysisExecutorFactory = Callable[[UUID], EvidenceAnalystAnalysisExecutor]
"""One production analysis-executor factory bound to an Investigation."""

ResearchExecutorFactory = Callable[[UUID], ResearchAgentResearchExecutor]
"""One production research-executor factory bound to an Investigation."""
