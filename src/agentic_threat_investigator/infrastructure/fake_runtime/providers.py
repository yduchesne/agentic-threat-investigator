# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic fake live evidence providers (PR 23D).

Each fake provider implements the existing :class:`EvidenceProvider` ABC,
preserves the exact production ``SourceId`` identity, mirrors the real
provider's ``supports(Entity)`` applicability, and returns existing
``ProviderResult``/``Evidence`` contracts built from the shared
:class:`~agentic_threat_investigator.infrastructure.fake_runtime.catalog.FakeWorldCatalog`.

Fake providers:

- never construct or use a production HTTP transport;
- require no provider API secret;
- perform no database access;
- perform no LLM call;
- are deterministic for a fixed world version, entity, and injected clock.

A single fixture-backed adapter is appropriate here because every fake
shares the same lookup semantics while each provider's identity,
applicability, evidence type, and normalized fact vocabulary come from the
catalog and the existing extraction contracts.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderResult,
    normalize_retrieval_timestamp,
    validate_investigation_entity,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeWorldCatalog,
)

# Real-provider applicability mirrored exactly (PR 23D Step 3.2): fake
# providers must not support every entity merely to maximize demo output.
_SUPPORTED_TYPES: dict[SourceId, frozenset[EntityType]] = {
    SourceId.GOOGLE_PUBLIC_DNS: frozenset({EntityType.DOMAIN, EntityType.IP_ADDRESS}),
    SourceId.RDAP: frozenset(
        {EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.ASN}
    ),
    SourceId.IPINFO_LITE: frozenset({EntityType.IP_ADDRESS}),
    SourceId.ABUSEIPDB: frozenset({EntityType.IP_ADDRESS}),
    SourceId.THREATFOX: frozenset({EntityType.DOMAIN, EntityType.IP_ADDRESS}),
    SourceId.URLHAUS: frozenset(
        {EntityType.URL, EntityType.DOMAIN, EntityType.IP_ADDRESS}
    ),
}


def fake_provider_supported_types(source: SourceId) -> frozenset[EntityType]:
    """Return the mirrored real-provider applicability for a fake source."""
    try:
        return _SUPPORTED_TYPES[source]
    except KeyError as exc:
        raise ValueError(
            f"no fake provider contract for source {source.value}"
        ) from exc


class FakeWorldEvidenceProvider(EvidenceProvider):
    """Fixture-backed deterministic live provider for one source identity.

    The provider resolves every supported investigation through the shared
    synthetic-world catalog and stamps ``retrieved_at`` from the injected
    clock (the default is UTC now, mirroring the production providers). The
    catalog supplies source-semantic ``observed_at`` values where the source
    contract supports them; ``raw_payload`` carries a small non-semantic
    synthetic-world marker so fake evidence remains visibly distinguishable
    from production intelligence without altering analytical facts.
    """

    def __init__(
        self,
        source: SourceId,
        catalog: FakeWorldCatalog,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the source identity, catalog, and optional deterministic clock."""
        self._source = source
        self._catalog = catalog
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )

    @property
    def id(self) -> str:
        """Return the exact production source URN for this provider."""
        return self._source.value

    def supports(self, entity: Entity) -> bool:
        """Return the mirrored real-provider applicability, without I/O."""
        return entity.type in fake_provider_supported_types(self._source)

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Retrieve and normalize deterministic world evidence for one entity.

        Unsupported or uncanonicalizable entities return the standard single
        non-retryable ``UNSUPPORTED_INDICATOR`` result exactly like the
        production providers; an unknown world entity is a deterministic
        no-result (a valid miss, never a benign assessment); a configured
        fixture error uses the existing typed ``ProviderError`` semantics.
        """
        validation = validate_investigation_entity(self, entity)
        rejection = validation[1]
        if rejection is not None:
            return rejection
        canonical_value = validation[0]
        assert canonical_value is not None

        retrieved_at = normalize_retrieval_timestamp(self._clock)
        response = self._catalog.provider_response(
            self._source.value, entity.type, canonical_value, retrieved_at
        )
        if response.error is not None:
            return ProviderResult(
                provider=self.id,
                errors=(response.error,),
            )
        evidence_list: list[Evidence] = []
        for observation in response.observations:
            evidence_list.append(
                Evidence(
                    investigation_id=investigation_id,
                    type=observation.evidence_type,
                    subject=EvidenceEntityRef(
                        id=entity.id,
                        type=entity.type,
                        value=canonical_value,
                    ),
                    source=self.id,
                    observed_at=observation.observed_at,
                    retrieved_at=retrieved_at,
                    facts=observation.facts,
                    raw_payload={
                        "synthetic_world": "fake_world_v1",
                        "provider": self.id,
                    },
                )
            )
        return ProviderResult(provider=self.id, evidence=tuple(evidence_list))
