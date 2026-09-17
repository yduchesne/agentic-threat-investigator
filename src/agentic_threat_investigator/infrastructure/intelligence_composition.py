# SPDX-License-Identifier: AGPL-3.0-only
"""Operating-mode intelligence-source composition (PR 23D).

``ATI_OPERATING_MODE`` selects which intelligence-source implementations are
composed at bootstrap. This module owns the single narrow mode branch:

```text
Settings.operating_mode
        |
        +-- fake        -> build_fake_intelligence_sources(...)
        |
        +-- production  -> build_production_intelligence_sources(...)
```

Both branches yield the same existing contracts needed by the application —
above all the ``SourceId``-keyed provider registry consumed by the
production investigation graph/runner. There is no fallback between modes:
``fake`` never instantiates a real provider, and ``production`` never
instantiates a fake one. The Coordinator, graph nodes, provider executor,
persistence services, API routers, domain models, and report code remain
mode-unaware.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config.settings import OperatingMode, Settings
from agentic_threat_investigator.domain.datasource import DatasourceDefinition
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    build_threatfox_datasource_provider,
)
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeBatchArtifactData,
    FakeWorldCatalog,
)
from agentic_threat_investigator.infrastructure.fake_runtime.providers import (
    FakeWorldEvidenceProvider,
)
from agentic_threat_investigator.infrastructure.providers.composition import (
    HttpClientFactory,
    ProviderComposition,
)


@dataclass(frozen=True)
class IntelligenceSourceComposition:
    """Owned intelligence-source composition for one operating mode.

    ``provider_registry`` is the read-only ``SourceId``-keyed registry the
    production graph/runner consumes. ``batch_bindings`` carries packaged
    fake batch fixture bindings in fake mode and is empty in production
    mode (production batch artifacts are deployment-supplied, not owned by
    this composition). ``_owned_resources`` carries process-owned
    infrastructure (for example the production ``ProviderComposition``) so
    :meth:`aclose` can release them; it is never part of the public
    contract.
    """

    provider_registry: Mapping[SourceId, EvidenceProvider]
    batch_bindings: tuple[FakeBatchArtifactData, ...] = ()
    _owned_resources: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        """Snapshot the registry read-only and the bindings deterministically."""
        object.__setattr__(
            self, "provider_registry", MappingProxyType(dict(self.provider_registry))
        )
        object.__setattr__(self, "batch_bindings", tuple(self.batch_bindings))
        object.__setattr__(self, "_owned_resources", tuple(self._owned_resources))

    @property
    def operating_mode_label(self) -> str:
        """Return the safe composition label for startup observability."""
        return "fake" if self.batch_bindings else "production"

    async def aclose(self) -> None:
        """Release process-owned resources, re-raising the first failure."""
        errors: list[BaseException] = []
        for resource in self._owned_resources:
            closer = getattr(resource, "aclose", None)
            if closer is None:
                continue
            try:
                await closer()
            except asyncio.CancelledError as exc:
                errors.append(exc)
            except Exception as exc:  # noqa: BLE001 - close failures propagate
                errors.append(exc)
        if errors:
            raise errors[0]


def build_fake_intelligence_sources(
    settings: Settings,
    *,
    catalog: FakeWorldCatalog | None = None,
    clock: Callable[[], datetime] | None = None,
) -> IntelligenceSourceComposition:
    """Compose deterministic fake live providers over the packaged world.

    The fake registry contains exactly the deterministic fake providers for
    the v0.1 live source set; no production provider, HTTP client, or
    provider secret is constructed. A missing or malformed packaged fixture
    fails composition through :class:`FakeWorldValidationError` before any
    provider is returned.
    """
    del settings
    world_catalog = catalog if catalog is not None else FakeWorldCatalog.load_packaged()
    registry: dict[SourceId, EvidenceProvider] = {
        SourceId.GOOGLE_PUBLIC_DNS: FakeWorldEvidenceProvider(
            SourceId.GOOGLE_PUBLIC_DNS, world_catalog, clock=clock
        ),
        SourceId.RDAP: FakeWorldEvidenceProvider(
            SourceId.RDAP, world_catalog, clock=clock
        ),
        SourceId.IPINFO_LITE: FakeWorldEvidenceProvider(
            SourceId.IPINFO_LITE, world_catalog, clock=clock
        ),
        SourceId.ABUSEIPDB: FakeWorldEvidenceProvider(
            SourceId.ABUSEIPDB, world_catalog, clock=clock
        ),
        SourceId.THREATFOX: FakeWorldEvidenceProvider(
            SourceId.THREATFOX, world_catalog, clock=clock
        ),
        SourceId.URLHAUS: FakeWorldEvidenceProvider(
            SourceId.URLHAUS, world_catalog, clock=clock
        ),
    }
    return IntelligenceSourceComposition(
        provider_registry=registry,
        batch_bindings=world_catalog.batch_artifacts(),
    )


def _threatfox_datasource_definition(settings: Settings) -> DatasourceDefinition:
    """Return the unique configured ThreatFox datasource definition.

    The migrated production provider is built from ``Settings.datasources``;
    there is no second independent definition. Zero or ambiguous ThreatFox
    definitions fail closed at bootstrap (the dimension contract itself is
    validated fail-closed by the acquirer before any I/O).
    """
    matches = [
        definition
        for definition in settings.datasources
        if definition.source_id is SourceId.THREATFOX
    ]
    if len(matches) != 1:
        raise ValueError(
            "exactly one ThreatFox datasource definition is required for "
            "the migrated production provider"
        )
    return matches[0]


async def build_production_intelligence_sources(
    settings: Settings,
    *,
    http_client_factory: HttpClientFactory | None = None,
    secrets: SecretsResolver | None = None,
    uow_factory: Callable[[], UnitOfWork],
) -> IntelligenceSourceComposition:
    """Compose the real configured intelligence sources (production branch).

    The owned HTTP clients and resolved provider credentials come from the
    infrastructure ``ProviderComposition``; the same composition also owns
    the PR 27C ``ThreatFoxDatasource``. The migrated PR 27E datasource-
    backed ThreatFox provider is composed here, at the operating-mode
    bootstrap boundary, because it requires the application UnitOfWork
    factory and the semantic-format converter registry: infrastructure
    provider composition never owns Evidence-persistence wiring merely
    because lifecycle recording uses a UnitOfWork.
    """
    composition = await ProviderComposition.create(
        settings,
        http_client_factory=http_client_factory,
        secrets=secrets,
    )
    registry = dict(composition.provider_registry())
    registry[SourceId.THREATFOX] = build_threatfox_datasource_provider(
        definition=_threatfox_datasource_definition(settings),
        datasource=composition.threatfox_datasource,
        uow_factory=uow_factory,
    )
    return IntelligenceSourceComposition(
        provider_registry=registry,
        _owned_resources=(composition,),
    )


async def build_intelligence_sources(
    settings: Settings,
    *,
    http_client_factory: HttpClientFactory | None = None,
    secrets: SecretsResolver | None = None,
    catalog: FakeWorldCatalog | None = None,
    clock: Callable[[], datetime] | None = None,
    uow_factory: Callable[[], UnitOfWork] | None = None,
) -> IntelligenceSourceComposition:
    """Select and build the intelligence-source composition for the mode.

    The mode branch lives only at this bootstrap/composition boundary. Both
    branches return the same existing provider-registry contract; there is
    no silent fallback between modes. ``uow_factory`` is required for the
    production branch (it backs the migrated datasource provider's lifecycle
    recorder) and ignored by the fake branch.
    """
    if settings.operating_mode is OperatingMode.FAKE:
        return build_fake_intelligence_sources(settings, catalog=catalog, clock=clock)
    if uow_factory is None:
        raise ValueError(
            "production intelligence composition requires a UnitOfWork factory"
        )
    return await build_production_intelligence_sources(
        settings,
        http_client_factory=http_client_factory,
        secrets=secrets,
        uow_factory=uow_factory,
    )
