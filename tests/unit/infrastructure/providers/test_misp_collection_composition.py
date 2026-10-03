# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 32D MISP collection producer composition tests (M32D-C01..C10).

Covers the settings-driven MISP collection composition seam: the
not-configured (blank URL) state, authoritative ``Settings.datasources``
resolution, fail-closed dimension/missing/ambiguous definition checks, the
real semantic-format converter registry selection, and MISP's continued
absence from the Investigation provider registry. These tests never touch a
live MISP server and never require a MISP API key for the blank-URL state.
"""

from __future__ import annotations

import inspect
from types import TracebackType
from typing import Self, cast

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.datasource_provider import (
    CollectionSemanticAcquirer,
)
from agentic_threat_investigator.app.evidence_conversion import (
    UnknownSemanticFormatError,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config import settings_from_config
from agentic_threat_investigator.config.settings import Settings
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.misp import MispDatasource
from agentic_threat_investigator.infrastructure.datasources.misp_evidence import (
    MispToEvidenceConverter,
    build_misp_conversion_registry,
)
from agentic_threat_investigator.infrastructure.providers.composition import (
    ProviderComposition,
    compose_misp_collection_producer,
    resolve_misp_datasource_definition,
)

pytestmark = pytest.mark.unit

_FAKE_KEY = "fake-test-misp-api-key"
_MISP_URL = "https://misp.example.test"


def _stub_datasource() -> MispDatasource:
    """Return a structural stand-in the composition never invokes.

    The composition function validates the definition and stores the
    acquirer; it never calls ``acquire`` and never opens the HTTP client,
    so a deterministic stand-in satisfies the seam for these tests.
    """
    return cast(MispDatasource, object())


class _KeyringResolver(SecretsResolver):
    """Deterministic resolver returning credential values from a keyring."""

    def __init__(self, **values: str) -> None:
        """Initialize with reference-name/value keyword pairs."""
        self._values = values

    def get(self, name: str) -> str | None:
        """Return the keyring value for a reference name."""
        return self._values.get(name)


def _full_keyring() -> _KeyringResolver:
    """Return a keyring satisfying every composition-time credential."""
    return _KeyringResolver(
        ATI_IPINFO_LITE_TOKEN="fake-ipinfo",
        ATI_ABUSEIPDB_API_KEY="fake-abuseipdb",
        ATI_THREATFOX_AUTH_KEY="fake-threatfox",
        ATI_URLHAUS_AUTH_KEY="fake-urlhaus",
        ATI_MISP_API_KEY=_FAKE_KEY,
    )


class _NoopUow(UnitOfWork):
    """A UnitOfWork fake the composition never actually opens."""

    async def __aenter__(self) -> Self:
        """No-op enter."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """No-op exit."""

    async def commit(self) -> None:
        """No-op commit."""

    async def rollback(self) -> None:
        """No-op rollback."""


def _uow_factory() -> UnitOfWork:
    """Return a fresh no-op UnitOfWork boundary."""
    return _NoopUow()


def _misp_definition(
    *,
    datasource_id: str = "misp-live",
    source_id: object = SourceId.MISP,
    protocol: object = DatasourceProtocol.HTTPS,
    serialization_format: object = SerializationFormat.JSON,
    semantic_format: object = SemanticFormatId.MISP,
) -> dict[str, object]:
    """Build one MISP-shaped datasource definition as profile JSON."""
    return {
        "datasource_id": datasource_id,
        "source_id": source_id,
        "protocol": protocol,
        "serialization_format": serialization_format,
        "semantic_format": semantic_format,
    }


def _settings(**config: object) -> Settings:
    """Build Settings from profile configuration."""
    return settings_from_config(config)


def test_c01_blank_misp_url_composes_no_collection_producer() -> None:
    """C01: a blank URL yields no producer and requires no MISP key."""
    settings = _settings(datasources=[_misp_definition()])
    producer = compose_misp_collection_producer(
        settings,
        datasource=None,
        uow_factory=_uow_factory,
    )
    assert producer is None
    assert settings.misp_base_url == ""


def test_c02_url_with_exact_definition_composes() -> None:
    """C02: URL + exact MISP definition composes the collection producer."""
    settings = _settings(
        misp_base_url=_MISP_URL,
        datasources=[_misp_definition()],
    )
    producer = compose_misp_collection_producer(
        settings,
        datasource=_stub_datasource(),
        uow_factory=_uow_factory,
    )
    assert producer is not None
    assert producer.definition.source_id is SourceId.MISP
    assert producer.definition.protocol is DatasourceProtocol.HTTPS
    assert producer.definition.serialization_format is SerializationFormat.JSON
    assert producer.definition.semantic_format is SemanticFormatId.MISP
    assert producer.definition.datasource_id == DatasourceId("misp-live")


def test_c03_url_plus_missing_definition_fails_before_acquisition() -> None:
    """C03: URL + missing definition fails closed before acquisition."""
    settings = _settings(
        misp_base_url=_MISP_URL,
        datasources=[_misp_definition(source_id=SourceId.THREATFOX)],
    )
    assert resolve_misp_datasource_definition(settings) is None
    with pytest.raises(ValueError, match="no MISP datasource definition"):
        compose_misp_collection_producer(
            settings,
            datasource=_stub_datasource(),
            uow_factory=_uow_factory,
        )


def test_c04_ambiguous_misp_definitions_fail_closed() -> None:
    """C04: multiple MISP definitions fail closed instead of guessing."""
    settings = _settings(
        misp_base_url=_MISP_URL,
        datasources=[
            _misp_definition(datasource_id="misp-live"),
            _misp_definition(datasource_id="misp-replay"),
        ],
    )
    with pytest.raises(ValueError, match="ambiguous"):
        resolve_misp_datasource_definition(settings)


def test_c05_wrong_protocol_fails() -> None:
    """C05: a FILE MISP definition fails closed before acquisition."""
    settings = _settings(
        misp_base_url=_MISP_URL,
        datasources=[_misp_definition(protocol=DatasourceProtocol.FILE)],
    )
    with pytest.raises(ValueError, match="protocol must be HTTPS"):
        compose_misp_collection_producer(
            settings,
            datasource=_stub_datasource(),
            uow_factory=_uow_factory,
        )


def test_c06_wrong_serialization_fails() -> None:
    """C06: a non-JSON MISP serialization is rejected at the settings boundary.

    ``SerializationFormat`` currently has exactly one value (JSON), so a
    definition that is not JSON cannot be constructed; the config boundary
    rejects the unknown serialization value before composition.
    """
    with pytest.raises(ValidationError):
        _settings(
            misp_base_url=_MISP_URL,
            datasources=[_misp_definition(serialization_format="xml")],
        )


def test_c07_wrong_semantic_format_fails() -> None:
    """C07: a non-MISP semantic format fails closed before acquisition."""
    settings = _settings(
        misp_base_url=_MISP_URL,
        datasources=[_misp_definition(semantic_format=SemanticFormatId.THREATFOX)],
    )
    with pytest.raises(ValueError, match="semantic_format must be MISP"):
        compose_misp_collection_producer(
            settings,
            datasource=_stub_datasource(),
            uow_factory=_uow_factory,
        )


def test_c08_wrong_source_fails() -> None:
    """C08: a non-MISP source identity fails closed before acquisition.

    Source identity is the selection dimension, so a wrong-source definition
    is simply not a MISP definition: resolution returns ``None`` and
    composition fails exactly like a missing definition.
    """
    settings = _settings(
        misp_base_url=_MISP_URL,
        datasources=[_misp_definition(source_id=SourceId.THREATFOX)],
    )
    assert resolve_misp_datasource_definition(settings) is None
    with pytest.raises(ValueError, match="no MISP datasource definition"):
        compose_misp_collection_producer(
            settings,
            datasource=_stub_datasource(),
            uow_factory=_uow_factory,
        )


def test_c09_real_misp_registry_selects_by_semantic_format() -> None:
    """C09: the real MISP registry is selected only by semantic format."""
    registry = build_misp_conversion_registry()
    converter = registry.get(SemanticFormatId.MISP)
    assert isinstance(converter, MispToEvidenceConverter)
    with pytest.raises(UnknownSemanticFormatError):
        registry.get(SemanticFormatId.THREATFOX)


@pytest.mark.asyncio
async def test_c10_provider_registry_has_no_misp() -> None:
    """C10: MISP never enters the Investigation provider registry."""
    settings = _settings(misp_base_url=_MISP_URL, datasources=[_misp_definition()])
    async with await ProviderComposition.create(
        settings, secrets=_full_keyring()
    ) as comp:
        registry = comp.provider_registry()
        assert SourceId.MISP not in registry
        assert SourceId.THREATFOX not in registry


def test_resolution_returns_the_single_misp_definition() -> None:
    """The authoritative definition comes from Settings.datasources."""
    settings = _settings(datasources=[_misp_definition()])
    resolved = resolve_misp_datasource_definition(settings)
    assert resolved is not None
    assert isinstance(resolved, DatasourceDefinition)
    assert resolved.source_id is SourceId.MISP


def test_misp_datasource_satisfies_collection_protocol_structurally() -> None:
    """The real MispDatasource needs no wrapper to fit the collection seam."""
    signature = inspect.signature(MispDatasource.acquire)
    parameters = signature.parameters
    assert "definition" in parameters
    assert "recorder" in parameters
    assert "entity" not in parameters
    assert "supports" not in CollectionSemanticAcquirer.__abstractmethods__
