# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E TAXII collection producer composition tests (T33E-R01..R15).

Covers the settings-driven TAXII collection composition seam: the
not-configured (blank URL) state, authoritative ``Settings.datasources``
resolution that can never accidentally select the MITRE ATT&CK STIX FILE
definition, fail-closed dimension/missing/ambiguous definition checks, the
real STIX_21 converter registry selection (never by source or protocol),
bearer-token resolution, and TAXII/OpenCTI's continued absence from the
Investigation provider registry. These tests never touch a live TAXII
server and never require a bearer token for the blank-URL state.
"""

from __future__ import annotations

from types import TracebackType
from typing import Self, cast

import pytest

from agentic_threat_investigator.app.evidence_conversion import (
    ToEvidenceConverterRegistry,
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
from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
    Stix21ToEvidenceConverter,
)
from agentic_threat_investigator.infrastructure.datasources.taxii21 import (
    Taxii21Datasource,
)
from agentic_threat_investigator.infrastructure.providers.composition import (
    ProviderComposition,
    compose_taxii_collection_producer,
    resolve_taxii_datasource_definition,
)

pytestmark = pytest.mark.unit

_ROOT = "https://taxii.example.test/root"
_COLLECTION = "collection-00000000-0000-4000-8000-000000000001"
_TOKEN = "fake-taxii-bearer-token"


def _taxii_definition(
    *,
    datasource_id: str = "opencti-collection",
    source_id: SourceId = SourceId.OPENCTI,
    protocol: DatasourceProtocol = DatasourceProtocol.TAXII_21,
    serialization_format: object = SerializationFormat.JSON,
    semantic_format: SemanticFormatId = SemanticFormatId.STIX_21,
) -> dict[str, object]:
    """Build one TAXII/STIX-shaped definition as profile JSON."""
    return {
        "datasource_id": datasource_id,
        "source_id": source_id,
        "protocol": protocol,
        "serialization_format": serialization_format,
        "semantic_format": semantic_format,
    }


def _stub_datasource() -> Taxii21Datasource:
    """Return a structural stand-in the composition never invokes.

    The composition function validates the definition and stores the
    acquirer; it never calls ``acquire`` and never opens the HTTP client,
    so a deterministic stand-in satisfies the seam for these tests.
    """
    return cast(Taxii21Datasource, object())


class _KeyringResolver(SecretsResolver):
    """Deterministic resolver returning credential values from a keyring."""

    def __init__(self, **values: str) -> None:
        """Initialize with reference-name/value keyword pairs."""
        self._values = values

    def get(self, name: str) -> str | None:
        """Return the keyring value for a reference name."""
        return self._values.get(name)


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
    """Return one fresh no-op UnitOfWork."""
    return _NoopUow()


class TestDatasourceResolution:
    """T33E-R01, R03, R04, R11: authoritative definition resolution."""

    def test_r11_mitre_file_definition_never_matches(self) -> None:
        """R11: a FILE/STIX MITRE definition alone resolves to no TAXII source."""
        settings = settings_from_config(
            {
                "taxii_api_root_url": _ROOT,
                "taxii_collection_id": _COLLECTION,
                "datasources": [
                    _taxii_definition(protocol=DatasourceProtocol.FILE),
                ],
            }
        )
        assert resolve_taxii_datasource_definition(settings) is None

    def test_r02_exact_taxii_definition_resolves(self) -> None:
        """R02: exactly one TAXII/STIX definition resolves authoritatively."""
        settings = settings_from_config(
            {
                "datasources": [
                    _taxii_definition(),
                ]
            }
        )
        definition = resolve_taxii_datasource_definition(settings)
        assert definition is not None
        assert definition.datasource_id.value == "opencti-collection"
        assert definition.protocol is DatasourceProtocol.TAXII_21
        assert definition.semantic_format is SemanticFormatId.STIX_21

    def test_r04_multiple_matching_definitions_fail_closed(self) -> None:
        """R04: more than one matching TAXII/STIX definition is ambiguous."""
        settings = settings_from_config(
            {
                "datasources": [
                    _taxii_definition(datasource_id="opencti-collection"),
                    _taxii_definition(
                        datasource_id="commercial-tip", source_id=SourceId.MISP
                    ),
                ]
            }
        )
        with pytest.raises(ValueError, match="ambiguous"):
            resolve_taxii_datasource_definition(settings)

    def test_r03_url_without_taxii_definition_fails_closed(self) -> None:
        """R03: a configured URL with no TAXII definition fails closed."""
        # Default settings already carry the representative TAXII definition,
        # so this scenario overrides datasources with only non-TAXII entries.
        settings = Settings(
            taxii_api_root_url=_ROOT,
            taxii_collection_id=_COLLECTION,
            datasources=(
                DatasourceDefinition(
                    datasource_id=DatasourceId("threatfox-live"),
                    source_id=SourceId.THREATFOX,
                    protocol=DatasourceProtocol.HTTPS,
                    serialization_format=SerializationFormat.JSON,
                    semantic_format=SemanticFormatId.THREATFOX,
                ),
            ),
        )
        with pytest.raises(ValueError, match="no TAXII/STIX datasource"):
            compose_taxii_collection_producer(
                settings,
                datasource=_stub_datasource(),
                uow_factory=_uow_factory,
            )


class TestProducerComposition:
    """T33E-R05..R14: definition dimensions and credential resolution."""

    @pytest.mark.parametrize(
        ("protocol", "semantic"),
        [
            (DatasourceProtocol.HTTPS, SemanticFormatId.STIX_21),
            (DatasourceProtocol.FILE, SemanticFormatId.STIX_21),
        ],
    )
    def test_r05_r06_wrong_protocol_fails_closed(
        self, protocol: DatasourceProtocol, semantic: SemanticFormatId
    ) -> None:
        """R05/R06: HTTPS/FILE instead of TAXII_21 never composes."""
        settings = settings_from_config(
            {
                "datasources": [
                    _taxii_definition(protocol=protocol, semantic_format=semantic),
                ]
            }
        )
        with pytest.raises(ValueError):
            compose_taxii_collection_producer(
                settings,
                datasource=_stub_datasource(),
                uow_factory=_uow_factory,
            )

    def test_r07_non_json_serialization_fails_closed(self) -> None:
        """R07: a non-JSON serialization is rejected at the settings boundary.

        ``SerializationFormat`` admits exactly ``json``, so an XML-shaped
        definition cannot be expressed as a valid ``DatasourceDefinition``;
        the settings layer fails closed before resolution can ever see it.
        """
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            settings_from_config(
                {
                    "datasources": [
                        _taxii_definition(serialization_format="xml"),
                    ]
                }
            )

    def test_r08_non_stix_semantic_format_fails_closed(self) -> None:
        """R08: TAXII with a non-STIX semantic format never matches."""
        settings = settings_from_config(
            {
                "datasources": [
                    _taxii_definition(semantic_format=SemanticFormatId.MISP),
                ]
            }
        )
        assert resolve_taxii_datasource_definition(settings) is None

    def test_r01_blank_url_returns_none_without_token(self) -> None:
        """R01: a blank TAXII URL composes no producer and needs no token."""
        settings = settings_from_config({})
        producer = compose_taxii_collection_producer(
            settings,
            datasource=None,
            uow_factory=_uow_factory,
            secrets=_KeyringResolver(),
        )
        assert producer is None

    @pytest.mark.asyncio
    async def test_r12_missing_bearer_secret_fails_before_http(self) -> None:
        """R12: a missing required bearer secret fails at composition time."""
        settings = settings_from_config(
            {
                "taxii_api_root_url": _ROOT,
                "taxii_collection_id": _COLLECTION,
            }
        )
        resolver = _KeyringResolver(
            ATI_IPINFO_LITE_TOKEN="fake-ipinfo",
            ATI_ABUSEIPDB_API_KEY="fake-abuseipdb",
            ATI_THREATFOX_AUTH_KEY="fake-threatfox",
            ATI_URLHAUS_AUTH_KEY="fake-urlhaus",
            ATI_MISP_API_KEY="fake-misp",
        )
        with pytest.raises(Exception, match="ATI_TAXII_BEARER_TOKEN"):
            await ProviderComposition.create(settings, secrets=resolver)

    def test_r13_public_auth_mode_resolves_no_secret(self) -> None:
        """R13: a public TAXII definition needs no token resolution at compose."""
        settings = settings_from_config(
            {
                "datasources": [_taxii_definition()],
            }
        )
        producer = compose_taxii_collection_producer(
            settings,
            datasource=cast(Taxii21Datasource, object()),
            uow_factory=_uow_factory,
            secrets=_KeyringResolver(),
        )
        assert producer is not None

    def test_r14_converter_registry_selected_only_by_stix21(self) -> None:
        """R14: the composed producer's registry selects Stix21ToEvidenceConverter."""
        settings = settings_from_config(
            {
                "datasources": [_taxii_definition()],
            }
        )
        producer = compose_taxii_collection_producer(
            settings,
            datasource=cast(Taxii21Datasource, object()),
            uow_factory=_uow_factory,
            secrets=_KeyringResolver(),
        )
        assert producer is not None
        registry: ToEvidenceConverterRegistry = producer._registry
        converter = registry.get(SemanticFormatId.STIX_21)
        assert isinstance(converter, Stix21ToEvidenceConverter)
        with pytest.raises(UnknownSemanticFormatError):
            registry.get(SemanticFormatId.MISP)

    def test_r09_opencti_source_is_only_provenance(self) -> None:
        """R09: the OpenCTI source identity is accepted as pure provenance."""
        settings = settings_from_config(
            {
                "datasources": [_taxii_definition()],
            }
        )
        producer = compose_taxii_collection_producer(
            settings,
            datasource=cast(Taxii21Datasource, object()),
            uow_factory=_uow_factory,
        )
        assert producer is not None
        assert producer.definition.source_id is SourceId.OPENCTI

    def test_r10_another_source_uses_the_generic_acquirer(self) -> None:
        """R10: any explicit source + TAXII/STIX dimensions composes the same way."""
        settings = settings_from_config(
            {
                "datasources": [
                    _taxii_definition(
                        datasource_id="commercial-tip", source_id=SourceId.CISA_KEV
                    ),
                ]
            }
        )
        producer = compose_taxii_collection_producer(
            settings,
            datasource=cast(Taxii21Datasource, object()),
            uow_factory=_uow_factory,
        )
        assert producer is not None
        assert producer.definition.source_id is SourceId.CISA_KEV


class TestProviderRegistry:
    """T33E-R15: TAXII/OpenCTI never enters the Investigation registry."""

    @pytest.mark.asyncio
    async def test_r15_taxii_absent_from_provider_registry(self) -> None:
        """R15: composed TAXII datasources are not Investigation providers."""
        settings = settings_from_config(
            {
                "taxii_api_root_url": _ROOT,
                "taxii_collection_id": _COLLECTION,
                "datasources": [_taxii_definition()],
            }
        )
        resolver = _KeyringResolver(
            ATI_IPINFO_LITE_TOKEN="fake-ipinfo",
            ATI_ABUSEIPDB_API_KEY="fake-abuseipdb",
            ATI_THREATFOX_AUTH_KEY="fake-threatfox",
            ATI_URLHAUS_AUTH_KEY="fake-urlhaus",
            ATI_MISP_API_KEY="fake-misp",
            ATI_TAXII_BEARER_TOKEN=_TOKEN,
        )
        async with await ProviderComposition.create(settings, secrets=resolver) as comp:
            registry = comp.provider_registry()
            assert SourceId.OPENCTI not in registry
            assert SourceId.MISP not in registry
            assert SourceId.THREATFOX not in registry
            assert comp.taxii_datasource is not None
