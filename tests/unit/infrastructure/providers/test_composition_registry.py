# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Provider-composition registry coverage (PR 19B)."""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-few-public-methods,redefined-outer-name

import pytest

from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config import settings_from_config
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.providers.composition import (
    DefaultHttpClientFactory,
    ProviderComposition,
)

_FAKE_TOKEN_SECRET_NAME = "ATI_IPINFO_LITE_TOKEN"
_FAKE_ABUSEIPDB_KEY_SECRET_NAME = "ATI_ABUSEIPDB_API_KEY"
_FAKE_THREATFOX_KEY_SECRET_NAME = "ATI_THREATFOX_AUTH_KEY"
_FAKE_URLHAUS_KEY_SECRET_NAME = "ATI_URLHAUS_AUTH_KEY"


class _StaticSecretsResolver(SecretsResolver):
    """Deterministic resolver backed by an in-memory mapping."""

    def __init__(self, values: dict[str, str]) -> None:
        """Initialize with the resolved reference-value mapping."""
        self._values = values

    def get(self, name: str) -> str | None:
        """Return the mapping value for a reference name."""
        return self._values.get(name)


def _fake_secrets() -> _StaticSecretsResolver:
    """Build the standard fake resolver carrying the fake test credentials."""
    return _StaticSecretsResolver(
        {
            _FAKE_TOKEN_SECRET_NAME: "fake-token",
            _FAKE_ABUSEIPDB_KEY_SECRET_NAME: "fake-abuseipdb-key",
            _FAKE_THREATFOX_KEY_SECRET_NAME: "fake-threatfox-key",
            _FAKE_URLHAUS_KEY_SECRET_NAME: "fake-urlhaus-key",
        }
    )


@pytest.mark.asyncio
async def test_composition_provider_registry_maps_source_ids() -> None:
    """The provider registry maps every composed SourceId to its provider."""
    settings = settings_from_config({})
    async with await ProviderComposition.create(
        settings,
        http_client_factory=DefaultHttpClientFactory(),
        secrets=_fake_secrets(),
    ) as comp:
        registry = comp.provider_registry()
        assert registry[SourceId.GOOGLE_PUBLIC_DNS] is comp.google_dns
        assert registry[SourceId.RDAP] is comp.rdap
        assert registry[SourceId.IPINFO_LITE] is comp.ipinfo_lite
        assert registry[SourceId.ABUSEIPDB] is comp.abuseipdb
        assert registry[SourceId.THREATFOX] is comp.threatfox
        assert registry[SourceId.URLHAUS] is comp.urlhaus
        # The DB-IP provider is composed only with a configured artifact URI.
        assert SourceId.DBIP_CITY_LITE not in registry
        # Every key is a SourceId member whose provider identity equals its
        # source URN, keeping registry typing end-to-end consistent.
        assert all(
            isinstance(key, SourceId) and provider.id == key.value
            for key, provider in registry.items()
        )
