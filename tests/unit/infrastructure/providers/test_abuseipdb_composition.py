# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""AbuseIPDB-specific provider composition tests.

Covers bootstrap key resolution, settings wiring, and the rollback
behavior of the composition root when the AbuseIPDB credential is missing
or blank. The fakes here are deliberately local and small so the shared
composition suite keeps its own fixtures.
"""

from __future__ import annotations

import pytest

from agentic_threat_investigator.app.secrets import SecretNotFoundError, SecretsResolver
from agentic_threat_investigator.config import settings_from_config
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.providers.composition import (
    HttpClientFactory,
    ProviderComposition,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpClient,
    ProviderHttpPolicy,
    RateLimiterSettings,
)

pytestmark = pytest.mark.asyncio

_ABUSEIPDB_KEY_SECRET_NAME = "ATI_ABUSEIPDB_API_KEY"
_FAKE_KEY = "fake-test-abuseipdb-key"
_FAKE_TOKEN = "fake-test-token"


class _KeyringResolver(SecretsResolver):  # pylint: disable=too-few-public-methods
    """Deterministic resolver returning credential values from a keyring."""

    def __init__(self, **values: str) -> None:
        """Initialize with reference-name/value keyword pairs."""
        self._values = values

    def get(self, name: str) -> str | None:
        """Return the keyring value for a reference name."""
        return self._values.get(name)


class _ClosingClient(ProviderHttpClient):
    """Owned client recording its close order into a shared list."""

    def __init__(self, closed: list[str], label: str) -> None:
        """Initialize with the shared close log and a label."""
        self._closed_log = closed
        self._label = label
        super().__init__()

    async def aclose(self) -> None:
        """Record the close, then close normally."""
        self._closed_log.append(self._label)
        await super().aclose()


class _SequentialFactory(HttpClientFactory):  # pylint: disable=too-few-public-methods
    """Factory yielding tracking clients in creation order."""

    def __init__(self, closed: list[str]) -> None:
        """Initialize with the shared close log."""
        self._closed = closed
        self.created = 0

    def create(
        self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
    ) -> ProviderHttpClient:
        """Create one tracking client labeled by creation order."""
        self.created += 1
        return _ClosingClient(self._closed, f"client-{self.created}")


async def test_composition_wires_abuseipdb_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Composition applies exact settings and a dedicated limiter to AbuseIPDB."""
    seen: list[RateLimiterSettings] = []

    class _RecordingLimiter(BoundedLimiter):
        """Spy recording the exact limiter settings AbuseIPDB receives."""

        def __init__(self, limiter_settings: RateLimiterSettings) -> None:
            seen.append(limiter_settings)
            super().__init__(limiter_settings)

    monkeypatch.setattr(
        "agentic_threat_investigator.infrastructure.providers.composition."
        "BoundedLimiter",
        _RecordingLimiter,
    )
    settings = settings_from_config(
        {
            "abuseipdb_max_concurrency": 6,
            "abuseipdb_requests_per_second": 8.0,
            "abuseipdb_max_age_in_days": 90,
            "abuseipdb_api_key_secret": "CUSTOM_ABUSEIPDB_VAR",
        }
    )

    async with await ProviderComposition.create(
        settings,
        secrets=_KeyringResolver(
            ATI_IPINFO_LITE_TOKEN=_FAKE_TOKEN,
            CUSTOM_ABUSEIPDB_VAR=_FAKE_KEY,
        ),
    ) as comp:
        assert seen[3] == RateLimiterSettings(
            max_concurrency=6, requests_per_second=8.0
        )
        assert comp.abuseipdb.supports(
            Entity(type=EntityType.IP_ADDRESS, value="192.0.2.39")
        )
        assert not comp.abuseipdb.supports(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert comp.abuseipdb.id == "urn:ati:source:abuseipdb"

        # White-box assertions proving bootstrap resolution and settings
        # wiring; the values are fake test credentials only.
        # pylint: disable=protected-access
        assert comp.abuseipdb._api_key == _FAKE_KEY
        assert comp.abuseipdb._max_age_in_days == 90
        # pylint: enable=protected-access


@pytest.mark.parametrize("blank_key", ["", "   ", "\t"])
async def test_composition_blank_abuseipdb_key_fails_before_client_creation(
    blank_key: str,
) -> None:
    """Empty, whitespace, and tab key values fail before the AbuseIPDB client."""
    closed: list[str] = []
    factory = _SequentialFactory(closed)
    with pytest.raises(SecretNotFoundError) as excinfo:
        await ProviderComposition.create(
            settings_from_config({}),
            http_client_factory=factory,
            secrets=_KeyringResolver(
                ATI_IPINFO_LITE_TOKEN=_FAKE_TOKEN,
                ATI_ABUSEIPDB_API_KEY=blank_key,
            ),
        )

    # Only Google DNS, RDAP, and IPinfo clients were created and rolled
    # back in LIFO unwind order; no AbuseIPDB client factory call occurred.
    assert factory.created == 3
    assert closed == ["client-3", "client-2", "client-1"]

    # The raised error carries only the configured reference name; the
    # blank resolved value never appears in it.
    assert (
        str(excinfo.value) == f"required secret not found: {_ABUSEIPDB_KEY_SECRET_NAME}"
    )
    assert blank_key not in str(excinfo.value) or not blank_key


async def test_composition_missing_abuseipdb_key_fails_before_client_creation() -> None:
    """A missing AbuseIPDB key fails clearly and rolls back created clients."""
    closed: list[str] = []
    factory = _SequentialFactory(closed)
    with pytest.raises(SecretNotFoundError) as excinfo:
        await ProviderComposition.create(
            settings_from_config({}),
            http_client_factory=factory,
            secrets=_KeyringResolver(ATI_IPINFO_LITE_TOKEN=_FAKE_TOKEN),
        )

    assert factory.created == 3
    assert closed == ["client-3", "client-2", "client-1"]
    assert (
        str(excinfo.value) == f"required secret not found: {_ABUSEIPDB_KEY_SECRET_NAME}"
    )
