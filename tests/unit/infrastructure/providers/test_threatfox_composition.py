# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ThreatFox-specific provider composition tests.

Covers bootstrap Auth-Key resolution, settings wiring, and the rollback
behavior of the composition root when the ThreatFox credential is missing
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

# The composition scaffolding intentionally mirrors
# test_abuseipdb_composition.py so each provider's wiring, secret
# resolution, and rollback tests stay symmetrical; the duplication is
# test-only and deliberately accepted.

_THREATFOX_KEY_SECRET_NAME = "ATI_THREATFOX_AUTH_KEY"
_FAKE_KEY = "fake-test-threatfox-key"
_FAKE_TOKEN = "fake-test-token"
_FAKE_ABUSEIPDB_KEY = "fake-test-abuseipdb-key"


class _KeyringResolver(SecretsResolver):
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


class _SequentialFactory(HttpClientFactory):
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


async def test_composition_wires_threatfox_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Composition applies exact settings and a dedicated limiter to ThreatFox."""
    seen: list[RateLimiterSettings] = []

    class _RecordingLimiter(BoundedLimiter):
        """Spy recording the exact limiter settings ThreatFox receives."""

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
            "threatfox_max_concurrency": 5,
            "threatfox_requests_per_second": 3.0,
            "threatfox_auth_key_secret": "CUSTOM_THREATFOX_VAR",
        }
    )

    async with await ProviderComposition.create(
        settings,
        secrets=_KeyringResolver(
            ATI_IPINFO_LITE_TOKEN=_FAKE_TOKEN,
            ATI_ABUSEIPDB_API_KEY=_FAKE_ABUSEIPDB_KEY,
            CUSTOM_THREATFOX_VAR=_FAKE_KEY,
            ATI_URLHAUS_AUTH_KEY="fake-test-urlhaus-key",
        ),
    ) as comp:
        # ThreatFox is composed after Google DNS, RDAP, IPinfo, and
        # AbuseIPDB, so its limiter is the fifth created.
        assert seen[4] == RateLimiterSettings(
            max_concurrency=5, requests_per_second=3.0
        )
        assert comp.threatfox.supports(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert comp.threatfox.supports(
            Entity(type=EntityType.IP_ADDRESS, value="192.0.2.39")
        )
        assert not comp.threatfox.supports(
            Entity(type=EntityType.URL, value="https://example.com/")
        )
        assert comp.threatfox.id == "urn:ati:source:threatfox"

        # White-box assertion proving bootstrap resolution and settings
        # wiring; the value is a fake test credential only.
        assert comp.threatfox._auth_key == _FAKE_KEY


@pytest.mark.parametrize("blank_key", ["", "   ", "\t"])
async def test_composition_blank_threatfox_key_fails_before_client_creation(
    blank_key: str,
) -> None:
    """Empty, whitespace, and tab key values fail before the ThreatFox client."""
    closed: list[str] = []
    factory = _SequentialFactory(closed)
    with pytest.raises(SecretNotFoundError) as excinfo:
        await ProviderComposition.create(
            settings_from_config({}),
            http_client_factory=factory,
            secrets=_KeyringResolver(
                ATI_IPINFO_LITE_TOKEN=_FAKE_TOKEN,
                ATI_ABUSEIPDB_API_KEY=_FAKE_ABUSEIPDB_KEY,
                ATI_THREATFOX_AUTH_KEY=blank_key,
            ),
        )

    # Google DNS, RDAP, IPinfo, and AbuseIPDB clients were created and
    # rolled back in LIFO unwind order; no ThreatFox factory call occurred.
    assert factory.created == 4
    assert closed == ["client-4", "client-3", "client-2", "client-1"]

    # The raised error carries only the configured reference name; the
    # blank resolved value never appears in it.
    assert (
        str(excinfo.value) == f"required secret not found: {_THREATFOX_KEY_SECRET_NAME}"
    )


async def test_composition_missing_threatfox_key_fails_before_client_creation() -> None:
    """A missing ThreatFox key fails clearly and rolls back created clients."""
    closed: list[str] = []
    factory = _SequentialFactory(closed)
    with pytest.raises(SecretNotFoundError) as excinfo:
        await ProviderComposition.create(
            settings_from_config({}),
            http_client_factory=factory,
            secrets=_KeyringResolver(
                ATI_IPINFO_LITE_TOKEN=_FAKE_TOKEN,
                ATI_ABUSEIPDB_API_KEY=_FAKE_ABUSEIPDB_KEY,
            ),
        )

    assert factory.created == 4
    assert closed == ["client-4", "client-3", "client-2", "client-1"]
    assert (
        str(excinfo.value) == f"required secret not found: {_THREATFOX_KEY_SECRET_NAME}"
    )
