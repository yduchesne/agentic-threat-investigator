# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""URLhaus-specific provider composition tests.

# The provider/test modules deliberately mirror the established
# provider-family shapes (see ThreatFox/AbuseIPDB); per-block R0801
# suppression is not supported by Pylint, so duplicate-code is
# disabled at module scope for the deliberately accepted duplication.
# pylint: disable=duplicate-code

Covers bootstrap Auth-Key resolution, settings wiring, and the rollback
behavior of the composition root when the URLhaus credential is missing
or blank. The scaffolding mirrors ``test_threatfox_composition.py``; the
duplication is test-only and deliberately accepted.
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

_URLHAUS_KEY_SECRET_NAME = "ATI_URLHAUS_AUTH_KEY"
_FAKE_URLHAUS_KEY = "fake-test-urlhaus-key"


class _KeyringResolver(SecretsResolver):  # pylint: disable=too-few-public-methods
    """Deterministic resolver returning credential values from a keyring."""

    def __init__(self, **values: str) -> None:
        """Initialize with reference-name/value keyword pairs."""
        self._values = values

    def get(self, name: str) -> str | None:
        """Return the keyring value for a reference name."""
        return self._values.get(name)


def _full_resolver(**overrides: str) -> _KeyringResolver:
    """Build a resolver carrying every required credential."""
    values: dict[str, str] = {
        "ATI_IPINFO_LITE_TOKEN": "fake-test-token",
        "ATI_ABUSEIPDB_API_KEY": "fake-test-abuseipdb-key",
        "ATI_THREATFOX_AUTH_KEY": "fake-test-threatfox-key",
        _URLHAUS_KEY_SECRET_NAME: _FAKE_URLHAUS_KEY,
    }
    values.update(overrides)
    return _KeyringResolver(**values)


async def test_composition_wires_urlhaus_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Composition applies exact settings and a dedicated limiter to URLhaus."""
    seen: list[RateLimiterSettings] = []

    class _RecordingLimiter(BoundedLimiter):
        """Spy recording the exact limiter settings URLhaus receives."""

        def __init__(self, limiter_settings: RateLimiterSettings) -> None:
            self.settings_seen = limiter_settings
            seen.append(limiter_settings)
            super().__init__(limiter_settings)

    composition_module_path = (
        "agentic_threat_investigator.infrastructure.providers.composition"
    )
    monkeypatch.setattr(f"{composition_module_path}.BoundedLimiter", _RecordingLimiter)
    settings = settings_from_config(
        {
            "urlhaus_max_concurrency": 6,
            "urlhaus_requests_per_second": 4.0,
            "urlhaus_auth_key_secret": "CUSTOM_URLHAUS_VAR",
        }
    )

    async with await ProviderComposition.create(
        settings, secrets=_full_resolver(CUSTOM_URLHAUS_VAR=_FAKE_URLHAUS_KEY)
    ) as comp:
        # URLhaus is composed after Google DNS, RDAP, IPinfo, AbuseIPDB,
        # and ThreatFox, so its limiter is the sixth created.
        assert seen[5] == RateLimiterSettings(
            max_concurrency=6, requests_per_second=4.0
        )
        assert comp.urlhaus.supports(
            Entity(type=EntityType.URL, value="https://example.com/")
        )
        assert comp.urlhaus.supports(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert comp.urlhaus.id == "urn:ati:source:urlhaus"

        # White-box assertion proving bootstrap resolution and settings
        # wiring; the value is a fake test credential only.
        # pylint: disable=protected-access
        assert comp.urlhaus._auth_key == _FAKE_URLHAUS_KEY
        # pylint: enable=protected-access


class _ProbeClient(ProviderHttpClient):
    """Client recording its close order into a shared rollback log."""

    def __init__(self, number: int, log: list[str]) -> None:
        self._number, self._log = number, log
        super().__init__()

    async def aclose(self) -> None:
        self._log.append(f"client-{self._number}")
        await super().aclose()


class _RollbackProbeFactory(
    HttpClientFactory
):  # pylint: disable=too-few-public-methods
    """Factory whose numbered clients feed a shared rollback log."""

    def __init__(self, log: list[str]) -> None:
        self._log = log
        self.created_count = 0

    def create(
        self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
    ) -> ProviderHttpClient:
        self.created_count += 1
        return _ProbeClient(self.created_count, self._log)


def _expect_five_client_rollback(log: list[str]) -> None:
    """Assert the five earlier clients rolled back in LIFO unwind order."""
    assert log == [f"client-{n}" for n in range(5, 0, -1)]


@pytest.mark.parametrize("blank_key", ["", "   ", "\t"])
async def test_composition_blank_urlhaus_key_fails_before_client_creation(
    blank_key: str,
) -> None:
    """Empty, whitespace, and tab key values fail before the URLhaus client."""
    closed: list[str] = []
    factory = _RollbackProbeFactory(closed)

    with pytest.raises(SecretNotFoundError) as excinfo:
        await ProviderComposition.create(
            settings_from_config({}),
            http_client_factory=factory,
            secrets=_full_resolver(ATI_URLHAUS_AUTH_KEY=blank_key),
        )

    # Google DNS, RDAP, IPinfo, AbuseIPDB, and ThreatFox clients were
    # created and rolled back; no URLhaus factory call occurred.
    assert factory.created_count == 5
    _expect_five_client_rollback(closed)
    # The raised error carries only the configured reference name; the
    # blank resolved value never appears in it.
    assert (
        str(excinfo.value) == f"required secret not found: {_URLHAUS_KEY_SECRET_NAME}"
    )


async def test_composition_missing_urlhaus_key_fails_before_client_creation() -> None:
    """A missing URLhaus key fails clearly and rolls back created clients."""
    closed: list[str] = []
    factory = _RollbackProbeFactory(closed)

    resolver = _full_resolver()
    del resolver._values[_URLHAUS_KEY_SECRET_NAME]  # pylint: disable=protected-access
    with pytest.raises(SecretNotFoundError) as excinfo:
        await ProviderComposition.create(
            settings_from_config({}),
            http_client_factory=factory,
            secrets=resolver,
        )

    assert factory.created_count == 5
    _expect_five_client_rollback(closed)
    assert (
        str(excinfo.value) == f"required secret not found: {_URLHAUS_KEY_SECRET_NAME}"
    )
