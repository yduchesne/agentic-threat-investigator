# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for settings-driven provider composition.

This module intentionally exceeds the default line-count bound: each live
provider's wiring, secret resolution, rollback, and close semantics are
covered in dedicated deterministic tests within one composition suite.
"""

from __future__ import annotations

import asyncio
import pathlib
import uuid
from contextlib import AsyncExitStack

import pytest

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.app.secrets import SecretNotFoundError, SecretsResolver
from agentic_threat_investigator.config import settings_from_config
from agentic_threat_investigator.config.settings import Settings
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.object_store import (
    ArtifactNotFoundError,
    FileSystemObjectStore,
)
from agentic_threat_investigator.infrastructure.providers import (
    composition as composition_module,
)
from agentic_threat_investigator.infrastructure.providers.composition import (
    HttpClientFactory,
    ProviderComposition,
)
from agentic_threat_investigator.infrastructure.providers.dbip_city_lite import (
    CityLiteDatabase,
    DbIpCityLiteProvider,
    MmdbLookupError,
    MmdbOpenError,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpClient,
    ProviderHttpPolicy,
    RateLimiterSettings,
)
from tests.support.mmdb import (
    build_synthetic_city_lite_mmdb,
    build_wrong_product_city_lite_mmdb,
)

pytestmark = pytest.mark.asyncio

_FAKE_TOKEN_SECRET_NAME = "ATI_IPINFO_LITE_TOKEN"
_FAKE_TOKEN = "fake-test-token"
_FAKE_ABUSEIPDB_KEY_SECRET_NAME = "ATI_ABUSEIPDB_API_KEY"
_FAKE_ABUSEIPDB_KEY = "fake-test-abuseipdb-key"
_FAKE_THREATFOX_KEY_SECRET_NAME = "ATI_THREATFOX_AUTH_KEY"
_FAKE_THREATFOX_KEY = "fake-test-threatfox-key"
_FAKE_URLHAUS_KEY_SECRET_NAME = "ATI_URLHAUS_AUTH_KEY"
_FAKE_URLHAUS_KEY = "fake-test-urlhaus-key"


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
            _FAKE_TOKEN_SECRET_NAME: _FAKE_TOKEN,
            _FAKE_ABUSEIPDB_KEY_SECRET_NAME: _FAKE_ABUSEIPDB_KEY,
            _FAKE_THREATFOX_KEY_SECRET_NAME: _FAKE_THREATFOX_KEY,
            _FAKE_URLHAUS_KEY_SECRET_NAME: _FAKE_URLHAUS_KEY,
        }
    )


class _SpyHttpClientFactory(HttpClientFactory):
    """Deterministic factory capturing construction arguments."""

    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.calls: list[tuple[ProviderHttpPolicy, BoundedLimiter]] = []
        self.fail_on_call = fail_on_call

    def create(
        self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
    ) -> ProviderHttpClient:
        """Capture arguments, optionally failing, and construct a real client."""
        self.calls.append((policy, limiter))
        if self.fail_on_call is not None and len(self.calls) >= self.fail_on_call:
            raise RuntimeError("simulated factory construction failure")
        return ProviderHttpClient(policy=policy, limiter=limiter)


async def test_composition_wires_google_dns_settings() -> None:
    """Composition applies exact settings and separate limiters to Google DNS."""
    factory = _SpyHttpClientFactory()
    settings = settings_from_config(
        {
            "provider_timeout_seconds": 25.0,
            "provider_max_retries": 4,
            "provider_retry_base_delay_seconds": 2.5,
            "provider_retry_max_delay_seconds": 45.0,
            "provider_retry_jitter_ratio": 0.25,
            "provider_max_response_bytes": 5_000_000,
            "google_dns_max_concurrency": 7,
            "google_dns_requests_per_second": 35.0,
        }
    )

    async with await ProviderComposition.create(
        settings, http_client_factory=factory, secrets=_fake_secrets()
    ) as comp:
        assert len(factory.calls) == 6
        google_policy, google_limiter = factory.calls[0]
        assert google_policy.timeout_seconds == 25.0
        assert google_policy.max_retries == 4
        assert google_policy.base_delay_seconds == 2.5
        assert google_policy.max_delay_seconds == 45.0
        assert google_policy.jitter_ratio == 0.25
        assert google_policy.max_response_bytes == 5_000_000
        assert isinstance(google_limiter, BoundedLimiter)

        # Both providers must receive distinct limiter instances
        _, rdap_limiter = factory.calls[1]
        assert google_limiter is not rdap_limiter

        assert comp.google_dns.supports(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert not comp.rdap.supports(
            Entity(type=EntityType.URL, value="https://example.com")
        )


async def test_composition_wires_rdap_settings() -> None:
    """Composition applies exact settings and cache duration to RDAP."""
    factory = _SpyHttpClientFactory()
    settings = settings_from_config(
        {
            "provider_timeout_seconds": 12.0,
            "rdap_max_concurrency": 3,
            "rdap_requests_per_second": 15.0,
            "rdap_bootstrap_cache_seconds": 7200,
        }
    )

    async with await ProviderComposition.create(
        settings, http_client_factory=factory, secrets=_fake_secrets()
    ) as comp:
        rdap_policy, rdap_limiter = factory.calls[1]
        assert rdap_policy.timeout_seconds == 12.0
        assert isinstance(rdap_limiter, BoundedLimiter)
        assert comp.rdap.supports(Entity(type=EntityType.DOMAIN, value="example.com"))


async def test_composition_closes_both_clients_on_individual_failure() -> None:
    """Closing continues to the second client even if the first client raises."""
    closed: list[str] = []

    class _FailingClient(ProviderHttpClient):
        def __init__(self, name: str) -> None:
            self._name = name
            super().__init__()

        async def aclose(self) -> None:
            closed.append(self._name)
            if self._name == "first":
                raise RuntimeError("simulated client aclose failure")

    clients = [
        _FailingClient("first"),
        _FailingClient("second"),
        _FailingClient("third"),
        _FailingClient("fourth"),
        _FailingClient("fifth"),
        _FailingClient("sixth"),
    ]

    class _CannedFactory(HttpClientFactory):
        def create(
            self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
        ) -> ProviderHttpClient:
            return clients.pop(0)

    settings = settings_from_config({})
    comp = await ProviderComposition.create(
        settings, http_client_factory=_CannedFactory(), secrets=_fake_secrets()
    )

    with pytest.raises(RuntimeError, match="simulated client aclose failure"):
        await comp.aclose()

    assert closed == ["first", "second", "third", "fourth", "fifth", "sixth"]


async def test_composition_rolls_back_on_partial_construction_failure() -> None:
    """A factory failure during RDAP construction closes the Google client."""
    closed: list[str] = []

    class _TrackingClient(ProviderHttpClient):
        def __init__(self, name: str) -> None:
            self._name = name
            super().__init__()

        async def aclose(self) -> None:
            closed.append(self._name)
            await super().aclose()

    class _FailOnSecondFactory(HttpClientFactory):
        def __init__(self) -> None:
            self.call_count = 0

        def create(
            self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
        ) -> ProviderHttpClient:
            self.call_count += 1
            if self.call_count == 2:
                raise RuntimeError("rdap construction failed")
            return _TrackingClient(f"client-{self.call_count}")

    settings = settings_from_config({})
    with pytest.raises(RuntimeError, match="rdap construction failed"):
        await ProviderComposition.create(
            settings,
            http_client_factory=_FailOnSecondFactory(),
            secrets=_fake_secrets(),
        )

    assert closed == ["client-1"]


async def test_composition_aclose_cancellation_closes_remaining_client() -> None:
    """A cancelled first aclose still closes the second client, then propagates."""

    class _CancellingClient(ProviderHttpClient):
        def __init__(self, name: str) -> None:
            self._name = name
            super().__init__()

        async def aclose(self) -> None:
            if self._name == "first":
                raise asyncio.CancelledError()
            raise AssertionError("second client must still be closed")

    class _OrderTrackingClient(ProviderHttpClient):
        def __init__(self, name: str) -> None:
            self._name = name
            super().__init__()

        async def aclose(self) -> None:
            closed.append(self._name)
            await super().aclose()

    closed: list[str] = []
    clients: list[ProviderHttpClient] = [
        _CancellingClient("first"),
        _OrderTrackingClient("second"),
        _OrderTrackingClient("third"),
        _OrderTrackingClient("fourth"),
        _OrderTrackingClient("fifth"),
        _OrderTrackingClient("sixth"),
    ]

    class _CannedFactory(HttpClientFactory):
        def create(
            self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
        ) -> ProviderHttpClient:
            return clients.pop(0)

    settings = settings_from_config({})
    comp = await ProviderComposition.create(
        settings, http_client_factory=_CannedFactory(), secrets=_fake_secrets()
    )

    with pytest.raises(asyncio.CancelledError):
        await comp.aclose()

    assert closed == ["second", "third", "fourth", "fifth", "sixth"]


async def test_composition_properties_require_create() -> None:
    """Accessing providers before create() raises an explicit runtime error."""
    comp = ProviderComposition()
    with pytest.raises(RuntimeError, match="create"):
        _ = comp.google_dns
    with pytest.raises(RuntimeError, match="create"):
        _ = comp.rdap
    with pytest.raises(RuntimeError, match="create"):
        _ = comp.ipinfo_lite
    with pytest.raises(RuntimeError, match="create"):
        _ = comp.abuseipdb
    with pytest.raises(RuntimeError, match="create"):
        _ = comp.threatfox
        _ = comp.urlhaus
    with pytest.raises(RuntimeError, match="create"):
        _ = comp.urlhaus


async def test_composition_wires_ipinfo_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Composition applies exact settings and a dedicated limiter to IPinfo."""
    factory = _SpyHttpClientFactory()
    settings = settings_from_config(
        {
            "ipinfo_lite_max_concurrency": 4,
            "ipinfo_lite_requests_per_second": 12.0,
            "ipinfo_lite_token_secret": "CUSTOM_TOKEN_VAR",
        }
    )

    seen_settings: list[RateLimiterSettings] = []

    class _RecordingBoundedLimiter(BoundedLimiter):
        """Spy recording the exact limiter settings each provider receives."""

        def __init__(self, limiter_settings: RateLimiterSettings) -> None:
            seen_settings.append(limiter_settings)
            super().__init__(limiter_settings)

    monkeypatch.setattr(composition_module, "BoundedLimiter", _RecordingBoundedLimiter)

    async with await ProviderComposition.create(
        settings,
        http_client_factory=factory,
        secrets=_StaticSecretsResolver(
            {
                "CUSTOM_TOKEN_VAR": _FAKE_TOKEN,
                _FAKE_ABUSEIPDB_KEY_SECRET_NAME: _FAKE_ABUSEIPDB_KEY,
                _FAKE_THREATFOX_KEY_SECRET_NAME: _FAKE_THREATFOX_KEY,
                _FAKE_URLHAUS_KEY_SECRET_NAME: _FAKE_URLHAUS_KEY,
            }
        ),
    ) as comp:
        assert len(factory.calls) == 6
        _, ipinfo_limiter = factory.calls[2]
        assert isinstance(ipinfo_limiter, BoundedLimiter)
        # All providers must receive distinct limiter instances.
        google_limiter = factory.calls[0][1]
        rdap_limiter = factory.calls[1][1]
        abuseipdb_limiter = factory.calls[3][1]
        threatfox_limiter = factory.calls[4][1]
        urlhaus_limiter = factory.calls[5][1]
        assert (
            len(
                {
                    id(google_limiter),
                    id(rdap_limiter),
                    id(ipinfo_limiter),
                    id(abuseipdb_limiter),
                    id(threatfox_limiter),
                    id(urlhaus_limiter),
                }
            )
            == 6
        )

        # The exact configured values reached each provider's limiter.
        assert seen_settings[0] == RateLimiterSettings(
            max_concurrency=10, requests_per_second=None
        )
        assert seen_settings[1] == RateLimiterSettings(
            max_concurrency=10, requests_per_second=None
        )
        assert seen_settings[2] == RateLimiterSettings(
            max_concurrency=4, requests_per_second=12.0
        )

        assert comp.ipinfo_lite.supports(
            Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
        )
        assert not comp.ipinfo_lite.supports(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )


async def test_composition_passes_resolved_token_to_provider() -> None:
    """The token resolved by the secrets resolver reaches the provider."""
    factory = _SpyHttpClientFactory()
    settings = settings_from_config({})
    resolver = _StaticSecretsResolver(
        {
            _FAKE_TOKEN_SECRET_NAME: _FAKE_TOKEN,
            _FAKE_ABUSEIPDB_KEY_SECRET_NAME: _FAKE_ABUSEIPDB_KEY,
            _FAKE_THREATFOX_KEY_SECRET_NAME: _FAKE_THREATFOX_KEY,
            _FAKE_URLHAUS_KEY_SECRET_NAME: _FAKE_URLHAUS_KEY,
        }
    )

    async with await ProviderComposition.create(
        settings, http_client_factory=factory, secrets=resolver
    ) as comp:
        # White-box assertion proving bootstrap resolution wired the resolved
        # credential into the provider; the value is a fake test token only.
        resolved = comp.ipinfo_lite._token
        assert resolved == _FAKE_TOKEN


async def test_composition_resolves_token_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default environment resolver supplies the configured reference."""
    monkeypatch.setenv(_FAKE_TOKEN_SECRET_NAME, _FAKE_TOKEN)
    monkeypatch.setenv(_FAKE_ABUSEIPDB_KEY_SECRET_NAME, _FAKE_ABUSEIPDB_KEY)
    monkeypatch.setenv(_FAKE_THREATFOX_KEY_SECRET_NAME, _FAKE_THREATFOX_KEY)
    monkeypatch.setenv(_FAKE_URLHAUS_KEY_SECRET_NAME, _FAKE_URLHAUS_KEY)
    factory = _SpyHttpClientFactory()
    settings = settings_from_config({})

    async with await ProviderComposition.create(
        settings, http_client_factory=factory
    ) as comp:
        resolved = comp.ipinfo_lite._token
        assert resolved == _FAKE_TOKEN


async def test_composition_missing_required_token_fails_before_client_creation() -> (
    None
):
    """A missing required secret fails clearly and rolls back created clients."""
    closed: list[str] = []

    class _TrackingClient(ProviderHttpClient):
        def __init__(self, name: str) -> None:
            self._name = name
            super().__init__()

        async def aclose(self) -> None:
            closed.append(self._name)
            await super().aclose()

    class _FailOnThirdFactory(HttpClientFactory):
        def __init__(self) -> None:
            self.call_count = 0

        def create(
            self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
        ) -> ProviderHttpClient:
            self.call_count += 1
            if self.call_count == 3:
                raise RuntimeError("should never be reached without the token")
            return _TrackingClient(f"client-{self.call_count}")

    settings = settings_from_config({})
    with pytest.raises(SecretNotFoundError, match=_FAKE_TOKEN_SECRET_NAME):
        await ProviderComposition.create(
            settings, http_client_factory=_FailOnThirdFactory()
        )

    # The token is resolved before the IPinfo client is created, so both
    # already-created owned clients roll back (LIFO unwind order) and no
    # third client exists.
    assert closed == ["client-2", "client-1"]


@pytest.mark.parametrize("blank_token", ["", "   "])
async def test_composition_blank_token_fails_before_client_creation(
    blank_token: str,
) -> None:
    """Empty and whitespace-only token values fail before the IPinfo client."""
    closed: list[str] = []

    class _TrackingClient(ProviderHttpClient):
        def __init__(self, name: str) -> None:
            self._name = name
            super().__init__()

        async def aclose(self) -> None:
            closed.append(self._name)
            await super().aclose()

    class _CountingFactory(HttpClientFactory):
        def __init__(self) -> None:
            self.call_count = 0

        def create(
            self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
        ) -> ProviderHttpClient:
            self.call_count += 1
            return _TrackingClient(f"client-{self.call_count}")

    settings = settings_from_config({})
    factory = _CountingFactory()
    with pytest.raises(SecretNotFoundError) as excinfo:
        await ProviderComposition.create(
            settings,
            http_client_factory=factory,
            secrets=_StaticSecretsResolver({_FAKE_TOKEN_SECRET_NAME: blank_token}),
        )

    # Only Google DNS and RDAP clients were created (no third factory call);
    # the two earlier clients rolled back in LIFO unwind order.
    assert factory.call_count == 2
    assert closed == ["client-2", "client-1"]

    # The raised error is exactly the reference-name message: the blank
    # value never appears in it.
    assert str(excinfo.value) == f"required secret not found: {_FAKE_TOKEN_SECRET_NAME}"


async def test_composition_later_failure_closes_ipinfo_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure after IPinfo client creation closes the IPinfo client too."""
    closed: list[str] = []

    class _TrackingClient(ProviderHttpClient):
        def __init__(self, name: str) -> None:
            self._name = name
            super().__init__()

        async def aclose(self) -> None:
            closed.append(self._name)
            await super().aclose()

    class _PassThroughFactory(HttpClientFactory):
        def __init__(self) -> None:
            self.call_count = 0

        def create(
            self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
        ) -> ProviderHttpClient:
            self.call_count += 1
            return _TrackingClient(f"client-{self.call_count}")

    def _failing_provider_construction(*args: object, **kwargs: object) -> None:
        raise RuntimeError("later construction failed")

    monkeypatch.setattr(
        composition_module,
        "IpinfoLiteProvider",
        _failing_provider_construction,
    )

    settings = settings_from_config({})
    with pytest.raises(RuntimeError, match="later construction failed"):
        await ProviderComposition.create(
            settings, http_client_factory=_PassThroughFactory(), secrets=_fake_secrets()
        )

    # All three created clients roll back, in LIFO unwind order.
    assert closed == ["client-3", "client-2", "client-1"]


async def test_composition_normal_close_closes_all_clients_once() -> None:
    """A successful composition close closes each owned client exactly once."""
    closed: list[str] = []

    class _TrackingClient(ProviderHttpClient):
        def __init__(self, name: str) -> None:
            self._name = name
            super().__init__()

        async def aclose(self) -> None:
            closed.append(self._name)
            await super().aclose()

    class _TrackingFactory(HttpClientFactory):
        def __init__(self) -> None:
            self.call_count = 0

        def create(
            self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
        ) -> ProviderHttpClient:
            self.call_count += 1
            return _TrackingClient(f"client-{self.call_count}")

    settings = settings_from_config({})
    async with await ProviderComposition.create(
        settings, http_client_factory=_TrackingFactory(), secrets=_fake_secrets()
    ) as comp:
        _ = comp.google_dns
        _ = comp.rdap
        _ = comp.ipinfo_lite
        _ = comp.abuseipdb
        _ = comp.threatfox
        _ = comp.urlhaus

    # The normal context exit closed Google DNS, RDAP, IPinfo, AbuseIPDB,
    # and ThreatFox clients, each exactly once, in creation order.
    assert closed == [
        "client-1",
        "client-2",
        "client-3",
        "client-4",
        "client-5",
        "client-6",
    ]


class TestDbIpCityLiteComposition:
    """Composition lifecycle for the local DB-IP City Lite provider."""

    @staticmethod
    def _artifact_settings(tmp_path: pathlib.Path) -> dict[str, object]:
        """Build settings pointing at a synthetic artifact below tmp datasets."""
        return {
            "data_dir": str(tmp_path),
            "dbip_city_lite_artifact_uri": (
                f"file://{tmp_path}/datasets/dbip-city-lite/city-lite.mmdb"
            ),
        }

    async def test_disabled_by_default(self) -> None:
        """Without a configured artifact URI the DB-IP provider is None."""
        async with await ProviderComposition.create(
            settings_from_config({}),
            http_client_factory=_SpyHttpClientFactory(),
            secrets=_fake_secrets(),
        ) as comp:
            assert comp.dbip_city_lite is None

    async def test_composed_with_present_artifact(self, tmp_path: pathlib.Path) -> None:
        """A present readable artifact composes a working local provider."""
        store = FileSystemObjectStore(pathlib.Path(tmp_path) / "datasets")
        await store.write(
            f"file://{tmp_path}/datasets/dbip-city-lite/city-lite.mmdb",
            build_synthetic_city_lite_mmdb(),
        )
        async with await ProviderComposition.create(
            settings_from_config(self._artifact_settings(tmp_path)),
            http_client_factory=_SpyHttpClientFactory(),
            secrets=_fake_secrets(),
        ) as comp:
            assert comp.dbip_city_lite is not None
            result = await comp.dbip_city_lite.investigate(
                uuid.UUID(int=1), Entity(type=EntityType.IP_ADDRESS, value="192.0.2.10")
            )
            assert result.errors == ()
            assert len(result.evidence) == 1

    async def test_missing_artifact_fails_composition(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A configured but absent artifact fails composition clearly."""
        with pytest.raises(ArtifactNotFoundError):
            await ProviderComposition.create(
                settings_from_config(self._artifact_settings(tmp_path)),
                http_client_factory=_SpyHttpClientFactory(),
                secrets=_fake_secrets(),
            )

    async def test_corrupt_artifact_fails_composition(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A corrupt artifact cannot be opened and fails composition."""
        store = FileSystemObjectStore(pathlib.Path(tmp_path) / "datasets")
        await store.write(
            f"file://{tmp_path}/datasets/dbip-city-lite/city-lite.mmdb",
            b"not an mmdb database at all",
        )
        with pytest.raises(MmdbOpenError):
            await ProviderComposition.create(
                settings_from_config(self._artifact_settings(tmp_path)),
                http_client_factory=_SpyHttpClientFactory(),
                secrets=_fake_secrets(),
            )

    async def test_aclose_closes_local_reader(self, tmp_path: pathlib.Path) -> None:
        """Composition teardown closes the owned local MMDB reader."""
        store = FileSystemObjectStore(pathlib.Path(tmp_path) / "datasets")
        await store.write(
            f"file://{tmp_path}/datasets/dbip-city-lite/city-lite.mmdb",
            build_synthetic_city_lite_mmdb(),
        )
        comp = await ProviderComposition.create(
            settings_from_config(self._artifact_settings(tmp_path)),
            http_client_factory=_SpyHttpClientFactory(),
            secrets=_fake_secrets(),
        )
        assert comp.dbip_city_lite is not None
        await comp.aclose()
        # The reader is closed: lookups now map to a typed unavailable error.
        result = await comp.dbip_city_lite.investigate(
            uuid.UUID(int=1), Entity(type=EntityType.IP_ADDRESS, value="192.0.2.10")
        )
        assert result.evidence == ()
        assert result.errors[0].code is ProviderErrorCode.PROVIDER_UNAVAILABLE

    async def test_partial_failure_closes_created_clients(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A DB-IP artifact failure rolls back all created HTTP clients."""
        closed: list[str] = []

        class _TrackingClient(ProviderHttpClient):
            def __init__(self, name: str) -> None:
                self._name = name
                super().__init__()

            async def aclose(self) -> None:
                closed.append(self._name)
                await super().aclose()

        class _PassThroughFactory(HttpClientFactory):
            def __init__(self) -> None:
                self.call_count = 0

            def create(
                self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
            ) -> ProviderHttpClient:
                self.call_count += 1
                return _TrackingClient(f"client-{self.call_count}")

        with pytest.raises(ArtifactNotFoundError):
            await ProviderComposition.create(
                settings_from_config(self._artifact_settings(tmp_path)),
                http_client_factory=_PassThroughFactory(),
                secrets=_fake_secrets(),
            )
        # All five already-created clients roll back, in LIFO unwind order.
        assert closed == [
            "client-6",
            "client-5",
            "client-4",
            "client-3",
            "client-2",
            "client-1",
        ]

    async def test_artifact_outside_datasets_root_rejected(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A valid file:// URI outside the datasets root fails the boundary."""
        outside = tmp_path / "outside"
        (outside / "dbip-city-lite").mkdir(parents=True)
        artifact = outside / "dbip-city-lite" / "city-lite.mmdb"
        artifact.write_bytes(build_synthetic_city_lite_mmdb())
        settings = settings_from_config(
            {
                "data_dir": str(tmp_path),
                "dbip_city_lite_artifact_uri": f"file://{artifact}",
            }
        )
        with pytest.raises(ValueError, match="escapes the datasets root"):
            await ProviderComposition.create(
                settings,
                http_client_factory=_SpyHttpClientFactory(),
                secrets=_fake_secrets(),
            )

    async def test_wrong_product_artifact_fails_composition(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A valid MMDB of a different product edition fails composition."""
        store = FileSystemObjectStore(pathlib.Path(tmp_path) / "datasets")
        await store.write(
            f"file://{tmp_path}/datasets/dbip-city-lite/city-lite.mmdb",
            build_wrong_product_city_lite_mmdb(),
        )
        with pytest.raises(MmdbOpenError, match="product type"):
            await ProviderComposition.create(
                settings_from_config(self._artifact_settings(tmp_path)),
                http_client_factory=_SpyHttpClientFactory(),
                secrets=_fake_secrets(),
            )

    async def test_later_provider_failure_closes_database_once(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pathlib.Path,
    ) -> None:
        """Provider construction failure closes the opened database exactly once."""
        store = FileSystemObjectStore(pathlib.Path(tmp_path) / "datasets")
        await store.write(
            f"file://{tmp_path}/datasets/dbip-city-lite/city-lite.mmdb",
            build_synthetic_city_lite_mmdb(),
        )
        captured: list[CityLiteDatabase] = []
        closed: list[str] = []

        class _TrackingClient(ProviderHttpClient):
            def __init__(self, name: str) -> None:
                self._name = name
                super().__init__()

            async def aclose(self) -> None:
                closed.append(self._name)
                await super().aclose()

        class _PassThroughFactory(HttpClientFactory):
            def __init__(self) -> None:
                self.call_count = 0

            def create(
                self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
            ) -> ProviderHttpClient:
                self.call_count += 1
                return _TrackingClient(f"client-{self.call_count}")

        def _failing_construction(database: CityLiteDatabase) -> None:
            captured.append(database)
            raise RuntimeError("provider construction failed")

        monkeypatch.setattr(
            composition_module, "DbIpCityLiteProvider", _failing_construction
        )

        with pytest.raises(RuntimeError, match="provider construction failed"):
            await ProviderComposition.create(
                settings_from_config(self._artifact_settings(tmp_path)),
                http_client_factory=_PassThroughFactory(),
                secrets=_fake_secrets(),
            )

        assert len(captured) == 1
        # The opened reader rolled back with construction: lookups now fail.
        with pytest.raises(MmdbLookupError):
            captured[0].lookup("192.0.2.10")
        # All five created HTTP clients still unwind in LIFO order.
        assert closed == [
            "client-6",
            "client-5",
            "client-4",
            "client-3",
            "client-2",
            "client-1",
        ]

    async def test_database_close_failure_still_closes_clients(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pathlib.Path,
    ) -> None:
        """A database close error is re-raised after all clients close."""

        class _BrokenCloseDatabase(CityLiteDatabase):
            """Database stub whose close always fails exactly once per call."""

            def __init__(self) -> None:
                self.close_attempts = 0

            def lookup(self, ip: str) -> None:
                """Never called in this test."""
                return

            def close(self) -> None:
                """Record the attempt and fail."""
                self.close_attempts += 1
                raise RuntimeError("database close boom")

        broken = _BrokenCloseDatabase()

        async def _fake_compose(
            _settings: Settings, _stack: AsyncExitStack
        ) -> tuple[DbIpCityLiteProvider, CityLiteDatabase]:
            _stack.callback(broken.close)
            return DbIpCityLiteProvider(broken), broken

        monkeypatch.setattr(
            composition_module, "_compose_dbip_city_lite", _fake_compose
        )
        closed: list[str] = []

        class _TrackingClient(ProviderHttpClient):
            def __init__(self, name: str) -> None:
                self._name = name
                super().__init__()

            async def aclose(self) -> None:
                closed.append(self._name)
                await super().aclose()

        class _PassThroughFactory(HttpClientFactory):
            def __init__(self) -> None:
                self.call_count = 0

            def create(
                self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
            ) -> ProviderHttpClient:
                self.call_count += 1
                return _TrackingClient(f"client-{self.call_count}")

        comp = await ProviderComposition.create(
            settings_from_config(self._artifact_settings(tmp_path)),
            http_client_factory=_PassThroughFactory(),
            secrets=_fake_secrets(),
        )
        with pytest.raises(RuntimeError, match="database close boom"):
            await comp.aclose()
        assert broken.close_attempts == 1
        assert closed == [
            "client-1",
            "client-2",
            "client-3",
            "client-4",
            "client-5",
            "client-6",
        ]

    async def test_first_close_failure_re_raised_after_full_cleanup(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pathlib.Path,
    ) -> None:
        """Every resource is attempted and the first failure is re-raised."""

        class _BrokenCloseDatabase(CityLiteDatabase):
            """Database stub whose close fails."""

            def __init__(self) -> None:
                self.close_attempts = 0

            def lookup(self, ip: str) -> None:
                """Never called in this test."""
                return

            def close(self) -> None:
                """Record the attempt and fail."""
                self.close_attempts += 1
                raise RuntimeError("database close boom")

        broken = _BrokenCloseDatabase()

        async def _fake_compose(
            _settings: Settings, _stack: AsyncExitStack
        ) -> tuple[DbIpCityLiteProvider, CityLiteDatabase]:
            _stack.callback(broken.close)
            return DbIpCityLiteProvider(broken), broken

        monkeypatch.setattr(
            composition_module, "_compose_dbip_city_lite", _fake_compose
        )
        closed: list[str] = []

        class _ExplodingClient(ProviderHttpClient):
            """Client whose close also fails, after tracking the attempt."""

            def __init__(self, name: str) -> None:
                self._name = name
                super().__init__()

            async def aclose(self) -> None:
                closed.append(self._name)
                raise RuntimeError(f"{self._name} close boom")

        class _ExplodingFactory(HttpClientFactory):
            def __init__(self) -> None:
                self.call_count = 0

            def create(
                self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
            ) -> ProviderHttpClient:
                self.call_count += 1
                return _ExplodingClient(f"client-{self.call_count}")

        comp = await ProviderComposition.create(
            settings_from_config(self._artifact_settings(tmp_path)),
            http_client_factory=_ExplodingFactory(),
            secrets=_fake_secrets(),
        )
        with pytest.raises(RuntimeError, match="database close boom"):
            await comp.aclose()
        # Every resource received exactly one close attempt despite failures.
        assert broken.close_attempts == 1
        assert closed == [
            "client-1",
            "client-2",
            "client-3",
            "client-4",
            "client-5",
            "client-6",
        ]
