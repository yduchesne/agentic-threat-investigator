# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Settings-driven provider composition.

Builds provider instances from application Settings, owning their HTTP clients
and limiters. This module is the composition root for provider infrastructure.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Mapping
from contextlib import AsyncExitStack
from types import MappingProxyType

from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.app.secrets import (
    EnvVarSecretsResolver,
    SecretsResolver,
)
from agentic_threat_investigator.config.settings import Settings
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.object_store import (
    FileSystemObjectStore,
    object_store_for_uri,
)
from agentic_threat_investigator.infrastructure.providers.abuseipdb import (
    AbuseIpdbProvider,
)
from agentic_threat_investigator.infrastructure.providers.dbip_city_lite import (
    CityLiteDatabase,
    CityLiteMmdb,
    DbIpCityLiteProvider,
)
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpClient,
    ProviderHttpPolicy,
    RateLimiterSettings,
)
from agentic_threat_investigator.infrastructure.providers.ipinfo_lite import (
    IpinfoLiteProvider,
)
from agentic_threat_investigator.infrastructure.providers.rdap import RdapProvider
from agentic_threat_investigator.infrastructure.providers.threatfox import (
    ThreatFoxProvider,
)
from agentic_threat_investigator.infrastructure.providers.urlhaus import UrlhausProvider


class HttpClientFactory(ABC):
    """Factory for constructing configured, owned provider HTTP clients.

    This is an architectural client-construction abstraction: production
    composition uses the default factory, and tests substitute deterministic
    implementations to capture construction arguments or simulate failures.
    """

    @abstractmethod
    def create(
        self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
    ) -> ProviderHttpClient:
        """Construct one provider HTTP client for the given policy and limiter."""


class DefaultHttpClientFactory(HttpClientFactory):
    """Default factory constructing owned ``ProviderHttpClient`` instances."""

    def create(
        self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
    ) -> ProviderHttpClient:
        """Construct one owned provider HTTP client."""
        return ProviderHttpClient(policy=policy, limiter=limiter)


async def _compose_dbip_city_lite(
    settings: Settings, stack: AsyncExitStack
) -> tuple[DbIpCityLiteProvider, CityLiteDatabase]:
    """Resolve, verify, and open the configured City Lite MMDB artifact.

    The artifact URI is resolved through the existing ObjectStore boundary
    and opened as a long-lived read-only reader. The opened reader is
    registered on the construction stack immediately, before the provider is
    constructed, so any later construction failure rolls it back. On success
    ``pop_all()`` discards that callback and explicit ``aclose()`` ownership
    takes over. Raises a typed error when the artifact is absent or
    unreadable; no download is ever attempted.
    """
    artifact_uri = settings.dbip_city_lite_artifact_uri
    file_store = FileSystemObjectStore(settings.datasets_dir)
    # Existing URI-scheme boundary: rejects unsupported schemes.
    object_store_for_uri(artifact_uri, file_store)
    payload = await file_store.read(artifact_uri)
    database: CityLiteDatabase = CityLiteMmdb(payload)
    stack.callback(database.close)
    provider = DbIpCityLiteProvider(database)
    return provider, database


class ProviderComposition:
    """Owned provider instances and their shared HTTP infrastructure.

    One named attribute per composed provider is deliberate: the extra
    instance attribute count is the accepted cost of explicit, typed
    accessors instead of an untyped provider registry.

    Construct asynchronously through :meth:`create` so a failure partway
    through construction rolls back already-created owned clients; the
    synchronous constructor only establishes the uninitialized invariant.
    Use as an async context manager or call ``aclose()`` to release resources.
    """

    def __init__(self) -> None:
        """Initialize the uninitialized composition invariant."""
        self._clients: tuple[ProviderHttpClient, ...] = ()
        self._databases: tuple[CityLiteDatabase, ...] = ()
        self._google_dns: GooglePublicDnsProvider | None = None
        self._rdap: RdapProvider | None = None
        self._ipinfo_lite: IpinfoLiteProvider | None = None
        self._abuseipdb: AbuseIpdbProvider | None = None
        self._threatfox: ThreatFoxProvider | None = None
        self._urlhaus: UrlhausProvider | None = None
        self._dbip_city_lite: DbIpCityLiteProvider | None = None

    @classmethod
    # The explicit one-step-per-provider composition is deliberate; the
    # named locals are the accepted cost of transparent, typed wiring.
    async def create(
        cls,
        settings: Settings,
        *,
        http_client_factory: HttpClientFactory | None = None,
        secrets: SecretsResolver | None = None,
    ) -> ProviderComposition:
        """Compose providers, rolling back owned clients on partial failure.

        The IPinfo Lite access token is resolved here, during composition,
        from the configured secret reference name; providers receive only the
        resolved credential and never read configuration or the environment.
        A missing required secret fails clearly before the corresponding
        client is created so already-created owned clients roll back.
        """
        factory = http_client_factory or DefaultHttpClientFactory()
        resolver = secrets if secrets is not None else EnvVarSecretsResolver()
        policy = ProviderHttpPolicy(
            timeout_seconds=settings.provider_timeout_seconds,
            max_retries=settings.provider_max_retries,
            base_delay_seconds=settings.provider_retry_base_delay_seconds,
            max_delay_seconds=settings.provider_retry_max_delay_seconds,
            jitter_ratio=settings.provider_retry_jitter_ratio,
            max_response_bytes=settings.provider_max_response_bytes,
        )
        composition = cls()
        clients: list[ProviderHttpClient] = []
        async with AsyncExitStack() as stack:
            http = factory.create(
                policy,
                BoundedLimiter(
                    RateLimiterSettings(
                        max_concurrency=settings.google_dns_max_concurrency,
                        requests_per_second=settings.google_dns_requests_per_second,
                    )
                ),
            )
            stack.push_async_callback(http.aclose)
            clients.append(http)
            composition._google_dns = GooglePublicDnsProvider(http)

            http = factory.create(
                policy,
                BoundedLimiter(
                    RateLimiterSettings(
                        max_concurrency=settings.rdap_max_concurrency,
                        requests_per_second=settings.rdap_requests_per_second,
                    )
                ),
            )
            stack.push_async_callback(http.aclose)
            clients.append(http)
            composition._rdap = RdapProvider(
                http,
                cache_seconds=settings.rdap_bootstrap_cache_seconds,
            )

            # The IPinfo Lite access token is resolved here, during
            # composition, from the configured secret reference name; the
            # provider receives only the resolved credential.
            ipinfo_token = resolver.require(settings.ipinfo_lite_token_secret)
            http = factory.create(
                policy,
                BoundedLimiter(
                    RateLimiterSettings(
                        max_concurrency=settings.ipinfo_lite_max_concurrency,
                        requests_per_second=settings.ipinfo_lite_requests_per_second,
                    )
                ),
            )
            stack.push_async_callback(http.aclose)
            clients.append(http)
            composition._ipinfo_lite = IpinfoLiteProvider(http, token=ipinfo_token)

            # The AbuseIPDB API key is resolved during composition through the
            # same bootstrap contract; the provider receives only the resolved
            # key and never reads configuration or the environment.
            abuseipdb_key = resolver.require(settings.abuseipdb_api_key_secret)
            http = factory.create(
                policy,
                BoundedLimiter(
                    RateLimiterSettings(
                        max_concurrency=settings.abuseipdb_max_concurrency,
                        requests_per_second=settings.abuseipdb_requests_per_second,
                    )
                ),
            )
            stack.push_async_callback(http.aclose)
            clients.append(http)
            composition._abuseipdb = AbuseIpdbProvider(
                http,
                api_key=abuseipdb_key,
                max_age_in_days=settings.abuseipdb_max_age_in_days,
            )

            # The ThreatFox Auth-Key is resolved during composition through
            # the same bootstrap contract; the provider receives only the
            # resolved key and never reads configuration or the environment.
            threatfox_key = resolver.require(settings.threatfox_auth_key_secret)
            http = factory.create(
                policy,
                BoundedLimiter(
                    RateLimiterSettings(
                        max_concurrency=settings.threatfox_max_concurrency,
                        requests_per_second=settings.threatfox_requests_per_second,
                    )
                ),
            )
            stack.push_async_callback(http.aclose)
            clients.append(http)
            composition._threatfox = ThreatFoxProvider(http, auth_key=threatfox_key)

            # The URLhaus Auth-Key is resolved during composition through
            # the same bootstrap contract; the provider receives only the
            # resolved key and never reads configuration or the environment.
            urlhaus_key = resolver.require(settings.urlhaus_auth_key_secret)
            http = factory.create(
                policy,
                BoundedLimiter(
                    RateLimiterSettings(
                        max_concurrency=settings.urlhaus_max_concurrency,
                        requests_per_second=settings.urlhaus_requests_per_second,
                    )
                ),
            )
            stack.push_async_callback(http.aclose)
            clients.append(http)
            composition._urlhaus = UrlhausProvider(http, auth_key=urlhaus_key)

            # Local DB-IP City Lite geolocation: composed only when the
            # credential-free artifact URI is configured. The artifact must
            # already exist and be readable; composition fails fast otherwise.
            # The provider is local evidence only: no HTTP client, no secret.
            if settings.dbip_city_lite_artifact_uri:
                (
                    composition._dbip_city_lite,
                    database,
                ) = await _compose_dbip_city_lite(settings, stack)
                composition._databases = (database,)

            composition._clients = tuple(clients)
            # Construction succeeded: the composition now owns explicit cleanup
            # through aclose(); the stack must not close the clients again.
            stack.pop_all()
        return composition

    @property
    def google_dns(self) -> GooglePublicDnsProvider:
        """Google Public DNS provider instance."""
        if self._google_dns is None:
            raise RuntimeError("ProviderComposition must be created via create()")
        return self._google_dns

    @property
    def rdap(self) -> RdapProvider:
        """RDAP provider instance."""
        if self._rdap is None:
            raise RuntimeError("ProviderComposition must be created via create()")
        return self._rdap

    @property
    def ipinfo_lite(self) -> IpinfoLiteProvider:
        """IPinfo Lite provider instance."""
        if self._ipinfo_lite is None:
            raise RuntimeError("ProviderComposition must be created via create()")
        return self._ipinfo_lite

    @property
    def abuseipdb(self) -> AbuseIpdbProvider:
        """AbuseIPDB provider instance."""
        if self._abuseipdb is None:
            raise RuntimeError("ProviderComposition must be created via create()")
        return self._abuseipdb

    @property
    def threatfox(self) -> ThreatFoxProvider:
        """ThreatFox provider instance."""
        if self._threatfox is None:
            raise RuntimeError("ProviderComposition must be created via create()")
        return self._threatfox

    @property
    def urlhaus(self) -> UrlhausProvider:
        """URLhaus provider instance."""
        if self._urlhaus is None:
            raise RuntimeError("ProviderComposition must be created via create()")
        return self._urlhaus

    @property
    def dbip_city_lite(self) -> DbIpCityLiteProvider | None:
        """DB-IP City Lite provider instance, or ``None`` when disabled.

        The provider is composed only when the DB-IP City Lite artifact URI
        is configured; a ``None`` value is the documented disabled state.
        """
        return self._dbip_city_lite

    def provider_registry(self) -> Mapping[SourceId, EvidenceProvider]:
        """Return the typed SourceId-to-provider registry for orchestration.

        Only composed providers appear in the mapping; an absent entry is the
        documented not-configured state. The mapping is read-only and keyed by
        enum members, so orchestration resolves a work item's ``SourceId``
        without string conversion.
        """
        registry: dict[SourceId, EvidenceProvider] = {
            SourceId.GOOGLE_PUBLIC_DNS: self.google_dns,
            SourceId.RDAP: self.rdap,
            SourceId.IPINFO_LITE: self.ipinfo_lite,
            SourceId.ABUSEIPDB: self.abuseipdb,
            SourceId.THREATFOX: self.threatfox,
            SourceId.URLHAUS: self.urlhaus,
        }
        if self._dbip_city_lite is not None:
            registry[SourceId.DBIP_CITY_LITE] = self._dbip_city_lite
        return MappingProxyType(registry)

    async def aclose(self) -> None:
        """Close all owned local readers and clients, re-raising the first failure."""
        errors: list[BaseException] = []
        for database in self._databases:
            try:
                database.close()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        for client in self._clients:
            try:
                await client.aclose()
            except asyncio.CancelledError as exc:
                errors.append(exc)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        if errors:
            raise errors[0]

    async def __aenter__(self) -> ProviderComposition:
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc_val: object,
        exc_tb: object,
    ) -> None:
        await self.aclose()
