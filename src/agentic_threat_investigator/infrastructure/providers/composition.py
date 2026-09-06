# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Settings-driven provider composition.

Builds provider instances from application Settings, owning their HTTP clients
and limiters. This module is the composition root for provider infrastructure.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from contextlib import AsyncExitStack

from agentic_threat_investigator.config.settings import Settings
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpClient,
    ProviderHttpPolicy,
    RateLimiterSettings,
)
from agentic_threat_investigator.infrastructure.providers.rdap import RdapProvider


class HttpClientFactory(ABC):  # pylint: disable=too-few-public-methods
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


class DefaultHttpClientFactory(  # pylint: disable=too-few-public-methods
    HttpClientFactory
):
    """Default factory constructing owned ``ProviderHttpClient`` instances."""

    def create(
        self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
    ) -> ProviderHttpClient:
        """Construct one owned provider HTTP client."""
        return ProviderHttpClient(policy=policy, limiter=limiter)


class ProviderComposition:
    """Owned provider instances and their shared HTTP infrastructure.

    Construct asynchronously through :meth:`create` so a failure partway
    through construction rolls back already-created owned clients; the
    synchronous constructor only establishes the uninitialized invariant.
    Use as an async context manager or call ``aclose()`` to release resources.
    """

    def __init__(self) -> None:
        """Initialize the uninitialized composition invariant."""
        self._clients: tuple[ProviderHttpClient, ...] = ()
        self._google_dns: GooglePublicDnsProvider | None = None
        self._rdap: RdapProvider | None = None

    @classmethod
    async def create(
        cls,
        settings: Settings,
        *,
        http_client_factory: HttpClientFactory | None = None,
    ) -> ProviderComposition:
        """Compose providers, rolling back owned clients on partial failure."""
        factory = http_client_factory or DefaultHttpClientFactory()
        policy = ProviderHttpPolicy(
            timeout_seconds=settings.provider_timeout_seconds,
            max_retries=settings.provider_max_retries,
            base_delay_seconds=settings.provider_retry_base_delay_seconds,
            max_delay_seconds=settings.provider_retry_max_delay_seconds,
            jitter_ratio=settings.provider_retry_jitter_ratio,
            max_response_bytes=settings.provider_max_response_bytes,
        )
        composition = cls()
        async with AsyncExitStack() as stack:
            google_http = factory.create(
                policy,
                BoundedLimiter(
                    RateLimiterSettings(
                        max_concurrency=settings.google_dns_max_concurrency,
                        requests_per_second=settings.google_dns_requests_per_second,
                    )
                ),
            )
            stack.push_async_callback(google_http.aclose)
            composition._google_dns = GooglePublicDnsProvider(google_http)

            rdap_http = factory.create(
                policy,
                BoundedLimiter(
                    RateLimiterSettings(
                        max_concurrency=settings.rdap_max_concurrency,
                        requests_per_second=settings.rdap_requests_per_second,
                    )
                ),
            )
            stack.push_async_callback(rdap_http.aclose)
            composition._rdap = RdapProvider(
                rdap_http,
                cache_seconds=settings.rdap_bootstrap_cache_seconds,
            )

            composition._clients = (google_http, rdap_http)
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

    async def aclose(self) -> None:
        """Close both clients and re-raise the first failure, including cancellation."""
        errors: list[BaseException] = []
        for client in self._clients:
            try:
                await client.aclose()
            except asyncio.CancelledError as exc:
                errors.append(exc)
            except Exception as exc:  # pylint: disable=broad-exception-caught
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
