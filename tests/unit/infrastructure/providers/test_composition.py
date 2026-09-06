# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for settings-driven provider composition."""

from __future__ import annotations

import asyncio

import pytest

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
)

pytestmark = pytest.mark.asyncio


class _SpyHttpClientFactory(  # pylint: disable=too-few-public-methods
    HttpClientFactory
):
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
        settings, http_client_factory=factory
    ) as comp:
        assert len(factory.calls) == 2
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
        settings, http_client_factory=factory
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

    clients = [_FailingClient("first"), _FailingClient("second")]

    class _CannedFactory(HttpClientFactory):  # pylint: disable=too-few-public-methods
        def create(
            self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
        ) -> ProviderHttpClient:
            return clients.pop(0)

    settings = settings_from_config({})
    comp = await ProviderComposition.create(
        settings, http_client_factory=_CannedFactory()
    )

    with pytest.raises(RuntimeError, match="simulated client aclose failure"):
        await comp.aclose()

    assert closed == ["first", "second"]


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

    class _FailOnSecondFactory(  # pylint: disable=too-few-public-methods
        HttpClientFactory
    ):
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
            settings, http_client_factory=_FailOnSecondFactory()
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
    ]

    class _CannedFactory(HttpClientFactory):  # pylint: disable=too-few-public-methods
        def create(
            self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
        ) -> ProviderHttpClient:
            return clients.pop(0)

    settings = settings_from_config({})
    comp = await ProviderComposition.create(
        settings, http_client_factory=_CannedFactory()
    )

    with pytest.raises(asyncio.CancelledError):
        await comp.aclose()

    assert closed == ["second"]


async def test_composition_properties_require_create() -> None:
    """Accessing providers before create() raises an explicit runtime error."""
    comp = ProviderComposition()
    with pytest.raises(RuntimeError, match="create"):
        _ = comp.google_dns
    with pytest.raises(RuntimeError, match="create"):
        _ = comp.rdap
