# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""IANA RDAP bootstrap parsing, selection, and bounded in-process caching."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time as _time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_threat_investigator.app.providers import ProviderError, ProviderErrorCode
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    read_monotonic_clock,
    validate_provider_url,
)

_BOOTSTRAP_REGISTRIES = {
    "dns": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
    "asn": "https://data.iana.org/rdap/asn.json",
}

_RDAP_ACCEPT_HEADER = "application/rdap+json, application/json"


def _monotonic_clock() -> float:
    """Production cache clock based on ``time.monotonic``.

    Bootstrap cache expiration must measure monotonic elapsed time so
    wall-clock adjustments can never make entries expire too early or
    remain valid too long.
    """
    return _time.monotonic()


# -- Strict Pydantic models for IANA bootstrap registries -----------------


class BootstrapService(BaseModel):
    """A strictly validated IANA bootstrap service entry."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    keys: tuple[str, ...] = Field(min_length=1)
    urls: tuple[str, ...] = Field(min_length=1)


class BootstrapRegistry(BaseModel):
    """A strictly validated IANA bootstrap registry file.

    An empty ``services`` list is a valid registry that simply matches no
    entity value (a documented no-match, not a schema error).
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    version: str = Field(min_length=1)
    publication: str = Field(min_length=1)
    services: tuple[BootstrapService, ...]

    @model_validator(mode="before")
    @classmethod
    def _parse_services(cls, data: Any) -> Any:
        """Convert exact raw IANA service pairs into typed immutable services."""
        if not isinstance(data, dict) or "services" not in data:
            raise ValueError("bootstrap services are required")
        raw_services = data["services"]
        if not isinstance(raw_services, list):
            raise ValueError("bootstrap services must be a list")

        parsed: list[BootstrapService] = []
        for service in raw_services:
            if not isinstance(service, list) or len(service) != 2:
                raise ValueError("bootstrap service must contain exactly keys and URLs")
            raw_keys, raw_urls = service
            if not isinstance(raw_keys, list) or not isinstance(raw_urls, list):
                raise ValueError("bootstrap service keys and URLs must be lists")
            if not raw_keys or not raw_urls:
                raise ValueError("bootstrap service keys and URLs must not be empty")
            if not all(isinstance(key, str) and key.strip() for key in raw_keys):
                raise ValueError("bootstrap service keys must be non-empty strings")
            if not all(isinstance(url, str) and url.strip() for url in raw_urls):
                raise ValueError("bootstrap service URLs must be non-empty strings")
            parsed.append(
                BootstrapService(
                    keys=tuple(key.strip() for key in raw_keys),
                    urls=tuple(url.strip() for url in raw_urls),
                )
            )
        copied = dict(data)
        copied["services"] = tuple(parsed)
        return copied


# -- Bootstrap typed selection outcomes -----------------------------------


@dataclass(frozen=True)
class BootstrapOutcome:
    """Result of a bootstrap registry fetch and selection."""

    base_url: str | None = None
    error: ProviderError | None = None


@dataclass(frozen=True)
class BootstrapCacheEntry:
    """A cached, validated bootstrap registry."""

    services: tuple[BootstrapService, ...]
    expires_at: float


# -- Pure selection logic -------------------------------------------------


_DNS_KEY_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
"""DNS bootstrap keys must be exactly one canonical final-label value."""


def _first_valid_https_url(urls: tuple[str, ...]) -> str | None:
    """Select the first valid HTTPS URL, normalized to exactly one trailing slash."""
    for raw_url in urls:
        try:
            return validate_provider_url(raw_url).rstrip("/") + "/"
        except ValueError:
            continue
    return None


def _select_dns_base(
    services: tuple[BootstrapService, ...],
    tld: str,
) -> BootstrapOutcome:
    """Select the authoritative base URL for a DNS TLD.

    Matching is a case-insensitive final-label comparison against each
    service's keys. Selection scans all matching services and their URL lists
    in registry source order and returns the first valid HTTPS base URL found
    across them; ``NOT_FOUND`` is returned only when no service key matches
    the TLD, and ``INVALID_RESPONSE`` when at least one service matches but
    none of them contains a valid HTTPS base URL.
    """
    canonical_tld = tld.lower().strip()
    matched = False
    for svc in services:
        if not any(key.lower().strip() == canonical_tld for key in svc.keys):
            continue
        matched = True
        url = _first_valid_https_url(svc.urls)
        if url is not None:
            return BootstrapOutcome(base_url=url)

    if matched:
        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="no valid HTTPS base URL in RDAP service",
                retryable=False,
            )
        )

    return BootstrapOutcome(
        error=ProviderError(
            provider=SourceId.RDAP.value,
            code=ProviderErrorCode.NOT_FOUND,
            message=f"no authoritative RDAP service found for {tld}",
            retryable=False,
        )
    )


def _select_ip_base(
    services: tuple[BootstrapService, ...],
    ip_str: str,
) -> BootstrapOutcome:
    """Select the unique longest-prefix base URL for an IP address."""
    try:
        target_addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.UNSUPPORTED_INDICATOR,
                message="invalid entity value",
                retryable=False,
            )
        )

    matches: list[tuple[int, BootstrapService]] = []
    for svc in services:
        for key in svc.keys:
            try:
                # Strict parsing: host-bit-set keys would silently broaden
                # the asserted range and are rejected, never masked.
                network = ipaddress.ip_network(key.strip(), strict=True)
                if target_addr in network:
                    matches.append((network.prefixlen, svc))
            except ValueError:
                continue

    if not matches:
        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.NOT_FOUND,
                message=f"no authoritative RDAP service found for {ip_str}",
                retryable=False,
            )
        )

    max_prefix = max(prefixlen for prefixlen, _ in matches)
    best_matches = [svc for prefixlen, svc in matches if prefixlen == max_prefix]

    selected_urls = {
        url for svc in best_matches if (url := _first_valid_https_url(svc.urls))
    }
    if len(selected_urls) > 1:
        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message=f"ambiguous RDAP authority for IP {ip_str}",
                retryable=False,
            )
        )
    if not selected_urls:
        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="no valid HTTPS base URL in RDAP service",
                retryable=False,
            )
        )
    return BootstrapOutcome(base_url=selected_urls.pop())


def _select_asn_base(
    services: tuple[BootstrapService, ...],
    asn_number_str: str,
) -> BootstrapOutcome:
    """Select the narrowest matching ASN range base URL, rejecting ambiguity."""
    try:
        target_asn = int(asn_number_str)
    except ValueError:
        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.UNSUPPORTED_INDICATOR,
                message="invalid entity value",
                retryable=False,
            )
        )

    matches: list[tuple[int, BootstrapService]] = []
    for svc in services:
        for key in svc.keys:
            try:
                if "-" in key:
                    parts = key.split("-", 1)
                    start, end = int(parts[0].strip()), int(parts[1].strip())
                else:
                    start = end = int(key.strip())
                if start <= target_asn <= end:
                    matches.append((end - start, svc))
            except ValueError:
                continue

    if not matches:
        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.NOT_FOUND,
                message=f"no authoritative RDAP service found for ASN {asn_number_str}",
                retryable=False,
            )
        )

    min_range = min(span for span, _ in matches)
    best_matches = [svc for span, svc in matches if span == min_range]

    selected_urls = {
        url for svc in best_matches if (url := _first_valid_https_url(svc.urls))
    }
    if len(selected_urls) > 1:
        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message=f"ambiguous RDAP authority for ASN {asn_number_str}",
                retryable=False,
            )
        )
    if not selected_urls:
        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="no valid HTTPS base URL in RDAP service",
                retryable=False,
            )
        )
    return BootstrapOutcome(base_url=selected_urls.pop())


def _validate_bootstrap_keys(
    bootstrap_key: str,
    services: tuple[BootstrapService, ...],
) -> None:
    """Validate every bootstrap key for its registry category."""
    for service in services:
        for key in service.keys:
            try:
                if bootstrap_key == "dns":
                    # DNS selection compares each key directly against one
                    # final TLD label, so keys must be exactly one label.
                    if not _DNS_KEY_LABEL_RE.fullmatch(key.lower().strip()):
                        raise ValueError("invalid DNS bootstrap key")
                elif bootstrap_key in ("ipv4", "ipv6"):
                    # Strict parsing: a host-bit-set registry key asserts a
                    # different range than it renders; it invalidates the
                    # registry instead of being silently masked.
                    network = ipaddress.ip_network(key, strict=True)
                    expected_version = 6 if bootstrap_key == "ipv6" else 4
                    if network.version != expected_version:
                        raise ValueError("bootstrap CIDR has wrong address family")
                elif bootstrap_key == "asn":
                    if "-" in key:
                        start_str, end_str = key.split("-", 1)
                        start, end = int(start_str), int(end_str)
                    else:
                        start = end = int(key)
                    if start <= 0 or end < start or end > 4294967295:
                        raise ValueError("invalid ASN bootstrap range")
                else:
                    raise ValueError("unknown bootstrap category")
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid RDAP bootstrap key") from exc


# -- In-process bounded cache ---------------------------------------------


class RdapBootstrapCache:
    """In-process bounded cache for IANA bootstrap registries keyed by registry URL."""

    def __init__(
        self,
        http_client: ProviderHttpClient,
        cache_seconds: int = 3600,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        """Initialize the cache with a client, TTL, and optional injected clock.

        The HTTP client is owned by the caller. When ``clock`` is omitted the
        production monotonic clock is used; tests inject deterministic clocks.
        ``cache_seconds`` is an integer TTL contract and must be strictly
        positive; invalid values are programmer/configuration errors and
        raise ``ValueError`` before any cache state is created.
        """
        if not isinstance(cache_seconds, int) or isinstance(cache_seconds, bool):
            raise ValueError("cache_seconds must be an integer")
        if cache_seconds <= 0:
            raise ValueError("cache_seconds must be a positive integer")
        self._http = http_client
        self._cache_seconds = cache_seconds
        self._clock = clock if clock is not None else _monotonic_clock
        self._cache: dict[str, BootstrapCacheEntry] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, registry_url: str) -> asyncio.Lock:
        """Return or create a dedicated lock for the given registry URL."""
        if registry_url not in self._locks:
            self._locks[registry_url] = asyncio.Lock()
        return self._locks[registry_url]

    async def get_services(
        self, bootstrap_key: str
    ) -> tuple[tuple[BootstrapService, ...] | None, ProviderError | None]:
        """Fetch and cache validated services for a bootstrap category."""
        registry_url = _BOOTSTRAP_REGISTRIES.get(bootstrap_key)
        if registry_url is None:
            return None, ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message=f"unknown bootstrap registry: {bootstrap_key}",
                retryable=False,
            )

        cached = self._cache.get(registry_url)
        if cached is not None and read_monotonic_clock(self._clock) < cached.expires_at:
            return cached.services, None

        async with self._get_lock(registry_url):
            now = read_monotonic_clock(self._clock)
            cached = self._cache.get(registry_url)
            if cached is not None and now < cached.expires_at:
                return cached.services, None
            return await self._fetch_and_parse_registry(registry_url, bootstrap_key)

    async def _fetch_and_parse_registry(
        self, registry_url: str, bootstrap_key: str
    ) -> tuple[tuple[BootstrapService, ...] | None, ProviderError | None]:
        """Execute HTTP request for registry and populate cache."""
        outcome = await self._http.request_json(
            "GET",
            registry_url,
            headers={"Accept": "application/json"},
        )
        if outcome.final_error_code is not None:
            return None, ProviderError(
                provider=SourceId.RDAP.value,
                code=outcome.final_error_code,
                message=outcome.final_error_message or "bootstrap fetch failed",
                retryable=outcome.final_error_code.retryable,
                retry_after_seconds=outcome.retry_after_seconds,
            )

        if not isinstance(outcome.response_json, dict):
            return None, ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="invalid RDAP bootstrap registry schema",
                retryable=False,
            )

        try:
            registry = BootstrapRegistry.model_validate(outcome.response_json)
            services = tuple(registry.services)
            _validate_bootstrap_keys(bootstrap_key, services)
        except ValueError:
            return None, ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="invalid RDAP bootstrap registry schema",
                retryable=False,
            )

        completion_time = read_monotonic_clock(self._clock)
        self._cache[registry_url] = BootstrapCacheEntry(
            services=services,
            expires_at=completion_time + self._cache_seconds,
        )
        return services, None

    async def find_authoritative_base(
        self, bootstrap_key: str, match_value: str
    ) -> BootstrapOutcome:
        """Find the authoritative RDAP base URL for the given entity value."""
        services, error = await self.get_services(bootstrap_key)
        if error is not None or services is None:
            return BootstrapOutcome(error=error)

        if bootstrap_key == "dns":
            return _select_dns_base(services, match_value)
        if bootstrap_key in ("ipv4", "ipv6"):
            return _select_ip_base(services, match_value)
        if bootstrap_key == "asn":
            return _select_asn_base(services, match_value)

        return BootstrapOutcome(
            error=ProviderError(
                provider=SourceId.RDAP.value,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message=f"unknown bootstrap category: {bootstrap_key}",
                retryable=False,
            )
        )
