# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Provider contract tests for RdapProvider, bootstrap discovery, and caching."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode, ProviderResult
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.infrastructure.providers import rdap_bootstrap
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from agentic_threat_investigator.infrastructure.providers.rdap import (
    RdapBootstrapCache,
    RdapProvider,
)

from .rdap_payloads import (
    _bootstrap_registry,
    _rdap_autnum,
    _rdap_domain,
    _rdap_network,
)

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapContract:
    """Deterministic provider contract tests for RdapProvider."""

    async def test_supports_matrix(self) -> None:
        """RdapProvider supports exactly DOMAIN, IP_ADDRESS, and ASN."""
        client = httpx.AsyncClient(
            transport=MockTransport(lambda _: httpx.Response(200, json={}))
        )
        provider = RdapProvider(ProviderHttpClient(client=client))

        supported = {EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.ASN}
        for entity_type in EntityType:
            expected = entity_type in supported
            assert provider.supports(Entity(type=entity_type, value="test")) is expected

    async def test_unsupported_entity_produces_no_io(self) -> None:
        """Investigating an unsupported entity issues zero HTTP requests."""
        network_hit = False

        def _guard_handler(_: httpx.Request) -> httpx.Response:
            nonlocal network_hit
            network_hit = True
            return httpx.Response(500)

        transport = MockTransport(_guard_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.ORGANIZATION, value="Acme Corp")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert network_hit is False
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR

    async def test_invalid_entity_value_produces_no_io(self) -> None:
        """Investigating an invalid entity value issues zero HTTP requests."""
        network_hit = False

        def _guard_handler(_: httpx.Request) -> httpx.Response:
            nonlocal network_hit
            network_hit = True
            return httpx.Response(500)

        transport = MockTransport(_guard_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.IP_ADDRESS, value="invalid-ip-string")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert network_hit is False
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR

    async def test_single_label_domain_bootstrap_lookup(self) -> None:
        """A canonical single-label domain bootstraps via its final TLD label."""
        bootstrap_paths: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            if host == "data.iana.org":
                bootstrap_paths.append(request.url.path)
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
                )
            assert request.url.path == "/domain/com"
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=_rdap_domain("com", "DOM-TLD"),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(
                ProviderHttpClient(client=client),
                clock=lambda: _FIXED_TS,
            )
            entity = Entity(type=EntityType.DOMAIN, value="COM.")
            result = await provider.investigate(_FIXED_UUID, entity)

        assert bootstrap_paths == ["/rdap/dns.json"]
        assert len(result.evidence) == 1
        ev = result.evidence[0]
        assert ev.type == EvidenceType.REGISTRATION
        assert ev.subject.value == "com"
        assert ev.source_record_id == "DOM-TLD"
        assert ev.source_url == "https://rdap.test/domain/com"
        assert ev.facts["ldh_name"] == "com"
        assert ev.facts["object_class_name"] == "domain"

    async def test_domain_lookup_and_provenance(self) -> None:
        """Domain lookups resolve via bootstrap and produce registration evidence."""

        def _handler(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            if host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry(
                        [[["com"], ["https://rdap.verisign.test/"]]]
                    ),
                )
            if host == "rdap.verisign.test":
                assert request.url.path == "/domain/example.com"
                assert "application/rdap+json" in request.headers["Accept"]
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/rdap+json"},
                    json=_rdap_domain("example.com", "DOM-100"),
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(
                ProviderHttpClient(client=client),
                clock=lambda: _FIXED_TS,
            )
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)

            assert result.provider == "urn:ati:source:rdap"
            assert len(result.evidence) == 1
            ev = result.evidence[0]
            assert ev.type == EvidenceType.REGISTRATION
            assert ev.investigation_id == _FIXED_UUID
            assert ev.subject.value == "example.com"
            assert ev.source == "urn:ati:source:rdap"
            assert ev.source_record_id == "DOM-100"
            assert ev.source_url == "https://rdap.verisign.test/domain/example.com"
            assert ev.retrieved_at == _FIXED_TS
            assert ev.observed_at == datetime(2026, 1, 10, 15, 30, 0, tzinfo=UTC)
            assert ev.facts["object_class_name"] == "domain"
            assert ev.facts["ldh_name"] == "example.com"
            assert list(ev.facts["nameservers"]) == ["ns1.example.com"]
            assert ev.facts["entities"][0]["display_name"] == "Example Admin"

    async def test_ipv4_longest_prefix_selection(self) -> None:
        """IPv4 address selects the most-specific containing network authority."""
        called_urls: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            called_urls.append(str(request.url))
            host = request.url.host
            if host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry(
                        [
                            [["198.51.0.0/16"], ["https://broad.rir.test/"]],
                            [["198.51.100.0/24"], ["https://specific.rir.test/"]],
                        ]
                    ),
                )
            if host == "specific.rir.test":
                assert request.url.path == "/ip/198.51.100.42"
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/rdap+json"},
                    json=_rdap_network(
                        "198.51.100.0", "198.51.100.255", "NET-SPECIFIC"
                    ),
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.IP_ADDRESS, value="198.51.100.42")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.evidence) == 1
            assert result.evidence[0].facts["handle"] == "NET-SPECIFIC"
            assert list(result.evidence[0].facts["cidr0_cidrs"]) == [
                {"prefix": "198.51.100.0", "length": 24}
            ]
            assert not any("broad.rir.test" in url for url in called_urls)

    async def test_ipv6_lookup(self) -> None:
        """IPv6 address queries the ipv6 bootstrap and authoritative service."""

        def _handler(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            if host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry(
                        [[["2001:db8::/32"], ["https://v6.rir.test/"]]]
                    ),
                )
            if host == "v6.rir.test":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/rdap+json"},
                    json=_rdap_network(
                        "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
                    ),
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.IP_ADDRESS, value="2001:db8::1")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.evidence) == 1
            assert result.evidence[0].facts["ip_version"] == "v6"

    async def test_asn_range_selection_and_as_prefix_removal(self) -> None:
        """ASN lookup strips AS prefix, tests boundary, and queries decimal path."""

        def _handler(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            if host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry(
                        [
                            [["1-1000"], ["https://broad.asn.test/"]],
                            [["500-600"], ["https://narrow.asn.test/"]],
                        ]
                    ),
                )
            if host == "narrow.asn.test":
                assert request.url.path == "/autnum/500"
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/rdap+json"},
                    json=_rdap_autnum(500, 600, "AS500"),
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.ASN, value="as500")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.evidence) == 1
            assert result.evidence[0].facts["start_autnum"] == 500
            assert result.evidence[0].source_record_id == "AS500"

    async def test_ambiguous_ip_prefix_returns_invalid_response(self) -> None:
        """Overlapping IP prefixes of equal specificity return INVALID_RESPONSE."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry(
                        [
                            [["198.51.100.0/24"], ["https://rir-a.test/"]],
                            [["198.51.100.0/24"], ["https://rir-b.test/"]],
                        ]
                    ),
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert any(
                e.code == ProviderErrorCode.INVALID_RESPONSE for e in result.errors
            )
            assert any("ambiguous" in e.message for e in result.errors)

    async def test_ambiguous_asn_range_returns_invalid_response(self) -> None:
        """Equal-span ASN ranges from different services return INVALID_RESPONSE."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry(
                        [
                            [["100-200"], ["https://asn-a.test/"]],
                            [["100-200"], ["https://asn-b.test/"]],
                        ]
                    ),
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.ASN, value="AS150")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert any(
                e.code == ProviderErrorCode.INVALID_RESPONSE for e in result.errors
            )
            assert any("ambiguous" in e.message for e in result.errors)

    async def test_malformed_bootstrap_key_returns_invalid_response(self) -> None:
        """Malformed CIDR keys are invalid bootstrap data, not a no-match."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_bootstrap_registry([[["not-a-cidr"], ["https://rdap.test/"]]]),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
            )
            assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_inconsistent_network_response_returns_invalid_response(self) -> None:
        """Malformed network boundaries become a typed provider error."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry(
                        [[["198.51.100.0/24"], ["https://rdap.test/"]]]
                    ),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json={
                    "objectClassName": "ip network",
                    "startAddress": "bad",
                    "endAddress": "198.51.100.255",
                    "ipVersion": "v4",
                },
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
            )
            assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_inconsistent_asn_response_returns_invalid_response(self) -> None:
        """Reversed or non-containing ASN ranges do not produce evidence."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["100-200"], ["https://rdap.test/"]]]),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json={
                    "objectClassName": "autnum",
                    "startAutnum": 200,
                    "endAutnum": 100,
                },
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID,
                Entity(type=EntityType.ASN, value="AS150"),
            )
            assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_domain_identity_mismatch_returns_invalid_response(self) -> None:
        """An authoritative domain for another name is rejected."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json={"objectClassName": "domain", "ldhName": "different.com"},
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID,
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )
            assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_wrong_authoritative_content_type_returns_invalid_response(
        self,
    ) -> None:
        """A problem JSON response is not accepted as RDAP data."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/problem+json"},
                json={"objectClassName": "domain"},
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID,
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )
            assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_no_bootstrap_match_returns_not_found(self) -> None:
        """A TLD with no matching service returns NOT_FOUND."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.com.test/"]]]),
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.DOMAIN, value="example.unknown")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert any(e.code == ProviderErrorCode.NOT_FOUND for e in result.errors)

    async def test_bootstrap_malformed_registry_schema(self) -> None:
        """Malformed bootstrap registry JSON returns INVALID_RESPONSE without raw payload."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"invalid": "no version or services"},
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert any(
                e.code == ProviderErrorCode.INVALID_RESPONSE for e in result.errors
            )
            assert result.errors[0].message == "invalid RDAP bootstrap registry schema"

    async def test_object_class_mismatch(self) -> None:
        """Returning an unexpected objectClassName produces INVALID_RESPONSE."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json={"objectClassName": "entity", "handle": "NOT-A-DOMAIN"},
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert any(
                e.code == ProviderErrorCode.INVALID_RESPONSE for e in result.errors
            )

    async def test_authoritative_http_error_propagation(self) -> None:
        """Authoritative 404, 401, 403, 429, and 503 produce typed errors."""
        for status_code, expected_code in [
            (404, ProviderErrorCode.NOT_FOUND),
            (401, ProviderErrorCode.AUTHENTICATION_FAILED),
            (403, ProviderErrorCode.FORBIDDEN),
            (429, ProviderErrorCode.RATE_LIMITED),
            (503, ProviderErrorCode.PROVIDER_UNAVAILABLE),
        ]:

            def _make_handler(code: int) -> Any:
                def _h(request: httpx.Request) -> httpx.Response:
                    if request.url.host == "data.iana.org":
                        return httpx.Response(
                            200,
                            headers={"Content-Type": "application/json"},
                            json=_bootstrap_registry(
                                [[["com"], ["https://rdap.test/"]]]
                            ),
                        )
                    return httpx.Response(code, json={"error": "authoritative failure"})

                return _h

            transport = MockTransport(_make_handler(status_code))
            async with httpx.AsyncClient(transport=transport) as client:
                provider = RdapProvider(
                    ProviderHttpClient(client=client, max_retries=0)
                )
                entity = Entity(type=EntityType.DOMAIN, value="example.com")
                result = await provider.investigate(_FIXED_UUID, entity)
                assert result.errors[0].code == expected_code

    async def test_source_record_id_fallback(self) -> None:
        """Blank handle falls back to normalized identity for domain and IP."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry(
                        [[["198.51.100.0/24"], ["https://rdap.test/"]]]
                    ),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json={
                    "objectClassName": "ip network",
                    "handle": "",  # Blank handle
                    "startAddress": "198.51.100.0",
                    "endAddress": "198.51.100.255",
                    "ipVersion": "v4",
                },
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.evidence) == 1
            assert result.evidence[0].source_record_id == "198.51.100.0-198.51.100.255"

    async def test_cache_hit_and_expiry_refresh(self) -> None:
        """Cache serves memory hits until expiry, then triggers a new refresh."""
        current_time = 1000.0
        fetch_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal fetch_count
            if request.url.host == "data.iana.org":
                fetch_count += 1
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=_rdap_domain("example.com"),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            cache = RdapBootstrapCache(
                ProviderHttpClient(client=client),
                cache_seconds=300,
                clock=lambda: current_time,
            )

            # First lookup: fetches from upstream
            out1 = await cache.find_authoritative_base("dns", "com")
            assert out1.base_url == "https://rdap.test/"
            assert fetch_count == 1

            # Second lookup at t+100: cache hit
            current_time = 1100.0
            out2 = await cache.find_authoritative_base("dns", "com")
            assert out2.base_url == "https://rdap.test/"
            assert fetch_count == 1

            # Third lookup at t+350 (expired): triggers refresh
            current_time = 1350.0
            out3 = await cache.find_authoritative_base("dns", "com")
            assert out3.base_url == "https://rdap.test/"
            assert fetch_count == 2

    async def test_concurrent_refresh_coalesced(self) -> None:
        """Concurrent requests to the same bootstrap URL are coalesced to a single fetch."""
        fetch_count = 0
        fetch_started = asyncio.Event()
        release_fetch = asyncio.Event()

        async def _slow_handler(request: httpx.Request) -> httpx.Response:
            nonlocal fetch_count
            if request.url.host == "data.iana.org":
                fetch_count += 1
                fetch_started.set()
                await release_fetch.wait()
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_slow_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            cache = RdapBootstrapCache(
                ProviderHttpClient(client=client),
                cache_seconds=300,
            )

            # Fire 5 concurrent lookups and hold the first upstream response
            tasks = [
                asyncio.create_task(cache.find_authoritative_base("dns", "com"))
                for _ in range(5)
            ]
            await fetch_started.wait()
            release_fetch.set()
            results = await asyncio.gather(*tasks)
            assert all(r.base_url == "https://rdap.test/" for r in results)
            assert fetch_count == 1  # Coalesced to 1 request

    async def test_bootstrap_failure_not_cached(self) -> None:
        """A failed bootstrap fetch is never cached; subsequent lookup retries."""
        call_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            if request.url.host == "data.iana.org":
                call_count += 1
                if call_count == 1:
                    return httpx.Response(500, json={"error": "server error"})
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            cache = RdapBootstrapCache(ProviderHttpClient(client=client, max_retries=0))
            out1 = await cache.find_authoritative_base("dns", "com")
            assert out1.error is not None

            # Next call must retry and succeed
            out2 = await cache.find_authoritative_base("dns", "com")
            assert out2.base_url == "https://rdap.test/"
            assert call_count == 2


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestBootstrapCacheMonotonicClock:
    """The production cache clock is monotonic; injected clocks stay deterministic."""

    async def test_default_cache_clock_is_monotonic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Production default expiry uses time.monotonic, never a wall clock."""
        # Structurally, the bootstrap module must not use wall-clock datetime.
        assert "datetime" not in rdap_bootstrap.__dict__

        current = {"value": 1000.0}

        def fake_monotonic() -> float:
            return current["value"]

        monkeypatch.setattr(
            rdap_bootstrap, "_time", SimpleNamespace(monotonic=fake_monotonic)
        )
        fetch_count = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal fetch_count
            fetch_count += 1
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            cache = RdapBootstrapCache(
                ProviderHttpClient(client=client), cache_seconds=300
            )
            out1 = await cache.find_authoritative_base("dns", "com")
            assert out1.base_url == "https://rdap.test/"
            assert fetch_count == 1

            # Advance the (production-default, now faked) monotonic clock past
            # the TTL: the entry must expire and trigger exactly one refetch.
            current["value"] = 1000.0 + 301.0
            out2 = await cache.find_authoritative_base("dns", "com")
            assert out2.base_url == "https://rdap.test/"
            assert fetch_count == 2

    async def test_provider_passes_injected_monotonic_clock_to_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RdapProvider forwards its monotonic_clock to the bootstrap cache."""
        current = {"value": 2000.0}

        def fake_monotonic() -> float:
            return current["value"]

        monkeypatch.setattr(
            rdap_bootstrap, "_time", SimpleNamespace(monotonic=fake_monotonic)
        )
        fetch_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal fetch_count
            if request.url.host == "data.iana.org":
                fetch_count += 1
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=_rdap_domain("example.com"),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(
                ProviderHttpClient(client=client),
                cache_seconds=300,
                monotonic_clock=fake_monotonic,
            )
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result1 = await provider.investigate(_FIXED_UUID, entity)
            assert len(result1.evidence) == 1
            assert fetch_count == 1

            # Expire the cache via the injected monotonic clock: refetch.
            current["value"] = 2000.0 + 301.0
            result2 = await provider.investigate(_FIXED_UUID, entity)
            assert len(result2.evidence) == 1
            assert fetch_count == 2

    async def test_provider_default_cache_clock_is_monotonic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without an injected clock the provider cache selects the monotonic default."""
        current = {"value": 3000.0}

        def fake_monotonic() -> float:
            return current["value"]

        monkeypatch.setattr(
            rdap_bootstrap, "_time", SimpleNamespace(monotonic=fake_monotonic)
        )
        fetch_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal fetch_count
            if request.url.host == "data.iana.org":
                fetch_count += 1
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry([[["com"], ["https://rdap.test/"]]]),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=_rdap_domain("example.com"),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(
                ProviderHttpClient(client=client), cache_seconds=300
            )
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result1 = await provider.investigate(_FIXED_UUID, entity)
            assert len(result1.evidence) == 1
            assert fetch_count == 1

            current["value"] = 3000.0 + 301.0
            result2 = await provider.investigate(_FIXED_UUID, entity)
            assert len(result2.evidence) == 1
            assert fetch_count == 2


@pytest.mark.unit
@pytest.mark.provider_contract
class TestBootstrapCacheLifetimeValidation:
    """Direct construction rejects non-positive or non-integer cache lifetimes."""

    @staticmethod
    def _make_cache(cache_seconds: Any) -> None:
        """Construct a cache with a throwaway client and the given TTL."""
        transport = MockTransport(lambda _: httpx.Response(500, json={}))
        client = httpx.AsyncClient(transport=transport)
        RdapBootstrapCache(
            ProviderHttpClient(client=client), cache_seconds=cache_seconds
        )

    @pytest.mark.parametrize("bad_ttl", [0, -1, -3600])
    def test_non_positive_cache_seconds_rejected(self, bad_ttl: int) -> None:
        """Zero and negative TTL values are programmer errors, not no-cache modes."""
        with pytest.raises(ValueError, match="positive"):
            self._make_cache(bad_ttl)

    @pytest.mark.parametrize("bad_ttl", [3600.0, "3600", True, None])
    def test_non_integer_cache_seconds_rejected(self, bad_ttl: Any) -> None:
        """The TTL stays an integer contract; other types are rejected."""
        with pytest.raises(ValueError, match="integer"):
            self._make_cache(bad_ttl)


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapAuthorityCanonicalization:
    """Canonically equivalent RDAP authorities cannot cause false ambiguity."""

    @staticmethod
    async def _investigate_with_services(
        services: list[Any],
        entity: Entity,
        authority_response: httpx.Response,
    ) -> tuple[ProviderResult, list[str]]:
        """Run one investigation against a bootstrap registry and one authority."""
        contacted_hosts: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_bootstrap_registry(services),
                )
            contacted_hosts.append(request.url.host)
            return authority_response

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(_FIXED_UUID, entity)
        return result, contacted_hosts

    async def test_ip_equivalent_authority_spellings_not_ambiguous(self) -> None:
        """Equal-prefix services whose URLs differ only by host spelling are one authority."""
        result, contacted = await self._investigate_with_services(
            [
                [["198.51.100.0/24"], ["https://RIR-A.TEST/"]],
                [["198.51.100.0/24"], ["https://rir-a.test./"]],
            ],
            Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
            httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=_rdap_network("198.51.100.0", "198.51.100.255"),
            ),
        )
        assert len(result.evidence) == 1
        assert result.evidence[0].source_url == "https://rir-a.test/ip/198.51.100.1"
        assert contacted == ["rir-a.test"]

    async def test_asn_equivalent_authority_spellings_not_ambiguous(self) -> None:
        """Equal-span ASN services with canonically equivalent URLs are one authority."""
        result, contacted = await self._investigate_with_services(
            [
                [["100-200"], ["https://ASN-REGISTRY.TEST:8443/"]],
                [["100-200"], ["https://asn-registry.test.:8443/"]],
            ],
            Entity(type=EntityType.ASN, value="AS150"),
            httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=_rdap_autnum(100, 200),
            ),
        )
        assert len(result.evidence) == 1
        assert (
            result.evidence[0].source_url == "https://asn-registry.test:8443/autnum/150"
        )
        assert contacted == ["asn-registry.test"]

    async def test_genuinely_different_authorities_still_ambiguous(self) -> None:
        """Canonically distinct authorities for equal specificity still error."""
        result, contacted = await self._investigate_with_services(
            [
                [["198.51.100.0/24"], ["https://RIR-A.TEST/"]],
                [["198.51.100.0/24"], ["https://rir-b.test./"]],
            ],
            Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
            httpx.Response(404, json={}),
        )
        assert not result.evidence
        assert contacted == []
        assert any(e.code == ProviderErrorCode.INVALID_RESPONSE for e in result.errors)
        assert any("ambiguous" in e.message for e in result.errors)

    async def test_malformed_credential_candidate_skipped_without_exposure(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A malformed credential-bearing bootstrap candidate is skipped safely.

        The invalid candidate must not be selected, logged, or returned, and a
        later valid HTTPS candidate for the same prefix must still be chosen.
        """
        with caplog.at_level(logging.DEBUG):
            result, contacted = await self._investigate_with_services(
                [
                    [
                        ["198.51.100.0/24"],
                        ["https://user:TOPSECRET@[bad/path?token=QUERYSECRET"],
                    ],
                    [["198.51.100.0/24"], ["https://rir-b.test/"]],
                ],
                Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
                httpx.Response(
                    200,
                    headers={"Content-Type": "application/rdap+json"},
                    json=_rdap_network("198.51.100.0", "198.51.100.255"),
                ),
            )
        assert len(result.evidence) == 1
        assert result.evidence[0].source_url == "https://rir-b.test/ip/198.51.100.1"
        assert contacted == ["rir-b.test"]
        assert "TOPSECRET" not in caplog.text
        assert "QUERYSECRET" not in caplog.text
        assert all("TOPSECRET" not in e.message for e in result.errors)
