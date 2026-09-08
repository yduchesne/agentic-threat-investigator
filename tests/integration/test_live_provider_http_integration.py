# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests for live providers through an in-process ASGI boundary.

Every provider request traverses a real ``httpx.AsyncClient`` over
``httpx.ASGITransport`` into an ATI-authored FastAPI stub application that
dispatches synthetic behavior by request host and path. No public internet
access, host-port listener, or credential occurs. A narrow fail-closed
transport wrapper rejects any host outside the test allowlist before the
ASGI application handles the request.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.infrastructure.providers.abuseipdb import (
    AbuseIpdbProvider,
)
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from agentic_threat_investigator.infrastructure.providers.ipinfo_lite import (
    IpinfoLiteProvider,
)
from agentic_threat_investigator.infrastructure.providers.rdap import RdapProvider

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
]

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
_GOOGLE_DNS_HOST = "dns.google"
_IANA_HOST = "data.iana.org"
_IPINFO_HOST = "api.ipinfo.io"
_ABUSEIPDB_HOST = "api.abuseipdb.com"
_FAKE_IPINFO_TOKEN = "fake-test-token"

_DNS_ACCEPT = "application/json, application/dns-json"
_IANA_ACCEPT = "application/json"
_RDAP_ACCEPT = "application/rdap+json, application/json"
_IPINFO_ACCEPT = "application/json"
_ABUSEIPDB_ACCEPT = "application/json"
_FAKE_ABUSEIPDB_KEY = "fake-test-abuseipdb-key"
_SYNTHETIC_IPV4 = "192.0.2.39"
"""ATI-authored synthetic RFC 5737 documentation address for AbuseIPDB fixtures."""


async def _no_op_sleep(_: float) -> None:
    """Non-blocking async sleep replacement for integration tests."""


def _zero_jitter() -> float:
    """Deterministic zero-offset jitter callable."""
    return 0.5


# -- ASGI stub upstream application ---------------------------------------


def _build_stub_app() -> FastAPI:
    """Build the synthetic upstream FastAPI application.

    Virtual upstreams are dispatched by request host and path inside real
    ASGI routes. Each route records the request on ``app.state`` so tests
    can prove requests traversed the ASGI application boundary, and each
    route asserts the exact method, User-Agent, and Accept headers.
    """
    app = FastAPI()
    state = app.state
    # (query name, rr type) -> payload dict, list of sequential Response
    # objects (last repeats), or None to use ``dns_default``.
    dns_responses: dict[tuple[str, str], Any] = {}
    bootstrap_registries: dict[str, dict[str, Any]] = {}
    rdap_responses: dict[tuple[str, str], dict[str, Any]] = {}
    ipinfo_responses: dict[str, Any] = {}
    abuseipdb_responses: dict[str, Any] = {}
    state.dns_requests = []
    state.dns_responses = dns_responses
    state.dns_default = None
    state.bootstrap_requests = []
    state.bootstrap_registries = bootstrap_registries
    state.rdap_requests = []
    state.rdap_responses = rdap_responses
    state.ipinfo_requests = []
    state.ipinfo_responses = ipinfo_responses
    state.abuseipdb_requests = []
    state.abuseipdb_responses = abuseipdb_responses

    @app.get("/resolve")
    async def dns_resolve(
        request: Request,
        name: str = Query(...),
        rrtype: str = Query(default="", alias="type"),
    ) -> Response:
        """Serve synthetic Google DNS JSON responses for /resolve."""
        state.dns_requests.append(request)
        assert "AgenticThreatInvestigator" in request.headers["User-Agent"]
        assert request.headers["Accept"] == _DNS_ACCEPT
        assert "edns_client_subnet" not in request.query_params
        entry = state.dns_responses.get((name, rrtype), state.dns_default)
        assert entry is not None, f"no stub DNS response for {(name, rrtype)!r}"
        if isinstance(entry, Response):
            return entry
        if isinstance(entry, list):
            response: Response = entry.pop(0) if len(entry) > 1 else entry[0]
            return response
        return JSONResponse(content=entry)

    @app.get("/rdap/{registry}.json")
    async def iana_bootstrap(request: Request, registry: str) -> Response:
        """Serve synthetic IANA bootstrap registry files."""
        state.bootstrap_requests.append(request)
        assert "AgenticThreatInvestigator" in request.headers["User-Agent"]
        assert request.headers["Accept"] == _IANA_ACCEPT
        payload = state.bootstrap_registries.get(registry)
        assert payload is not None, f"no stub bootstrap registry for {registry!r}"
        return JSONResponse(payload)

    @app.get("/lite/{ip}")
    async def ipinfo_lite_lookup(request: Request, ip: str) -> Response:
        """Serve synthetic IPinfo Lite responses for the /lite lookup path."""
        state.ipinfo_requests.append(request)
        assert "AgenticThreatInvestigator" in request.headers["User-Agent"]
        assert request.headers["Accept"] == _IPINFO_ACCEPT
        assert request.method == "GET"
        assert request.headers["Authorization"] == f"Bearer {_FAKE_IPINFO_TOKEN}"
        # The access token must never travel in the URL query string.
        assert "token" not in request.url.query
        assert not request.url.query
        entry = state.ipinfo_responses.get(ip)
        assert entry is not None, f"no stub IPinfo response for {ip!r}"
        if isinstance(entry, Response):
            return entry
        if isinstance(entry, list):
            response: Response = entry.pop(0) if len(entry) > 1 else entry[0]
            return response
        return JSONResponse(content=entry)

    @app.get("/api/v2/check")
    async def abuseipdb_check(request: Request) -> Response:
        """Serve synthetic AbuseIPDB check responses for /api/v2/check."""
        state.abuseipdb_requests.append(request)
        assert "AgenticThreatInvestigator" in request.headers["User-Agent"]
        assert request.headers["Accept"] == _ABUSEIPDB_ACCEPT
        assert request.method == "GET"
        assert request.headers["Key"] == _FAKE_ABUSEIPDB_KEY
        # The API key must never travel in the URL query string.
        assert "key" not in request.url.query
        # ``verbose`` must be present; its wire representation is not
        # asserted beyond presence.
        assert "verbose" in request.query_params
        assert "maxAgeInDays" in request.query_params
        ip = request.query_params["ipAddress"]
        entry = state.abuseipdb_responses.get(ip)
        assert entry is not None, f"no stub AbuseIPDB response for {ip!r}"
        if isinstance(entry, Response):
            return entry
        if isinstance(entry, list):
            response: Response = entry.pop(0) if len(entry) > 1 else entry[0]
            return response
        return JSONResponse(content=entry)

    @app.get("/{full_path:path}")
    async def rdap_authority(request: Request, full_path: str) -> Response:
        """Serve synthetic authoritative RDAP object responses."""
        state.rdap_requests.append(request)
        assert "AgenticThreatInvestigator" in request.headers["User-Agent"]
        assert request.headers["Accept"] == _RDAP_ACCEPT
        key = (request.url.hostname or "", "/" + full_path)
        payload = state.rdap_responses.get(key)
        assert payload is not None, f"no stub RDAP response for {key!r}"
        return JSONResponse(payload, media_type="application/rdap+json")

    return app


class HostAllowlistASGITransport(httpx.AsyncBaseTransport):
    """Fail-closed guard rejecting unapproved hosts before the ASGI app.

    Its only responsibility is the allowlist check; it never synthesizes
    provider responses. Approved requests are delegated unchanged to the
    wrapped ``httpx.ASGITransport`` driving the stub application.
    """

    def __init__(self, app: FastAPI, *, allowed_hosts: set[str]) -> None:
        self._app = app
        self._asgi_transport = httpx.ASGITransport(app=app)
        self._allowed_hosts = allowed_hosts

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Reject unapproved hosts, then delegate to the ASGI transport."""
        host = request.url.host
        if host not in self._allowed_hosts:
            raise RuntimeError(
                f"request to unapproved host {host!r}; allowed={self._allowed_hosts}"
            )
        return await self._asgi_transport.handle_async_request(request)

    async def aclose(self) -> None:
        """Close the wrapped ASGI transport."""
        await self._asgi_transport.aclose()


# -- DNS response payloads -------------------------------------------------

_DNS_A_RESPONSE = {
    "Status": 0,
    "TC": False,
    "RD": True,
    "RA": True,
    "Question": [{"name": "example.com.", "type": 1}],
    "Answer": [{"name": "example.com.", "type": 1, "TTL": 300, "data": "1.2.3.4"}],
}

_DNS_AAAA_RESPONSE = {
    "Status": 0,
    "TC": False,
    "RD": True,
    "RA": True,
    "Question": [{"name": "example.com.", "type": 28}],
    "Answer": [{"name": "example.com.", "type": 28, "TTL": 300, "data": "2001:db8::1"}],
}

_DNS_EMPTY_RESPONSE = {
    "Status": 0,
    "Answer": [],
}

_DNS_PTR_RESPONSE = {
    "Status": 0,
    "Question": [{"name": "1.2.0.192.in-addr.arpa.", "type": 12}],
    "Answer": [
        {
            "name": "1.2.0.192.in-addr.arpa.",
            "type": 12,
            "TTL": 300,
            "data": "host.example.com.",
        }
    ],
}

_DNS_NXDOMAIN_RESPONSE = {
    "Status": 3,
    "Question": [{"name": "nonexistent.example.", "type": 1}],
    "Answer": [],
}

# -- RDAP response payloads ------------------------------------------------

_RDAP_DOMAIN_RESPONSE = {
    "objectClassName": "domain",
    "handle": "DOM-1234",
    "ldhName": "example.com",
    "status": ["active"],
    "events": [{"eventAction": "last changed", "eventDate": "2026-01-15T00:00:00Z"}],
    "entities": [
        {
            "handle": "ENT-1",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrant"]]],
        }
    ],
}

_RDAP_IPV4_SPECIFIC_RESPONSE = {
    "objectClassName": "ip network",
    "handle": "NET-SPECIFIC-V4",
    "startAddress": "198.51.100.0",
    "endAddress": "198.51.100.255",
    "ipVersion": "v4",
    "status": ["active"],
    "cidr0_cidrs": [{"v4prefix": "198.51.100.0", "length": 24}],
}

_RDAP_IPV6_SPECIFIC_RESPONSE = {
    "objectClassName": "ip network",
    "handle": "NET-SPECIFIC-V6",
    "startAddress": "2001:db8:100::",
    "endAddress": "2001:db8:100:ffff:ffff:ffff:ffff:ffff",
    "ipVersion": "v6",
    "status": ["active"],
    "cidr0_cidrs": [{"v6prefix": "2001:db8:100::", "length": 48}],
}

_RDAP_ASN_RESPONSE = {
    "objectClassName": "autnum",
    "handle": "AS-150",
    "startAutnum": 100,
    "endAutnum": 200,
    "status": ["active"],
}


class TestDnsIntegration:
    """Domain and PTR resolution integration flows."""

    async def test_domain_returns_a_and_aaaa(self) -> None:
        """A domain query traverses the ASGI route with exact RR order and provenance."""
        expected_rr_order = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        app = _build_stub_app()
        app.state.dns_responses = {
            ("example.com", "A"): _DNS_A_RESPONSE,
            ("example.com", "AAAA"): _DNS_AAAA_RESPONSE,
            ("example.com", "CNAME"): _DNS_EMPTY_RESPONSE,
            ("example.com", "MX"): _DNS_EMPTY_RESPONSE,
            ("example.com", "NS"): _DNS_EMPTY_RESPONSE,
            ("example.com", "TXT"): _DNS_EMPTY_RESPONSE,
            ("example.com", "SOA"): _DNS_EMPTY_RESPONSE,
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_GOOGLE_DNS_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)

            assert result.provider == "urn:ati:source:google_public_dns"
            assert len(result.evidence) == 2
            a_ev = next(e for e in result.evidence if e.facts["query_type"] == "A")
            aaaa_ev = next(
                e for e in result.evidence if e.facts["query_type"] == "AAAA"
            )

            for ev in (a_ev, aaaa_ev):
                assert ev.source == "urn:ati:source:google_public_dns"
                assert ev.subject.value == "example.com"
                assert ev.subject.type == EntityType.DOMAIN
                assert ev.investigation_id == _FIXED_UUID
                assert ev.source_url == "https://dns.google/resolve"
                assert ev.retrieved_at == _FIXED_TS
                assert ev.observed_at is None
                assert ev.raw_payload is None

            assert a_ev.facts["answers"][0]["value"] == "1.2.3.4"
            assert aaaa_ev.facts["answers"][0]["value"] == "2001:db8::1"

            # Every query reached the ASGI /resolve route in exact stable
            # RR order, one query per RR type.
            assert len(app.state.dns_requests) == 7
            assert [
                request.query_params["type"] for request in app.state.dns_requests
            ] == expected_rr_order
            assert all(
                request.url.path == "/resolve" for request in app.state.dns_requests
            )

    async def test_ptr_returns_canonical_hostname(self) -> None:
        """A PTR query sends reverse-pointer domain name and normalizes hostname."""
        app = _build_stub_app()
        app.state.dns_responses = {("1.2.0.192.in-addr.arpa", "PTR"): _DNS_PTR_RESPONSE}

        transport = HostAllowlistASGITransport(app, allowed_hosts={_GOOGLE_DNS_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
            entity = Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            result = await provider.investigate(_FIXED_UUID, entity)

            assert len(app.state.dns_requests) == 1
            dns_request = app.state.dns_requests[0]
            assert dns_request.url.path == "/resolve"
            assert dns_request.query_params["name"] == "1.2.0.192.in-addr.arpa"
            assert dns_request.query_params["type"] == "PTR"
            assert len(result.evidence) == 1
            assert result.evidence[0].facts["query_type"] == "PTR"
            assert result.evidence[0].facts["answers"][0]["value"] == "host.example.com"

    async def test_nxdomain_returns_valid_miss(self) -> None:
        """NXDOMAIN short-circuits remaining queries without emitting errors."""
        app = _build_stub_app()
        app.state.dns_default = _DNS_NXDOMAIN_RESPONSE

        transport = HostAllowlistASGITransport(app, allowed_hosts={_GOOGLE_DNS_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
            entity = Entity(type=EntityType.DOMAIN, value="nonexistent.example")
            result = await provider.investigate(_FIXED_UUID, entity)

            assert len(result.evidence) == 0
            assert len(result.errors) == 0
            assert len(app.state.dns_requests) == 1


class TestRdapIntegration:
    """RDAP discovery and authority integration flows."""

    async def test_domain_bootstrap_to_authority_exact_path(self) -> None:
        """RDAP domain discovery traverses IANA and authoritative ASGI routes."""
        app = _build_stub_app()
        app.state.bootstrap_registries = {
            "dns": {
                "version": "1.0",
                "publication": "2026-01-01T00:00:00Z",
                "services": [[["com"], ["https://rdap.verisign.test/"]]],
            }
        }
        app.state.rdap_responses = {
            ("rdap.verisign.test", "/domain/example.com"): _RDAP_DOMAIN_RESPONSE
        }

        transport = HostAllowlistASGITransport(
            app, allowed_hosts={_IANA_HOST, "rdap.verisign.test"}
        )
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = RdapProvider(http, cache_seconds=3600, clock=lambda: _FIXED_TS)
            query_entity = Entity(type=EntityType.DOMAIN, value="example.com")
            outcome = await provider.investigate(_FIXED_UUID, query_entity)

            assert outcome.provider == "urn:ati:source:rdap"
            assert len(outcome.evidence) == 1
            observed_ev = outcome.evidence[0]
            assert observed_ev.type == EvidenceType.REGISTRATION
            assert (
                observed_ev.source_url
                == "https://rdap.verisign.test/domain/example.com"
            )
            assert observed_ev.retrieved_at == _FIXED_TS
            assert observed_ev.facts["handle"] == "DOM-1234"

            # Both requests traversed distinct virtual ASGI upstreams.
            assert len(app.state.bootstrap_requests) == 1
            assert app.state.bootstrap_requests[0].url.path == "/rdap/dns.json"
            assert app.state.bootstrap_requests[0].url.hostname == _IANA_HOST
            assert len(app.state.rdap_requests) == 1
            assert app.state.rdap_requests[0].url.path == "/domain/example.com"
            assert app.state.rdap_requests[0].url.hostname == "rdap.verisign.test"

    async def test_ipv4_and_ipv6_overlapping_longest_prefix(self) -> None:
        """RDAP resolves overlapping IPv4 and IPv6 prefixes to their most-specific services."""
        app = _build_stub_app()
        app.state.bootstrap_registries = {
            "ipv4": {
                "version": "1.0",
                "publication": "2026-01-01T00:00:00Z",
                "services": [
                    [["198.51.0.0/16"], ["https://generic-v4.rir.test/"]],
                    [["198.51.100.0/24"], ["https://specific-v4.rir.test/"]],
                ],
            },
            "ipv6": {
                "version": "1.0",
                "publication": "2026-01-01T00:00:00Z",
                "services": [
                    [["2001:db8::/32"], ["https://generic-v6.rir.test/"]],
                    [["2001:db8:100::/48"], ["https://specific-v6.rir.test/"]],
                ],
            },
        }
        app.state.rdap_responses = {
            ("specific-v4.rir.test", "/ip/198.51.100.42"): _RDAP_IPV4_SPECIFIC_RESPONSE,
            (
                "specific-v6.rir.test",
                "/ip/2001:db8:100::1",
            ): _RDAP_IPV6_SPECIFIC_RESPONSE,
        }

        transport = HostAllowlistASGITransport(
            app,
            allowed_hosts={
                _IANA_HOST,
                "generic-v4.rir.test",
                "specific-v4.rir.test",
                "generic-v6.rir.test",
                "specific-v6.rir.test",
            },
        )
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = RdapProvider(http, cache_seconds=3600, clock=lambda: _FIXED_TS)

            res_v4 = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="198.51.100.42")
            )
            assert len(res_v4.evidence) == 1
            assert res_v4.evidence[0].facts["handle"] == "NET-SPECIFIC-V4"
            assert all(
                request.url.hostname != "generic-v4.rir.test"
                for request in app.state.rdap_requests
            )

            res_v6 = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="2001:db8:100::1")
            )
            assert len(res_v6.evidence) == 1
            assert res_v6.evidence[0].facts["handle"] == "NET-SPECIFIC-V6"
            assert all(
                request.url.hostname != "generic-v6.rir.test"
                for request in app.state.rdap_requests
            )
            # The provider emitted the exact percent-encoded IPv6 request URL.
            assert (
                res_v6.evidence[0].source_url
                == f"https://specific-v6.rir.test/ip/{quote('2001:db8:100::1', safe='')}"
            )
            # The decoded path reached the correct ASGI route on the
            # most-specific (never the generic) virtual RDAP upstream.
            assert [
                (request.url.hostname, request.url.path)
                for request in app.state.rdap_requests
            ] == [
                ("specific-v4.rir.test", "/ip/198.51.100.42"),
                ("specific-v6.rir.test", "/ip/2001:db8:100::1"),
            ]

    async def test_asn_inclusive_range_and_decimal_path(self) -> None:
        """ASN discovery strips AS prefix, tests boundary, and queries /autnum/{decimal}."""
        app = _build_stub_app()
        app.state.bootstrap_registries = {
            "asn": {
                "version": "1.0",
                "publication": "2026-01-01T00:00:00Z",
                "services": [[["100-200"], ["https://asn-registry.test/"]]],
            }
        }
        app.state.rdap_responses = {
            ("asn-registry.test", "/autnum/100"): _RDAP_ASN_RESPONSE
        }

        transport = HostAllowlistASGITransport(
            app, allowed_hosts={_IANA_HOST, "asn-registry.test"}
        )
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = RdapProvider(http, cache_seconds=3600, clock=lambda: _FIXED_TS)
            entity = Entity(type=EntityType.ASN, value="AS100")
            result = await provider.investigate(_FIXED_UUID, entity)

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.facts["start_autnum"] == 100
            assert evidence.facts["end_autnum"] == 200

            # Inclusive selection queried exactly one IANA bootstrap request
            # and one authoritative request on the ASN registry virtual host.
            assert len(app.state.bootstrap_requests) == 1
            assert len(app.state.rdap_requests) == 1
            assert app.state.rdap_requests[0].url.hostname == "asn-registry.test"
            # The exact decimal path proves the AS prefix was removed and no
            # alternate path was used.
            assert app.state.rdap_requests[0].url.path == "/autnum/100"

            # The flow also proves normalization: full evidence provenance.
            assert evidence.investigation_id == _FIXED_UUID
            assert evidence.subject.value == "AS100"
            assert evidence.subject.type == EntityType.ASN
            assert evidence.source == "urn:ati:source:rdap"
            assert evidence.type == EvidenceType.REGISTRATION
            assert evidence.source_url == "https://asn-registry.test/autnum/100"

            contacted_hosts = {
                request.url.hostname
                for request in (
                    *app.state.bootstrap_requests,
                    *app.state.rdap_requests,
                )
            }
            # The generic/wrong ASN authority host is never contacted.
            assert contacted_hosts == {_IANA_HOST, "asn-registry.test"}


# -- IPinfo Lite response payloads ------------------------------------------

_IPINFO_IPV4_RESPONSE = {
    "ip": "8.8.8.8",
    "asn": "AS15169",
    "as_name": "Google LLC",
    "as_domain": "google.com",
    "country_code": "US",
    "country": "United States",
    "continent_code": "NA",
    "continent": "North America",
}

_IPINFO_IPV6_RESPONSE = {
    "ip": "2001:db8::1",
    "asn": "AS123",
    "as_name": "Example Operator",
    "country_code": "NL",
    "country": "Netherlands",
}

_ABUSEIPDB_CHECK_RESPONSE = {
    "data": {
        "ipAddress": _SYNTHETIC_IPV4,
        "isPublic": False,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 100,
        "countryCode": "US",
        "usageType": "Documentation Network",
        "isp": "Example Network Operator",
        "domain": "example.invalid",
        "hostnames": [],
        "isTor": False,
        "totalReports": 1,
        "numDistinctUsers": 1,
        "lastReportedAt": "2026-01-15T12:00:00+00:00",
        "reports": [
            {
                "reportedAt": "2026-01-15T12:00:00+00:00",
                "comment": "synthetic ignored report comment",
                "categories": [18, 22],
                "reporterId": 1,
                "reporterCountryCode": "US",
                "reporterCountryName": "United States",
            }
        ],
    }
}

_ABUSEIPDB_IPV6_RESPONSE = {
    "data": {
        "ipAddress": "2001:db8::1",
        "isPublic": True,
        "ipVersion": 6,
        "isWhitelisted": None,
        "abuseConfidenceScore": 0,
        "isTor": False,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
        "reports": [],
    }
}


class TestIpinfoLiteIntegration:
    """IPinfo Lite lookup integration flows over the ASGI boundary."""

    async def test_ipv4_lookup_traverses_asgi_route_with_bearer_header(self) -> None:
        """An IPv4 lookup sends the exact path and Bearer header and normalizes facts."""
        app = _build_stub_app()
        app.state.ipinfo_responses = {"8.8.8.8": _IPINFO_IPV4_RESPONSE}

        transport = HostAllowlistASGITransport(app, allowed_hosts={_IPINFO_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = IpinfoLiteProvider(
                http, token=_FAKE_IPINFO_TOKEN, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )

            assert len(app.state.ipinfo_requests) == 1
            request = app.state.ipinfo_requests[0]
            assert request.method == "GET"
            assert request.url.path == "/lite/8.8.8.8"
            assert request.headers["Accept"] == _IPINFO_ACCEPT
            assert request.headers["Authorization"] == f"Bearer {_FAKE_IPINFO_TOKEN}"
            assert not request.url.query

            assert result.provider == "urn:ati:source:ipinfo_lite"
            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.type == EvidenceType.NETWORK
            assert evidence.investigation_id == _FIXED_UUID
            assert evidence.subject.value == "8.8.8.8"
            assert evidence.subject.type == EntityType.IP_ADDRESS
            assert evidence.source == "urn:ati:source:ipinfo_lite"
            assert evidence.source_url == "https://api.ipinfo.io/lite/8.8.8.8"
            assert evidence.retrieved_at == _FIXED_TS
            assert evidence.observed_at is None
            assert evidence.raw_payload is None
            assert evidence.facts == {
                "ip": "8.8.8.8",
                "asn": "AS15169",
                "as_name": "Google LLC",
                "as_domain": "google.com",
                "country_code": "US",
                "country": "United States",
                "continent_code": "NA",
                "continent": "North America",
            }
            # The fake token never reaches evidence provenance or facts.
            assert _FAKE_IPINFO_TOKEN not in str(evidence.source_url)
            assert _FAKE_IPINFO_TOKEN not in str(evidence.facts)

    async def test_ipv6_lookup_percent_encoded_path(self) -> None:
        """An IPv6 lookup percent-encodes the path and normalizes canonical facts."""
        app = _build_stub_app()
        app.state.ipinfo_responses = {"2001:db8::1": _IPINFO_IPV6_RESPONSE}

        transport = HostAllowlistASGITransport(app, allowed_hosts={_IPINFO_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = IpinfoLiteProvider(
                http, token=_FAKE_IPINFO_TOKEN, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value="2001:0DB8:0000::1"),
            )

            assert len(app.state.ipinfo_requests) == 1
            request = app.state.ipinfo_requests[0]
            assert request.url.path == "/lite/2001:db8::1"

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.subject.value == "2001:db8::1"
            assert evidence.facts["ip"] == "2001:db8::1"
            assert evidence.facts["asn"] == "AS123"
            assert evidence.facts["country_code"] == "NL"
            assert "continent" not in evidence.facts
            # Provider provenance retains the exact percent-encoded IPv6 URL.
            assert (
                evidence.source_url == f"https://{_IPINFO_HOST}/lite/2001%3Adb8%3A%3A1"
            )

    async def test_401_produces_single_attempt_typed_error(self) -> None:
        """A 401 yields non-retryable AUTHENTICATION_FAILED on exactly one attempt."""
        app = _build_stub_app()
        app.state.ipinfo_responses = {
            "8.8.8.8": JSONResponse(status_code=401, content={})
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_IPINFO_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = IpinfoLiteProvider(
                http, token=_FAKE_IPINFO_TOKEN, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )

            assert len(app.state.ipinfo_requests) == 1
            assert len(result.evidence) == 0
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.AUTHENTICATION_FAILED
            assert result.errors[0].retryable is False

    async def test_429_exhausts_retries_with_exact_attempt_count(self) -> None:
        """A persistent 429 exhausts retries on exact attempts without real sleeping."""
        app = _build_stub_app()
        app.state.ipinfo_responses = {
            "8.8.8.8": JSONResponse(
                status_code=429, headers={"Retry-After": "30"}, content={}
            )
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_IPINFO_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            policy = ProviderHttpPolicy(max_retries=1, base_delay_seconds=0.01)
            http = ProviderHttpClient(
                client=client,
                policy=policy,
                sleep=_no_op_sleep,
                jitter_fn=_zero_jitter,
            )
            provider = IpinfoLiteProvider(
                http, token=_FAKE_IPINFO_TOKEN, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )

            assert len(app.state.ipinfo_requests) == 2
            assert len(result.evidence) == 0
            assert result.errors[0].code == ProviderErrorCode.RATE_LIMITED
            assert result.errors[0].retry_after_seconds == 30


class TestAbuseIpdbIntegration:
    """AbuseIPDB check integration flows over the ASGI boundary."""

    async def test_ipv4_lookup_traverses_asgi_route_with_key_header(self) -> None:
        """An IPv4 lookup sends the exact query params and Key header and normalizes facts."""
        app = _build_stub_app()
        app.state.abuseipdb_responses = {_SYNTHETIC_IPV4: _ABUSEIPDB_CHECK_RESPONSE}

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=_SYNTHETIC_IPV4)
            )

            assert len(app.state.abuseipdb_requests) == 1
            request = app.state.abuseipdb_requests[0]
            assert request.method == "GET"
            assert request.url.path == "/api/v2/check"
            assert request.headers["Accept"] == _ABUSEIPDB_ACCEPT
            assert request.headers["Key"] == _FAKE_ABUSEIPDB_KEY
            assert request.query_params["ipAddress"] == _SYNTHETIC_IPV4
            assert request.query_params["maxAgeInDays"] == "30"
            assert "verbose" in request.query_params
            # The API key must never travel in the URL.
            assert _FAKE_ABUSEIPDB_KEY not in str(request.url)

            assert result.provider == "urn:ati:source:abuseipdb"
            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.type == EvidenceType.REPUTATION
            assert evidence.investigation_id == _FIXED_UUID
            assert evidence.subject.value == _SYNTHETIC_IPV4
            assert evidence.subject.type == EntityType.IP_ADDRESS
            assert evidence.source == "urn:ati:source:abuseipdb"
            assert evidence.source_url == "https://api.abuseipdb.com/api/v2/check"
            assert evidence.retrieved_at == _FIXED_TS
            # observed_at is the normalized lastReportedAt source fact.
            assert evidence.observed_at == datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
            assert evidence.raw_payload is None
            facts = evidence.facts
            assert set(facts) == {
                "ip_address",
                "is_public",
                "ip_version",
                "is_whitelisted",
                "abuse_confidence_score",
                "is_tor",
                "total_reports",
                "num_distinct_users",
                "last_reported_at",
                "max_age_in_days",
                "reports",
            }
            assert facts["ip_address"] == _SYNTHETIC_IPV4
            assert facts["is_public"] is False
            assert facts["ip_version"] == 4
            assert facts["is_whitelisted"] is False
            assert facts["abuse_confidence_score"] == 100
            assert facts["is_tor"] is False
            assert facts["total_reports"] == 1
            assert facts["num_distinct_users"] == 1
            assert facts["last_reported_at"] == "2026-01-15T12:00:00+00:00"
            assert facts["max_age_in_days"] == 30
            reports_fact = facts["reports"]
            assert len(reports_fact) == 1
            assert set(reports_fact[0]) == {"reported_at", "categories"}
            assert reports_fact[0]["reported_at"] == "2026-01-15T12:00:00+00:00"
            assert list(reports_fact[0]["categories"]) == [18, 22]
            # Ignored upstream geography/network/comment/reporter data and
            # derived labels never reach the normalized facts.
            serialized = str(facts)
            for fragment in (
                "country",
                "usage",
                "isp",
                "domain",
                "hostname",
                "comment",
                "reporter",
                "category_labels",
            ):
                assert fragment not in serialized
            # The fake key never reaches evidence provenance or facts.
            assert _FAKE_ABUSEIPDB_KEY not in str(evidence.source_url)
            assert _FAKE_ABUSEIPDB_KEY not in str(evidence.facts)

    async def test_ipv6_lookup_zero_score_is_success_not_benign(self) -> None:
        """An IPv6 zero-score lookup succeeds and retains the score facts."""
        app = _build_stub_app()
        app.state.abuseipdb_responses = {"2001:db8::1": _ABUSEIPDB_IPV6_RESPONSE}

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value="2001:0DB8:0000::1"),
            )

            request = app.state.abuseipdb_requests[0]
            assert request.query_params["ipAddress"] == "2001:db8::1"

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.type == EvidenceType.REPUTATION
            assert evidence.subject.value == "2001:db8::1"
            facts = evidence.facts
            assert set(facts) == {
                "ip_address",
                "is_public",
                "ip_version",
                "is_whitelisted",
                "abuse_confidence_score",
                "is_tor",
                "total_reports",
                "num_distinct_users",
                "last_reported_at",
                "max_age_in_days",
                "reports",
            }
            assert facts["ip_address"] == "2001:db8::1"
            assert facts["ip_version"] == 6
            assert facts["is_whitelisted"] is None
            assert facts["abuse_confidence_score"] == 0
            assert facts["total_reports"] == 0
            # Null lastReportedAt is retained as a null fact.
            assert facts["last_reported_at"] is None
            assert evidence.observed_at is None
            # The empty reports array stays an explicit empty reports fact.
            assert list(facts["reports"]) == []
            assert facts["max_age_in_days"] == 30

    async def test_403_produces_single_attempt_typed_error(self) -> None:
        """A 403 yields non-retryable FORBIDDEN on exactly one attempt."""
        app = _build_stub_app()
        app.state.abuseipdb_responses = {
            _SYNTHETIC_IPV4: JSONResponse(status_code=403, content={})
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=_SYNTHETIC_IPV4)
            )

            assert len(app.state.abuseipdb_requests) == 1
            assert len(result.evidence) == 0
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.FORBIDDEN
            assert result.errors[0].retryable is False

    async def test_persistent_5xx_exhausts_retries_with_exact_attempt_count(
        self,
    ) -> None:
        """A persistent 5xx exhausts retries and ends retryable PROVIDER_UNAVAILABLE."""
        app = _build_stub_app()
        app.state.abuseipdb_responses = {
            _SYNTHETIC_IPV4: JSONResponse(
                status_code=503, content={"error": "service unavailable"}
            )
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            policy = ProviderHttpPolicy(max_retries=2, base_delay_seconds=0.01)
            http = ProviderHttpClient(
                client=client,
                policy=policy,
                sleep=_no_op_sleep,
                jitter_fn=_zero_jitter,
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=_SYNTHETIC_IPV4)
            )

            # Exactly three attempts (initial + two retries).
            assert len(app.state.abuseipdb_requests) == 3
            assert len(result.evidence) == 0
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.PROVIDER_UNAVAILABLE
            assert result.errors[0].retryable is True

    async def test_malformed_schema_produces_typed_error(self) -> None:
        """Valid JSON with a malformed schema is a non-retryable INVALID_RESPONSE."""
        app = _build_stub_app()
        # A strict scalar violation: the abuse score is a numeric string.
        app.state.abuseipdb_responses = {
            _SYNTHETIC_IPV4: JSONResponse(
                content={
                    "data": {
                        "ipAddress": _SYNTHETIC_IPV4,
                        "isPublic": False,
                        "ipVersion": 4,
                        "isWhitelisted": False,
                        "abuseConfidenceScore": "100",
                        "isTor": False,
                        "totalReports": 0,
                        "numDistinctUsers": 0,
                        "lastReportedAt": None,
                        "reports": [],
                    }
                }
            )
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=_SYNTHETIC_IPV4)
            )

            assert len(app.state.abuseipdb_requests) == 1
            assert len(result.evidence) == 0
            assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
            assert result.errors[0].retryable is False

    async def test_identity_mismatch_produces_typed_error(self) -> None:
        """A response about a different IP is a non-retryable INVALID_RESPONSE."""
        app = _build_stub_app()
        mismatched = {
            "data": {
                "ipAddress": "192.0.2.40",
                "isPublic": False,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": 0,
                "isTor": False,
                "totalReports": 0,
                "numDistinctUsers": 0,
                "lastReportedAt": None,
                "reports": [],
            }
        }
        app.state.abuseipdb_responses = {
            _SYNTHETIC_IPV4: JSONResponse(content=mismatched)
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=_SYNTHETIC_IPV4)
            )

            assert len(app.state.abuseipdb_requests) == 1
            assert len(result.evidence) == 0
            assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
            assert result.errors[0].retryable is False

    async def test_401_produces_single_attempt_typed_error(self) -> None:
        """A 401 yields non-retryable AUTHENTICATION_FAILED on exactly one attempt."""
        app = _build_stub_app()
        app.state.abuseipdb_responses = {
            _SYNTHETIC_IPV4: JSONResponse(status_code=401, content={})
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=_SYNTHETIC_IPV4)
            )

            assert len(app.state.abuseipdb_requests) == 1
            assert len(result.evidence) == 0
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.AUTHENTICATION_FAILED
            assert result.errors[0].retryable is False

    async def test_429_exhausts_retries_with_exact_attempt_count(self) -> None:
        """A persistent 429 exhausts retries and schedules the Retry-After delay."""
        app = _build_stub_app()
        app.state.abuseipdb_responses = {
            _SYNTHETIC_IPV4: JSONResponse(
                status_code=429, headers={"Retry-After": "30"}, content={}
            )
        }
        scheduled_delays: list[float] = []

        async def _spy_sleep(seconds: float) -> None:
            """Record each requested retry delay without sleeping."""
            scheduled_delays.append(seconds)

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            policy = ProviderHttpPolicy(
                max_retries=1, base_delay_seconds=0.01, max_delay_seconds=30.0
            )
            http = ProviderHttpClient(
                client=client,
                policy=policy,
                sleep=_spy_sleep,
                jitter_fn=_zero_jitter,
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=_SYNTHETIC_IPV4)
            )

            # Exactly two attempts (initial + one retry) and exactly one
            # scheduled retry delay.
            assert len(app.state.abuseipdb_requests) == 2
            assert len(scheduled_delays) == 1
            # The Retry-After value dominates the jittered exponential
            # backoff and is clamped to the configured maximum delay cap.
            assert scheduled_delays[0] == 30.0
            assert scheduled_delays[0] <= policy.max_delay_seconds
            # The final typed error stays RATE_LIMITED and carries the
            # unmodified parsed Retry-After value.
            assert len(result.evidence) == 0
            assert result.errors[0].code == ProviderErrorCode.RATE_LIMITED
            assert result.errors[0].retry_after_seconds == 30

    async def test_malformed_json_produces_typed_error(self) -> None:
        """A malformed JSON body is a non-retryable INVALID_RESPONSE."""
        app = _build_stub_app()
        app.state.abuseipdb_responses = {
            _SYNTHETIC_IPV4: Response(
                status_code=200,
                content=b"{not json",
                media_type="application/json",
            )
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=_SYNTHETIC_IPV4)
            )

            assert len(result.evidence) == 0
            assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
            assert result.errors[0].retryable is False


class TestTransportRetryIntegration:
    """Exact attempt counts and error handling under transport retries."""

    async def test_503_transient_retry_success_exact_count(self) -> None:
        """A single query (PTR) retries once on 503 and succeeds on exact attempt 2."""
        app = _build_stub_app()
        app.state.dns_responses = {
            ("1.2.0.192.in-addr.arpa", "PTR"): [
                JSONResponse(status_code=503, content={"error": "service unavailable"}),
                JSONResponse(content=_DNS_PTR_RESPONSE),
            ]
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_GOOGLE_DNS_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            policy = ProviderHttpPolicy(max_retries=2, base_delay_seconds=0.01)
            http = ProviderHttpClient(
                client=client,
                policy=policy,
                sleep=_no_op_sleep,
                jitter_fn=_zero_jitter,
            )
            provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
            entity = Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            result = await provider.investigate(_FIXED_UUID, entity)

            assert len(result.evidence) == 1
            assert len(result.errors) == 0
            # Both attempts traversed the ASGI route: exact retry count 1.
            assert len(app.state.dns_requests) == 2

    async def test_429_exhaustion_exact_count_and_typed_error(self) -> None:
        """A persistent 429 exhausts retries on exact attempt 2 without wall-clock sleep."""
        app = _build_stub_app()
        app.state.dns_responses = {
            ("1.2.0.192.in-addr.arpa", "PTR"): JSONResponse(
                status_code=429, headers={"Retry-After": "30"}, content={}
            )
        }

        transport = HostAllowlistASGITransport(app, allowed_hosts={_GOOGLE_DNS_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            policy = ProviderHttpPolicy(max_retries=1, base_delay_seconds=0.01)
            http = ProviderHttpClient(
                client=client,
                policy=policy,
                sleep=_no_op_sleep,
                jitter_fn=_zero_jitter,
            )
            provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
            entity = Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            result = await provider.investigate(_FIXED_UUID, entity)

            assert len(result.evidence) == 0
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.RATE_LIMITED
            assert result.errors[0].retry_after_seconds == 30
            assert len(app.state.dns_requests) == 2

    async def test_unapproved_host_fails_before_asgi_app(self) -> None:
        """An unapproved host fails closed before the ASGI application handles it."""
        app = _build_stub_app()

        transport = HostAllowlistASGITransport(app, allowed_hosts={"approved.test"})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = GooglePublicDnsProvider(http)
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            with pytest.raises(RuntimeError, match="unapproved host"):
                await provider.investigate(_FIXED_UUID, entity)

            # The ASGI application saw no request at all.
            assert len(app.state.dns_requests) == 0
            assert len(app.state.bootstrap_requests) == 0
            assert len(app.state.rdap_requests) == 0


class TestNoPersistenceSideEffect:  # pylint: disable=too-few-public-methods
    """Provider invocation alone writes no evidence to the database."""

    async def test_provider_call_does_not_persist_to_database(
        self,
        integration_engine: AsyncEngine,
    ) -> None:
        """Provider invocation returns domain evidence without writing rows to ati.evidence."""
        app = _build_stub_app()
        app.state.dns_responses = {("1.2.0.192.in-addr.arpa", "PTR"): _DNS_PTR_RESPONSE}

        transport = HostAllowlistASGITransport(app, allowed_hosts={_GOOGLE_DNS_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
            entity = Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")

            async with integration_engine.connect() as conn:
                count_before = (
                    await conn.execute(text("SELECT count(*) FROM ati.evidence"))
                ).scalar_one()

            result = await provider.investigate(_FIXED_UUID, entity)

            assert len(result.evidence) == 1
            assert result.evidence[0].id is None
            assert result.evidence[0].investigation_id == _FIXED_UUID

            async with integration_engine.connect() as conn:
                count_after = (
                    await conn.execute(text("SELECT count(*) FROM ati.evidence"))
                ).scalar_one()

            assert count_before == count_after

    async def test_abuseipdb_provider_call_does_not_persist_to_database(
        self,
        integration_engine: AsyncEngine,
    ) -> None:
        """An AbuseIPDB provider invocation alone writes no evidence rows."""
        app = _build_stub_app()
        app.state.abuseipdb_responses = {_SYNTHETIC_IPV4: _ABUSEIPDB_CHECK_RESPONSE}

        transport = HostAllowlistASGITransport(app, allowed_hosts={_ABUSEIPDB_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = AbuseIpdbProvider(
                http, api_key=_FAKE_ABUSEIPDB_KEY, clock=lambda: _FIXED_TS
            )
            entity = Entity(type=EntityType.IP_ADDRESS, value=_SYNTHETIC_IPV4)

            async with integration_engine.connect() as conn:
                count_before = (
                    await conn.execute(text("SELECT count(*) FROM ati.evidence"))
                ).scalar_one()

            result = await provider.investigate(_FIXED_UUID, entity)

            assert len(result.evidence) == 1
            assert result.evidence[0].id is None
            assert result.evidence[0].investigation_id == _FIXED_UUID

            async with integration_engine.connect() as conn:
                count_after = (
                    await conn.execute(text("SELECT count(*) FROM ati.evidence"))
                ).scalar_one()

            assert count_before == count_after

    async def test_ipinfo_provider_call_does_not_persist_to_database(
        self,
        integration_engine: AsyncEngine,
    ) -> None:
        """An IPinfo Lite provider invocation alone writes no evidence rows."""
        app = _build_stub_app()
        app.state.ipinfo_responses = {"8.8.8.8": _IPINFO_IPV4_RESPONSE}

        transport = HostAllowlistASGITransport(app, allowed_hosts={_IPINFO_HOST})
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(
                client=client, sleep=_no_op_sleep, jitter_fn=_zero_jitter
            )
            provider = IpinfoLiteProvider(
                http, token=_FAKE_IPINFO_TOKEN, clock=lambda: _FIXED_TS
            )
            entity = Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")

            async with integration_engine.connect() as conn:
                count_before = (
                    await conn.execute(text("SELECT count(*) FROM ati.evidence"))
                ).scalar_one()

            result = await provider.investigate(_FIXED_UUID, entity)

            assert len(result.evidence) == 1
            assert result.evidence[0].id is None
            assert result.evidence[0].investigation_id == _FIXED_UUID

            async with integration_engine.connect() as conn:
                count_after = (
                    await conn.execute(text("SELECT count(*) FROM ati.evidence"))
                ).scalar_one()

            assert count_before == count_after
