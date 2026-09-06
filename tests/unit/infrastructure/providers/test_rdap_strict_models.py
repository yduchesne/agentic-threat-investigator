# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Strict model, boundary, and bootstrap contract tests for the RDAP provider."""

from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
from typing import Any

import httpx
import pytest
from httpx import MockTransport
from pydantic import ValidationError

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from agentic_threat_investigator.infrastructure.providers.rdap import (
    RdapBootstrapCache,
    RdapProvider,
)
from agentic_threat_investigator.infrastructure.providers.rdap_bootstrap import (
    BootstrapCacheEntry,
    BootstrapOutcome,
    BootstrapService,
)

from .rdap_contract_helpers import (
    _FIXED_UUID,
    _assert_invalid,
    _iana_then_authority_handler,
    _investigate,
)
from .rdap_payloads import (
    _bootstrap_registry,
    _rdap_autnum,
    _rdap_domain,
    _rdap_network,
    iana_registry_response,
)

# -- Strict-model payload helpers ------------------------------------------


def _domain_payload(**overrides: Any) -> dict[str, Any]:
    """A valid domain payload with overridable fields."""
    payload = _rdap_domain("example.com")
    payload.update(overrides)
    return payload


def _network_payload(**overrides: Any) -> dict[str, Any]:
    """A valid IPv4 network payload with overridable fields."""
    payload = _rdap_network("198.51.100.0", "198.51.100.255")
    payload.update(overrides)
    return payload


def _autnum_payload(**overrides: Any) -> dict[str, Any]:
    """A valid autnum payload with overridable fields."""
    payload = _rdap_autnum(500, 600)
    payload.update(overrides)
    return payload


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapStrictNestedModels:
    """Strict nested RDAP field validation cannot produce evidence."""

    async def test_malformed_link_href_type_rejected(self) -> None:
        """A non-string link href is a schema error."""
        await _assert_invalid(
            _domain_payload(links=[{"href": 123}]),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )

    async def test_malformed_link_rel_type_value_rejected(self) -> None:
        """Non-string link rel/type/value fields are schema errors."""
        for link in [
            {"href": "https://rdap.test/", "rel": 5},
            {"href": "https://rdap.test/", "type": 5},
            {"href": "https://rdap.test/", "value": 5},
        ]:
            await _assert_invalid(
                _domain_payload(links=[link]),
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )

    async def test_malformed_notice_and_remark_descriptions_rejected(self) -> None:
        """Wrong notice/remark description shapes are schema errors."""
        for field in ("notices", "remarks"):
            await _assert_invalid(
                _domain_payload(**{field: [{"description": "single string"}]}),
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )
            await _assert_invalid(
                _domain_payload(**{field: [{"description": [123]}]}),
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )

    async def test_malformed_nameserver_shape_rejected(self) -> None:
        """Wrong nameserver shapes and invalid supplied names are schema errors."""
        for nameservers in [
            [{"ldhName": 5}],
            [{"unicodeName": 5}],
            [{"ldhName": "bad_name.example"}],
            [{"ldhName": "bad label.example"}],
            [{"ldhName": "a..b.example"}],
            [{"ldhName": "ns1.example.com", "unicodeName": "other.example"}],
        ]:
            await _assert_invalid(
                _domain_payload(nameservers=nameservers),
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )

    async def test_malformed_vcard_container_rejected(self) -> None:
        """Wrong or short vCard container shapes are schema errors, never IndexError."""
        for vcard in [
            "notalist",
            [],
            ["vcard"],
            ["notvcard", []],
            ["vcard", "notalist"],
            ["vcard", [], "extra"],
            [["vcard"], []],
        ]:
            await _assert_invalid(
                _domain_payload(entities=[{"handle": "E1", "vcardArray": vcard}]),
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )

    async def test_minimal_valid_vcard_container_extracts_display_name(self) -> None:
        """A minimal two-element vCard container still yields its display name."""
        payload = _domain_payload(
            entities=[
                {
                    "handle": "E1",
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Minimal Admin"]]],
                }
            ]
        )
        result = await _investigate(
            _iana_then_authority_handler(payload),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert len(result.evidence) == 1
        assert (
            result.evidence[0].facts["entities"][0]["display_name"] == "Minimal Admin"
        )

    async def test_malformed_vcard_fn_values_omitted(self) -> None:
        """Malformed individual fn values are omitted, not turned into evidence."""
        for fn_value in [123, "x" * 300, "   "]:
            payload = _domain_payload(
                entities=[
                    {
                        "handle": "E1",
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [["fn", {}, "text", fn_value]]],
                    }
                ]
            )
            result = await _investigate(
                _iana_then_authority_handler(payload),
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )
            assert len(result.evidence) == 1
            assert "display_name" not in result.evidence[0].facts["entities"][0]

    async def test_cidr0_discriminator_rejected(self) -> None:
        """CIDR0 entries need exactly one family discriminator."""
        for cidr in [
            {"v4prefix": "198.51.100.0", "v6prefix": "2001:db8::", "length": 24},
            {"length": 24},
        ]:
            await _assert_invalid(
                _network_payload(cidr0_cidrs=[cidr]),
                Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
            )

    async def test_cidr0_wrong_length_types_and_range_rejected(self) -> None:
        """Bool/string lengths and out-of-range prefixes are schema errors."""
        for cidr in [
            {"v4prefix": "198.51.100.0", "length": "24"},
            {"v4prefix": "198.51.100.0", "length": True},
            {"v4prefix": "198.51.100.0", "length": 33},
        ]:
            await _assert_invalid(
                _network_payload(cidr0_cidrs=[cidr]),
                Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
            )

    async def test_cidr0_wrong_family_rejected(self) -> None:
        """A v4 discriminator with an IPv6 prefix is a schema error."""
        await _assert_invalid(
            _network_payload(cidr0_cidrs=[{"v4prefix": "2001:db8::", "length": 32}]),
            Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
        )

    async def test_unrelated_cidr0_network_rejected(self) -> None:
        """A CIDR0 entry outside the authoritative range is a contradiction."""
        await _assert_invalid(
            _network_payload(cidr0_cidrs=[{"v4prefix": "203.0.113.0", "length": 24}]),
            Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
        )

    async def test_domain_ldh_name_with_multiple_terminal_dots_rejected(self) -> None:
        """A domain ldhName with multiple terminal dots is INVALID_RESPONSE."""
        await _assert_invalid(
            _domain_payload(ldhName="example.com.."),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )

    async def test_nameserver_ldh_name_with_multiple_terminal_dots_rejected(
        self,
    ) -> None:
        """A nameserver ldhName with multiple terminal dots is INVALID_RESPONSE."""
        await _assert_invalid(
            _domain_payload(nameservers=[{"ldhName": "ns1.example.com.."}]),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )

    async def test_missing_network_identity_fields_rejected(self) -> None:
        """Missing startAddress, endAddress, or ipVersion are schema errors."""
        for field in ("startAddress", "endAddress", "ipVersion"):
            payload = _network_payload()
            del payload[field]
            await _assert_invalid(
                payload,
                Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
            )

    async def test_missing_autnum_identity_fields_rejected(self) -> None:
        """Missing startAutnum or endAutnum are schema errors."""
        for field in ("startAutnum", "endAutnum"):
            payload = _autnum_payload()
            del payload[field]
            await _assert_invalid(
                payload,
                Entity(type=EntityType.ASN, value="AS500"),
            )

    async def test_string_autnum_rejected(self) -> None:
        """Strict models reject string coercion for autnum boundaries."""
        await _assert_invalid(
            _autnum_payload(startAutnum="500"),
            Entity(type=EntityType.ASN, value="AS500"),
        )

    async def test_invalid_ascii_domain_input_rejected_without_io(self) -> None:
        """Spaces and underscores in queried domain names never reach HTTP."""

        def _guard(_: httpx.Request) -> httpx.Response:
            raise AssertionError("HTTP request issued for an invalid domain")

        for bad_value in ["bad label.com", "bad_label.com", "a..b.com"]:
            transport = MockTransport(_guard)
            async with httpx.AsyncClient(transport=transport) as client:
                provider = RdapProvider(ProviderHttpClient(client=client))
                result = await provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.DOMAIN, value=bad_value)
                )
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR

    async def test_no_entity_or_link_recursion(self) -> None:
        """Response links and entities never trigger additional lookups."""
        request_paths: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            request_paths.append(request.url.path)
            if request.url.host == "data.iana.org":
                return iana_registry_response([[["com"], ["https://rdap.test/"]]])
            payload = _domain_payload(
                links=[
                    {
                        "href": "https://rdap.test/entity/REG-1",
                        "rel": "related",
                    }
                ],
                entities=[
                    {
                        "handle": "REG-1",
                        "roles": ["registrant"],
                        "links": [
                            {"href": "https://rdap.test/entity/REG-1", "rel": "self"}
                        ],
                    }
                ],
            )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=payload,
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert request_paths == ["/rdap/dns.json", "/domain/example.com"]
        assert len(result.evidence) == 1


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapEventActorContract:
    """RDAP event-actor validation, normalization, and safety contract."""

    async def test_event_actor_normalization_policy(self) -> None:
        """A valid actor is trimmed into the fact; blank and missing actors omitted."""
        payload = _domain_payload(
            events=[
                {
                    "eventAction": "registration",
                    "eventDate": "2020-01-01T00:00:00Z",
                    "eventActor": "  REG-ADMIN-1  ",
                },
                {
                    "eventAction": "transfer",
                    "eventDate": "2021-01-01T00:00:00Z",
                    "eventActor": "   ",
                },
                {
                    "eventAction": "expiration",
                    "eventDate": "2030-01-01T00:00:00Z",
                },
            ]
        )
        result = await _investigate(
            _iana_then_authority_handler(payload),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert len(result.evidence) == 1
        events = result.evidence[0].facts["events"]
        assert events[0] == {
            "action": "registration",
            "date": "2020-01-01T00:00:00+00:00",
            "actor": "REG-ADMIN-1",
        }
        assert "actor" not in events[1]
        assert "actor" not in events[2]

    async def test_overlong_event_actor_omitted(self) -> None:
        """An actor over the bounded event-text length is omitted, not rejected."""
        payload = _domain_payload(
            events=[
                {
                    "eventAction": "registration",
                    "eventDate": "2020-01-01T00:00:00Z",
                    "eventActor": "A" * 65,
                }
            ]
        )
        result = await _investigate(
            _iana_then_authority_handler(payload),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert len(result.evidence) == 1
        events = result.evidence[0].facts["events"]
        assert events[0]["action"] == "registration"
        assert "actor" not in events[0]

    async def test_malformed_event_actor_type_rejected(self) -> None:
        """A non-string eventActor is a schema error, not silently ignored."""
        for bad_actor in [42, ["REG-1"], {"handle": "REG-1"}, True]:
            await _assert_invalid(
                _domain_payload(
                    events=[
                        {
                            "eventAction": "registration",
                            "eventDate": "2020-01-01T00:00:00Z",
                            "eventActor": bad_actor,
                        }
                    ]
                ),
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )

    async def test_event_actor_does_not_trigger_entity_lookup(self) -> None:
        """A provider-supplied actor never causes entity lookup or relationship work."""
        request_paths: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            request_paths.append(request.url.path)
            if request.url.host == "data.iana.org":
                return iana_registry_response([[["com"], ["https://rdap.test/"]]])
            payload = _domain_payload(
                events=[
                    {
                        "eventAction": "registration",
                        "eventDate": "2020-01-01T00:00:00Z",
                        "eventActor": "https://rdap.test/entity/REG-1",
                    }
                ]
            )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=payload,
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert request_paths == ["/rdap/dns.json", "/domain/example.com"]
        assert len(result.evidence) == 1
        assert (
            result.evidence[0].facts["events"][0]["actor"]
            == "https://rdap.test/entity/REG-1"
        )


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapBoundaryContract:
    """Bootstrap vs authoritative boundary error classification."""

    async def test_bootstrap_timeout_distinct_from_authoritative(self) -> None:
        """A bootstrap timeout never contacts the authority and is TIMEOUT."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                raise httpx.TimeoutException("bootstrap timed out")
            raise AssertionError("authority must not be contacted")

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client, max_retries=0))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert result.errors[0].code == ProviderErrorCode.TIMEOUT

    async def test_authoritative_timeout_after_successful_bootstrap(self) -> None:
        """A timeout from the authority is TIMEOUT after bootstrap succeeded."""
        authority_hits = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal authority_hits
            if request.url.host == "data.iana.org":
                return iana_registry_response([[["com"], ["https://rdap.test/"]]])
            authority_hits += 1
            raise httpx.TimeoutException("authority timed out")

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client, max_retries=0))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert authority_hits == 1
        assert result.errors[0].code == ProviderErrorCode.TIMEOUT

    async def test_bootstrap_network_error_classification(self) -> None:
        """A bootstrap transport failure is PROVIDER_UNAVAILABLE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("bootstrap unreachable")

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client, max_retries=0))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert result.errors[0].code == ProviderErrorCode.PROVIDER_UNAVAILABLE

    async def test_authoritative_network_error_classification(self) -> None:
        """An authoritative transport failure is PROVIDER_UNAVAILABLE."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return iana_registry_response([[["com"], ["https://rdap.test/"]]])
            raise httpx.ConnectError("authority unreachable")

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client, max_retries=0))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert result.errors[0].code == ProviderErrorCode.PROVIDER_UNAVAILABLE

    async def test_malformed_json_at_both_boundaries(self) -> None:
        """Malformed JSON at bootstrap or authority is INVALID_RESPONSE."""
        result = await _investigate(
            _iana_then_authority_handler(
                bootstrap_content=b"{not json",
                authority_content=b'{"objectClassName": "domain"}',
            ),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].message == "malformed JSON"

        result = await _investigate(
            _iana_then_authority_handler(authority_content=b"{not json"),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].message == "malformed JSON"

    async def test_oversized_responses_at_both_boundaries(self) -> None:
        """Oversized bootstrap and authority bodies are INVALID_RESPONSE."""
        big_payload = "x" * 500
        result = await _investigate(
            _iana_then_authority_handler(
                bootstrap_payload={
                    "version": "1.0",
                    "publication": big_payload,
                    "services": [],
                }
            ),
            Entity(type=EntityType.DOMAIN, value="example.com"),
            max_response_bytes=100,
        )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

        result = await _investigate(
            _iana_then_authority_handler(_domain_payload(unicodeName=big_payload)),
            Entity(type=EntityType.DOMAIN, value="example.com"),
            max_response_bytes=100,
        )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_missing_content_type_at_both_boundaries(self) -> None:
        """A missing Content-Type header is rejected at each boundary."""

        def _bootstrap_no_content_type(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b'{"version": "1.0", "publication": "x", "services": []}',
            )

        result = await _investigate(
            _bootstrap_no_content_type,
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert "content type" in result.errors[0].message

        def _authority_no_content_type(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return iana_registry_response([[["com"], ["https://rdap.test/"]]])
            return httpx.Response(200, content=b"{}")

        result = await _investigate(
            _authority_no_content_type,
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert "content type" in result.errors[0].message

    async def test_exhausted_authoritative_5xx_exact_attempts(self) -> None:
        """A persistent authoritative 5xx exhausts exactly max_retries + 1 hits."""
        authority_hits = 0
        bootstrap_hits = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal authority_hits, bootstrap_hits
            if request.url.host == "data.iana.org":
                bootstrap_hits += 1
                return iana_registry_response([[["com"], ["https://rdap.test/"]]])
            authority_hits += 1
            return httpx.Response(503, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(
                ProviderHttpClient(
                    client=client,
                    max_retries=2,
                    base_delay_seconds=0.01,
                    jitter_fn=lambda: 0.5,
                )
            )
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert bootstrap_hits == 1
        assert authority_hits == 3
        assert result.errors[0].code == ProviderErrorCode.PROVIDER_UNAVAILABLE

    async def test_first_valid_https_authority_url(self) -> None:
        """The first valid HTTPS URL of the matched service is selected."""
        requested_hosts: list[str | None] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            requested_hosts.append(request.url.host)
            if request.url.host == "data.iana.org":
                return iana_registry_response(
                    [
                        [
                            ["com"],
                            ["https://bad host/", "https://rdap-valid.test/"],
                        ]
                    ]
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=_domain_payload(),
            )

        result = await _investigate(
            _handler, Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert "rdap-valid.test" in requested_hosts
        assert len(result.evidence) == 1
        assert (
            result.evidence[0].source_url
            == "https://rdap-valid.test/domain/example.com"
        )

    async def test_domain_and_asn_fallback_record_ids(self) -> None:
        """Blank handles fall back to normalized identity for domain and ASN."""
        result = await _investigate(
            _iana_then_authority_handler(_domain_payload(handle="")),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
        assert result.evidence[0].source_record_id == "example.com"

        result = await _investigate(
            _iana_then_authority_handler(
                _autnum_payload(handle=""),
                bootstrap_payload=_bootstrap_registry(
                    [[["500-600"], ["https://rdap.test/"]]]
                ),
            ),
            Entity(type=EntityType.ASN, value="AS500"),
        )
        assert result.evidence[0].source_record_id == "AS500-600"


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapBootstrapCacheContract:
    """Bootstrap registry cache semantics and immutability."""

    async def test_empty_registry_is_valid_no_match(self) -> None:
        """An empty services list is valid and yields NOT_FOUND, not a schema error."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"version": "1.0", "publication": "2026-01-01", "services": []},
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert result.errors[0].code == ProviderErrorCode.NOT_FOUND

    async def test_multi_label_dns_key_rejected(self) -> None:
        """DNS bootstrap keys must be exactly one canonical final label."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_bootstrap_registry(
                    [[["sub.example.com"], ["https://rdap.test/"]]]
                ),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_wrong_family_cidr_key_rejected(self) -> None:
        """An IPv6 key inside the ipv4 registry is a schema error."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_bootstrap_registry([[["2001:db8::/32"], ["https://rdap.test/"]]]),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_reversed_asn_range_key_rejected(self) -> None:
        """A reversed ASN bootstrap range is a schema error."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_bootstrap_registry([[["600-500"], ["https://rdap.test/"]]]),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.ASN, value="AS550")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_service_must_be_exactly_two_elements(self) -> None:
        """Services with wrong arity are schema errors."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_bootstrap_registry([[["com"]]]),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_missing_services_field_rejected(self) -> None:
        """A registry without a services field is a schema error."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"version": "1.0", "publication": "2026-01-01"},
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_ambiguity_uses_normalized_selected_url(self) -> None:
        """Same selected normalized URL is unambiguous despite different fallbacks."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return iana_registry_response(
                    [
                        [
                            ["198.51.100.0/24"],
                            ["https://rir-a.test/", "https://fallback-a.invalid/"],
                        ],
                        [
                            ["198.51.100.0/24"],
                            ["https://rir-a.test", "https://fallback-b.invalid/"],
                        ],
                    ]
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/rdap+json"},
                json=_rdap_network("198.51.100.0", "198.51.100.255"),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1")
            )
        assert len(result.evidence) == 1

    async def test_ambiguity_when_selected_urls_differ(self) -> None:
        """Distinct selected normalized URLs are still ambiguous."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "data.iana.org":
                return iana_registry_response(
                    [
                        [["198.51.100.0/24"], ["https://rir-a.test/"]],
                        [["198.51.100.0/24"], ["https://rir-b.test/"]],
                    ]
                )
            raise AssertionError("ambiguous registry must not contact an authority")

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = RdapProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1")
            )
        assert any(
            e.code == ProviderErrorCode.INVALID_RESPONSE and "ambiguous" in e.message
            for e in result.errors
        )

    async def test_cache_entry_is_immutable(self) -> None:
        """Cached registry entries reject mutation attempts."""
        entry = BootstrapCacheEntry(services=(), expires_at=1.0)
        assert isinstance(entry.services, tuple)
        with pytest.raises(FrozenInstanceError):
            entry.expires_at = 2.0  # type: ignore[misc]

        service = BootstrapService(keys=("com",), urls=("https://rdap.test/",))
        with pytest.raises(ValidationError):
            service.keys = ("net",)

    async def test_independent_registry_refresh_concurrency(self) -> None:
        """Two different registries refresh concurrently under separate locks."""
        dns_started = asyncio.Event()
        ipv4_started = asyncio.Event()
        release = asyncio.Event()
        fetches: list[str] = []

        async def _handler(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            path = request.url.path
            if host == "data.iana.org":
                fetches.append(path)
                if path == "/rdap/dns.json":
                    dns_started.set()
                else:
                    ipv4_started.set()
                await release.wait()
                return iana_registry_response(
                    [[["com"], ["https://rdap.test/"]]]
                    if path == "/rdap/dns.json"
                    else [[["198.51.100.0/24"], ["https://rdap.test/"]]]
                )
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            cache = RdapBootstrapCache(ProviderHttpClient(client=client, max_retries=0))
            dns_task = asyncio.create_task(cache.find_authoritative_base("dns", "com"))
            ipv4_task = asyncio.create_task(
                cache.find_authoritative_base("ipv4", "198.51.100.1")
            )
            # Both registries must be able to start their fetch independently.
            await asyncio.wait_for(
                asyncio.gather(dns_started.wait(), ipv4_started.wait()), timeout=1.0
            )
            release.set()
            dns_outcome, ipv4_outcome = await asyncio.gather(dns_task, ipv4_task)

        assert dns_outcome.base_url == "https://rdap.test/"
        assert ipv4_outcome.base_url == "https://rdap.test/"
        assert sorted(fetches) == ["/rdap/dns.json", "/rdap/ipv4.json"]


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestDnsBootstrapSourceOrderSelection:
    """DNS selection takes the first valid HTTPS URL across matching services."""

    @staticmethod
    async def _select(services: list[Any], tld: str = "com") -> BootstrapOutcome:
        """Select a DNS base from a synthetic registry served over the mock transport."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_bootstrap_registry(services),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            cache = RdapBootstrapCache(ProviderHttpClient(client=client, max_retries=0))
            return await cache.find_authoritative_base("dns", tld)

    async def test_invalid_service_followed_by_matching_valid_service(self) -> None:
        """A matching service without valid URLs does not stop the scan."""
        outcome = await self._select(
            [
                [["com"], ["http://invalid.example/", "https://bad host/"]],
                [["com"], ["https://valid-rdap.test/"]],
            ]
        )
        assert outcome.error is None
        assert outcome.base_url == "https://valid-rdap.test/"

    async def test_first_valid_url_in_overall_source_order_wins(self) -> None:
        """Several matching services with valid URLs select the first one."""
        outcome = await self._select(
            [
                [["com"], ["https://first.test/"]],
                [["com"], ["https://second.test/"]],
            ]
        )
        assert outcome.error is None
        assert outcome.base_url == "https://first.test/"

    async def test_matching_services_without_valid_url_stay_invalid(self) -> None:
        """Matching services with no valid HTTPS URL yield INVALID_RESPONSE."""
        outcome = await self._select(
            [
                [["com"], ["http://invalid.example/"]],
                [["com"], ["https://bad host/"]],
            ]
        )
        assert outcome.base_url is None
        assert outcome.error is not None
        assert outcome.error.code == ProviderErrorCode.INVALID_RESPONSE
        assert outcome.error.retryable is False

    async def test_no_matching_tld_stays_not_found(self) -> None:
        """A TLD matched by no service key still yields NOT_FOUND."""
        outcome = await self._select(
            [
                [["net"], ["http://invalid.example/"]],
                [["org"], ["https://valid-rdap.test/"]],
            ]
        )
        assert outcome.base_url is None
        assert outcome.error is not None
        assert outcome.error.code == ProviderErrorCode.NOT_FOUND
