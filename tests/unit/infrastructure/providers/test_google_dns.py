# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Provider contract tests for GooglePublicDnsProvider."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    _NUMERIC_TO_RR_TYPE,
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _dns_response(
    status: int = 0,
    answers: list[dict[str, Any]] | None = None,
    flags: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """Helper to build a strictly typed Google DNS JSON response."""
    result: dict[str, Any] = {"Status": status}
    if flags:
        for k, v in flags.items():
            result[k] = v
    if answers is not None:
        result["Answer"] = answers
    return result


def _record(name: str, rr_type: int, data: str, ttl: int = 300) -> dict[str, Any]:
    """Helper to build a strictly typed answer record."""
    return {"name": name, "type": rr_type, "TTL": ttl, "data": data}


class _RecordingSleep:  # pylint: disable=too-few-public-methods
    """Records sleep calls for exact retry-attempt assertions."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _zero_jitter() -> float:
    """Neutral jitter value (0.5 maps to zero offset)."""
    return 0.5


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestGoogleDnsContract:
    """Deterministic provider contract tests for GooglePublicDnsProvider."""

    async def test_supports_matrix(self) -> None:
        """Only DOMAIN and IP_ADDRESS entity types are supported."""
        transport = MockTransport(lambda _: httpx.Response(200, json=_dns_response()))
        client = httpx.AsyncClient(transport=transport)
        provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))

        supported = {EntityType.DOMAIN, EntityType.IP_ADDRESS}
        for entity_type in EntityType:
            expected = entity_type in supported
            assert provider.supports(Entity(type=entity_type, value="test")) is expected

    async def test_unsupported_entity_produces_no_io(self) -> None:
        """Investigating an unsupported entity issues zero HTTP requests."""

        def _failing_handler(_: httpx.Request) -> httpx.Response:
            pytest.fail("HTTP request issued for unsupported entity")

        transport = MockTransport(_failing_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.URL, value="https://example.com")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
            assert result.errors[0].retryable is False

    async def test_invalid_entity_value_produces_no_io(self) -> None:
        """Investigating an un-canonicalizable domain issues zero HTTP requests."""

        def _failing_handler(_: httpx.Request) -> httpx.Response:
            pytest.fail("HTTP request issued for invalid entity")

        transport = MockTransport(_failing_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.DOMAIN, value="   ")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
            assert result.errors[0].retryable is False

    async def test_positive_a_record_and_provenance(self) -> None:
        """A records normalize to compressed IPv4 with complete provenance."""

        def _handler(request: httpx.Request) -> httpx.Response:
            rr_type = request.url.params.get("type")
            if rr_type == "A":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_dns_response(
                        answers=[_record("example.com.", 1, "192.0.2.1")],
                        flags={"RD": True, "RA": True},
                    ),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(
                ProviderHttpClient(client=client),
                clock=lambda: _FIXED_TS,
            )
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)

            assert result.provider == "urn:ati:source:google_public_dns"
            assert len(result.evidence) == 1
            ev = result.evidence[0]
            assert ev.type == EvidenceType.DNS
            assert ev.investigation_id == _FIXED_UUID
            assert ev.subject.value == "example.com"
            assert ev.source == "urn:ati:source:google_public_dns"
            assert ev.source_url == "https://dns.google/resolve"
            assert ev.observed_at is None
            assert ev.retrieved_at == _FIXED_TS
            assert ev.raw_payload is None
            assert ev.facts["query_name"] == "example.com"
            assert ev.facts["query_type"] == "A"
            assert ev.facts["flags"] == {"rd": True, "ra": True}
            assert ev.facts["answers"][0]["value"] == "192.0.2.1"

    async def test_positive_aaaa_record_canonical_ipv6(self) -> None:
        """AAAA records normalize to compressed lowercase IPv6 format."""
        ipv6_raw = "2001:0DB8:0000:0000:0000:0000:0000:0001"

        def _handler(request: httpx.Request) -> httpx.Response:
            rr_type = request.url.params.get("type")
            if rr_type == "AAAA":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_dns_response(answers=[_record("example.com.", 28, ipv6_raw)]),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(
                ProviderHttpClient(client=client),
                clock=lambda: _FIXED_TS,
            )
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.evidence) == 1
            assert result.evidence[0].facts["answers"][0]["value"] == "2001:db8::1"

    async def test_cname_mx_ns_txt_soa_records(self) -> None:
        """CNAME, MX, NS, TXT, and SOA records are strictly parsed and normalized."""

        def _handler(request: httpx.Request) -> httpx.Response:
            rr_type = request.url.params.get("type")
            if rr_type == "CNAME":
                data = _dns_response(
                    answers=[_record("alias.example.", 5, "canonical.example.")]
                )
            elif rr_type == "MX":
                data = _dns_response(
                    answers=[_record("example.com.", 15, "10 mail.example.com.")]
                )
            elif rr_type == "NS":
                data = _dns_response(
                    answers=[_record("example.com.", 2, "ns1.example.com.")]
                )
            elif rr_type == "TXT":
                data = _dns_response(
                    answers=[_record("example.com.", 16, "v=spf1 -all")]
                )
            elif rr_type == "SOA":
                soa_data = "ns1.example. admin.example. 20260101 7200 3600 1209600 300"
                data = _dns_response(answers=[_record("example.com.", 6, soa_data)])
            else:
                data = _dns_response()
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json=data
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(
                ProviderHttpClient(client=client),
                clock=lambda: _FIXED_TS,
            )
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)
            types_found = {e.facts["query_type"] for e in result.evidence}
            assert types_found == {"CNAME", "MX", "NS", "TXT", "SOA"}

            mx_ev = next(e for e in result.evidence if e.facts["query_type"] == "MX")
            assert mx_ev.facts["answers"][0]["preference"] == 10
            assert mx_ev.facts["answers"][0]["exchange"] == "mail.example.com"

            soa_ev = next(e for e in result.evidence if e.facts["query_type"] == "SOA")
            soa_ans = soa_ev.facts["answers"][0]
            assert soa_ans["mname"] == "ns1.example"
            assert soa_ans["rname"] == "admin.example"
            assert soa_ans["serial"] == 20260101
            assert soa_ans["expire"] == 1209600

    async def test_ptr_query_reverse_pointer(self) -> None:
        """IP address queries construct reverse-pointer domain and parse PTR answers."""
        requested_name: str | None = None

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal requested_name
            requested_name = request.url.params.get("name")
            record_data = _record(requested_name or "", 12, "host.example.com.")
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(answers=[record_data]),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.IP_ADDRESS, value="198.51.100.42")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert requested_name == "42.100.51.198.in-addr.arpa"
            assert len(result.evidence) == 1
            assert result.evidence[0].facts["query_type"] == "PTR"
            assert result.evidence[0].facts["answers"][0]["value"] == "host.example.com"

    async def test_idna_domain_canonicalization(self) -> None:
        """Internationalized domain names are converted to Punycode before I/O."""
        requested_name: str | None = None

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal requested_name
            requested_name = request.url.params.get("name")
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.DOMAIN, value="bücher.example.")
            await provider.investigate(_FIXED_UUID, entity)
            assert requested_name == "xn--bcher-kva.example"

    async def test_nxdomain_short_circuits_with_no_errors(self) -> None:
        """NXDOMAIN on the first A query short-circuits and returns zero evidence/errors."""
        call_count = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(status=3),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.DOMAIN, value="nx.example.com")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.evidence) == 0
            assert len(result.errors) == 0
            assert call_count == 1  # Only queried A, short-circuited remaining 6

    async def test_nxdomain_with_answer_is_invalid_response(self) -> None:
        """NXDOMAIN carrying an Answer section is contradictory and rejected."""
        call_count = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(
                    status=3, answers=[_record("example.com.", 1, "192.0.2.1")]
                ),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)

        assert len(result.evidence) == 0
        assert result.errors
        for error in result.errors:
            assert error.code == ProviderErrorCode.INVALID_RESPONSE
            assert error.retryable is False
            # The safe error message never echoes answer or name content.
            assert "192.0.2.1" not in error.message
            assert "example.com" not in error.message
        assert call_count == 7  # Contradiction does not short-circuit remaining types

    async def test_nxdomain_with_malformed_answer_data_is_invalid_response(
        self,
    ) -> None:
        """NXDOMAIN with schema-invalid answer data remains INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(
                    status=3,
                    answers=[
                        {"name": "example.com.", "type": 1, "TTL": "nope", "data": "x"}
                    ],
                ),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)

        assert len(result.evidence) == 0
        assert any(
            e.code == ProviderErrorCode.INVALID_RESPONSE and not e.retryable
            for e in result.errors
        )

    async def test_noerror_no_answers_is_valid_empty(self) -> None:
        """NOERROR with empty Answer list produces valid empty result."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(status=0, answers=[]),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            entity = Entity(type=EntityType.DOMAIN, value="empty.example.com")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.evidence) == 0
            assert len(result.errors) == 0

    async def test_strict_schema_rejection_missing_or_coerced_status(self) -> None:
        """Responses with missing Status or coerced types are rejected as INVALID_RESPONSE."""

        def _make_handler(payload: dict[str, Any]) -> Any:
            def _h(_: httpx.Request) -> httpx.Response:
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                )

            return _h

        for bad_payload in (
            {},
            {"Status": "0"},
            {"Status": 0, "TC": "true"},
            {"Status": 0, "Answer": [{"name": "x.", "type": 1, "TTL": 10}]},
        ):
            transport = MockTransport(_make_handler(bad_payload))
            async with httpx.AsyncClient(transport=transport) as client:
                provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
                entity = Entity(type=EntityType.DOMAIN, value="example.com")
                result = await provider.investigate(_FIXED_UUID, entity)
                assert any(
                    e.code == ProviderErrorCode.INVALID_RESPONSE for e in result.errors
                )

    async def test_dns_servfail_and_unknown_status(self) -> None:
        """SERVFAIL returns PROVIDER_UNAVAILABLE; unknown status returns INVALID_RESPONSE."""

        def _make_status_handler(code: int) -> Any:
            def _h(_: httpx.Request) -> httpx.Response:
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_dns_response(status=code),
                )

            return _h

        for status_code, expected_err, retryable in [
            (2, ProviderErrorCode.PROVIDER_UNAVAILABLE, True),
            (5, ProviderErrorCode.INVALID_RESPONSE, False),
        ]:
            transport = MockTransport(_make_status_handler(status_code))
            async with httpx.AsyncClient(transport=transport) as client:
                provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
                entity = Entity(type=EntityType.DOMAIN, value="example.com")
                result = await provider.investigate(_FIXED_UUID, entity)
                assert result.errors[0].code == expected_err
                assert result.errors[0].retryable is retryable

    async def test_malformed_answer_data_for_record_types(self) -> None:
        """Malformed data for every RR form reaches its parser/schema path.

        Each query type A, AAAA, CNAME, MX, NS, TXT, SOA, and PTR receives a
        malformed answer matching its own numeric RR type, so the intended
        parser or strict-schema rejection path is exercised directly. The
        malformed payload is returned only when the query ``type`` matches
        the answer's RR type, so no earlier type contradiction interferes.
        """

        rr_type_by_number = dict(_NUMERIC_TO_RR_TYPE)
        malformed_by_number: dict[int, dict[str, Any]] = {
            1: _record("example.com.", 1, "not-an-ip"),
            28: _record("example.com.", 28, "192.0.2.1"),  # IPv4 in AAAA
            5: _record("alias.example.", 5, "bad_label.example."),
            15: _record("example.com.", 15, "not-valid-mx"),
            2: _record("example.com.", 2, "bad_label.example."),
            16: {  # wrong-type TXT data rejected by the strict schema
                "name": "example.com.",
                "type": 16,
                "TTL": 300,
                "data": 123,
            },
            6: _record("example.com.", 6, "mname rname 1 2 3"),  # missing numbers
            12: _record("1.2.0.192.in-addr.arpa.", 12, "bad_label.example."),
        }

        def _make_answer_handler(bad_number: int) -> Any:
            def _h(request: httpx.Request) -> httpx.Response:
                requested = request.url.params.get("type")
                if requested == rr_type_by_number[bad_number]:
                    payload = _dns_response(answers=[malformed_by_number[bad_number]])
                else:
                    payload = _dns_response()
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                )

            return _h

        for bad_number, bad_answer in malformed_by_number.items():
            transport = MockTransport(_make_answer_handler(bad_number))
            async with httpx.AsyncClient(transport=transport) as client:
                provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
                if bad_number == 12:
                    entity: Entity = Entity(
                        type=EntityType.IP_ADDRESS, value="192.0.2.1"
                    )
                else:
                    entity = Entity(type=EntityType.DOMAIN, value="example.com")
                result = await provider.investigate(_FIXED_UUID, entity)
                # No evidence is emitted for the investigated entity, and
                # exactly one non-retryable INVALID_RESPONSE is returned.
                assert len(result.evidence) == 0
                assert len(result.errors) == 1
                assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
                assert result.errors[0].retryable is False
                # Malformed provider content never appears in the message.
                data = bad_answer["data"]
                for error in result.errors:
                    assert str(data) not in error.message

    async def test_partial_evidence_plus_later_error(self) -> None:
        """A successful A query followed by a failed AAAA query returns both evidence and errors."""

        def _handler(request: httpx.Request) -> httpx.Response:
            rr_type = request.url.params.get("type")
            if rr_type == "A":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_dns_response(
                        answers=[_record("example.com.", 1, "192.0.2.1")]
                    ),
                )
            if rr_type == "AAAA":
                return httpx.Response(500, json={"error": "internal"})
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(
                ProviderHttpClient(client=client, max_retries=0)
            )
            entity = Entity(type=EntityType.DOMAIN, value="example.com")
            result = await provider.investigate(_FIXED_UUID, entity)
            assert len(result.evidence) >= 1
            assert any(
                e.code == ProviderErrorCode.PROVIDER_UNAVAILABLE for e in result.errors
            )
            assert result.evidence[0].source == result.provider

    async def test_wrong_content_type_returns_invalid_response(self) -> None:
        """A successful non-DNS JSON media type is rejected."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/problem+json"},
                json=_dns_response(),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            )
            assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_naive_clock_raises_value_error(self) -> None:
        """An injected naive clock is rejected as a configuration error."""
        transport = MockTransport(lambda _: httpx.Response(200, json=_dns_response()))
        provider = GooglePublicDnsProvider(
            ProviderHttpClient(client=httpx.AsyncClient(transport=transport)),
            clock=lambda: datetime(2026, 1, 15, 12, 0, 0),  # Naive
        )
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        with pytest.raises(ValueError, match="timezone-aware"):
            await provider.investigate(_FIXED_UUID, entity)


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestGoogleDnsHttpContract:
    """Provider-level transport and HTTP status contract coverage."""

    async def _investigate_ptr(
        self,
        client: httpx.AsyncClient,
        **http_kwargs: Any,
    ) -> tuple[Any, int]:
        """Run one PTR investigation against the supplied client."""
        provider = GooglePublicDnsProvider(
            ProviderHttpClient(client=client, **http_kwargs)
        )
        entity = Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
        return await provider.investigate(_FIXED_UUID, entity), 1

    async def test_timeout_typed_error_with_exact_attempts(self) -> None:
        """A persistent timeout produces TIMEOUT with exactly max_retries + 1 attempts."""
        attempts = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            raise httpx.TimeoutException("connection timed out")

        transport = MockTransport(_handler)
        sleep = _RecordingSleep()
        async with httpx.AsyncClient(transport=transport) as client:
            result, _ = await self._investigate_ptr(
                client,
                max_retries=1,
                base_delay_seconds=0.01,
                sleep=sleep,
                jitter_fn=_zero_jitter,
            )
        assert result.errors[0].code == ProviderErrorCode.TIMEOUT
        assert result.errors[0].retryable is True
        assert attempts == 2
        assert len(sleep.calls) == 1

    async def test_rate_limited_429_with_retry_after(self) -> None:
        """A 429 with Retry-After produces RATE_LIMITED with parsed seconds."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(429, headers={"Retry-After": "30"}, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result, _ = await self._investigate_ptr(client, max_retries=0)
        assert result.errors[0].code == ProviderErrorCode.RATE_LIMITED
        assert result.errors[0].retryable is True
        assert result.errors[0].retry_after_seconds == 30

    async def test_unauthorized_401_typed_error(self) -> None:
        """A 401 produces non-retryable AUTHENTICATION_FAILED."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result, _ = await self._investigate_ptr(client, max_retries=0)
        assert result.errors[0].code == ProviderErrorCode.AUTHENTICATION_FAILED
        assert result.errors[0].retryable is False

    async def test_forbidden_403_typed_error(self) -> None:
        """A 403 produces non-retryable FORBIDDEN."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result, _ = await self._investigate_ptr(client, max_retries=0)
        assert result.errors[0].code == ProviderErrorCode.FORBIDDEN
        assert result.errors[0].retryable is False

    async def test_not_found_404_typed_error(self) -> None:
        """A 404 produces non-retryable NOT_FOUND."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result, _ = await self._investigate_ptr(client, max_retries=0)
        assert result.errors[0].code == ProviderErrorCode.NOT_FOUND
        assert result.errors[0].retryable is False

    async def test_malformed_json_produces_invalid_response(self) -> None:
        """Malformed JSON with an accepted media type produces INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=b"{not json",
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result, _ = await self._investigate_ptr(client)
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    async def test_missing_content_type_produces_invalid_response(self) -> None:
        """A successful response without Content-Type produces INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b'{"Status": 0}')

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result, _ = await self._investigate_ptr(client)
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert "content type" in result.errors[0].message

    async def test_exhausted_5xx_exact_attempts(self) -> None:
        """A persistent 5xx exhausts exactly max_retries + 1 attempts."""
        attempts = 0

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(503, json={})

        transport = MockTransport(_handler)
        sleep = _RecordingSleep()
        async with httpx.AsyncClient(transport=transport) as client:
            result, _ = await self._investigate_ptr(
                client,
                max_retries=2,
                base_delay_seconds=0.01,
                sleep=sleep,
                jitter_fn=_zero_jitter,
            )
        assert result.errors[0].code == ProviderErrorCode.PROVIDER_UNAVAILABLE
        assert result.errors[0].retryable is True
        assert attempts == 3
        assert len(sleep.calls) == 2


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestGoogleDnsValidation:
    """Strict DNS-name validation and structured answer contract coverage."""

    async def test_invalid_ascii_dns_names_rejected_without_io(self) -> None:
        """Spaces, underscores, empty labels, and overlong labels never reach HTTP."""
        network_hit = False

        def _guard_handler(_: httpx.Request) -> httpx.Response:
            nonlocal network_hit
            network_hit = True
            return httpx.Response(200, json=_dns_response())

        for bad_value in [
            "bad label.com",
            "bad_label.com",
            "a..b.com",
            "x" * 64 + ".com",
            ".leadingdot.com",
            "-leadinghyphen.com",
        ]:
            transport = MockTransport(_guard_handler)
            async with httpx.AsyncClient(transport=transport) as client:
                provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
                result = await provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.DOMAIN, value=bad_value)
                )
                assert network_hit is False
                assert len(result.errors) == 1
                assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
                assert result.errors[0].message == "invalid entity value"

    async def test_idna_and_trailing_dot_names_accepted(self) -> None:
        """Unicode and trailing-dot names canonicalize and reach HTTP."""
        requested_names: list[str | None] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            requested_names.append(request.url.params.get("name"))
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="Bücher.Example.")
            )
        assert requested_names[-1] == "xn--bcher-kva.example"

    async def test_malformed_answer_name_produces_invalid_response(self) -> None:
        """An answer record with an invalid DNS name produces INVALID_RESPONSE."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.params.get("type") == "PTR":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_dns_response(
                        answers=[_record("bad_label.example.", 12, "host.example.")]
                    ),
                )
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json=_dns_response()
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert len(result.evidence) == 0

    async def test_question_name_contradiction_rejected(self) -> None:
        """A question name that does not match the query is rejected."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={
                    "Status": 0,
                    "Question": [{"name": "other.example.", "type": 12}],
                    "Answer": [_record("other.example.", 12, "host.example.")],
                },
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_question_type_contradiction_rejected(self) -> None:
        """A question type that does not match the query is rejected."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={
                    "Status": 0,
                    "Question": [{"name": "1.2.0.192.in-addr.arpa.", "type": 1}],
                },
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_unknown_numeric_answer_type_rejected(self) -> None:
        """An answer with an unknown numeric RR type produces INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(
                    answers=[_record("1.2.0.192.in-addr.arpa.", 999, "?")]
                ),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_contradictory_known_answer_type_rejected(self) -> None:
        """An A-record answer to a PTR query is a type contradiction."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(
                    answers=[_record("1.2.0.192.in-addr.arpa.", 1, "192.0.2.1")]
                ),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_valid_cname_chain_accepted(self) -> None:
        """A CNAME answer to an A query is accepted as a valid CNAME chain record."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.params.get("type") == "A":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=_dns_response(
                        answers=[
                            _record("alias.example.com.", 5, "target.example.com.")
                        ]
                    ),
                )
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json=_dns_response()
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["query_type"] == "A"
        answer = result.evidence[0].facts["answers"][0]
        assert answer["record_type"] == "CNAME"
        assert answer["value"] == "target.example.com"

    async def test_ipv6_ptr_reverse_pointer(self) -> None:
        """An IPv6 PTR query uses the ip6.arpa reverse-pointer name."""
        requested_name: str | None = None

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal requested_name
            requested_name = request.url.params.get("name")
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(
                    answers=[_record(requested_name or "", 12, "host.example.com.")]
                ),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="2001:db8::1")
            )
        expected_ptr = (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
        assert requested_name == expected_ptr
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["query_type"] == "PTR"
        assert result.evidence[0].facts["answers"][0]["value"] == "host.example.com"

    async def test_facts_deep_immutable(self) -> None:
        """Nested fact mutation attempts fail; evidence facts are deeply immutable."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=_dns_response(
                    answers=[
                        _record("1.2.0.192.in-addr.arpa.", 12, "host.example.com.")
                    ]
                ),
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = GooglePublicDnsProvider(ProviderHttpClient(client=client))
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            )
        evidence = result.evidence[0]
        assert evidence.raw_payload is None
        assert isinstance(evidence.facts["answers"], tuple)
        with pytest.raises(TypeError):
            evidence.facts["query_type"] = "mutated"
        with pytest.raises(TypeError):
            evidence.facts["flags"]["rd"] = False
