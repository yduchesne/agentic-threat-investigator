# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic provider contract tests for the AbuseIPDB provider.

Covers lookup behavior, request shape, typed error mapping, and the
adversarial response matrix over ATI-authored synthetic fixtures; no test
contacts the real AbuseIPDB service.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.infrastructure.providers.abuseipdb import (
    _ABUSEIPDB_ENDPOINT,
    AbuseIpdbProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from tests.support.abuseipdb_fixtures import (
    FIXED_KEY,
    FIXED_TS,
    FIXED_UUID,
    REMOVED,
    SYNTHETIC_IPV4,
    SYNTHETIC_IPV4_ENTITY,
    SYNTHETIC_IPV6,
    assert_no_key_leak,
    check_data,
    check_response,
)
from tests.support.abuseipdb_fixtures import provider as build_provider
from tests.support.provider_http import failing_io_client, handler_client, static_client

_APPROVED_FACT_KEYS = {
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

# Documented upstream members ATI ignores; they must never appear in facts.
_IGNORED_FACT_FRAGMENTS = (
    "country_code",
    "usage_type",
    "isp",
    "domain",
    "hostnames",
    "comment",
    "reporter_id",
    "reporter_country",
    "category_labels",
)

# Derived assessment keys that must never appear as fact keys.
_DERIVED_FACT_KEYS = {
    "risk",
    "severity",
    "malicious",
    "verdict",
    "confidence",
    "ati_score",
}


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestAbuseIpdbProviderContract:
    """Deterministic provider contract tests for AbuseIpdbProvider."""

    async def test_supports_matrix(self) -> None:
        """Only IP-address entities are supported."""
        provider = build_provider(failing_io_client())
        assert provider.supports(Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8"))
        # Every non-IP entity type must be unsupported.
        for unsupported in set(EntityType) - {EntityType.IP_ADDRESS}:
            assert not provider.supports(Entity(type=unsupported, value="test"))

    async def test_unsupported_entity_produces_no_io(self) -> None:
        """An unsupported entity yields one UNSUPPORTED_INDICATOR with no HTTP I/O."""
        provider = build_provider(failing_io_client())
        for unsupported in set(EntityType) - {EntityType.IP_ADDRESS}:
            result = await provider.investigate(
                FIXED_UUID, Entity(type=unsupported, value="test")
            )
            assert result.evidence == ()
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
            assert result.errors[0].retryable is False

    async def test_invalid_entity_value_produces_no_io(self) -> None:
        """An uncanonicalizable entity value yields one error with no HTTP I/O."""
        provider = build_provider(failing_io_client())
        result = await provider.investigate(
            FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="not-an-ip")
        )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert result.errors[0].retryable is False

    async def test_positive_lookup_request_shape(self) -> None:
        """A successful lookup sends the exact fixed-endpoint request contract."""
        captured: dict[str, Any] = {}

        def _handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["method"] = request.method
            captured["key"] = request.headers.get("Key")
            captured["accept"] = request.headers.get("Accept")
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json=check_response())

        async with handler_client(_handler) as client:
            provider = build_provider(client, clock=lambda: FIXED_TS)
            result = await provider.investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )

        assert captured["method"] == "GET"
        assert captured["url"] == (
            f"{_ABUSEIPDB_ENDPOINT}?ipAddress={SYNTHETIC_IPV4}&maxAgeInDays=30&verbose="
        )
        assert captured["key"] == FIXED_KEY
        assert captured["accept"] == "application/json"
        assert captured["params"] == {
            "ipAddress": SYNTHETIC_IPV4,
            "maxAgeInDays": "30",
            "verbose": "",
        }
        assert_no_key_leak(captured["url"])
        assert result.errors == ()
        assert result.provider == "urn:ati:source:abuseipdb"

    async def test_positive_lookup_and_provenance(self) -> None:
        """A successful lookup emits exactly one canonical evidence observation."""
        async with handler_client(
            lambda _: httpx.Response(200, json=check_response())
        ) as client:
            provider = build_provider(client, clock=lambda: FIXED_TS)
            result = await provider.investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )

        assert result.errors == ()
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.type == EvidenceType.REPUTATION
        assert evidence.investigation_id == FIXED_UUID
        assert evidence.source == provider.id
        assert evidence.source_record_id is None
        assert evidence.source_url == "https://api.abuseipdb.com/api/v2/check"
        assert evidence.subject.value == SYNTHETIC_IPV4
        assert evidence.subject.type == EntityType.IP_ADDRESS
        assert evidence.retrieved_at == FIXED_TS
        # observed_at is the normalized lastReportedAt source fact.
        assert evidence.observed_at == datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        assert evidence.raw_payload is None
        # Exactly the approved fact keys are emitted.
        assert set(evidence.facts) == _APPROVED_FACT_KEYS
        facts = evidence.facts
        assert facts["ip_address"] == SYNTHETIC_IPV4
        assert facts["is_public"] is False
        assert facts["ip_version"] == 4
        assert facts["is_whitelisted"] is False
        assert facts["abuse_confidence_score"] == 100
        assert facts["is_tor"] is False
        assert facts["total_reports"] == 1
        assert facts["num_distinct_users"] == 1
        assert facts["max_age_in_days"] == 30
        assert facts["last_reported_at"] == "2026-01-15T12:00:00+00:00"
        reports_fact = facts["reports"]
        assert len(reports_fact) == 1
        assert set(reports_fact[0]) == {"reported_at", "categories"}
        assert reports_fact[0]["reported_at"] == "2026-01-15T12:00:00+00:00"
        assert list(reports_fact[0]["categories"]) == [18, 22]
        # Ignored upstream data is never copied into facts.
        serialized = str(facts)
        for fragment in _IGNORED_FACT_FRAGMENTS:
            assert fragment not in serialized
        # No derived assessment key exists (the abuse-confidence source fact
        # is the only member whose name contains "confidence").
        for derived in _DERIVED_FACT_KEYS:
            assert derived not in facts
        assert_no_key_leak(str(evidence.source_url))

    async def test_zero_report_success_is_not_benign(self) -> None:
        """A zero-score, zero-report response is one neutral REPUTATION evidence."""
        data = check_data(
            abuseConfidenceScore=0,
            totalReports=0,
            numDistinctUsers=0,
            lastReportedAt=None,
            reports=[],
        )
        async with static_client(httpx.Response(200, json=check_response(data))) as (
            client
        ):
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.errors == ()
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.type == EvidenceType.REPUTATION
        # All approved keys remain present, with documented null/empty values.
        assert set(evidence.facts) == _APPROVED_FACT_KEYS
        facts = evidence.facts
        assert facts["abuse_confidence_score"] == 0
        assert facts["total_reports"] == 0
        assert facts["num_distinct_users"] == 0
        assert facts["last_reported_at"] is None
        assert not facts["reports"]
        assert facts["max_age_in_days"] == 30
        # Null lastReportedAt means observed_at is None.
        assert evidence.observed_at is None

    async def test_whitelist_values_preserved_without_verdict(self) -> None:
        """All three whitelist source values are retained without assessment."""
        for value in (True, False, None):
            data = check_data(isWhitelisted=value)
            async with static_client(
                httpx.Response(200, json=check_response(data))
            ) as client:
                result = await build_provider(client).investigate(
                    FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
                )
            assert result.errors == ()
            assert result.evidence[0].facts["is_whitelisted"] is value

    async def test_canonical_ipv6_lookup(self) -> None:
        """An IPv6 lookup queries the canonical form and checks family 6."""

        def _handler(request: httpx.Request) -> httpx.Response:
            assert dict(request.url.params)["ipAddress"] == "2001:db8::1"
            return httpx.Response(
                200,
                json=check_response(check_data(ipAddress="2001:db8::1", ipVersion=6)),
            )

        async with handler_client(_handler) as client:
            result = await build_provider(client).investigate(
                FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value="2001:0DB8:0000::1"),
            )
        assert result.errors == ()
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.subject.value == SYNTHETIC_IPV6
        assert set(evidence.facts) == _APPROVED_FACT_KEYS
        assert evidence.facts["ip_address"] == SYNTHETIC_IPV6
        assert evidence.facts["ip_version"] == 6
        assert evidence.facts["max_age_in_days"] == 30

    async def test_configured_max_age_reaches_request_and_facts(self) -> None:
        """The configured report window is sent as maxAgeInDays and kept in facts."""

        def _handler(request: httpx.Request) -> httpx.Response:
            assert dict(request.url.params)["maxAgeInDays"] == "90"
            return httpx.Response(200, json=check_response())

        async with handler_client(_handler) as client:
            result = await build_provider(client, max_age_in_days=90).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.errors == ()
        assert result.evidence[0].facts["max_age_in_days"] == 90

    async def test_textual_variant_identity_accepted(self) -> None:
        """A canonical response IP matching the canonical query is valid."""
        async with static_client(
            httpx.Response(200, json=check_response(check_data()))
        ) as client:
            result = await build_provider(client).investigate(
                FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value=f"  {SYNTHETIC_IPV4}  "),
            )
        assert result.errors == ()
        assert result.evidence[0].facts["ip_address"] == SYNTHETIC_IPV4

    async def test_wrong_identity_rejected(self) -> None:
        """A response about a different IP is rejected as INVALID_RESPONSE."""
        async with static_client(
            httpx.Response(200, json=check_response(check_data(ipAddress="8.8.8.8")))
        ) as client:
            result = await build_provider(client).investigate(
                FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4),
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    @pytest.mark.parametrize(
        ("data_version", "query_ip"),
        [(6, SYNTHETIC_IPV4), (4, "2001:db8::1")],
    )
    async def test_family_mismatch_rejected(
        self, data_version: int, query_ip: str
    ) -> None:
        """A reported IP version that mismatches the address family is rejected."""
        response_ip = "2001:db8::1" if data_version == 6 else SYNTHETIC_IPV4
        data = check_data(ipAddress=response_ip, ipVersion=data_version)
        async with static_client(httpx.Response(200, json=check_response(data))) as (
            client
        ):
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=query_ip)
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    @pytest.mark.parametrize(
        "data",
        [
            check_data(ipAddress=True),
            check_data(isPublic=1),
            check_data(isTor="false"),
            check_data(abuseConfidenceScore="100"),
            check_data(isWhitelisted="false"),
            check_data(ipAddress=REMOVED),
            check_data(lastReportedAt=REMOVED),
            check_data(reports=REMOVED),
            check_data(reports=None),
            check_data(reports={"not": "a list"}),
            check_data(reports=[42]),
            check_data(reports=[{"reportedAt": "2026-01-15T12:00:00+00:00"}]),
            check_data(reports=[{"categories": [14]}]),
            check_data(lastReportedAt="nope"),
            {},
        ],
    )
    async def test_malformed_schema_rejected(self, data: Any) -> None:
        """A schema-malformed data object yields exactly one typed error."""
        async with static_client(httpx.Response(200, json=check_response(data))) as (
            client
        ):
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.evidence == ()
        assert len(result.errors) == 1
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    @pytest.mark.parametrize(
        "payload",
        [
            [],
            "text",
            1,
            True,
            None,
            {"errors": [{"detail": "bad", "status": 400}]},
            {"data": "not-an-object"},
            {"data": 42},
        ],
    )
    async def test_non_object_or_missing_data_rejected(self, payload: Any) -> None:
        """Non-object responses and missing/non-object data members are rejected."""
        async with static_client(httpx.Response(200, json=payload)) as client:
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_error_body_detail_never_echoed(self) -> None:
        """The provider never echoes the response body into error messages."""
        body = {"errors": [{"detail": "secret-ish detail with " + SYNTHETIC_IPV4}]}
        async with static_client(httpx.Response(422, json=body)) as client:
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert "secret-ish" not in result.errors[0].message

    async def test_category_order_and_duplicates_preserved(self) -> None:
        """Category identifiers keep source order and duplicates, with no labels."""
        data = check_data(
            reports=[
                {
                    "reportedAt": "2026-01-15T12:00:00+00:00",
                    "categories": [99, 14, 14],
                }
            ]
        )
        async with static_client(httpx.Response(200, json=check_response(data))) as (
            client
        ):
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        reports = result.evidence[0].facts["reports"]
        assert list(reports[0]["categories"]) == [99, 14, 14]

    async def test_report_order_preserved(self) -> None:
        """Report entries keep the source array order."""
        reports = [
            {"reportedAt": "2026-01-15T11:00:00+00:00", "categories": [14]},
            {"reportedAt": "2026-01-15T12:00:00+00:00", "categories": [18]},
        ]
        data = check_data(reports=reports)
        async with static_client(httpx.Response(200, json=check_response(data))) as (
            client
        ):
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        reports_fact = result.evidence[0].facts["reports"]
        assert [r["reported_at"] for r in reports_fact] == [
            "2026-01-15T11:00:00+00:00",
            "2026-01-15T12:00:00+00:00",
        ]

    async def test_empty_reports_array_retained(self) -> None:
        """An explicitly returned empty reports array stays an empty fact."""
        data = check_data(reports=[], lastReportedAt=None)
        async with static_client(httpx.Response(200, json=check_response(data))) as (
            client
        ):
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.errors == ()
        facts = result.evidence[0].facts
        assert not facts["reports"]
        assert facts["last_reported_at"] is None
        assert facts["max_age_in_days"] == 30


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestAbuseIpdbProviderFailures:
    """Shared HTTP failure, cancellation, and lifecycle contract tests."""

    @pytest.mark.parametrize(
        ("status", "headers", "expected_code", "retryable"),
        [
            (401, {}, ProviderErrorCode.AUTHENTICATION_FAILED, False),
            (402, {}, ProviderErrorCode.FORBIDDEN, False),
            (403, {}, ProviderErrorCode.FORBIDDEN, False),
            (404, {}, ProviderErrorCode.NOT_FOUND, False),
            (422, {}, ProviderErrorCode.INVALID_RESPONSE, False),
            (429, {"Retry-After": "30"}, ProviderErrorCode.RATE_LIMITED, True),
            (500, {}, ProviderErrorCode.PROVIDER_UNAVAILABLE, True),
        ],
    )
    async def test_shared_http_status_errors(
        self,
        status: int,
        headers: dict[str, str],
        expected_code: ProviderErrorCode,
        retryable: bool,
    ) -> None:
        """Shared HTTP failures map to their documented typed provider errors."""
        async with static_client(
            httpx.Response(status, headers=headers, json={})
        ) as client:
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.evidence == ()
        assert len(result.errors) == 1
        assert result.errors[0].code == expected_code
        assert result.errors[0].retryable is retryable

    async def test_rate_limited_carries_retry_after(self) -> None:
        """A 429 with Retry-After carries the parsed seconds without sleeping."""
        async with static_client(
            httpx.Response(429, headers={"Retry-After": "29241"}, json={})
        ) as client:
            result = await build_provider(
                client, http_kwargs={"policy": ProviderHttpPolicy(max_retries=0)}
            ).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.errors[0].retry_after_seconds == 29241

    async def test_timeout_typed_error(self) -> None:
        """A transport timeout yields a typed timeout error without real sleeping."""

        def _handler(_: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("connection timed out")

        async with handler_client(_handler) as client:
            result = await build_provider(
                client, http_kwargs={"policy": ProviderHttpPolicy(max_retries=0)}
            ).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.TIMEOUT
        assert result.errors[0].retryable is True

    async def test_oversized_response_rejected(self) -> None:
        """A response exceeding the shared size bound is a non-retryable typed error."""
        policy = ProviderHttpPolicy(max_response_bytes=64, max_retries=0)
        result = await build_provider(
            static_client(httpx.Response(200, json=check_response())),
            http_kwargs={"policy": policy},
        ).investigate(FIXED_UUID, SYNTHETIC_IPV4_ENTITY)
        assert result.evidence == ()
        (error,) = result.errors
        assert error.code == ProviderErrorCode.INVALID_RESPONSE
        assert error.retryable is False
        assert_no_key_leak(error.message)

    async def test_invalid_content_type_rejected(self) -> None:
        """A non-JSON success content type is a non-retryable typed error."""
        async with static_client(
            httpx.Response(
                200, content=b"plain text", headers={"content-type": "text/plain"}
            )
        ) as client:
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    async def test_error_messages_carry_no_key(self) -> None:
        """Typed error messages never contain the API key."""
        async with static_client(httpx.Response(401, json={})) as client:
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert_no_key_leak(result.errors[0].message)

    async def test_cancellation_propagates(self) -> None:
        """Task cancellation propagates without swallowing or yielding evidence."""

        def _handler(_: httpx.Request) -> httpx.Response:
            raise asyncio.CancelledError()

        async with handler_client(_handler) as client:
            with pytest.raises(asyncio.CancelledError):
                await build_provider(client).investigate(
                    FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
                )

    async def test_facts_deep_immutable(self) -> None:
        """Evidence facts are deeply immutable after normalization."""
        async with static_client(httpx.Response(200, json=check_response())) as (
            client
        ):
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        evidence = result.evidence[0]
        with pytest.raises(TypeError):
            evidence.facts["ip_address"] = "changed"
        with pytest.raises(TypeError):
            evidence.facts["reports"][0]["categories"] = []
        with pytest.raises(TypeError):
            evidence.facts.clear()

    async def test_naive_clock_rejected(self) -> None:
        """An injected naive clock is rejected as a configuration error."""
        async with static_client(httpx.Response(200, json=check_response())) as (
            client
        ):
            provider = build_provider(
                client,
                clock=lambda: datetime(2026, 1, 15, 12, 0, 0),  # Naive
            )
            with pytest.raises(ValueError, match="timezone-aware"):
                await provider.investigate(
                    FIXED_UUID,
                    Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4),
                )

    async def test_blank_key_rejected_at_construction(self) -> None:
        """A blank API key is rejected before any I/O can occur."""
        async with failing_io_client() as client:
            for blank in ("", "   "):
                with pytest.raises(ValueError, match="key must not be blank"):
                    AbuseIpdbProvider(ProviderHttpClient(client=client), api_key=blank)

    @pytest.mark.parametrize("bad_window", [0, -1, 366, True, 2.5, "30"])
    async def test_invalid_window_rejected_at_construction(
        self, bad_window: Any
    ) -> None:
        """Out-of-range or non-integer report windows are rejected."""
        async with failing_io_client() as client:
            with pytest.raises(ValueError, match="max_age_in_days"):
                AbuseIpdbProvider(
                    ProviderHttpClient(client=client),
                    api_key=FIXED_KEY,
                    max_age_in_days=bad_window,
                )

    async def test_window_boundaries_accepted(self) -> None:
        """Window bounds 1 and 365 are accepted."""
        async with failing_io_client() as client:
            for window in (1, 365):
                AbuseIpdbProvider(
                    ProviderHttpClient(client=client),
                    api_key=FIXED_KEY,
                    max_age_in_days=window,
                )

    async def test_no_persistence_or_relationship_side_effects(self) -> None:
        """A successful lookup yields only evidence: no persistence artifacts."""

        async with static_client(httpx.Response(200, json=check_response())) as (
            client
        ):
            result = await build_provider(client).investigate(
                FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value=SYNTHETIC_IPV4)
            )
        assert result.evidence[0].subject.id is None
        # The evidence carries exactly one REPUTATION observation and no
        # relationship, pivot, or persistence artifact of any kind.
        assert len(result.evidence) == 1
        assert result.evidence[0].type == EvidenceType.REPUTATION
