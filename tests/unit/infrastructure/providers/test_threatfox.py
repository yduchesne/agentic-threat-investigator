# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ThreatFox provider unit tests.

Covers the strict response-record schema, the pure IOC identity-matching
rules, envelope/query-status handling, evidence normalization, and the
exact HTTP request contract, all against ATI-authored synthetic responses
carried by an in-process transport. No test contacts the real ThreatFox
service.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from agentic_threat_investigator.app.providers import (
    ProviderError,
    ProviderErrorCode,
    ProviderResult,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from agentic_threat_investigator.infrastructure.providers.threatfox import (
    ThreatFoxProvider,
)
from tests.support.provider_http import failing_io_client, handler_client
from tests.support.threatfox_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    CANONICAL_ASYNCRAT_IP,
    CANONICAL_ASYNCRAT_IP_PORT,
    CANONICAL_ASYNCRAT_MALWARE,
    CANONICAL_ASYNCRAT_PRINTABLE,
    FIXED_KEY,
    FIXED_TS,
    FIXED_UUID,
    asyncrat_domain_record,
    asyncrat_ip_port_record,
    MATCH_FACT_KEYS,
    investigate,
    threatfox_no_result_response,
    threatfox_provider,
    threatfox_search_response,
)

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]

_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

_DOMAIN_ENTITY = Entity(type=EntityType.DOMAIN, value=CANONICAL_ASYNCRAT_DOMAIN)
_IP_ENTITY = Entity(type=EntityType.IP_ADDRESS, value=CANONICAL_ASYNCRAT_IP)

# -- Strict record schema ---------------------------------------------------


# -- HTTP request contract ---------------------------------------------------


class _CapturingHandler:  # pylint: disable=too-few-public-methods
    """Captures requests and serves a canned response."""

    def __init__(self, response: httpx.Response) -> None:
        self.requests: list[httpx.Request] = []
        self._response = response

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._response


@pytest.mark.unit
class TestHttpRequestContract:
    """Exact POST endpoint, body, and header contract tests."""

    async def test_exact_post_endpoint_body_and_headers(self) -> None:
        """A domain query sends the exact documented POST request."""
        handler = _CapturingHandler(
            httpx.Response(
                200, json=threatfox_search_response(asyncrat_domain_record())
            )
        )
        async with handler_client(handler) as client:
            provider = threatfox_provider(client, clock=lambda: FIXED_TS)
            await provider.investigate(FIXED_UUID, _DOMAIN_ENTITY)

        assert len(handler.requests) == 1
        request = handler.requests[0]
        assert request.method == "POST"
        assert str(request.url) == _ENDPOINT
        assert request.url.path == "/api/v1/"
        assert request.headers["Auth-Key"] == FIXED_KEY
        assert request.headers["Content-Type"] == "application/json"
        assert request.headers["Accept"] == "application/json"
        body = json.loads(request.content.decode("utf-8"))
        assert body == {
            "query": "search_ioc",
            "search_term": CANONICAL_ASYNCRAT_DOMAIN,
            "exact_match": True,
        }

    async def test_auth_key_never_in_url_or_body(self) -> None:
        """The Auth-Key travels only in its header, never in URL or body."""
        handler = _CapturingHandler(
            httpx.Response(
                200, json=threatfox_search_response(asyncrat_ip_port_record())
            )
        )
        async with handler_client(handler) as client:
            provider = threatfox_provider(client)
            result = await provider.investigate(FIXED_UUID, _IP_ENTITY)

        assert result.errors == ()
        request = handler.requests[0]
        assert FIXED_KEY not in str(request.url)
        assert FIXED_KEY not in request.content.decode("utf-8")
        assert "auth" not in str(request.url).lower()
        assert FIXED_KEY not in str(result.evidence[0].source_url)

    async def test_search_term_is_canonical_value(self) -> None:
        """The search term is the canonicalized entity value, not raw input."""
        handler = _CapturingHandler(
            httpx.Response(
                200, json=threatfox_search_response(asyncrat_ip_port_record())
            )
        )
        entity = Entity(type=EntityType.IP_ADDRESS, value="203.0.113.42")
        async with handler_client(handler) as client:
            provider = threatfox_provider(client)
            await provider.investigate(FIXED_UUID, entity)

        body = json.loads(handler.requests[0].content.decode("utf-8"))
        assert body["search_term"] == "203.0.113.42"


# -- Status, envelope, and transport failure handling -------------------------


@pytest.mark.unit
class TestStatusAndTransportFailures:
    """Typed failure mapping for HTTP statuses and body-encoded statuses."""

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (401, ProviderErrorCode.AUTHENTICATION_FAILED),
            (403, ProviderErrorCode.FORBIDDEN),
        ],
    )
    async def test_auth_failures_single_attempt(
        self, status: int, expected: ProviderErrorCode
    ) -> None:
        """401/403 yield non-retryable typed errors on exactly one attempt."""
        handler = _CapturingHandler(httpx.Response(status, json={}))
        async with handler_client(handler) as client:
            provider = threatfox_provider(client)
            result = await provider.investigate(FIXED_UUID, _DOMAIN_ENTITY)

        assert len(handler.requests) == 1
        assert result.evidence == ()
        assert len(result.errors) == 1
        error = result.errors[0]
        assert error.code == expected
        assert error.retryable is False
        assert FIXED_KEY not in error.message

    async def test_429_retries_then_reports_retry_after(self) -> None:
        """A 429 with Retry-After schedules exactly that delay and retries once."""
        handler = _CapturingHandler(
            httpx.Response(429, headers={"Retry-After": "30"}, json={})
        )
        scheduled: list[float] = []

        async def _spy_sleep(seconds: float) -> None:
            scheduled.append(seconds)

        policy = ProviderHttpPolicy(max_retries=1, base_delay_seconds=0.01)
        async with handler_client(handler) as client:
            provider = threatfox_provider(
                client, http_kwargs={"policy": policy, "sleep": _spy_sleep}
            )
            result = await provider.investigate(FIXED_UUID, _DOMAIN_ENTITY)

        assert len(handler.requests) == 2
        assert scheduled == [30.0]
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.RATE_LIMITED
        assert result.errors[0].retryable is True
        assert result.errors[0].retry_after_seconds == 30

    async def test_persistent_5xx_exhausts_retries(self) -> None:
        """A persistent 5xx exhausts retries and ends PROVIDER_UNAVAILABLE."""
        handler = _CapturingHandler(httpx.Response(503, json={}))
        policy = ProviderHttpPolicy(max_retries=2, base_delay_seconds=0.01)
        async with handler_client(handler) as client:
            provider = threatfox_provider(client, http_kwargs={"policy": policy})
            result = await provider.investigate(FIXED_UUID, _DOMAIN_ENTITY)

        assert len(handler.requests) == 3
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.PROVIDER_UNAVAILABLE
        assert result.errors[0].retryable is True

    async def test_malformed_json_is_invalid_response(self) -> None:
        """A malformed JSON body is a non-retryable INVALID_RESPONSE."""
        handler = _CapturingHandler(
            httpx.Response(
                200,
                content=b"{not json",
                headers={"Content-Type": "application/json"},
            )
        )
        async with handler_client(handler) as client:
            provider = threatfox_provider(client)
            result = await provider.investigate(FIXED_UUID, _DOMAIN_ENTITY)

        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    async def test_body_encoded_ratelimited_maps_to_typed_error(self) -> None:
        """The body-encoded ``ratelimited`` status maps to RATE_LIMITED."""
        handler = _CapturingHandler(
            httpx.Response(200, json={"query_status": "ratelimited"})
        )
        async with handler_client(handler) as client:
            provider = threatfox_provider(client)
            result = await provider.investigate(FIXED_UUID, _DOMAIN_ENTITY)

        assert len(handler.requests) == 1
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.RATE_LIMITED
        assert result.errors[0].retryable is True

    async def test_cancellation_propagates(self) -> None:
        """A cancelled request propagates ``CancelledError`` unchanged."""

        def handler(_: httpx.Request) -> httpx.Response:
            raise asyncio.CancelledError()

        async with handler_client(handler) as client:
            provider = threatfox_provider(client)
            with pytest.raises(asyncio.CancelledError):
                await provider.investigate(FIXED_UUID, _DOMAIN_ENTITY)


# -- Envelope and query-status handling ---------------------------------------


@pytest.mark.unit
class TestEnvelopeValidation:
    """Top-level envelope and query-status validation tests."""

    @pytest.mark.parametrize(
        "payload",
        [
            [],  # non-object top level
            ["ok"],
            {},  # missing query_status
            {"query_status": None},
            {"query_status": 42},
            {"query_status": ""},
        ],
    )
    async def test_malformed_envelope_rejected(self, payload: Any) -> None:
        """A missing, non-string, or empty query_status is INVALID_RESPONSE."""
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    @pytest.mark.parametrize(
        "payload",
        [
            {"query_status": "error"},
            {"query_status": "unauthorized"},
            {"query_status": "illegal_search_term"},
            {"query_status": "some_future_status"},
        ],
    )
    async def test_unknown_query_status_never_success(
        self, payload: dict[str, Any]
    ) -> None:
        """Unknown statuses are never success and map to INVALID_RESPONSE."""
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    @pytest.mark.parametrize(
        "payload",
        [
            {"query_status": "ok"},
            {"query_status": "ok", "data": None},
            {"query_status": "ok", "data": {"id": "1"}},
            {"query_status": "ok", "data": "records"},
        ],
    )
    async def test_ok_without_array_data_rejected(
        self, payload: dict[str, Any]
    ) -> None:
        """An ``ok`` response without a data array is INVALID_RESPONSE."""
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_no_result_is_valid_empty_result(self) -> None:
        """A ``no_result`` status yields an empty result and no error."""
        result = await investigate(
            httpx.Response(200, json=threatfox_no_result_response()),
            entity=_DOMAIN_ENTITY,
        )
        assert result.provider == "urn:ati:source:threatfox"
        assert result.evidence == ()
        assert result.errors == ()

    async def test_ok_with_empty_data_array_is_valid_no_result(self) -> None:
        """An explicitly empty data array is a valid no-result outcome."""
        result = await investigate(
            httpx.Response(200, json=threatfox_search_response()),
            entity=_DOMAIN_ENTITY,
        )
        assert result.evidence == ()
        assert result.errors == ()

    async def test_malformed_record_invalidates_whole_response(self) -> None:
        """One malformed record invalidates the response: no partial evidence."""
        payload = threatfox_search_response(
            asyncrat_domain_record(),
            {"id": "not-decimal", "ioc": "other.test"},
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_unrelated_record_invalidates_whole_response(self) -> None:
        """An unrelated record is rejected even though exact_match was sent."""
        payload = threatfox_search_response(
            asyncrat_domain_record(),
            asyncrat_domain_record(id="864299", ioc="unrelated-domain.test"),
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE


# -- Evidence normalization ---------------------------------------------------


@pytest.mark.unit
class TestEvidenceNormalization:
    """Grouped-evidence normalization tests for successful searches."""

    async def test_domain_hit_normalizes_grouped_evidence(self) -> None:
        """A domain hit emits one THREAT_INTELLIGENCE evidence with facts."""
        result = await investigate(
            httpx.Response(
                200, json=threatfox_search_response(asyncrat_domain_record())
            ),
            entity=_DOMAIN_ENTITY,
            clock=lambda: FIXED_TS,
        )
        assert result.errors == ()
        assert result.provider == "urn:ati:source:threatfox"
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.type == EvidenceType.THREAT_INTELLIGENCE
        assert evidence.investigation_id == FIXED_UUID
        assert evidence.subject.type == EntityType.DOMAIN
        assert evidence.subject.value == CANONICAL_ASYNCRAT_DOMAIN
        assert evidence.source == "urn:ati:source:threatfox"
        assert evidence.source_url == _ENDPOINT
        assert evidence.retrieved_at == FIXED_TS
        # observed_at is the latest retained source observation.
        assert evidence.observed_at == datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)
        assert evidence.raw_payload is None

        matches = evidence.facts["matches"]
        # Facts are deeply immutable: lists are frozen into tuples.
        assert isinstance(matches, tuple) and len(matches) == 1
        match = matches[0]
        assert set(match) == MATCH_FACT_KEYS
        assert match["threatfox_id"] == "864201"
        assert match["ioc"] == CANONICAL_ASYNCRAT_DOMAIN
        assert match["ioc_type"] == "domain"
        assert match["threat_type"] == "botnet_cc"
        assert match["threat_type_description"] == (
            "Indicator that identifies a botnet command&control server (C&C)"
        )
        assert match["malware"] == CANONICAL_ASYNCRAT_MALWARE
        assert match["malware_printable"] == CANONICAL_ASYNCRAT_PRINTABLE
        assert match["confidence_level"] == 100
        assert match["first_seen"] == "2026-08-20T12:00:00+00:00"
        assert match["last_seen"] == "2026-08-21T12:00:00+00:00"
        assert match["reference"] is None
        assert match["tags"] == ("AsyncRAT",)
        # Ignored upstream members never reach the normalized facts.
        serialized = str(evidence.facts)
        for fragment in (
            "reporter",
            "comment",
            "credits",
            "malware_samples",
            "malware_alias",
            "malware_malpedia",
        ):
            assert fragment not in serialized

    async def test_ip_port_hit_normalizes_canonical_subject(self) -> None:
        """An ip:port hit keeps the canonical queried IP as the subject."""
        result = await investigate(
            httpx.Response(
                200, json=threatfox_search_response(asyncrat_ip_port_record())
            ),
            entity=_IP_ENTITY,
            clock=lambda: FIXED_TS,
        )
        assert result.errors == ()
        evidence = result.evidence[0]
        assert evidence.subject.type == EntityType.IP_ADDRESS
        assert evidence.subject.value == CANONICAL_ASYNCRAT_IP
        match = evidence.facts["matches"][0]
        assert match["ioc"] == CANONICAL_ASYNCRAT_IP_PORT
        assert match["ioc_type"] == "ip:port"

    async def test_bare_ipv6_hit_normalizes_canonical_subject(self) -> None:
        """A bare IPv6 hit canonicalizes both the subject and source record."""
        result = await investigate(
            httpx.Response(
                200,
                json=threatfox_search_response(
                    asyncrat_ip_port_record(ioc="2001:0DB8:0000::1")
                ),
            ),
            entity=Entity(type=EntityType.IP_ADDRESS, value="2001:db8::1"),
        )
        assert result.errors == ()
        evidence = result.evidence[0]
        assert evidence.subject.value == "2001:db8::1"

    async def test_observed_at_is_latest_source_observation(self) -> None:
        """observed_at is the latest retained source observation of any match."""
        payload = threatfox_search_response(
            # Record 1 has no last_seen: its observation is first_seen 08-20.
            asyncrat_ip_port_record(id="864202", last_seen=None),
            # Record 2 observes the same IOC on a different port, also seen
            # 08-20 with no last_seen.
            asyncrat_ip_port_record(
                id="864203", ioc=CANONICAL_ASYNCRAT_IP + ":8443", last_seen=None
            ),
        )
        result = await investigate(httpx.Response(200, json=payload), entity=_IP_ENTITY)
        assert result.errors == ()
        matches = result.evidence[0].facts["matches"]
        assert [m["threatfox_id"] for m in matches] == ["864202", "864203"]
        assert result.evidence[0].observed_at == datetime(
            2026, 8, 20, 12, 0, 0, tzinfo=UTC
        )

    async def test_multiple_distinct_malware_identifiers_remain_distinct(self) -> None:
        """Distinct malware identifiers remain distinct in normalized facts."""
        payload = threatfox_search_response(
            asyncrat_ip_port_record(id="864202", malware="win.asyncrat"),
            asyncrat_ip_port_record(id="864203", malware="win.other_rat"),
        )
        result = await investigate(httpx.Response(200, json=payload), entity=_IP_ENTITY)
        matches = result.evidence[0].facts["matches"]
        assert {m["malware"] for m in matches} == {"win.asyncrat", "win.other_rat"}

    async def test_multiple_records_same_malware_are_retained(self) -> None:
        """Distinct records mapping one IOC to one malware are all retained.

        Semantic deduplication of malware identities and associations is
        the deterministic persistence-boundary extractor's concern (PR 18);
        the provider preserves every distinct validated source record.
        """
        payload = threatfox_search_response(
            asyncrat_ip_port_record(id="864202"),
            asyncrat_ip_port_record(id="864203", ioc=CANONICAL_ASYNCRAT_IP_PORT),
        )
        result = await investigate(httpx.Response(200, json=payload), entity=_IP_ENTITY)
        matches = result.evidence[0].facts["matches"]
        assert len(matches) == 2
        assert {m["threatfox_id"] for m in matches} == {"864202", "864203"}
        assert {m["malware"] for m in matches} == {CANONICAL_ASYNCRAT_MALWARE}

    async def test_printable_name_difference_does_not_change_identity_input(
        self,
    ) -> None:
        """The machine identifier, not the printable name, is the identity input."""
        payload = threatfox_search_response(
            asyncrat_ip_port_record(id="864202", malware_printable="AsyncRAT"),
            asyncrat_ip_port_record(id="864203", malware_printable="asyncrat"),
        )
        result = await investigate(httpx.Response(200, json=payload), entity=_IP_ENTITY)
        matches = result.evidence[0].facts["matches"]
        assert {m["malware"] for m in matches} == {CANONICAL_ASYNCRAT_MALWARE}
        assert {m["malware_printable"] for m in matches} == {"AsyncRAT", "asyncrat"}

    async def test_source_confidence_remains_source_fact(self) -> None:
        """The provider confidence level is retained without any derived weight."""
        payload = threatfox_search_response(
            asyncrat_ip_port_record(confidence_level=75)
        )
        result = await investigate(httpx.Response(200, json=payload), entity=_IP_ENTITY)
        match = result.evidence[0].facts["matches"][0]
        assert match["confidence_level"] == 75
        assert set(result.evidence[0].facts) == {"matches"}

    async def test_null_tags_and_reference_retained(self) -> None:
        """Documented null tags/reference values are retained as nulls."""
        payload = threatfox_search_response(
            asyncrat_ip_port_record(tags=None, reference=None)
        )
        result = await investigate(httpx.Response(200, json=payload), entity=_IP_ENTITY)
        match = result.evidence[0].facts["matches"][0]
        assert match["tags"] is None
        assert match["reference"] is None

    async def test_no_entity_relationship_or_persistence_objects(self) -> None:
        """The result carries evidence only: no discovered entities or edges."""
        result = await investigate(
            httpx.Response(
                200, json=threatfox_search_response(asyncrat_ip_port_record())
            ),
            entity=_IP_ENTITY,
        )
        assert isinstance(result, ProviderResult)
        assert result.errors == ()
        assert set(result.model_dump()) == {"provider", "evidence", "errors"}
        evidence = result.evidence[0]
        assert evidence.type == EvidenceType.THREAT_INTELLIGENCE
        # The evidence facts carry no entity/relationship structures.
        serialized = str(evidence.facts)
        for fragment in ("entity", "relationship", "associated_with", "discovery"):
            assert fragment not in serialized


# -- Input validation ordering ------------------------------------------------


@pytest.mark.unit
class TestInputValidationOrdering:
    """Validation happens before clock evaluation and HTTP I/O."""

    @staticmethod
    async def _investigate_no_io(entity: Entity) -> ProviderResult:
        async with failing_io_client() as client:
            provider = threatfox_provider(client)
            return await provider.investigate(FIXED_UUID, entity)

    @pytest.mark.parametrize(
        "entity",
        [
            Entity(type=EntityType.URL, value="https://example.com/path"),
            Entity(type=EntityType.MALWARE, value="win.asyncrat"),
            Entity(type=EntityType.ASN, value="AS64496"),
            Entity(type=EntityType.ATTACK_TECHNIQUE, value="T1566"),
            Entity(type=EntityType.VULNERABILITY, value="CVE-2026-1234"),
            Entity(type=EntityType.NETWORK_PREFIX, value="203.0.113.0/24"),
            Entity(type=EntityType.ORGANIZATION, value="Example Corp"),
            Entity(type=EntityType.DOMAIN, value="example.com.."),
            Entity(type=EntityType.DOMAIN, value="under_score.example.com"),
            Entity(type=EntityType.IP_ADDRESS, value="999.999.999.999"),
            Entity(type=EntityType.IP_ADDRESS, value="not-an-ip"),
        ],
    )
    async def test_unsupported_or_invalid_input_never_performs_io(
        self, entity: Entity
    ) -> None:
        """Unsupported and invalid inputs yield UNSUPPORTED_INDICATOR with zero I/O."""
        result = await self._investigate_no_io(entity)
        assert result.evidence == ()
        assert len(result.errors) == 1
        assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert result.errors[0].retryable is False

    async def test_provider_id_is_stable_source_urn(self) -> None:
        """The provider publishes the stable ThreatFox source URN."""
        async with failing_io_client() as client:
            provider = threatfox_provider(client)
            assert provider.id == "urn:ati:source:threatfox"

    async def test_supports_only_domain_and_ip(self) -> None:
        """``supports`` is deterministic and covers exactly DOMAIN/IP_ADDRESS."""
        async with failing_io_client() as client:
            provider = threatfox_provider(client)
            assert provider.supports(_DOMAIN_ENTITY)
            assert provider.supports(_IP_ENTITY)
            assert not provider.supports(
                Entity(type=EntityType.URL, value="https://example.com/")
            )

    async def test_blank_auth_key_rejected(self) -> None:
        """A blank Auth-Key is a construction-time failure."""
        async with failing_io_client() as client:
            with pytest.raises(ValueError, match="Auth-Key"):
                ThreatFoxProvider(ProviderHttpClient(client=client), auth_key="   ")

    async def test_error_result_is_single_typed_error(self) -> None:
        """Every failure path yields exactly one typed ProviderError."""
        result = await investigate(httpx.Response(401, json={}), entity=_DOMAIN_ENTITY)
        assert len(result.errors) == 1
        assert isinstance(result.errors[0], ProviderError)
