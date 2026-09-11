# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""URLhaus provider unit tests.

# The provider/test modules deliberately mirror the established
# provider-family shapes (see ThreatFox/AbuseIPDB); per-block R0801
# suppression is not supported by Pylint, so duplicate-code is
# disabled at module scope for the deliberately accepted duplication.

Covers the strict response-record schema, the pure identity-matching
rules, envelope/query-status handling, evidence normalization, payload
fact-only policy, duplicate handling, and input-validation ordering —
all against ATI-authored synthetic responses carried by an in-process
transport. No test contacts the real URLhaus service, fetches any
returned URL, or downloads any payload.
"""

from __future__ import annotations

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
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from agentic_threat_investigator.infrastructure.providers.urlhaus import UrlhausProvider
from tests.support.provider_http import failing_io_client
from tests.support.urlhaus_fixtures import (
    CANONICAL_URLHAUS_DOMAIN,
    CANONICAL_URLHAUS_IPV4,
    CANONICAL_URLHAUS_URL,
    FIXED_TS,
    FIXED_UUID,
    MATCH_FACT_KEYS,
    PAYLOAD_FACT_KEYS,
    SYNTHETIC_MD5,
    SYNTHETIC_SHA256,
    investigate,
    urlhaus_host_response,
    urlhaus_host_url_record,
    urlhaus_no_results_response,
    urlhaus_payload,
    urlhaus_provider,
    urlhaus_url_record,
    urlhaus_url_response,
)

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]

_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

_DOMAIN_ENTITY = Entity(type=EntityType.DOMAIN, value=CANONICAL_URLHAUS_DOMAIN)
_URL_ENTITY = Entity(type=EntityType.URL, value=CANONICAL_URLHAUS_URL)
_IPV4_ENTITY = Entity(type=EntityType.IP_ADDRESS, value=CANONICAL_URLHAUS_IPV4)


def _assert_unsupported_no_io(result: ProviderResult) -> None:
    """Assert exactly one non-retryable UNSUPPORTED_INDICATOR and no evidence."""
    (error,) = result.errors
    assert not result.evidence
    assert error.code is ProviderErrorCode.UNSUPPORTED_INDICATOR
    assert error.retryable is False


def _assert_invalid_response(result: ProviderResult) -> None:
    """Assert exactly one non-retryable INVALID_RESPONSE error and no evidence."""
    (error,) = result.errors
    assert not result.evidence
    assert error.code is ProviderErrorCode.INVALID_RESPONSE
    assert error.retryable is False


def _assert_one_invalid_response(result: ProviderResult) -> None:
    """Assert exactly one error, no evidence, without a retryability claim."""
    (error,) = result.errors
    assert not result.evidence
    assert error.code is ProviderErrorCode.INVALID_RESPONSE


# -- Applicability and input validation ordering -------------------------------


@pytest.mark.unit
class TestApplicabilityAndValidationOrdering:
    """Support decisions and validation happen before clock and HTTP I/O."""

    @staticmethod
    async def _probe_without_io(entity: Entity) -> ProviderResult:
        """Investigate through a client that fails the test on any I/O."""
        async with failing_io_client() as client:
            urlhaus = urlhaus_provider(client)
            return await urlhaus.investigate(FIXED_UUID, entity)

    async def test_url_entity_is_supported(self) -> None:
        """URL entities are supported now that the identity contract exists."""
        async with failing_io_client() as client:
            provider = urlhaus_provider(client)
            assert provider.supports(_URL_ENTITY)
            assert provider.id == "urn:ati:source:urlhaus"

    @pytest.mark.parametrize(
        "entity",
        [
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
            Entity(type=EntityType.URL, value="ftp://example.com/"),
            Entity(type=EntityType.URL, value="http://user:pass@example.com/"),
            Entity(type=EntityType.URL, value="http://example.com/#frag"),
        ],
    )
    async def test_unsupported_or_invalid_input_never_performs_io(
        self, entity: Entity
    ) -> None:
        """Unsupported and invalid inputs yield UNSUPPORTED_INDICATOR with zero I/O."""
        result = await self._probe_without_io(entity)
        _assert_unsupported_no_io(result)

    async def test_ipv6_host_lookup_is_unsupported(self) -> None:
        """IPv6 hosts are rejected: the host-query contract documents IPv4 only."""
        result = await self._probe_without_io(
            Entity(type=EntityType.IP_ADDRESS, value="2001:db8::1")
        )
        _assert_unsupported_no_io(result)

    async def test_blank_auth_key_rejected(self) -> None:
        """A blank Auth-Key is a construction-time failure."""
        async with failing_io_client() as client:
            with pytest.raises(ValueError, match="Auth-Key"):
                UrlhausProvider(ProviderHttpClient(client=client), auth_key="   ")


# -- Evidence normalization: URL lookup ----------------------------------------


@pytest.mark.unit
class TestUrlLookupEvidence:
    """Exact-URL lookup normalization and identity checks."""

    async def test_url_hit_normalizes_grouped_evidence(self) -> None:
        """A URL hit emits one THREAT_INTELligence evidence with exact facts."""
        result = await investigate(
            httpx.Response(200, json=urlhaus_url_response()),
            entity=_URL_ENTITY,
            clock=lambda: FIXED_TS,
        )
        assert result.errors == ()
        assert result.provider == "urn:ati:source:urlhaus"
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.type == EvidenceType.THREAT_INTELLIGENCE
        assert evidence.investigation_id == FIXED_UUID
        assert evidence.subject.type == EntityType.URL
        assert evidence.subject.value == CANONICAL_URLHAUS_URL
        assert evidence.source == "urn:ati:source:urlhaus"
        assert evidence.source_url == _URL_ENDPOINT
        assert evidence.retrieved_at == FIXED_TS
        assert evidence.observed_at == datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)
        assert evidence.raw_payload is None

        matches = evidence.facts["matches"]
        assert len(matches) == 1
        match = matches[0]
        assert isinstance(matches, tuple)
        assert set(match) == MATCH_FACT_KEYS
        assert match["urlhaus_id"] == "556677"
        assert match["url"] == CANONICAL_URLHAUS_URL
        assert match["url_status"] == "online"
        assert match["date_added"] == "2026-08-20T12:00:00Z"
        assert match["last_online"] is None
        assert match["threat"] == "malware_download"
        assert match["host"] == CANONICAL_URLHAUS_DOMAIN
        assert match["tags"] == ("elf",)
        payloads = match["payloads"]
        assert len(payloads) == 1
        assert set(payloads[0]) == PAYLOAD_FACT_KEYS
        assert payloads[0]["first_seen"] == "2026-08-20"
        assert payloads[0]["response_md5"] == SYNTHETIC_MD5
        assert payloads[0]["response_sha256"] == SYNTHETIC_SHA256
        assert payloads[0]["response_size"] == 12345
        assert payloads[0]["signature"] is None
        # Download links and analyst metadata never reach the facts.
        serialized = str(evidence.facts)
        for fragment in (
            "urlhaus_download",
            "virustotal",
            "imphash",
            "ssdeep",
            "tlsh",
            "magika",
            "reporter",
            "blacklists",
            "urlhaus_reference",
        ):
            assert fragment not in serialized

    async def test_url_lookup_ignores_query_status_member_in_record(self) -> None:
        """The record-level ``query_status`` member is not part of the facts."""
        result = await investigate(
            httpx.Response(200, json=urlhaus_url_response()),
            entity=_URL_ENTITY,
        )
        assert set(result.evidence[0].facts) == {"matches"}

    async def test_mismatched_returned_url_invalidates_response(self) -> None:
        """A returned URL that canonicalizes differently is INVALID_RESPONSE."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_url_response(url=CANONICAL_URLHAUS_URL + "x"),
            ),
            entity=_URL_ENTITY,
        )
        _assert_one_invalid_response(result)

    async def test_canonical_equivalent_returned_url_matches(self) -> None:
        """A canonically equivalent returned URL passes identity validation."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_url_response(
                    url="http://MALICIOUS-domain.test/download/payload.bin"
                ),
            ),
            entity=_URL_ENTITY,
        )
        assert result.errors == ()
        assert len(result.evidence) == 1

    async def test_malformed_returned_url_invalidates_response(self) -> None:
        """A returned URL outside the identity contract is INVALID_RESPONSE."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_url_response(url="http://malicious-domain.test/%zz"),
            ),
            entity=_URL_ENTITY,
        )
        _assert_one_invalid_response(result)


# -- Evidence normalization: host lookup ----------------------------------------


@pytest.mark.unit
class TestHostLookupEvidence:
    """Host-lookup normalization, identity checks, and duplicate handling."""

    async def test_domain_hit_normalizes_grouped_evidence(self) -> None:
        """A domain hit emits one grouped evidence over the host records."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_host_response(urlhaus_host_url_record(), url_count="1"),
            ),
            entity=_DOMAIN_ENTITY,
            clock=lambda: FIXED_TS,
        )
        assert result.errors == ()
        evidence = result.evidence[0]
        assert evidence.subject.type == EntityType.DOMAIN
        assert evidence.subject.value == CANONICAL_URLHAUS_DOMAIN
        assert evidence.source_url == _HOST_ENDPOINT
        assert evidence.observed_at == datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)
        match = evidence.facts["matches"][0]
        assert match["url"] == CANONICAL_URLHAUS_URL
        assert match["host"] is None  # host-query entries carry no host member
        assert evidence.facts["url_count"] == 1

    async def test_ipv4_host_hit_normalizes_grouped_evidence(self) -> None:
        """An IPv4 hit keeps the canonical queried IP as the subject."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_host_response(
                    urlhaus_host_url_record(url="http://203.0.113.42/payload.bin"),
                    url_count="1",
                    host=CANONICAL_URLHAUS_IPV4,
                ),
            ),
            entity=_IPV4_ENTITY,
        )
        assert result.errors == ()
        evidence = result.evidence[0]
        assert evidence.subject.type == EntityType.IP_ADDRESS
        assert evidence.subject.value == CANONICAL_URLHAUS_IPV4
        assert evidence.facts["matches"][0]["url"] == "http://203.0.113.42/payload.bin"

    async def test_host_record_on_other_host_invalidates_response(self) -> None:
        """One unrelated record invalidates the whole host response."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_host_response(
                    urlhaus_host_url_record(),
                    urlhaus_host_url_record(
                        id="556678", url="http://other-domain.test/x.bin"
                    ),
                    url_count="2",
                ),
            ),
            entity=_DOMAIN_ENTITY,
        )
        _assert_one_invalid_response(result)

    async def test_malformed_host_record_url_invalidates_response(self) -> None:
        """A host record with an unparseable URL invalidates the response."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_host_response(
                    urlhaus_host_url_record(url="not a url at all"), url_count="1"
                ),
            ),
            entity=_DOMAIN_ENTITY,
        )
        _assert_one_invalid_response(result)

    async def test_exact_duplicate_id_produces_one_match(self) -> None:
        """Two identical entries sharing one ID collapse to one match."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_host_response(
                    urlhaus_host_url_record(id="556677"),
                    urlhaus_host_url_record(id="556677"),
                    url_count="1",
                ),
            ),
            entity=_DOMAIN_ENTITY,
        )
        assert result.errors == ()
        matches = result.evidence[0].facts["matches"]
        assert len(matches) == 1
        assert matches[0]["urlhaus_id"] == "556677"

    async def test_conflicting_duplicate_id_invalidates_response(self) -> None:
        """The same ID with different consumed content is INVALID_RESPONSE."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_host_response(
                    urlhaus_host_url_record(id="556677", url_status="online"),
                    urlhaus_host_url_record(id="556677", url_status="offline"),
                    url_count="2",
                ),
            ),
            entity=_DOMAIN_ENTITY,
        )
        _assert_invalid_response(result)
        assert "556677" not in result.errors[0].message
        assert CANONICAL_URLHAUS_URL not in result.errors[0].message

    async def test_duplicate_id_with_ignored_field_change_is_exact_duplicate(
        self,
    ) -> None:
        """Ignored-field differences do not conflict or create extra facts."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_host_response(
                    urlhaus_host_url_record(id="556677"),
                    urlhaus_host_url_record(
                        id="556677",
                        reporter="other_reporter",
                        larted="true",
                        takedown_time_seconds=42,
                    ),
                    url_count="1",
                ),
            ),
            entity=_DOMAIN_ENTITY,
        )
        assert result.errors == ()
        matches = result.evidence[0].facts["matches"]
        assert len(matches) == 1

    async def test_distinct_ids_with_same_url_both_remain_in_order(self) -> None:
        """Distinct source IDs are never merged, even with identical URLs."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_host_response(
                    urlhaus_host_url_record(id="556677"),
                    urlhaus_host_url_record(id="556678"),
                    url_count="2",
                ),
            ),
            entity=_DOMAIN_ENTITY,
        )
        matches = result.evidence[0].facts["matches"]
        assert [m["urlhaus_id"] for m in matches] == ["556677", "556678"]


# -- Envelope and query-status handling -----------------------------------------


@pytest.mark.unit
class TestEnvelopeValidation:
    """Top-level envelope and query-status validation tests."""

    @pytest.mark.parametrize(
        "payload",
        [
            [],
            ["ok"],
            {},
            {"query_status": None},
            {"query_status": 42},
            {"query_status": ""},
        ],
    )
    async def test_malformed_envelope_rejected(self, payload: Any) -> None:
        """A missing, non-string, or empty query_status is INVALID_RESPONSE."""
        result = await investigate(
            httpx.Response(200, json=payload), entity=_URL_ENTITY
        )
        _assert_one_invalid_response(result)

    @pytest.mark.parametrize(
        "status",
        ["no_result", "ratelimited", "error", "http_get_expected", "mystery"],
    )
    async def test_unknown_or_wrong_status_never_success(self, status: str) -> None:
        """Unknown statuses (including ThreatFox spellings) are never success."""
        result = await investigate(
            httpx.Response(200, json={"query_status": status}), entity=_URL_ENTITY
        )
        _assert_invalid_response(result)

    async def test_no_results_is_valid_empty_result(self) -> None:
        """The documented plural ``no_results`` yields an empty result."""
        result = await investigate(
            httpx.Response(200, json=urlhaus_no_results_response()),
            entity=_URL_ENTITY,
        )
        assert result.provider == "urn:ati:source:urlhaus"
        assert result.evidence == ()
        assert result.errors == ()

    async def test_body_encoded_request_errors_map_to_invalid_response(self) -> None:
        """Documented body-encoded request errors are non-retryable failures."""
        for status in ("http_post_expected", "invalid_url", "invalid_host"):
            result = await investigate(
                httpx.Response(200, json={"query_status": status}),
                entity=_URL_ENTITY,
            )
            _assert_invalid_response(result)

    async def test_ok_url_response_missing_required_members_rejected(self) -> None:
        """An ok URL response missing required members is INVALID_RESPONSE."""
        record = urlhaus_url_response()
        del record["url_status"]
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        _assert_one_invalid_response(result)

    async def test_ok_host_response_missing_urls_collection_rejected(self) -> None:
        """An ok host response without the urls array is INVALID_RESPONSE."""
        payload = urlhaus_host_response(urlhaus_host_url_record())
        del payload["urls"]
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_one_invalid_response(result)

    async def test_ok_host_response_wrong_collection_type_rejected(self) -> None:
        """A non-list urls collection is INVALID_RESPONSE."""
        payload = urlhaus_host_response(urlhaus_host_url_record())
        payload["urls"] = {"id": "556677"}
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_one_invalid_response(result)

    async def test_ok_host_response_wrong_url_count_type_rejected(self) -> None:
        """A non-numeric url_count is INVALID_RESPONSE."""
        payload = urlhaus_host_response(urlhaus_host_url_record(), url_count="many")
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_one_invalid_response(result)


# -- Strict record schema --------------------------------------------------------


@pytest.mark.unit
class TestStrictRecordSchema:
    """Strict scalar, enum, timestamp, tag, and payload member validation."""

    @pytest.mark.parametrize(
        "overrides",
        [
            {"id": "not-decimal"},
            {"id": 556677},
            {"url_status": "benign"},
            {"url_status": 1},
            {"threat": ""},
            {"threat": " padded"},
            {"date_added": "2026-08-20T12:00:00Z"},
            {"date_added": "2026-08-20 12:00:00"},
            {"date_added": "not a timestamp"},
            {"last_online": "2026-08-19 00:00:00 UTC"},  # before date_added
            {"tags": "elf"},
            {"tags": [42]},
            {"tags": [" padded"]},
            {"payloads": {"firstseen": "2026-08-20"}},
            {"host": " padded host"},
        ],
    )
    async def test_malformed_record_members_rejected(
        self, overrides: dict[str, Any]
    ) -> None:
        """One malformed member invalidates the whole response."""
        result = await investigate(
            httpx.Response(200, json=urlhaus_url_response(**overrides)),
            entity=_URL_ENTITY,
        )
        _assert_invalid_response(result)
        # The error never carries the response body or the offending record.
        assert "payload.bin" not in result.errors[0].message

    async def test_null_last_online_retained(self) -> None:
        """The documented null last_online value is retained as a null."""
        record = urlhaus_url_record(last_online=None)
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        match = result.evidence[0].facts["matches"][0]
        assert match["last_online"] is None

    async def test_null_tags_and_payloads_are_rejected(self) -> None:
        """Tags and payloads are documented required lists: null is invalid."""
        for overrides in ({"tags": None}, {"payloads": None}):
            record = urlhaus_url_record(**overrides)
            result = await investigate(
                httpx.Response(200, json=record), entity=_URL_ENTITY
            )
            _assert_invalid_response(result)

    @pytest.mark.parametrize(
        "missing_key",
        [
            "id",
            "url",
            "url_status",
            "host",
            "date_added",
            "last_online",
            "threat",
            "tags",
            "payloads",
        ],
    )
    async def test_missing_required_direct_record_key_rejected(
        self, missing_key: str
    ) -> None:
        """Each documented direct-record key is required: absence is invalid."""
        record = urlhaus_url_record()
        del record[missing_key]
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        _assert_invalid_response(result)

    async def test_last_online_after_date_added_observed_at(self) -> None:
        """observed_at is the latest source observation including last_online."""
        record = urlhaus_url_record(last_online="2026-08-21 09:30:00 UTC")
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        evidence = result.evidence[0]
        assert evidence.observed_at == datetime(2026, 8, 21, 9, 30, 0, tzinfo=UTC)
        match = evidence.facts["matches"][0]
        assert match["last_online"] == "2026-08-21T09:30:00Z"

    async def test_uppercase_hashes_normalized_lowercase(self) -> None:
        """Hash source facts are normalized to lowercase hex."""
        record = urlhaus_url_record(
            payloads=[
                urlhaus_payload(
                    response_md5=SYNTHETIC_MD5.upper(),
                    response_sha256=SYNTHETIC_SHA256.upper(),
                )
            ]
        )
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        payload = result.evidence[0].facts["matches"][0]["payloads"][0]
        assert payload["response_md5"] == SYNTHETIC_MD5
        assert payload["response_sha256"] == SYNTHETIC_SHA256

    @pytest.mark.parametrize(
        "overrides",
        [
            {"response_md5": "short"},
            {"response_md5": "g" * 32},
            {"response_sha256": "a" * 63},
            {"response_sha256": 42},
            {"response_size": True},
            {"response_size": "12.5"},
            {"response_size": -1},
            {"firstseen": "2026-08-20T00:00:00Z"},
            {"firstseen": "2026-13-40"},
        ],
    )
    async def test_malformed_payload_members_rejected(
        self, overrides: dict[str, Any]
    ) -> None:
        """One malformed payload member invalidates the whole response."""
        record = urlhaus_url_record(payloads=[urlhaus_payload(**overrides)])
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        _assert_one_invalid_response(result)

    async def test_empty_payloads_list_retained(self) -> None:
        """An explicitly empty payloads array is a valid empty fact list."""
        record = urlhaus_url_record(payloads=[])
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        match = result.evidence[0].facts["matches"][0]
        assert match["payloads"] == ()

    async def test_multiple_payloads_retained_in_order(self) -> None:
        """Multiple payload entries remain distinct and ordered."""
        record = urlhaus_url_record(
            payloads=[
                urlhaus_payload(),
                urlhaus_payload(firstseen="2026-08-21", filename="second.bin"),
            ]
        )
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        payloads = result.evidence[0].facts["matches"][0]["payloads"]
        assert [p["filename"] for p in payloads] == ["payload.bin", "second.bin"]

    async def test_integer_response_size_accepted(self) -> None:
        """A strict integer response_size is also accepted per the contract."""
        record = urlhaus_url_record(payloads=[urlhaus_payload(response_size=4096)])
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        payload = result.evidence[0].facts["matches"][0]["payloads"][0]
        assert payload["response_size"] == 4096


# -- Semantics and safety ---------------------------------------------------------


@pytest.mark.unit
class TestSemanticsAndSafety:
    """No-result, verdict, and boundary semantics."""

    async def test_no_results_is_not_benign(self) -> None:
        """A valid miss is an empty result with no error and no verdict."""
        result = await investigate(
            httpx.Response(200, json=urlhaus_no_results_response()),
            entity=_DOMAIN_ENTITY,
        )
        assert isinstance(result, ProviderResult)
        assert result.evidence == ()
        assert result.errors == ()
        assert set(result.model_dump()) == {"provider", "evidence", "errors"}

    async def test_offline_status_is_not_a_benign_verdict(self) -> None:
        """An offline url_status is a source fact, never an ATI verdict."""
        record = urlhaus_url_record(url_status="offline")
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        match = result.evidence[0].facts["matches"][0]
        assert match["url_status"] == "offline"

    async def test_payload_metadata_is_not_maliciousness(self) -> None:
        """Payload/signature facts carry no derived maliciousness label."""
        record = urlhaus_url_record(payloads=[urlhaus_payload(signature="Heodo")])
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        payload = result.evidence[0].facts["matches"][0]["payloads"][0]
        assert payload["signature"] == "Heodo"
        # No verdict, confidence, or assessment keys exist anywhere.
        assert "verdict" not in str(result.evidence[0].facts)
        assert "confidence" not in str(result.evidence[0].facts)

    async def test_no_entity_relationship_or_persistence_objects(self) -> None:
        """The result carries evidence only: no discovered entities or edges."""
        result = await investigate(
            httpx.Response(200, json=urlhaus_url_response()), entity=_URL_ENTITY
        )
        assert set(result.model_dump()) == {"provider", "evidence", "errors"}
        assert isinstance(result, ProviderResult)
        assert result.errors == ()
        evidence = result.evidence[0]
        assert evidence.type is EvidenceType.THREAT_INTELLIGENCE
        for fragment in ("relationship", "associated_with", "discovery", "resolves_to"):
            assert fragment not in str(evidence.facts)

    async def test_error_result_is_single_typed_error(self) -> None:
        """Every failure path yields exactly one typed ProviderError."""
        result = await investigate(httpx.Response(401, json={}), entity=_URL_ENTITY)
        assert len(result.errors) == 1
        assert isinstance(result.errors[0], ProviderError)


# -- Remediation: host-response envelope and collection totality ----------------


def _raising_clock() -> Any:
    """Build a clock callable that fails the test if it is ever evaluated."""

    def _clock() -> datetime:
        raise AssertionError("clock must not be evaluated before validation")

    return _clock


@pytest.mark.unit
class TestHostEnvelopeValidation:
    """Top-level host identity and firstseen provenance validation."""

    async def test_empty_host_urls_collection_is_typed_error(self) -> None:
        """An ok host response with zero urls entries is INVALID_RESPONSE."""
        payload = urlhaus_host_response(url_count="0")
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_invalid_response(result)

    async def test_missing_top_level_host_is_typed_error(self) -> None:
        """A host response without the documented host member is invalid."""
        payload = urlhaus_host_response(urlhaus_host_url_record())
        del payload["host"]
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_invalid_response(result)

    @pytest.mark.parametrize("bad_host", [42, None, "   ", ""])
    async def test_non_string_or_blank_top_level_host_is_typed_error(
        self, bad_host: Any
    ) -> None:
        """A non-string, null, or blank top-level host is invalid."""
        payload = urlhaus_host_response(urlhaus_host_url_record(), host=bad_host)
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_invalid_response(result)

    async def test_mismatched_top_level_domain_is_typed_error(self) -> None:
        """A response for a different domain is invalid even with matching URLs."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(), host="other-domain.test"
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_invalid_response(result)

    async def test_mismatched_top_level_ip_is_typed_error(self) -> None:
        """An IP query with a domain top-level host is invalid."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(url="http://203.0.113.42/payload.bin"),
            host=CANONICAL_URLHAUS_DOMAIN,
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_IPV4_ENTITY
        )
        _assert_invalid_response(result)

    async def test_wrong_family_ip_top_level_host_is_typed_error(self) -> None:
        """An IPv6 top-level host cannot match an IPv4 query."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(url="http://203.0.113.42/payload.bin"),
            host="2001:db8::1",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_IPV4_ENTITY
        )
        _assert_invalid_response(result)

    async def test_malformed_ip_top_level_host_is_typed_error(self) -> None:
        """A malformed IP top-level host is invalid for an IP query."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(url="http://203.0.113.42/payload.bin"),
            host="999.999.999.999",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_IPV4_ENTITY
        )
        _assert_invalid_response(result)

    @pytest.mark.parametrize(
        "firstseen",
        [
            None,
            42,
            "not a timestamp",
            "2026-08-19T08:00:00Z",
            " 2026-08-19 08:00:00 UTC",
        ],
    )
    async def test_missing_or_malformed_firstseen_is_typed_error(
        self, firstseen: Any
    ) -> None:
        """Missing, null, non-string, or malformed firstseen is invalid."""
        payload = urlhaus_host_response(urlhaus_host_url_record())
        if firstseen is None:
            del payload["firstseen"]
        else:
            payload["firstseen"] = firstseen
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_invalid_response(result)

    async def test_canonical_equivalent_top_level_host_accepted(self) -> None:
        """A case/trailing-dot equivalent top-level host is accepted."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(), host="MALICIOUS-domain.test."
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.errors == ()
        evidence = result.evidence[0]
        assert evidence.facts["queried_host"] == CANONICAL_URLHAUS_DOMAIN
        assert evidence.facts["first_seen"] == "2026-08-19T08:00:00Z"
        assert evidence.facts["url_count"] == 1

    async def test_host_provenance_facts_are_normalized(self) -> None:
        """The host envelope facts use the stable documented names."""
        result = await investigate(
            httpx.Response(200, json=urlhaus_host_response(urlhaus_host_url_record())),
            entity=_DOMAIN_ENTITY,
            clock=lambda: FIXED_TS,
        )
        evidence = result.evidence[0]
        assert evidence.facts["queried_host"] == CANONICAL_URLHAUS_DOMAIN
        assert evidence.facts["first_seen"] == "2026-08-19T08:00:00Z"
        assert evidence.facts["url_count"] == 1
        assert evidence.retrieved_at == FIXED_TS
        assert evidence.raw_payload is None

    async def test_observed_at_is_latest_of_firstseen_and_records(self) -> None:
        """A later host firstseen does not lose a newer record observation."""
        later_firstseen = urlhaus_host_response(
            urlhaus_host_url_record(),
            firstseen="2026-08-25 00:00:00 UTC",
        )
        result = await investigate(
            httpx.Response(200, json=later_firstseen), entity=_DOMAIN_ENTITY
        )
        assert result.evidence[0].observed_at == datetime(
            2026, 8, 25, 0, 0, 0, tzinfo=UTC
        )

        earlier_firstseen = urlhaus_host_response(
            urlhaus_host_url_record(id="556678", date_added="2026-08-22 09:00:00 UTC"),
            firstseen="2026-08-19 08:00:00 UTC",
            url_count="1",
        )
        result = await investigate(
            httpx.Response(200, json=earlier_firstseen), entity=_DOMAIN_ENTITY
        )
        assert result.evidence[0].observed_at == datetime(
            2026, 8, 22, 9, 0, 0, tzinfo=UTC
        )


@pytest.mark.unit
class TestDirectRecordCrossFieldHost:
    """Cross-field validation of the direct-record host member."""

    async def test_host_disagreeing_with_url_is_rejected(self) -> None:
        """A record host that differs from its URL host is invalid."""
        record = urlhaus_url_record(host="other-domain.test")
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        _assert_invalid_response(result)

    async def test_canonical_equivalent_host_spelling_accepted(self) -> None:
        """A case-equivalent host spelling is accepted and normalized."""
        record = urlhaus_url_record(host="MALICIOUS-domain.test")
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        assert result.errors == ()
        match = result.evidence[0].facts["matches"][0]
        assert match["host"] == "malicious-domain.test"
        assert match["url"] == CANONICAL_URLHAUS_URL

    async def test_terminal_root_dot_host_is_canonicalized(self) -> None:
        """A terminal DNS root dot on the record host is canonicalized away."""
        record = urlhaus_url_record(host="malicious-domain.test.")
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        assert result.errors == ()
        match = result.evidence[0].facts["matches"][0]
        assert match["host"] == "malicious-domain.test"

    async def test_canonical_equivalent_ipv6_host_normalized(self) -> None:
        """An expanded IPv6 record host emits the compressed canonical form.

        This is a direct URL lookup only; it does not enable IPv6 host
        queries, which remain unsupported.
        """
        url = "http://[2001:0db8:0000:0000:0000:0000:0000:0001]/payload.bin"
        record = urlhaus_url_record(
            url=url, host="2001:0DB8:0000:0000:0000:0000:0000:0001"
        )
        result = await investigate(
            httpx.Response(200, json=record),
            entity=Entity(
                type=EntityType.URL, value="http://[2001:db8::1]/payload.bin"
            ),
        )
        assert result.errors == ()
        match = result.evidence[0].facts["matches"][0]
        assert match["url"] == "http://[2001:db8::1]/payload.bin"
        assert match["host"] == "2001:db8::1"

    async def test_ip_host_url_with_ip_record_host_accepted(self) -> None:
        """An IP-host URL requires the record host to be the same IP."""
        url = "http://203.0.113.42/payload.bin"
        record = urlhaus_url_record(url=url, host="203.0.113.42")
        result = await investigate(
            httpx.Response(200, json=record),
            entity=Entity(type=EntityType.URL, value=url),
        )
        assert result.errors == ()

    async def test_ip_host_url_with_domain_record_host_rejected(self) -> None:
        """An IP-host URL with a domain record host is cross-field invalid."""
        url = "http://203.0.113.42/payload.bin"
        record = urlhaus_url_record(url=url, host="malicious-domain.test")
        result = await investigate(
            httpx.Response(200, json=record),
            entity=Entity(type=EntityType.URL, value=url),
        )
        _assert_invalid_response(result)

    async def test_malformed_record_host_is_rejected(self) -> None:
        """A malformed record host never passes cross-field validation."""
        record = urlhaus_url_record(host="under_score.example.test")
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        _assert_invalid_response(result)


@pytest.mark.unit
class TestEndpointSpecificRecords:
    """Endpoint-specific record shapes and the documented threat value."""

    async def test_host_nested_records_ignore_url_only_fields(self) -> None:
        """Unexpected URL-only members are ignored and never emitted."""
        nested = urlhaus_host_url_record(
            host="evil.test",
            last_online="2026-08-21 00:00:00 UTC",
            payloads=[urlhaus_payload()],
        )
        result = await investigate(
            httpx.Response(200, json=urlhaus_host_response(nested, url_count="1")),
            entity=_DOMAIN_ENTITY,
        )
        assert result.errors == ()
        match = result.evidence[0].facts["matches"][0]
        assert match["host"] is None
        assert match["last_online"] is None
        assert match["payloads"] is None

    async def test_unknown_threat_rejected_on_both_endpoints(self) -> None:
        """Only the documented malware_download threat value is accepted."""
        direct = urlhaus_url_record(threat="phishing")
        result = await investigate(httpx.Response(200, json=direct), entity=_URL_ENTITY)
        _assert_invalid_response(result)

        nested = urlhaus_host_url_record(threat="phishing")
        result = await investigate(
            httpx.Response(200, json=urlhaus_host_response(nested, url_count="1")),
            entity=_DOMAIN_ENTITY,
        )
        _assert_invalid_response(result)

    @pytest.mark.parametrize(
        "bad_threat", [42, None, "", " padded", "Malware_download"]
    )
    async def test_malformed_threat_is_rejected(self, bad_threat: Any) -> None:
        """Padded, blank, non-string, and case-shifted threats are invalid."""
        record = urlhaus_url_record(threat=bad_threat)
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        _assert_invalid_response(result)
