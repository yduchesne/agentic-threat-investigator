# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Strict schema and provider contract tests for IpinfoLiteProvider."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from agentic_threat_investigator.infrastructure.providers.ipinfo_lite import (
    _IPINFO_LITE_ENDPOINT,
    _LITE_RESPONSE_FIELDS,
    IpinfoLiteProvider,
    IpinfoLiteResponse,
)
from tests.support.provider_http import failing_io_client as _client_failing_io
from tests.support.provider_http import handler_client as _client_handler
from tests.support.provider_http import no_op_sleep as _no_op_sleep
from tests.support.provider_http import static_client as _client_static
from tests.support.provider_http import zero_jitter as _zero_jitter

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
_FIXED_TOKEN = "test-ipinfo-token"


class _Removed:  # pylint: disable=too-few-public-methods
    """Sentinel marking a member as absent from the synthetic response."""


_REMOVED = _Removed()


def _lite_response(**overrides: Any) -> dict[str, Any]:
    """Helper building a fully populated canonical Lite response."""
    data: dict[str, Any] = {
        "ip": "8.8.8.8",
        "asn": "AS15169",
        "as_name": "Google LLC",
        "as_domain": "google.com",
        "country_code": "US",
        "country": "United States",
        "continent_code": "NA",
        "continent": "North America",
    }
    for key, value in overrides.items():
        if value is _REMOVED:
            data.pop(key, None)
        else:
            data[key] = value
    return data


def _provider(
    client: httpx.AsyncClient,
    *,
    clock: Any = None,
    http_kwargs: dict[str, Any] | None = None,
) -> IpinfoLiteProvider:
    """Build the provider under test with the deterministic test token.

    ``http_kwargs`` apply to the shared HTTP client (sleep, jitter, policy);
    ``clock`` is the provider's UTC retrieval clock.
    """
    client_kwargs: dict[str, Any] = {
        "sleep": _no_op_sleep,
        "jitter_fn": _zero_jitter,
    }
    if http_kwargs:
        client_kwargs.update(http_kwargs)
    provider_kwargs: dict[str, Any] = {"clock": clock} if clock is not None else {}
    return IpinfoLiteProvider(
        ProviderHttpClient(client=client, **client_kwargs),
        token=_FIXED_TOKEN,
        **provider_kwargs,
    )


def _assert_no_token_leak(value: str) -> None:
    """Prove a provider-facing string carries no credential material."""
    assert _FIXED_TOKEN not in value, "credential material must never leak"


# -- Strict response model -------------------------------------------------


@pytest.mark.unit
@pytest.mark.provider_contract
class TestIpinfoLiteSchema:
    """Strict response-schema tests for the Lite lookup response model."""

    def test_fully_populated_response_parses(self) -> None:
        """A fully populated canonical response parses into canonical members."""
        parsed = IpinfoLiteResponse.model_validate(_lite_response())
        assert parsed.ip == "8.8.8.8"
        assert parsed.asn == "AS15169"
        assert parsed.as_name == "Google LLC"
        assert parsed.as_domain == "google.com"
        assert parsed.country_code == "US"
        assert parsed.country == "United States"
        assert parsed.continent_code == "NA"
        assert parsed.continent == "North America"

    def test_minimal_response_only_ip(self) -> None:
        """A response with only the required IP member parses with no optionals."""
        parsed = IpinfoLiteResponse.model_validate({"ip": "8.8.8.8"})
        assert parsed.ip == "8.8.8.8"
        for member in _LITE_RESPONSE_FIELDS[1:]:
            assert getattr(parsed, member) is None

    def test_unknown_top_level_member_ignored(self) -> None:
        """Unknown top-level members are ignored and never copied into facts."""
        parsed = IpinfoLiteResponse.model_validate(
            _lite_response(provider="IPinfo", future_member={"x": 1})
        )
        assert not hasattr(parsed, "provider")
        assert not hasattr(parsed, "future_member")

    def test_unknown_value_member_ignored(self) -> None:
        """Unknown member values do not affect canonical members."""
        parsed = IpinfoLiteResponse.model_validate(_lite_response(ip_version="v4"))
        assert parsed.ip == "8.8.8.8"

    @pytest.mark.parametrize("member", _LITE_RESPONSE_FIELDS)
    @pytest.mark.parametrize("bad", [True, 1, ["x"], {"x": 1}])
    def test_wrong_scalar_types_rejected(self, member: str, bad: Any) -> None:
        """Booleans, integers, lists, and objects are rejected for string members."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(**{member: bad}))

    @pytest.mark.parametrize("member", _LITE_RESPONSE_FIELDS[1:])
    def test_null_optional_member_rejected(self, member: str) -> None:
        """An explicit null member is malformed, not missing source data."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(**{member: None}))

    def test_null_required_member_rejected(self) -> None:
        """A null required member is malformed."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(ip=None))

    def test_missing_required_member_rejected(self) -> None:
        """A response without the required member is malformed."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(ip=_REMOVED))

    def test_empty_object_rejected(self) -> None:
        """An empty response object is malformed."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate({})

    @pytest.mark.parametrize(
        "member", ["asn", "as_name", "as_domain", "country", "continent"]
    )
    def test_blank_optional_member_rejected(self, member: str) -> None:
        """Present-but-blank string members are malformed."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(**{member: ""}))

    @pytest.mark.parametrize("member", ["as_name", "country", "continent"])
    def test_whitespace_only_descriptive_member_rejected(self, member: str) -> None:
        """Whitespace-only descriptive members are malformed."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(**{member: "   "}))

    def test_overlong_members_rejected(self) -> None:
        """Overlong members are rejected."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(ip="x" * 46))
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(asn="AS" + "9" * 11))
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(as_name="x" * 257))
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(as_domain="x" * 254))
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(country="x" * 129))
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(continent="x" * 65))

    @pytest.mark.parametrize(
        "textual",
        [
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::1",
            "2001:DB8::1",
        ],
    )
    def test_ipv6_canonicalization(self, textual: str) -> None:
        """Textual IPv6 variants parse into the canonical compressed form."""
        parsed = IpinfoLiteResponse.model_validate({"ip": textual})
        assert parsed.ip == "2001:db8::1"

    @pytest.mark.parametrize(
        "bad",
        ["999.999.999.999", "8.8.8", "example.com", "8.8.8.8/32", "  "],
    )
    def test_malformed_ip_rejected(self, bad: str) -> None:
        """Malformed IP members are rejected."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate({"ip": bad})

    def test_both_address_families_accepted(self) -> None:
        """Both address families are accepted."""
        assert IpinfoLiteResponse.model_validate({"ip": "8.8.4.4"}).ip == "8.8.4.4"
        assert (
            IpinfoLiteResponse.model_validate({"ip": "::ffff:8.8.8.8"}).ip
            == "::ffff:808:808"
        )


@pytest.mark.unit
@pytest.mark.provider_contract
class TestIpinfoLiteCanonicalization:
    """Whitespace-tolerant canonicalization and length-boundary behavior."""

    @pytest.mark.parametrize("textual", ["  8.8.8.8  ", "8.8.8.8 "])
    def test_ip_outer_whitespace_canonicalized(self, textual: str) -> None:
        """Outer whitespace is stripped before address parsing (RDAP convention)."""
        parsed = IpinfoLiteResponse.model_validate({"ip": textual})
        assert parsed.ip == "8.8.8.8"

    def test_max_asn_with_outer_whitespace_canonicalized(self) -> None:
        """A padded maximum legal ASN is judged on its canonical length."""
        parsed = IpinfoLiteResponse.model_validate(_lite_response(asn=" AS4294967295 "))
        assert parsed.asn == "AS4294967295"

    def test_max_length_ip_with_outer_whitespace_canonicalized(self) -> None:
        """A padded maximum-length textual IP canonicalizes instead of failing
        the raw member bound (45-character address plus whitespace)."""
        raw = " ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255 "
        assert len(raw) > 45
        parsed = IpinfoLiteResponse.model_validate({"ip": raw})
        assert parsed.ip == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

    def test_boundary_domain_with_outer_whitespace_canonicalized(self) -> None:
        """A padded domain whose canonical form sits at the length limit is accepted."""
        canonical = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
        assert len(canonical) == 253
        parsed = IpinfoLiteResponse.model_validate(
            _lite_response(as_domain=f"  {canonical} ")
        )
        assert parsed.as_domain == canonical

    def test_domain_over_max_length_after_canonicalization_rejected(self) -> None:
        """A domain whose canonical form exceeds the length limit is rejected."""
        overlong = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 62
        assert len(overlong) == 254
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(as_domain=overlong))

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("  AS15169  ", "AS15169"), ("AS15169 ", "AS15169")],
    )
    def test_asn_outer_whitespace_canonicalized(self, raw: str, expected: str) -> None:
        """Outer whitespace on the ASN is stripped before canonicalization."""
        parsed = IpinfoLiteResponse.model_validate(_lite_response(asn=raw))
        assert parsed.asn == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [(" google.com ", "google.com"), ("GOOGLE.COM\t", "google.com")],
    )
    def test_as_domain_outer_whitespace_canonicalized(
        self, raw: str, expected: str
    ) -> None:
        """Outer whitespace on the operator domain is stripped by the strict
        DNS-name canonicalizer, which also lowercases the value."""
        parsed = IpinfoLiteResponse.model_validate(_lite_response(as_domain=raw))
        assert parsed.as_domain == expected


@pytest.mark.unit
@pytest.mark.provider_contract
class TestIpinfoLiteAsn:
    """ASN normalization tests for the Lite response model."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("AS15169", "AS15169"),
            ("as15169", "AS15169"),
            ("AS000015169", "AS15169"),
            ("AS4294967295", "AS4294967295"),
        ],
    )
    def test_valid_asn_canonical(self, raw: str, expected: str) -> None:
        """Legal Lite ASN spellings parse into the canonical uppercase form."""
        parsed = IpinfoLiteResponse.model_validate(_lite_response(asn=raw))
        assert parsed.asn == expected

    @pytest.mark.parametrize(
        "bad",
        [
            "15169",
            "AS",
            "ASD",
            "ASX123",
            "AS 123",
            "AS123X",
            "AS12.3",
            "AS0",
            "AS4294967296",
            "AS-1",
        ],
    )
    def test_malformed_asn_rejected(self, bad: str) -> None:
        """Missing prefix, non-decimal suffix, zero, out-of-range, and
        negative-looking ASN values are malformed."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(asn=bad))


@pytest.mark.unit
@pytest.mark.provider_contract
class TestIpinfoLiteCodesAndDomain:
    """Country/continent code and operator domain tests."""

    def test_valid_codes_parse_verbatim(self) -> None:
        """Legal bounded uppercase codes parse verbatim."""
        parsed = IpinfoLiteResponse.model_validate(
            _lite_response(country_code="US", continent_code="NA")
        )
        assert parsed.country_code == "US"
        assert parsed.continent_code == "NA"

    @pytest.mark.parametrize("assigned", ["US", "NL", "GB"])
    def test_assigned_country_codes_accepted(self, assigned: str) -> None:
        """Officially assigned ISO 3166-1 alpha-2 codes are accepted."""
        parsed = IpinfoLiteResponse.model_validate(
            _lite_response(country_code=assigned)
        )
        assert parsed.country_code == assigned

    @pytest.mark.parametrize("unassigned", ["ZZ", "UK"])
    def test_unassigned_country_codes_rejected(self, unassigned: str) -> None:
        """Unassigned or exceptionally reserved codes are rejected (GB is the ISO code)."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(country_code=unassigned))

    @pytest.mark.parametrize("member", ["country_code", "continent_code"])
    @pytest.mark.parametrize("bad", ["us", "USA", "  ", "U", "U1"])
    def test_malformed_codes_rejected(self, member: str, bad: str) -> None:
        """Lowercase, overlong, and non-alphabetic codes are malformed."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(**{member: bad}))

    def test_valid_operator_domain(self) -> None:
        """A legal operator domain parses canonically."""
        parsed = IpinfoLiteResponse.model_validate(
            _lite_response(as_domain="GOOGLE.COM")
        )
        assert parsed.as_domain == "google.com"

    def test_valid_operator_domain_idna(self) -> None:
        """An IDNA operator domain parses into its canonical IDNA form."""
        parsed = IpinfoLiteResponse.model_validate(_lite_response(as_domain="例え.jp"))
        assert parsed.as_domain == "xn--r8jz45g.jp"

    @pytest.mark.parametrize(
        "bad", ["", "  ", "-bad-.example", "exa mple.com", "example.com.."]
    )
    def test_malformed_operator_domain_rejected(self, bad: str) -> None:
        """Malformed operator domains are rejected."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(as_domain=bad))

    def test_descriptive_members_preserve_text(self) -> None:
        """Descriptive members preserve provider presentation text."""
        parsed = IpinfoLiteResponse.model_validate(
            _lite_response(as_name="  Google LLC", country="  United States")
        )
        assert parsed.as_name == "  Google LLC"
        assert parsed.country == "  United States"

    def test_nested_object_rejected_for_string_member(self) -> None:
        """Nested objects are rejected for documented string members."""
        with pytest.raises(ValidationError):
            IpinfoLiteResponse.model_validate(_lite_response(country={"code": "US"}))

    def test_response_model_is_frozen(self) -> None:
        """The strict response model is immutable."""
        parsed = IpinfoLiteResponse.model_validate(_lite_response())
        with pytest.raises(ValidationError):
            parsed.ip = "1.1.1.1"


# -- Provider contract -----------------------------------------------------


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestIpinfoLiteProviderContract:
    """Deterministic provider contract tests for IpinfoLiteProvider."""

    async def test_supports_matrix(self) -> None:
        """Only IP-address entities are supported."""
        provider = _provider(_client_failing_io())
        assert provider.supports(Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8"))
        for unsupported in (
            EntityType.DOMAIN,
            EntityType.URL,
            EntityType.NETWORK_PREFIX,
            EntityType.ASN,
            EntityType.ORGANIZATION,
            EntityType.MALWARE,
            EntityType.ATTACK_TECHNIQUE,
            EntityType.VULNERABILITY,
        ):
            assert not provider.supports(Entity(type=unsupported, value="test"))

    async def test_unsupported_entity_produces_no_io(self) -> None:
        """An unsupported entity yields one UNSUPPORTED_INDICATOR with no HTTP I/O."""
        provider = _provider(_client_failing_io())
        for unsupported in (
            EntityType.DOMAIN,
            EntityType.URL,
            EntityType.NETWORK_PREFIX,
            EntityType.ASN,
            EntityType.ORGANIZATION,
            EntityType.MALWARE,
            EntityType.ATTACK_TECHNIQUE,
            EntityType.VULNERABILITY,
        ):
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=unsupported, value="test")
            )
            assert result.evidence == ()
            assert len(result.errors) == 1
            assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
            assert result.errors[0].retryable is False

    async def test_invalid_entity_value_produces_no_io(self) -> None:
        """An uncanonicalizable entity value yields one error with no HTTP I/O."""
        provider = _provider(_client_failing_io())
        result = await provider.investigate(
            _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="not-an-ip")
        )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert result.errors[0].retryable is False

    async def test_positive_lookup_and_provenance(self) -> None:
        """A successful lookup emits exactly one canonical evidence observation."""
        captured: dict[str, str] = {}

        def _handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["method"] = request.method
            captured["authorization"] = request.headers.get("Authorization")
            captured["accept"] = request.headers.get("Accept")
            return httpx.Response(200, json=_lite_response())

        async with _client_handler(_handler) as client:
            provider = _provider(client, clock=lambda: _FIXED_TS)
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )

        assert captured["method"] == "GET"
        assert captured["url"] == f"{_IPINFO_LITE_ENDPOINT}/8.8.8.8"
        assert captured["authorization"] == f"Bearer {_FIXED_TOKEN}"
        assert captured["accept"] == "application/json"
        _assert_no_token_leak(captured["url"])

        assert result.errors == ()
        assert result.provider == "urn:ati:source:ipinfo_lite"
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.type == EvidenceType.NETWORK
        assert evidence.investigation_id == _FIXED_UUID
        assert evidence.source == provider.id
        assert evidence.source_record_id is None
        assert evidence.subject.value == "8.8.8.8"
        assert evidence.subject.type == EntityType.IP_ADDRESS
        assert evidence.retrieved_at == _FIXED_TS
        assert evidence.observed_at is None
        assert evidence.raw_payload is None
        assert evidence.facts["ip"] == "8.8.8.8"
        assert evidence.facts["asn"] == "AS15169"
        assert evidence.facts["as_name"] == "Google LLC"
        assert evidence.facts["as_domain"] == "google.com"
        assert evidence.facts["country_code"] == "US"
        assert evidence.facts["country"] == "United States"
        assert evidence.facts["continent_code"] == "NA"
        assert evidence.facts["continent"] == "North America"
        _assert_no_token_leak(str(evidence.source_url))

    async def test_canonical_ipv6_lookup(self) -> None:
        """An IPv6 lookup percent-encodes the request and canonicalizes evidence."""

        def _handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/2001:db8::1")
            assert str(request.url).endswith("/2001%3Adb8%3A%3A1")
            return httpx.Response(
                200,
                json=_lite_response(ip="2001:db8::1", asn="AS123"),
            )

        async with _client_handler(_handler) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value="2001:0DB8:0000::1"),
            )
        assert result.errors == ()
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.subject.value == "2001:db8::1"
        assert evidence.facts["ip"] == "2001:db8::1"
        assert evidence.facts["asn"] == "AS123"
        _assert_no_token_leak(str(evidence.source_url))

    async def test_textual_variant_identity_accepted(self) -> None:
        """A canonical response IP matching the canonical query is valid."""

        async with _client_static(httpx.Response(200, json=_lite_response())) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value="  8.8.8.8  "),
            )
        assert result.errors == ()
        assert result.evidence[0].facts["ip"] == "8.8.8.8"

    async def test_expanded_ipv6_response_identity_accepted(self) -> None:
        """An equivalent fully expanded IPv6 response satisfies the identity check."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_lite_response(
                    ip="2001:0db8:0000:0000:0000:0000:0000:0001",
                    asn="AS123",
                ),
            )

        async with _client_handler(_handler) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID,
                Entity(type=EntityType.IP_ADDRESS, value="2001:db8::1"),
            )
        assert result.errors == ()
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.subject.value == "2001:db8::1"
        assert evidence.facts["ip"] == "2001:db8::1"
        assert evidence.facts["asn"] == "AS123"

    async def test_wrong_identity_rejected(self) -> None:
        """A response about a different IP is rejected as INVALID_RESPONSE."""
        async with _client_static(
            httpx.Response(200, json=_lite_response(ip="8.8.4.4"))
        ) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    async def test_unassigned_country_code_invalid_response(self) -> None:
        """An unassigned country code yields exactly one INVALID_RESPONSE, no evidence."""
        async with _client_static(
            httpx.Response(200, json=_lite_response(country_code="ZZ"))
        ) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert len(result.errors) == 1
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    async def test_malformed_returned_ip_invalid_response(self) -> None:
        """A nonblank malformed returned IP yields INVALID_RESPONSE, no evidence."""
        async with _client_static(
            httpx.Response(200, json=_lite_response(ip="999.999.999.999"))
        ) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert len(result.errors) == 1
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    @pytest.mark.parametrize(
        "omitted",
        [
            "asn",
            "as_name",
            "as_domain",
            "country_code",
            "country",
            "continent_code",
            "continent",
        ],
    )
    async def test_missing_optional_field_omitted_from_facts(
        self, omitted: str
    ) -> None:
        """Each omitted optional field succeeds and only that fact key is absent."""
        response = _lite_response(**{omitted: _REMOVED})
        async with _client_static(httpx.Response(200, json=response)) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.errors == ()
        assert len(result.evidence) == 1
        facts = result.evidence[0].facts
        assert omitted not in facts
        expected_keys = set(_lite_response()) - {omitted}
        assert set(facts) == expected_keys

    async def test_address_family_mismatch_rejected(self) -> None:
        """A response about a different address family is rejected."""
        async with _client_static(
            httpx.Response(200, json=_lite_response(ip="2001:db8::1", asn=_REMOVED))
        ) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    @pytest.mark.parametrize(
        "malformed",
        [
            _lite_response(ip=True),
            _lite_response(asn=1),
            _lite_response(ip=""),
            _lite_response(ip=None),
            _lite_response(ip=_REMOVED),
            _lite_response(asn="15169"),
            _lite_response(country_code="us"),
            _lite_response(country_code=None),
            {},
        ],
    )
    async def test_malformed_schema_rejected(self, malformed: Any) -> None:
        """A schema-malformed response yields exactly one typed error."""
        async with _client_static(httpx.Response(200, json=malformed)) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert len(result.errors) == 1
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    @pytest.mark.parametrize("payload", [[], "text", 1, True, None])
    async def test_non_object_response_rejected(self, payload: Any) -> None:
        """A non-object JSON response is rejected."""
        async with _client_static(httpx.Response(200, json=payload)) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_wrong_content_type_rejected(self) -> None:
        """A successful non-JSON media type is rejected by the shared client."""
        async with _client_static(
            httpx.Response(
                200,
                headers={"Content-Type": "application/problem+json"},
                json=_lite_response(),
            )
        ) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE

    async def test_malformed_json_rejected(self) -> None:
        """A malformed JSON body is rejected by the shared client."""
        async with _client_static(
            httpx.Response(
                200, content=b"{not json", headers={"Content-Type": "application/json"}
            )
        ) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestIpinfoLiteProviderFailures:
    """Shared HTTP failure, cancellation, and lifecycle contract tests."""

    @pytest.mark.parametrize(
        ("status", "headers", "expected_code", "retryable"),
        [
            (401, {}, ProviderErrorCode.AUTHENTICATION_FAILED, False),
            (403, {}, ProviderErrorCode.FORBIDDEN, False),
            (404, {}, ProviderErrorCode.NOT_FOUND, False),
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
        async with _client_static(
            httpx.Response(status, headers=headers, json={})
        ) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert len(result.errors) == 1
        assert result.errors[0].code == expected_code
        assert result.errors[0].retryable is retryable

    async def test_rate_limited_carries_retry_after(self) -> None:
        """A 429 with Retry-After carries the parsed seconds without sleeping."""
        async with _client_static(
            httpx.Response(429, headers={"Retry-After": "30"}, json={})
        ) as client:
            result = await _provider(
                client, http_kwargs={"policy": ProviderHttpPolicy(max_retries=0)}
            ).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.errors[0].retry_after_seconds == 30

    async def test_timeout_typed_error(self) -> None:
        """A transport timeout yields a typed timeout error without real sleeping."""

        def _handler(_: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("connection timed out")

        async with _client_handler(_handler) as client:
            result = await _provider(
                client, http_kwargs={"policy": ProviderHttpPolicy(max_retries=0)}
            ).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert result.errors[0].code == ProviderErrorCode.TIMEOUT
        assert result.errors[0].retryable is True

    async def test_oversized_response_rejected(self) -> None:
        """A response exceeding the shared size bound is a non-retryable typed error."""
        oversized = _lite_response(continent="x" * 4096)
        policy = ProviderHttpPolicy(max_response_bytes=64, max_retries=0)
        async with _client_static(httpx.Response(200, json=oversized)) as client:
            result = await _provider(
                client, http_kwargs={"policy": policy}
            ).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        assert result.evidence == ()
        assert len(result.errors) == 1
        assert result.errors[0].code == ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False
        # The response body and the credential never reach the error message.
        assert "xxxx" not in result.errors[0].message
        _assert_no_token_leak(result.errors[0].message)

    async def test_error_messages_carry_no_token(self) -> None:
        """Typed error messages never contain the access token."""
        async with _client_static(httpx.Response(401, json={})) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        _assert_no_token_leak(result.errors[0].message)

    async def test_cancellation_propagates(self) -> None:
        """Task cancellation propagates without swallowing or yielding evidence."""

        def _handler(_: httpx.Request) -> httpx.Response:
            raise asyncio.CancelledError()

        async with _client_handler(_handler) as client:
            with pytest.raises(asyncio.CancelledError):
                await _provider(client).investigate(
                    _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
                )

    async def test_facts_deep_immutable(self) -> None:
        """Evidence facts are deeply immutable after normalization."""
        async with _client_static(httpx.Response(200, json=_lite_response())) as client:
            result = await _provider(client).investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
            )
        evidence = result.evidence[0]
        with pytest.raises(TypeError):
            evidence.facts["ip"] = "changed"
        with pytest.raises(TypeError):
            evidence.facts.clear()

    async def test_naive_clock_rejected(self) -> None:
        """An injected naive clock is rejected as a configuration error."""
        async with _client_static(httpx.Response(200, json=_lite_response())) as client:
            provider = _provider(
                client, clock=lambda: datetime(2026, 1, 15, 12, 0, 0)  # Naive
            )
            with pytest.raises(ValueError, match="timezone-aware"):
                await provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="8.8.8.8")
                )

    async def test_blank_token_rejected_at_construction(self) -> None:
        """A blank access token is rejected before any I/O can occur."""
        async with _client_failing_io() as client:
            for blank in ("", "   "):
                with pytest.raises(ValueError, match="token must not be blank"):
                    IpinfoLiteProvider(ProviderHttpClient(client=client), token=blank)
