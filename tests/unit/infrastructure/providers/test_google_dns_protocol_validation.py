# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Provider contract tests for DNS protocol semantics and RR-set consistency.

Covers answer ownership/CNAME-chain attribution, protocol-root names,
RFC 1035 presentation escapes, null-MX normalization, and RR-set consistency
for ``GooglePublicDnsProvider`` per the authoritative DNS validation matrix.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode, ProviderResult
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)

_RR_NUMBER: dict[str, int] = {
    "A": 1,
    "CNAME": 5,
    "MX": 15,
    "NS": 2,
    "SOA": 6,
    "PTR": 12,
}


def _record(name: str, rr_type: str | int, data: str, ttl: int = 300) -> dict[str, Any]:
    """Build one answer record; ``rr_type`` accepts a name or numeric type."""
    number = _RR_NUMBER[rr_type] if isinstance(rr_type, str) else rr_type
    return {"name": name, "type": number, "TTL": ttl, "data": data}


def _handler_for(
    rr_type: str, answers: list[dict[str, Any]] | None
) -> Callable[[httpx.Request], httpx.Response]:
    """Serve ``answers`` for one RR type and empty NOERROR for all others."""

    def _handler(request: httpx.Request) -> httpx.Response:
        requested = request.url.params.get("type")
        payload: dict[str, Any] = (
            {"Status": 0, "Answer": answers} if requested == rr_type else {"Status": 0}
        )
        return httpx.Response(
            200, headers={"Content-Type": "application/json"}, json=payload
        )

    return _handler


def _guard_handler(_: httpx.Request) -> httpx.Response:
    """Fail the test if any HTTP request is issued."""
    pytest.fail("HTTP request issued where none was expected")


async def _investigate(
    handler: Callable[[httpx.Request], httpx.Response],
    entity: Entity,
) -> ProviderResult:
    """Run one investigation against a mock transport handler."""
    transport = MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = GooglePublicDnsProvider(
            ProviderHttpClient(client=client), clock=lambda: _FIXED_TS
        )
        return await provider.investigate(_FIXED_UUID, entity)


async def _investigate_domain(
    rr_type: str, answers: list[dict[str, Any]] | None, value: str = "example.com"
) -> ProviderResult:
    """Investigate a domain with stubbed answers for one RR type."""
    entity = Entity(type=EntityType.DOMAIN, value=value)
    return await _investigate(_handler_for(rr_type, answers), entity)


async def _assert_invalid(result: ProviderResult, *secrets: str) -> None:
    """Assert one non-retryable INVALID_RESPONSE with no evidence and no leak."""
    [error] = result.errors
    assert error.code == ProviderErrorCode.INVALID_RESPONSE
    assert error.retryable is False
    assert not result.evidence
    for secret in secrets:
        assert secret not in error.message


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestAnswerOwnershipAndChains:
    """Answers must be attributable to the queried name or a valid chain."""

    async def test_direct_answer_at_query_owner_accepted(self) -> None:
        """A direct A answer owned by the queried name is valid evidence."""
        result = await _investigate_domain(
            "A", [_record("example.com.", "A", "192.0.2.1")]
        )
        assert len(result.evidence) == 1
        assert result.errors == ()
        answer = result.evidence[0].facts["answers"][0]
        assert answer["record_type"] == "A"
        assert answer["name"] == "example.com"
        assert answer["value"] == "192.0.2.1"

    async def test_unrelated_owner_rejected(self) -> None:
        """An otherwise valid A answer with an unrelated owner is rejected."""
        result = await _investigate_domain(
            "A", [_record("unrelated.example.", "A", "192.0.2.1")]
        )
        await _assert_invalid(result, "unrelated.example", "192.0.2.1")

    async def test_rooted_chain_with_terminal_answer_accepted(self) -> None:
        """A contiguous query-rooted CNAME chain plus terminal A is accepted."""
        result = await _investigate_domain(
            "A",
            [
                _record("example.com.", "CNAME", "alias.example.com."),
                _record("alias.example.com.", "A", "192.0.2.7"),
            ],
        )
        assert len(result.evidence) == 1
        answers = result.evidence[0].facts["answers"]
        assert [answer["record_type"] for answer in answers] == ["CNAME", "A"]

    async def test_cname_only_chain_rooted_at_query_accepted(self) -> None:
        """A single query-rooted CNAME answer remains a valid observation."""
        result = await _investigate_domain(
            "A", [_record("example.com.", "CNAME", "alias.example.com.")]
        )
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["answers"][0]["record_type"] == "CNAME"

    async def test_lone_cname_with_unrelated_owner_rejected(self) -> None:
        """A CNAME owned by an unrelated name cannot become A-query evidence."""
        result = await _investigate_domain(
            "A", [_record("alias.example.com.", "CNAME", "target.example.com.")]
        )
        await _assert_invalid(result, "alias.example.com")

    async def test_broken_chain_rejected(self) -> None:
        """A terminal answer at a non-chain owner is rejected."""
        result = await _investigate_domain(
            "A",
            [
                _record("example.com.", "CNAME", "alias.example.com."),
                _record("other.example.com.", "A", "192.0.2.7"),
            ],
        )
        await _assert_invalid(result, "other.example.com")

    async def test_chain_loop_rejected(self) -> None:
        """A CNAME chain pointing back to the queried name is rejected."""
        result = await _investigate_domain(
            "A",
            [
                _record("example.com.", "CNAME", "alias.example.com."),
                _record("alias.example.com.", "CNAME", "example.com."),
            ],
        )
        await _assert_invalid(result)

    async def test_conflicting_cname_targets_rejected(self) -> None:
        """Two CNAME records at the queried owner are rejected."""
        result = await _investigate_domain(
            "A",
            [
                _record("example.com.", "CNAME", "alias1.example.com."),
                _record("example.com.", "CNAME", "alias2.example.com."),
            ],
        )
        await _assert_invalid(result)

    async def test_cname_after_terminal_answer_rejected(self) -> None:
        """A CNAME following a terminal requested-type answer is rejected."""
        result = await _investigate_domain(
            "A",
            [
                _record("example.com.", "A", "192.0.2.1"),
                _record("example.com.", "CNAME", "alias.example.com."),
            ],
        )
        await _assert_invalid(result)

    async def test_unrelated_known_type_rejected(self) -> None:
        """An NS answer to an A query is a type contradiction."""
        result = await _investigate_domain(
            "A", [_record("example.com.", "NS", "ns1.example.com.")]
        )
        await _assert_invalid(result)

    async def test_unknown_rr_type_rejected(self) -> None:
        """An answer with an unknown numeric RR type is rejected."""
        result = await _investigate_domain("A", [_record("example.com.", 999, "?")])
        await _assert_invalid(result)

    async def test_soa_via_rooted_chain_accepted(self) -> None:
        """A CNAME chain is honored for SOA queries like every other type."""
        soa_data = "ns1.example. admin.example. 1 2 3 4 5"
        result = await _investigate_domain(
            "SOA",
            [
                _record("example.com.", "CNAME", "alias.example.com."),
                _record("alias.example.com.", "SOA", soa_data),
            ],
        )
        assert len(result.evidence) == 1
        answers = result.evidence[0].facts["answers"]
        assert answers[0]["record_type"] == "CNAME"
        assert answers[1]["record_type"] == "SOA"
        assert answers[1]["mname"] == "ns1.example"

    async def test_invalid_chain_emits_no_partial_evidence(self) -> None:
        """One invalid entry invalidates the whole query observation."""
        result = await _investigate_domain(
            "A",
            [
                _record("example.com.", "A", "192.0.2.1"),
                _record("unrelated.example.", "A", "192.0.2.2"),
            ],
        )
        await _assert_invalid(result, "unrelated.example")


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestProtocolNamesAndEscapes:
    """Domain-valued RDATA follows protocol-name normalization rules."""

    async def test_root_target_retained_as_sentinel_fact(self) -> None:
        """A root CNAME target normalizes to ``.`` as a non-entity fact."""
        result = await _investigate_domain(
            "CNAME", [_record("example.com.", "CNAME", ".")]
        )
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["answers"][0]["value"] == "."

    async def test_root_ns_target_retained_as_sentinel_fact(self) -> None:
        """A root NS target normalizes to ``.`` as a non-entity fact."""
        result = await _investigate_domain("NS", [_record("example.com.", "NS", ".")])
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["answers"][0]["value"] == "."

    async def test_root_ptr_target_retained_as_sentinel_fact(self) -> None:
        """A root PTR target normalizes to ``.`` as a non-entity fact."""
        entity = Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
        result = await _investigate(
            _handler_for("PTR", [_record("1.2.0.192.in-addr.arpa.", "PTR", ".")]),
            entity,
        )
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["answers"][0]["value"] == "."

    async def test_root_is_invalid_as_investigated_domain_without_io(self) -> None:
        """The DNS root is not an ATI domain entity and never reaches HTTP."""
        result = await _investigate(
            _guard_handler, Entity(type=EntityType.DOMAIN, value=".")
        )
        assert len(result.evidence) == 0
        [error] = result.errors
        assert error.code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert error.retryable is False

    async def test_idna_and_case_normalization_unchanged(self) -> None:
        """Ordinary IDNA and case normalization behavior is preserved."""
        result = await _investigate_domain(
            "CNAME", [_record("example.com.", "CNAME", "Bücher.Example.")]
        )
        assert result.evidence[0].facts["answers"][0]["value"] == (
            "xn--bcher-kva.example"
        )

    async def test_quoted_character_escape_normalizes(self) -> None:
        """A quoted-character escape decodes before label validation."""
        result = await _investigate_domain(
            "NS", [_record("example.com.", "NS", r"a\-b.example.")]
        )
        assert result.evidence[0].facts["answers"][0]["value"] == "a-b.example"

    async def test_decimal_escape_normalizes(self) -> None:
        """A three-digit decimal escape decodes one printable ASCII octet."""
        result = await _investigate_domain(
            "CNAME", [_record("example.com.", "CNAME", r"ns\049.example.")]
        )
        assert result.evidence[0].facts["answers"][0]["value"] == "ns1.example"

    @pytest.mark.parametrize(
        "data",
        [
            r"a\.b.example.",  # escaped dot is not representable canonically
            "ns1.example.\\",  # trailing backslash
            r"ns\04.example.",  # incomplete decimal escape
            r"ns\300.example.",  # out-of-range octet
            r"ns\001.example.",  # control octet
            r"ns\255.example.",  # unsupported arbitrary octet
            "ns\\٠٩٧.example.",  # Arabic-Indic digits are not RFC ASCII DDD
            "ns\\０９７.example.",  # full-width digits are not RFC ASCII DDD
            "ns\\0٩7.example.",  # mixed ASCII/Unicode decimal spelling
        ],
    )
    async def test_malformed_escapes_rejected(self, data: str) -> None:
        """Malformed or unsupported presentation escapes are INVALID_RESPONSE."""
        result = await _investigate_domain(
            "CNAME", [_record("example.com.", "CNAME", data)]
        )
        await _assert_invalid(result)

    async def test_soa_with_escaped_names_normalized(self) -> None:
        """SOA names are escape-decoded before strict validation."""
        result = await _investigate_domain(
            "SOA",
            [
                _record(
                    "example.com.",
                    "SOA",
                    r"ns\049.example. admin.example. 1 2 3 4 5",
                )
            ],
        )
        answers = result.evidence[0].facts["answers"]
        assert answers[0]["mname"] == "ns1.example"
        assert answers[0]["rname"] == "admin.example"

    async def test_soa_tab_separated_fields_accepted(self) -> None:
        """Any ASCII whitespace separates SOA fields, not only spaces."""
        result = await _investigate_domain(
            "SOA",
            [
                _record(
                    "example.com.",
                    "SOA",
                    "ns1.example.\tadmin.example.\t1 2 3 4 5",
                )
            ],
        )
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["answers"][0]["serial"] == 1

    async def test_soa_escaped_whitespace_rejected(self) -> None:
        """Escaped whitespace inside an SOA name cannot become a valid label."""
        result = await _investigate_domain(
            "SOA",
            [
                _record(
                    "example.com.",
                    "SOA",
                    r"ns1\ example. admin.example. 1 2 3 4 5",
                )
            ],
        )
        await _assert_invalid(result)

    async def test_soa_without_field_separator_rejected(self) -> None:
        """Missing whitespace between SOA name fields changes tokenization."""
        result = await _investigate_domain(
            "SOA",
            [
                _record(
                    "example.com.",
                    "SOA",
                    "ns1.example.admin.example. 1 2 3 4 5",
                )
            ],
        )
        await _assert_invalid(result)


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestNullMxAndSetConsistency:
    """Null MX is normalized and validated at record and RR-set levels."""

    async def test_valid_null_mx_accepted(self) -> None:
        """A single ``0 .`` answer is valid null-MX evidence."""
        result = await _investigate_domain("MX", [_record("example.com.", "MX", "0 .")])
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert not result.errors
        answer = evidence.facts["answers"][0]
        assert answer["record_type"] == "MX"
        assert answer["preference"] == 0
        assert answer["exchange"] == "."
        assert evidence.facts["query_type"] == "MX"
        assert evidence.investigation_id == _FIXED_UUID
        assert evidence.retrieved_at == _FIXED_TS
        assert evidence.raw_payload is None

    async def test_nonzero_root_preference_rejected(self) -> None:
        """A root exchange with a nonzero preference is malformed."""
        result = await _investigate_domain(
            "MX", [_record("example.com.", "MX", "10 .")]
        )
        await _assert_invalid(result)

    async def test_duplicate_null_mx_rejected(self) -> None:
        """Two null-MX answers cannot form one valid RR set."""
        result = await _investigate_domain(
            "MX",
            [
                _record("example.com.", "MX", "0 ."),
                _record("example.com.", "MX", "0 ."),
            ],
        )
        await _assert_invalid(result)

    async def test_null_mx_mixed_with_ordinary_mx_rejected(self) -> None:
        """A null MX mixed with an ordinary MX is an inconsistent RR set."""
        result = await _investigate_domain(
            "MX",
            [
                _record("example.com.", "MX", "0 ."),
                _record("example.com.", "MX", "10 mail.example."),
            ],
        )
        await _assert_invalid(result, "mail.example")

    async def test_preference_zero_ordinary_mx_accepted(self) -> None:
        """Preference zero with a real exchanger is an ordinary MX record."""
        result = await _investigate_domain(
            "MX", [_record("example.com.", "MX", "0 mail.example.")]
        )
        assert len(result.evidence) == 1
        answer = result.evidence[0].facts["answers"][0]
        assert answer["preference"] == 0
        assert answer["exchange"] == "mail.example"

    async def test_null_mx_via_rooted_chain_accepted(self) -> None:
        """A query-rooted CNAME chain plus one null MX is valid and counted once."""
        result = await _investigate_domain(
            "MX",
            [
                _record("example.com.", "CNAME", "alias.example.com."),
                _record("alias.example.com.", "MX", "0 ."),
            ],
        )
        assert len(result.evidence) == 1
        answers = result.evidence[0].facts["answers"]
        assert [answer["record_type"] for answer in answers] == ["CNAME", "MX"]
        assert answers[1]["exchange"] == "."

    async def test_null_mx_sentinel_is_not_a_domain_value(self) -> None:
        """The root exchange is retained only as a provider fact."""
        result = await _investigate_domain("MX", [_record("example.com.", "MX", "0 .")])
        answer = result.evidence[0].facts["answers"][0]
        assert answer["exchange"] == "."
        # The provider emits facts only; the sentinel must never look like a
        # discoverable domain entity value in the evidence shape.
        assert set(answer) == {
            "name",
            "record_type",
            "ttl",
            "preference",
            "exchange",
        }
