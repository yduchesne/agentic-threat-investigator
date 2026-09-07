# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Google Public DNS provider for A, AAAA, CNAME, MX, NS, TXT, SOA, and PTR queries.

Uses the JSON API at ``https://dns.google/resolve``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderError,
    ProviderErrorCode,
    ProviderResult,
    normalize_retrieval_timestamp,
    unsupported_indicator_result,
    validate_investigation_entity,
)
from agentic_threat_investigator.domain.entities import (
    Entity,
    EntityType,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient

_GOOGLE_DNS_ENDPOINT = "https://dns.google/resolve"
_DOMAIN_RR_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

_ASCII_WHITESPACE = frozenset(" \t\n\r\f\v")
_PRINTABLE_ASCII_MIN = 0x21
_PRINTABLE_ASCII_MAX = 0x7E

_NUMERIC_TO_RR_TYPE: dict[int, str] = {
    1: "A",
    28: "AAAA",
    5: "CNAME",
    15: "MX",
    2: "NS",
    16: "TXT",
    6: "SOA",
    12: "PTR",
}

_MAX_UINT32 = 4294967295


# -- Strict Pydantic models for the Google DNS JSON API response ----------


class GoogleDnsAnswer(BaseModel):
    """A single strictly validated DNS answer record from the Google JSON API."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    name: str = Field(min_length=1)
    type: int = Field(gt=0)
    TTL: int = Field(ge=0)
    data: str = Field(min_length=1)


class GoogleDnsQuestion(BaseModel):
    """A single strictly validated DNS question entry."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    name: str = Field(min_length=1)
    type: int = Field(gt=0)


class GoogleDnsResponse(BaseModel):
    """Top-level strictly validated response from ``dns.google/resolve``."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    Status: int = Field(ge=0)
    TC: bool | None = None
    RD: bool | None = None
    RA: bool | None = None
    AD: bool | None = None
    CD: bool | None = None
    Question: list[GoogleDnsQuestion] = Field(default_factory=list)
    Answer: list[GoogleDnsAnswer] = Field(default_factory=list)


# -- Query context and outcome --------------------------------------------


@dataclass(frozen=True)
class DnsQueryContext:
    """Invocation context for DNS queries."""

    investigation_id: UUID
    subject: EvidenceEntityRef
    retrieved_at: datetime


@dataclass(frozen=True)
class DnsQueryOutcome:
    """Internal result of querying one DNS RR type."""

    evidence: Evidence | None = None
    errors: tuple[ProviderError, ...] = ()
    is_nxdomain: bool = False


# -- DNS presentation parsing ---------------------------------------------


def _tokenize_rdata(data: str) -> list[str] | None:
    """Split RDATA presentation text on unescaped ASCII whitespace.

    Escape sequences are preserved inside tokens for later decoding. Returns
    ``None`` when the text ends with an incomplete escape, so field boundaries
    can never be moved by escaped or malformed whitespace.
    """
    tokens: list[str] = []
    current: list[str] = []
    escaped = False
    for char in data:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char in _ASCII_WHITESPACE:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if escaped:
        return None
    if current:
        tokens.append("".join(current))
    return tokens


def _decode_presentation_label(label: str) -> str | None:
    """Decode RFC 1035 presentation escapes within one name label.

    A backslash followed by exactly three decimal digits decodes one octet;
    a backslash followed by any other character quotes that character.
    Returns ``None`` for trailing or incomplete escapes, out-of-range octets,
    octets outside the printable ASCII range (control characters, whitespace,
    and unsupported arbitrary bytes), and escaped literal dots, which cannot
    be represented unambiguously in canonical dotted form.
    """
    decoded: list[str] = []
    index = 0
    length = len(label)
    while index < length:
        char = label[index]
        if char != "\\":
            decoded.append(char)
            index += 1
            continue
        if index + 1 >= length:
            return None
        following = label[index + 1]
        if following.isdigit() and not "0" <= following <= "9":
            return None
        if "0" <= following <= "9":
            digits = label[index + 1 : index + 4]
            if (
                index + 4 > length
                or len(digits) != 3
                or not digits.isascii()
                or not digits.isdecimal()
            ):
                return None
            octet = int(label[index + 1 : index + 4])
            if not _PRINTABLE_ASCII_MIN <= octet <= _PRINTABLE_ASCII_MAX:
                return None
            decoded.append(chr(octet))
            index += 4
            continue
        if following == ".":
            return None
        decoded.append(following)
        index += 2
    return "".join(decoded)


def _split_name_labels(candidate: str) -> list[str] | None:
    """Split a presentation name into raw labels on unescaped dots.

    Escapes are preserved inside labels for later decoding. Returns ``None``
    for empty labels (leading dot, double dot) and for a trailing backslash.
    """
    labels: list[str] = []
    current: list[str] = []
    escaped = False
    for char in candidate:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ".":
            if not current:
                return None
            labels.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        return None
    if current:
        labels.append("".join(current))
    return labels


def _normalize_protocol_name(raw: str) -> str | None:
    """Normalize a domain-valued DNS protocol name for provider facts.

    The exact root name normalizes to ``.``. Every other name is split on
    unescaped label separators, decoded from presentation escapes per label,
    and validated through the strict domain-name contract (IDNA, label
    characters, and length limits). Returns ``None`` for malformed,
    incomplete, or unrepresentable names.

    The result is a source fact only: a normalized root never becomes an ATI
    domain entity, relationship endpoint, or pivot target.
    """
    candidate = raw.strip()
    if not candidate:
        return None
    if candidate == ".":
        return "."
    labels = _split_name_labels(candidate)
    if labels is None:
        return None
    decoded_labels: list[str] = []
    for label in labels:
        decoded = _decode_presentation_label(label)
        if not decoded:
            return None
        decoded_labels.append(decoded)
    try:
        return validate_dns_name(".".join(decoded_labels))
    except ValueError:
        return None


# -- Answer normalizers ---------------------------------------------------


def _normalize_ip_answer(
    answer: GoogleDnsAnswer, expected_version: int, record_type: str
) -> dict[str, Any] | None:
    """Normalize an A or AAAA answer record."""
    owner = _normalize_protocol_name(answer.name)
    if owner is None:
        return None
    try:
        ip_obj = ipaddress.ip_address(answer.data.strip())
        if ip_obj.version != expected_version:
            return None
        return {
            "name": owner,
            "record_type": record_type,
            "ttl": answer.TTL,
            "value": str(ip_obj),
        }
    except ValueError:
        return None


def _normalize_name_answer(
    answer: GoogleDnsAnswer, record_type: str
) -> dict[str, Any] | None:
    """Normalize a CNAME, NS, or PTR answer record.

    The target normalizes through the protocol-name contract: the root name
    is retained as ``.`` and is not eligible to become an ATI domain entity.
    """
    owner = _normalize_protocol_name(answer.name)
    value = _normalize_protocol_name(answer.data)
    if owner is None or value is None:
        return None
    return {
        "name": owner,
        "record_type": record_type,
        "ttl": answer.TTL,
        "value": value,
    }


def _normalize_mx_answer(answer: GoogleDnsAnswer) -> dict[str, Any] | None:
    """Normalize an MX answer record.

    The exchange normalizes through the protocol-name contract. The exact
    pair of preference ``0`` and root exchange ``.`` is the null-MX sentinel;
    a root exchange with any nonzero preference is malformed.
    """
    tokens = _tokenize_rdata(answer.data)
    preference: int | None = None
    exchange: str | None = None
    if (
        tokens is not None
        and len(tokens) == 2
        and tokens[0].isdigit()
        and 0 <= int(tokens[0]) <= 65535
    ):
        candidate_exchange = _normalize_protocol_name(tokens[1])
        if candidate_exchange is not None and (
            candidate_exchange != "." or int(tokens[0]) == 0
        ):
            preference = int(tokens[0])
            exchange = candidate_exchange
    owner = _normalize_protocol_name(answer.name)
    if preference is None or exchange is None or owner is None:
        return None
    return {
        "name": owner,
        "record_type": "MX",
        "ttl": answer.TTL,
        "preference": preference,
        "exchange": exchange,
    }


def _normalize_soa_answer(answer: GoogleDnsAnswer) -> dict[str, Any] | None:
    """Normalize an SOA authority record.

    RDATA must tokenize into exactly seven fields: two protocol names and
    five unsigned 32-bit integers. Tokenization honors escape boundaries so
    escaped whitespace can never move a field boundary.
    """
    tokens = _tokenize_rdata(answer.data)
    if tokens is None or len(tokens) != 7:
        return None
    mname = _normalize_protocol_name(tokens[0])
    rname = _normalize_protocol_name(tokens[1])
    if mname is None or rname is None:
        return None
    number_tokens = tokens[2:]
    if not all(token.isdigit() for token in number_tokens):
        return None
    numbers = [int(token) for token in number_tokens]
    if any(not 0 <= number <= _MAX_UINT32 for number in numbers):
        return None
    owner = _normalize_protocol_name(answer.name)
    if owner is None:
        return None
    return {
        "name": owner,
        "record_type": "SOA",
        "ttl": answer.TTL,
        "mname": mname,
        "rname": rname,
        "serial": numbers[0],
        "refresh": numbers[1],
        "retry": numbers[2],
        "expire": numbers[3],
        "minimum": numbers[4],
    }


def _normalize_txt_answer(answer: GoogleDnsAnswer) -> dict[str, Any] | None:
    """Normalize a TXT answer record."""
    owner = _normalize_protocol_name(answer.name)
    if owner is None:
        return None
    return {
        "name": owner,
        "record_type": "TXT",
        "ttl": answer.TTL,
        "value": answer.data,
    }


_NORMALIZERS: dict[str, Callable[[GoogleDnsAnswer], dict[str, Any] | None]] = {
    "A": lambda a: _normalize_ip_answer(a, expected_version=4, record_type="A"),
    "AAAA": lambda a: _normalize_ip_answer(a, expected_version=6, record_type="AAAA"),
    "CNAME": lambda a: _normalize_name_answer(a, "CNAME"),
    "NS": lambda a: _normalize_name_answer(a, "NS"),
    "PTR": lambda a: _normalize_name_answer(a, "PTR"),
    "MX": _normalize_mx_answer,
    "SOA": _normalize_soa_answer,
    "TXT": _normalize_txt_answer,
}


def _normalize_single_answer(
    answer: GoogleDnsAnswer, requested_type: str
) -> dict[str, Any] | None:
    """Validate and normalize one answer record against the requested query."""
    actual_type = _NUMERIC_TO_RR_TYPE.get(answer.type)
    if actual_type is None:
        return None
    if actual_type == "CNAME" and requested_type != "CNAME":
        return _normalize_name_answer(answer, "CNAME")
    if actual_type != requested_type:
        return None
    normalizer = _NORMALIZERS.get(actual_type)
    return normalizer(answer) if normalizer is not None else None


def _validate_answer_set(
    normalized: list[dict[str, Any]],
    query_name: str,
    rr_type: str,
) -> bool:
    """Validate answer attribution, CNAME chains, and MX-set consistency.

    Every answer must belong to the queried canonical name, either directly
    or through a contiguous acyclic CNAME chain rooted at it. A CNAME chain
    may not follow a terminal answer or point back to an earlier owner, and
    terminal answers of the requested type must sit at the final chain
    target; several terminal answers may share that owner. For MX queries, a
    root exchange (null MX) must be the only MX record in the set, with
    preference zero. This is source attribution validation only: it infers
    no relationships, entities, or maliciousness.
    """
    expected_owner = query_name
    visited_owners = {query_name}
    saw_terminal = False
    for answer in normalized:
        record_type = answer["record_type"]
        if record_type == "CNAME":
            if saw_terminal or answer["name"] != expected_owner:
                return False
            target = answer["value"]
            if target in visited_owners:
                return False
            visited_owners.add(target)
            expected_owner = target
            continue
        if record_type != rr_type:
            return False
        if answer["name"] != expected_owner:
            return False
        saw_terminal = True
    if rr_type == "MX":
        mx_answers = [answer for answer in normalized if answer["record_type"] == "MX"]
        if any(answer["exchange"] == "." for answer in mx_answers):
            if len(mx_answers) != 1 or mx_answers[0]["preference"] != 0:
                return False
    return True


def _validate_question(
    parsed: GoogleDnsResponse,
    query_name: str,
    requested_type: str,
) -> None:
    """Validate optional question metadata against the requested DNS query."""
    if not parsed.Question:
        return
    expected_type = next(
        (
            number
            for number, name in _NUMERIC_TO_RR_TYPE.items()
            if name == requested_type
        ),
        None,
    )
    if expected_type is None:
        raise ValueError("unsupported DNS query type")
    for question in parsed.Question:
        if validate_dns_name(question.name) != validate_dns_name(query_name):
            raise ValueError("DNS question name does not match query")
        if question.type != expected_type:
            raise ValueError("DNS question type does not match query")


def _evaluate_dns_status(
    parsed: GoogleDnsResponse,
    provider_id: str,
) -> DnsQueryOutcome | None:
    """Check DNS status codes and empty answer sections."""
    if parsed.Status == 3:
        if parsed.Answer:
            # NXDOMAIN asserts the name does not exist; carrying an Answer
            # section is contradictory upstream data. The message stays
            # generic and never includes answer content.
            return DnsQueryOutcome(
                errors=(
                    ProviderError(
                        provider=provider_id,
                        code=ProviderErrorCode.INVALID_RESPONSE,
                        message="contradictory DNS response: NXDOMAIN with answers",
                        retryable=False,
                    ),
                )
            )
        return DnsQueryOutcome(is_nxdomain=True)

    if parsed.Status == 2:
        return DnsQueryOutcome(
            errors=(
                ProviderError(
                    provider=provider_id,
                    code=ProviderErrorCode.PROVIDER_UNAVAILABLE,
                    message="DNS server failure (SERVFAIL)",
                    retryable=True,
                ),
            )
        )

    if parsed.Status != 0:
        return DnsQueryOutcome(
            errors=(
                ProviderError(
                    provider=provider_id,
                    code=ProviderErrorCode.INVALID_RESPONSE,
                    message=f"unexpected DNS status {parsed.Status}",
                    retryable=False,
                ),
            )
        )

    if not parsed.Answer:
        return DnsQueryOutcome()

    return None


# -- Provider implementation ----------------------------------------------


class GooglePublicDnsProvider(EvidenceProvider):
    """Provider using Google Public DNS JSON API for resolution."""

    def __init__(
        self,
        http_client: ProviderHttpClient,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the provider with an injected HTTP client and UTC clock.

        The HTTP client is owned by the caller. The UTC wall clock is used
        only for Evidence ``retrieved_at`` timestamps; tests may inject a
        deterministic replacement, otherwise ``datetime.now(UTC)`` is used.
        """
        self._http = http_client
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def id(self) -> str:
        """Return the stable ``urn:ati:source:google_public_dns`` identifier."""
        return SourceId.GOOGLE_PUBLIC_DNS.value

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to domain and IP address entities.

        Domains are investigated via A/AAAA/CNAME/MX/NS/TXT/SOA queries;
        IP addresses only via their reverse-pointer PTR lookup.
        """
        return entity.type in (EntityType.DOMAIN, EntityType.IP_ADDRESS)

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Resolve DNS records for a supported entity via the Google JSON API.

        Domains are queried once per RR type in the fixed A, AAAA, CNAME,
        MX, NS, TXT, SOA order; IP addresses yield a single reverse PTR
        query. Answers are strictly validated and normalized into immutable
        DNS Evidence; NXDOMAIN is a valid miss and no persistence occurs.
        """
        canonical_value, error_result = validate_investigation_entity(self, entity)
        if error_result is not None:
            return error_result
        assert canonical_value is not None

        # Domain values are strictly validated against the original value by
        # the shared validation helper before any lossy canonicalization, so
        # no provider-local revalidation is required here.

        retrieved_at = normalize_retrieval_timestamp(self._clock)
        if entity.type == EntityType.DOMAIN:
            return await self._query_domain(
                investigation_id, entity, canonical_value, retrieved_at
            )
        return await self._query_ptr(
            investigation_id, entity, canonical_value, retrieved_at
        )

    async def _query_domain(
        self,
        investigation_id: UUID,
        entity: Entity,
        canonical_domain: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        provider = self.id
        subject = EvidenceEntityRef(
            id=entity.id, type=EntityType.DOMAIN, value=canonical_domain
        )
        context = DnsQueryContext(
            investigation_id=investigation_id,
            subject=subject,
            retrieved_at=retrieved_at,
        )
        evidence_list: list[Evidence] = []
        errors_list: list[ProviderError] = []

        first_outcome = await self._query_rr_type(
            context, canonical_domain, _DOMAIN_RR_TYPES[0]
        )
        if first_outcome.is_nxdomain:
            return ProviderResult(provider=provider)

        if first_outcome.evidence is not None:
            evidence_list.append(first_outcome.evidence)
        errors_list.extend(first_outcome.errors)

        for rr_type in _DOMAIN_RR_TYPES[1:]:
            outcome = await self._query_rr_type(context, canonical_domain, rr_type)
            if outcome.evidence is not None:
                evidence_list.append(outcome.evidence)
            errors_list.extend(outcome.errors)

        return ProviderResult(
            provider=provider,
            evidence=tuple(evidence_list),
            errors=tuple(errors_list),
        )

    async def _query_rr_type(
        self,
        context: DnsQueryContext,
        query_name: str,
        rr_type: str,
    ) -> DnsQueryOutcome:
        """Query a single RR type and return a structured DnsQueryOutcome."""
        provider = self.id
        params = {"name": query_name, "type": rr_type}
        outcome = await self._http.request_json(
            "GET",
            _GOOGLE_DNS_ENDPOINT,
            params=params,
            headers={"Accept": "application/json, application/dns-json"},
            accepted_media_types=("application/json", "application/dns-json"),
        )

        if outcome.final_error_code is not None:
            return DnsQueryOutcome(
                errors=(
                    ProviderError(
                        provider=provider,
                        code=outcome.final_error_code,
                        message=outcome.final_error_message or "HTTP request failed",
                        retryable=outcome.final_error_code.retryable,
                        retry_after_seconds=outcome.retry_after_seconds,
                    ),
                )
            )

        if not isinstance(outcome.response_json, dict):
            return DnsQueryOutcome(
                errors=(
                    ProviderError(
                        provider=provider,
                        code=ProviderErrorCode.INVALID_RESPONSE,
                        message="invalid DNS response schema",
                        retryable=False,
                    ),
                )
            )

        try:
            parsed = GoogleDnsResponse.model_validate(outcome.response_json)
        except ValueError:
            return DnsQueryOutcome(
                errors=(
                    ProviderError(
                        provider=provider,
                        code=ProviderErrorCode.INVALID_RESPONSE,
                        message="invalid DNS response schema",
                        retryable=False,
                    ),
                )
            )

        try:
            _validate_question(parsed, query_name, rr_type)
        except ValueError:
            return DnsQueryOutcome(
                errors=(
                    ProviderError(
                        provider=provider,
                        code=ProviderErrorCode.INVALID_RESPONSE,
                        message="invalid DNS response schema",
                        retryable=False,
                    ),
                )
            )

        status_outcome = _evaluate_dns_status(parsed, provider)
        if status_outcome is not None:
            return status_outcome

        return self._build_evidence_outcome(context, parsed, query_name, rr_type)

    def _build_evidence_outcome(
        self,
        context: DnsQueryContext,
        parsed: GoogleDnsResponse,
        query_name: str,
        rr_type: str,
    ) -> DnsQueryOutcome:
        """Normalize answer records and build an Evidence observation."""
        normalized_answers: list[dict[str, Any]] = []
        for answer in parsed.Answer:
            norm = _normalize_single_answer(answer, rr_type)
            if norm is None:
                return DnsQueryOutcome(
                    errors=(
                        ProviderError(
                            provider=self.id,
                            code=ProviderErrorCode.INVALID_RESPONSE,
                            message="invalid DNS answer data",
                            retryable=False,
                        ),
                    )
                )
            normalized_answers.append(norm)

        if not _validate_answer_set(normalized_answers, query_name, rr_type):
            return DnsQueryOutcome(
                errors=(
                    ProviderError(
                        provider=self.id,
                        code=ProviderErrorCode.INVALID_RESPONSE,
                        message="inconsistent DNS answer set",
                        retryable=False,
                    ),
                )
            )

        flags: dict[str, bool] = {}
        for flag_name, flag_val in [
            ("tc", parsed.TC),
            ("rd", parsed.RD),
            ("ra", parsed.RA),
            ("ad", parsed.AD),
            ("cd", parsed.CD),
        ]:
            if flag_val is not None:
                flags[flag_name] = flag_val

        facts: dict[str, Any] = {
            "query_name": query_name,
            "query_type": rr_type,
            "status": parsed.Status,
            "flags": flags,
            "answers": normalized_answers,
        }

        evidence = Evidence(
            investigation_id=context.investigation_id,
            type=EvidenceType.DNS,
            subject=context.subject,
            source=self.id,
            source_url=_GOOGLE_DNS_ENDPOINT,
            retrieved_at=context.retrieved_at,
            facts=facts,
            raw_payload=None,
        )
        return DnsQueryOutcome(evidence=evidence)

    async def _query_ptr(
        self,
        investigation_id: UUID,
        entity: Entity,
        canonical_ip: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        provider = self.id
        subject = EvidenceEntityRef(
            id=entity.id, type=EntityType.IP_ADDRESS, value=canonical_ip
        )

        try:
            ip_obj = ipaddress.ip_address(canonical_ip)
            ptr_name = ip_obj.reverse_pointer
        except ValueError:
            return unsupported_indicator_result(provider, "invalid entity value")

        context = DnsQueryContext(
            investigation_id=investigation_id,
            subject=subject,
            retrieved_at=retrieved_at,
        )
        outcome = await self._query_rr_type(context, ptr_name, "PTR")

        if outcome.evidence is not None:
            return ProviderResult(
                provider=provider,
                evidence=(outcome.evidence,),
                errors=outcome.errors,
            )

        return ProviderResult(
            provider=provider,
            errors=outcome.errors,
        )
