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


# -- Answer normalizers ---------------------------------------------------


def _normalize_ip_answer(
    answer: GoogleDnsAnswer, expected_version: int, record_type: str
) -> dict[str, Any] | None:
    """Normalize an A or AAAA answer record."""
    try:
        ip_obj = ipaddress.ip_address(answer.data.strip())
        if ip_obj.version != expected_version:
            return None
        return {
            "name": validate_dns_name(answer.name),
            "record_type": record_type,
            "ttl": answer.TTL,
            "value": str(ip_obj),
        }
    except ValueError:
        return None


def _normalize_name_answer(
    answer: GoogleDnsAnswer, record_type: str
) -> dict[str, Any] | None:
    """Normalize a CNAME, NS, or PTR answer record."""
    try:
        return {
            "name": validate_dns_name(answer.name),
            "record_type": record_type,
            "ttl": answer.TTL,
            "value": validate_dns_name(answer.data),
        }
    except ValueError:
        return None


def _normalize_mx_answer(answer: GoogleDnsAnswer) -> dict[str, Any] | None:
    """Normalize an MX answer record."""
    parts = answer.data.strip().split(None, 1)
    if len(parts) != 2:
        return None
    try:
        preference = int(parts[0])
        if not 0 <= preference <= 65535:
            return None
        exchange = validate_dns_name(parts[1])
        return {
            "name": validate_dns_name(answer.name),
            "record_type": "MX",
            "ttl": answer.TTL,
            "preference": preference,
            "exchange": exchange,
        }
    except ValueError:
        return None


def _normalize_soa_answer(answer: GoogleDnsAnswer) -> dict[str, Any] | None:
    """Normalize an SOA authority record."""
    parts = answer.data.strip().split(None, 6)
    if len(parts) != 7:
        return None
    try:
        mname = validate_dns_name(parts[0])
        rname = validate_dns_name(parts[1])
        numbers = [int(p) for p in parts[2:]]
        if any(not 0 <= n <= _MAX_UINT32 for n in numbers):
            return None
        return {
            "name": validate_dns_name(answer.name),
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
    except ValueError:
        return None


def _normalize_txt_answer(answer: GoogleDnsAnswer) -> dict[str, Any] | None:
    """Normalize a TXT answer record."""
    try:
        return {
            "name": validate_dns_name(answer.name),
            "record_type": "TXT",
            "ttl": answer.TTL,
            "value": answer.data,
        }
    except ValueError:
        return None


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

    if actual_type != requested_type:
        if actual_type == "CNAME" and requested_type in (
            "A",
            "AAAA",
            "MX",
            "NS",
            "TXT",
            "PTR",
        ):
            return _normalize_name_answer(answer, "CNAME")
        return None

    normalizer = _NORMALIZERS.get(actual_type)
    return normalizer(answer) if normalizer is not None else None


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
