# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""AbuseIPDB provider for IP-address reputation evidence.

Queries the official AbuseIPDB API v2 check endpoint
(``https://api.abuseipdb.com/api/v2/check``) with ``Key``-header
authentication and normalizes the response into immutable ``REPUTATION``
evidence. Provider scores, counts, categories, and report timestamps are
retained as source facts only: the provider never assesses maliciousness,
never weights assessment confidence, never persists, never creates
relationships, and never instantiates discovered entities. A zero abuse
score, zero reports, or a whitelisted flag is a source fact, not a benign
assessment.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderErrorCode,
    ProviderResult,
    normalize_retrieval_timestamp,
    provider_error_result,
    validate_investigation_entity,
)
from agentic_threat_investigator.domain.entities import (
    Entity,
    EntityType,
    canonicalize_ip_address,
)
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient

_ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
"""Fixed AbuseIPDB API v2 check authority; query parameters carry the lookup."""

_MIN_MAX_AGE_IN_DAYS = 1
"""Smallest supported report look-back window in days."""

_MAX_MAX_AGE_IN_DAYS = 365
"""Largest supported report look-back window in days."""

_PositiveCategory = Annotated[int, Field(strict=True, gt=0)]
"""Strict positive integer category identifier exactly as reported."""


def _parse_source_timestamp(value: object) -> datetime:
    """Parse a strict timezone-aware ISO 8601 source timestamp.

    Booleans, non-strings, naive timestamps, unparseable values, and
    whitespace-padded strings are rejected: the raw string must parse
    directly as a timezone-aware ISO 8601 timestamp (``Z`` and explicit
    offsets are accepted) and is not normalized away. The parsed value is
    normalized to UTC.
    """
    if not isinstance(value, str):
        raise ValueError("source timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("invalid source timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("source timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


class AbuseIpdbReport(BaseModel):
    """Strictly validated single AbuseIPDB report entry.

    Only the approved ``reportedAt`` and ``categories`` members are
    consumed. Unknown entry members (``comment``, ``reporterId``,
    ``reporterCountryCode``, ``reporterCountryName``, and anything else)
    are ignored and never copied into facts. Category codes are strict
    positive integers exactly as reported: ``0``, negative integers,
    booleans, floats, numeric strings, and null are rejected. Both
    members are required; an explicitly empty ``categories`` list is
    valid.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    reported_at: datetime = Field(alias="reportedAt")
    categories: list[_PositiveCategory]

    @field_validator("reported_at", mode="before")
    @classmethod
    def _strict_timestamp(cls, value: object) -> datetime:
        """Require a strict timezone-aware ISO 8601 timestamp, UTC-normalized."""
        return _parse_source_timestamp(value)


class AbuseIpdbCheckResponse(BaseModel):
    """Strictly validated AbuseIPDB check response ``data`` object.

    Only the approved members are consumed; unknown members and all
    geography, network, comment, and reporter metadata members are
    ignored and never copied into facts (``extra="ignore"``). Scalars are
    strict: booleans, floats, numeric strings, lists, and objects are
    rejected where a number, boolean, or string is documented.

    ``isWhitelisted`` and ``lastReportedAt`` are required members whose
    documented null values are valid and always retained; every other
    member is required non-nullable. Because ATI always requests
    ``verbose``, ``reports`` is a required array and an explicitly empty
    array is valid.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    ip_address: str = Field(min_length=1, max_length=45, alias="ipAddress")
    is_public: bool = Field(alias="isPublic")
    ip_version: int = Field(alias="ipVersion")
    is_whitelisted: bool | None = Field(alias="isWhitelisted")
    abuse_confidence_score: int = Field(ge=0, le=100, alias="abuseConfidenceScore")
    is_tor: bool = Field(alias="isTor")
    total_reports: int = Field(ge=0, alias="totalReports")
    num_distinct_users: int = Field(ge=0, alias="numDistinctUsers")
    last_reported_at: datetime | None = Field(alias="lastReportedAt")
    reports: list[AbuseIpdbReport]

    @field_validator("ip_address", mode="before")
    @classmethod
    def _canonical_ip(cls, value: object) -> str:
        """Require a valid IPv4/IPv6 address, canonicalized before bounds.

        Outer whitespace is stripped first so a padded representation is
        judged on its canonical form. Non-string scalars are rejected.
        """
        if not isinstance(value, str):
            raise ValueError("check response ipAddress member must be a string")
        try:
            return canonicalize_ip_address(value)
        except ValueError as exc:
            raise ValueError("invalid check response ipAddress member") from exc

    @field_validator("ip_version")
    @classmethod
    def _validate_ip_version(cls, value: int) -> int:
        """Require the documented IP version members 4 or 6."""
        if value not in (4, 6):
            raise ValueError("check response ipVersion member must be 4 or 6")
        return value

    @field_validator("last_reported_at", mode="before")
    @classmethod
    def _strict_last_reported(cls, value: object) -> datetime | None:
        """Require a strict timezone-aware ISO 8601 timestamp when non-null.

        The documented null value is valid and is retained as ``None``.
        """
        if value is None:
            return None
        return _parse_source_timestamp(value)


class AbuseIpdbProvider(EvidenceProvider):
    """Provider using the AbuseIPDB API v2 check endpoint for IP reputation."""

    def __init__(
        self,
        http_client: ProviderHttpClient,
        *,
        api_key: str,
        max_age_in_days: int = 30,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the provider with an HTTP client and a resolved key.

        The HTTP client is owned by the caller. ``api_key`` must be the API
        key already resolved during composition/bootstrap; the provider
        never reads configuration or the environment and the value is used
        only in the ``Key`` header, never in URLs, facts, or logs.
        ``max_age_in_days`` is the fixed report look-back window sent on
        every lookup and retained in evidence facts. The UTC wall clock is
        used only for Evidence ``retrieved_at`` timestamps; tests may
        inject a deterministic replacement, otherwise ``datetime.now(UTC)``
        is used.
        """
        if not api_key.strip():
            raise ValueError("AbuseIPDB API key must not be blank")
        if isinstance(max_age_in_days, bool) or not isinstance(max_age_in_days, int):
            raise ValueError("max_age_in_days must be an integer")
        if not _MIN_MAX_AGE_IN_DAYS <= max_age_in_days <= _MAX_MAX_AGE_IN_DAYS:
            raise ValueError(
                "max_age_in_days must be between "
                f"{_MIN_MAX_AGE_IN_DAYS} and {_MAX_MAX_AGE_IN_DAYS}"
            )
        self._http = http_client
        self._api_key = api_key.strip()
        self._max_age_in_days = max_age_in_days
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def id(self) -> str:
        """Return the stable ``urn:ati:source:abuseipdb`` identifier."""
        return SourceId.ABUSEIPDB.value

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to IP-address entities only."""
        return entity.type == EntityType.IP_ADDRESS

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Retrieve AbuseIPDB reputation facts for one IP-address entity.

        The shared validation helper rejects unsupported entity types and
        uncanonicalizable values before any HTTP I/O. A successful lookup
        emits exactly one immutable ``REPUTATION`` evidence observation; a
        malformed response yields one typed error and no evidence. The
        provider never persists, creates relationships, or assesses
        maliciousness; a zero score or zero reports is a retained source
        fact, never a benign assessment.
        """
        validation = validate_investigation_entity(self, entity)
        rejection = validation[1]
        if rejection is not None:
            return rejection
        canonical_ip = validation[0]
        assert canonical_ip is not None
        return await self._lookup(
            investigation_id=investigation_id,
            entity=entity,
            canonical_ip=canonical_ip,
            retrieved_at=normalize_retrieval_timestamp(self._clock),
        )

    async def _lookup(
        self,
        *,
        investigation_id: UUID,
        entity: Entity,
        canonical_ip: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        """Query the check endpoint and normalize one evidence observation."""
        # Query parameters travel through the shared client's bounded
        # parameter handling; the URL never carries the API key or a
        # hand-built query string. ``verbose`` is sent as an empty query
        # value so the source includes the detailed reports array.
        params: dict[str, Any] = {
            "ipAddress": canonical_ip,
            "maxAgeInDays": self._max_age_in_days,
            "verbose": "",
        }
        outcome = await self._http.request_json(
            "GET",
            _ABUSEIPDB_ENDPOINT,
            params=params,
            # The API key travels only in the custom Key header; the shared
            # client contributes the standard JSON Accept header.
            headers={"Key": self._api_key},
        )

        if outcome.final_error_code is not None:
            return provider_error_result(
                self.id,
                _remap_status_error(outcome.final_status, outcome.final_error_code),
                outcome.final_error_message or "AbuseIPDB request failed",
                retry_after_seconds=outcome.retry_after_seconds,
            )

        data = _extract_data_object(outcome.response_json)
        if data is None:
            return self._malformed_response(
                "AbuseIPDB response data must be a JSON object"
            )

        try:
            parsed = AbuseIpdbCheckResponse.model_validate(data)
        except ValueError:
            return self._malformed_response("invalid AbuseIPDB response schema")

        # Cross-field identity: the returned IP must canonicalize exactly to
        # the requested canonical IP (covers textual variants and a wrong
        # address), and the reported version must match the address family.
        if (
            parsed.ip_address != canonical_ip
            or parsed.ip_version != ipaddress.ip_address(canonical_ip).version
        ):
            return self._malformed_response(
                "AbuseIPDB response identity does not match the queried IP"
            )

        subject = EvidenceEntityRef(
            id=entity.id,
            type=EntityType.IP_ADDRESS,
            value=canonical_ip,
        )
        evidence = Evidence(
            investigation_id=investigation_id,
            type=EvidenceType.REPUTATION,
            subject=subject,
            source=self.id,
            source_url=_ABUSEIPDB_ENDPOINT,
            observed_at=parsed.last_reported_at,
            retrieved_at=retrieved_at,
            facts=_build_facts(parsed, self._max_age_in_days),
            raw_payload=None,
        )
        return ProviderResult(provider=self.id, evidence=(evidence,))

    def _malformed_response(self, message: str) -> ProviderResult:
        """Build a standard non-retryable ``INVALID_RESPONSE`` failure."""
        return provider_error_result(
            self.id, ProviderErrorCode.INVALID_RESPONSE, message
        )


def _extract_data_object(response_json: Any) -> dict[str, Any] | None:
    """Return the response ``data`` object, or ``None`` when malformed."""
    if not isinstance(response_json, dict):
        return None
    data = response_json.get("data")
    return data if isinstance(data, dict) else None


def _remap_status_error(
    final_status: int | None, code: ProviderErrorCode
) -> ProviderErrorCode:
    """Remap the shared classification for AbuseIPDB-specific statuses.

    HTTP 402 (expired subscription) is an access denial rather than a
    malformed response, so it is reported as ``FORBIDDEN``. Every other
    status keeps the shared client classification.
    """
    if final_status == 402 and code is ProviderErrorCode.INVALID_RESPONSE:
        return ProviderErrorCode.FORBIDDEN
    return code


def _build_facts(
    parsed: AbuseIpdbCheckResponse, max_age_in_days: int
) -> dict[str, Any]:
    """Build the normalized AbuseIPDB fact dictionary from canonical model data.

    Exactly the approved fact keys are always emitted, including
    ``max_age_in_days`` so report and count semantics remain interpretable
    against the queried window, and a null ``last_reported_at`` when the
    source reported no last-report time. Category identifiers and report
    entries preserve source array order; no labels, geography, network,
    comment, or reporter metadata is ever synthesized or copied.
    """
    return {
        "ip_address": parsed.ip_address,
        "is_public": parsed.is_public,
        "ip_version": parsed.ip_version,
        "is_whitelisted": parsed.is_whitelisted,
        "abuse_confidence_score": parsed.abuse_confidence_score,
        "is_tor": parsed.is_tor,
        "total_reports": parsed.total_reports,
        "num_distinct_users": parsed.num_distinct_users,
        "last_reported_at": (
            None
            if parsed.last_reported_at is None
            else parsed.last_reported_at.isoformat()
        ),
        "max_age_in_days": max_age_in_days,
        "reports": [_build_report_facts(report) for report in parsed.reports],
    }


def _build_report_facts(report: AbuseIpdbReport) -> dict[str, Any]:
    """Build one normalized report fact object.

    Each report contains exactly ``reported_at`` and ``categories``; the
    source order of reports and category identifiers is preserved,
    including duplicates.
    """
    return {
        "reported_at": report.reported_at.isoformat(),
        "categories": list(report.categories),
    }
