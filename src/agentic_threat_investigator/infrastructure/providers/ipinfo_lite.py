# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""IPinfo Lite provider for IP-address infrastructure enrichment.

Queries the current IPinfo Lite API (``https://api.ipinfo.io/lite/<ip>``)
with Bearer-token authentication and normalizes the response into immutable
``NETWORK`` evidence. The provider retrieves and normalizes only: it never
persists, never creates relationships, never instantiates discovered
entities from response data, and never assesses maliciousness.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
    canonicalize_asn,
    canonicalize_ip_address,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    validate_entity_url_path,
)

_IPINFO_LITE_ENDPOINT = "https://api.ipinfo.io/lite"
"""Fixed Lite API authority; the canonical IP is the only variable path part."""

_MAX_IP_LENGTH = 45
"""Longest legal textual IPv4/IPv6 address representation."""

_MAX_ASN_LENGTH = 12
"""``AS`` prefix plus the largest legal 32-bit decimal autonomous system number."""

_MAX_OPERATOR_LENGTH = 256
"""Bound for the Lite operator/organization display name."""

_MAX_COUNTRY_LENGTH = 128
"""Bound for the Lite full country name."""

_MAX_CONTINENT_LENGTH = 64
"""Bound for the Lite full continent name."""

_CODE_PATTERN = re.compile(r"[A-Z]{2}")
"""Exact grammar for the bounded two-letter country and continent codes."""

# Officially assigned ISO 3166-1 alpha-2 country-code elements.
# Authoritative source: ISO 3166-1, ISO 3166 maintenance agency
# (https://www.iso.org/iso-3166-country-codes.html), officially assigned
# code elements; snapshot verified against the published 249-entry assigned
# list during PR 13 integration (2026-02). Exceptionally reserved elements
# (for example ``UK``) and unassigned elements (for example ``ZZ``) are
# deliberately excluded. Keep provider-local until a later geolocation
# integration justifies a shared domain registry.
_ISO_3166_1_ALPHA_2_ASSIGNED: frozenset[str] = frozenset(
    {
        "AD",
        "AE",
        "AF",
        "AG",
        "AI",
        "AL",
        "AM",
        "AO",
        "AQ",
        "AR",
        "AS",
        "AT",
        "AU",
        "AW",
        "AX",
        "AZ",
        "BA",
        "BB",
        "BD",
        "BE",
        "BF",
        "BG",
        "BH",
        "BI",
        "BJ",
        "BL",
        "BM",
        "BN",
        "BO",
        "BQ",
        "BR",
        "BS",
        "BT",
        "BV",
        "BW",
        "BY",
        "BZ",
        "CA",
        "CC",
        "CD",
        "CF",
        "CG",
        "CH",
        "CI",
        "CK",
        "CL",
        "CM",
        "CN",
        "CO",
        "CR",
        "CU",
        "CV",
        "CW",
        "CX",
        "CY",
        "CZ",
        "DE",
        "DJ",
        "DK",
        "DM",
        "DO",
        "DZ",
        "EC",
        "EE",
        "EG",
        "EH",
        "ER",
        "ES",
        "ET",
        "FI",
        "FJ",
        "FK",
        "FM",
        "FO",
        "FR",
        "GA",
        "GB",
        "GD",
        "GE",
        "GF",
        "GG",
        "GH",
        "GI",
        "GL",
        "GM",
        "GN",
        "GP",
        "GQ",
        "GR",
        "GS",
        "GT",
        "GU",
        "GW",
        "GY",
        "HK",
        "HM",
        "HN",
        "HR",
        "HT",
        "HU",
        "ID",
        "IE",
        "IL",
        "IM",
        "IN",
        "IO",
        "IQ",
        "IR",
        "IS",
        "IT",
        "JE",
        "JM",
        "JO",
        "JP",
        "KE",
        "KG",
        "KH",
        "KI",
        "KM",
        "KN",
        "KP",
        "KR",
        "KW",
        "KY",
        "KZ",
        "LA",
        "LB",
        "LC",
        "LI",
        "LK",
        "LR",
        "LS",
        "LT",
        "LU",
        "LV",
        "LY",
        "MA",
        "MC",
        "MD",
        "ME",
        "MF",
        "MG",
        "MH",
        "MK",
        "ML",
        "MM",
        "MN",
        "MO",
        "MP",
        "MQ",
        "MR",
        "MS",
        "MT",
        "MU",
        "MV",
        "MW",
        "MX",
        "MY",
        "MZ",
        "NA",
        "NC",
        "NE",
        "NF",
        "NG",
        "NI",
        "NL",
        "NO",
        "NP",
        "NR",
        "NU",
        "NZ",
        "OM",
        "PA",
        "PE",
        "PF",
        "PG",
        "PH",
        "PK",
        "PL",
        "PM",
        "PN",
        "PR",
        "PS",
        "PT",
        "PW",
        "PY",
        "QA",
        "RE",
        "RO",
        "RS",
        "RU",
        "RW",
        "SA",
        "SB",
        "SC",
        "SD",
        "SE",
        "SG",
        "SH",
        "SI",
        "SJ",
        "SK",
        "SL",
        "SM",
        "SN",
        "SO",
        "SR",
        "SS",
        "ST",
        "SV",
        "SX",
        "SY",
        "SZ",
        "TC",
        "TD",
        "TF",
        "TG",
        "TH",
        "TJ",
        "TK",
        "TL",
        "TM",
        "TN",
        "TO",
        "TR",
        "TT",
        "TV",
        "TW",
        "TZ",
        "UA",
        "UG",
        "UM",
        "US",
        "UY",
        "UZ",
        "VA",
        "VC",
        "VE",
        "VG",
        "VI",
        "VN",
        "VU",
        "WF",
        "WS",
        "YE",
        "YT",
        "ZA",
        "ZM",
        "ZW",
    }
)
"""Officially assigned ISO 3166-1 alpha-2 country codes (249 elements)."""

_LITE_RESPONSE_FIELDS = (
    "ip",
    "asn",
    "as_name",
    "as_domain",
    "country_code",
    "country",
    "continent_code",
    "continent",
)
"""All documented Lite response members used for explicit-null rejection."""


class IpinfoLiteResponse(BaseModel):
    """Strictly validated IPinfo Lite lookup response.

    Unknown top-level members are ignored and never copied into facts
    (``extra="ignore"``). Scalars are strict: booleans, integers, lists,
    objects, and null are rejected where a string is documented, so provider
    data can never coerce into a plausible-looking fact. An explicit null is
    not a missing-field sentinel: absent optional members mean the source
    carries no such data, while a present null member is malformed.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    ip: str = Field(min_length=1, max_length=_MAX_IP_LENGTH)
    asn: str | None = Field(default=None, min_length=1, max_length=_MAX_ASN_LENGTH)
    as_name: str | None = Field(
        default=None, min_length=1, max_length=_MAX_OPERATOR_LENGTH
    )
    as_domain: str | None = Field(default=None, min_length=1, max_length=253)
    country_code: str | None = Field(default=None, min_length=1, max_length=2)
    country: str | None = Field(
        default=None, min_length=1, max_length=_MAX_COUNTRY_LENGTH
    )
    continent_code: str | None = Field(default=None, min_length=1, max_length=2)
    continent: str | None = Field(
        default=None, min_length=1, max_length=_MAX_CONTINENT_LENGTH
    )

    @model_validator(mode="before")
    @classmethod
    def _reject_explicit_null(cls, data: object) -> object:
        """Reject explicit null members; only absent keys mean no source data."""
        if isinstance(data, dict):
            for key in _LITE_RESPONSE_FIELDS:
                if key in data and data[key] is None:
                    raise ValueError(f"Lite response member {key} must not be null")
        return data

    @field_validator("ip", mode="before")
    @classmethod
    def _canonical_ip(cls, value: object) -> object:
        """Require a valid IPv4/IPv6 address, canonicalized before length bounds.

        Outer whitespace is stripped first so a raw representation whose
        whitespace-padded length exceeds the member bound is judged on its
        canonical form. Non-string scalars are rejected explicitly.
        """
        if not isinstance(value, str):
            raise ValueError("Lite response ip member must be a string")
        try:
            return canonicalize_ip_address(value)
        except ValueError as exc:
            raise ValueError("invalid Lite response ip member") from exc

    @field_validator("asn", mode="before")
    @classmethod
    def _canonical_asn(cls, value: object) -> object:
        """Require an ``AS``-prefixed ASN, canonicalized before length bounds.

        Outer whitespace is stripped first so a padded maximum-length ASN
        canonicalizes instead of failing the raw member bound. Non-string
        scalars are rejected explicitly.
        """
        if not isinstance(value, str):
            raise ValueError("Lite response asn member must be a string")
        candidate = value.strip()
        if not candidate.upper().startswith("AS"):
            raise ValueError("Lite response asn member must carry an AS prefix")
        try:
            return canonicalize_asn(candidate)
        except ValueError as exc:
            raise ValueError("invalid Lite response asn member") from exc

    @field_validator("as_domain", mode="before")
    @classmethod
    def _canonical_domain(cls, value: object) -> object:
        """Require a strict DNS name, canonicalized before length bounds.

        The canonical lowercase/IDNA form is produced first so a padded
        boundary-length domain is judged on its canonical length.
        Non-string scalars are rejected explicitly. The canonical operator
        domain remains a source fact only: it never becomes a discovered
        ATI ``DOMAIN`` entity or relationship endpoint.
        """
        if not isinstance(value, str):
            raise ValueError("Lite response as_domain member must be a string")
        try:
            return validate_dns_name(value)
        except ValueError as exc:
            raise ValueError("invalid Lite response as_domain member") from exc

    @field_validator("country_code")
    @classmethod
    def _validate_country_code(cls, value: str) -> str:
        """Require an officially assigned ISO 3166-1 alpha-2 country code."""
        if _CODE_PATTERN.fullmatch(value) is None:
            raise ValueError("Lite response country code must be two uppercase letters")
        try:
            return _validate_assigned_country_code(value)
        except ValueError as exc:
            raise ValueError(
                "Lite response country code is not an assigned code"
            ) from exc

    @field_validator("continent_code")
    @classmethod
    def _validate_continent_code(cls, value: str) -> str:
        """Require a bounded uppercase two-letter continent code."""
        if _CODE_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "Lite response continent code must be two uppercase letters"
            )
        return value

    @field_validator("as_name", "country", "continent")
    @classmethod
    def _reject_blank_descriptive(cls, value: str) -> str:
        """Reject whitespace-only descriptive members, preserving the text."""
        if not value.strip():
            raise ValueError("Lite response descriptive member must not be blank")
        return value


class IpinfoLiteProvider(EvidenceProvider):
    """Provider using the IPinfo Lite API for IP-address network context."""

    def __init__(
        self,
        http_client: ProviderHttpClient,
        *,
        token: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the provider with an HTTP client and a resolved token.

        The HTTP client is owned by the caller. ``token`` must be the access
        token already resolved during composition/bootstrap; the provider
        never reads configuration or the environment and the value is used
        only in the Authorization header, never in URLs or logs. The UTC wall
        clock is used only for Evidence ``retrieved_at`` timestamps; tests
        may inject a deterministic replacement, otherwise
        ``datetime.now(UTC)`` is used.
        """
        if not token.strip():
            raise ValueError("IPinfo Lite access token must not be blank")
        self._http = http_client
        self._token = token.strip()
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def id(self) -> str:
        """Return the stable ``urn:ati:source:ipinfo_lite`` identifier."""
        return SourceId.IPINFO_LITE.value

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to IP-address entities only."""
        return entity.type == EntityType.IP_ADDRESS

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Retrieve Lite network context for one IP-address entity.

        The shared validation helper rejects unsupported entity types and
        uncanonicalizable values before any HTTP I/O. A successful lookup
        emits exactly one immutable ``NETWORK`` evidence observation; a
        malformed response yields one typed error and no evidence. The
        provider never persists, creates relationships, or assesses
        maliciousness.
        """
        canonical_ip, rejection = validate_investigation_entity(self, entity)
        if rejection is not None:
            return rejection
        assert canonical_ip is not None
        # The retrieval timestamp is evaluated after validation succeeds and
        # before any HTTP I/O, so rejected entities never consume a reading.
        return await self._lookup(
            investigation_id,
            entity,
            canonical_ip,
            normalize_retrieval_timestamp(self._clock),
        )

    async def _lookup(
        self,
        investigation_id: UUID,
        entity: Entity,
        canonical_ip: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        """Query the Lite endpoint and normalize one evidence observation."""
        # The canonical IP is percent-encoded into the fixed resource path;
        # the URL never carries a query, fragment, or the access token.
        url = validate_entity_url_path(
            _IPINFO_LITE_ENDPOINT, quote(canonical_ip, safe="")
        )
        outcome = await self._http.request_json(
            "GET",
            url,
            # The access token travels only in the Authorization header; the
            # shared client contributes the standard JSON Accept header.
            headers={"Authorization": f"Bearer {self._token}"},
        )

        if outcome.final_error_code is not None:
            return _lite_error_result(
                self.id,
                outcome.final_error_code,
                outcome.final_error_message or "Lite request failed",
                retry_after_seconds=outcome.retry_after_seconds,
            )

        if not isinstance(outcome.response_json, dict):
            return self._invalid_response("Lite response must be a JSON object")

        try:
            parsed = IpinfoLiteResponse.model_validate(outcome.response_json)
        except ValueError:
            return self._invalid_response("invalid Lite response schema")

        # Cross-field identity: the returned IP must canonicalize exactly to
        # the requested canonical IP (covers textual variants, address-family
        # mismatch, and a wrong address).
        if parsed.ip != canonical_ip:
            return self._invalid_response(
                "Lite response identity does not match the queried IP"
            )

        evidence = Evidence(
            investigation_id=investigation_id,
            type=EvidenceType.NETWORK,
            subject=EvidenceEntityRef(
                id=entity.id,
                type=EntityType.IP_ADDRESS,
                value=canonical_ip,
            ),
            source=self.id,
            source_url=url,
            observed_at=None,
            retrieved_at=retrieved_at,
            facts=_build_facts(parsed),
            raw_payload=None,
        )
        return ProviderResult(provider=self.id, evidence=(evidence,))

    def _invalid_response(self, message: str) -> ProviderResult:
        """Build a standard non-retryable ``INVALID_RESPONSE`` failure."""
        return _lite_error_result(self.id, ProviderErrorCode.INVALID_RESPONSE, message)


def _lite_error_result(
    provider_urn: str,
    code: ProviderErrorCode,
    message: str,
    *,
    retry_after_seconds: int | None = None,
) -> ProviderResult:
    """Build one typed provider error attributed to the Lite provider."""
    return provider_error_result(
        provider_urn,
        code,
        message,
        retry_after_seconds=retry_after_seconds,
    )


def _validate_assigned_country_code(value: str) -> str:
    """Return ``value`` only when it is an officially assigned alpha-2 code."""
    if value not in _ISO_3166_1_ALPHA_2_ASSIGNED:
        raise ValueError(f"not an assigned ISO 3166-1 alpha-2 code: {value}")
    return value


def _build_facts(parsed: IpinfoLiteResponse) -> dict[str, Any]:
    """Build the normalized Lite fact dictionary from canonical model data.

    Only present members are included; omitted optional members are omitted
    from facts as documented source-absence, never inferred.
    """
    facts: dict[str, Any] = {"ip": parsed.ip}
    if parsed.asn is not None:
        facts["asn"] = parsed.asn
    if parsed.as_name is not None:
        facts["as_name"] = parsed.as_name
    if parsed.as_domain is not None:
        facts["as_domain"] = parsed.as_domain
    if parsed.country_code is not None:
        facts["country_code"] = parsed.country_code
    if parsed.country is not None:
        facts["country"] = parsed.country
    if parsed.continent_code is not None:
        facts["continent_code"] = parsed.continent_code
    if parsed.continent is not None:
        facts["continent"] = parsed.continent
    return facts
