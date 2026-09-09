# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""URLhaus provider for malicious-URL threat-intelligence evidence.

Queries the official abuse.ch URLhaus Community API v1 lookup endpoints
(``https://urlhaus-api.abuse.ch/v1/url/`` for exact URL lookups and
``https://urlhaus-api.abuse.ch/v1/host/`` for host lookups over
``application/x-www-form-urlencoded`` bodies with ``Auth-Key`` header
authentication) and normalizes validated matching records into immutable
``THREAT_INTELLIGENCE`` evidence. Returned URL records, source statuses,
threat labels, tags, timestamps, and payload metadata (hashes, sizes, file
types, signatures) are retained strictly as source facts: the provider
never downloads payloads, never fetches any returned URL, never assesses
maliciousness, never persists, never creates relationships, and never
instantiates discovered entities. The normalized ``matches`` facts carry
the exact source URL and host members so a deterministic
persistence-boundary extractor (PR 18B) can later derive canonical URL and
infrastructure entities under its own approved semantics. A no-result
response is an empty result, never a benign assessment.

The two endpoints use endpoint-specific strict record models: a direct
URL response carries the documented ``host``, ``last_online``, ``tags``,
and ``payloads`` members, while host-response ``urls[]`` records carry
only ``id``, ``url``, ``url_status``, ``date_added``, ``threat``, and
``tags``. Documented collection limits (max 100 payload entries per URL
record and max 100 ``urls[]`` entries per host response) are enforced
before any normalization.
"""

# The provider modules deliberately mirror the established provider-family
# shapes (see ThreatFox/AbuseIPDB); per-block R0801 suppression is not
# supported by Pylint, so duplicate-code is disabled at module scope for
# the deliberately accepted duplication.
# pylint: disable=duplicate-code

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
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
    canonicalize_url,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient

_URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
"""Official URLhaus Community API exact-URL lookup endpoint."""

_URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
"""Official URLhaus Community API host lookup endpoint (IPv4/hostname/domain)."""

_URLHAUS_ID_RE = re.compile(r"^[0-9]{1,16}$")
"""Official URLhaus URL identifier form: a bounded decimal string."""

_URLHAUS_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$")
"""Official URLhaus source timestamp form, always UTC."""

_URLHAUS_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
"""Official URLhaus payload firstseen date form."""

_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
"""MD5 hash form: exactly 32 hexadecimal characters."""

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
"""SHA256 hash form: exactly 64 hexadecimal characters."""

_URL_STATUS_VALUES = frozenset({"online", "offline", "unknown"})
"""Documented url_status vocabulary."""

_DOCUMENTED_THREAT = "malware_download"
"""The only threat value the official URLhaus lookup contract documents."""

_MAX_COLLECTION_ENTRIES = 100
"""Documented maximum entries: URL payloads and host-response ``urls[]``."""

_URL_MAX_LENGTH = 2048
_HOST_MAX_LENGTH = 253
_TAG_MAX_LENGTH = 64
_FILE_TYPE_MAX_LENGTH = 64
_FILENAME_MAX_LENGTH = 256
_SIGNATURE_MAX_LENGTH = 128
_RESPONSE_SIZE_MAX = 10**15
"""Bounded response_size ceiling far above any real HTTP body size."""


def _parse_urlhaus_timestamp(value: object) -> datetime:
    """Parse the strict official URLhaus source timestamp form into UTC.

    Only the documented ``YYYY-MM-DD HH:MM:SS UTC`` form is accepted:
    booleans, non-strings, ISO-8601 spellings, whitespace-padded strings,
    and unparseable calendar values are rejected. The parsed value is
    timezone-aware UTC.
    """
    if not isinstance(value, str):
        raise ValueError("source timestamp must be a string")
    if not _URLHAUS_TIMESTAMP_RE.fullmatch(value):
        raise ValueError("source timestamp must use the URLhaus UTC form")
    parsed = datetime.strptime(value[: -len(" UTC")], "%Y-%m-%d %H:%M:%S")
    return parsed.replace(tzinfo=UTC)


def _parse_urlhaus_date(value: object) -> str:
    """Validate the documented payload ``firstseen`` date form.

    The date is retained verbatim as a source fact; only its strict
    ``YYYY-MM-DD`` calendar form is enforced.
    """
    if not isinstance(value, str) or not _URLHAUS_DATE_RE.fullmatch(value):
        raise ValueError("payload firstseen must use the YYYY-MM-DD form")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("payload firstseen is not a valid calendar date") from exc
    return value


def _parse_hex_hash(value: object, length: int, member: str) -> str:
    """Validate and lowercase a fixed-length hexadecimal hash source fact."""
    pattern = _MD5_RE if length == 32 else _SHA256_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"payload {member} must be a {length}-character hex digest")
    return value.lower()


def _parse_response_size(value: object) -> int:
    """Parse the documented response_size form (decimal digits, string or int).

    The official API renders the payload byte size as a decimal string;
    a strict integer is also accepted. Booleans, floats, and non-decimal
    strings are rejected.
    """
    if isinstance(value, bool):
        raise ValueError("payload response_size must be a byte count")
    if isinstance(value, int):
        size = value
    elif isinstance(value, str) and value.isdigit():
        size = int(value)
    else:
        raise ValueError("payload response_size must be a byte count")
    if not 0 <= size <= _RESPONSE_SIZE_MAX:
        raise ValueError("payload response_size is out of bounds")
    return size


def _is_bounded_tag(tag: object) -> bool:
    """Return whether one tag is a bounded, unpadded, nonblank string."""
    return (
        isinstance(tag, str)
        and bool(tag.strip())
        and tag == tag.strip()
        and len(tag) <= _TAG_MAX_LENGTH
    )


def _validate_required_tags(value: object) -> list[str]:
    """Require the documented bounded-string tag list form (never null)."""
    if not isinstance(value, list) or any(not _is_bounded_tag(tag) for tag in value):
        raise ValueError("URLhaus record tags must be a list of bounded strings")
    return value


def _validate_required_host(value: object) -> str:
    """Require a bounded, nonblank, unpadded host member string."""
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > _HOST_MAX_LENGTH
    ):
        raise ValueError("invalid URLhaus record host member")
    return value


def _validate_optional_string(value: object, bound: int, member: str) -> str | None:
    """Validate an optional bounded nonblank source string member."""
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > bound
    ):
        raise ValueError(f"invalid {member} member")
    return value


def _canonical_host_identity(value: str) -> str | None:
    """Return the canonical DOMAIN/IPv4/IPv6 identity of a host string.

    IP literals (any family) use the canonical IP representation; every
    other spelling is validated as a strict DNS name. Parser, family,
    and Unicode errors map to ``None``.
    """
    try:
        return canonicalize_ip_address(value)
    except ValueError:
        pass
    try:
        return validate_dns_name(value)
    except ValueError, UnicodeError:
        return None


def _host_identity_of_url(url: str) -> str | None:
    """Return the canonical host identity parsed from a URL string.

    URLs without a parseable host, and hosts outside the DOMAIN/IP
    identity contracts, map to ``None``.
    """
    hostname = urlsplit(url).hostname
    if not hostname:
        return None
    return _canonical_host_identity(hostname)


class UrlhausPayload(BaseModel):
    """Strictly validated single URLhaus payload metadata entry.

    Only the documented fact members are consumed: the observation date,
    filename, file type, HTTP response size, MD5/SHA256 digests, and
    malware signature. The ``urlhaus_download`` location and all
    VirusTotal/imphash/ssdeep/tlsh/magika members are deliberately
    unconsumed: ATI never stores payload download links in v0.1. Unknown
    members are ignored. All values remain fact-only source data.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    firstseen: str
    filename: str | None = None
    file_type: str | None = None
    response_size: int
    response_md5: str | None = None
    response_sha256: str | None = None
    signature: str | None = None

    @field_validator("firstseen", mode="before")
    @classmethod
    def _validate_firstseen(cls, value: object) -> str:
        """Require the documented payload observation date form."""
        return _parse_urlhaus_date(value)

    @field_validator("filename", mode="before")
    @classmethod
    def _validate_filename(cls, value: object) -> str | None:
        """Validate the optional bounded filename member."""
        return _validate_optional_string(value, _FILENAME_MAX_LENGTH, "filename")

    @field_validator("file_type", mode="before")
    @classmethod
    def _validate_file_type(cls, value: object) -> str | None:
        """Validate the optional bounded file-type member."""
        return _validate_optional_string(value, _FILE_TYPE_MAX_LENGTH, "file_type")

    @field_validator("response_size", mode="before")
    @classmethod
    def _validate_response_size(cls, value: object) -> int:
        """Require the documented response-size form."""
        return _parse_response_size(value)

    @field_validator("response_md5", mode="before")
    @classmethod
    def _validate_response_md5(cls, value: object) -> str | None:
        """Require an MD5 digest or the documented null."""
        if value is None:
            return None
        return _parse_hex_hash(value, 32, "response_md5")

    @field_validator("response_sha256", mode="before")
    @classmethod
    def _validate_response_sha256(cls, value: object) -> str | None:
        """Require a SHA256 digest or the documented null."""
        if value is None:
            return None
        return _parse_hex_hash(value, 64, "response_sha256")

    @field_validator("signature", mode="before")
    @classmethod
    def _validate_signature(cls, value: object) -> str | None:
        """Validate the optional bounded signature member."""
        return _validate_optional_string(value, _SIGNATURE_MAX_LENGTH, "signature")


class _UrlhausRecordBase(BaseModel):
    """Shared strict members of both URLhaus endpoint record shapes.

    ``urlhaus_reference``, ``blacklists``, ``reporter``, ``larted``, and
    ``takedown_time_seconds`` are unconsumed and never copied into facts.
    Unknown members are ignored. Scalars are strict: booleans, floats,
    and numeric strings are rejected where a string, integer, or list is
    documented.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    id: str
    url: str = Field(min_length=1, max_length=_URL_MAX_LENGTH)
    url_status: str
    date_added: datetime
    threat: str

    @field_validator("id", mode="before")
    @classmethod
    def _validate_id(cls, value: object) -> str:
        """Require the official bounded decimal identifier string form."""
        if not isinstance(value, str) or not _URLHAUS_ID_RE.fullmatch(value):
            raise ValueError("URLhaus record id must be a decimal string")
        return value

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        """Require a bounded, unpadded source URL value; it is never fetched."""
        if value != value.strip() or not value.strip():
            raise ValueError("URLhaus record url must be a nonblank string")
        return value

    @field_validator("url_status")
    @classmethod
    def _validate_url_status(cls, value: str) -> str:
        """Require the documented url_status vocabulary."""
        if value not in _URL_STATUS_VALUES:
            raise ValueError("URLhaus record url_status is not documented")
        return value

    @field_validator("date_added", mode="before")
    @classmethod
    def _validate_date_added(cls, value: object) -> datetime:
        """Require the strict official URLhaus timestamp form."""
        return _parse_urlhaus_timestamp(value)

    @field_validator("threat")
    @classmethod
    def _validate_threat(cls, value: str) -> str:
        """Require exactly the documented ``malware_download`` threat value."""
        if value != _DOCUMENTED_THREAT:
            raise ValueError("URLhaus record threat is not documented")
        return value


class UrlhausUrlRecord(_UrlhausRecordBase):
    """Strictly validated direct URL-lookup record.

    Every documented member is required: ``id``, ``url``, ``url_status``,
    ``host``, ``date_added``, ``last_online``, ``threat``, ``tags``, and
    ``payloads`` (0..100 entries). Nullable members may carry null only
    where the official contract permits it (``last_online``); an omitted
    key is always invalid. The ``host`` member is cross-field checked
    against the returned URL's parsed canonical host by the provider.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    host: str = Field(min_length=1, max_length=_HOST_MAX_LENGTH)
    last_online: datetime | None
    tags: list[str]
    payloads: list[UrlhausPayload] = Field(
        min_length=0, max_length=_MAX_COLLECTION_ENTRIES
    )

    @field_validator("host", mode="before")
    @classmethod
    def _validate_host(cls, value: object) -> str:
        """Require a bounded, nonblank, unpadded host member."""
        return _validate_required_host(value)

    @field_validator("tags", mode="before")
    @classmethod
    def _validate_tags(cls, value: object) -> list[str]:
        """Require the documented bounded-string tag list form."""
        return _validate_required_tags(value)

    @field_validator("payloads", mode="before")
    @classmethod
    def _validate_payloads(cls, value: object) -> list[UrlhausPayload]:
        """Require the documented payload-object list form."""
        if not isinstance(value, list):
            raise ValueError("URLhaus record payloads must be a list")
        payloads: list[UrlhausPayload] = []
        for entry in value:
            try:
                payloads.append(UrlhausPayload.model_validate(entry))
            except ValueError as exc:
                raise ValueError("invalid URLhaus payload entry") from exc
        return payloads

    @field_validator("last_online", mode="before")
    @classmethod
    def _validate_last_online(cls, value: object) -> datetime | None:
        """Require the strict timestamp form or the documented null."""
        if value is None:
            return None
        return _parse_urlhaus_timestamp(value)

    @field_validator("last_online")
    @classmethod
    def _validate_last_online_not_before_date_added(
        cls, value: datetime | None, info: Any
    ) -> datetime | None:
        """Reject a last_online earlier than date_added."""
        date_added = info.data.get("date_added")
        if value is not None and date_added is not None and value < date_added:
            raise ValueError("URLhaus last_online must not precede date_added")
        return value


class UrlhausHostUrlRecord(_UrlhausRecordBase):
    """Strictly validated host-response ``urls[]`` record.

    Host-response URL entries carry only the documented members: ``id``,
    ``url``, ``url_status``, ``date_added``, ``threat``, and ``tags``.
    There is deliberately no ``host``, ``last_online``, or ``payloads``
    member: this endpoint never provides them, and the normalized match
    facts emit those keys as explicit nulls.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    tags: list[str]

    @field_validator("tags", mode="before")
    @classmethod
    def _validate_tags(cls, value: object) -> list[str]:
        """Require the documented bounded-string tag list form."""
        return _validate_required_tags(value)


class UrlhausHostResponse(BaseModel):
    """Strictly validated successful URLhaus host-lookup response body.

    The documented required provenance members ``host`` and ``firstseen``
    are required and strictly validated; ``blacklists`` and
    ``urlhaus_reference`` are unconsumed. The documented string-rendered
    ``url_count`` is parsed strictly, and the ``urls[]`` collection must
    carry 1..100 raw entries (before duplicate collapsing).
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    query_status: str
    host: str = Field(min_length=1, max_length=_HOST_MAX_LENGTH)
    firstseen: datetime
    url_count: int
    urls: list[UrlhausHostUrlRecord] = Field(
        min_length=1, max_length=_MAX_COLLECTION_ENTRIES
    )

    @field_validator("query_status")
    @classmethod
    def _validate_query_status(cls, value: str) -> str:
        """Require the documented ``ok`` success status."""
        if value != "ok":
            raise ValueError("host response query_status must be ok")
        return value

    @field_validator("host", mode="before")
    @classmethod
    def _validate_host(cls, value: object) -> str:
        """Require a bounded, nonblank, unpadded top-level host member."""
        return _validate_required_host(value)

    @field_validator("firstseen", mode="before")
    @classmethod
    def _validate_firstseen(cls, value: object) -> datetime:
        """Require the strict official URLhaus UTC timestamp form."""
        return _parse_urlhaus_timestamp(value)

    @field_validator("url_count", mode="before")
    @classmethod
    def _validate_url_count(cls, value: object) -> int:
        """Require the documented decimal string or integer url_count."""
        if isinstance(value, bool):
            raise ValueError("url_count must be a count")
        if isinstance(value, int):
            count = value
        elif isinstance(value, str) and value.isdigit():
            count = int(value)
        else:
            raise ValueError("url_count must be a count")
        if count < 0:
            raise ValueError("url_count must not be negative")
        return count


@dataclass(frozen=True)
class _LookupContext:
    """Invocation context for one URLhaus lookup normalization pass."""

    investigation_id: UUID
    entity: Entity
    canonical_value: str
    retrieved_at: datetime


class UrlhausProvider(EvidenceProvider):
    """Provider using the URLhaus Community API v1 lookup queries."""

    def __init__(
        self,
        http_client: ProviderHttpClient,
        *,
        auth_key: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the provider with an HTTP client and a resolved key.

        The HTTP client is owned by the caller. ``auth_key`` must be the
        abuse.ch Auth-Key already resolved during composition/bootstrap;
        the provider never reads configuration or the environment and the
        value is used only in the ``Auth-Key`` header, never in URLs,
        bodies, facts, errors, or logs. The UTC wall clock is used only
        for Evidence ``retrieved_at`` timestamps; tests may inject a
        deterministic replacement, otherwise ``datetime.now(UTC)`` is
        used.
        """
        if not auth_key.strip():
            raise ValueError("URLhaus Auth-Key must not be blank")
        self._http = http_client
        self._auth_key = auth_key.strip()
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def id(self) -> str:
        """Return the stable ``urn:ati:source:urlhaus`` identifier."""
        return SourceId.URLHAUS.value

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to URL, domain, and IPv4-address entities.

        IPv6 host lookups are unsupported: the official URLhaus host-query
        documentation covers IPv4 addresses, hostnames, and domain names
        only. IPv6 addresses are therefore rejected before any I/O.
        """
        return entity.type in (
            EntityType.URL,
            EntityType.DOMAIN,
            EntityType.IP_ADDRESS,
        )

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Retrieve URLhaus facts for one supported entity.

        The shared validation helper rejects unsupported entity types and
        uncanonicalizable values before any HTTP I/O or clock evaluation;
        IPv6 entities are rejected here because the verified host-query
        contract does not cover them. A successful lookup emits exactly
        one immutable ``THREAT_INTELLIGENCE`` evidence observation
        carrying every validated matching record; a valid no-result emits
        an empty result and is not a benign assessment; a malformed
        response yields one typed error and no evidence. The provider
        never persists, creates relationships, instantiates discovered
        entities, fetches returned URLs, downloads payloads, or assesses
        maliciousness.
        """
        canonical, rejection = validate_investigation_entity(self, entity)
        if rejection is not None:
            return rejection
        assert canonical is not None
        if entity.type is EntityType.IP_ADDRESS and ":" in canonical:
            return provider_error_result(
                self.id,
                ProviderErrorCode.UNSUPPORTED_INDICATOR,
                "URLhaus host lookup does not document IPv6 hosts",
            )
        return await self._lookup(
            investigation_id=investigation_id,
            entity=entity,
            canonical_value=canonical,
            retrieved_at=normalize_retrieval_timestamp(self._clock),
        )

    async def _lookup(
        self,
        *,
        investigation_id: UUID,
        entity: Entity,
        canonical_value: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        """Query the verified endpoint and normalize one grouped evidence."""
        if entity.type is EntityType.URL:
            endpoint = _URLHAUS_URL_ENDPOINT
            form = {"url": canonical_value}
        else:
            endpoint = _URLHAUS_HOST_ENDPOINT
            form = {"host": canonical_value}

        # The form body carries only the queried indicator; the
        # Auth-Key travels only in its dedicated header and never in
        # the URL or body.
        auth_header = {"Auth-Key": self._auth_key}
        outcome = await self._http.request_json(
            "POST",
            endpoint,
            form_body=form,
            headers=auth_header,
        )

        failure_code = outcome.final_error_code
        if failure_code is not None:
            return provider_error_result(
                self.id,
                failure_code,
                outcome.final_error_message or "URLhaus request failed",
                retry_after_seconds=outcome.retry_after_seconds,
            )

        return self._normalize_lookup_response(
            outcome.response_json,
            _LookupContext(
                investigation_id=investigation_id,
                entity=entity,
                canonical_value=canonical_value,
                retrieved_at=retrieved_at,
            ),
            endpoint,
        )

    def _normalize_lookup_response(
        self,
        response_json: Any,
        context: _LookupContext,
        endpoint: str,
    ) -> ProviderResult:
        """Validate the lookup envelope and normalize one grouped evidence.

        ``ok`` responses must carry the documented record collection in
        which every record is strictly valid and independently matches
        the queried identity; one malformed or unrelated record
        invalidates the whole response. Explicit ``no_results`` statuses
        are valid no-result outcomes. The body-encoded request-error
        statuses (``http_post_expected``, ``invalid_url``,
        ``invalid_host``) map to non-retryable ``INVALID_RESPONSE``
        because they can only result from an ATI request defect. Unknown
        statuses are never success. The return count is intrinsic to the
        exhaustive explicit terminal-outcome mapping.
        """
        # pylint: disable=too-many-return-statements
        if not isinstance(response_json, dict):
            return _malformed_result(self.id, "URLhaus response must be a JSON object")

        query_status = response_json.get("query_status")
        if not isinstance(query_status, str) or not query_status:
            return _malformed_result(
                self.id, "URLhaus response query_status must be a string"
            )

        if query_status == "no_results":
            return ProviderResult(provider=self.id)
        if query_status in ("http_post_expected", "invalid_url", "invalid_host"):
            return _malformed_result(self.id, "URLhaus rejected the request as invalid")
        if query_status != "ok":
            return _malformed_result(self.id, "unknown URLhaus query_status")

        if context.entity.type is EntityType.URL:
            return self._normalize_url_response(response_json, context, endpoint)
        return self._normalize_host_response(response_json, context, endpoint)

    def _normalize_url_response(
        self,
        response_json: dict[str, Any],
        context: _LookupContext,
        endpoint: str,
    ) -> ProviderResult:
        """Validate and normalize an exact-URL ``ok`` response.

        The response carries one record whose ``url`` must canonicalize
        to exactly the queried canonical URL and whose ``host`` member
        must be the canonical identity of the returned URL's own host;
        any mismatch invalidates the response.
        """
        try:
            record = UrlhausUrlRecord.model_validate(response_json)
        except ValueError:
            return _malformed_result(self.id, "invalid URLhaus response record")
        identity = _direct_record_identity(record, context.canonical_value)
        if identity is None:
            return _malformed_result(
                self.id,
                "URLhaus response record does not match the queried indicator",
            )
        canonical_url, canonical_host = identity
        return self._build_evidence(
            [record],
            context,
            endpoint,
            canonical_urls=[canonical_url],
            canonical_hosts=[canonical_host],
        )

    def _normalize_host_response(
        self,
        response_json: dict[str, Any],
        context: _LookupContext,
        endpoint: str,
    ) -> ProviderResult:
        """Validate and normalize a host-lookup ``ok`` response.

        The response must carry the documented top-level ``host`` and
        ``firstseen`` provenance members; the top-level host must
        validate to exactly the queried canonical identity. The
        ``urls[]`` collection must be non-empty (a true miss uses the
        documented ``no_results`` status), and every record must be
        valid and carry the queried canonical host; one unrelated record
        invalidates the whole response because the endpoint promises
        exact host results.
        """
        try:
            response = UrlhausHostResponse.model_validate(response_json)
        except ValueError:
            return _malformed_result(self.id, "invalid URLhaus host response")

        queried_host = _canonical_host_identity(response.host)
        if not _host_envelope_matches(
            queried_host, context.entity.type, context.canonical_value
        ):
            return _malformed_result(
                self.id,
                "URLhaus response record does not match the queried indicator",
            )

        records: list[UrlhausHostUrlRecord] = []
        canonical_urls: list[str] = []
        consumed_by_id: dict[str, tuple[Any, ...]] = {}
        for record in response.urls:
            canonical_url = _host_record_identity(record, context.canonical_value)
            if canonical_url is None:
                return _malformed_result(
                    self.id,
                    "URLhaus response record does not match the queried indicator",
                )
            # Duplicate identity is the consumed normalized content: the
            # canonical URL (never the raw spelling), url_status, normalized
            # date_added, threat, and tags in source order. Ignored upstream
            # members are excluded, so canonical-equivalent URL spellings for
            # the same source ID collapse to one match while meaningful
            # differences conflict; the source ID is the dict key only.
            normalized = (
                canonical_url,
                record.url_status,
                record.date_added,
                record.threat,
                tuple(record.tags),
            )
            first = consumed_by_id.get(record.id)
            if first is not None and first != normalized:
                # Conflicting duplicate source ID: one generic error,
                # no evidence, and no ID, record, body, URL, or key in
                # the message.
                return _malformed_result(
                    self.id,
                    "URLhaus response contains conflicting duplicate records",
                )
            if first is not None:
                # Exact duplicate of a consumed record: the first
                # occurrence stays authoritative for content and position.
                continue
            consumed_by_id[record.id] = normalized
            records.append(record)
            canonical_urls.append(canonical_url)

        return self._build_evidence(
            records,
            context,
            endpoint,
            canonical_urls=canonical_urls,
            queried_host=queried_host,
            host_first_seen=response.firstseen,
            url_count=response.url_count,
        )

    def _build_evidence(
        self,
        records: list[Any],
        context: _LookupContext,
        endpoint: str,
        *,
        canonical_urls: list[str],
        canonical_hosts: list[str] | None = None,
        queried_host: str | None = None,
        host_first_seen: datetime | None = None,
        url_count: int | None = None,
    ) -> ProviderResult:
        """Build the single grouped ``THREAT_INTELLIGENCE`` evidence.

        The optional host-envelope parameters are the documented grouped fact
        members of the host endpoint; the argument count is their accepted
        cost. Defense in depth: a collection that would leave no relevant
        source timestamp is a typed ``INVALID_RESPONSE``, never an escaping
        exception from ``max()``.
        """
        # pylint: disable=too-many-arguments
        subject = EvidenceEntityRef(
            id=context.entity.id,
            type=context.entity.type,
            value=context.canonical_value,
        )
        facts: dict[str, Any] = {
            "matches": [
                _build_match_facts(
                    record,
                    canonical_url=canonical_url,
                    canonical_host=(
                        canonical_hosts[index] if canonical_hosts is not None else None
                    ),
                )
                for index, (record, canonical_url) in enumerate(
                    zip(records, canonical_urls)
                )
            ]
        }
        if url_count is not None:
            facts["url_count"] = url_count
        if queried_host is not None:
            facts["queried_host"] = queried_host
        if host_first_seen is not None:
            facts["first_seen"] = format_urlhaus_fact_timestamp(host_first_seen)
        timestamps = [
            timestamp
            for record in records
            for timestamp in (record.date_added, getattr(record, "last_online", None))
            if timestamp is not None
        ]
        if host_first_seen is not None:
            timestamps.append(host_first_seen)
        if not timestamps:
            return _malformed_result(
                self.id, "URLhaus response carries no source timestamp"
            )
        evidence = Evidence(
            type=EvidenceType.THREAT_INTELLIGENCE,
            investigation_id=context.investigation_id,
            subject=subject,
            source=self.id,
            source_url=endpoint,
            observed_at=max(timestamps),
            retrieved_at=context.retrieved_at,
            facts=facts,
            raw_payload=None,
        )
        return ProviderResult(provider=self.id, evidence=(evidence,))


def _host_envelope_matches(
    queried_host: str | None, entity_type: EntityType, canonical_value: str
) -> bool:
    """Return whether the top-level host matches the queried identity.

    A DOMAIN query requires the strict canonical DNS form of the
    top-level host to equal the queried canonical domain; an IP query
    requires a canonical IPv4 identity equal to the queried canonical
    address. A missing or unparseable top-level host never matches.
    """
    if queried_host is None:
        return False
    if entity_type is EntityType.DOMAIN:
        return queried_host == canonical_value
    try:
        address = ipaddress.ip_address(queried_host)
    except ValueError:
        return False
    return address.version == 4 and queried_host == canonical_value


def _host_record_identity(
    record: UrlhausHostUrlRecord, canonical_value: str
) -> str | None:
    """Return the canonical form of a host-response record URL, or ``None``.

    Every returned URL must pass the complete shared ATI URL identity
    contract (:func:`canonicalize_url`): a matching hostname alone is
    insufficient, and unsupported schemes, userinfo, fragments, malformed
    escapes, invalid ports, whitespace, controls, and malformed hosts never
    match. The canonical URL's host identity must equal the queried canonical
    DOMAIN or IPv4 identity. Pure parsing: the URL is never resolved or
    fetched.
    """
    try:
        canonical_url = canonicalize_url(record.url)
    except ValueError:
        return None
    host = _host_identity_of_url(canonical_url)
    if host is None or host != canonical_value:
        return None
    return canonical_url


def _direct_record_identity(
    record: UrlhausUrlRecord, canonical_value: str
) -> tuple[str, str] | None:
    """Return the canonical URL and host of a direct record, or ``None``.

    The returned source URL must pass the complete shared ATI URL identity
    contract and canonicalize to exactly the queried canonical URL, and the
    record's ``host`` member must be the canonical identity (DOMAIN or IP) of
    the returned canonical URL's own host. Pure parsing: never resolved or
    fetched.
    """
    try:
        canonical_url = canonicalize_url(record.url)
    except ValueError:
        return None
    url_host = _host_identity_of_url(canonical_url)
    record_host = _canonical_host_identity(record.host)
    if url_host is None or record_host is None or url_host != record_host:
        return None
    if canonical_url != canonical_value:
        return None
    return canonical_url, record_host


def _malformed_result(provider_id: str, message: str) -> ProviderResult:
    """Build a standard non-retryable ``INVALID_RESPONSE`` failure result."""
    return provider_error_result(
        provider_id, ProviderErrorCode.INVALID_RESPONSE, message
    )


def format_urlhaus_fact_timestamp(value: datetime) -> str:
    """Format an already validated timezone-aware UTC datetime as ``...Z``.

    Normalized URLhaus fact timestamps use the canonical UTC ISO 8601
    form ending in ``Z``, for example ``2026-08-20T12:00:00Z``.
    """
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_match_facts(
    record: UrlhausUrlRecord | UrlhausHostUrlRecord,
    *,
    canonical_url: str,
    canonical_host: str | None,
) -> dict[str, Any]:
    """Build one normalized match fact object from a validated record.

    Each match contains exactly the approved handoff keys. The ``url`` and
    ``host`` members are the entity-eligible identity inputs a deterministic
    extractor may later canonicalize; both are emitted in canonical ATI form
    (never the original source spelling). Payload metadata is fact-only.
    Timestamps are normalized to UTC ISO 8601 and source order is preserved.
    Host-response records deliberately emit ``host``, ``last_online``, and
    ``payloads`` as explicit nulls: that endpoint never provides them.
    """
    payloads = getattr(record, "payloads", None)
    last_online = getattr(record, "last_online", None)
    return {
        "urlhaus_id": record.id,
        "url": canonical_url,
        "url_status": record.url_status,
        "date_added": format_urlhaus_fact_timestamp(record.date_added),
        "last_online": (
            None if last_online is None else format_urlhaus_fact_timestamp(last_online)
        ),
        "threat": record.threat,
        "host": canonical_host,
        "tags": list(record.tags),
        "payloads": (
            None
            if payloads is None
            else [
                {
                    "first_seen": payload.firstseen,
                    "filename": payload.filename,
                    "file_type": payload.file_type,
                    "response_size": payload.response_size,
                    "response_md5": payload.response_md5,
                    "response_sha256": payload.response_sha256,
                    "signature": payload.signature,
                }
                for payload in payloads
            ]
        ),
    }
