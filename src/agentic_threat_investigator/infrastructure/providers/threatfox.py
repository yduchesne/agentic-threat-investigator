# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ThreatFox provider for IOC-to-malware threat-intelligence evidence.

Queries the official abuse.ch ThreatFox Community API v1 ``search_ioc``
endpoint (``https://threatfox-api.abuse.ch/api/v1/``) with ``Auth-Key``
header authentication, ``exact_match=true``, and strict response
validation, and normalizes validated matching records into immutable
``THREAT_INTELLIGENCE`` evidence. Provider confidence levels, threat
types, timestamps, and references are retained as source facts only: the
provider never assesses maliciousness, never weights assessment
confidence, never persists, never creates relationships, and never
instantiates discovered entities. The normalized ``matches`` facts carry
the validated ThreatFox machine malware identifier and printable name so
a deterministic persistence-boundary extractor can later derive the
canonical ``MALWARE`` entity and the queried IOC ``ASSOCIATED_WITH``
malware relationship. A no-result response is an empty result, never a
benign assessment.
"""

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
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient

_THREATFOX_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"
"""Fixed ThreatFox Community API v1 authority; the JSON body carries the query."""

_THREATFOX_ID_RE = re.compile(r"^[0-9]{1,16}$")
"""Official ThreatFox IOC identifier form: a bounded decimal string."""

_THREATFOX_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$")
"""Official ThreatFox source timestamp form, always UTC."""

_MALWARE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
"""Bounded lowercase machine identifier form of ThreatFox malware labels."""

_IOC_MAX_LENGTH = 2048
_DESCRIPTION_MAX_LENGTH = 512
_PRINTABLE_MAX_LENGTH = 256
_ALIAS_MAX_LENGTH = 512
_URL_MAX_LENGTH = 2048
_TAG_MAX_LENGTH = 64

_SUPPORTED_IOC_TYPES = frozenset({"domain", "ip:port", "url"})


def _parse_threatfox_timestamp(value: object) -> datetime:
    """Parse the strict official ThreatFox source timestamp form into UTC.

    Only the documented ``YYYY-MM-DD HH:MM:SS UTC`` form is accepted:
    booleans, non-strings, ISO-8601 spellings, whitespace-padded strings,
    and unparseable calendar values are rejected. The parsed value is
    timezone-aware UTC.
    """
    if not isinstance(value, str):
        raise ValueError("source timestamp must be a string")
    if not _THREATFOX_TIMESTAMP_RE.fullmatch(value):
        raise ValueError("source timestamp must use the ThreatFox UTC form")
    parsed = datetime.strptime(value[: -len(" UTC")], "%Y-%m-%d %H:%M:%S")
    return parsed.replace(tzinfo=UTC)


def _validate_optional_url(value: object, member: str) -> str | None:
    """Validate an optional source URL member without fetching it.

    A documented null is valid and retained as ``None``. When present the
    value must be a bounded ``http``/``https`` URL with a hostname and no
    embedded whitespace. The URL is never fetched.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{member} must be a string or null")
    if (
        not value
        or len(value) > _URL_MAX_LENGTH
        or any(char.isspace() for char in value)
    ):
        raise ValueError(f"invalid {member} member")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"invalid {member} member")
    return value


@dataclass(frozen=True)
class _SearchContext:
    """Invocation context for one ``search_ioc`` normalization pass."""

    investigation_id: UUID
    entity: Entity
    canonical_value: str
    retrieved_at: datetime


class ThreatFoxRecord(BaseModel):
    """Strictly validated single ThreatFox IOC record.

    Only the approved members are consumed and normalized into evidence
    facts. ``malware_alias`` and ``malware_malpedia`` are validated as
    bounded source metadata but deliberately not retained; ``reporter``,
    ``comment``, ``credits``, and ``malware_samples`` are unconsumed and
    never copied into facts. Unknown members at any level are ignored.
    Scalars are strict: booleans, floats, numeric strings, and objects are
    rejected where a string, integer, list, or null is documented.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    id: str
    ioc: str = Field(min_length=1, max_length=_IOC_MAX_LENGTH)
    threat_type: str = Field(min_length=1, max_length=64)
    threat_type_desc: str = Field(min_length=1, max_length=_DESCRIPTION_MAX_LENGTH)
    ioc_type: str = Field(min_length=1, max_length=32)
    ioc_type_desc: str = Field(min_length=1, max_length=_DESCRIPTION_MAX_LENGTH)
    malware: str
    malware_printable: str | None = Field(
        default=None, min_length=1, max_length=_PRINTABLE_MAX_LENGTH
    )
    malware_alias: str | None = Field(
        default=None, min_length=1, max_length=_ALIAS_MAX_LENGTH
    )
    malware_malpedia: str | None = None
    confidence_level: int = Field(ge=0, le=100)
    first_seen: datetime
    last_seen: datetime | None = None
    reference: str | None = None
    tags: list[str] | None = None

    @field_validator("id", mode="before")
    @classmethod
    def _validate_id(cls, value: object) -> str:
        """Require the official bounded decimal identifier string form."""
        if not isinstance(value, str) or not _THREATFOX_ID_RE.fullmatch(value):
            raise ValueError("ThreatFox record id must be a decimal string")
        return value

    @field_validator("ioc")
    @classmethod
    def _validate_ioc(cls, value: str) -> str:
        """Require a bounded, unpadded source IOC value."""
        if value != value.strip() or not value.strip():
            raise ValueError("ThreatFox record ioc must be a nonblank string")
        return value

    @field_validator("threat_type", "threat_type_desc", "ioc_type", "ioc_type_desc")
    @classmethod
    def _validate_nonblank_bounded(cls, value: str) -> str:
        """Require nonblank bounded source strings without padding."""
        if value != value.strip() or not value.strip():
            raise ValueError("ThreatFox record string member must be nonblank")
        return value

    @field_validator("malware", mode="before")
    @classmethod
    def _validate_malware_identifier(cls, value: object) -> str:
        """Require a strict bounded lowercase machine malware identifier."""
        if not isinstance(value, str) or not _MALWARE_LABEL_RE.fullmatch(value):
            raise ValueError("ThreatFox record malware must be a machine identifier")
        return value

    @field_validator("malware_printable", "malware_alias", mode="before")
    @classmethod
    def _validate_optional_bounded_string(cls, value: object) -> str | None:
        """Require an optional strict nonblank unpadded source string.

        A documented null is valid and retained as ``None``; field-level
        length bounds are enforced by the model fields.
        """
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("optional ThreatFox string member must be a string")
        if not value.strip() or value != value.strip():
            raise ValueError("invalid optional ThreatFox string member")
        return value

    @field_validator("malware_malpedia", mode="before")
    @classmethod
    def _validate_malpedia_url(cls, value: object) -> str | None:
        """Validate the optional Malpedia URL member; it is never fetched."""
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > _URL_MAX_LENGTH:
            raise ValueError("invalid malware_malpedia member")
        return _validate_optional_url(value, "malware_malpedia")

    @field_validator("first_seen", mode="before")
    @classmethod
    def _validate_first_seen(cls, value: object) -> datetime:
        """Require the strict official ThreatFox timestamp form."""
        return _parse_threatfox_timestamp(value)

    @field_validator("last_seen", mode="before")
    @classmethod
    def _validate_last_seen(cls, value: object) -> datetime | None:
        """Require the strict timestamp form or the documented null."""
        if value is None:
            return None
        return _parse_threatfox_timestamp(value)

    @field_validator("reference", mode="before")
    @classmethod
    def _validate_reference(cls, value: object) -> str | None:
        """Validate the optional reference URL member; it is never fetched."""
        return _validate_optional_url(value, "reference")

    @field_validator("tags", mode="before")
    @classmethod
    def _validate_tags(cls, value: object) -> list[str] | None:
        """Require the documented null or bounded-string list form.

        Each tag must be a nonempty string that is unchanged by stripping
        (no outer whitespace) and no longer than the tag bound. Valid
        order and duplicate valid tags are preserved.
        """
        if value is None:
            return None
        if not isinstance(value, list):
            raise ValueError("ThreatFox record tags must be a list or null")
        for tag in value:
            if (
                not isinstance(tag, str)
                or not tag.strip()
                or tag != tag.strip()
                or len(tag) > _TAG_MAX_LENGTH
            ):
                raise ValueError("invalid ThreatFox record tag")
        return value

    @field_validator("confidence_level", mode="before")
    @classmethod
    def _validate_confidence(cls, value: object) -> int:
        """Require a strict integer source confidence level."""
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("ThreatFox confidence_level must be an integer")
        return value

    @field_validator("last_seen")
    @classmethod
    def _validate_last_seen_not_before_first_seen(
        cls, value: datetime | None, info: Any
    ) -> datetime | None:
        """Reject a last_seen earlier than first_seen."""
        first_seen = info.data.get("first_seen")
        if value is not None and first_seen is not None and value < first_seen:
            raise ValueError("ThreatFox last_seen must not precede first_seen")
        return value


def parse_source_ip_ioc(value: str) -> tuple[str, int | None] | None:
    """Parse a source IOC as a bare IP or an unambiguous ``ip:port`` pair.

    Returns the canonical host identity and the port, or ``None`` when the
    value is not a safe unambiguous IP form. A whole value that parses as
    an IPv4 or IPv6 address is a bare IP with no port. An IPv4
    ``address:port`` pair and a bracketed RFC 3986 ``[address]:port`` pair
    are accepted when the port is an integer in ``1..65535``. An
    unbracketed colon-containing value is never split to infer a port: a
    multi-colon value is accepted only when it parses as a whole bare IPv6
    address, so ambiguous unbracketed IPv6-plus-port spellings are
    rejected rather than guessed. The branch and return counts are
    intrinsic to the explicit per-form unambiguity rules below.
    """
    # pylint: disable=too-many-return-statements,too-many-branches
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1:
            return None
        host_text = value[1:closing]
        remainder = value[closing + 1 :]
        if not remainder.startswith(":"):
            return None
        try:
            port = int(remainder[1:])
        except ValueError:
            return None
        if not 1 <= port <= 65535:
            return None
        try:
            address = ipaddress.ip_address(host_text)
        except ValueError:
            return None
        if address.version != 6:
            return None
        return canonicalize_ip_address(host_text), port

    colon_count = value.count(":")
    if colon_count == 0:
        try:
            return canonicalize_ip_address(value), None
        except ValueError:
            return None
    if colon_count == 1:
        host_text, _, port_text = value.partition(":")
        try:
            port = int(port_text)
        except ValueError:
            return None
        if not 1 <= port <= 65535:
            return None
        try:
            return canonicalize_ip_address(host_text), port
        except ValueError:
            return None
    try:
        # Multiple colons: only a whole bare IPv6 address is unambiguous.
        return canonicalize_ip_address(value), None
    except ValueError:
        return None


def record_matches_query(
    record: ThreatFoxRecord, entity_type: EntityType, canonical_value: str
) -> bool:
    """Return whether one validated record independently matches the query.

    The record's ``ioc_type`` must agree with its actual IOC syntax and
    with the queried entity type, and the record's IOC value must
    canonicalize exactly to the queried canonical identity. Unrelated
    records are rejected even though the request asked for an exact
    match.
    """
    if record.ioc_type not in _SUPPORTED_IOC_TYPES:
        return False
    if entity_type is EntityType.DOMAIN:
        return (
            record.ioc_type == "domain"
            and _canonical_record_domain(record.ioc) == canonical_value
        )
    if entity_type is EntityType.IP_ADDRESS:
        if record.ioc_type != "ip:port":
            return False
        parsed = parse_source_ip_ioc(record.ioc)
        return parsed is not None and parsed[0] == canonical_value
    return False


def _canonical_record_domain(value: str) -> str | None:
    """Return the strict canonical form of a returned domain, or ``None``.

    The untrusted returned IOC is validated with ATI's strict provider
    DNS-name validator (not the persistence-oriented canonicalizer), so
    malformed spellings such as multiple terminal dots, underscores,
    invalid IDNA input, and overlong names can never match a valid
    queried domain. Every parser or Unicode error maps to ``None``.
    """
    try:
        return validate_dns_name(value)
    except ValueError, UnicodeError:
        return None


class ThreatFoxProvider(EvidenceProvider):
    """Provider using the ThreatFox Community API v1 ``search_ioc`` query."""

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
            raise ValueError("ThreatFox Auth-Key must not be blank")
        self._http = http_client
        self._auth_key = auth_key.strip()
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def id(self) -> str:
        """Return the stable ``urn:ati:source:threatfox`` identifier."""
        return SourceId.THREATFOX.value

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to domain and IP-address entities.

        URL entities are unsupported: ATI has no approved URL
        canonicalization or exact URL identity contract yet.
        """
        return entity.type in (EntityType.DOMAIN, EntityType.IP_ADDRESS)

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Retrieve ThreatFox IOC facts for one supported entity.

        The shared validation helper rejects unsupported entity types and
        uncanonicalizable values before any HTTP I/O. A successful search
        emits exactly one immutable ``THREAT_INTELLIGENCE`` evidence
        observation carrying every validated matching record; a valid
        no-result emits an empty result and is not a benign assessment; a
        malformed response yields one typed error and no evidence. The
        provider never persists, creates relationships, instantiates
        discovered entities, or assesses maliciousness.
        """
        validation = validate_investigation_entity(self, entity)
        rejection = validation[1]
        if rejection is not None:
            return rejection
        canonical_value = validation[0]
        assert canonical_value is not None
        return await self._search(
            investigation_id=investigation_id,
            entity=entity,
            canonical_value=canonical_value,
            retrieved_at=normalize_retrieval_timestamp(self._clock),
        )

    async def _search(
        self,
        *,
        investigation_id: UUID,
        entity: Entity,
        canonical_value: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        """Query ``search_ioc`` and normalize one grouped evidence observation."""
        outcome = await self._http.request_json(
            "POST",
            _THREATFOX_ENDPOINT,
            # The JSON body carries the search; the Auth-Key travels only in
            # its dedicated header and never in the URL or body.
            json_body={
                "query": "search_ioc",
                "search_term": canonical_value,
                "exact_match": True,
            },
            headers={"Auth-Key": self._auth_key},
        )

        if outcome.final_error_code is not None:
            return provider_error_result(
                self.id,
                outcome.final_error_code,
                outcome.final_error_message or "ThreatFox request failed",
                retry_after_seconds=outcome.retry_after_seconds,
            )

        return self._normalize_search_response(
            outcome.response_json,
            _SearchContext(
                investigation_id=investigation_id,
                entity=entity,
                canonical_value=canonical_value,
                retrieved_at=retrieved_at,
            ),
        )

    def _normalize_search_response(
        self, response_json: Any, context: _SearchContext
    ) -> ProviderResult:
        """Validate the search envelope and normalize one grouped evidence.

        ``ok`` responses must carry a ``data`` array in which every record
        is strictly valid and independently matches the queried identity;
        one malformed or unrelated record invalidates the whole response.
        An explicit ``no_result`` status and an explicit empty ``data``
        array are valid no-result outcomes. The body-encoded
        ``ratelimited`` status maps to the typed rate-limit error. Unknown
        statuses are never success. The return count is intrinsic to the
        exhaustive explicit terminal-outcome mapping.
        """
        # pylint: disable=too-many-return-statements
        if not isinstance(response_json, dict):
            return _malformed_result(
                self.id, "ThreatFox response must be a JSON object"
            )

        query_status = response_json.get("query_status")
        if not isinstance(query_status, str) or not query_status:
            return _malformed_result(
                self.id, "ThreatFox response query_status must be a string"
            )

        if query_status == "no_result":
            return ProviderResult(provider=self.id)
        if query_status == "ratelimited":
            return provider_error_result(
                self.id, ProviderErrorCode.RATE_LIMITED, "rate limited"
            )
        if query_status != "ok":
            return _malformed_result(self.id, "unknown ThreatFox query_status")

        data = response_json.get("data")
        if not isinstance(data, list):
            return _malformed_result(
                self.id, "ThreatFox response data must be an array"
            )
        if not data:
            # An explicitly empty data array is a valid no-result outcome.
            return ProviderResult(provider=self.id)

        records: list[ThreatFoxRecord] = []
        consumed_by_id: dict[str, ThreatFoxRecord] = {}
        for entry in data:
            try:
                record = ThreatFoxRecord.model_validate(entry)
            except ValueError:
                return _malformed_result(self.id, "invalid ThreatFox response record")
            if not record_matches_query(
                record, context.entity.type, context.canonical_value
            ):
                return _malformed_result(
                    self.id,
                    "ThreatFox response record does not match the queried indicator",
                )
            first = consumed_by_id.get(record.id)
            if first is not None:
                if first != record:
                    # Conflicting duplicate source ID: one generic error, no
                    # evidence, and no ID, record, body, IOC, URL, or key in
                    # the message.
                    return _malformed_result(
                        self.id,
                        "ThreatFox response contains conflicting duplicate records",
                    )
                # Exact duplicate of a consumed record: the first occurrence
                # stays authoritative for content and output position.
                continue
            consumed_by_id[record.id] = record
            records.append(record)

        subject = EvidenceEntityRef(
            id=context.entity.id,
            type=context.entity.type,
            value=context.canonical_value,
        )
        evidence = Evidence(
            investigation_id=context.investigation_id,
            type=EvidenceType.THREAT_INTELLIGENCE,
            subject=subject,
            source=self.id,
            source_url=_THREATFOX_ENDPOINT,
            observed_at=max(
                record.last_seen if record.last_seen is not None else record.first_seen
                for record in records
            ),
            retrieved_at=context.retrieved_at,
            facts={"matches": [_build_match_facts(record) for record in records]},
            raw_payload=None,
        )
        return ProviderResult(provider=self.id, evidence=(evidence,))


def _malformed_result(provider_id: str, message: str) -> ProviderResult:
    """Build a standard non-retryable ``INVALID_RESPONSE`` failure result."""
    return provider_error_result(
        provider_id, ProviderErrorCode.INVALID_RESPONSE, message
    )


def format_threatfox_fact_timestamp(value: datetime) -> str:
    """Format an already validated timezone-aware UTC datetime as ``...Z``.

    Normalized ThreatFox fact timestamps use the canonical UTC ISO 8601
    form ending in ``Z``, for example ``2026-08-20T12:00:00Z``.
    """
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_match_facts(record: ThreatFoxRecord) -> dict[str, Any]:
    """Build one normalized match fact object from a validated record.

    Each match contains exactly the approved handoff keys. The malware
    machine identifier is retained verbatim as the canonical identity
    input for later deterministic entity discovery; the printable name is
    display metadata only. Timestamps are normalized to UTC ISO 8601,
    source order is preserved, and no derived risk labels, verdicts, or
    confidence weightings are ever synthesized.
    """
    return {
        "threatfox_id": record.id,
        "ioc": record.ioc,
        "ioc_type": record.ioc_type,
        "threat_type": record.threat_type,
        "threat_type_description": record.threat_type_desc,
        "malware": record.malware,
        "malware_printable": record.malware_printable,
        "confidence_level": record.confidence_level,
        "first_seen": format_threatfox_fact_timestamp(record.first_seen),
        "last_seen": (
            None
            if record.last_seen is None
            else format_threatfox_fact_timestamp(record.last_seen)
        ),
        "reference": record.reference,
        "tags": None if record.tags is None else list(record.tags),
    }
