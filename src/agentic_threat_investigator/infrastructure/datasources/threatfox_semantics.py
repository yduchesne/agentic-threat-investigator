# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ThreatFox semantic-format parsing (PR 27C).

Interprets a decoded ThreatFox Community API ``search_ioc`` response into
validated source-native :class:`ThreatFoxRecord` objects. This module owns
the ThreatFox semantic contract — strict timestamps, URL validation, IOC
parsing/matching, response-envelope/query-status validation, duplicate
source-ID rules, and unrelated-record rejection — and nothing else. It
constructs no ATI Evidence, performs no network/DB/persistence I/O, and
logs no payloads. The legacy ``ThreatFoxProvider`` reuses this parser and
maps its outcome onto the transitional Evidence path.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    DatasourceStageError,
)
from agentic_threat_investigator.domain.entities import (
    EntityType,
    canonicalize_ip_address,
    validate_dns_name,
)

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


def parse_threatfox_timestamp(value: object) -> datetime:
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


def validate_threatfox_reference_url(value: object, member: str) -> str | None:
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


class ThreatFoxRecord(BaseModel):
    """Strictly validated single ThreatFox IOC record.

    Only the approved members are consumed and normalized into source facts.
    ``malware_alias`` and ``malware_malpedia`` are validated as bounded
    source metadata but deliberately not retained; ``reporter``,
    ``comment``, ``credits``, and ``malware_samples`` are unconsumed and
    never copied. Unknown members at any level are ignored. Scalars are
    strict: booleans, floats, numeric strings, and objects are rejected
    where a string, integer, list, or null is documented.
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
        return validate_threatfox_reference_url(value, "malware_malpedia")

    @field_validator("first_seen", mode="before")
    @classmethod
    def _validate_first_seen(cls, value: object) -> datetime:
        """Require the strict official ThreatFox timestamp form."""
        return parse_threatfox_timestamp(value)

    @field_validator("last_seen", mode="before")
    @classmethod
    def _validate_last_seen(cls, value: object) -> datetime | None:
        """Require the strict timestamp form or the documented null."""
        if value is None:
            return None
        return parse_threatfox_timestamp(value)

    @field_validator("reference", mode="before")
    @classmethod
    def _validate_reference(cls, value: object) -> str | None:
        """Validate the optional reference URL member; it is never fetched."""
        return validate_threatfox_reference_url(value, "reference")

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


def canonical_record_domain(value: str) -> str | None:
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
            and canonical_record_domain(record.ioc) == canonical_value
        )
    if entity_type is EntityType.IP_ADDRESS:
        if record.ioc_type != "ip:port":
            return False
        parsed = parse_source_ip_ioc(record.ioc)
        return parsed is not None and parsed[0] == canonical_value
    return False


@dataclass(frozen=True)
class ThreatFoxSemanticResult:
    """One parsed ThreatFox semantic outcome.

    Invariant: success means ``error is None`` with ``records`` possibly
    empty (``no_result`` and an empty ``data`` array are successful empty
    semantics, never benign evidence); failure means ``error`` is set and
    ``records`` is empty.
    """

    records: tuple[ThreatFoxRecord, ...] = ()
    error: DatasourceStageError | None = None

    def __post_init__(self) -> None:
        """Enforce the success/failure invariant of the parsed outcome."""
        if self.error is not None and self.records:
            raise ValueError("a failed ThreatFox parse cannot carry records")


def _semantic_validation_error() -> DatasourceStageError:
    """Build the standard non-retryable semantic-validation stage error."""
    return DatasourceStageError(
        stage=DatasourceStage.SEMANTIC_VALIDATION,
        code="semantic_validation_failed",
        retryable=False,
    )


def parse_threatfox_response(
    decoded: object,
    *,
    entity_type: EntityType,
    canonical_value: str,
) -> ThreatFoxSemanticResult:
    """Parse a decoded ThreatFox ``search_ioc`` response into typed records.

    The decoded value is validated fail-closed: a JSON object is required
    with a valid ``query_status``; ``no_result`` and an empty ``data``
    array are empty successes; ``ok`` requires an array ``data`` in which
    every record validates through the strict source model and
    independently matches the queried identity; an identical duplicate
    source ID is retained once (first occurrence), a conflicting duplicate
    ID, malformed record, or unrelated record fails the whole response.
    Source order of first unique records is retained. The body-encoded
    ``ratelimited`` status is an operational acquisition failure, not a
    semantic object. No Evidence, network I/O, or persistence is involved.
    """
    if not isinstance(decoded, dict):
        return ThreatFoxSemanticResult(error=_semantic_validation_error())

    query_status = decoded.get("query_status")
    if not isinstance(query_status, str) or not query_status:
        return ThreatFoxSemanticResult(error=_semantic_validation_error())

    if query_status == "no_result":
        return ThreatFoxSemanticResult()
    if query_status == "ratelimited":
        return ThreatFoxSemanticResult(
            error=DatasourceStageError(
                stage=DatasourceStage.ACQUISITION,
                code="rate_limited",
                retryable=True,
            )
        )
    if query_status != "ok":
        return ThreatFoxSemanticResult(error=_semantic_validation_error())

    data = decoded.get("data")
    if not isinstance(data, list):
        return ThreatFoxSemanticResult(error=_semantic_validation_error())
    if not data:
        # An explicitly empty data array is a valid no-result outcome.
        return ThreatFoxSemanticResult()

    records: list[ThreatFoxRecord] = []
    consumed_by_id: dict[str, ThreatFoxRecord] = {}
    for entry in data:
        try:
            record = ThreatFoxRecord.model_validate(entry)
        except ValueError:
            return ThreatFoxSemanticResult(error=_semantic_validation_error())
        if not record_matches_query(record, entity_type, canonical_value):
            return ThreatFoxSemanticResult(error=_semantic_validation_error())
        first = consumed_by_id.get(record.id)
        if first is not None:
            if first != record:
                # Conflicting duplicate source ID: the whole response fails.
                return ThreatFoxSemanticResult(error=_semantic_validation_error())
            # Exact duplicate of a consumed record: the first occurrence
            # stays authoritative for content and output position.
            continue
        consumed_by_id[record.id] = record
        records.append(record)
    return ThreatFoxSemanticResult(records=tuple(records))
