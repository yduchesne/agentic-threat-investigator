# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""RDAP provider using IANA bootstrap discovery and authoritative RIR services.

Supports domain, IP network, and ASN lookups through standard RDAP paths.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, TypeVar
from urllib.parse import quote
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

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
from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    validate_entity_url_path,
)
from agentic_threat_investigator.infrastructure.providers.rdap_bootstrap import (
    BootstrapOutcome,
    BootstrapRegistry,
    BootstrapService,
    RdapBootstrapCache,
)

_RDAP_ACCEPT_HEADER = "application/rdap+json, application/json"

_ASN_UPPER_BOUND = 4294967295
"""Largest legal 32-bit autonomous system number (ATI canonical ASN domain)."""

CommonT = TypeVar("CommonT", bound="RdapCommonFields")
"""A concrete strict RDAP response model type."""

__all__ = [
    "BootstrapOutcome",
    "BootstrapRegistry",
    "BootstrapService",
    "RdapBootstrapCache",
    "RdapProvider",
]

# -- RDAP response strict models ------------------------------------------

_BoundedStr = Annotated[str, Field(max_length=2048)]
_MAX_DISPLAY_NAME_LENGTH = 256
_MAX_HANDLE_LENGTH = 256
_MAX_STATUS_LENGTH = 64

_StatusStr = Annotated[str, Field(max_length=_MAX_STATUS_LENGTH)]


class RdapEvent(BaseModel):
    """A strictly validated RDAP event entry.

    Event fields must be strings when present; semantic problems such as a
    blank action, an unparseable date, or a blank actor are omitted at
    fact-building time following the documented optional-entry policy.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    eventAction: _BoundedStr = ""
    eventDate: _BoundedStr = ""
    eventActor: _BoundedStr | None = None


class RdapLink(BaseModel):
    """A strictly validated RFC 9083 link object."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    href: _BoundedStr = Field(min_length=1)
    rel: _BoundedStr | None = None
    type: _BoundedStr | None = None
    value: _BoundedStr | None = None
    title: _BoundedStr | None = None


class RdapNoticeRemark(BaseModel):
    """A strictly validated RDAP notice or remark object."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    title: _BoundedStr | None = None
    description: list[_BoundedStr] | None = None
    links: list[RdapLink] = Field(default_factory=list)


class RdapEntity(BaseModel):
    """A strictly validated RDAP related-entity reference.

    The vCard container is strictly validated; malformed individual vCard
    properties are omitted at fact-building time per the documented policy.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    handle: _BoundedStr = ""
    roles: list[_BoundedStr] = Field(default_factory=list)
    vcardArray: list[Any] | None = None

    @field_validator("vcardArray")
    @classmethod
    def _validate_vcard_container(cls, value: list[Any] | None) -> list[Any] | None:
        """Reject wrong vCard container shapes (wrong types are schema errors).

        The accepted jCard contract is exactly ``["vcard", [property, ...]]``:
        two top-level elements, the literal ``"vcard"`` tag first, and a list
        of vCard properties second. The complete container shape is validated
        before any indexing so a short container becomes a typed
        ``INVALID_RESPONSE`` instead of an uncaught ``IndexError``. Individual
        malformed properties remain subject to the documented omission policy.
        """
        if value is None:
            return None
        if len(value) != 2 or value[0] != "vcard" or not isinstance(value[1], list):
            raise ValueError("malformed RDAP vCard container")
        return value


class RdapNameserver(BaseModel):
    """A strictly validated RDAP nameserver object with canonical DNS names.

    RFC 9083 describes both ``ldhName`` and ``unicodeName`` as optional
    registration-data members, so either may be omitted by a real registry.
    Each supplied name is canonicalized through the strict DNS-name helper;
    wrong member types and syntactically invalid supplied names remain
    schema errors. When both names are supplied they must canonicalize to
    the same DNS identity.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    ldhName: str | None = Field(default=None, min_length=1, max_length=253)
    unicodeName: str | None = Field(default=None, max_length=253)

    @field_validator("ldhName", "unicodeName")
    @classmethod
    def _canonical_name(cls, value: str | None) -> str | None:
        """Canonicalize and strictly validate a supplied nameserver name."""
        return None if value is None else validate_dns_name(value)

    @model_validator(mode="after")
    def _validate_name_identity(self) -> RdapNameserver:
        """Reject contradictory LDH and Unicode forms of the same nameserver."""
        if (
            self.ldhName is not None
            and self.unicodeName is not None
            and self.ldhName != self.unicodeName
        ):
            raise ValueError("RDAP nameserver LDH and Unicode names disagree")
        return self

    @property
    def normalized_name(self) -> str | None:
        """The canonical DNS name for facts, or None when neither name is present.

        Precedence is deterministic: the canonical ``ldhName`` when present,
        otherwise the canonical IDNA form derived from ``unicodeName``.
        """
        if self.ldhName is not None:
            return self.ldhName
        return self.unicodeName


class RdapSecureDns(BaseModel):
    """A strictly validated RDAP secureDNS object."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    zoneSigned: bool | None = None
    delegationSigned: bool | None = None
    maxSigLife: int | None = Field(default=None, ge=0)


class RdapCidr0Entry(BaseModel):
    """A strictly validated RIR CIDR0 entry for one address family."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    v4prefix: str | None = Field(default=None, min_length=1, max_length=45)
    v6prefix: str | None = Field(default=None, min_length=1, max_length=45)
    length: int

    _network: ipaddress.IPv4Network | ipaddress.IPv6Network = PrivateAttr()

    @model_validator(mode="after")
    def _validate_entry(self) -> RdapCidr0Entry:
        """Enforce single-family discriminator, legal prefix, and parseability."""
        if (self.v4prefix is None) == (self.v6prefix is None):
            raise ValueError("CIDR0 entry requires exactly one family prefix")
        prefix = self.v4prefix if self.v4prefix is not None else self.v6prefix
        try:
            # Strict parsing: a host-bit-set prefix asserts a different
            # network than it renders and must not be silently masked.
            network = ipaddress.ip_network(f"{prefix}/{self.length}", strict=True)
        except ValueError as exc:
            raise ValueError("invalid RDAP CIDR0 prefix or length") from exc
        expected_version = 4 if self.v4prefix is not None else 6
        if network.version != expected_version:
            raise ValueError("CIDR0 prefix does not match its family discriminator")
        self._network = network
        return self

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """The validated canonical network for this entry."""
        return self._network


class RdapCommonFields(BaseModel):
    """Strict fields common to all RDAP object response types.

    Unknown provider fields are tolerated; every documented present field is
    type-checked and length-bounded so malformed nested data can never become
    evidence. Status entries are normalized at validation time to the single
    documented stable form: trimmed, lowercase, blank entries omitted, and
    duplicates removed while preserving first-seen source order.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    objectClassName: str = Field(min_length=1, max_length=64)
    handle: str = Field(default="", max_length=_MAX_HANDLE_LENGTH)
    status: list[_StatusStr] = Field(default_factory=list)
    events: list[RdapEvent] = Field(default_factory=list)
    entities: list[RdapEntity] = Field(default_factory=list)
    links: list[RdapLink] = Field(default_factory=list)
    notices: list[RdapNoticeRemark] = Field(default_factory=list)
    remarks: list[RdapNoticeRemark] = Field(default_factory=list)

    @field_validator("handle")
    @classmethod
    def _trim_handle(cls, value: str) -> str:
        """Trim surrounding whitespace; a whitespace-only handle becomes blank."""
        return value.strip()

    @field_validator("status")
    @classmethod
    def _normalize_status_entries(cls, value: list[str]) -> list[str]:
        """Normalize status entries into the stable canonical vocabulary form.

        Entries are trimmed and lowercased, blank entries are omitted, and
        duplicates are removed while preserving first-seen source order.
        Wrong entry types and overlong entries are schema errors caught by
        strict list validation before this validator runs.
        """
        normalized: list[str] = []
        seen: set[str] = set()
        for entry in value:
            candidate = entry.strip().lower()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            normalized.append(candidate)
        return normalized


class RdapDomainResponse(RdapCommonFields):
    """Strict RDAP domain object response with canonical identity members.

    ``ldhName`` is canonicalized through the strict DNS-name helper. A
    supplied ``unicodeName`` is trimmed and must be a syntactically valid
    IDNA DNS name; its trimmed provider Unicode form is preserved for the
    documented ``unicode_name`` fact while the canonical ASCII identity is
    kept for comparison. When both names are supplied they must
    canonicalize to the same DNS identity.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    ldhName: str | None = Field(default=None, min_length=1, max_length=253)
    unicodeName: str | None = Field(default=None, min_length=1, max_length=253)
    nameservers: list[RdapNameserver] = Field(default_factory=list)
    secureDNS: RdapSecureDns | None = None

    _canonical_unicode_name: str | None = PrivateAttr(default=None)

    @field_validator("ldhName")
    @classmethod
    def _canonical_ldh_name(cls, value: str | None) -> str | None:
        """Canonicalize and strictly validate the queried LDH name."""
        return None if value is None else validate_dns_name(value)

    @field_validator("unicodeName")
    @classmethod
    def _trim_unicode_name(cls, value: str | None) -> str | None:
        """Trim the supplied Unicode name; blank values are schema errors."""
        return None if value is None else value.strip()

    @model_validator(mode="after")
    def _validate_name_identity(self) -> RdapDomainResponse:
        """Validate the Unicode name and cross-check both identity members.

        A supplied ``unicodeName`` must be a syntactically valid IDNA DNS
        name (malformed Unicode syntax is a schema error); when both names
        are supplied they must canonicalize to the same DNS identity.
        """
        if self.unicodeName is not None:
            self._canonical_unicode_name = validate_dns_name(self.unicodeName)
            if (
                self.ldhName is not None
                and self.ldhName != self._canonical_unicode_name
            ):
                raise ValueError("RDAP domain LDH and Unicode names disagree")
        return self

    @property
    def canonical_identities(self) -> tuple[str, ...]:
        """Canonical ASCII identities supplied by the response name members.

        Contains the canonical ``ldhName`` when present and the canonical
        IDNA form derived from ``unicodeName`` when present, in that order.
        """
        identities: list[str] = []
        if self.ldhName is not None:
            identities.append(self.ldhName)
        if self._canonical_unicode_name is not None:
            identities.append(self._canonical_unicode_name)
        return tuple(identities)


class RdapNetworkResponse(RdapCommonFields):
    """Strict RDAP IP network response with canonical boundary addresses."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    startAddress: str = Field(min_length=1, max_length=45)
    endAddress: str = Field(min_length=1, max_length=45)
    ipVersion: str = Field(min_length=1, max_length=8)
    name: str | None = Field(default=None, min_length=1, max_length=256)
    type: str | None = Field(default=None, min_length=1, max_length=64)
    country: str | None = Field(default=None, min_length=1, max_length=128)
    parentHandle: str | None = Field(default=None, min_length=1, max_length=256)
    cidr0_cidrs: list[RdapCidr0Entry] = Field(default_factory=list)

    @field_validator("startAddress", "endAddress")
    @classmethod
    def _canonical_ip(cls, value: str) -> str:
        """Canonicalize boundary addresses; malformed addresses are schema errors."""
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("invalid RDAP network boundary address") from exc


class RdapAutnumResponse(RdapCommonFields):
    """Strict RDAP autonomous-number response with a required inclusive range."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    startAutnum: int = Field(ge=1, le=_ASN_UPPER_BOUND)
    endAutnum: int = Field(ge=1, le=_ASN_UPPER_BOUND)
    name: str | None = Field(default=None, min_length=1, max_length=256)
    type: str | None = Field(default=None, min_length=1, max_length=64)
    country: str | None = Field(default=None, min_length=1, max_length=128)


ResponseModel = type[RdapCommonFields]
"""The strict response model family accepted for authoritative validation."""


# -- Normalization helpers -------------------------------------------------

_MAX_EVENT_TEXT_LENGTH = 64

_RFC3339_DATE_TIME_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})"
)
"""RFC 3339 date-time grammar accepted for RDAP event dates.

Runs before ``datetime.fromisoformat`` to reject non-RFC spellings that
parser accepts (space separator, colon-less offsets, naive forms).
"""


def _parse_utc_event_date(date_str: str) -> datetime | None:
    """Parse an RFC 3339 RDAP event date into UTC, rejecting other spellings.

    Invalid values return ``None`` so callers omit the entry per the
    documented optional-entry policy.
    """
    if _RFC3339_DATE_TIME_RE.fullmatch(date_str) is None:
        return None
    normalized = date_str.replace("t", "T").replace("z", "Z")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError, TypeError:
        return None
    if dt.tzinfo is None or dt.utcoffset() is None:
        return None
    return dt.astimezone(UTC)


def _find_latest_last_changed(parsed: RdapCommonFields) -> datetime | None:
    """Find the newest ``last changed`` event timestamp, normalized to UTC."""
    latest: datetime | None = None
    for event in parsed.events:
        if event.eventAction.strip().lower() != "last changed":
            continue
        if not event.eventDate.strip():
            continue
        dt_utc = _parse_utc_event_date(event.eventDate)
        if dt_utc is None:
            continue
        if latest is None or dt_utc > latest:
            latest = dt_utc
    return latest


def _extract_vcard_display_name(vcard_array: list[Any] | None) -> str | None:
    """Extract a bounded display name (fn) without link or entity traversal.

    Malformed individual vCard properties are omitted following the
    documented optional-entry policy; the container itself is validated by
    the response model.
    """
    if not vcard_array or not isinstance(vcard_array[1], list):
        return None
    for prop in vcard_array[1]:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        if prop[0] != "fn":
            continue
        fn_value = prop[3]
        if not isinstance(fn_value, str):
            continue
        display_name = fn_value.strip()
        if not display_name or len(display_name) > _MAX_DISPLAY_NAME_LENGTH:
            continue
        return display_name
    return None


def _normalize_event_actor(actor: str | None) -> str | None:
    """Normalize an event actor into a bounded safe label, or None.

    The actor is trimmed of surrounding whitespace and omitted when blank or
    over the bounded event-text length. No organization, relationship, or
    ownership meaning is inferred from the value; it is recorded verbatim as
    provider-attributed context only.
    """
    if actor is None:
        return None
    trimmed = actor.strip()
    if not trimmed or len(trimmed) > _MAX_EVENT_TEXT_LENGTH:
        return None
    return trimmed


def _build_events_facts(events: list[RdapEvent]) -> list[dict[str, str]]:
    """Normalize events, omitting entries lacking action and valid UTC date.

    An event fact is emitted only when it has both a nonblank bounded action
    and a valid timezone-aware timestamp normalized to UTC. A malformed,
    naive, blank, or missing date never produces an action-only event.
    """
    result: list[dict[str, str]] = []
    for ev in events:
        action = ev.eventAction.strip()
        if not action or len(action) > _MAX_EVENT_TEXT_LENGTH:
            continue
        date_str = ev.eventDate.strip()
        if not date_str or len(date_str) > _MAX_EVENT_TEXT_LENGTH:
            continue
        dt_utc = _parse_utc_event_date(date_str)
        if dt_utc is None:
            continue
        entry: dict[str, str] = {"action": action, "date": dt_utc.isoformat()}
        actor = _normalize_event_actor(ev.eventActor)
        if actor is not None:
            entry["actor"] = actor
        result.append(entry)
    return result


def _build_entities_facts(entities: list[RdapEntity]) -> list[dict[str, Any]]:
    """Compact related entities with bounded display names.

    Handles are trimmed; a related-entity reference without a nonblank
    handle is unusable and omitted individually without failing the
    otherwise valid lookup. Source order is preserved and no relationships
    are inferred from the entries.
    """
    result: list[dict[str, Any]] = []
    for ent in entities:
        handle = ent.handle.strip()
        if not handle:
            continue
        item: dict[str, Any] = {"handle": handle, "roles": ent.roles}
        display_name = _extract_vcard_display_name(ent.vcardArray)
        if display_name:
            item["display_name"] = display_name
        result.append(item)
    return result


def _build_common_facts(parsed: RdapCommonFields) -> dict[str, Any]:
    """Build shared facts across domain, network, and autnum objects.

    ``object_class_name`` is the canonical lowercase form already validated
    against the expected object class; statuses are consumed in their
    model-normalized stable form. The handle is trimmed at model validation,
    so a whitespace-only handle is omitted here and in the provenance ID.
    """
    facts: dict[str, Any] = {
        "object_class_name": parsed.objectClassName.strip().lower(),
    }
    if parsed.handle:
        facts["handle"] = parsed.handle
    if parsed.status:
        facts["status"] = parsed.status

    events = _build_events_facts(parsed.events)
    if events:
        facts["events"] = events

    entities = _build_entities_facts(parsed.entities)
    if entities:
        facts["entities"] = entities

    return facts


def _build_domain_facts(parsed: RdapDomainResponse) -> dict[str, Any]:
    """Build domain-specific facts from canonical validated model data."""
    facts = _build_common_facts(parsed)
    if parsed.ldhName is not None:
        facts["ldh_name"] = parsed.ldhName
    if parsed.unicodeName is not None:
        # The trimmed provider Unicode form; its canonical ASCII identity was
        # already validated to match the queried domain.
        facts["unicode_name"] = parsed.unicodeName
    if parsed.secureDNS is not None:
        facts["secure_dns"] = {
            key: value
            for key, value in (
                ("zone_signed", parsed.secureDNS.zoneSigned),
                ("delegation_signed", parsed.secureDNS.delegationSigned),
                ("max_sig_life", parsed.secureDNS.maxSigLife),
            )
            if value is not None
        }
    if parsed.nameservers:
        names = [
            name
            for ns in parsed.nameservers
            if (name := ns.normalized_name) is not None
        ]
        if names:
            facts["nameservers"] = names
    return facts


def _build_network_facts(parsed: RdapNetworkResponse) -> dict[str, Any]:
    """Build IP network-specific facts from canonical validated model data."""
    facts = _build_common_facts(parsed)
    facts["start_address"] = parsed.startAddress
    facts["end_address"] = parsed.endAddress
    facts["ip_version"] = parsed.ipVersion
    if parsed.name is not None:
        facts["name"] = parsed.name
    if parsed.type is not None:
        facts["type"] = parsed.type
    if parsed.country is not None:
        facts["country"] = parsed.country
    if parsed.parentHandle is not None:
        facts["parent_handle"] = parsed.parentHandle
    if parsed.cidr0_cidrs:
        facts["cidr0_cidrs"] = [
            {"prefix": str(entry.network.network_address), "length": entry.length}
            for entry in parsed.cidr0_cidrs
        ]
    return facts


def _build_autnum_facts(parsed: RdapAutnumResponse) -> dict[str, Any]:
    """Build autnum-specific facts from canonical validated model data."""
    facts = _build_common_facts(parsed)
    facts["start_autnum"] = parsed.startAutnum
    facts["end_autnum"] = parsed.endAutnum
    if parsed.name is not None:
        facts["name"] = parsed.name
    if parsed.type is not None:
        facts["type"] = parsed.type
    if parsed.country is not None:
        facts["country"] = parsed.country
    return facts


def _derive_source_record_id(
    parsed: RdapCommonFields,
    canonical_value: str,
) -> str:
    """Derive a stable source_record_id from handle or normalized identity.

    The handle is already trimmed by the response model, so a whitespace-only
    handle falls through to the documented normalized identity fallback.
    """
    if parsed.handle:
        return parsed.handle.strip()
    if isinstance(parsed, RdapNetworkResponse):
        return f"{parsed.startAddress}-{parsed.endAddress}"
    if isinstance(parsed, RdapAutnumResponse):
        return f"AS{parsed.startAutnum}-{parsed.endAutnum}"
    return canonical_value


def _validate_domain_object(parsed: RdapDomainResponse, canonical_value: str) -> None:
    """Validate domain identity consistency; model data is already canonical.

    Every supplied identity member (``ldhName`` and ``unicodeName``) must
    canonicalize to the queried canonical domain; a malformed or
    contradictory member never reaches evidence.
    """
    if any(identity != canonical_value for identity in parsed.canonical_identities):
        raise ValueError("RDAP domain identity does not match query")


def _validate_network_object(parsed: RdapNetworkResponse, canonical_value: str) -> None:
    """Validate network boundaries, family, target containment, and CIDR0."""
    start = ipaddress.ip_address(parsed.startAddress)
    end = ipaddress.ip_address(parsed.endAddress)
    target = ipaddress.ip_address(canonical_value)
    if start.version != end.version or target.version != start.version:
        raise ValueError("inconsistent RDAP network address family")
    if int(start) > int(end) or not int(start) <= int(target) <= int(end):
        raise ValueError("RDAP network range is inconsistent")
    expected_version = "v6" if start.version == 6 else "v4"
    if parsed.ipVersion.lower() != expected_version:
        raise ValueError("inconsistent RDAP network IP version")
    for entry in parsed.cidr0_cidrs:
        if entry.network.version != start.version:
            raise ValueError("CIDR0 entry does not match the network family")
        if not (
            int(start) <= int(entry.network.network_address)
            and int(entry.network.broadcast_address) <= int(end)
        ):
            raise ValueError("CIDR0 entry is inconsistent with the network range")


def _validate_autnum_object(parsed: RdapAutnumResponse, canonical_value: str) -> None:
    """Validate ASN range ordering and queried-ASN containment.

    Endpoint values are already constrained by the strict response model to
    the legal 32-bit ASN domain (``1..4294967295``), the same bounds ATI
    canonical ASN values and IANA bootstrap ranges must satisfy.
    """
    target_asn = int(canonical_value[2:])
    if (
        parsed.startAutnum > parsed.endAutnum
        or not parsed.startAutnum <= target_asn <= parsed.endAutnum
    ):
        raise ValueError("RDAP ASN range is inconsistent")


def _response_model_for(expected_object_class: str) -> ResponseModel:
    """Return the strict response model for the requested RDAP object class."""
    if expected_object_class == "domain":
        return RdapDomainResponse
    if expected_object_class == "ip network":
        return RdapNetworkResponse
    return RdapAutnumResponse


def _validate_rdap_object(
    parsed: RdapCommonFields,
    expected_object_class: str,
    canonical_value: str,
) -> None:
    """Validate object identity and range consistency before fact building."""
    if parsed.objectClassName.strip().lower() != expected_object_class:
        raise ValueError("unexpected RDAP object class")
    if isinstance(parsed, RdapDomainResponse):
        _validate_domain_object(parsed, canonical_value)
    elif isinstance(parsed, RdapNetworkResponse):
        _validate_network_object(parsed, canonical_value)
    elif isinstance(parsed, RdapAutnumResponse):
        _validate_autnum_object(parsed, canonical_value)
    else:
        raise ValueError("unsupported RDAP response model")


# -- Provider implementation ----------------------------------------------


class RdapProvider(EvidenceProvider):
    """RDAP provider using IANA bootstrap discovery."""

    def __init__(
        self,
        http_client: ProviderHttpClient,
        *,
        cache_seconds: int = 3600,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        """Initialize the provider with an injected HTTP client and clocks.

        The HTTP client and bootstrap cache are owned by the caller-supplied
        client; the UTC wall clock (used only for Evidence ``retrieved_at``
        timestamps) and the monotonic clock (used only for bootstrap cache
        expiration) default to production implementations when omitted, and
        tests may inject deterministic replacements for either.
        """
        self._http = http_client
        self._clock = clock or (lambda: datetime.now(UTC))
        self._bootstrap = RdapBootstrapCache(
            http_client,
            cache_seconds=cache_seconds,
            clock=monotonic_clock,
        )

    @property
    def id(self) -> str:
        """Return the stable ``urn:ati:source:rdap`` provider identifier."""
        return SourceId.RDAP.value

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to domain, IP address, and ASN entities."""
        return entity.type in (
            EntityType.DOMAIN,
            EntityType.IP_ADDRESS,
            EntityType.ASN,
        )

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Retrieve registration evidence via RDAP for a supported entity.

        Discovers the authoritative RDAP service from the IANA bootstrap
        registry for the entity's DNS, IPv4/IPv6, or ASN category, then
        queries the authoritative service and normalizes the strict-validated
        response into immutable Evidence. No persistence occurs here.
        """
        canonical_value, error_result = validate_investigation_entity(self, entity)
        if error_result is not None:
            return error_result
        assert canonical_value is not None

        timestamp = normalize_retrieval_timestamp(self._clock)
        if entity.type == EntityType.DOMAIN:
            return await self._lookup_domain(
                investigation_id, entity, canonical_value, timestamp
            )
        if entity.type == EntityType.IP_ADDRESS:
            return await self._lookup_ip(
                investigation_id, entity, canonical_value, timestamp
            )
        return await self._lookup_asn(
            investigation_id, entity, canonical_value, timestamp
        )

    async def _lookup_domain(
        self,
        investigation_id: UUID,
        entity: Entity,
        canonical_domain: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        # Domain values are strictly validated against the original value by
        # the shared validation helper before any lossy canonicalization, so
        # no provider-local revalidation is required here.
        # Bootstrap selection matches the canonical final TLD label. A
        # canonical single-label DNS name such as ``com`` already consists of
        # its final TLD label and is looked up as the top-level object itself.
        tld = canonical_domain.rsplit(".", 1)[-1]

        bootstrap = await self._bootstrap.find_authoritative_base("dns", tld)
        if bootstrap.error is not None or bootstrap.base_url is None:
            err = bootstrap.error or ProviderError(
                provider=self.id,
                code=ProviderErrorCode.NOT_FOUND,
                message=f"no authoritative RDAP service found for {tld}",
                retryable=False,
            )
            return ProviderResult(provider=self.id, errors=(err,))

        rdap_url = validate_entity_url_path(
            bootstrap.base_url, f"domain/{quote(canonical_domain, safe='')}"
        )
        return await self._query_authoritative(
            investigation_id,
            entity,
            canonical_domain,
            retrieved_at,
            EvidenceType.REGISTRATION,
            rdap_url,
            "domain",
            RdapDomainResponse,
            _build_domain_facts,
        )

    async def _lookup_ip(
        self,
        investigation_id: UUID,
        entity: Entity,
        canonical_ip: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        try:
            ip_obj = ipaddress.ip_address(canonical_ip)
        except ValueError:
            return unsupported_indicator_result(self.id, "invalid entity value")

        category = "ipv6" if ip_obj.version == 6 else "ipv4"
        bootstrap = await self._bootstrap.find_authoritative_base(
            category, canonical_ip
        )
        if bootstrap.error is not None or bootstrap.base_url is None:
            err = bootstrap.error or ProviderError(
                provider=self.id,
                code=ProviderErrorCode.NOT_FOUND,
                message=f"no authoritative RDAP service found for {canonical_ip}",
                retryable=False,
            )
            return ProviderResult(provider=self.id, errors=(err,))

        rdap_url = validate_entity_url_path(
            bootstrap.base_url, f"ip/{quote(canonical_ip, safe='')}"
        )
        return await self._query_authoritative(
            investigation_id,
            entity,
            canonical_ip,
            retrieved_at,
            EvidenceType.NETWORK,
            rdap_url,
            "ip network",
            RdapNetworkResponse,
            _build_network_facts,
        )

    async def _lookup_asn(
        self,
        investigation_id: UUID,
        entity: Entity,
        canonical_asn: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        asn_str = canonical_asn
        if asn_str.upper().startswith("AS"):
            asn_str = asn_str[2:]
        if not asn_str.isdigit():
            return unsupported_indicator_result(self.id, "invalid entity value")

        bootstrap = await self._bootstrap.find_authoritative_base("asn", asn_str)
        if bootstrap.error is not None or bootstrap.base_url is None:
            err = bootstrap.error or ProviderError(
                provider=self.id,
                code=ProviderErrorCode.NOT_FOUND,
                message=f"no authoritative RDAP service found for ASN {asn_str}",
                retryable=False,
            )
            return ProviderResult(provider=self.id, errors=(err,))

        rdap_url = validate_entity_url_path(
            bootstrap.base_url, f"autnum/{quote(asn_str, safe='')}"
        )
        return await self._query_authoritative(
            investigation_id,
            entity,
            canonical_asn,
            retrieved_at,
            EvidenceType.REGISTRATION,
            rdap_url,
            "autnum",
            RdapAutnumResponse,
            _build_autnum_facts,
        )

    async def _query_authoritative(
        self,
        investigation_id: UUID,
        entity: Entity,
        canonical_value: str,
        retrieved_at: datetime,
        evidence_type: EvidenceType,
        rdap_url: str,
        expected_object_class: str,
        response_model: type[CommonT],
        facts_builder: Callable[[CommonT], dict[str, Any]],
    ) -> ProviderResult:
        """Fetch authoritative RDAP response, validate schema, and normalize evidence."""
        outcome = await self._http.request_json(
            "GET",
            rdap_url,
            headers={"Accept": _RDAP_ACCEPT_HEADER},
            accepted_media_types=("application/rdap+json", "application/json"),
        )

        if outcome.final_error_code is not None:
            return ProviderResult(
                provider=self.id,
                errors=(
                    ProviderError(
                        provider=self.id,
                        code=outcome.final_error_code,
                        message=outcome.final_error_message or "RDAP request failed",
                        retryable=outcome.final_error_code.retryable,
                        retry_after_seconds=outcome.retry_after_seconds,
                    ),
                ),
            )

        if not isinstance(outcome.response_json, dict):
            return ProviderResult(
                provider=self.id,
                errors=(
                    ProviderError(
                        provider=self.id,
                        code=ProviderErrorCode.INVALID_RESPONSE,
                        message="invalid RDAP response schema",
                        retryable=False,
                    ),
                ),
            )

        try:
            parsed = response_model.model_validate(outcome.response_json)
        except ValueError:
            return ProviderResult(
                provider=self.id,
                errors=(
                    ProviderError(
                        provider=self.id,
                        code=ProviderErrorCode.INVALID_RESPONSE,
                        message="invalid RDAP response schema",
                        retryable=False,
                    ),
                ),
            )

        try:
            _validate_rdap_object(parsed, expected_object_class, canonical_value)
            observed_at = _find_latest_last_changed(parsed)
            facts = facts_builder(parsed)
            record_id = _derive_source_record_id(parsed, canonical_value)
        except TypeError, ValueError:
            return ProviderResult(
                provider=self.id,
                errors=(
                    ProviderError(
                        provider=self.id,
                        code=ProviderErrorCode.INVALID_RESPONSE,
                        message="invalid RDAP response schema",
                        retryable=False,
                    ),
                ),
            )

        evidence = Evidence(
            investigation_id=investigation_id,
            type=evidence_type,
            subject=EvidenceEntityRef(
                id=entity.id,
                type=entity.type,
                value=canonical_value,
            ),
            source=self.id,
            source_record_id=record_id,
            source_url=rdap_url,
            observed_at=observed_at,
            retrieved_at=retrieved_at,
            facts=facts,
            raw_payload=None,
        )

        return ProviderResult(provider=self.id, evidence=(evidence,))
