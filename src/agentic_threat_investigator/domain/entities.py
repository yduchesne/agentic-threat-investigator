# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical entities and canonicalization contracts.

An item is an entity when it is independently identifiable, reusable across
observations, and meaningful as a relationship participant. Otherwise it is
an attribute or evidence fact.

Entities are globally deduplicated by ``(type, canonical_value)``. The
canonical value is not stored on the domain model; persistence derives it by
calling :func:`canonicalize` at the persistence boundary so the confirmed
``Entity`` contract stays free of redundant derived state.
"""

import ipaddress
import re
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from pydantic import BaseModel, Field

_ASN_UPPER_BOUND = 4294967295
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DNS_MAX_NAME_LENGTH = 253
_DNS_MAX_LABEL_LENGTH = 63


class EntityType(str, Enum):
    """Canonical entity types that can participate in relationships."""

    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    NETWORK_PREFIX = "network_prefix"
    ASN = "asn"
    ORGANIZATION = "organization"
    MALWARE = "malware"
    ATTACK_TECHNIQUE = "attack_technique"
    VULNERABILITY = "vulnerability"


class Entity(BaseModel):
    """An independently identifiable object reusable across observations.

    Entities are stable identities deduplicated by type and canonical value.
    """

    id: UUID | None = None
    type: EntityType
    value: str
    display_name: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    content_hash: bytes | None = None
    # Persistence-owned fields are exposed so repository writes can return the
    # authoritative revision and deletion state without leaking ORM types.
    version: int | None = None
    deleted_at: datetime | None = None
    deleted_by_actor_id: UUID | None = None


def canonicalize_domain(value: str) -> str:
    """Return the canonical form of a domain name.

    Lowercases, trims surrounding whitespace, removes trailing dots, and
    encodes internationalized labels to their IDNA punycode representation.
    """

    trimmed = value.strip().rstrip(".")
    if not trimmed:
        raise ValueError("domain value must not be empty")
    if all(ord(char) < 128 for char in trimmed):
        return trimmed.lower()
    return trimmed.encode("idna").decode("ascii")


def validate_dns_name(value: str) -> str:
    """Return the strict canonical form of a DNS name used by providers.

    Beyond :func:`canonicalize_domain` normalization, this rejects names with
    empty labels, embedded whitespace, underscores, malformed label
    characters, labels longer than 63 octets, and names longer than 253
    octets. At most one terminal DNS root dot is removed; a name that still
    ends in a dot afterwards contains an empty label and is rejected, so
    malformed names such as ``example.com..`` never silently canonicalize.
    Non-ASCII input is canonicalized to IDNA punycode before label
    validation, so the returned value is always a canonical ASCII name.
    """

    trimmed = value.strip()
    if trimmed.endswith("."):
        trimmed = trimmed[:-1]
    if trimmed.endswith("."):
        raise ValueError("DNS name has multiple terminal dots")
    if not trimmed:
        raise ValueError("DNS name must not be empty")
    if len(trimmed) > _DNS_MAX_NAME_LENGTH:
        raise ValueError("DNS name exceeds the maximum length")
    if not trimmed.isascii():
        try:
            trimmed = trimmed.encode("idna").decode("ascii")
        except (UnicodeError, ValueError) as exc:
            raise ValueError("DNS name is not valid IDNA") from exc
        if len(trimmed) > _DNS_MAX_NAME_LENGTH:
            raise ValueError("DNS name exceeds the maximum length")
    trimmed = trimmed.lower()
    labels = trimmed.split(".")
    for label in labels:
        if not label or len(label) > _DNS_MAX_LABEL_LENGTH:
            raise ValueError("DNS name has an invalid label length")
        if not _DNS_LABEL_RE.fullmatch(label):
            raise ValueError("DNS name has invalid label characters")
    return trimmed


def canonicalize_ip_address(value: str) -> str:
    """Return the canonical compressed representation of an IP address.

    The IPv6 form is rebuilt from the numeric 128-bit address rather than
    from ``ipaddress``' textual rendering: Python releases have changed how
    IPv4-mapped addresses such as ``::ffff:8.8.8.8`` are displayed, while
    canonical entity values and provider identity checks must remain stable
    across environments.
    """
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv4Address):
        return str(address)

    number = int(address)
    hextets = [format((number >> shift) & 0xFFFF, "x") for shift in range(112, -1, -16)]
    best_start = -1
    best_length = 0
    index = 0
    while index < len(hextets):
        if hextets[index] != "0":
            index += 1
            continue
        end = index
        while end < len(hextets) and hextets[end] == "0":
            end += 1
        if end - index > best_length:
            best_start = index
            best_length = end - index
        index = end

    if best_length < 2:
        return ":".join(hextets)
    return (
        ":".join(hextets[:best_start])
        + "::"
        + ":".join(hextets[best_start + best_length :])
    )


def canonicalize_asn(value: str) -> str:
    """Return the canonical numeric identity of an ASN as ``AS<number>``.

    Accepts an optional ``AS``/``as`` prefix and strips leading zeros so
    differently rendered ASNs canonicalize to the same identity.
    """

    candidate = value.strip().upper()
    if candidate.startswith("AS"):
        candidate = candidate[2:]
    if not candidate.isdigit():
        raise ValueError(f"invalid ASN value: {value!r}")
    number = int(candidate)
    if not 0 < number <= _ASN_UPPER_BOUND:
        raise ValueError(f"ASN number out of range: {value!r}")
    return f"AS{number}"


def canonicalize_network_prefix(value: str) -> str:
    """Return the canonical network boundary of a prefix.

    Host bits beyond the prefix length are zeroed so any address inside a
    prefix canonicalizes to the prefix's network boundary.
    """

    return str(ipaddress.ip_network(value.strip(), strict=False))


def canonicalize_cve(value: str) -> str:
    """Return the canonical uppercase CVE identifier."""

    candidate = value.strip().upper()
    if not candidate:
        raise ValueError("CVE identifier must not be empty")
    return candidate


def canonicalize_attack_technique(value: str) -> str:
    """Return the canonical uppercase ATT&CK technique identifier.

    Both technique identifiers (``T1234``) and sub-technique identifiers
    (``T1234.567``) canonicalize to their uppercase form.
    """

    candidate = value.strip().upper()
    if not candidate:
        raise ValueError("ATT&CK identifier must not be empty")
    return candidate


Canonicalizer = Callable[[str], str]
"""A pure function mapping a raw entity value to its canonical form."""


def canonicalize_url(value: str) -> str:
    """Return the canonical form of an HTTP/HTTPS URL (v0.1 identity contract).

    The v0.1 URL identity contract is deliberately conservative so the
    result is deterministic, stable across Python runtimes, safe as a
    persistence identity, and non-lossy with respect to
    security-relevant URL components:

    - Only the ``http`` and ``https`` schemes are supported; any other
      scheme is rejected.
    - Userinfo (username/password), fragments, missing hosts, invalid
      ports (including port 0 and ports above 65535), embedded
      whitespace, and control characters are rejected.
    - The scheme is lowercased. A DNS host is strictly validated with
      :func:`validate_dns_name` (including IDNA) and lowercased; an IP
      host uses :func:`canonicalize_ip_address`. IPv6 hosts are rendered
      bracketed in the canonical URL.
    - The default port for the scheme (80 for ``http``, 443 for
      ``https``) is omitted; any other port is preserved.
    - An empty path becomes ``/``; any other path, the query string, and
      existing percent-encoded octets are preserved byte-for-byte after
      syntax validation (every ``%`` must introduce two hex digits), so
      the identity never decodes, reorders, or case-folds application
      data. Query parameters are never sorted or dropped, dot-segments
      are never resolved, and trailing slashes are never removed.
    - Fragments are rejected because they are not transmitted in HTTP
      requests and would create ambiguous indicator identity. An empty
      query is indistinguishable from no query and canonicalizes to no
      query.

    Raises ``ValueError`` for any input outside the contract. The branch
    count is intrinsic to the explicit per-rejection contract rules.
    """
    # pylint: disable=too-many-branches
    # Only plain ASCII spaces are trimmed from the ends; tab, newline,
    # and other control characters anywhere in the URL are rejected so
    # they can never be silently dropped by broader Unicode trimming.
    candidate = value.strip(" ")
    if not candidate or any(
        char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in candidate
    ):
        raise ValueError("URL contains embedded whitespace or control characters")
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise ValueError("malformed URL") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must not contain userinfo")
    if parsed.fragment or "#" in candidate:
        raise ValueError("URL must not contain a fragment")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must have a host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL has an invalid port") from exc
    if port is not None and port == 0:
        raise ValueError("URL port must not be zero")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            canonical_host = validate_dns_name(hostname)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("URL has an invalid DNS host") from exc
    else:
        canonical_host = canonicalize_ip_address(str(address))

    _validate_percent_encoding(parsed.path, "path")
    _validate_percent_encoding(parsed.query, "query")

    default_port = 80 if scheme == "http" else 443
    host_render = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    if port is not None and port != default_port:
        netloc = f"{host_render}:{port}"
    else:
        netloc = host_render
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def _validate_percent_encoding(component: str, member: str) -> None:
    """Require every ``%`` in a URL component to introduce two hex digits.

    Percent-encodings are otherwise preserved byte-for-byte: the contract
    never decodes, re-encodes, or case-folds existing escapes.
    """
    index = component.find("%")
    while index != -1:
        escape = component[index + 1 : index + 3]
        if len(escape) != 2 or any(
            char not in "0123456789abcdefABCDEF" for char in escape
        ):
            raise ValueError(f"URL {member} has malformed percent encoding")
        index = component.find("%", index + 3)


_CANONICALIZERS: dict[EntityType, Canonicalizer] = {
    EntityType.DOMAIN: canonicalize_domain,
    EntityType.IP_ADDRESS: canonicalize_ip_address,
    EntityType.URL: canonicalize_url,
    EntityType.NETWORK_PREFIX: canonicalize_network_prefix,
    EntityType.ASN: canonicalize_asn,
    EntityType.VULNERABILITY: canonicalize_cve,
    EntityType.ATTACK_TECHNIQUE: canonicalize_attack_technique,
}


def canonicalize(entity_type: EntityType, value: str) -> str:
    """Return the canonical value of an entity for its type.

    Raises ValueError when the value violates the type's contract or when no
    canonicalization contract is defined for the entity type yet.
    """

    canonicalizer = _CANONICALIZERS.get(entity_type)
    if canonicalizer is None:
        raise ValueError(f"no canonicalization contract for type: {entity_type.value}")
    return canonicalizer(value)
