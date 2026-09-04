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
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

_ASN_UPPER_BOUND = 4294967295


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


def canonicalize_ip_address(value: str) -> str:
    """Return the canonical compressed representation of an IP address."""

    return str(ipaddress.ip_address(value.strip()))


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

_CANONICALIZERS: dict[EntityType, Canonicalizer] = {
    EntityType.DOMAIN: canonicalize_domain,
    EntityType.IP_ADDRESS: canonicalize_ip_address,
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
