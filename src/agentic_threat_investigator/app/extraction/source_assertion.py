# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Source-neutral durable assertion fact validation (PR 33D Part 2).

External CTI intelligence can assert relationships and sightings. ATI
persists those assertions only through the global Evidence path: converters
preserve normalized source-assertion facts inside Evidence, durable message
reconstruction derives a safe transient invocation identity from them, and
deterministic extraction revalidates them before graph state is created.

This module owns the **source-neutral** validation of the normalized
source-assertion fact contract. It deliberately knows nothing about STIX
parser objects, PostgreSQL, Kafka, FastAPI, or frontend DTOs; a future MISP
Object Reference adapter can reuse the same endpoint/sighting/relationship
validation without importing STIX vocabulary. What is deliberately **not**
here is the STIX-to-ATI relationship/profile mapping: mapping a source
relationship string plus endpoint types to an ATI :class:`RelationshipType`
belongs to the STIX conversion/extraction adapter, so MISP never becomes
coupled to STIX vocabulary.

The validators consume only the normalized fact forms documented in the
STIX Evidence contract — canonical ATI entity wire types, canonical machine
values, canonical UTC ``Z`` timestamps, and bounded ordered reference-list
facts — and raise :class:`ValueError` with static messages that never echo
source content. Callers translate :class:`ValueError` into their own bounded
error contracts (:class:`ConversionError` for conversion,
:class:`MalformedMessageExtractionError` for durable reconstruction,
:class:`EvidenceExtractionError` for extraction).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from agentic_threat_investigator.domain.entities import (
    EntityType,
    canonicalize,
)
from agentic_threat_investigator.domain.relationships import RelationshipType

STIX_ASSERTION_REFERENCE_LIST_MAX = 256
"""Single explicit maximum for each source-assertion reference list.

``where_sighted_refs`` / ``observed_data_refs`` (and any future
source-assertion reference list) are bounded provenance facts: an over-bound
list fails closed instead of being truncated, sorted, or deduplicated. The
bound is shared by conversion (admission) and durable-fact revalidation so
both sides enforce the identical contract.
"""

# A source-assertion block ``kind`` is one of the two literals
# ``"relationship"`` or ``"sighting"`` (plan §6.1/§6.2); dispatch is owned
# by the STIX extractor and the message-context seam.

_SOURCE_NEUTRAL_RELATIONSHIP_TYPES: frozenset[RelationshipType] = frozenset(
    {
        RelationshipType.USES,
        RelationshipType.TARGETS,
        RelationshipType.ATTRIBUTED_TO,
        RelationshipType.CONTROLS,
    }
)
"""The source-neutral relationship vocabulary admitted by the assertion seam.

Exactly the four PR 33D RelationshipType values; nothing else can appear in
a validated durable source-assertion fact. Existing DNS/network/registration
relationship URNs are never produced by the source-assertion seam.
"""

_CTI_ENDPOINT_WIRE_TYPES: dict[str, EntityType] = {
    EntityType.THREAT_ACTOR.value: EntityType.THREAT_ACTOR,
    EntityType.CAMPAIGN.value: EntityType.CAMPAIGN,
    EntityType.INTRUSION_SET.value: EntityType.INTRUSION_SET,
    EntityType.TOOL.value: EntityType.TOOL,
    EntityType.INFRASTRUCTURE.value: EntityType.INFRASTRUCTURE,
}
"""The exact ATI Entity wire values an assertion endpoint may carry (PR 33D).

Only the five PR 33C CTI Entity types are reconstructible from a reference;
a durable endpoint fact with any other wire value is malformed, never
fabricated.
"""

_UTC_Z_FACT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
"""Canonical UTC ``Z`` fact form of source-assertion timestamps.

Mirrors the STIX common-fact timestamp rendering contract so durable
assertion timestamps are byte-comparable with other normalized STIX facts.
"""


@dataclass(frozen=True)
class NormalizedRelationshipAssertion:
    """One validated durable relationship-assertion body.

    ``stix_type`` is the exact admitted source relationship string;
    ``ati_type`` is the source-neutral ATI RelationshipType; ``source`` and
    ``target`` are ``(EntityType, canonical value)`` identities; the
    timestamps are canonical UTC ``Z`` facts or ``None``.
    """

    stix_type: str
    ati_type: RelationshipType
    source: tuple[EntityType, str]
    target: tuple[EntityType, str]
    start_time: str | None
    stop_time: str | None


@dataclass(frozen=True)
class NormalizedSightingAssertion:
    """One validated durable sighting-assertion body.

    ``sighting_of`` is the ``(EntityType, canonical value)`` identity of the
    sighted object; ``first_seen``/``last_seen`` are canonical UTC ``Z``
    facts or ``None``; ``count`` is a positive integer or ``None``;
    ``summary`` is a boolean or ``None``; the reference lists preserve
    source order exactly and are bounded provenance facts only.
    """

    sighting_of: tuple[EntityType, str]
    first_seen: str | None
    last_seen: str | None
    count: int | None
    summary: bool | None
    where_sighted_refs: tuple[str, ...]
    observed_data_refs: tuple[str, ...]


def endpoint_entity_type_for_wire(wire: str) -> EntityType | None:
    """Return the ATI Entity type of one admitted endpoint wire value.

    ``None`` signals a wire value that is not one of the five CTI endpoint
    Entity types; callers treat it as malformed — an unknown wire value is
    never guessed or fabricated into an Entity.
    """
    return _CTI_ENDPOINT_WIRE_TYPES.get(wire)


def validate_assertion_endpoint(endpoint: Any) -> tuple[EntityType, str]:
    """Validate one canonical endpoint identity fact.

    The fact must be an object carrying an exact admitted CTI Entity wire
    ``type`` and a ``value`` that already equals its canonical form (the PR
    33C CTI machine-ID contract, e.g. ``threat-actor--<canonical-uuid>``).
    Any violation raises :class:`ValueError` with a static message that
    never echoes the endpoint value.
    """
    if not isinstance(endpoint, Mapping):
        raise ValueError("source assertion endpoint must be an object")
    endpoint_type = endpoint.get("type")
    value = endpoint.get("value")
    if not isinstance(endpoint_type, str) or not isinstance(value, str) or not value:
        raise ValueError("source assertion endpoint carries invalid identity fields")
    entity_type = endpoint_entity_type_for_wire(endpoint_type)
    if entity_type is None:
        raise ValueError("source assertion endpoint carries an unknown entity type")
    try:
        canonical = canonicalize(entity_type, value)
    except ValueError as exc:
        raise ValueError("source assertion endpoint value is malformed") from exc
    if canonical != value:
        raise ValueError("source assertion endpoint value is not in canonical form")
    return entity_type, canonical


def _validate_optional_utc_fact(value: Any) -> str | None:
    """Validate one optional canonical UTC ``Z`` timestamp fact.

    ``None`` is the documented absence; a present value must be a string
    that renders byte-for-byte as its canonical UTC ``Z`` form. Naive,
    malformed, or non-canonical (for example microsecond-preserving)
    durable values fail closed.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("source assertion timestamp must be a string when present")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(
            "source assertion timestamp is not a valid canonical UTC fact"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("source assertion timestamp must be timezone-aware")
    rendered = parsed.astimezone(UTC).strftime(_UTC_Z_FACT_FORMAT)
    if rendered != value:
        raise ValueError("source assertion timestamp is not in canonical form")
    return rendered


def _validate_optional_positive_int(value: Any) -> int | None:
    """Validate one optional positive integer fact (booleans rejected)."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("source assertion count must be an integer when present")
    if value <= 0:
        raise ValueError("source assertion count must be positive when present")
    return int(value)


def _validate_optional_bool(value: Any) -> bool | None:
    """Validate one optional boolean fact."""
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError("source assertion summary must be a boolean when present")
    return value


def _validate_reference_list(value: Any) -> tuple[str, ...]:
    """Validate one bounded ordered source-reference fact list.

    ``None`` is the documented absence (no list); a present value must be an
    array of at most :data:`STIX_ASSERTION_REFERENCE_LIST_MAX` exact
    nonblank unpadded strings. Source order is preserved exactly; the list
    is never sorted, deduplicated, or interpreted.
    """
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise ValueError("source assertion reference list must be an array")
    if len(value) > STIX_ASSERTION_REFERENCE_LIST_MAX:
        raise ValueError("source assertion reference list exceeds the bounded maximum")
    for item in value:
        if not isinstance(item, str) or not item or item != item.strip():
            raise ValueError(
                "source assertion reference list contains a malformed member"
            )
    return tuple(value)


def validate_relationship_body(body: Any) -> NormalizedRelationshipAssertion:
    """Validate one durable relationship-assertion body.

    The body must carry an exact nonblank source relationship string
    (``type``), an exact known source-neutral ATI RelationshipType URN
    (``ati_type``), canonical ``source``/``target`` endpoint facts, and
    optional canonical UTC ``Z`` ``start_time``/``stop_time`` facts with
    ``stop_time >= start_time``. The semantic mapping between the source
    string and the ATI type is deliberately **not** verified here: that is
    the STIX adapter's profile check, so MISP stays uncoupled from STIX
    vocabulary.
    """
    if not isinstance(body, Mapping):
        raise ValueError("relationship assertion body must be an object")
    relationship_type = body.get("type")
    ati_type = body.get("ati_type")
    if not isinstance(relationship_type, str) or not relationship_type.strip():
        raise ValueError("relationship assertion body carries an invalid type")
    if not isinstance(ati_type, str) or not ati_type.strip():
        raise ValueError("relationship assertion body carries an invalid ati_type")
    try:
        parsed_ati_type = RelationshipType(ati_type)
    except ValueError as exc:
        raise ValueError(
            "relationship assertion body carries an unknown ati_type"
        ) from exc
    if parsed_ati_type not in _SOURCE_NEUTRAL_RELATIONSHIP_TYPES:
        raise ValueError(
            "relationship assertion body carries a non-source-neutral ati_type"
        )
    source = validate_assertion_endpoint(body.get("source"))
    target = validate_assertion_endpoint(body.get("target"))
    start_time = _validate_optional_utc_fact(body.get("start_time"))
    stop_time = _validate_optional_utc_fact(body.get("stop_time"))
    if start_time is not None and stop_time is not None and stop_time < start_time:
        raise ValueError("relationship assertion timestamps are out of order")
    return NormalizedRelationshipAssertion(
        stix_type=relationship_type,
        ati_type=parsed_ati_type,
        source=source,
        target=target,
        start_time=start_time,
        stop_time=stop_time,
    )


def validate_sighting_body(body: Any) -> NormalizedSightingAssertion:
    """Validate one durable sighting-assertion body.

    The body must carry a canonical ``sighting_of`` endpoint fact, optional
    canonical UTC ``Z`` ``first_seen``/``last_seen`` facts with
    ``last_seen >= first_seen``, an optional positive integer ``count``, an
    optional boolean ``summary``, and bounded ordered
    ``where_sighted_refs``/``observed_data_refs`` reference lists. Reference
    lists are provenance facts only and produce no Entities or edges.
    """
    if not isinstance(body, Mapping):
        raise ValueError("sighting assertion body must be an object")
    sighting_of = validate_assertion_endpoint(body.get("sighting_of"))
    first_seen = _validate_optional_utc_fact(body.get("first_seen"))
    last_seen = _validate_optional_utc_fact(body.get("last_seen"))
    if first_seen is not None and last_seen is not None and last_seen < first_seen:
        raise ValueError("sighting assertion timestamps are out of order")
    count = _validate_optional_positive_int(body.get("count"))
    summary = _validate_optional_bool(body.get("summary"))
    where_sighted_refs = _validate_reference_list(body.get("where_sighted_refs"))
    observed_data_refs = _validate_reference_list(body.get("observed_data_refs"))
    return NormalizedSightingAssertion(
        sighting_of=sighting_of,
        first_seen=first_seen,
        last_seen=last_seen,
        count=count,
        summary=summary,
        where_sighted_refs=where_sighted_refs,
        observed_data_refs=observed_data_refs,
    )


__all__ = [
    "NormalizedRelationshipAssertion",
    "NormalizedSightingAssertion",
    "STIX_ASSERTION_REFERENCE_LIST_MAX",
    "endpoint_entity_type_for_wire",
    "validate_assertion_endpoint",
    "validate_relationship_body",
    "validate_sighting_body",
]
