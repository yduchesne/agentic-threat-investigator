# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""STIX 2.1 IOC Evidence conversion (PR 33B).

Owns the pure :class:`Stix21ToEvidenceConverter` for the
``urn:ati:datasource:semanticformat:stix21`` semantic format plus the
STIX-specific fact builders and normalization helpers. The semantic parser
(``stix21_semantics.py``) remains PR 33A source validation only and
constructs no Evidence; this module consumes only already-validated
:class:`Stix21Object` values through the reusable single-object seam.

The converter maps one supported STIX object plus the explicit
:class:`EvidenceConversionContext` to exactly one :class:`ConvertedEvidence`:
a stable global ``THREAT_INTELLIGENCE`` :class:`Evidence` whose
deterministic PR 28A identity is pinned to ``semantic_format=STIX_21``,
the ATI source namespace carried by the context, and the **exact STIX
``id``** as ``source_record_id``, plus an
:class:`EvidenceObservationCandidate` with ``observed_at=None`` (STIX
timestamps are normalized source facts, never ATI observation time),
``retrieved_at`` from the semantic context, the normalized
STIX/IOC facts, and ``raw_payload=None``. No Investigation, subject,
verdict, confidence interpretation, attribution, relationship, observation
version, or diff is synthesized.

Supported Evidence profile (deliberately narrow):

- ``domain-name`` SCO with a string ``value`` -> one canonical DOMAIN IOC;
- ``ipv4-addr`` SCO with an actually-IPv4 string ``value`` -> one canonical
  IP_ADDRESS IOC (an IPv6 payload here is a ``ConversionError``);
- ``ipv6-addr`` SCO with an actually-IPv6 string ``value`` -> one canonical
  IP_ADDRESS IOC (an IPv4 payload here is a ``ConversionError``);
- ``indicator`` SDO whose ``pattern_type == "stix"``, whose ``pattern`` is
  a nonblank string, and whose **entire** pattern belongs to the approved
  equality-only IOC whitelist -> one Evidence whose ``iocs`` preserve the
  left-to-right pattern leaf order (duplicates included);
- the five PR 33C CTI SDO types ``threat-actor``, ``campaign``,
  ``intrusion-set``, ``tool``, and ``infrastructure`` -> one Evidence whose
  normalized facts carry exactly one ``cti_entity`` represented-entity block
  (the exact validated STIX machine ID plus the source ``name`` as display
  metadata) and an empty ``iocs`` array;
- PR 33D ``relationship`` SDOs whose ``relationship_type`` plus exact
  ``source_ref``/``target_ref`` endpoint type pair match the approved
  source-neutral profile (§5.3) -> one Evidence whose normalized facts carry
  exactly one ``source_assertion`` block with the admitted relationship
  string, the exact ATI RelationshipType wire URN, canonical endpoint machine
  identities, and normalized ``start_time``/``stop_time`` facts;
- PR 33D ``sighting`` SDOs whose ``sighting_of_ref`` is an exact canonical
  reference to one of the five CTI Entity types -> one Evidence whose
  normalized facts carry exactly one ``source_assertion`` block with the
  sighted CTI identity plus the bounded Sighting facts
  (``first_seen``/``last_seen``, ``count``, ``summary``,
  ``where_sighted_refs``/``observed_data_refs``);
- every other valid STIX object, every valid-but-unsupported Indicator
  pattern, every Relationship outside the approved profile (including
  otherwise familiar strings such as ``indicates``/``related-to`` and
  admitted strings whose endpoint types are outside the table), and every
  Sighting whose ``sighting_of_ref`` is not one of the five CTI types ->
  zero Evidence (a valid no-result, never a failure).

Generic STIX ``attack-pattern``, ``malware``, and ``vulnerability`` objects
are deliberately **not** admitted: ATI's ``ATTACK_TECHNIQUE``/``MALWARE``/
``VULNERABILITY`` contracts are narrower canonical identity contracts and
name-based mapping would be unsafe. CTI ``name`` values are display metadata
and never participate in canonical identity. STIX ``relationship``/``sighting``
objects outside the approved PR 33D profile, every reference field not
consumed by that profile (aliases, labels, markings,
``where_sighted_refs``/``observed_data_refs`` members, unresolved STIX
references), and every STIX temporal field stay unconsumed source facts and
never become ATI graph state. The converter preserves source assertions as
Evidence facts only and never persists or directly constructs durable graph
rows.

Indicator pattern interpretation is delegated to the ATI-owned structural
adapter (``stix21_pattern.py``) which uses the maintained OASIS
``stix2-patterns`` grammar parser; ATI never regex-parses STIX Patterning.
A syntactically malformed approved-context Indicator pattern and a
supported SCO whose consumed IOC value fails ATI canonicalization each
raise a bounded :class:`ConversionError`.

Approved STIX metadata is preserved as source facts only — ``id``, ``type``,
``spec_version``, ``created``/``modified``/``valid_from``/``valid_until``
(normalized UTC ``Z``), ``revoked``, ``labels``, ``confidence``, ``lang``,
``external_references``, ``object_marking_refs``, ``granular_markings``,
SCO ``defanged``, and the Indicator pattern/version/validity/type fields —
never dereferenced, interpreted, or enforced.

The converter performs no I/O, no persistence, no clock/random reads, no
secret lookup, never allocates an observation version, and is selected
exclusively by :class:`SemanticFormatId.STIX_21` (there is deliberately no
fixed ``SourceId`` guard: future TAXII sources may carry STIX under other
source identities). The STIX-to-ATI relationship profile mapping lives here
as the authoritative conversion table; the source-neutral assertion seam
(``app.extraction.source_assertion``) validates the durable normalized form
and the deterministic extractor cross-validates the same profile from the
durable facts.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any, Mapping

from agentic_threat_investigator.app.evidence_conversion import (
    ConversionError,
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
)
from agentic_threat_investigator.domain.entities import (
    CTI_ENTITY_DISPLAY_NAME_MAX_LENGTH,
    EntityType,
    canonicalize_cti_object_id,
    canonicalize_ip_address,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import SemanticFormatId
from agentic_threat_investigator.infrastructure.datasources.stix21_pattern import (
    APPROVED_STIX_IOC_OBJECT_TYPES,
    Stix21PatternStatus,
    interpret_stix21_pattern,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    Stix21Object,
)

__all__ = [
    "Stix21ToEvidenceConverter",
    "STIX_RELATIONSHIP_PROFILE",
    "build_stix21_conversion_registry",
    "build_stix_common_facts",
    "build_stix_cti_entity_facts",
    "build_stix_indicator_facts",
    "build_stix_normalized_facts",
    "build_stix_relationship_assertion",
    "build_stix_sighting_assertion",
    "extract_stix_ioc_facts",
]

_STIX_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
"""Canonical UTC ``Z`` fact form for normalized STIX timestamps.

Mirrors the established MISP fact-timestamp format contract so STIX and
MISP normalized timestamps render identically. The source-assertion
revalidation seam reuses the same canonical form.
"""

_STIX_CTI_ENTITY_TYPES: dict[str, EntityType] = {
    "threat-actor": EntityType.THREAT_ACTOR,
    "campaign": EntityType.CAMPAIGN,
    "intrusion-set": EntityType.INTRUSION_SET,
    "tool": EntityType.TOOL,
    "infrastructure": EntityType.INFRASTRUCTURE,
}
"""Exact STIX 2.1 object-type to ATI CTI Entity mapping (PR 33C).

An explicit source-neutral mapping; nothing is inferred from enum names or
spelling. Generic STIX ``attack-pattern``/``malware``/``vulnerability`` are
deliberately absent: they are not admitted here (see the module invariants).
This map is the single authoritative STIX-reference prefix resolution used
by Relationship and Sighting conversion; the extractor instead revalidates
the durable ATI wire values against the canonical identity contract.
"""

STIX_RELATIONSHIP_PROFILE: dict[
    str, tuple[str, frozenset[EntityType], frozenset[EntityType]]
] = {
    "uses": (
        "urn:ati:relationship:threat:uses",
        frozenset(
            {
                EntityType.THREAT_ACTOR,
                EntityType.CAMPAIGN,
                EntityType.INTRUSION_SET,
            }
        ),
        frozenset({EntityType.TOOL, EntityType.INFRASTRUCTURE}),
    ),
    "targets": (
        "urn:ati:relationship:threat:targets",
        frozenset(
            {
                EntityType.THREAT_ACTOR,
                EntityType.CAMPAIGN,
                EntityType.INTRUSION_SET,
            }
        ),
        frozenset({EntityType.INFRASTRUCTURE}),
    ),
    "attributed-to": (
        "urn:ati:relationship:threat:attributed_to",
        frozenset({EntityType.CAMPAIGN, EntityType.INTRUSION_SET}),
        frozenset({EntityType.THREAT_ACTOR}),
    ),
    "controls": (
        "urn:ati:relationship:threat:controls",
        frozenset({EntityType.THREAT_ACTOR, EntityType.INTRUSION_SET}),
        frozenset({EntityType.INFRASTRUCTURE}),
    ),
}
"""The exact approved PR 33D STIX Relationship profile.

``STIX relationship string -> (ATI RelationshipType wire URN, allowed source
Entity types, allowed target Entity types)``. This is ATI's initial supported
profile (plan §5.3), not a claim to model the entire STIX 2.1 relationship
matrix; a valid Relationship outside this table is valid-but-Evidence-
unsupported and returns zero Evidence. The converter emits the wire URN
string (the domain ``RelationshipType`` enum values are intentionally not
imported here); the deterministic extractor owns the same profile keyed by
the domain enum, and a regression test pins the two tables to each other.
No unsupported STIX string is ever mapped to an existing ATI relationship
URN.
"""

_STIX_REFERENCE_LIST_BOUND = 256
"""Conversion-side bound of one Sighting reference-list fact.

Must equal ``app.extraction.source_assertion.STIX_ASSERTION_REFERENCE_LIST_MAX``
(the durable revalidation seam's authoritative single maximum); a regression
test pins the two values to each other. The converter is deliberately free
of ``app.extraction`` imports (see M33C-S35), so the bound is declared here
and mirrored there.
"""


def _optional_stix_string(source_value: Mapping[str, Any], key: str) -> str | None:
    """Return one optional STIX string member, or ``None`` when absent.

    A present non-string value fails closed: silent coercion is never
    applied to modeled optional fields.
    """
    value = source_value.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConversionError(f"STIX {key} must be a string when present")
    return value


def _require_stix_string(source_value: Mapping[str, Any], key: str) -> str:
    """Return one required nonblank STIX string member."""
    value = _optional_stix_string(source_value, key)
    if value is None or not value.strip():
        raise ConversionError(f"STIX {key} must be a nonblank string")
    return value


def _optional_stix_bool(source_value: Mapping[str, Any], key: str) -> bool | None:
    """Return one optional STIX boolean member, or ``None`` when absent."""
    value = source_value.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ConversionError(f"STIX {key} must be a boolean when present")
    return value


def _optional_stix_int(source_value: Mapping[str, Any], key: str) -> int | None:
    """Return one optional STIX integer member, or ``None`` when absent.

    Booleans are rejected (they are not integers); only the source type is
    preserved, no confidence/verdict semantics are interpreted.
    """
    value = source_value.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        raise ConversionError(f"STIX {key} must be an integer when present")
    if not isinstance(value, int):
        raise ConversionError(f"STIX {key} must be an integer when present")
    return value


def _optional_stix_string_list(source_value: Mapping[str, Any], key: str) -> list[str]:
    """Return one ordered STIX string-list member, or ``[]`` when absent."""
    value = source_value.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConversionError(f"STIX {key} must be a list of strings")
    return list(value)


def _optional_stix_object_list(
    source_value: Mapping[str, Any], key: str
) -> list[dict[str, Any]]:
    """Return one ordered STIX object-list member, or ``[]`` when absent."""
    value = source_value.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConversionError(f"STIX {key} must be a list of objects")
    return list(value)


def _normalize_stix_timestamp(source_value: Mapping[str, Any], key: str) -> str | None:
    """Normalize one optional STIX timestamp member to canonical UTC ``Z``.

    A documented absent member yields ``None``. A present member must be a
    timezone-aware ISO-8601 string (a ``Z`` suffix is accepted); naive or
    malformed values fail closed. The normalized value is rendered in the
    canonical UTC ``Z`` fact form; the raw source timestamp is never used
    anywhere else (STIX timestamps never enter Evidence identity or ATI
    observation time).
    """
    value = _optional_stix_string(source_value, key)
    if value is None:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ConversionError(f"STIX {key} must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ConversionError(f"STIX {key} must be a timezone-aware timestamp")
    return parsed.astimezone(UTC).strftime(_STIX_TIMESTAMP_FORMAT)


def build_stix_common_facts(source_value: Mapping[str, Any]) -> dict[str, Any]:
    """Build the normalized common STIX fact object for one supported object.

    Explicitly selects the modeled STIX common properties: ``id``, ``type``,
    ``spec_version``, ``created``, ``modified``, ``revoked``, ``labels``,
    ``confidence``, ``lang``, ``external_references``,
    ``object_marking_refs``, ``granular_markings``, and SCO ``defanged``.
    Optional scalars use stable explicit ``None``; modeled list fields use
    ``[]`` when absent; list source order is preserved; timestamps are
    normalized to UTC ``Z``; a present field of an incompatible type fails
    closed. No marking is dereferenced, no TLP inferred, and no confidence
    is interpreted.
    """
    return {
        "id": source_value["id"],
        "type": source_value["type"],
        "spec_version": source_value.get("spec_version"),
        "created": _normalize_stix_timestamp(source_value, "created"),
        "modified": _normalize_stix_timestamp(source_value, "modified"),
        "revoked": _optional_stix_bool(source_value, "revoked"),
        "labels": _optional_stix_string_list(source_value, "labels"),
        "confidence": _optional_stix_int(source_value, "confidence"),
        "lang": _optional_stix_string(source_value, "lang"),
        "external_references": _optional_stix_object_list(
            source_value, "external_references"
        ),
        "object_marking_refs": _optional_stix_string_list(
            source_value, "object_marking_refs"
        ),
        "granular_markings": _optional_stix_object_list(
            source_value, "granular_markings"
        ),
        "defanged": _optional_stix_bool(source_value, "defanged"),
    }


def build_stix_indicator_facts(source_value: Mapping[str, Any]) -> dict[str, Any]:
    """Build the normalized Indicator fact object for one supported Indicator.

    Preserves the original ``pattern`` string exactly, ``pattern_type``,
    optional ``pattern_version``, ``valid_from``/``valid_until`` (normalized
    UTC ``Z`` when present), and ordered ``indicator_types``. Optional
    scalars use stable explicit ``None``; the pattern/type fields are only
    read after the Evidence-support guards passed, so they are already
    contract-valid here. No verdict, confidence, attribution, or lifetime
    semantics are synthesized.
    """
    return {
        "pattern": _require_stix_string(source_value, "pattern"),
        "pattern_type": _require_stix_string(source_value, "pattern_type"),
        "pattern_version": _optional_stix_string(source_value, "pattern_version"),
        "valid_from": _normalize_stix_timestamp(source_value, "valid_from"),
        "valid_until": _normalize_stix_timestamp(source_value, "valid_until"),
        "indicator_types": _optional_stix_string_list(source_value, "indicator_types"),
    }


def _canonical_stix_domain(value: str) -> str:
    """Canonicalize one approved DOMAIN IOC value with the strict helper.

    Reuses the existing ``validate_dns_name`` contract (mixed-case, root
    dot, and IDNA normalization); a failure on an already admitted
    comparison is a bounded local :class:`ConversionError`.
    """
    try:
        return validate_dns_name(value)
    except ValueError as exc:
        raise ConversionError(
            "STIX domain value failed strict DNS canonicalization"
        ) from exc


def _canonical_stix_ip(value: str, required_family: type) -> str:
    """Canonicalize one approved IP IOC value and enforce its family.

    Reuses the existing ``canonicalize_ip_address`` contract, then proves
    the canonical address belongs to the required STIX object family: an
    ``ipv4-addr`` containing IPv6 and an ``ipv6-addr`` containing IPv4 are
    each a bounded :class:`ConversionError`, never a silent family switch.
    """
    try:
        canonical = canonicalize_ip_address(value)
    except ValueError as exc:
        raise ConversionError(
            "STIX IP value failed canonical IP normalization"
        ) from exc
    parsed = ipaddress.ip_address(canonical)
    if not isinstance(parsed, required_family):
        raise ConversionError("STIX IP value does not match its declared family")
    return canonical


def _canonicalize_ioc_leaf(leaf: Mapping[str, str]) -> dict[str, str]:
    """Canonicalize one approved pattern leaf into an ATI IOC fact.

    ``leaf`` carries the exact STIX object type and the raw decoded
    string-literal value from the whitelist adapter. Canonicalization is
    applied only after the whole pattern tree was admitted; a malformed
    value in an already admitted comparison is a bounded
    :class:`ConversionError`.
    """
    stix_type = leaf["stix_type"]
    value = leaf["value"]
    if stix_type == "domain-name":
        return {
            "type": EntityType.DOMAIN.value,
            "value": _canonical_stix_domain(value),
        }
    if stix_type == "ipv4-addr":
        return {
            "type": EntityType.IP_ADDRESS.value,
            "value": _canonical_stix_ip(value, ipaddress.IPv4Address),
        }
    if stix_type == "ipv6-addr":
        return {
            "type": EntityType.IP_ADDRESS.value,
            "value": _canonical_stix_ip(value, ipaddress.IPv6Address),
        }
    raise ConversionError("unsupported approved STIX IOC object type")


def _direct_sco_ioc_facts(
    source_value: Mapping[str, Any],
) -> tuple[dict[str, str], ...]:
    """Extract the canonical IOC fact for one supported direct SCO.

    Requires the string ``value`` member of a supported SCO type; a
    missing/non-string or non-canonicalizable value is a bounded
    :class:`ConversionError`. IP family is enforced (``ipv4-addr`` must be
    IPv4, ``ipv6-addr`` must be IPv6).
    """
    stix_type = source_value["type"]
    value = _optional_stix_string(source_value, "value")
    if value is None:
        raise ConversionError(f"STIX {stix_type} object requires a string value")
    if stix_type == "domain-name":
        return (
            {"type": EntityType.DOMAIN.value, "value": _canonical_stix_domain(value)},
        )
    if stix_type == "ipv4-addr":
        return (
            {
                "type": EntityType.IP_ADDRESS.value,
                "value": _canonical_stix_ip(value, ipaddress.IPv4Address),
            },
        )
    if stix_type == "ipv6-addr":
        return (
            {
                "type": EntityType.IP_ADDRESS.value,
                "value": _canonical_stix_ip(value, ipaddress.IPv6Address),
            },
        )
    return ()


def extract_stix_ioc_facts(source: Stix21Object) -> tuple[dict[str, str], ...]:
    """Extract canonical entity-eligible IOC facts for one supported object.

    A supported direct SCO produces exactly one ordered fact; a supported
    Indicator produces one fact per approved pattern leaf in deterministic
    left-to-right order (duplicates preserved, never sorted or
    deduplicated). A valid unsupported STIX object or a valid
    but-unsupported Indicator pattern returns the empty tuple; a malformed
    Indicator pattern and a supported object with a malformed consumed IOC
    value each raise a bounded :class:`ConversionError`. Facts carry only
    canonical entity-eligible values and never analysis, verdict, or risk
    semantics.
    """
    source_value = source.source_value()
    stix_type = source_value["type"]
    if stix_type in APPROVED_STIX_IOC_OBJECT_TYPES:
        return _direct_sco_ioc_facts(source_value)
    if stix_type != "indicator":
        return ()
    if source_value.get("pattern_type") != "stix":
        return ()
    _require_stix_string(source_value, "pattern")
    _optional_stix_string(source_value, "pattern_version")
    interpretation = interpret_stix21_pattern(
        _require_stix_string(source_value, "pattern")
    )
    if interpretation.status is Stix21PatternStatus.MALFORMED:
        raise ConversionError("STIX indicator pattern is not valid Patterning syntax")
    if interpretation.status is Stix21PatternStatus.VALID_BUT_UNSUPPORTED:
        return ()
    return tuple(_canonicalize_ioc_leaf(leaf) for leaf in interpretation.iocs)


def build_stix_cti_entity_facts(
    source_value: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Build the normalized represented-entity block for one supported CTI SDO.

    Returns ``None`` for every non-CTI object type. For one of the five
    supported CTI SDO types (``threat-actor``, ``campaign``,
    ``intrusion-set``, ``tool``, ``infrastructure``) it fail-closed requires
    an exact validated STIX ``id`` whose type prefix matches ``type`` and a
    nonblank bounded ``name`` string; the returned block carries the ATI
    Entity wire value, the exact canonical opaque machine ID, and the exact
    source ``name`` spelling as display metadata. A malformed machine ID,
    missing/non-string name, or over-bound name is a bounded
    :class:`ConversionError`; source content is never echoed. No
    relationship reference, alias, goal, role, motivation, or description is
    interpreted or admitted.
    """
    stix_type = source_value["type"]
    entity_type = _STIX_CTI_ENTITY_TYPES.get(stix_type)
    if entity_type is None:
        return None
    name = _optional_stix_string(source_value, "name")
    if name is None or not name.strip():
        raise ConversionError(f"STIX {stix_type} object requires a nonblank name")
    if len(name) > CTI_ENTITY_DISPLAY_NAME_MAX_LENGTH:
        raise ConversionError(f"STIX {stix_type} name exceeds the bounded maximum")
    try:
        machine_id = canonicalize_cti_object_id(entity_type, source_value["id"])
    except ValueError as exc:
        raise ConversionError(
            "STIX object id does not match its declared CTI object type"
        ) from exc
    return {
        "type": entity_type.value,
        "value": machine_id,
        "display_name": name,
    }


def _optional_stix_positive_int(
    source_value: Mapping[str, Any], key: str
) -> int | None:
    """Return one optional positive STIX integer member, or ``None`` when absent.

    A present non-integer (including a boolean) and a present non-positive
    integer both fail closed: the Sighting ``count`` contract requires a
    positive integer when present.
    """
    value = _optional_stix_int(source_value, key)
    if value is not None and value <= 0:
        raise ConversionError(f"STIX {key} must be a positive integer when present")
    return value


def _optional_stix_bounded_reference_list(
    source_value: Mapping[str, Any], key: str, *, bound: int
) -> list[str]:
    """Return one ordered bounded STIX reference-list member, or ``[]``.

    Every member must be an exact nonblank unpadded string; the list bound
    is enforced with a static bounded error and source order is preserved
    exactly (the list is provenance data, never sorted or deduplicated).
    """
    value = _optional_stix_string_list(source_value, key)
    if len(value) > bound:
        raise ConversionError(f"STIX {key} exceeds the bounded maximum")
    for member in value:
        if not member or member != member.strip():
            raise ConversionError(f"STIX {key} contains a malformed member")
    return value


def _resolve_stix_cti_reference(ref: str) -> tuple[EntityType, str] | None:
    """Resolve one exact STIX reference to a CTI Entity identity, or ``None``.

    Only the five PR 33C CTI reference prefixes resolve to
    ``(EntityType, canonical machine value)``; any other exact reference
    prefix returns ``None`` (a valid-but-unsupported endpoint, never an
    error). A blank/padded reference and an admitted prefix whose suffix is
    not a canonical UUID fail closed with a bounded :class:`ConversionError`
    (plan §5.4: malformed consumed supported-profile field). The PR 33C
    ``canonicalize_cti_object_id`` contract is reused verbatim; no UUID
    parsing rule is duplicated. A reference is never normalized and never
    becomes a domain/IP/malware/CVE/ATT&CK identity.
    """
    if not ref.strip() or ref != ref.strip():
        raise ConversionError("STIX reference is blank or padded with whitespace")
    prefix = ref.split("--", 1)[0]
    entity_type = _STIX_CTI_ENTITY_TYPES.get(prefix)
    if entity_type is None:
        return None
    try:
        return entity_type, canonicalize_cti_object_id(entity_type, ref)
    except ValueError as exc:
        raise ConversionError(
            "STIX reference does not match its declared CTI object type"
        ) from exc


def _assertion_endpoint_fact(identity: tuple[EntityType, str]) -> dict[str, str]:
    """Build the normalized ``{"type", "value"}`` endpoint fact of one identity.

    Only canonical machine identities are emitted; no display name is ever
    fabricated from the reference (plan §1.4).
    """
    entity_type, value = identity
    return {"type": entity_type.value, "value": value}


def build_stix_relationship_assertion(
    source_value: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Build the normalized source-assertion fact of one Relationship object.

    Returns ``None`` for a valid-but-Evidence-unsupported Relationship (an
    unadmitted ``relationship_type`` string, a non-CTI endpoint reference, or
    an admitted string whose endpoint type pair is outside the approved
    profile) and the pinned ``kind=relationship`` fact block for an admitted
    one. Once the object claims an admitted profile candidate every consumed
    field fails closed: a blank/non-string ``relationship_type``,
    ``source_ref``/``target_ref``, an admitted endpoint prefix with a
    malformed/non-canonical UUID, and malformed or out-of-order
    ``start_time``/``stop_time`` are each a bounded
    :class:`ConversionError`. Errors never echo source-controlled values.
    """
    relationship_type = _require_stix_string(source_value, "relationship_type")
    profile = STIX_RELATIONSHIP_PROFILE.get(relationship_type)
    if profile is None:
        return None
    source_ref = _require_stix_string(source_value, "source_ref")
    target_ref = _require_stix_string(source_value, "target_ref")
    source = _resolve_stix_cti_reference(source_ref)
    if source is None:
        return None
    target = _resolve_stix_cti_reference(target_ref)
    if target is None:
        return None
    ati_type, source_types, target_types = profile
    if source[0] not in source_types or target[0] not in target_types:
        return None
    start_time = _normalize_stix_timestamp(source_value, "start_time")
    stop_time = _normalize_stix_timestamp(source_value, "stop_time")
    if start_time is not None and stop_time is not None and stop_time < start_time:
        raise ConversionError("STIX relationship timestamps are out of order")
    return {
        "kind": "relationship",
        "relationship": {
            "type": relationship_type,
            "ati_type": ati_type,
            "source": _assertion_endpoint_fact(source),
            "target": _assertion_endpoint_fact(target),
            "start_time": start_time,
            "stop_time": stop_time,
        },
        "sighting": None,
    }


def build_stix_sighting_assertion(
    source_value: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Build the normalized source-assertion fact of one Sighting object.

    Returns ``None`` for a valid-but-Evidence-unsupported Sighting whose
    ``sighting_of_ref`` is not an exact canonical reference to one of the
    five PR 33C CTI Entity types, and the pinned ``kind=sighting`` fact
    block for a supported one. Consumed Sighting fields fail closed with
    bounded :class:`ConversionError`: a blank/non-string ``sighting_of_ref``,
    an admitted prefix with a malformed UUID, out-of-order
    ``first_seen``/``last_seen``, non-positive/non-integer ``count``,
    non-boolean ``summary``, and over-bound or malformed
    ``where_sighted_refs``/``observed_data_refs``. Reference lists preserve
    source order exactly and are provenance facts only — they create no
    Entities and no edges.
    """
    sighting_of_ref = _require_stix_string(source_value, "sighting_of_ref")
    sighted = _resolve_stix_cti_reference(sighting_of_ref)
    if sighted is None:
        return None
    first_seen = _normalize_stix_timestamp(source_value, "first_seen")
    last_seen = _normalize_stix_timestamp(source_value, "last_seen")
    if first_seen is not None and last_seen is not None and last_seen < first_seen:
        raise ConversionError("STIX sighting timestamps are out of order")
    count = _optional_stix_positive_int(source_value, "count")
    summary = _optional_stix_bool(source_value, "summary")
    where_sighted_refs = _optional_stix_bounded_reference_list(
        source_value, "where_sighted_refs", bound=_STIX_REFERENCE_LIST_BOUND
    )
    observed_data_refs = _optional_stix_bounded_reference_list(
        source_value, "observed_data_refs", bound=_STIX_REFERENCE_LIST_BOUND
    )
    return {
        "kind": "sighting",
        "relationship": None,
        "sighting": {
            "sighting_of": _assertion_endpoint_fact(sighted),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "count": count,
            "summary": summary,
            "where_sighted_refs": where_sighted_refs,
            "observed_data_refs": observed_data_refs,
        },
    }


def build_stix_normalized_facts(
    source: Stix21Object,
    iocs: tuple[dict[str, str], ...],
    cti_entity: dict[str, Any] | None = None,
    source_assertion: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the stable normalized STIX/IOC/CTI/source-assertion fact object.

    One stable shape (key order pinned by the regression tests):

    - ``stix``: the common selected STIX metadata (see
      :func:`build_stix_common_facts`);
    - ``indicator``: the normalized Indicator block for an ``indicator``
      source, otherwise ``None``;
    - ``iocs``: canonical entity-eligible values as ordered
      ``{"type", "value"}`` objects (``[]`` for CTI SDO and
      Relationship/Sighting Evidence);
    - ``cti_entity``: the one represented CTI Entity block (see
      :func:`build_stix_cti_entity_facts`) for a supported CTI SDO,
      otherwise ``None`` (IOC/Indicator Evidence keeps ``null``);
    - ``source_assertion``: the one normalized Relationship/Sighting
      assertion block (PR 33D), otherwise explicit ``None`` — the key is
      never conditionally absent.

    Optional modeled fields use stable explicit ``None``; list fields use
    ``[]`` when absent; list source order is preserved; the original
    Indicator pattern is preserved exactly. No verdict, risk, attribution,
    or unapproved relationship semantics are synthesized.
    """
    source_value = source.source_value()
    return {
        "stix": build_stix_common_facts(source_value),
        "indicator": (
            build_stix_indicator_facts(source_value)
            if source_value["type"] == "indicator"
            else None
        ),
        "iocs": list(iocs),
        "cti_entity": cti_entity,
        "source_assertion": source_assertion,
    }


class Stix21ToEvidenceConverter(ToEvidenceConverter[Stix21Object]):
    """Semantic-format converter of validated STIX 2.1 objects to Evidence.

    Consumes only already-validated PR 33A ``Stix21Object`` values; it never
    re-parses raw JSON, never validates Bundle envelopes, never creates fake
    Bundles, and never duplicates ``parse_stix21_object()``. One supported
    object maps to exactly one ``ConvertedEvidence`` (a stable global
    ``THREAT_INTELLIGENCE`` ``Evidence`` plus its
    ``EvidenceObservationCandidate``); a valid unsupported object or
    Indicator pattern maps to zero Evidence. The converter is stateless,
    deterministic, pure, and performs no I/O or persistence.
    """

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Return the STIX 2.1 semantic format owned by this converter."""
        return SemanticFormatId.STIX_21

    def convert(
        self,
        source: Stix21Object,
        context: EvidenceConversionContext,
    ) -> tuple[ConvertedEvidence, ...]:
        """Convert one validated STIX object into zero or one ConvertedEvidence.

        Fail-closed guards: a non-``Stix21Object`` source and a context whose
        semantic format is not STIX 2.1 each raise a deterministic bounded
        :class:`ConversionError`. There is deliberately **no** fixed
        ``SourceId`` guard: STIX is a shared open semantic model and future
        TAXII sources may carry it under any ATI source namespace. Then the
        dispatch is exact: ``domain-name``/``ipv4-addr``/``ipv6-addr`` are
        direct SCOs, ``indicator`` goes through the whitelist adapter,
        ``relationship``/``sighting`` go through the PR 33D source-assertion
        builders, and every other valid type returns the empty tuple. A
        supported object emits exactly one Evidence whose deterministic PR
        28A identity is pinned to the STIX 2.1 semantic format, the context
        source namespace, and the **exact STIX ``id``** as
        ``source_record_id``; ``created``/``modified``/``valid_from`` and
        retrieval time never participate in that identity. A supported
        Relationship/Sighting with a different STIX object ID therefore
        yields a distinct Evidence identity even when the asserted semantic
        edge is the same. The observation candidate carries the
        credential-free source reference, ``observed_at=None`` (STIX
        timestamps including Relationship ``start_time``/``stop_time`` and
        Sighting ``first_seen``/``last_seen`` stay normalized source facts),
        the semantic retrieval time, normalized facts, and
        ``raw_payload=None``. No Investigation, subject, verdict,
        confidence, attribution, lifetime inference, observation version, or
        diff is synthesized.
        """
        if not isinstance(source, Stix21Object):
            raise ConversionError("STIX converter requires a validated STIX 2.1 object")
        semantic = context.semantic_source
        if semantic.semantic_format is not SemanticFormatId.STIX_21:
            raise ConversionError(
                "STIX converter requires a STIX 2.1 semantic-format context"
            )
        source_value = source.source_value()
        stix_type = source_value["type"]
        if stix_type == "relationship":
            source_assertion = build_stix_relationship_assertion(source_value)
        elif stix_type == "sighting":
            source_assertion = build_stix_sighting_assertion(source_value)
        else:
            source_assertion = None
        iocs = extract_stix_ioc_facts(source)
        cti_entity = (
            None
            if source_assertion is not None
            else build_stix_cti_entity_facts(source_value)
        )
        if not iocs and cti_entity is None and source_assertion is None:
            return ()
        evidence = Evidence(
            id=evidence_id_for_source_record(
                SemanticFormatId.STIX_21,
                semantic.source_id,
                source.id,
            ),
            type=EvidenceType.THREAT_INTELLIGENCE,
            source=semantic.source_id.value,
            source_record_id=source.id,
        )
        candidate = EvidenceObservationCandidate(
            evidence_id=evidence.id,
            source_url=semantic.source_reference,
            observed_at=None,
            retrieved_at=semantic.retrieved_at,
            facts=build_stix_normalized_facts(
                source, iocs, cti_entity, source_assertion
            ),
            raw_payload=None,
        )
        return (ConvertedEvidence(evidence=evidence, observation=candidate),)


def build_stix21_conversion_registry() -> ToEvidenceConverterRegistry:
    """Build the explicit production converter registry for STIX 2.1.

    A tiny explicit side-effect-free factory; no global mutable registry, no
    decorator registration, no import-time side effect, and no plugin
    discovery. Only the STIX 2.1 converter is registered, keyed exclusively
    by :class:`SemanticFormatId.STIX_21`; additional semantic-format
    converters are added here as they land.
    """
    return ToEvidenceConverterRegistry(converters=(Stix21ToEvidenceConverter(),))
