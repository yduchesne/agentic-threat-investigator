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
- every other valid STIX object and every valid-but-unsupported Indicator
  pattern -> zero Evidence (a valid no-result, never a failure).

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
source identities).
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
    EntityType,
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
    "build_stix21_conversion_registry",
    "build_stix_common_facts",
    "build_stix_indicator_facts",
    "build_stix_normalized_facts",
    "extract_stix_ioc_facts",
]

_STIX_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
"""Canonical UTC ``Z`` fact form for normalized STIX timestamps.

Mirrors the established MISP fact-timestamp format contract so STIX and
MISP normalized timestamps render identically.
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


def build_stix_normalized_facts(
    source: Stix21Object, iocs: tuple[dict[str, str], ...]
) -> dict[str, Any]:
    """Build the stable normalized STIX/IOC fact object for one supported object.

    One stable shape:

    - ``stix``: the common selected STIX metadata (see
      :func:`build_stix_common_facts`);
    - ``indicator``: the normalized Indicator block for an ``indicator``
      source, otherwise ``None``;
    - ``iocs``: canonical entity-eligible values as ordered
      ``{"type", "value"}`` objects.

    Optional modeled fields use stable explicit ``None``; list fields use
    ``[]`` when absent; list source order is preserved; the original
    Indicator pattern is preserved exactly. No verdict, risk, attribution,
    or relationship semantics are synthesized.
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
        direct SCOs, ``indicator`` goes through the whitelist adapter, and
        every other valid type returns the empty tuple. A supported object
        emits exactly one Evidence whose deterministic PR 28A identity is
        pinned to the STIX 2.1 semantic format, the context source
        namespace, and the **exact STIX ``id``** as ``source_record_id``;
        ``created``/``modified``/``valid_from`` and retrieval time never
        participate in that identity. The observation candidate carries the
        credential-free source reference, ``observed_at=None`` (STIX
        timestamps stay normalized source facts), the semantic retrieval
        time, normalized facts, and ``raw_payload=None``. No Investigation,
        subject, verdict, confidence, attribution, relationship, observation
        version, or diff is synthesized.
        """
        if not isinstance(source, Stix21Object):
            raise ConversionError("STIX converter requires a validated STIX 2.1 object")
        semantic = context.semantic_source
        if semantic.semantic_format is not SemanticFormatId.STIX_21:
            raise ConversionError(
                "STIX converter requires a STIX 2.1 semantic-format context"
            )
        iocs = extract_stix_ioc_facts(source)
        if not iocs:
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
            facts=build_stix_normalized_facts(source, iocs),
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
