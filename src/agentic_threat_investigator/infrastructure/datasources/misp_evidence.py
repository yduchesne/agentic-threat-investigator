# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Native MISP semantic-format Evidence conversion (PR 32B).

Owns the pure :class:`MispToEvidenceConverter` for the
``urn:ati:datasource:semanticformat:misp`` semantic format plus the
MISP-specific fact builders and normalization helpers. The semantic parser
(``misp_semantics.py``) remains source validation only and constructs no
Evidence; this module consumes only already-validated
:class:`MispAttributeRecord` / :class:`MispObjectRecord` values.

The converter maps one supported Event-level :class:`MispAttributeRecord`
plus the explicit :class:`EvidenceConversionContext` to exactly one
:class:`ConvertedEvidence`: a stable global ``THREAT_INTELLIGENCE``
:class:`Evidence` whose deterministic PR 28A identity is pinned to
``semantic_format=MISP``, ``source=MISP`` and
``source_record_id=str(attribute.uuid)``, plus an
:class:`EvidenceObservationCandidate` carrying the credential-free source
reference, the exact Attribute source timestamp as ``observed_at``, the
acquisition retrieval time, normalized Event/Attribute/IOC facts, and
``raw_payload=None``.

Supported MISP IOC profile (exact type names only, never substring/similarity
inference):

- ``domain`` / ``hostname`` -> one canonical DOMAIN IOC;
- ``ip-src`` / ``ip-dst`` -> one canonical IP_ADDRESS IOC (IPv4 + IPv6);
- ``domain|ip`` -> exactly one Evidence carrying two ordered IOC facts
  (DOMAIN then IP_ADDRESS); component identities are never fabricated.

Attribute value canonicalization reuses the existing source-neutral
canonicalizers ``validate_dns_name`` and ``canonicalize_ip_address``. A
supported Attribute whose value fails canonicalization or the exact
two-component ``domain|ip`` form raises a bounded
:class:`ConversionError`. A valid unsupported Attribute type and every
:class:`MispObjectRecord` deterministically produce zero Evidence (Objects
are never flattened). ``deleted``/``to_ids``/``distribution``/
``sharing_group_id``/tags are preserved as source facts, never interpreted
as verdict, authorization, or policy. The converter performs no I/O, no
persistence, no clock/random reads, no secret lookup, never allocates an
observation version, and never synthesizes verdicts, confidence,
attribution, or relationships.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

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
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.misp_semantics import (
    MispAttribute,
    MispAttributeRecord,
    MispEventContext,
    MispObjectRecord,
    MispSemanticRecord,
)

__all__ = [
    "MispToEvidenceConverter",
    "SUPPORTED_MISP_IOC_TYPES",
    "build_misp_attribute_facts",
    "build_misp_conversion_registry",
    "build_misp_event_facts",
    "build_misp_normalized_facts",
    "extract_misp_ioc_facts",
    "format_misp_fact_timestamp",
]

SUPPORTED_MISP_IOC_TYPES: frozenset[str] = frozenset(
    {"domain", "hostname", "ip-src", "ip-dst", "domain|ip"}
)
"""Exact MISP Attribute types that produce canonical IOC facts.

Membership is deliberate and total: no substring, similarity, or fallback
inference is ever applied, so valid-but-unsupported types (``url``,
hashes, filenames, email, ports, AS, certificate types, ...) yield zero
Evidence.
"""

_COMPOUND_DOMAIN_IP_TYPE = "domain|ip"
"""The only supported compound MISP Attribute type."""


def format_misp_fact_timestamp(value: datetime) -> str:
    """Format an already validated timezone-aware UTC datetime as ``...Z``.

    Normalized MISP fact timestamps use the canonical UTC ISO 8601 form
    ending in ``Z``, for example ``2023-11-14T22:13:20Z``. Attribute/Event
    source timestamps are already UTC-aware from the PR 32A parser; the
    formatter never re-derives or substitutes timestamps.
    """
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_misp_domain(value: str) -> str:
    """Canonicalize one MISP DOMAIN/IOC component with the strict helper.

    Reuses the existing ``validate_dns_name`` contract; a canonicalization
    failure for an otherwise supported MISP type is a bounded local
    :class:`ConversionError`, never a silent pass-through.
    """
    try:
        return validate_dns_name(value)
    except ValueError as exc:
        raise ConversionError(
            "MISP domain value failed strict DNS canonicalization"
        ) from exc


def _canonical_misp_ip(value: str) -> str:
    """Canonicalize one MISP IP IOC component with the existing helper.

    Reuses the existing ``canonicalize_ip_address`` contract so IPv4 and
    IPv6 both normalize (for example IPv6 is rebuilt to its canonical
    compressed representation). A failure is a bounded local
    :class:`ConversionError`.
    """
    try:
        return canonicalize_ip_address(value)
    except ValueError as exc:
        raise ConversionError(
            "MISP IP value failed canonical IP normalization"
        ) from exc


def _extract_domain_ip_iocs(value: str) -> tuple[dict[str, str], ...]:
    """Parse the exact two-component ``domain|ip`` source value.

    Requires exactly two nonempty components separated by exactly one
    literal ``|``. Component 0 is canonicalized as DOMAIN and component 1 as
    IP_ADDRESS, independently; a missing/extra/blank/invalid component is a
    bounded :class:`ConversionError`. No generic composite-type parsing and
    no fabricated component identities are applied: the value stays one
    Evidence identity with two ordered IOC facts.
    """
    parts = value.split("|")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ConversionError(
            "compound MISP domain|ip value must have exactly two nonempty components"
        )
    domain_value, ip_value = parts
    return (
        {
            "type": EntityType.DOMAIN.value,
            "value": _canonical_misp_domain(domain_value),
        },
        {
            "type": EntityType.IP_ADDRESS.value,
            "value": _canonical_misp_ip(ip_value),
        },
    )


def extract_misp_ioc_facts(
    attribute: MispAttribute,
) -> tuple[dict[str, str], ...]:
    """Extract canonical entity-eligible IOC facts for one Attribute.

    Exact type dispatch over the supported MISP IOC profile only: the four
    single-IOC types produce one ordered fact each and ``domain|ip`` exactly
    two (DOMAIN then IP_ADDRESS). A valid unsupported type returns the empty
    tuple; a supported type whose value is malformed raises a bounded
    :class:`ConversionError`. Facts contain only canonical entity-eligible
    values and carry no analysis, verdict, or risk semantics.
    """
    attribute_type = attribute.type
    if attribute_type in ("domain", "hostname"):
        return (
            {
                "type": EntityType.DOMAIN.value,
                "value": _canonical_misp_domain(attribute.value),
            },
        )
    if attribute_type in ("ip-src", "ip-dst"):
        return (
            {
                "type": EntityType.IP_ADDRESS.value,
                "value": _canonical_misp_ip(attribute.value),
            },
        )
    if attribute_type == _COMPOUND_DOMAIN_IP_TYPE:
        return _extract_domain_ip_iocs(attribute.value)
    return ()


def build_misp_event_facts(event: MispEventContext) -> dict[str, Any]:
    """Build the normalized Event fact object for one MISP Attribute record.

    Preserves Event UUID, ``info``, UTC ``Z`` timestamp, ``published``,
    ``publish_timestamp``, ``extends_uuid``, distribution, sharing-group
    state, and ordered tag names. Optional modeled fields use stable
    explicit ``None``; local MISP numeric IDs never appear.
    """
    return {
        "uuid": str(event.uuid),
        "info": event.info,
        "timestamp": format_misp_fact_timestamp(event.timestamp),
        "published": event.published,
        "publish_timestamp": (
            None
            if event.publish_timestamp is None
            else format_misp_fact_timestamp(event.publish_timestamp)
        ),
        "extends_uuid": (
            None if event.extends_uuid is None else str(event.extends_uuid)
        ),
        "distribution": event.distribution,
        "sharing_group_id": event.sharing_group_id,
        "tags": [tag.name for tag in event.tags],
    }


def build_misp_attribute_facts(attribute: MispAttribute) -> dict[str, Any]:
    """Build the normalized Attribute fact object for one MISP Attribute.

    Preserves Attribute UUID, type, category, **original source value**,
    UTC ``Z`` timestamp, ``to_ids``, ``deleted``, distribution,
    sharing-group state, comment, ``object_relation``, and ordered tag
    names. Optional modeled fields use stable explicit ``None``; binary
    ``data`` and local MISP numeric IDs never appear. No verdict, risk,
    attribution, or relationship semantics are synthesized.
    """
    return {
        "uuid": str(attribute.uuid),
        "type": attribute.type,
        "category": attribute.category,
        "value": attribute.value,
        "timestamp": format_misp_fact_timestamp(attribute.timestamp),
        "to_ids": attribute.to_ids,
        "deleted": attribute.deleted,
        "distribution": attribute.distribution,
        "sharing_group_id": attribute.sharing_group_id,
        "comment": attribute.comment,
        "object_relation": attribute.object_relation,
        "tags": [tag.name for tag in attribute.tags],
    }


def build_misp_normalized_facts(
    record: MispAttributeRecord,
) -> dict[str, Any]:
    """Build the stable normalized Event/Attribute/IOC fact object.

    One stable shape for every supported Attribute, composing
    :func:`build_misp_event_facts` and :func:`build_misp_attribute_facts`
    with the canonical ``iocs`` list:

    - ``event`` and ``attribute`` preserve the exact source/provenance and
      handling metadata (see the two builders);
    - ``iocs``: only canonical entity-eligible values as ordered
      ``{"type", "value"}`` objects.

    Optional modeled fields use stable explicit ``None``. Tags are plain
    ordered tag-name lists; TLP/PAP/taxonomy/Galaxy are never interpreted.
    Local MISP numeric IDs and binary ``data`` never appear. No verdict,
    risk, attribution, or relationship semantics are synthesized.
    """
    return {
        "event": build_misp_event_facts(record.event),
        "attribute": build_misp_attribute_facts(record.attribute),
        "iocs": list(extract_misp_ioc_facts(record.attribute)),
    }


class MispToEvidenceConverter(ToEvidenceConverter[MispSemanticRecord]):
    """Semantic-format converter of validated MISP records to Evidence.

    Consumes only already-validated PR 32A MISP semantic records; it never
    re-parses raw JSON or re-runs semantic validation. One supported
    Event-level ``MispAttributeRecord`` maps to exactly one
    ``ConvertedEvidence`` (a stable global ``THREAT_INTELLIGENCE``
    ``Evidence`` plus its ``EvidenceObservationCandidate``); a valid
    unsupported Attribute and every ``MispObjectRecord`` map to zero
    Evidence. The converter is stateless, deterministic, pure, and performs
    no I/O or persistence.
    """

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Return the MISP semantic format owned by this converter."""
        return SemanticFormatId.MISP

    def convert(
        self,
        source: MispSemanticRecord,
        context: EvidenceConversionContext,
    ) -> tuple[ConvertedEvidence, ...]:
        """Convert one validated MISP record into zero or one ConvertedEvidence.

        Fail-closed guards: a non-MISP source object and a context whose
        semantic format is not MISP each raise a deterministic
        :class:`ConversionError`; defense-in-depth provenance requires the
        context's source identity to be :data:`SourceId.MISP`. A valid
        :class:`MispObjectRecord` and a valid unsupported Attribute type
        return the empty tuple. For a supported Event-level Attribute the
        emitted Evidence carries the deterministic PR 28A identity pinned to
        the MISP semantic format, source namespace, and the exact upstream
        ``source_record_id`` (``str(attribute.uuid)`` — never the value,
        which is content, not identity). The observation candidate carries
        the credential-free source reference, the exact Attribute source
        timestamp as ``observed_at``, the semantic retrieval time,
        normalized facts, and ``raw_payload=None``. No Investigation,
        subject, verdict, confidence, attribution, relationship, observation
        version, or diff is synthesized.
        """
        if not isinstance(source, (MispAttributeRecord, MispObjectRecord)):
            raise ConversionError(
                "MISP converter requires a validated MISP semantic record"
            )
        semantic = context.semantic_source
        if semantic.semantic_format is not SemanticFormatId.MISP:
            raise ConversionError(
                "MISP converter requires a MISP semantic-format context"
            )
        if semantic.source_id is not SourceId.MISP:
            raise ConversionError(
                "MISP converter requires the MISP source identity in context"
            )
        if isinstance(source, MispObjectRecord):
            return ()
        iocs = extract_misp_ioc_facts(source.attribute)
        if not iocs:
            return ()
        evidence = Evidence(
            id=evidence_id_for_source_record(
                SemanticFormatId.MISP,
                semantic.source_id,
                str(source.attribute.uuid),
            ),
            type=EvidenceType.THREAT_INTELLIGENCE,
            source=semantic.source_id.value,
            source_record_id=str(source.attribute.uuid),
        )
        candidate = EvidenceObservationCandidate(
            evidence_id=evidence.id,
            source_url=semantic.source_reference,
            observed_at=source.attribute.timestamp,
            retrieved_at=semantic.retrieved_at,
            facts=build_misp_normalized_facts(source),
            raw_payload=None,
        )
        return (ConvertedEvidence(evidence=evidence, observation=candidate),)


def build_misp_conversion_registry() -> ToEvidenceConverterRegistry:
    """Build the explicit production converter registry for MISP.

    A tiny explicit side-effect-free factory; no global mutable registry, no
    decorator registration, no import-time side effect, and no plugin
    discovery. Only the MISP converter is registered, keyed exclusively by
    :class:`SemanticFormatId.MISP`; additional semantic-format converters
    are added here as they land.
    """
    return ToEvidenceConverterRegistry(converters=(MispToEvidenceConverter(),))
