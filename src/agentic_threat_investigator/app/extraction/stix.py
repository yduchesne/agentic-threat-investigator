# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic STIX durable-Evidence entity extraction (PR 33C).

STIX collection Evidence has no natural provider invocation path; the
source-neutral durable extraction seam reconstructs the invocation target
from the normalized facts (``message_context.py``) exactly as the MISP
solution does, and this extractor consumes the durable ``EvidenceMessage``
facts, never raw :class:`Stix21Object` instances and never a STIX pattern
reparse.

Supported durable fact profiles:

- **CTI SDO Evidence** — ``facts.cti_entity`` is a validated
  represented-entity block, ``facts.iocs == []``: exactly one canonical CTI
  :class:`ExtractedEntity` (type, exact machine ID, source ``name`` as
  display metadata) and zero relationships.
- **PR 33B IOC Evidence** — ``facts.cti_entity is None`` and ``facts.iocs``
  is the ordered canonical IOC array (duplicates preserved by the
  converter): every represented canonical IOC identity becomes a discovered
  Entity in first-seen source order (the invocation identity, which leads
  the array, is emitted only by the message-context boundary), and zero
  relationships are inferred from co-occurrence.

Everything else — a malformed ``cti_entity`` block, an unknown CTI Entity
wire type, a non-canonical machine value, an invalid display name, a
malformed/non-canonical IOC, or a profile whose blocks disagree — fails
closed with :class:`EvidenceExtractionError` (``MALFORMED_FACTS``) with no
source value or name echoed. No ``created_by_ref``, alias, label, marking,
external reference, or other STIX reference field ever creates an Entity or
an edge (PR 33D owns source-asserted relationships/sightings).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionError,
    EvidenceExtractionView,
    ExtractedEntity,
    ExtractionResult,
    deduplicate_entities,
    malformed_facts,
    unsupported_evidence_type,
)
from agentic_threat_investigator.domain.entities import (
    CTI_ENTITY_DISPLAY_NAME_MAX_LENGTH,
    EntityType,
    canonicalize,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import EvidenceType

_STIX_IOC_TYPE_DOMAIN = EntityType.DOMAIN.value
_STIX_IOC_TYPE_IP_ADDRESS = EntityType.IP_ADDRESS.value
"""The exact durable STIX ``facts.iocs`` type vocabulary (PR 33B)."""

_STIX_CTI_ENTITY_TYPES_BY_WIRE: dict[str, EntityType] = {
    EntityType.THREAT_ACTOR.value: EntityType.THREAT_ACTOR,
    EntityType.CAMPAIGN.value: EntityType.CAMPAIGN,
    EntityType.INTRUSION_SET.value: EntityType.INTRUSION_SET,
    EntityType.TOOL.value: EntityType.TOOL,
    EntityType.INFRASTRUCTURE.value: EntityType.INFRASTRUCTURE,
}
"""Exact durable CTI Entity wire-value vocabulary (PR 33C).

Nothing is inferred from spelling; unknown wire values fail closed.
"""


def validate_stix_cti_entity_fact(fact: Any) -> tuple[EntityType, str, str]:
    """Validate one durable ``cti_entity`` fact and return its identity.

    Returns ``(entity_type, canonical machine value, display name)``. The
    fact must be an object carrying an exact allowed ATI CTI Entity wire
    ``type``, a ``value`` that canonicalizes byte-for-byte to itself, and a
    nonblank bounded string ``display_name``. Any violation raises
    :class:`ValueError`; the message is static and never echoes the fact
    content, so every caller can translate it into its own bounded error
    contract.
    """
    if not isinstance(fact, Mapping):
        raise ValueError("cti_entity fact must be an object")
    fact_type = fact.get("type")
    value = fact.get("value")
    display_name = fact.get("display_name")
    if not isinstance(fact_type, str) or not isinstance(value, str):
        raise ValueError("cti_entity fact carries invalid identity fields")
    entity_type = _STIX_CTI_ENTITY_TYPES_BY_WIRE.get(fact_type)
    if entity_type is None:
        raise ValueError("cti_entity fact carries an unknown entity type")
    if not isinstance(display_name, str) or not display_name.strip():
        raise ValueError("cti_entity fact requires a nonblank display name")
    if len(display_name) > CTI_ENTITY_DISPLAY_NAME_MAX_LENGTH:
        raise ValueError("cti_entity display name exceeds the bounded maximum")
    try:
        canonical = canonicalize(entity_type, value)
    except ValueError as exc:
        raise ValueError("cti_entity value is malformed") from exc
    if canonical != value:
        raise ValueError("cti_entity value is not in canonical form")
    return entity_type, canonical, display_name


def validate_stix_ioc_fact(ioc: Any) -> tuple[EntityType, str]:
    """Validate one durable STIX ``iocs`` fact and return its identity.

    Returns the canonical ``(entity_type, value)`` pair. ``type`` maps
    exactly to the durable PR 33B vocabulary (``domain`` ->
    ``EntityType.DOMAIN`` with the strict DNS validator, ``ip_address`` ->
    ``EntityType.IP_ADDRESS`` with the canonical IP helper); the durable
    value must already equal its canonical form. Any violation raises
    :class:`ValueError` with a static message.
    """
    if not isinstance(ioc, Mapping):
        raise ValueError("STIX ioc fact must be an object")
    ioc_type = ioc.get("type")
    value = ioc.get("value")
    if not isinstance(ioc_type, str) or not isinstance(value, str) or not value:
        raise ValueError("STIX ioc fact carries an invalid type or value")
    if ioc_type == _STIX_IOC_TYPE_DOMAIN:
        try:
            canonical = validate_dns_name(value)
        except ValueError as exc:
            raise ValueError("STIX ioc domain is malformed") from exc
        if canonical != value:
            raise ValueError("STIX ioc domain is not in canonical form")
        return EntityType.DOMAIN, canonical
    if ioc_type == _STIX_IOC_TYPE_IP_ADDRESS:
        try:
            canonical = canonicalize(EntityType.IP_ADDRESS, value)
        except ValueError as exc:
            raise ValueError("STIX ioc ip_address is malformed") from exc
        if canonical != value:
            raise ValueError("STIX ioc ip_address is not in canonical form")
        return EntityType.IP_ADDRESS, canonical
    raise ValueError("STIX ioc fact carries an unknown type")


def _malformed(source: str, evidence_id: UUID, message: str) -> EvidenceExtractionError:
    """Build a bounded malformed-facts extraction failure."""
    return malformed_facts(source, message, evidence_id=evidence_id)


def extract_stix(view: EvidenceExtractionView) -> ExtractionResult:
    """Extract the represented Entities of one durable STIX observation.

    Revalidates the durable normalized facts defensively (never the raw
    STIX object and never a pattern reparse) and returns one canonical CTI
    Entity for a CTI SDO, or every additional represented IOC identity for
    PR 33B IOC Evidence. The invocation identity is provided by the
    message-context boundary and leads the IOC array; the extractor returns
    the remaining ordered identities (first-seen deduplicated) so multiple
    Indicator leaves associate all represented Entities without inferred
    edges. Relationships are always empty and malformed facts fail the whole
    observation.
    """
    evidence_id = view.evidence.id
    source = view.evidence.source
    if view.evidence.type is not EvidenceType.THREAT_INTELLIGENCE:
        raise unsupported_evidence_type(
            source,
            "STIX evidence type is not supported for extraction",
            evidence_id=evidence_id,
        )
    facts = view.observation.facts
    cti_entity = facts.get("cti_entity")
    if cti_entity is not None:
        iocs = facts.get("iocs")
        if not isinstance(iocs, (list, tuple)) or iocs:
            raise _malformed(
                source, evidence_id, "STIX CTI evidence must carry an empty iocs array"
            )
        try:
            entity_type, value, display_name = validate_stix_cti_entity_fact(cti_entity)
        except ValueError as exc:
            raise _malformed(
                source, evidence_id, "STIX cti_entity facts are malformed"
            ) from exc
        entity = ExtractedEntity(
            type=entity_type, value=value, display_name=display_name
        )
        return ExtractionResult(entities=(entity,), relationships=())

    iocs = facts.get("iocs")
    if not isinstance(iocs, (list, tuple)) or not iocs:
        raise _malformed(source, evidence_id, "STIX evidence must carry validated iocs")
    identities: list[tuple[EntityType, str]] = []
    for ioc in iocs:
        try:
            identities.append(validate_stix_ioc_fact(ioc))
        except ValueError as exc:
            raise _malformed(
                source, evidence_id, "STIX ioc facts are malformed"
            ) from exc
    invocation = (view.invocation_entity.type, view.invocation_entity.value)
    if identities[0] != invocation:
        raise _malformed(
            source,
            evidence_id,
            "STIX iocs do not lead with the invocation identity",
        )
    additional = [
        ExtractedEntity(type=entity_type, value=value)
        for entity_type, value in identities[1:]
    ]
    return ExtractionResult(
        entities=deduplicate_entities(additional),
        relationships=(),
    )
