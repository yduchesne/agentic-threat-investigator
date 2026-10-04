# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic STIX durable-Evidence entity extraction (PR 33C/33D).

STIX collection Evidence has no natural provider invocation path; the
source-neutral durable extraction seam reconstructs the invocation target
from the normalized facts (``message_context.py``) exactly as the MISP
solution does, and this extractor consumes the durable ``EvidenceMessage``
facts, never raw :class:`Stix21Object` instances and never a STIX pattern
reparse.

Supported durable fact profiles:

- **PR 33D source-assertion Evidence** — ``facts.source_assertion`` is a
  validated normalized Relationship or Sighting assertion block (with an
  empty ``iocs`` array and no ``cti_entity``): a Relationship assertion
  yields exactly the source and target endpoint Entities (first-seen order)
  and exactly one approved :class:`RelationshipAssertion`; a Sighting
  assertion yields exactly the sighted CTI Entity and zero relationships.
  The durable fact revalidation is defensive: the assertion body must be
  well formed, the STIX relationship string / ATI relationship type /
  endpoint Entity types must still match the exact approved profile, a
  self-edge is malformed, `where_sighted_refs`/`observed_data_refs`
  never produce Entities or edges, and nothing is trusted merely because
  the converter once produced it.
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

Everything else — a malformed assertion block, a contradiction between
profiles (an assertion combined with ``cti_entity`` or ``iocs``), a
malformed ``cti_entity`` block, an unknown CTI Entity wire type, a
non-canonical machine value, an invalid display name, a malformed/
non-canonical IOC, or a profile whose blocks disagree — fails closed with
:class:`EvidenceExtractionError` (``MALFORMED_FACTS``) with no source value
or name echoed. No ``created_by_ref``, alias, label, marking, external
reference, Sighting reference-list member, or other non-assertion STIX
reference field ever creates an Entity or an edge.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.extraction.models import (
    EntityIdentity,
    EvidenceExtractionError,
    EvidenceExtractionView,
    ExtractedEntity,
    ExtractionResult,
    RelationshipAssertion,
    deduplicate_assertions,
    deduplicate_entities,
    malformed_facts,
    unsupported_evidence_type,
)
from agentic_threat_investigator.app.extraction.source_assertion import (
    validate_relationship_body,
    validate_sighting_body,
)
from agentic_threat_investigator.domain.entities import (
    CTI_ENTITY_DISPLAY_NAME_MAX_LENGTH,
    EntityType,
    canonicalize,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType

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

Nothing is inferred from spelling; unknown wire values fail closed. The
source-neutral :mod:`source_assertion` seam owns the same vocabulary for
assertion endpoints.
"""

STIX_RELATIONSHIP_PROFILE: dict[
    str, tuple[RelationshipType, frozenset[EntityType], frozenset[EntityType]]
] = {
    "uses": (
        RelationshipType.USES,
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
        RelationshipType.TARGETS,
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
        RelationshipType.ATTRIBUTED_TO,
        frozenset({EntityType.CAMPAIGN, EntityType.INTRUSION_SET}),
        frozenset({EntityType.THREAT_ACTOR}),
    ),
    "controls": (
        RelationshipType.CONTROLS,
        frozenset({EntityType.THREAT_ACTOR, EntityType.INTRUSION_SET}),
        frozenset({EntityType.INFRASTRUCTURE}),
    ),
}
"""The exact approved PR 33D STIX Relationship profile (durable side).

Mirrors ``infrastructure.datasources.stix21_evidence.STIX_RELATIONSHIP_PROFILE``
(the conversion-side table) so the extractor can cross-validate the durable
``(stix type, ATI type, endpoint Entity types)`` triple against the same
profile; a regression test pins the two tables to each other. Unsupported
STIX relationship strings and endpoint pairs never map to an existing ATI
relationship URN.
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


def _extract_relationship_assertion_fact(
    source: str,
    evidence_id: UUID,
    body: Mapping[str, Any],
) -> ExtractionResult:
    """Extract one validated durable Relationship assertion fact.

    Revalidates the durable body, cross-checks the exact approved profile
    (§5.3: STIX relationship string, ATI relationship type, and endpoint
    Entity types must all agree), rejects a self-edge, and returns the two
    canonical endpoint Entities (first-seen source order) plus exactly one
    :class:`RelationshipAssertion` preserved in source-asserted direction
    (source -> target). A tampered durable fact (for example
    ``{"type": "uses", "ati_type": "...targets"}``) fails closed with
    ``MALFORMED_FACTS`` and never echoes fact content.
    """
    try:
        assertion = validate_relationship_body(dict(body))
    except ValueError as exc:
        raise _malformed(
            source, evidence_id, "STIX relationship assertion facts are malformed"
        ) from exc
    relationship_type = assertion.stix_type
    ati_type = assertion.ati_type
    source_type, source_value = assertion.source
    target_type, target_value = assertion.target
    if (source_type, source_value) == (target_type, target_value):
        raise _malformed(source, evidence_id, "STIX relationship asserts a self-edge")
    profile = STIX_RELATIONSHIP_PROFILE.get(relationship_type)
    if profile is None:
        raise _malformed(
            source,
            evidence_id,
            "STIX relationship type is not in the supported profile",
        )
    expected_ati_type, source_types, target_types = profile
    if ati_type != expected_ati_type:
        raise _malformed(
            source, evidence_id, "STIX relationship mapping is inconsistent"
        )
    if source_type not in source_types or target_type not in target_types:
        raise _malformed(
            source,
            evidence_id,
            "STIX relationship endpoint types are inconsistent",
        )
    return ExtractionResult(
        entities=deduplicate_entities(
            (
                ExtractedEntity(type=source_type, value=source_value),
                ExtractedEntity(type=target_type, value=target_value),
            )
        ),
        relationships=deduplicate_assertions(
            (
                RelationshipAssertion(
                    source=EntityIdentity(type=source_type, value=source_value),
                    type=ati_type,
                    target=EntityIdentity(type=target_type, value=target_value),
                ),
            )
        ),
    )


def _extract_sighting_assertion_fact(
    source: str,
    evidence_id: UUID,
    body: Mapping[str, Any],
) -> ExtractionResult:
    """Extract one validated durable Sighting assertion fact.

    Revalidates the durable body and returns exactly the sighted CTI Entity
    with **zero** relationship assertions: ``where_sighted_refs`` /
    ``observed_data_refs`` are provenance facts and never fabricate an
    edge or Entity (plan §1.7).
    """
    try:
        sighting = validate_sighting_body(dict(body))
    except ValueError as exc:
        raise _malformed(
            source, evidence_id, "STIX sighting assertion facts are malformed"
        ) from exc
    sighted_type, sighted_value = sighting.sighting_of
    return ExtractionResult(
        entities=(ExtractedEntity(type=sighted_type, value=sighted_value),),
        relationships=(),
    )


def _extract_source_assertion(
    view: EvidenceExtractionView,
    facts: Mapping[str, Any],
) -> ExtractionResult:
    """Extract one durable normalized source-assertion fact (PR 33D).

    The assertion profile is mutually exclusive with the CTI/IOC profiles:
    an assertion Evidence must carry ``cti_entity is None`` and an empty
    ``iocs`` array. The assertion ``kind`` dispatches to the Relationship or
    Sighting extractors; an unknown kind or a mismatched relationship/
    sighting body pair fails closed.
    """
    evidence_id = view.evidence.id
    source = view.evidence.source
    if facts.get("cti_entity") is not None:
        raise _malformed(
            source, evidence_id, "STIX assertion evidence cannot carry cti_entity"
        )
    iocs = facts.get("iocs")
    if not isinstance(iocs, (list, tuple)) or iocs:
        raise _malformed(
            source,
            evidence_id,
            "STIX assertion evidence must carry an empty iocs array",
        )
    source_assertion = facts.get("source_assertion")
    if not isinstance(source_assertion, Mapping):
        raise _malformed(
            source, evidence_id, "STIX source assertion facts are malformed"
        )
    kind = source_assertion.get("kind")
    if kind == "relationship":
        if source_assertion.get("sighting") is not None:
            raise _malformed(
                source,
                evidence_id,
                "STIX relationship assertion carries a sighting body",
            )
        body = source_assertion.get("relationship")
        if not isinstance(body, Mapping):
            raise _malformed(
                source, evidence_id, "STIX relationship assertion body is missing"
            )
        return _extract_relationship_assertion_fact(source, evidence_id, body)
    if kind == "sighting":
        if source_assertion.get("relationship") is not None:
            raise _malformed(
                source,
                evidence_id,
                "STIX sighting assertion carries a relationship body",
            )
        body = source_assertion.get("sighting")
        if not isinstance(body, Mapping):
            raise _malformed(
                source, evidence_id, "STIX sighting assertion body is missing"
            )
        return _extract_sighting_assertion_fact(source, evidence_id, body)
    raise _malformed(
        source, evidence_id, "STIX source assertion carries an unknown kind"
    )


def extract_stix(view: EvidenceExtractionView) -> ExtractionResult:
    """Extract the represented Entities of one durable STIX observation.

    Revalidates the durable normalized facts defensively (never the raw
    STIX object and never a pattern reparse). A PR 33D source-assertion
    block produces its endpoint/assertion output; a represented ``cti_entity``
    produces one canonical CTI Entity; PR 33B IOC evidence produces the
    additional represented IOC identities. The invocation identity is
    provided by the message-context boundary and leads the IOC array; the
    extractor returns the remaining ordered identities (first-seen
    deduplicated) so multiple Indicator leaves associate all represented
    Entities without inferred edges. Malformed facts fail the whole
    observation with ``MALFORMED_FACTS``.
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
    if facts.get("source_assertion") is not None:
        return _extract_source_assertion(view, facts)
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
