# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic MISP IOC observation association (PR 32D).

MISP durable evidence never produces Relationship assertions and never
infers relationships from IOC co-occurrence: a ``domain|ip`` Attribute is
one Evidence item with two represented IOC Entities and zero edges. The
transient invocation Entity (the first ordered ``facts.iocs`` entry,
DOMAIN for ``domain|ip``, established by the message-context boundary) is
execution context only; this extractor validates the normalized facts and
returns the **additional** represented IOC identities as discovered
Entities:

    Facts                    Entities                Relationships
    ------------------------ ----------------------- -------------
    domain                   ()                      ()
    hostname-produced        ()                      ()
    IPv4                     ()                      ()
    IPv6                     ()                      ()
    domain + ip_address      (IP_ADDRESS,)           ()

No tag, category, distribution, sharing-group, ``to_ids``, or ``deleted``
field ever creates an Entity or Relationship. The extractor is pure and
synchronous: no I/O, no persistence, no database, no provider call. It
performs the same fail-closed canonical validation as the message-context
boundary, so anything outside the documented normalized shape is a typed
contract failure rather than a silent guess.
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
    validate_extractor_input,
)
from agentic_threat_investigator.domain.entities import (
    EntityType,
    canonicalize,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId

_MISP_IOC_TYPE_DOMAIN = EntityType.DOMAIN.value
_MISP_IOC_TYPE_IP_ADDRESS = EntityType.IP_ADDRESS.value
"""The exact durable MISP ``facts.iocs`` type vocabulary (PR 32B)."""


def extract_misp(view: EvidenceExtractionView) -> ExtractionResult:
    """Extract the additional represented MISP IOC Entities of one observation.

    Validates the extractor contract (MISP source + ``THREAT_INTELLIGENCE``
    evidence, DOMAIN/IP_ADDRESS invocation subject), revalidates the durable
    ``facts.iocs`` array exactly as the message-context boundary does
    (non-empty object entries, canonical ``domain``/``ip_address`` values,
    distinct identities), requires the invocation identity to lead the
    array, and returns every remaining IOC identity as a canonical
    discovered Entity. Relationships are always empty: co-occurrence is
    source fact, never an inferred edge. Failures are typed
    :class:`EvidenceExtractionError` values that fail the whole observation.
    """
    evidence_id = view.evidence.id
    validate_extractor_input(
        view,
        source=SourceId.MISP.value,
        evidence_type=EvidenceType.THREAT_INTELLIGENCE,
        subject_types=(EntityType.DOMAIN, EntityType.IP_ADDRESS),
    )
    identities = _validated_ioc_identities(
        view.observation.facts.get("iocs"), evidence_id
    )
    invocation = (view.invocation_entity.type, view.invocation_entity.value)
    if not identities or identities[0] != invocation:
        raise _malformed(
            evidence_id, "MISP iocs do not lead with the invocation identity"
        )
    additional = [
        ExtractedEntity(type=entity_type, value=value)
        for entity_type, value in identities[1:]
    ]
    return ExtractionResult(
        entities=deduplicate_entities(additional),
        relationships=(),
    )


def _malformed(evidence_id: UUID, message: str) -> EvidenceExtractionError:
    """Build the MISP extraction error with the bounded safe context."""
    return malformed_facts(SourceId.MISP.value, message, evidence_id=evidence_id)


def _validated_ioc_identities(
    iocs: Any, evidence_id: UUID
) -> tuple[tuple[EntityType, str], ...]:
    """Validate the durable ``facts.iocs`` array and return ordered identities.

    Mirrors the message-context boundary: a non-empty array of objects, each
    carrying a supported ``type`` and an already-canonical value, with
    distinct identities. Any violation fails closed.
    """
    if not isinstance(iocs, (list, tuple)) or not iocs:
        raise _malformed(evidence_id, "MISP evidence must carry validated iocs")
    identities: list[tuple[EntityType, str]] = []
    for ioc in iocs:
        identities.append(_ioc_identity(ioc, evidence_id))
    if len(set(identities)) != len(identities):
        raise _malformed(evidence_id, "MISP iocs repeat an entity identity")
    return tuple(identities)


def _ioc_identity(ioc: Any, evidence_id: UUID) -> tuple[EntityType, str]:
    """Derive one canonical MISP IOC identity, failing closed on violations."""
    if not isinstance(ioc, Mapping):
        raise _malformed(evidence_id, "MISP ioc must be an object")
    ioc_type = ioc.get("type")
    value = ioc.get("value")
    if not isinstance(ioc_type, str) or not isinstance(value, str) or not value:
        raise _malformed(evidence_id, "MISP ioc carries an invalid type or value")
    if ioc_type == _MISP_IOC_TYPE_DOMAIN:
        try:
            canonical = validate_dns_name(value)
        except ValueError as exc:
            raise _malformed(evidence_id, "MISP ioc domain is malformed") from exc
        if canonical != value:
            raise _malformed(evidence_id, "MISP ioc domain is not in canonical form")
        return EntityType.DOMAIN, canonical
    if ioc_type == _MISP_IOC_TYPE_IP_ADDRESS:
        try:
            canonical = canonicalize(EntityType.IP_ADDRESS, value)
        except ValueError as exc:
            raise _malformed(evidence_id, "MISP ioc ip_address is malformed") from exc
        if canonical != value:
            raise _malformed(
                evidence_id, "MISP ioc ip_address is not in canonical form"
            )
        return EntityType.IP_ADDRESS, canonical
    raise _malformed(evidence_id, "MISP ioc carries an unknown type")
