# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Conservative RDAP extraction.

Implements the documented conservative RDAP extraction matrix. The RDAP
source envelope (persisted Evidence ID, canonical subject, and object-class
pairing) is validated on every registered branch before any empty return.

Only IP-subject RDAP network evidence participates in PR 18B extraction:
when the normalized ``cidr0_cidrs`` facts supply explicit prefixes, each
prefix is canonicalized, verified to match the subject address family and to
contain the subject address, discovered as a ``NETWORK_PREFIX`` entity, and
asserted as the subject IP ``BELONGS_TO`` the prefix. The relationship
source is always the validated canonical subject value, never the original
unchecked string.

No prefix is ever synthesized from arbitrary ``start_address``/``end_address``
ranges. RDAP handles, display names, and related-entity references never
become ORGANIZATION entities or REGISTERED_TO/OPERATED_BY/ANNOUNCED_BY
assertions, and RDAP domain nameserver facts produce no extraction. Domain
and ASN RDAP evidence (``REGISTRATION``) validates its envelope and then
returns an empty result in PR 18B.
"""

import ipaddress
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.extraction.models import (
    EntityIdentity,
    EvidenceExtractionError,
    ExtractedEntity,
    ExtractionResult,
    RelationshipAssertion,
    deduplicate_assertions,
    deduplicate_entities,
    malformed_facts,
    unsupported_evidence_type,
    validate_extractor_input,
)
from agentic_threat_investigator.domain.entities import (
    EntityType,
    canonicalize_asn,
    canonicalize_ip_address,
    canonicalize_network_prefix,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.relationships import RelationshipType

_NETWORK_OBJECT_CLASS = "ip network"
_DOMAIN_OBJECT_CLASS = "domain"
_AUTNUM_OBJECT_CLASS = "autnum"


def extract_rdap(evidence: Evidence) -> ExtractionResult:
    """Extract the documented conservative RDAP output from one Evidence.

    Both registered RDAP branches require a persisted Evidence ID, a
    canonical subject of the expected type, and the object-class pairing
    promised by the provider, and then return conservative output: an empty
    result for ``REGISTRATION`` (domain and ASN objects) and explicit-prefix
    ``BELONGS_TO`` extraction for IP-network evidence.
    """
    if evidence.source != SourceId.RDAP.value:
        raise unsupported_evidence_type(
            evidence.source,
            "evidence source/type does not match the extractor contract",
            evidence_id=evidence.id,
        )
    if evidence.type is EvidenceType.REGISTRATION:
        return _validated_registration(evidence)
    if evidence.type is not EvidenceType.NETWORK:
        raise unsupported_evidence_type(
            evidence.source,
            "RDAP extraction supports only network and registration evidence",
            evidence_id=evidence.id,
        )
    evidence_id = validate_extractor_input(
        evidence,
        source=SourceId.RDAP.value,
        evidence_type=EvidenceType.NETWORK,
        subject_types=(EntityType.IP_ADDRESS,),
    )
    return _extract_ip_network(evidence, evidence_id)


def _validated_registration(evidence: Evidence) -> ExtractionResult:
    """Validate the registration envelope and return an empty result.

    Only canonical DOMAIN and ASN subjects with their promised object-class
    pairing are accepted; nothing from nameservers, handles, entities, roles,
    or display names is inspected for graph output.
    """
    if evidence.subject.type not in (EntityType.DOMAIN, EntityType.ASN):
        raise _malformed(
            evidence.id,
            "RDAP registration evidence requires a DOMAIN or ASN subject",
        )
    if evidence.subject.type is EntityType.DOMAIN:
        try:
            canonical_subject = validate_dns_name(evidence.subject.value)
        except (ValueError, UnicodeError) as exc:
            raise _malformed(
                evidence.id, "RDAP registration subject is malformed"
            ) from exc
        expected_object_class = _DOMAIN_OBJECT_CLASS
    else:
        try:
            canonical_subject = canonicalize_asn(evidence.subject.value)
        except ValueError as exc:
            raise _malformed(
                evidence.id, "RDAP registration subject is malformed"
            ) from exc
        expected_object_class = _AUTNUM_OBJECT_CLASS
    if canonical_subject != evidence.subject.value:
        raise _malformed(
            evidence.id, "RDAP registration subject is not in canonical form"
        )
    object_class = evidence.facts.get("object_class_name")
    if object_class != expected_object_class:
        raise _malformed(
            evidence.id, "RDAP registration evidence carries an unexpected object class"
        )
    _ = validate_extractor_input(
        evidence,
        source=SourceId.RDAP.value,
        evidence_type=EvidenceType.REGISTRATION,
    )
    return ExtractionResult()


def _extract_ip_network(evidence: Evidence, evidence_id: UUID) -> ExtractionResult:
    """Extract explicit CIDR0 prefixes for a validated IP-network observation.

    The canonical subject identity is validated first — even when no CIDR0
    facts exist — so an impossible subject can never pass silently.
    """
    object_class = evidence.facts.get("object_class_name")
    if object_class != _NETWORK_OBJECT_CLASS:
        raise _malformed(
            evidence_id, "RDAP network evidence carries an unexpected object class"
        )
    try:
        canonical_subject = canonicalize_ip_address(evidence.subject.value)
    except ValueError as exc:
        raise _malformed(evidence_id, "RDAP subject address is malformed") from exc
    if canonical_subject != evidence.subject.value:
        raise _malformed(evidence_id, "RDAP subject address is not in canonical form")

    cidrs = evidence.facts.get("cidr0_cidrs")
    if cidrs is None:
        return ExtractionResult()
    if not isinstance(cidrs, (list, tuple)):
        raise _malformed(evidence_id, "RDAP CIDR0 facts are malformed")
    if not cidrs:
        return ExtractionResult()

    subject = EntityIdentity(type=EntityType.IP_ADDRESS, value=canonical_subject)
    subject_address = ipaddress.ip_address(canonical_subject)

    entities: list[ExtractedEntity] = []
    relationships: list[RelationshipAssertion] = []
    for entry in cidrs:
        prefix_value = _validated_prefix(entry, evidence_id)
        prefix_network = ipaddress.ip_network(prefix_value)
        if prefix_network.version != subject_address.version:
            raise _malformed(
                evidence_id, "RDAP CIDR0 prefix family does not match the subject"
            )
        if subject_address not in prefix_network:
            raise _malformed(
                evidence_id, "RDAP CIDR0 prefix does not contain the subject address"
            )
        prefix_identity = EntityIdentity(
            type=EntityType.NETWORK_PREFIX, value=prefix_value
        )
        entities.append(
            ExtractedEntity(type=EntityType.NETWORK_PREFIX, value=prefix_value)
        )
        relationships.append(
            RelationshipAssertion(
                source=subject,
                type=RelationshipType.BELONGS_TO,
                target=prefix_identity,
                evidence_id=evidence_id,
            )
        )
    return ExtractionResult(
        entities=deduplicate_entities(entities),
        relationships=deduplicate_assertions(relationships),
    )


def _validated_prefix(entry: Any, evidence_id: UUID) -> str:
    """Return the canonical network form of one normalized CIDR0 entry.

    Normalized CIDR0 facts promise the network address with a legal prefix
    length and no host bits set, so a value that canonicalizes differently is
    a contract failure, never a silent mask to the network boundary.
    """
    if not isinstance(entry, Mapping):
        raise _malformed(evidence_id, "RDAP CIDR0 entry must be an object")
    prefix = entry.get("prefix")
    length = entry.get("length")
    if not isinstance(prefix, str):
        raise _malformed(evidence_id, "RDAP CIDR0 entry carries an invalid prefix")
    if isinstance(length, bool) or not isinstance(length, int):
        raise _malformed(evidence_id, "RDAP CIDR0 entry carries an invalid length")
    raw = f"{prefix}/{length}"
    try:
        canonical = canonicalize_network_prefix(raw)
    except ValueError as exc:
        raise _malformed(evidence_id, "RDAP CIDR0 prefix is malformed") from exc
    if canonical != raw:
        raise _malformed(
            evidence_id, "RDAP CIDR0 prefix is not in canonical network form"
        )
    return canonical


def _malformed(evidence_id: UUID | None, message: str) -> EvidenceExtractionError:
    """Build the RDAP extraction error with the bounded safe context."""
    return malformed_facts(
        SourceId.RDAP.value,
        message,
        evidence_id=evidence_id,
    )
