# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic DNS entity and relationship extraction.

Implements the documented Google Public DNS extraction matrix on normalized
``DNS`` evidence facts. Extraction is pure and synchronous: it consumes
already-normalized, persisted Evidence, re-canonicalizes every identity
through the shared domain canonicalizers, and fails explicitly on malformed
facts instead of producing a partial result.

Semantics (exactly, nothing more):

- A/AAAA: answer owner DOMAIN ``RESOLVES_TO`` answer IP_ADDRESS; the address
  is discovered. The answer owner (not blindly the Evidence subject) is the
  relationship source because CNAME chains legitimately change owners.
- CNAME: answer owner DOMAIN ``CNAME_OF`` target DOMAIN; the target is
  discovered.
- NS: answer owner DOMAIN ``USES_NAME_SERVER`` target DOMAIN; the target is
  discovered.
- Ordinary MX: answer owner DOMAIN ``USES_MAIL_SERVER`` exchange DOMAIN; the
  exchange is discovered. The null-MX sentinel (preference ``0`` with root
  exchange ``.``) produces nothing; a root exchange with a nonzero preference
  cannot occur in normalized facts and is a contract failure.
- PTR: the target DOMAIN is discovered only; PTR is not proof of forward
  resolution, so no relationship is asserted.
- TXT and SOA: no extraction.
- The DNS root (``.``) is never an entity: root-valued RDATA contributes
  nothing, and a root answer owner is a contract failure.
"""

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
    validate_extractor_input,
)
from agentic_threat_investigator.domain.entities import (
    EntityType,
    canonicalize_ip_address,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.relationships import RelationshipType

_QUERY_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT"})
_ROOT_NAME = "."
_DNS_NAME_RELATIONSHIPS = {
    "CNAME": RelationshipType.CNAME_OF,
    "NS": RelationshipType.USES_NAME_SERVER,
}


def extract_dns(evidence: Evidence) -> ExtractionResult:
    """Extract the documented DNS identities and assertions from one Evidence."""
    evidence_id = validate_extractor_input(
        evidence,
        source=SourceId.GOOGLE_PUBLIC_DNS.value,
        evidence_type=EvidenceType.DNS,
        subject_types=(EntityType.DOMAIN, EntityType.IP_ADDRESS),
    )
    _validate_query_facts(evidence.facts, evidence_id)
    answers = evidence.facts.get("answers")
    if not isinstance(answers, (list, tuple)) or not answers:
        raise _malformed(
            evidence_id,
            "DNS evidence must carry a non-empty normalized answer set",
        )

    entities: list[ExtractedEntity] = []
    relationships: list[RelationshipAssertion] = []
    for answer in answers:
        _extract_answer(answer, evidence_id, entities, relationships)
    return ExtractionResult(
        entities=deduplicate_entities(entities),
        relationships=deduplicate_assertions(relationships),
    )


def _malformed(evidence_id: UUID, message: str) -> EvidenceExtractionError:
    """Build the DNS extraction error with the bounded safe context."""
    return malformed_facts(
        SourceId.GOOGLE_PUBLIC_DNS.value, message, evidence_id=evidence_id
    )


def _validate_query_facts(facts: Mapping[str, Any], evidence_id: UUID) -> None:
    """Validate the query-level normalized facts promised by the provider.

    Persisted DNS evidence is only ever emitted for a NOERROR query with a
    non-empty answer set, so any other status is a contract failure.
    """
    query_type = facts.get("query_type")
    if not isinstance(query_type, str) or query_type not in _QUERY_TYPES:
        raise _malformed(evidence_id, "DNS evidence carries an unsupported query type")
    status = facts.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or status != 0:
        raise _malformed(evidence_id, "only NOERROR DNS observations are extractable")


def _extract_answer(
    answer: Any,
    evidence_id: UUID,
    entities: list[ExtractedEntity],
    relationships: list[RelationshipAssertion],
) -> None:
    """Process one normalized answer record in source order."""
    if not isinstance(answer, Mapping):
        raise _malformed(evidence_id, "DNS answer must be an object")
    owner = answer.get("name")
    record_type = answer.get("record_type")
    ttl = answer.get("ttl")
    if not isinstance(owner, str) or not isinstance(record_type, str):
        raise _malformed(evidence_id, "DNS answer carries invalid members")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0:
        raise _malformed(evidence_id, "DNS answer carries an invalid TTL")
    if owner == _ROOT_NAME:
        raise _malformed(evidence_id, "the DNS root is never an extractable owner")
    owner_identity = _domain_identity(owner, evidence_id)

    if record_type in ("A", "AAAA"):
        _extract_address_record(
            owner_identity, answer, evidence_id, entities, relationships
        )
    elif record_type in _DNS_NAME_RELATIONSHIPS:
        output = _name_relation_output(
            owner_identity,
            answer,
            _DNS_NAME_RELATIONSHIPS[record_type],
            evidence_id,
        )
        if output is not None:
            entity, assertion = output
            entities.append(entity)
            relationships.append(assertion)
    elif record_type == "MX":
        _extract_mx_record(owner_identity, answer, evidence_id, entities, relationships)
    elif record_type == "PTR":
        _extract_ptr_target(answer, evidence_id, entities)
    elif record_type in ("TXT", "SOA"):
        return
    else:
        raise _malformed(evidence_id, "DNS evidence carries an unsupported record type")


def _extract_address_record(
    owner: EntityIdentity,
    answer: Mapping[str, Any],
    evidence_id: UUID,
    entities: list[ExtractedEntity],
    relationships: list[RelationshipAssertion],
) -> None:
    """Assert owner ``RESOLVES_TO`` address and discover the address."""
    address = _ip_identity(_answer_value(answer, evidence_id), evidence_id)
    relationships.append(
        RelationshipAssertion(
            source=owner,
            type=RelationshipType.RESOLVES_TO,
            target=address,
            evidence_id=evidence_id,
        )
    )
    entities.append(ExtractedEntity(type=EntityType.IP_ADDRESS, value=address.value))


def _name_relation_output(
    owner: EntityIdentity,
    answer: Mapping[str, Any],
    relationship_type: RelationshipType,
    evidence_id: UUID,
) -> tuple[ExtractedEntity, RelationshipAssertion] | None:
    """Build an owner-to-domain relation and its discovered target.

    The root name is a protocol sentinel that is never an entity: a record
    whose target is the root contributes nothing.
    """
    target_value = _answer_value(answer, evidence_id)
    if target_value == _ROOT_NAME:
        return None
    target = _domain_identity(target_value, evidence_id)
    return (
        ExtractedEntity(type=EntityType.DOMAIN, value=target.value),
        RelationshipAssertion(
            source=owner,
            type=relationship_type,
            target=target,
            evidence_id=evidence_id,
        ),
    )


def _extract_mx_record(
    owner: EntityIdentity,
    answer: Mapping[str, Any],
    evidence_id: UUID,
    entities: list[ExtractedEntity],
    relationships: list[RelationshipAssertion],
) -> None:
    """Assert an ordinary mail-exchange relation and discover the exchange.

    The exact pair of preference ``0`` and root exchange ``.`` is the null-MX
    sentinel and produces nothing. A root exchange with any nonzero preference
    cannot occur in normalized facts and is a contract failure.
    """
    preference = answer.get("preference")
    exchange = answer.get("exchange")
    if (
        isinstance(preference, bool)
        or not isinstance(preference, int)
        or not 0 <= preference <= 65535
    ):
        raise _malformed(evidence_id, "DNS MX answer carries an invalid preference")
    if not isinstance(exchange, str):
        raise _malformed(evidence_id, "DNS MX answer carries an invalid exchange")
    if exchange == _ROOT_NAME:
        if preference == 0:
            return
        raise _malformed(
            evidence_id, "a root MX exchange is only valid as the null-MX sentinel"
        )
    target = _domain_identity(exchange, evidence_id)
    relationships.append(
        RelationshipAssertion(
            source=owner,
            type=RelationshipType.USES_MAIL_SERVER,
            target=target,
            evidence_id=evidence_id,
        )
    )
    entities.append(ExtractedEntity(type=EntityType.DOMAIN, value=target.value))


def _extract_ptr_target(
    answer: Mapping[str, Any],
    evidence_id: UUID,
    entities: list[ExtractedEntity],
) -> None:
    """Discover a PTR target domain only; no relationship is asserted.

    A reverse pointer is not proof of forward resolution. The root name is a
    protocol sentinel and is never discovered.
    """
    target_value = _answer_value(answer, evidence_id)
    if target_value == _ROOT_NAME:
        return
    target = _domain_identity(target_value, evidence_id)
    entities.append(ExtractedEntity(type=EntityType.DOMAIN, value=target.value))


def _answer_value(answer: Mapping[str, Any], evidence_id: UUID) -> str:
    """Return the validated string RDATA value of a normalized answer."""
    value = answer.get("value")
    if not isinstance(value, str):
        raise _malformed(evidence_id, "DNS answer carries an invalid RDATA value")
    return value


def _domain_identity(value: str, evidence_id: UUID) -> EntityIdentity:
    """Return the DOMAIN identity of an already-canonical DNS name fact.

    Normalized DNS facts promise strict canonical names, so a value that
    canonicalizes differently is a contract failure, not a silent repair.
    """
    try:
        canonical = validate_dns_name(value)
    except (ValueError, UnicodeError) as exc:
        raise _malformed(evidence_id, "DNS name fact is malformed") from exc
    if canonical != value:
        raise _malformed(evidence_id, "DNS name fact is not in canonical form")
    return EntityIdentity(type=EntityType.DOMAIN, value=canonical)


def _ip_identity(value: str, evidence_id: UUID) -> EntityIdentity:
    """Return the IP_ADDRESS identity of an already-canonical address fact."""
    try:
        canonical = canonicalize_ip_address(value)
    except ValueError as exc:
        raise _malformed(evidence_id, "DNS address fact is malformed") from exc
    if canonical != value:
        raise _malformed(evidence_id, "DNS address fact is not in canonical form")
    return EntityIdentity(type=EntityType.IP_ADDRESS, value=canonical)
