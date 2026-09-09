# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic DNS entity and relationship extraction.

Implements the documented Google Public DNS extraction matrix on normalized
``DNS`` evidence facts. Extraction is pure and synchronous: it consumes
already-normalized, persisted Evidence, re-canonicalizes every identity
through the shared domain canonicalizers, and fails explicitly on malformed
facts instead of producing a partial result.

The complete normalized query/answer contract is enforced at the extraction
boundary: the query envelope (name, type, status, flags, and subject
pairing), answer attribution and CNAME-chain sequencing, and every supported
answer shape — including TXT and SOA answers that produce no graph output —
are validated before any result is returned.

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
  exchange ``.``) produces nothing and must be the only MX answer in the
  set; a root exchange with a nonzero preference cannot occur in normalized
  facts and is a contract failure.
- PTR: the target DOMAIN is discovered only; PTR is not proof of forward
  resolution, so no relationship is asserted.
- TXT and SOA: no extraction.
- The DNS root (``.``) is never an entity: root-valued RDATA contributes
  nothing, and a root answer owner is a contract failure.
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
_DNS_FLAGS = frozenset({"tc", "rd", "ra", "ad", "cd"})
_MAX_UINT32 = 4294967295


def extract_dns(evidence: Evidence) -> ExtractionResult:
    """Extract the documented DNS identities and assertions from one Evidence."""
    evidence_id = validate_extractor_input(
        evidence,
        source=SourceId.GOOGLE_PUBLIC_DNS.value,
        evidence_type=EvidenceType.DNS,
        subject_types=(EntityType.DOMAIN, EntityType.IP_ADDRESS),
    )
    query_name, query_type = _validate_query_envelope(evidence, evidence_id)
    answers = evidence.facts.get("answers")
    if not isinstance(answers, (list, tuple)) or not answers:
        raise _malformed(
            evidence_id,
            "DNS evidence must carry a non-empty normalized answer set",
        )
    _validate_answer_set(answers, query_name, query_type, evidence_id)

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


def _validate_query_envelope(evidence: Evidence, evidence_id: UUID) -> tuple[str, str]:
    """Validate the complete query envelope and return the validated values.

    Persisted DNS evidence is only ever emitted for a NOERROR query whose
    subject and query name agree with the source contract: forward queries
    carry the queried canonical DOMAIN as both subject and ``query_name``,
    and PTR queries carry the queried canonical IP whose reverse-pointer
    name is ``query_name``.
    """
    facts = evidence.facts
    query_type = facts.get("query_type")
    if not isinstance(query_type, str) or query_type not in _QUERY_TYPES:
        raise _malformed(evidence_id, "DNS evidence carries an unsupported query type")
    status = facts.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or status != 0:
        raise _malformed(evidence_id, "only NOERROR DNS observations are extractable")
    _validate_flags(facts.get("flags"), evidence_id)

    query_name = _validate_query_name(facts, evidence_id)
    expected_query_name = _validate_subject_pairing(evidence, query_type, evidence_id)
    if query_name != expected_query_name:
        raise _malformed(evidence_id, "DNS query name does not match the subject")
    return query_name, query_type


def _validate_query_name(facts: Mapping[str, Any], evidence_id: UUID) -> str:
    """Require a canonical strict DNS query name in the normalized facts."""
    query_name = facts.get("query_name")
    if not isinstance(query_name, str):
        raise _malformed(evidence_id, "DNS evidence carries an invalid query name")
    try:
        canonical_query_name = validate_dns_name(query_name)
    except (ValueError, UnicodeError) as exc:
        raise _malformed(evidence_id, "DNS query name is malformed") from exc
    if canonical_query_name != query_name:
        raise _malformed(evidence_id, "DNS query name is not in canonical form")
    return query_name


def _validate_subject_pairing(
    evidence: Evidence, query_type: str, evidence_id: UUID
) -> str:
    """Return the query name the evidence subject pairing requires.

    Forward queries require a canonical DOMAIN subject equal to the query
    name; PTR queries require a canonical IP subject whose reverse-pointer
    name is the query name.
    """
    subject = evidence.subject
    if query_type == "PTR":
        if subject.type is not EntityType.IP_ADDRESS:
            raise _malformed(evidence_id, "a PTR query requires an IP_ADDRESS subject")
        try:
            canonical_subject = canonicalize_ip_address(subject.value)
        except ValueError as exc:
            raise _malformed(evidence_id, "DNS subject address is malformed") from exc
        if canonical_subject != subject.value:
            raise _malformed(
                evidence_id, "DNS subject address is not in canonical form"
            )
        return ipaddress.ip_address(canonical_subject).reverse_pointer
    if subject.type is not EntityType.DOMAIN:
        raise _malformed(evidence_id, "a forward query requires a DOMAIN subject")
    try:
        canonical_subject = validate_dns_name(subject.value)
    except (ValueError, UnicodeError) as exc:
        raise _malformed(evidence_id, "DNS subject name is malformed") from exc
    if canonical_subject != subject.value:
        raise _malformed(evidence_id, "DNS subject name is not in canonical form")
    return subject.value


def _validate_flags(flags: Any, evidence_id: UUID) -> None:
    """Require flags to be a mapping of documented names to strict booleans."""
    if not isinstance(flags, Mapping):
        raise _malformed(evidence_id, "DNS flags must be an object")
    for name, value in flags.items():
        if name not in _DNS_FLAGS:
            raise _malformed(evidence_id, "DNS flags carry an unknown flag name")
        if not isinstance(value, bool):
            raise _malformed(evidence_id, "DNS flags carry a non-boolean value")


def _validate_answer_set(
    answers: tuple[Any, ...] | list[Any],
    query_name: str,
    query_type: str,
    evidence_id: UUID,
) -> None:
    """Validate answer attribution, sequencing, and the complete answer set.

    Every answer must belong to the queried canonical name, either directly
    or through a contiguous acyclic CNAME chain rooted at it. A CNAME chain
    may not follow a terminal answer or point back to an earlier owner, and
    non-CNAME answers of the requested type must sit at the final chain
    owner; several terminal answers may share that owner. A root MX is the
    null-MX sentinel and must be the only MX answer in the set, with
    preference zero. This is source attribution validation only: it infers
    no relationships, entities, or maliciousness.
    """
    expected_owner = query_name
    visited_owners = {query_name}
    saw_terminal = False
    mx_answers: list[Mapping[str, Any]] = []
    for answer in answers:
        owner, record_type = _validate_answer_common_fields(answer, evidence_id)
        if owner != expected_owner:
            raise _malformed(
                evidence_id, "DNS answer owner does not follow the query/CNAME chain"
            )
        if record_type == "CNAME":
            if saw_terminal:
                raise _malformed(evidence_id, "a CNAME cannot follow a terminal answer")
            target = _protocol_name(_answer_value(answer, evidence_id), evidence_id)
            # Every validated CNAME target participates in chain state,
            # including the root sentinel: the authoritative provider chain
            # validation always advances the expected owner to every CNAME
            # target, so a root target can never be followed by an answer at
            # the pre-CNAME owner. The root still never becomes an entity or
            # relationship endpoint.
            if target in visited_owners:
                raise _malformed(
                    evidence_id, "DNS CNAME chain cycles or revisits an owner"
                )
            visited_owners.add(target)
            expected_owner = target
            continue
        if record_type != query_type:
            raise _malformed(
                evidence_id, "DNS answer record type differs from the requested query"
            )
        saw_terminal = True
        if record_type == "MX" and isinstance(answer, Mapping):
            mx_answers.append(answer)

    if (
        any(
            isinstance(answer.get("exchange"), str)
            and answer.get("exchange") == _ROOT_NAME
            for answer in mx_answers
        )
        and len(mx_answers) != 1
    ):
        raise _malformed(
            evidence_id, "a root MX exchange must be the only MX answer in the set"
        )


def _validate_answer_common_fields(answer: Any, evidence_id: UUID) -> tuple[str, str]:
    """Validate the common normalized members of one answer record."""
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
    return owner, record_type


def _extract_answer(
    answer: Any,
    evidence_id: UUID,
    entities: list[ExtractedEntity],
    relationships: list[RelationshipAssertion],
) -> None:
    """Process one validated normalized answer record in source order."""
    if not isinstance(answer, Mapping):
        raise _malformed(evidence_id, "DNS answer must be an object")
    owner = answer.get("name")
    record_type = answer.get("record_type")
    if not isinstance(owner, str) or not isinstance(record_type, str):
        raise _malformed(evidence_id, "DNS answer carries invalid members")
    owner_identity = _domain_identity(owner, evidence_id)

    if record_type in ("A", "AAAA"):
        expected_version = 4 if record_type == "A" else 6
        address = _ip_identity(
            _answer_value(answer, evidence_id), expected_version, evidence_id
        )
        relationships.append(
            RelationshipAssertion(
                source=owner_identity,
                type=RelationshipType.RESOLVES_TO,
                target=address,
                evidence_id=evidence_id,
            )
        )
        entities.append(
            ExtractedEntity(type=EntityType.IP_ADDRESS, value=address.value)
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
    elif record_type == "TXT":
        _answer_value(answer, evidence_id)
    elif record_type == "SOA":
        _validate_soa_answer(answer, evidence_id)
    else:
        raise _malformed(evidence_id, "DNS evidence carries an unsupported record type")


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


def _validate_soa_answer(answer: Mapping[str, Any], evidence_id: UUID) -> None:
    """Validate the complete normalized SOA shape without producing output.

    SOA requires canonical ``mname`` and ``rname`` plus strict unsigned
    32-bit ``serial``, ``refresh``, ``retry``, ``expire``, and ``minimum``
    integers; booleans are invalid. SOA never yields entities or assertions.
    """
    _protocol_name(_answer_member(answer, "mname", evidence_id), evidence_id)
    _protocol_name(_answer_member(answer, "rname", evidence_id), evidence_id)
    for member in ("serial", "refresh", "retry", "expire", "minimum"):
        value = answer.get(member)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= _MAX_UINT32
        ):
            raise _malformed(evidence_id, "DNS SOA answer carries an invalid integer")


def _answer_value(answer: Mapping[str, Any], evidence_id: UUID) -> str:
    """Return the validated string RDATA value of a normalized answer."""
    value = answer.get("value")
    if not isinstance(value, str):
        raise _malformed(evidence_id, "DNS answer carries an invalid RDATA value")
    return value


def _answer_member(answer: Mapping[str, Any], member: str, evidence_id: UUID) -> str:
    """Return a validated string answer member of a normalized record."""
    value = answer.get(member)
    if not isinstance(value, str):
        raise _malformed(evidence_id, "DNS answer carries an invalid member")
    return value


def _protocol_name(value: str, evidence_id: UUID) -> str:
    """Return the validated canonical protocol name of a DNS name fact.

    The exact root sentinel ``.`` is a valid protocol value that is never an
    entity; every other value must pass the strict DNS-name contract and
    already be canonical.
    """
    if value == _ROOT_NAME:
        return value
    try:
        canonical = validate_dns_name(value)
    except (ValueError, UnicodeError) as exc:
        raise _malformed(evidence_id, "DNS name fact is malformed") from exc
    if canonical != value:
        raise _malformed(evidence_id, "DNS name fact is not in canonical form")
    return canonical


def _domain_identity(value: str, evidence_id: UUID) -> EntityIdentity:
    """Return the DOMAIN identity of an already-canonical DNS name fact.

    Normalized DNS facts promise strict canonical names, so a value that
    canonicalizes differently is a contract failure, not a silent repair.
    """
    return EntityIdentity(
        type=EntityType.DOMAIN, value=_protocol_name(value, evidence_id)
    )


def _ip_identity(
    value: str, expected_version: int, evidence_id: UUID
) -> EntityIdentity:
    """Return the IP_ADDRESS identity of an already-canonical address fact.

    The address family must match the record type: an A record carries only
    IPv4 and an AAAA record only IPv6.
    """
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise _malformed(evidence_id, "DNS address fact is malformed") from exc
    if parsed.version != expected_version:
        raise _malformed(
            evidence_id, "DNS address family does not match the record type"
        )
    canonical = canonicalize_ip_address(value)
    if canonical != value:
        raise _malformed(evidence_id, "DNS address fact is not in canonical form")
    return EntityIdentity(type=EntityType.IP_ADDRESS, value=canonical)
